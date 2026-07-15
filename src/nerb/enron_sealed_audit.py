"""Preregistered, prediction-independent sampling for a sealed Enron audit.

This module is deliberately pure: it validates one closed audit plan and
selects exact ``subject_current_body`` projections from caller-supplied test
records.  It does not open split artifacts, run NERB, or persist private text.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from .enron_private_io import (
    EnronPrivateIOError,
    PrivateRun,
    open_private_binary_input_at,
    open_private_directory_input,
)

AUDIT_PLAN_SCHEMA_VERSION = "nerb.enron_sealed_audit_plan.v1"
AUDIT_SAMPLE_SCHEMA_VERSION = "nerb.enron_sealed_audit_sample.v1"
AUDIT_RECEIPT_SCHEMA_VERSION = "nerb.enron_sealed_audit_receipt.v1"
AUDIT_OUTPUT_BINDING_SCHEMA_VERSION = "nerb.enron_sealed_audit_output_binding.v1"
SPLIT_MEMBERSHIP_SCHEMA_VERSION = "nerb.enron_split_membership.v2"

PRODUCTION_SAMPLE_SIZE = 100
DEFAULT_MAX_SAMPLE_SIZE = 10_000
DEFAULT_MAX_INPUT_BYTES = 2 * 1024 * 1024 * 1024
DEFAULT_MAX_PROJECTION_BYTES = 10 * 1024 * 1024
DEFAULT_MAX_RETAINED_PROJECTION_BYTES = 512 * 1024 * 1024
MAX_PLAN_BYTES = 64 * 1024
MAX_RECEIPT_BYTES = 1024 * 1024

_RANK_DOMAIN = "nerb/enron/sealed-audit-rank/v1"
_PLAN_FIELDS = frozenset(
    {
        "schema_version",
        "fixture_mode",
        "sample_size",
        "frame_documents",
        "frame_groups",
        "test_artifact_sha256",
        "membership_artifact_sha256",
        "split_manifest_sha256",
        "split_policy_sha256",
        "frozen_git_commit",
        "bank_sha256",
        "evaluator_source_sha256",
        "thresholds_sha256",
        "performance_manifest_sha256",
        "annotation_policy_sha256",
        "catalog_policy_sha256",
        "audit_execution_policy_sha256",
        "projection",
        "selection_policy_sha256",
        "no_tuning",
        "resource_limits",
    }
)
_RESOURCE_LIMIT_FIELDS = frozenset({"max_input_bytes", "max_projection_bytes", "max_retained_projection_bytes"})
_MEMBERSHIP_FIELDS = frozenset(
    {
        "schema_version",
        "document_id",
        "group_id",
        "role",
        "occurrence_count",
        "temporal",
        "mailbox",
        "mailbox_recurrence",
        "size",
        "group_size",
        "identities",
        "views",
        "challenges",
    }
)
_TEMPORAL_FIELDS = frozenset({"eligible", "status", "anchor_utc"})
_IDENTITY_FIELDS = frozenset({"recurrence", "count", "contains_frequency"})
_VIEW_FIELDS = frozenset({"natural", "structured"})
_IDENTITY_BANDS = ("all_known", "mixed", "all_novel", "unavailable")
_SIZE_BUCKETS = frozenset(
    {"0", "1-255", "256-1023", "1024-4095", "4096-16383", "16384-65535", "65536-262143", "262144-1048575", "1048576+"}
)
_GROUP_SIZE_BUCKETS = frozenset({"1", "2", "3-4", "5-9", "10-99", "100+"})
_CHALLENGES = frozenset(
    {
        "non_temporal",
        "mailbox_unavailable",
        "mailbox_novelty",
        "multi_record_leakage_group",
        "exact_duplicate_group",
        "thread_or_reply_group",
        "near_duplicate_group",
        "temporal_future",
        "natural_empty",
        "structured_empty",
        "identity_novelty",
    }
)
_RISK_CHALLENGES = frozenset(
    {
        "non_temporal",
        "multi_record_leakage_group",
        "exact_duplicate_group",
        "thread_or_reply_group",
        "near_duplicate_group",
        "natural_empty",
    }
)
_FORBIDDEN_KEYS = frozenset(
    {
        "prediction",
        "predictions",
        "detected_entities",
        "matches",
        "gold",
        "gold_spans",
        "label",
        "labels",
        "annotations",
    }
)
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_DOCUMENT_ID_RE = re.compile(r"^doc_[0-9a-f]{64}$")
_SAMPLE_FIELDS = frozenset(
    {
        "schema_version",
        "document_id",
        "group_id",
        "text_view",
        "text",
        "text_sha256",
        "unicode_scalars",
        "stratum",
        "selection_rank_sha256",
    }
)
_STRATUM_FIELDS = frozenset({"identity", "size", "risk"})
_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "audit_plan_sha256",
        "selection_policy_sha256",
        "projection",
        "input_records",
        "input_bytes",
        "population_groups",
        "sample_documents",
        "plan_artifact",
        "sample_artifact",
        "strata",
        "privacy",
        "fixture_mode",
        "promotable",
        "audit_output_binding_sha256",
    }
)
_RECEIPT_CORE_FIELDS = _RECEIPT_FIELDS - {"audit_output_binding_sha256"}

_SELECTION_POLICY = {
    "version": "nerb.enron-sealed-audit-selection.v1",
    "population_unit": "one_min_rank_representative_per_leakage_group",
    "strata": ["identity_recurrence_4", "projection_size_3", "structural_risk_2"],
    "allocation": "base_min_2_then_hamilton_over_residual_capacity",
    "selection": "sha256_rank_then_document_id",
    "projection": "views.subject_current_body",
    "risk_challenges": sorted(_RISK_CHALLENGES),
}

AUDIT_EXECUTION_POLICY: dict[str, Any] = {
    "schema_version": "nerb.enron_audit_execution_policy",
    "scope": {"combined": "person_contact", "entity_classes": ["contact", "person"]},
    "catalog_qualification": "committed_bank_aware_prediction_blind_before_scoring",
    "scoring": {
        "bank_compilations": 1,
        "scans_per_document": 1,
        "matching": "one_to_one_exact_span_and_class",
        "character_accounting": "document_disjoint_cross_class_interval_union",
    },
    "prediction_audit": {
        "review_all": ["false_negative", "false_positive", "boundary_or_class_mismatch", "wrong_canonical"],
        "true_positive_sample": "domain_separated_min_sha256_up_to_20",
        "certified_negative_sample": "domain_separated_min_sha256_up_to_20",
        "reviewer_separation": (
            "prediction_audit_reviewer_distinct_from_both_gold_annotators_gold_adjudicator_and_catalog_reviewer"
        ),
        "selected_case_coverage": "exact",
        "unresolved_cases_allowed": 0,
        "gold_defect": "invalidate_without_rescore",
    },
    "mutability": "sample_gold_catalog_bank_evaluator_thresholds_and_score_immutable_after_each_commit",
}


class EnronSealedAuditError(ValueError):
    """Raised when a sealed-audit plan or input cannot be used exactly."""


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


SELECTION_POLICY_SHA256 = "sha256:" + hashlib.sha256(_canonical_bytes(_SELECTION_POLICY)).hexdigest()
AUDIT_EXECUTION_POLICY_SHA256 = "sha256:" + hashlib.sha256(_canonical_bytes(AUDIT_EXECUTION_POLICY)).hexdigest()


def _audit_output_binding_sha256(receipt_core: Mapping[str, Any]) -> str:
    if set(receipt_core) != _RECEIPT_CORE_FIELDS:
        raise EnronSealedAuditError("Sealed-audit receipt core is invalid.")
    payload = {
        "schema_version": AUDIT_OUTPUT_BINDING_SCHEMA_VERSION,
        "audit_plan_sha256": receipt_core["audit_plan_sha256"],
        "plan_artifact": receipt_core["plan_artifact"],
        "sample_artifact": receipt_core["sample_artifact"],
        "receipt_core_sha256": "sha256:" + hashlib.sha256(_canonical_bytes(receipt_core)).hexdigest(),
    }
    return "sha256:" + hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def make_enron_sealed_audit_plan(
    *,
    sample_size: int,
    frame_documents: int,
    frame_groups: int,
    test_artifact_sha256: str,
    membership_artifact_sha256: str,
    split_manifest_sha256: str,
    split_policy_sha256: str,
    frozen_git_commit: str,
    bank_sha256: str,
    evaluator_source_sha256: str,
    thresholds_sha256: str,
    performance_manifest_sha256: str,
    annotation_policy_sha256: str,
    catalog_policy_sha256: str,
    fixture_mode: bool = False,
    max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES,
    max_projection_bytes: int = DEFAULT_MAX_PROJECTION_BYTES,
    max_retained_projection_bytes: int = DEFAULT_MAX_RETAINED_PROJECTION_BYTES,
) -> dict[str, Any]:
    """Construct and validate the one closed preregistration shape."""

    return validate_enron_sealed_audit_plan(
        {
            "schema_version": AUDIT_PLAN_SCHEMA_VERSION,
            "fixture_mode": fixture_mode,
            "sample_size": sample_size,
            "frame_documents": frame_documents,
            "frame_groups": frame_groups,
            "test_artifact_sha256": test_artifact_sha256,
            "membership_artifact_sha256": membership_artifact_sha256,
            "split_manifest_sha256": split_manifest_sha256,
            "split_policy_sha256": split_policy_sha256,
            "frozen_git_commit": frozen_git_commit,
            "bank_sha256": bank_sha256,
            "evaluator_source_sha256": evaluator_source_sha256,
            "thresholds_sha256": thresholds_sha256,
            "performance_manifest_sha256": performance_manifest_sha256,
            "annotation_policy_sha256": annotation_policy_sha256,
            "catalog_policy_sha256": catalog_policy_sha256,
            "audit_execution_policy_sha256": AUDIT_EXECUTION_POLICY_SHA256,
            "projection": "views.subject_current_body",
            "selection_policy_sha256": SELECTION_POLICY_SHA256,
            "no_tuning": True,
            "resource_limits": {
                "max_input_bytes": max_input_bytes,
                "max_projection_bytes": max_projection_bytes,
                "max_retained_projection_bytes": max_retained_projection_bytes,
            },
        }
    )


def validate_enron_sealed_audit_plan(plan: Mapping[str, Any]) -> dict[str, Any]:
    """Return a detached validated plan, rejecting unknown or mutable policy fields."""

    if not isinstance(plan, Mapping) or set(plan) != _PLAN_FIELDS:
        raise EnronSealedAuditError("Sealed-audit plan fields are invalid.")
    sample_size = plan["sample_size"]
    fixture_mode = plan["fixture_mode"]
    frame_documents = plan["frame_documents"]
    frame_groups = plan["frame_groups"]
    limits = plan["resource_limits"]
    if (
        not isinstance(fixture_mode, bool)
        or type(sample_size) is not int
        or type(frame_documents) is not int
        or type(frame_groups) is not int
        or sample_size < 1
        or frame_documents < 1
        or frame_groups < sample_size
        or frame_groups > frame_documents
        or sample_size > DEFAULT_MAX_SAMPLE_SIZE
        or (not fixture_mode and sample_size != PRODUCTION_SAMPLE_SIZE)
        or not isinstance(limits, Mapping)
        or set(limits) != _RESOURCE_LIMIT_FIELDS
        or any(type(limits[field]) is not int or limits[field] < 1 for field in _RESOURCE_LIMIT_FIELDS)
        or limits["max_input_bytes"] > DEFAULT_MAX_INPUT_BYTES
        or limits["max_projection_bytes"] > DEFAULT_MAX_PROJECTION_BYTES
        or limits["max_retained_projection_bytes"] > DEFAULT_MAX_RETAINED_PROJECTION_BYTES
    ):
        raise EnronSealedAuditError("Sealed-audit sample size violates the frozen policy.")
    commitment_fields = (
        "test_artifact_sha256",
        "membership_artifact_sha256",
        "split_manifest_sha256",
        "split_policy_sha256",
        "bank_sha256",
        "evaluator_source_sha256",
        "thresholds_sha256",
        "performance_manifest_sha256",
        "annotation_policy_sha256",
        "catalog_policy_sha256",
        "audit_execution_policy_sha256",
    )
    if (
        plan["schema_version"] != AUDIT_PLAN_SCHEMA_VERSION
        or plan["projection"] != "views.subject_current_body"
        or plan["selection_policy_sha256"] != SELECTION_POLICY_SHA256
        or plan["audit_execution_policy_sha256"] != AUDIT_EXECUTION_POLICY_SHA256
        or plan["no_tuning"] is not True
        or any(
            not isinstance(plan[field], str) or _SHA256_RE.fullmatch(plan[field]) is None for field in commitment_fields
        )
        or not isinstance(plan["frozen_git_commit"], str)
        or _COMMIT_RE.fullmatch(plan["frozen_git_commit"]) is None
    ):
        raise EnronSealedAuditError("Sealed-audit plan identity or policy is invalid.")
    detached = {field: plan[field] for field in sorted(_PLAN_FIELDS)}
    detached["resource_limits"] = {field: limits[field] for field in sorted(_RESOURCE_LIMIT_FIELDS)}
    return detached


def hash_enron_sealed_audit_plan(plan: Mapping[str, Any]) -> str:
    """Hash the canonical, closed preregistration."""

    validated = validate_enron_sealed_audit_plan(plan)
    return "sha256:" + hashlib.sha256(_canonical_bytes(validated)).hexdigest()


def _rank(plan: Mapping[str, Any], plan_sha256: str, document_id: str) -> str:
    payload = "\0".join(
        (
            _RANK_DOMAIN,
            str(plan["test_artifact_sha256"]),
            str(plan["split_policy_sha256"]),
            plan_sha256,
            str(plan["frozen_git_commit"]),
            document_id,
        )
    )
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _size_bucket(byte_count: int) -> str:
    for upper, label in (
        (0, "0"),
        (255, "1-255"),
        (1_023, "256-1023"),
        (4_095, "1024-4095"),
        (16_383, "4096-16383"),
        (65_535, "16384-65535"),
        (262_143, "65536-262143"),
        (1_048_575, "262144-1048575"),
    ):
        if byte_count <= upper:
            return label
    return "1048576+"


def _size_band(size: str) -> str:
    if size in {"0", "1-255", "256-1023"}:
        return "short"
    if size in {"1024-4095", "4096-16383"}:
        return "medium"
    return "long"


def _closed_mapping(value: Any, fields: frozenset[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise EnronSealedAuditError("Sealed-audit membership is malformed.")
    return value


def _validate_membership(membership: Mapping[str, Any], document_id: str, text: str) -> tuple[str, str, str, str]:
    value = _closed_mapping(membership, _MEMBERSHIP_FIELDS)
    temporal = _closed_mapping(value["temporal"], _TEMPORAL_FIELDS)
    identities = _closed_mapping(value["identities"], _IDENTITY_FIELDS)
    views = _closed_mapping(value["views"], _VIEW_FIELDS)
    challenges = value["challenges"]
    frequencies = identities["contains_frequency"]
    if (
        value["schema_version"] != SPLIT_MEMBERSHIP_SCHEMA_VERSION
        or value["document_id"] != document_id
        or not isinstance(value["group_id"], str)
        or _SHA256_RE.fullmatch(value["group_id"]) is None
        or value["role"] != "test"
        or type(value["occurrence_count"]) is not int
        or value["occurrence_count"] < 1
        or not isinstance(temporal["eligible"], bool)
        or temporal["status"] not in {"valid", "missing", "invalid", "out_of_range", "ambiguous_timezone"}
        or (temporal["anchor_utc"] is not None and not isinstance(temporal["anchor_utc"], str))
        or value["mailbox"] not in {"inbox", "sent", "draft", "deleted", "archive", "other", "unavailable"}
        or value["mailbox_recurrence"] not in {"known", "novel", "unavailable"}
        or value["size"] not in _SIZE_BUCKETS
        or value["size"] != _size_bucket(len(text.encode("utf-8")))
        or value["group_size"] not in _GROUP_SIZE_BUCKETS
        or identities["recurrence"] not in _IDENTITY_BANDS
        or type(identities["count"]) is not int
        or identities["count"] < 0
        or not isinstance(frequencies, list)
        or frequencies != sorted(set(frequencies))
        or any(item not in {"novel", "tail", "mid", "head"} for item in frequencies)
        or not isinstance(views["natural"], bool)
        or not isinstance(views["structured"], bool)
        or views["natural"] is not bool(text)
        or not isinstance(challenges, list)
        or challenges != sorted(set(challenges))
        or any(item not in _CHALLENGES for item in challenges)
    ):
        raise EnronSealedAuditError("Sealed-audit membership is malformed.")
    risk = "risk" if _RISK_CHALLENGES.intersection(challenges) else "ordinary"
    return str(value["group_id"]), str(identities["recurrence"]), _size_band(str(value["size"])), risk


def _reject_prediction_or_label_fields(record: Mapping[str, Any]) -> None:
    pending: list[Any] = [record]
    nodes = 0
    while pending:
        value = pending.pop()
        nodes += 1
        if nodes > 100_000:
            raise EnronSealedAuditError("Sealed-audit record structure exceeds the bounded policy.")
        if isinstance(value, Mapping):
            for key, child in value.items():
                if not isinstance(key, str) or key.casefold() in _FORBIDDEN_KEYS:
                    raise EnronSealedAuditError(
                        "Prediction or label fields are forbidden before sealed-audit selection."
                    )
                pending.append(child)
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            pending.extend(value)


def _hamilton_quotas_from_populations(
    populations: Mapping[tuple[str, str, str], int], sample_size: int
) -> dict[tuple[str, str, str], int]:
    quotas = {key: min(2, population) for key, population in populations.items()}
    base_total = sum(quotas.values())
    population = sum(populations.values())
    if population < sample_size:
        raise EnronSealedAuditError("Sealed-audit sampling frame has fewer groups than the requested sample.")
    if base_total > sample_size:
        raise EnronSealedAuditError("Sealed-audit sample cannot cover every frozen nonempty stratum.")
    remaining = sample_size - base_total
    capacities = {key: populations[key] - quotas[key] for key in populations}
    capacity_total = sum(capacities.values())
    if remaining:
        floors = {key: remaining * capacity // capacity_total for key, capacity in capacities.items()}
        for key, amount in floors.items():
            quotas[key] += amount
        residual = remaining - sum(floors.values())
        remainders = sorted(
            ((remaining * capacities[key] % capacity_total, key) for key in populations),
            key=lambda item: (-item[0], item[1]),
        )
        for _, key in remainders[:residual]:
            quotas[key] += 1
    return quotas


def _hamilton_quotas(
    strata: Mapping[tuple[str, str, str], Sequence[dict[str, Any]]], sample_size: int
) -> dict[tuple[str, str, str], int]:
    return _hamilton_quotas_from_populations({key: len(rows) for key, rows in strata.items()}, sample_size)


def select_enron_sealed_audit_sample(
    records_and_memberships: Iterable[tuple[Mapping[str, Any], Mapping[str, Any]]],
    plan: Mapping[str, Any],
) -> tuple[tuple[dict[str, Any], ...], dict[str, Any]]:
    """Select private sample rows and return a text-free aggregate receipt."""

    validated = validate_enron_sealed_audit_plan(plan)
    limits = validated["resource_limits"]
    plan_sha256 = hash_enron_sealed_audit_plan(validated)
    representatives: dict[str, dict[str, Any]] = {}
    seen_documents: set[str] = set()
    retained_bytes = 0
    input_rows = 0
    input_bytes = 0
    for pair in records_and_memberships:
        input_rows += 1
        if input_rows > validated["frame_documents"] or not isinstance(pair, Sequence) or len(pair) != 2:
            raise EnronSealedAuditError("Sealed-audit input exceeds its row bound or is malformed.")
        record, membership = pair
        if not isinstance(record, Mapping) or not isinstance(membership, Mapping):
            raise EnronSealedAuditError("Sealed-audit input pair is malformed.")
        _reject_prediction_or_label_fields(record)
        input_bytes += len(_canonical_bytes(record)) + len(_canonical_bytes(membership)) + 2
        if input_bytes > limits["max_input_bytes"]:
            raise EnronSealedAuditError("Sealed-audit input exceeds its frozen byte bound.")
        document_id = record.get("document_id")
        views = record.get("views")
        if (
            not isinstance(document_id, str)
            or _DOCUMENT_ID_RE.fullmatch(document_id) is None
            or document_id in seen_documents
            or not isinstance(views, Mapping)
            or not isinstance(views.get("subject_current_body"), str)
        ):
            raise EnronSealedAuditError("Sealed-audit record identity or projection is malformed.")
        seen_documents.add(document_id)
        text = str(views["subject_current_body"])
        text_bytes = len(text.encode("utf-8"))
        if text_bytes > limits["max_projection_bytes"]:
            raise EnronSealedAuditError("Sealed-audit projection exceeds its byte bound.")
        group_id, identity, size, risk = _validate_membership(membership, document_id, text)
        rank = _rank(validated, plan_sha256, document_id)
        candidate = {
            "schema_version": AUDIT_SAMPLE_SCHEMA_VERSION,
            "document_id": document_id,
            "group_id": group_id,
            "text_view": "subject_current_body",
            "text": text,
            "text_sha256": "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "unicode_scalars": len(text),
            "stratum": {"identity": identity, "size": size, "risk": risk},
            "selection_rank_sha256": rank,
            "_text_bytes": text_bytes,
        }
        previous = representatives.get(group_id)
        if previous is None or (rank, document_id) < (previous["selection_rank_sha256"], previous["document_id"]):
            retained_bytes += text_bytes - (0 if previous is None else int(previous["_text_bytes"]))
            if retained_bytes > limits["max_retained_projection_bytes"]:
                raise EnronSealedAuditError("Sealed-audit retained projections exceed their aggregate byte bound.")
            representatives[group_id] = candidate
    if input_rows != validated["frame_documents"]:
        raise EnronSealedAuditError("Sealed-audit input did not consume the complete frozen frame.")
    if len(representatives) != validated["frame_groups"]:
        raise EnronSealedAuditError("Sealed-audit group population differs from the frozen frame.")

    strata: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for candidate in representatives.values():
        descriptor = candidate["stratum"]
        if not isinstance(descriptor, Mapping):
            raise EnronSealedAuditError("Sealed-audit internal stratum descriptor is invalid.")
        key = (str(descriptor["identity"]), str(descriptor["size"]), str(descriptor["risk"]))
        strata[key].append(candidate)
    for rows in strata.values():
        rows.sort(key=lambda row: (row["selection_rank_sha256"], row["document_id"]))
    quotas = _hamilton_quotas(strata, int(validated["sample_size"]))
    selected = [row for key in sorted(strata) for row in strata[key][: quotas[key]]]
    if len(selected) != validated["sample_size"]:
        raise EnronSealedAuditError("Sealed-audit allocation did not fill the exact sample size.")
    private_rows = tuple({key: value for key, value in row.items() if key != "_text_bytes"} for row in selected)
    encoded = b"".join(_canonical_bytes(row) + b"\n" for row in private_rows)
    plan_bytes = _canonical_bytes(validated) + b"\n"
    receipt_core = {
        "schema_version": AUDIT_RECEIPT_SCHEMA_VERSION,
        "fixture_mode": validated["fixture_mode"],
        "promotable": not validated["fixture_mode"],
        "audit_plan_sha256": plan_sha256,
        "selection_policy_sha256": SELECTION_POLICY_SHA256,
        "projection": "views.subject_current_body",
        "input_records": input_rows,
        "input_bytes": input_bytes,
        "population_groups": len(representatives),
        "sample_documents": len(private_rows),
        "plan_artifact": {
            "sha256": "sha256:" + hashlib.sha256(plan_bytes).hexdigest(),
            "bytes": len(plan_bytes),
        },
        "sample_artifact": {
            "sha256": "sha256:" + hashlib.sha256(encoded).hexdigest(),
            "bytes": len(encoded),
            "records": len(private_rows),
        },
        "strata": [
            {
                "identity": key[0],
                "size": key[1],
                "risk": key[2],
                "population_groups": len(strata[key]),
                "base": min(2, len(strata[key])),
                "quota": quotas[key],
            }
            for key in sorted(strata)
        ],
        "privacy": {"aggregate_only": True, "raw_text_included": False, "document_ids_included": False},
    }
    receipt = {
        **receipt_core,
        "audit_output_binding_sha256": _audit_output_binding_sha256(receipt_core),
    }
    return private_rows, receipt


def _validate_plan_target_binding(plan: Mapping[str, Any], frozen_target: Mapping[str, str]) -> None:
    bindings = {
        "test_artifact_sha256": "test_artifact_sha256",
        "split_manifest_sha256": "split_manifest_sha256",
        "frozen_git_commit": "git_commit",
        "bank_sha256": "bank_hash",
        "evaluator_source_sha256": "evaluator_source_sha256",
        "thresholds_sha256": "thresholds_sha256",
        "performance_manifest_sha256": "performance_manifest_sha256",
    }
    if (
        not isinstance(frozen_target, Mapping)
        or any(frozen_target.get(target_field) != plan[plan_field] for plan_field, target_field in bindings.items())
        or frozen_target.get("audit_plan_sha256") != hash_enron_sealed_audit_plan(plan)
    ):
        raise EnronSealedAuditError("Sealed-audit plan differs from the frozen final-test target.")


def _begin_final_test_access(sealed_dir: Path, frozen_target: Mapping[str, str]) -> Any:
    from .enron_splitting import begin_enron_final_test_access

    return begin_enron_final_test_access(sealed_dir, frozen_target=frozen_target)


def _iter_bound_capture_stream(
    pairs: Iterable[tuple[Mapping[str, Any], Mapping[str, Any]]],
    plan: Mapping[str, Any],
) -> Iterable[tuple[Mapping[str, Any], Mapping[str, Any]]]:
    test_digest = hashlib.sha256()
    membership_digest = hashlib.sha256()
    for record, membership in pairs:
        test_digest.update(_canonical_bytes(record) + b"\n")
        membership_digest.update(_canonical_bytes(membership) + b"\n")
        yield record, membership
    if (
        "sha256:" + test_digest.hexdigest() != plan["test_artifact_sha256"]
        or "sha256:" + membership_digest.hexdigest() != plan["membership_artifact_sha256"]
    ):
        raise EnronSealedAuditError("Sealed-audit paired stream differs from its frozen artifact commitments.")


def capture_enron_sealed_audit_sample(
    sealed_dir: Path,
    output_dir: Path,
    *,
    frozen_target: Mapping[str, str],
    plan: Mapping[str, Any],
    allow_unignored_output: bool = False,
) -> dict[str, Any]:
    """Consume one sealed access into an atomically committed private sample run."""

    validated = validate_enron_sealed_audit_plan(plan)
    _validate_plan_target_binding(validated, frozen_target)
    if (
        not isinstance(sealed_dir, Path)
        or not isinstance(output_dir, Path)
        or not isinstance(allow_unignored_output, bool)
    ):
        raise EnronSealedAuditError("Sealed-audit capture options are invalid.")
    plan_sha256 = hash_enron_sealed_audit_plan(validated)
    plan_bytes = _canonical_bytes(validated) + b"\n"
    receipt_bytes = b""
    receipt: dict[str, Any] | None = None
    access_completion: dict[str, Any] | None = None
    try:
        with PrivateRun(output_dir, allow_unignored_output=allow_unignored_output) as run:
            with run.open_binary("plan.json") as handle:
                handle.write(plan_bytes)
            access = _begin_final_test_access(sealed_dir, frozen_target)
            bind = getattr(access, "bind_audit_plan", None)
            if not callable(bind):
                raise EnronSealedAuditError("Final-test access does not support the frozen audit-plan binding.")
            bind(plan_sha256)
            with access as active:
                bound_stream = _iter_bound_capture_stream(active.iter_records_with_memberships(), validated)
                rows, receipt = select_enron_sealed_audit_sample(bound_stream, validated)
                documents_bytes = b"".join(_canonical_bytes(row) + b"\n" for row in rows)
                if receipt["plan_artifact"] != {
                    "sha256": "sha256:" + hashlib.sha256(plan_bytes).hexdigest(),
                    "bytes": len(plan_bytes),
                }:
                    raise EnronSealedAuditError("Sealed-audit plan descriptor changed during capture.")
                if receipt["sample_artifact"] != {
                    "sha256": "sha256:" + hashlib.sha256(documents_bytes).hexdigest(),
                    "bytes": len(documents_bytes),
                    "records": len(rows),
                }:
                    raise EnronSealedAuditError("Sealed-audit sample descriptor changed during capture.")
                receipt_bytes = _canonical_bytes(receipt) + b"\n"
                with run.open_binary("documents.jsonl") as handle:
                    handle.write(documents_bytes)
                with run.open_binary("receipt.json") as handle:
                    handle.write(receipt_bytes)
                run.commit()
                bind_output = getattr(active, "bind_audit_output", None)
                if not callable(bind_output):
                    raise EnronSealedAuditError(
                        "Final-test access does not support the committed audit-output binding."
                    )
                bound_output = bind_output(receipt["audit_output_binding_sha256"])
                expected_bound_output = {
                    "status": "audit_output_bound",
                    "audit_output_binding_sha256": receipt["audit_output_binding_sha256"],
                }
                if bound_output != expected_bound_output:
                    raise EnronSealedAuditError("Final-test access returned an invalid audit-output binding state.")
                access_completion = {
                    "status": "completed",
                    "audit_output_binding_sha256": receipt["audit_output_binding_sha256"],
                }
        assert receipt is not None
        assert access_completion is not None
    except EnronSealedAuditError:
        raise
    except Exception:
        raise EnronSealedAuditError("Sealed-audit capture failed safely.") from None
    return {
        "schema_version": AUDIT_RECEIPT_SCHEMA_VERSION,
        "captured": True,
        "fixture_mode": validated["fixture_mode"],
        "promotable": not validated["fixture_mode"],
        "audit_plan_sha256": plan_sha256,
        "audit_output_binding_sha256": receipt["audit_output_binding_sha256"],
        "access_completion": access_completion,
        "plan_artifact": dict(receipt["plan_artifact"]),
        "sample_artifact": dict(receipt["sample_artifact"]),
        "receipt_artifact": {
            "sha256": "sha256:" + hashlib.sha256(receipt_bytes).hexdigest(),
            "bytes": len(receipt_bytes),
        },
        "privacy": dict(receipt["privacy"]),
    }


def _decode_canonical_object(raw: bytes, *, description: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise EnronSealedAuditError(f"{description} contains duplicate keys.")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except EnronSealedAuditError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        raise EnronSealedAuditError(f"{description} is invalid JSON.") from None
    if not isinstance(value, dict) or raw != _canonical_bytes(value) + b"\n":
        raise EnronSealedAuditError(f"{description} is not one canonical JSON object.")
    return value


def _read_bounded_file_at(directory_fd: int, name: str, maximum: int) -> bytes:
    with open_private_binary_input_at(directory_fd, name) as handle:
        value = handle.read(maximum + 1)
    if len(value) > maximum:
        raise EnronSealedAuditError("Sealed-audit artifact exceeds its frozen byte bound.")
    return value


def _valid_artifact_descriptor(value: Any, *, records: bool) -> bool:
    fields = {"sha256", "bytes", "records"} if records else {"sha256", "bytes"}
    return bool(
        isinstance(value, Mapping)
        and set(value) == fields
        and isinstance(value.get("sha256"), str)
        and _SHA256_RE.fullmatch(value["sha256"]) is not None
        and type(value.get("bytes")) is int
        and value["bytes"] > 0
        and (not records or (type(value.get("records")) is int and value["records"] > 0))
    )


def _verify_receipt_shape(receipt: Mapping[str, Any], plan: Mapping[str, Any]) -> None:
    if (
        set(receipt) != _RECEIPT_FIELDS
        or receipt.get("schema_version") != AUDIT_RECEIPT_SCHEMA_VERSION
        or receipt.get("fixture_mode") is not plan["fixture_mode"]
        or receipt.get("promotable") is not (not plan["fixture_mode"])
        or receipt.get("audit_plan_sha256") != hash_enron_sealed_audit_plan(plan)
        or receipt.get("selection_policy_sha256") != SELECTION_POLICY_SHA256
        or receipt.get("projection") != "views.subject_current_body"
        or receipt.get("input_records") != plan["frame_documents"]
        or type(receipt.get("input_bytes")) is not int
        or not 0 < receipt["input_bytes"] <= plan["resource_limits"]["max_input_bytes"]
        or receipt.get("population_groups") != plan["frame_groups"]
        or receipt.get("sample_documents") != plan["sample_size"]
        or not _valid_artifact_descriptor(receipt.get("plan_artifact"), records=False)
        or not _valid_artifact_descriptor(receipt.get("sample_artifact"), records=True)
        or receipt["sample_artifact"]["records"] != plan["sample_size"]
        or receipt.get("privacy")
        != {"aggregate_only": True, "raw_text_included": False, "document_ids_included": False}
        or not isinstance(receipt.get("strata"), list)
        or not isinstance(receipt.get("audit_output_binding_sha256"), str)
        or _SHA256_RE.fullmatch(receipt["audit_output_binding_sha256"]) is None
    ):
        raise EnronSealedAuditError("Sealed-audit receipt is invalid.")


def _verify_receipt_output_binding(receipt: Mapping[str, Any]) -> str:
    receipt_core = {key: receipt[key] for key in receipt if key != "audit_output_binding_sha256"}
    expected = _audit_output_binding_sha256(receipt_core)
    if receipt.get("audit_output_binding_sha256") != expected:
        raise EnronSealedAuditError("Sealed-audit output binding is invalid.")
    return expected


def _verify_private_sample_rows(
    handle: Any,
    plan: Mapping[str, Any],
) -> tuple[int, int, str, dict[tuple[str, str, str], int]]:
    count = 0
    byte_count = 0
    digest = hashlib.sha256()
    documents: set[str] = set()
    groups: set[str] = set()
    selected: dict[tuple[str, str, str], int] = defaultdict(int)
    plan_sha256 = hash_enron_sealed_audit_plan(plan)
    previous_selection_key: tuple[str, str, str, str, str] | None = None
    line_limit = int(plan["resource_limits"]["max_projection_bytes"]) + 64 * 1024
    while raw := handle.readline(line_limit + 1):
        if len(raw) > line_limit:
            raise EnronSealedAuditError("Sealed-audit sample row exceeds its frozen byte bound.")
        row = _decode_canonical_object(raw, description="Sealed-audit sample row")
        stratum = row.get("stratum")
        document_id = row.get("document_id")
        group_id = row.get("group_id")
        text = row.get("text")
        if (
            set(row) != _SAMPLE_FIELDS
            or row.get("schema_version") != AUDIT_SAMPLE_SCHEMA_VERSION
            or not isinstance(document_id, str)
            or _DOCUMENT_ID_RE.fullmatch(document_id) is None
            or document_id in documents
            or not isinstance(group_id, str)
            or _SHA256_RE.fullmatch(group_id) is None
            or group_id in groups
            or row.get("text_view") != "subject_current_body"
            or not isinstance(text, str)
            or len(text.encode("utf-8")) > plan["resource_limits"]["max_projection_bytes"]
            or row.get("text_sha256") != "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
            or type(row.get("unicode_scalars")) is not int
            or row.get("unicode_scalars") != len(text)
            or not isinstance(stratum, Mapping)
            or set(stratum) != _STRATUM_FIELDS
            or stratum.get("identity") not in _IDENTITY_BANDS
            or stratum.get("size") not in {"short", "medium", "long"}
            or stratum.get("risk") not in {"risk", "ordinary"}
            or not isinstance(row.get("selection_rank_sha256"), str)
            or _SHA256_RE.fullmatch(row["selection_rank_sha256"]) is None
            or row["selection_rank_sha256"] != _rank(plan, plan_sha256, document_id)
        ):
            raise EnronSealedAuditError("Sealed-audit private sample row is invalid.")
        documents.add(document_id)
        groups.add(group_id)
        stratum_key = (str(stratum["identity"]), str(stratum["size"]), str(stratum["risk"]))
        selection_key = (*stratum_key, str(row["selection_rank_sha256"]), document_id)
        if previous_selection_key is not None and selection_key <= previous_selection_key:
            raise EnronSealedAuditError("Sealed-audit private sample rows are not in frozen selection order.")
        previous_selection_key = selection_key
        selected[stratum_key] += 1
        digest.update(raw)
        byte_count += len(raw)
        count += 1
    return count, byte_count, "sha256:" + digest.hexdigest(), dict(selected)


def _verify_strata(
    receipt: Mapping[str, Any],
    plan: Mapping[str, Any],
    selected: Mapping[tuple[str, str, str], int],
) -> None:
    expected_fields = {"identity", "size", "risk", "population_groups", "base", "quota"}
    seen: set[tuple[str, str, str]] = set()
    population = 0
    quota = 0
    previous: tuple[str, str, str] | None = None
    populations: dict[tuple[str, str, str], int] = {}
    for row in receipt["strata"]:
        if not isinstance(row, Mapping) or set(row) != expected_fields:
            raise EnronSealedAuditError("Sealed-audit stratum receipt is invalid.")
        key = (str(row.get("identity")), str(row.get("size")), str(row.get("risk")))
        if (
            key[0] not in _IDENTITY_BANDS
            or key[1] not in {"short", "medium", "long"}
            or key[2] not in {"risk", "ordinary"}
            or key in seen
            or (previous is not None and key <= previous)
            or type(row.get("population_groups")) is not int
            or row["population_groups"] < 1
            or row.get("base") != min(2, row["population_groups"])
            or type(row.get("quota")) is not int
            or not row["base"] <= row["quota"] <= row["population_groups"]
            or selected.get(key, 0) != row["quota"]
        ):
            raise EnronSealedAuditError("Sealed-audit stratum receipt is invalid.")
        seen.add(key)
        populations[key] = row["population_groups"]
        previous = key
        population += row["population_groups"]
        quota += row["quota"]
    if population != plan["frame_groups"] or quota != plan["sample_size"] or set(selected) != seen:
        raise EnronSealedAuditError("Sealed-audit stratum totals are invalid.")
    expected_quotas = _hamilton_quotas_from_populations(populations, int(plan["sample_size"]))
    if any(selected[key] != expected_quotas[key] for key in expected_quotas):
        raise EnronSealedAuditError("Sealed-audit stratum allocation differs from the frozen Hamilton policy.")


def _verify_completed_access_outcome(
    sealed_dir: Path,
    *,
    audit_plan_sha256: str,
    audit_output_binding_sha256: str,
) -> dict[str, Any]:
    from .enron_splitting import EnronSplitError, verify_enron_final_test_access_outcome

    try:
        return verify_enron_final_test_access_outcome(
            sealed_dir,
            expected_audit_plan_sha256=audit_plan_sha256,
            expected_audit_output_binding_sha256=audit_output_binding_sha256,
        )
    except EnronSplitError:
        raise EnronSealedAuditError("Sealed-audit sample does not match the completed sealed access outcome.") from None


def verify_enron_sealed_audit_sample(
    run_dir: Path,
    *,
    expected_audit_output_binding_sha256: str | None = None,
    sealed_dir: Path | None = None,
) -> dict[str, Any]:
    """Deep-verify a committed sample and, for production, its immutable access binding."""

    if (
        not isinstance(run_dir, Path)
        or (sealed_dir is not None and not isinstance(sealed_dir, Path))
        or (
            expected_audit_output_binding_sha256 is not None
            and (
                not isinstance(expected_audit_output_binding_sha256, str)
                or _SHA256_RE.fullmatch(expected_audit_output_binding_sha256) is None
            )
        )
    ):
        raise EnronSealedAuditError("Sealed-audit verification options are invalid.")
    directory_fd: int | None = None
    try:
        directory_fd = open_private_directory_input(run_dir)
        if set(os.listdir(directory_fd)) != {"COMMITTED", "plan.json", "documents.jsonl", "receipt.json"}:
            raise EnronSealedAuditError("Sealed-audit run inventory is invalid.")
        if _read_bounded_file_at(directory_fd, "COMMITTED", 64) != b"nerb.enron.private-run.v2\n":
            raise EnronSealedAuditError("Sealed-audit commit marker is invalid.")
        plan_raw = _read_bounded_file_at(directory_fd, "plan.json", MAX_PLAN_BYTES)
        plan = validate_enron_sealed_audit_plan(_decode_canonical_object(plan_raw, description="Sealed-audit plan"))
        receipt_raw = _read_bounded_file_at(directory_fd, "receipt.json", MAX_RECEIPT_BYTES)
        receipt = _decode_canonical_object(receipt_raw, description="Sealed-audit receipt")
        _verify_receipt_shape(receipt, plan)
        if receipt["plan_artifact"] != {
            "sha256": "sha256:" + hashlib.sha256(plan_raw).hexdigest(),
            "bytes": len(plan_raw),
        }:
            raise EnronSealedAuditError("Sealed-audit physical plan descriptor is invalid.")
        with open_private_binary_input_at(directory_fd, "documents.jsonl") as handle:
            records, sample_bytes, sample_sha256, selected = _verify_private_sample_rows(handle, plan)
        if receipt["sample_artifact"] != {
            "sha256": sample_sha256,
            "bytes": sample_bytes,
            "records": records,
        }:
            raise EnronSealedAuditError("Sealed-audit physical sample descriptor is invalid.")
        _verify_strata(receipt, plan, selected)
        audit_output_binding_sha256 = _verify_receipt_output_binding(receipt)
        if (
            expected_audit_output_binding_sha256 is not None
            and audit_output_binding_sha256 != expected_audit_output_binding_sha256
        ):
            raise EnronSealedAuditError("Sealed-audit sample does not match its trusted audit-output binding.")
        if not plan["fixture_mode"] and expected_audit_output_binding_sha256 is None and sealed_dir is None:
            raise EnronSealedAuditError(
                "Production sealed-audit verification requires a trusted output binding or sealed access outcome."
            )
        access_completion: dict[str, Any] | None = None
        if sealed_dir is not None:
            access_state = _verify_completed_access_outcome(
                sealed_dir,
                audit_plan_sha256=receipt["audit_plan_sha256"],
                audit_output_binding_sha256=audit_output_binding_sha256,
            )
            access_completion = {
                "status": access_state["status"],
                "audit_output_binding_sha256": access_state["audit_output_binding_sha256"],
            }
        return {
            "valid": True,
            "fixture_mode": plan["fixture_mode"],
            "promotable": not plan["fixture_mode"],
            "audit_plan_sha256": receipt["audit_plan_sha256"],
            "audit_output_binding_sha256": audit_output_binding_sha256,
            "access_completion": access_completion,
            "plan_artifact": dict(receipt["plan_artifact"]),
            "sample_artifact": dict(receipt["sample_artifact"]),
            "receipt_artifact": {
                "sha256": "sha256:" + hashlib.sha256(receipt_raw).hexdigest(),
                "bytes": len(receipt_raw),
            },
            "privacy": dict(receipt["privacy"]),
        }
    except EnronSealedAuditError:
        raise
    except (EnronPrivateIOError, OSError, ValueError):
        raise EnronSealedAuditError("Sealed-audit verification failed safely.") from None
    finally:
        if directory_fd is not None:
            os.close(directory_fd)

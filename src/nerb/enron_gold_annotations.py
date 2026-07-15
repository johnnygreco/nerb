"""Independent, prediction-blind gold annotation validation for Enron audits.

The functions in this module operate on private in-memory envelopes.  They do
not scan a bank and they never include text or span surfaces in their result.
File capture and public aggregate export belong to the sealed-audit steward.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .enron_private_io import (
    EnronPrivateIOError,
    PrivateRun,
    is_owner_only_private_mode,
    iter_strict_jsonl,
    open_private_binary_input,
    open_private_binary_input_at,
    open_private_directory_input,
)
from .enron_sealed_audit import (
    AUDIT_RECEIPT_SCHEMA_VERSION,
    AUDIT_SAMPLE_SCHEMA_VERSION,
    EnronSealedAuditError,
    hash_enron_sealed_audit_plan,
    validate_enron_sealed_audit_plan,
    verify_enron_sealed_audit_sample,
)

ANNOTATION_POLICY_SCHEMA_VERSION = "nerb.enron_gold_annotation_policy"
ANNOTATION_PASS_SCHEMA_VERSION = "nerb.enron_gold_annotation_pass"
ADJUDICATION_SCHEMA_VERSION = "nerb.enron_gold_adjudication"
ANNOTATION_REVIEW_SCHEMA_VERSION = "nerb.enron_gold_annotation_review"
GOLD_SCHEMA_VERSION = "nerb.enron_gold"
GOLD_RUN_MANIFEST_SCHEMA_VERSION = "nerb.enron_gold_annotation_run"
GOLD_RUN_RECEIPT_SCHEMA_VERSION = "nerb.enron_gold_annotation_run_receipt"
_GOLD_STATE_SCHEMA_VERSION = "nerb.enron_gold_commitment_state.v1"

_COMMIT_PAYLOAD = b"nerb.enron.private-run.v2\n"
_SAMPLE_RUN_FILES = frozenset({"COMMITTED", "plan.json", "documents.jsonl", "receipt.json"})
_GOLD_RUN_FILES = frozenset(
    {
        "COMMITTED",
        "pass-a.jsonl",
        "pass-b.jsonl",
        "adjudication.jsonl",
        "review.jsonl",
        "gold.jsonl",
        "manifest.json",
        "receipt.json",
    }
)
_ARTIFACT_FILENAMES = {
    "pass_a": "pass-a.jsonl",
    "pass_b": "pass-b.jsonl",
    "adjudication": "adjudication.jsonl",
    "review": "review.jsonl",
    "gold": "gold.jsonl",
}
_CAPTURED_DOCUMENT_FIELDS = frozenset(
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
_SAMPLE_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "fixture_mode",
        "promotable",
        "audit_output_binding_sha256",
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
    }
)
_PLAN_ARTIFACT_FIELDS = frozenset({"sha256", "bytes"})
_SAMPLE_ARTIFACT_FIELDS = frozenset({"sha256", "bytes", "records"})
_MAX_JSON_FILE_BYTES = 16 * 1024 * 1024
_MAX_JSONL_LINE_BYTES = 16 * 1024 * 1024
_MAX_ANNOTATION_ROWS = 10_000
_GOLD_COMMITMENT_FIELDS = frozenset({"gold_sha256", "manifest_sha256", "artifacts_sha256"})

ENTITY_CLASSES = ("contact", "person")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_PASS_FIELDS = frozenset(
    {
        "schema_version",
        "document_id",
        "text_sha256",
        "reviewer_id",
        "coverage",
        "spans",
        "unresolved",
    }
)
_ADJUDICATION_FIELDS = frozenset(
    {
        "schema_version",
        "document_id",
        "text_sha256",
        "adjudicator_id",
        "spans",
        "decisions",
        "unresolved",
    }
)
_REVIEW_FIELDS = frozenset(
    {
        "schema_version",
        "document_id",
        "text_sha256",
        "reviewer_id",
        "adjudication_sha256",
        "disagreements_reviewed",
        "agreement_audit",
        "status",
        "unresolved",
    }
)
_SPAN_FIELDS = frozenset({"entity_class", "start", "end"})
_DECISION_FIELDS = frozenset({"entity_class", "start", "end", "resolution", "reason_code"})
_COVERAGE_FIELDS = frozenset({"start", "end"})

ANNOTATION_POLICY: dict[str, Any] = {
    "schema_version": ANNOTATION_POLICY_SCHEMA_VERSION,
    "text_view": "subject_current_body",
    "offset_unit": "unicode_scalar",
    "entity_classes": list(ENTITY_CLASSES),
    "person": {
        "include": [
            "explicit_human_names",
            "unambiguous_single_names",
            "initials",
            "nicknames",
            "misspellings",
            "signature_names",
        ],
        "exclude": [
            "pronouns",
            "role_only_terms",
            "honorific_only_terms",
            "organization_or_location_only_uses",
            "substrings_inside_contact_spans",
        ],
    },
    "contact": {
        "include": ["exact_contiguous_email_address"],
        "exclude_from_boundary": ["mailto_prefix", "angle_brackets", "whitespace", "surrounding_punctuation"],
        "exclude": ["malformed_or_obfuscated_address"],
    },
    "passes": 2,
    "pass_visibility": "text_and_policy_only",
    "adjudication_visibility": "text_policy_and_blind_passes_only",
    "prediction_visibility": "forbidden_until_gold_and_catalog_bindings_are_immutable",
    "review": {
        "all_disagreements": True,
        "agreement_document_fraction": 0.2,
        "selection": "domain_separated_min_sha256",
    },
    "unresolved_policy": "fail_closed",
}


class EnronGoldAnnotationError(ValueError):
    """Raised when private gold annotation evidence is incomplete or invalid."""


def enron_gold_annotation_policy_sha256() -> str:
    """Return the canonical commitment to the frozen annotation semantics."""

    return _canonical_hash(ANNOTATION_POLICY)


def hash_enron_gold_adjudication(adjudication: Mapping[str, Any]) -> str:
    """Commit one normalized adjudication decision for independent review."""

    if not isinstance(adjudication, Mapping) or set(adjudication) != _ADJUDICATION_FIELDS:
        raise EnronGoldAnnotationError("Adjudication commitment schema is invalid.")
    if adjudication.get("schema_version") != ADJUDICATION_SCHEMA_VERSION:
        raise EnronGoldAnnotationError("Adjudication commitment version is invalid.")
    document_id = _identifier(adjudication.get("document_id"), "document_id")
    text_sha256 = adjudication.get("text_sha256")
    if not isinstance(text_sha256, str) or _SHA256_RE.fullmatch(text_sha256) is None:
        raise EnronGoldAnnotationError("Adjudication commitment text binding is invalid.")
    spans = adjudication.get("spans")
    decisions = adjudication.get("decisions")
    unresolved = adjudication.get("unresolved")
    if not isinstance(spans, list) or not isinstance(decisions, list):
        raise EnronGoldAnnotationError("Adjudication commitment spans and decisions must be lists.")
    if not isinstance(unresolved, list) or unresolved:
        raise EnronGoldAnnotationError("Adjudication commitment must have zero unresolved items.")
    normalized_spans: list[dict[str, Any]] = []
    for value in spans:
        if (
            not isinstance(value, Mapping)
            or set(value) != _SPAN_FIELDS
            or not isinstance(value["entity_class"], str)
            or type(value["start"]) is not int
            or type(value["end"]) is not int
        ):
            raise EnronGoldAnnotationError("Adjudication commitment span is invalid.")
        normalized_spans.append({"entity_class": value["entity_class"], "start": value["start"], "end": value["end"]})
    normalized_spans.sort(key=lambda value: (value["start"], value["end"], value["entity_class"]))
    normalized_decisions: list[dict[str, Any]] = []
    for value in decisions:
        if (
            not isinstance(value, Mapping)
            or set(value) != _DECISION_FIELDS
            or not isinstance(value["entity_class"], str)
            or type(value["start"]) is not int
            or type(value["end"]) is not int
            or not isinstance(value["resolution"], str)
            or not isinstance(value["reason_code"], str)
        ):
            raise EnronGoldAnnotationError("Adjudication commitment decision is invalid.")
        normalized_decisions.append(
            {
                "entity_class": value["entity_class"],
                "start": value["start"],
                "end": value["end"],
                "resolution": value["resolution"],
                "reason_code": value["reason_code"],
            }
        )
    normalized_decisions.sort(
        key=lambda value: (
            value["start"],
            value["end"],
            value["entity_class"],
            value["resolution"],
            value["reason_code"],
        )
    )
    return _canonical_hash(
        {
            "schema_version": ADJUDICATION_SCHEMA_VERSION,
            "document_id": document_id,
            "text_sha256": text_sha256,
            "spans": normalized_spans,
            "decisions": normalized_decisions,
            "unresolved": list(unresolved),
        }
    )


def build_enron_gold(
    documents: Sequence[Mapping[str, Any]],
    pass_a: Sequence[Mapping[str, Any]],
    pass_b: Sequence[Mapping[str, Any]],
    adjudications: Sequence[Mapping[str, Any]],
    reviews: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Validate two blind passes, adjudication, and review into private gold.

    ``documents`` may contain text because it is a private input.  Returned
    gold contains only document commitments and coordinates, never text or
    surfaces.
    """

    normalized_documents = _prepare_documents(documents)
    document_ids = tuple(sorted(normalized_documents))
    first, first_reviewers = _prepare_pass("A", pass_a, normalized_documents)
    second, second_reviewers = _prepare_pass("B", pass_b, normalized_documents)
    if first_reviewers & second_reviewers:
        raise EnronGoldAnnotationError("Blind annotation passes must use distinct reviewer identities.")
    final, adjudicators, adjudication_commitments, required_reviews, disagreement_count, decision_count = (
        _prepare_adjudications(
            adjudications,
            normalized_documents,
            first,
            second,
        )
    )
    if (first_reviewers | second_reviewers) & adjudicators:
        raise EnronGoldAnnotationError("Adjudicators must be distinct from both blind annotation passes.")

    sample_binding_sha256 = _canonical_hash(
        {
            "schema_version": "nerb.enron_gold_sample_binding",
            "documents": [
                {
                    "document_id": document_id,
                    "text_sha256": normalized_documents[document_id]["text_sha256"],
                    "unicode_scalars": normalized_documents[document_id]["unicode_scalars"],
                }
                for document_id in document_ids
            ],
        }
    )
    agreement_documents = {document_id for document_id in document_ids if first[document_id] == second[document_id]}
    reviewed_by, agreement_audits = _prepare_reviews(
        reviews,
        normalized_documents,
        required_reviews,
        agreement_documents,
        sample_binding_sha256,
        adjudication_commitments,
    )
    if (first_reviewers | second_reviewers | adjudicators) & reviewed_by:
        raise EnronGoldAnnotationError(
            "Independent review identities must be distinct from annotators and adjudicators."
        )

    gold_documents = []
    class_spans: Counter[str] = Counter()
    class_positive_documents: Counter[str] = Counter()
    class_sensitive_characters: Counter[str] = Counter()
    combined_positive_documents = 0
    combined_sensitive_characters = 0
    for document_id in document_ids:
        spans = final[document_id]
        per_class = Counter(span[0] for span in spans)
        for entity_class in ENTITY_CLASSES:
            class_spans[entity_class] += per_class[entity_class]
            if per_class[entity_class]:
                class_positive_documents[entity_class] += 1
        if spans:
            combined_positive_documents += 1
        covered_by_class: dict[str, set[int]] = {entity_class: set() for entity_class in ENTITY_CLASSES}
        covered_combined: set[int] = set()
        for entity_class, start, end in spans:
            covered_by_class[entity_class].update(range(start, end))
            covered_combined.update(range(start, end))
        for entity_class in ENTITY_CLASSES:
            class_sensitive_characters[entity_class] += len(covered_by_class[entity_class])
        combined_sensitive_characters += len(covered_combined)
        gold_documents.append(
            {
                "document_id": document_id,
                "text_sha256": normalized_documents[document_id]["text_sha256"],
                "unicode_scalars": normalized_documents[document_id]["unicode_scalars"],
                "spans": [_span_payload(span) for span in spans],
            }
        )

    counts = {
        "documents": len(document_ids),
        "documents_with_sensitive_gold": combined_positive_documents,
        "negative_documents": len(document_ids) - combined_positive_documents,
        "gold_spans": sum(class_spans.values()),
        "sensitive_gold_characters": combined_sensitive_characters,
        "by_class": {
            entity_class: {
                "documents_with_sensitive_gold": class_positive_documents[entity_class],
                "negative_documents": len(document_ids) - class_positive_documents[entity_class],
                "gold_spans": class_spans[entity_class],
                "sensitive_gold_characters": class_sensitive_characters[entity_class],
            }
            for entity_class in ENTITY_CLASSES
        },
    }
    provenance = {
        "annotation_passes": 2,
        "pass_a_reviewers": len(first_reviewers),
        "pass_b_reviewers": len(second_reviewers),
        "adjudicators": len(adjudicators),
        "independent_reviewers": len(reviewed_by),
        "disagreements": disagreement_count,
        "adjudication_decisions": decision_count,
        "agreement_audit_documents": agreement_audits,
        "full_character_coverage": True,
        "unresolved": 0,
    }
    core = {
        "schema_version": GOLD_SCHEMA_VERSION,
        "annotation_policy_sha256": enron_gold_annotation_policy_sha256(),
        "sample_binding_sha256": sample_binding_sha256,
        "documents": gold_documents,
        "counts": counts,
        "provenance": provenance,
    }
    return {**core, "gold_sha256": _canonical_hash(core)}


def public_enron_gold_receipt(gold: Mapping[str, Any]) -> dict[str, Any]:
    """Project validated private gold into a path- and identifier-free receipt."""

    if not isinstance(gold, Mapping) or set(gold) != {
        "schema_version",
        "annotation_policy_sha256",
        "sample_binding_sha256",
        "documents",
        "counts",
        "provenance",
        "gold_sha256",
    }:
        raise EnronGoldAnnotationError("Gold artifact schema is invalid.")
    core = {key: gold[key] for key in gold if key != "gold_sha256"}
    if gold["gold_sha256"] != _canonical_hash(core):
        raise EnronGoldAnnotationError("Gold artifact commitment is invalid.")
    return {
        "schema_version": "nerb.enron_gold_public_receipt",
        "annotation_policy_sha256": gold["annotation_policy_sha256"],
        "sample_binding_sha256": gold["sample_binding_sha256"],
        "gold_sha256": gold["gold_sha256"],
        "counts": gold["counts"],
        "provenance": gold["provenance"],
        "privacy": {
            "raw_text_included": False,
            "document_ids_included": False,
            "span_surfaces_included": False,
            "private_paths_included": False,
        },
    }


def finalize_enron_gold_annotations_files(
    sample_run_dir: Path,
    pass_a_path: Path,
    pass_b_path: Path,
    adjudication_path: Path,
    review_path: Path,
    output_dir: Path,
    *,
    expected_audit_output_binding_sha256: str | None = None,
    gold_state_dir: Path | None = None,
    allow_unignored_output: bool = False,
) -> dict[str, Any]:
    """Validate and transactionally capture one prediction-blind gold bundle.

    The returned receipt is aggregate-only.  Full annotation rows and gold
    coordinates remain inside the owner-only committed run.
    """

    try:
        documents, sample_binding = _load_sample_run(
            Path(sample_run_dir),
            expected_audit_output_binding_sha256=expected_audit_output_binding_sha256,
        )
        if not sample_binding["fixture_mode"] and gold_state_dir is None:
            raise EnronGoldAnnotationError("Production gold finalization requires an explicit gold-state directory.")
        if gold_state_dir is not None:
            state_directory_fd = _open_gold_state_directory(Path(gold_state_dir))
            os.close(state_directory_fd)
        source_rows = {
            "pass_a": _load_annotation_rows(Path(pass_a_path), "Annotation pass A"),
            "pass_b": _load_annotation_rows(Path(pass_b_path), "Annotation pass B"),
            "adjudication": _load_annotation_rows(Path(adjudication_path), "Adjudications"),
            "review": _load_annotation_rows(Path(review_path), "Annotation reviews"),
        }
        gold = build_enron_gold(
            documents,
            source_rows["pass_a"],
            source_rows["pass_b"],
            source_rows["adjudication"],
            source_rows["review"],
        )
        canonical_rows = {
            key: tuple(sorted(rows, key=lambda row: str(row["document_id"]))) for key, rows in source_rows.items()
        }
        gold_rows = tuple(gold["documents"])
        payloads = {
            key: _canonical_jsonl(rows)
            for key, rows in {
                **canonical_rows,
                "gold": gold_rows,
            }.items()
        }
        artifacts = {
            key: _artifact_descriptor(_ARTIFACT_FILENAMES[key], payload, len(canonical_rows.get(key, gold_rows)))
            for key, payload in payloads.items()
        }
        manifest = _gold_run_manifest(sample_binding, artifacts, gold)
        receipt = _gold_run_receipt(manifest)

        with PrivateRun(Path(output_dir), allow_unignored_output=allow_unignored_output) as run:
            for key in ("pass_a", "pass_b", "adjudication", "review", "gold"):
                with run.open_binary(_ARTIFACT_FILENAMES[key]) as file:
                    file.write(payloads[key])
            with run.open_binary("manifest.json") as file:
                file.write(_canonical_json_file(manifest))
            with run.open_binary("receipt.json") as file:
                file.write(_canonical_json_file(receipt))
            run.commit()
        if gold_state_dir is not None:
            _register_gold_commitment(Path(gold_state_dir), receipt)
        return _detached_mapping(receipt)
    except EnronGoldAnnotationError:
        raise
    except (EnronPrivateIOError, EnronSealedAuditError, OSError, TypeError, ValueError):
        raise EnronGoldAnnotationError("Gold annotation files could not be finalized safely.") from None


def verify_enron_gold_annotations(
    run_dir: Path,
    sample_run_dir: Path,
    *,
    expected_audit_output_binding_sha256: str | None = None,
    expected_gold_commitment: Mapping[str, str] | None = None,
    gold_state_dir: Path | None = None,
) -> dict[str, Any]:
    """Deep-verify one committed gold bundle and return aggregate-only evidence."""

    try:
        documents, sample_binding = _load_sample_run(
            Path(sample_run_dir),
            expected_audit_output_binding_sha256=expected_audit_output_binding_sha256,
        )
        root = _validate_private_run_tree(Path(run_dir), _GOLD_RUN_FILES, "Gold annotation run")
        manifest, manifest_raw = _load_strict_json_object(root / "manifest.json", "Gold annotation manifest")
        receipt, receipt_raw = _load_strict_json_object(root / "receipt.json", "Gold annotation receipt")
        if manifest_raw != _canonical_json_file(manifest) or receipt_raw != _canonical_json_file(receipt):
            raise EnronGoldAnnotationError("Gold annotation metadata is not canonically encoded.")

        loaded_rows: dict[str, list[dict[str, Any]]] = {}
        artifacts: dict[str, dict[str, Any]] = {}
        for key, name in _ARTIFACT_FILENAMES.items():
            rows, descriptor = _load_jsonl(root / name, description=f"Gold annotation {key}", require_canonical=True)
            if key != "gold" and rows != sorted(rows, key=lambda row: str(row.get("document_id"))):
                raise EnronGoldAnnotationError(f"Gold annotation {key} rows are not in canonical order.")
            loaded_rows[key] = rows
            artifacts[key] = {"name": name, **descriptor}

        gold = build_enron_gold(
            documents,
            loaded_rows["pass_a"],
            loaded_rows["pass_b"],
            loaded_rows["adjudication"],
            loaded_rows["review"],
        )
        expected_gold_rows = tuple(gold["documents"])
        if loaded_rows["gold"] != list(expected_gold_rows):
            raise EnronGoldAnnotationError("Stored gold rows differ from deterministic annotation replay.")
        expected_gold_payload = _canonical_jsonl(expected_gold_rows)
        if artifacts["gold"] != {
            "name": _ARTIFACT_FILENAMES["gold"],
            **_artifact_descriptor_without_name(expected_gold_payload, len(expected_gold_rows)),
        }:
            raise EnronGoldAnnotationError("Stored gold artifact commitment is invalid.")

        expected_manifest = _gold_run_manifest(sample_binding, artifacts, gold)
        if manifest != expected_manifest:
            raise EnronGoldAnnotationError("Gold annotation manifest differs from deterministic replay.")
        expected_receipt = _gold_run_receipt(expected_manifest)
        if receipt != expected_receipt:
            raise EnronGoldAnnotationError("Gold annotation receipt differs from deterministic replay.")
        _validate_expected_gold_commitment(expected_receipt, expected_gold_commitment)
        _verify_registered_gold_commitment(gold_state_dir, expected_receipt)
        return _detached_mapping(expected_receipt)
    except EnronGoldAnnotationError:
        raise
    except (EnronPrivateIOError, EnronSealedAuditError, OSError, TypeError, ValueError):
        raise EnronGoldAnnotationError("Gold annotation run could not be verified safely.") from None


def _load_sample_run(
    sample_run_dir: Path,
    *,
    expected_audit_output_binding_sha256: str | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    root = _validate_private_run_tree(sample_run_dir, _SAMPLE_RUN_FILES, "Sealed-audit sample run")
    plan, plan_raw = _load_strict_json_object(root / "plan.json", "Sealed-audit plan")
    receipt, receipt_raw = _load_strict_json_object(root / "receipt.json", "Sealed-audit receipt")
    if plan_raw != _canonical_json_file(plan) or receipt_raw != _canonical_json_file(receipt):
        raise EnronGoldAnnotationError("Sealed-audit plan or receipt is not canonically encoded.")
    validated_plan = validate_enron_sealed_audit_plan(plan)
    audit_plan_sha256 = hash_enron_sealed_audit_plan(validated_plan)
    if validated_plan.get("annotation_policy_sha256") != enron_gold_annotation_policy_sha256():
        raise EnronGoldAnnotationError("Sealed-audit plan binds a different annotation policy.")
    _validate_sample_receipt(receipt, validated_plan, plan_raw, receipt_raw, audit_plan_sha256)
    output_binding = receipt["audit_output_binding_sha256"]
    if expected_audit_output_binding_sha256 is not None and (
        not isinstance(expected_audit_output_binding_sha256, str)
        or _SHA256_RE.fullmatch(expected_audit_output_binding_sha256) is None
        or expected_audit_output_binding_sha256 != output_binding
    ):
        raise EnronGoldAnnotationError("Trusted sealed-audit output binding is invalid or does not match.")
    if not validated_plan["fixture_mode"] and expected_audit_output_binding_sha256 is None:
        raise EnronGoldAnnotationError("Production gold finalization requires a trusted sealed-audit output binding.")
    verification = verify_enron_sealed_audit_sample(
        sample_run_dir,
        expected_audit_output_binding_sha256=expected_audit_output_binding_sha256,
    )
    if not isinstance(verification, Mapping) or verification.get("valid") is not True:
        raise EnronGoldAnnotationError("Sealed-audit sample verification did not succeed.")

    documents, sample_descriptor = _load_jsonl(
        root / "documents.jsonl",
        description="Sealed-audit documents",
        require_canonical=True,
    )
    _validate_captured_documents(documents)
    expected_sample = receipt["sample_artifact"]
    if sample_descriptor != expected_sample:
        raise EnronGoldAnnotationError("Sealed-audit document artifact differs from its receipt.")
    if len(documents) != validated_plan["sample_size"] or len(documents) != receipt["sample_documents"]:
        raise EnronGoldAnnotationError("Sealed-audit document count differs from the frozen plan.")
    if verification.get("audit_plan_sha256") != audit_plan_sha256:
        raise EnronGoldAnnotationError("Sealed-audit verification returned a different plan binding.")
    if verification.get("audit_output_binding_sha256") != receipt["audit_output_binding_sha256"]:
        raise EnronGoldAnnotationError("Sealed-audit verification returned a different output binding.")

    sample_binding = {
        "audit_plan_sha256": audit_plan_sha256,
        "audit_output_binding_sha256": receipt["audit_output_binding_sha256"],
        "audit_execution_policy_sha256": validated_plan["audit_execution_policy_sha256"],
        "annotation_policy_sha256": validated_plan["annotation_policy_sha256"],
        "catalog_policy_sha256": validated_plan["catalog_policy_sha256"],
        "bank_sha256": validated_plan["bank_sha256"],
        "evaluator_source_sha256": validated_plan["evaluator_source_sha256"],
        "thresholds_sha256": validated_plan["thresholds_sha256"],
        "plan_artifact": dict(receipt["plan_artifact"]),
        "sample_artifact": dict(receipt["sample_artifact"]),
        "receipt_artifact": _artifact_descriptor_without_name(receipt_raw, 1),
        "fixture_mode": validated_plan["fixture_mode"],
        "promotable": receipt["promotable"],
    }
    return documents, sample_binding


def _validate_sample_receipt(
    receipt: Mapping[str, Any],
    plan: Mapping[str, Any],
    plan_raw: bytes,
    receipt_raw: bytes,
    audit_plan_sha256: str,
) -> None:
    del receipt_raw
    if set(receipt) != _SAMPLE_RECEIPT_FIELDS or receipt.get("schema_version") != AUDIT_RECEIPT_SCHEMA_VERSION:
        raise EnronGoldAnnotationError("Sealed-audit receipt schema is invalid.")
    plan_artifact = receipt.get("plan_artifact")
    sample_artifact = receipt.get("sample_artifact")
    if (
        not isinstance(plan_artifact, Mapping)
        or set(plan_artifact) != _PLAN_ARTIFACT_FIELDS
        or not isinstance(sample_artifact, Mapping)
        or set(sample_artifact) != _SAMPLE_ARTIFACT_FIELDS
    ):
        raise EnronGoldAnnotationError("Sealed-audit receipt artifact descriptors are invalid.")
    expected_plan_artifact = _artifact_descriptor_without_name(plan_raw, 1)
    expected_plan_artifact.pop("records")
    fixture_mode = plan["fixture_mode"]
    if (
        receipt.get("audit_plan_sha256") != audit_plan_sha256
        or plan_artifact != expected_plan_artifact
        or receipt.get("projection") != "views.subject_current_body"
        or not isinstance(receipt.get("audit_output_binding_sha256"), str)
        or _SHA256_RE.fullmatch(str(receipt["audit_output_binding_sha256"])) is None
        or receipt.get("fixture_mode") is not fixture_mode
        or receipt.get("promotable") is not (not fixture_mode)
        or receipt.get("privacy")
        != {"aggregate_only": True, "raw_text_included": False, "document_ids_included": False}
    ):
        raise EnronGoldAnnotationError("Sealed-audit receipt binding or privacy envelope is invalid.")


def _validate_captured_documents(documents: Sequence[Mapping[str, Any]]) -> None:
    document_ids: set[str] = set()
    group_ids: set[str] = set()
    ranks: set[str] = set()
    for index, row in enumerate(documents):
        if not isinstance(row, Mapping) or set(row) != _CAPTURED_DOCUMENT_FIELDS:
            raise EnronGoldAnnotationError(f"Captured document row {index} schema is invalid.")
        document_id = _identifier(row["document_id"], "document_id")
        group_id = row["group_id"]
        rank = row["selection_rank_sha256"]
        text = row["text"]
        text_sha256 = row["text_sha256"]
        unicode_scalars = row["unicode_scalars"]
        stratum = row["stratum"]
        if (
            row["schema_version"] != AUDIT_SAMPLE_SCHEMA_VERSION
            or not isinstance(group_id, str)
            or _SHA256_RE.fullmatch(group_id) is None
            or row["text_view"] != "subject_current_body"
            or not isinstance(text, str)
            or not isinstance(text_sha256, str)
            or _SHA256_RE.fullmatch(text_sha256) is None
            or text_sha256 != _hash_bytes(text.encode("utf-8"))
            or type(unicode_scalars) is not int
            or unicode_scalars != len(text)
            or not isinstance(rank, str)
            or _SHA256_RE.fullmatch(rank) is None
            or not isinstance(stratum, Mapping)
            or set(stratum) != _STRATUM_FIELDS
            or stratum["identity"] not in {"all_known", "mixed", "all_novel", "unavailable"}
            or stratum["size"] not in {"short", "medium", "long"}
            or stratum["risk"] not in {"risk", "ordinary"}
        ):
            raise EnronGoldAnnotationError(f"Captured document row {index} value is invalid.")
        if document_id in document_ids or group_id in group_ids or rank in ranks:
            raise EnronGoldAnnotationError("Captured document, group, and selection-rank identities must be unique.")
        document_ids.add(document_id)
        group_ids.add(group_id)
        ranks.add(rank)
    if not documents:
        raise EnronGoldAnnotationError("Captured documents must not be empty.")


def _load_annotation_rows(path: Path, description: str) -> list[dict[str, Any]]:
    rows, _descriptor = _load_jsonl(path, description=description, require_canonical=False)
    if not rows:
        raise EnronGoldAnnotationError(f"{description} must not be empty.")
    return rows


def _load_jsonl(
    path: Path,
    *,
    description: str,
    require_canonical: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    digest = hashlib.sha256()
    byte_count = 0
    try:
        for line_no, raw, row in iter_strict_jsonl(path, _MAX_JSONL_LINE_BYTES):
            if line_no > _MAX_ANNOTATION_ROWS:
                raise EnronGoldAnnotationError(f"{description} exceeds the row limit.")
            detached = dict(row)
            if require_canonical and raw != _canonical_bytes(detached) + b"\n":
                raise EnronGoldAnnotationError(f"{description} row {line_no} is not canonically encoded.")
            rows.append(detached)
            digest.update(raw)
            byte_count += len(raw)
    except EnronPrivateIOError:
        raise EnronGoldAnnotationError(f"{description} is not valid private JSONL.") from None
    return rows, {"sha256": "sha256:" + digest.hexdigest(), "bytes": byte_count, "records": len(rows)}


def _validate_private_run_tree(path: Path, expected: frozenset[str], description: str) -> Path:
    root = _absolute_path(path)
    directory_fd: int | None = None
    try:
        directory_fd = open_private_directory_input(root)
        root_info = os.fstat(directory_fd)
        if stat.S_IMODE(root_info.st_mode) != 0o700 or root_info.st_uid != os.geteuid():
            raise EnronGoldAnnotationError(f"{description} directory permissions are invalid.")
        if set(os.listdir(directory_fd)) != expected:
            raise EnronGoldAnnotationError(f"{description} inventory is invalid.")
        for name in expected:
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or not is_owner_only_private_mode(stat.S_IMODE(info.st_mode))
            ):
                raise EnronGoldAnnotationError(f"{description} artifact permissions or identity are invalid.")
        with open_private_binary_input_at(directory_fd, "COMMITTED") as marker:
            if marker.read(len(_COMMIT_PAYLOAD) + 1) != _COMMIT_PAYLOAD:
                raise EnronGoldAnnotationError(f"{description} commit marker is invalid.")
    except EnronGoldAnnotationError:
        raise
    except (EnronPrivateIOError, OSError, ValueError):
        raise EnronGoldAnnotationError(f"{description} could not be opened safely.") from None
    finally:
        if directory_fd is not None:
            os.close(directory_fd)
    return root


def _absolute_path(path: Path) -> Path:
    candidate = Path(path).expanduser()
    if any(part == os.pardir for part in candidate.parts):
        raise EnronGoldAnnotationError("Private paths must not contain parent traversal.")
    return candidate if candidate.is_absolute() else Path.cwd() / candidate


def _load_strict_json_object(path: Path, description: str) -> tuple[dict[str, Any], bytes]:
    try:
        with open_private_binary_input(path) as file:
            raw = file.read(_MAX_JSON_FILE_BYTES + 1)
    except EnronPrivateIOError:
        raise EnronGoldAnnotationError(f"{description} could not be opened safely.") from None
    if len(raw) > _MAX_JSON_FILE_BYTES:
        raise EnronGoldAnnotationError(f"{description} exceeds the byte limit.")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise EnronGoldAnnotationError(f"{description} is not strict JSON.") from None
    if not isinstance(value, dict):
        raise EnronGoldAnnotationError(f"{description} must contain a JSON object.")
    return value, raw


def _reject_duplicate_pairs(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = child
    return value


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _canonical_json_file(value: Any) -> bytes:
    return _canonical_bytes(value) + b"\n"


def _canonical_jsonl(rows: Sequence[Mapping[str, Any]]) -> bytes:
    return b"".join(_canonical_bytes(row) + b"\n" for row in rows)


def _artifact_descriptor(name: str, payload: bytes, records: int) -> dict[str, Any]:
    return {"name": name, **_artifact_descriptor_without_name(payload, records)}


def _artifact_descriptor_without_name(payload: bytes, records: int) -> dict[str, Any]:
    return {"sha256": _hash_bytes(payload), "bytes": len(payload), "records": records}


def _gold_run_manifest(
    sample_binding: Mapping[str, Any],
    artifacts: Mapping[str, Mapping[str, Any]],
    gold: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": GOLD_RUN_MANIFEST_SCHEMA_VERSION,
        "sample_binding": _detached_mapping(sample_binding),
        "annotation_policy_sha256": gold["annotation_policy_sha256"],
        "planned_evaluator_source_sha256": sample_binding["evaluator_source_sha256"],
        "planned_thresholds_sha256": sample_binding["thresholds_sha256"],
        "gold_schema_version": gold["schema_version"],
        "sample_binding_sha256": gold["sample_binding_sha256"],
        "gold_sha256": gold["gold_sha256"],
        "artifacts": {key: _detached_mapping(artifacts[key]) for key in sorted(artifacts)},
        "counts": _detached_mapping(gold["counts"]),
        "provenance": _detached_mapping(gold["provenance"]),
    }


def _gold_run_receipt(manifest: Mapping[str, Any]) -> dict[str, Any]:
    sample_binding = manifest["sample_binding"]
    if not isinstance(sample_binding, Mapping):
        raise EnronGoldAnnotationError("Gold annotation manifest sample binding is invalid.")
    plan_artifact = sample_binding["plan_artifact"]
    sample_artifact = sample_binding["sample_artifact"]
    receipt_artifact = sample_binding["receipt_artifact"]
    if not all(isinstance(value, Mapping) for value in (plan_artifact, sample_artifact, receipt_artifact)):
        raise EnronGoldAnnotationError("Gold annotation manifest sample artifacts are invalid.")
    return {
        "schema_version": GOLD_RUN_RECEIPT_SCHEMA_VERSION,
        "valid": True,
        "fixture_mode": sample_binding["fixture_mode"],
        "promotable": sample_binding["promotable"],
        "audit_plan_sha256": sample_binding["audit_plan_sha256"],
        "audit_output_binding_sha256": sample_binding["audit_output_binding_sha256"],
        "audit_execution_policy_sha256": sample_binding["audit_execution_policy_sha256"],
        "catalog_policy_sha256": sample_binding["catalog_policy_sha256"],
        "planned_bank_sha256": sample_binding["bank_sha256"],
        "planned_evaluator_source_sha256": manifest["planned_evaluator_source_sha256"],
        "planned_thresholds_sha256": manifest["planned_thresholds_sha256"],
        "sample_plan_artifact_sha256": plan_artifact["sha256"],
        "sample_artifact_sha256": sample_artifact["sha256"],
        "sample_receipt_artifact_sha256": receipt_artifact["sha256"],
        "annotation_policy_sha256": manifest["annotation_policy_sha256"],
        "sample_binding_sha256": manifest["sample_binding_sha256"],
        "gold_sha256": manifest["gold_sha256"],
        "manifest_sha256": _canonical_hash(manifest),
        "artifacts_sha256": _canonical_hash(manifest["artifacts"]),
        "counts": _detached_mapping(manifest["counts"]),
        "provenance": _detached_mapping(manifest["provenance"]),
        "privacy": {
            "aggregate_only": True,
            "raw_text_included": False,
            "document_ids_included": False,
            "reviewer_ids_included": False,
            "span_coordinates_included": False,
            "span_surfaces_included": False,
            "private_paths_included": False,
        },
    }


def _detached_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    detached = json.loads(_canonical_bytes(value))
    if not isinstance(detached, dict):
        raise EnronGoldAnnotationError("Canonical object projection failed.")
    return detached


def _validate_expected_gold_commitment(
    receipt: Mapping[str, Any],
    expected_gold_commitment: Mapping[str, str] | None,
) -> None:
    actual = {key: receipt.get(key) for key in sorted(_GOLD_COMMITMENT_FIELDS)}
    if any(not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None for value in actual.values()):
        raise EnronGoldAnnotationError("Gold receipt commitments are invalid.")
    if expected_gold_commitment is None:
        if receipt.get("fixture_mode") is not True:
            raise EnronGoldAnnotationError("Production gold verification requires an explicit trusted gold commitment.")
        return
    if (
        not isinstance(expected_gold_commitment, Mapping)
        or set(expected_gold_commitment) != _GOLD_COMMITMENT_FIELDS
        or any(
            not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None
            for value in expected_gold_commitment.values()
        )
        or dict(expected_gold_commitment) != actual
    ):
        raise EnronGoldAnnotationError("Trusted gold commitment is invalid or does not match deterministic replay.")


def _gold_commitment(receipt: Mapping[str, Any]) -> dict[str, str]:
    commitment = {key: receipt.get(key) for key in sorted(_GOLD_COMMITMENT_FIELDS)}
    if any(not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None for value in commitment.values()):
        raise EnronGoldAnnotationError("Gold receipt commitments are invalid.")
    return {key: str(commitment[key]) for key in sorted(commitment)}


def _expected_gold_state(receipt: Mapping[str, Any]) -> dict[str, Any]:
    audit_plan_sha256 = receipt.get("audit_plan_sha256")
    audit_output_binding_sha256 = receipt.get("audit_output_binding_sha256")
    if (
        not isinstance(audit_plan_sha256, str)
        or _SHA256_RE.fullmatch(audit_plan_sha256) is None
        or not isinstance(audit_output_binding_sha256, str)
        or _SHA256_RE.fullmatch(audit_output_binding_sha256) is None
    ):
        raise EnronGoldAnnotationError("Gold state audit binding is invalid.")
    commitment = _gold_commitment(receipt)
    core = {
        "schema_version": _GOLD_STATE_SCHEMA_VERSION,
        "audit_plan_sha256": audit_plan_sha256,
        "audit_output_binding_sha256": audit_output_binding_sha256,
        "gold_commitment": commitment,
        "gold_commitment_sha256": _canonical_hash(commitment),
    }
    return {**core, "gold_state_sha256": _canonical_hash(core)}


def _gold_state_filename(receipt: Mapping[str, Any]) -> str:
    binding = _canonical_hash(
        {
            "schema_version": "nerb.enron_gold_commitment_state_key.v1",
            "audit_plan_sha256": receipt.get("audit_plan_sha256"),
            "audit_output_binding_sha256": receipt.get("audit_output_binding_sha256"),
        }
    )
    return f"gold-{binding.removeprefix('sha256:')}.json"


def _open_gold_state_directory(path: Path) -> int:
    root = _absolute_path(path)
    try:
        descriptor = os.open(
            root,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            os.close(descriptor)
            raise EnronGoldAnnotationError("Gold-state directory must be owner-only mode 0700.")
        return descriptor
    except EnronGoldAnnotationError:
        raise
    except OSError:
        raise EnronGoldAnnotationError("Gold-state directory could not be opened safely.") from None


def _register_gold_commitment(gold_state_dir: Path, receipt: Mapping[str, Any]) -> None:
    value = _expected_gold_state(receipt)
    name = _gold_state_filename(receipt)
    directory_fd = _open_gold_state_directory(gold_state_dir)
    descriptor: int | None = None
    try:
        descriptor = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
        payload = _canonical_json_file(value)
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
        os.fsync(directory_fd)
    except FileExistsError:
        raise EnronGoldAnnotationError(
            "This sealed audit binding already has a first committed gold commitment."
        ) from None
    except (OSError, TypeError, ValueError):
        raise EnronGoldAnnotationError("Gold commitment could not be registered durably.") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory_fd)


def _verify_registered_gold_commitment(gold_state_dir: Path | None, receipt: Mapping[str, Any]) -> None:
    if gold_state_dir is None:
        if receipt.get("fixture_mode") is not True:
            raise EnronGoldAnnotationError("Production gold verification requires an explicit gold-state directory.")
        return
    expected = _expected_gold_state(receipt)
    name = _gold_state_filename(receipt)
    directory_fd = _open_gold_state_directory(Path(gold_state_dir))
    try:
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise EnronGoldAnnotationError("Registered gold commitment identity is invalid.")
        with open_private_binary_input_at(directory_fd, name) as file:
            raw = file.read(_MAX_JSON_FILE_BYTES + 1)
    except EnronGoldAnnotationError:
        raise
    except (EnronPrivateIOError, OSError):
        raise EnronGoldAnnotationError("Registered gold commitment could not be loaded safely.") from None
    finally:
        os.close(directory_fd)
    if len(raw) > _MAX_JSON_FILE_BYTES:
        raise EnronGoldAnnotationError("Registered gold commitment exceeds the byte limit.")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise EnronGoldAnnotationError("Registered gold commitment is not strict JSON.") from None
    if not isinstance(value, dict) or raw != _canonical_json_file(value) or value != expected:
        raise EnronGoldAnnotationError("Registered gold commitment differs from deterministic replay.")


def _load_verified_enron_gold_annotations_files(
    run_dir: Path,
    sample_run_dir: Path,
    *,
    expected_audit_output_binding_sha256: str | None = None,
    expected_gold_commitment: Mapping[str, str] | None = None,
    gold_state_dir: Path | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    """Return private documents and gold only after full committed-run replay."""

    verified_receipt = verify_enron_gold_annotations(
        run_dir,
        sample_run_dir,
        expected_audit_output_binding_sha256=expected_audit_output_binding_sha256,
        expected_gold_commitment=expected_gold_commitment,
        gold_state_dir=gold_state_dir,
    )
    documents, _sample_binding = _load_sample_run(
        sample_run_dir,
        expected_audit_output_binding_sha256=expected_audit_output_binding_sha256,
    )
    root = _validate_private_run_tree(run_dir, _GOLD_RUN_FILES, "Gold annotation run")
    manifest, manifest_raw = _load_strict_json_object(root / "manifest.json", "Gold annotation manifest")
    if (
        manifest_raw != _canonical_json_file(manifest)
        or _canonical_hash(manifest) != verified_receipt["manifest_sha256"]
    ):
        raise EnronGoldAnnotationError("Reloaded gold manifest differs from the verified commitment.")
    gold_rows, gold_descriptor = _load_jsonl(
        root / _ARTIFACT_FILENAMES["gold"],
        description="Gold annotation gold",
        require_canonical=True,
    )
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, Mapping) or artifacts.get("gold") != {
        "name": _ARTIFACT_FILENAMES["gold"],
        **gold_descriptor,
    }:
        raise EnronGoldAnnotationError("Reloaded gold artifact differs from the verified manifest.")
    gold = {
        "schema_version": manifest["gold_schema_version"],
        "annotation_policy_sha256": manifest["annotation_policy_sha256"],
        "sample_binding_sha256": manifest["sample_binding_sha256"],
        "documents": gold_rows,
        "counts": manifest["counts"],
        "provenance": manifest["provenance"],
        "gold_sha256": manifest["gold_sha256"],
    }
    if public_enron_gold_receipt(gold)["gold_sha256"] != verified_receipt["gold_sha256"]:
        raise EnronGoldAnnotationError("Verified gold reconstruction differs from its aggregate receipt.")
    return documents, gold, verified_receipt


def _load_verified_enron_gold_role_identities(
    run_dir: Path,
    expected_gold_commitment: Mapping[str, Any],
) -> set[str]:
    """Load private role identities from the exact bound gold artifacts."""

    if not isinstance(expected_gold_commitment, Mapping):
        raise EnronGoldAnnotationError("Bound gold commitment is invalid.")
    root = _validate_private_run_tree(Path(run_dir), _GOLD_RUN_FILES, "Gold annotation run")
    manifest, manifest_raw = _load_strict_json_object(root / "manifest.json", "Gold annotation manifest")
    receipt, receipt_raw = _load_strict_json_object(root / "receipt.json", "Gold annotation receipt")
    if manifest_raw != _canonical_json_file(manifest) or receipt_raw != _canonical_json_file(receipt):
        raise EnronGoldAnnotationError("Gold annotation metadata is not canonically encoded.")
    actual_commitment = {
        "gold_sha256": manifest.get("gold_sha256"),
        "manifest_sha256": _canonical_hash(manifest),
        "artifacts_sha256": _canonical_hash(manifest.get("artifacts")),
    }
    expected_commitment = {key: expected_gold_commitment.get(key) for key in sorted(_GOLD_COMMITMENT_FIELDS)}
    if (
        any(not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None for value in expected_commitment.values())
        or actual_commitment != expected_commitment
        or receipt != _gold_run_receipt(manifest)
    ):
        raise EnronGoldAnnotationError("Gold annotation run differs from the bound gold commitment.")

    definitions = {
        "pass_a": (_PASS_FIELDS, "reviewer_id"),
        "pass_b": (_PASS_FIELDS, "reviewer_id"),
        "adjudication": (_ADJUDICATION_FIELDS, "adjudicator_id"),
        "review": (_REVIEW_FIELDS, "reviewer_id"),
        "gold": (None, None),
    }
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, Mapping) or set(artifacts) != set(definitions):
        raise EnronGoldAnnotationError("Gold annotation artifact inventory is invalid.")
    identities: set[str] = set()
    for key, (fields, identity_field) in definitions.items():
        filename = _ARTIFACT_FILENAMES[key]
        rows, descriptor = _load_jsonl(
            root / filename,
            description=f"Gold annotation {key}",
            require_canonical=True,
        )
        if artifacts.get(key) != {"name": filename, **descriptor}:
            raise EnronGoldAnnotationError(f"Gold annotation {key} artifact differs from its manifest.")
        if fields is not None and identity_field is not None:
            for index, row in enumerate(rows):
                if set(row) != fields:
                    raise EnronGoldAnnotationError(f"Gold annotation {key} row {index} schema is invalid.")
                identities.add(_identifier(row[identity_field], identity_field))
    if not identities:
        raise EnronGoldAnnotationError("Gold annotation role identities are missing.")
    return identities


def _prepare_documents(values: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    _require_sequence(values, "Sample documents")
    documents: dict[str, dict[str, Any]] = {}
    for index, value in enumerate(values):
        if not isinstance(value, Mapping):
            raise EnronGoldAnnotationError(f"Sample document {index} must be an object.")
        required = {"document_id", "text", "text_sha256", "unicode_scalars"}
        if not required <= set(value):
            raise EnronGoldAnnotationError(f"Sample document {index} is incomplete.")
        if set(value) & {"predictions", "matches", "gold_spans", "labels"}:
            raise EnronGoldAnnotationError("Annotation inputs must not contain predictions or labels.")
        document_id = _identifier(value["document_id"], "document_id")
        text = value["text"]
        text_sha256 = value["text_sha256"]
        unicode_scalars = value["unicode_scalars"]
        if (
            not isinstance(text, str)
            or not isinstance(text_sha256, str)
            or not _SHA256_RE.fullmatch(text_sha256)
            or text_sha256 != _hash_bytes(text.encode("utf-8"))
            or type(unicode_scalars) is not int
            or unicode_scalars != len(text)
        ):
            raise EnronGoldAnnotationError(f"Sample document {index} text commitment is invalid.")
        if document_id in documents:
            raise EnronGoldAnnotationError("Sample document IDs must be unique.")
        documents[document_id] = {
            "document_id": document_id,
            "text": text,
            "text_sha256": text_sha256,
            "unicode_scalars": unicode_scalars,
        }
    if not documents:
        raise EnronGoldAnnotationError("Sample documents must not be empty.")
    return documents


def _prepare_pass(
    name: str,
    rows: Sequence[Mapping[str, Any]],
    documents: Mapping[str, Mapping[str, Any]],
) -> tuple[dict[str, tuple[tuple[str, int, int], ...]], set[str]]:
    _require_sequence(rows, f"Annotation pass {name}")
    result: dict[str, tuple[tuple[str, int, int], ...]] = {}
    reviewers: set[str] = set()
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping) or set(row) != _PASS_FIELDS:
            raise EnronGoldAnnotationError(f"Annotation pass {name} row {index} schema is invalid.")
        if row["schema_version"] != ANNOTATION_PASS_SCHEMA_VERSION:
            raise EnronGoldAnnotationError(f"Annotation pass {name} row {index} version is invalid.")
        document_id = _bound_document(row, documents, f"Annotation pass {name} row {index}")
        reviewer_id = _identifier(row["reviewer_id"], "reviewer_id")
        if row["unresolved"] != []:
            raise EnronGoldAnnotationError("Blind annotation passes must resolve every candidate.")
        coverage = row["coverage"]
        expected_coverage = [{"start": 0, "end": documents[document_id]["unicode_scalars"]}]
        if coverage != expected_coverage or any(
            not isinstance(item, Mapping) or set(item) != _COVERAGE_FIELDS for item in coverage
        ):
            raise EnronGoldAnnotationError("Blind annotation passes must attest complete character coverage.")
        if document_id in result:
            raise EnronGoldAnnotationError(f"Annotation pass {name} document IDs must be unique.")
        result[document_id] = _prepare_spans(row["spans"], documents[document_id], description=f"pass {name}")
        reviewers.add(reviewer_id)
    if set(result) != set(documents):
        raise EnronGoldAnnotationError(f"Annotation pass {name} must cover every sampled document exactly once.")
    return result, reviewers


def _prepare_adjudications(
    rows: Sequence[Mapping[str, Any]],
    documents: Mapping[str, Mapping[str, Any]],
    first: Mapping[str, tuple[tuple[str, int, int], ...]],
    second: Mapping[str, tuple[tuple[str, int, int], ...]],
) -> tuple[
    dict[str, tuple[tuple[str, int, int], ...]],
    set[str],
    dict[str, str],
    set[str],
    int,
    int,
]:
    _require_sequence(rows, "Adjudications")
    result: dict[str, tuple[tuple[str, int, int], ...]] = {}
    adjudicators: set[str] = set()
    adjudication_commitments: dict[str, str] = {}
    required_reviews: set[str] = set()
    disagreement_count = 0
    decision_count = 0
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping) or set(row) != _ADJUDICATION_FIELDS:
            raise EnronGoldAnnotationError(f"Adjudication row {index} schema is invalid.")
        if row["schema_version"] != ADJUDICATION_SCHEMA_VERSION:
            raise EnronGoldAnnotationError(f"Adjudication row {index} version is invalid.")
        document_id = _bound_document(row, documents, f"Adjudication row {index}")
        if document_id in result:
            raise EnronGoldAnnotationError("Adjudication document IDs must be unique.")
        if row["unresolved"] != []:
            raise EnronGoldAnnotationError("Adjudication must resolve every candidate.")
        adjudicators.add(_identifier(row["adjudicator_id"], "adjudicator_id"))
        final = _prepare_spans(row["spans"], documents[document_id], description="adjudication")
        a = set(first[document_id])
        b = set(second[document_id])
        union = a | b
        symmetric_difference = a ^ b
        decisions = _prepare_decisions(row["decisions"], documents[document_id], final)
        required_decisions = symmetric_difference | (union - set(final)) | (set(final) - union)
        if set(decisions) != required_decisions:
            raise EnronGoldAnnotationError("Adjudication decisions must exactly explain all disagreements and changes.")
        for span, resolution in decisions.items():
            if (span in set(final)) != (resolution == "include"):
                raise EnronGoldAnnotationError("Adjudication decision does not agree with the final span set.")
        if required_decisions:
            required_reviews.add(document_id)
        disagreement_count += len(symmetric_difference)
        decision_count += len(decisions)
        result[document_id] = final
        adjudication_commitments[document_id] = hash_enron_gold_adjudication(row)
    if set(result) != set(documents):
        raise EnronGoldAnnotationError("Adjudication must cover every sampled document exactly once.")
    return result, adjudicators, adjudication_commitments, required_reviews, disagreement_count, decision_count


def _prepare_reviews(
    rows: Sequence[Mapping[str, Any]],
    documents: Mapping[str, Mapping[str, Any]],
    required_disagreement_reviews: set[str],
    agreement_documents: set[str],
    sample_binding_sha256: str,
    adjudication_commitments: Mapping[str, str],
) -> tuple[set[str], int]:
    _require_sequence(rows, "Annotation reviews")
    result: dict[str, Mapping[str, Any]] = {}
    reviewers: set[str] = set()
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping) or set(row) != _REVIEW_FIELDS:
            raise EnronGoldAnnotationError(f"Annotation review row {index} schema is invalid.")
        if row["schema_version"] != ANNOTATION_REVIEW_SCHEMA_VERSION:
            raise EnronGoldAnnotationError(f"Annotation review row {index} version is invalid.")
        document_id = _bound_document(row, documents, f"Annotation review row {index}")
        if document_id in result:
            raise EnronGoldAnnotationError("Annotation review document IDs must be unique.")
        if row["adjudication_sha256"] != adjudication_commitments[document_id]:
            raise EnronGoldAnnotationError("Annotation review does not bind the normalized adjudication decision.")
        if (
            type(row["disagreements_reviewed"]) is not bool
            or type(row["agreement_audit"]) is not bool
            or row["status"] != "accepted"
            or row["unresolved"] != []
        ):
            raise EnronGoldAnnotationError("Annotation review must be a closed accepted zero-unresolved attestation.")
        reviewers.add(_identifier(row["reviewer_id"], "reviewer_id"))
        result[document_id] = row
    if set(result) != set(documents):
        raise EnronGoldAnnotationError("Annotation review must cover every sampled document exactly once.")
    if any(not result[document_id]["disagreements_reviewed"] for document_id in required_disagreement_reviews):
        raise EnronGoldAnnotationError("Every adjudication disagreement must receive independent review.")
    required_agreement_count = math.ceil(len(agreement_documents) * 0.2)
    ranked = sorted(
        agreement_documents,
        key=lambda document_id: (
            hashlib.sha256(
                ("nerb/enron/gold-agreement-review\0" + sample_binding_sha256 + "\0" + document_id).encode("utf-8")
            ).digest(),
            document_id,
        ),
    )
    required_agreement_audits = set(ranked[:required_agreement_count])
    attested_agreement_audits = {document_id for document_id, row in result.items() if row["agreement_audit"]}
    if attested_agreement_audits != required_agreement_audits:
        raise EnronGoldAnnotationError("The deterministic 20% agreement audit set is not exact.")
    return reviewers, len(required_agreement_audits)


def _prepare_spans(
    values: Any,
    document: Mapping[str, Any],
    *,
    description: str,
) -> tuple[tuple[str, int, int], ...]:
    _require_sequence(values, f"{description} spans")
    spans: list[tuple[str, int, int]] = []
    for index, value in enumerate(values):
        if not isinstance(value, Mapping) or set(value) != _SPAN_FIELDS:
            raise EnronGoldAnnotationError(f"{description} span {index} schema is invalid.")
        span = _span_key(value, document, description=f"{description} span {index}")
        spans.append(span)
    if len(set(spans)) != len(spans):
        raise EnronGoldAnnotationError(f"{description} spans must be unique.")
    spans.sort(key=lambda item: (item[1], item[2], item[0]))
    by_class: dict[str, list[tuple[str, int, int]]] = {entity_class: [] for entity_class in ENTITY_CLASSES}
    for span in spans:
        by_class[span[0]].append(span)
    for entity_class, items in by_class.items():
        if any(left[2] > right[1] for left, right in zip(items, items[1:], strict=False)):
            raise EnronGoldAnnotationError(f"{description} {entity_class} spans must not overlap.")
    contact_spans = by_class["contact"]
    if any(
        contact[1] <= person[1] and person[2] <= contact[2]
        for person in by_class["person"]
        for contact in contact_spans
    ):
        raise EnronGoldAnnotationError("Person spans must not be nested inside contact spans.")
    for left_index, left in enumerate(spans):
        if any(left[1] < right[2] and right[1] < left[2] for right in spans[left_index + 1 :] if right[0] != left[0]):
            raise EnronGoldAnnotationError(f"{description} spans from different entity classes must not overlap.")
    return tuple(spans)


def _prepare_decisions(
    values: Any,
    document: Mapping[str, Any],
    final: tuple[tuple[str, int, int], ...],
) -> dict[tuple[str, int, int], str]:
    _require_sequence(values, "Adjudication decisions")
    decisions: dict[tuple[str, int, int], str] = {}
    for index, value in enumerate(values):
        if not isinstance(value, Mapping) or set(value) != _DECISION_FIELDS:
            raise EnronGoldAnnotationError(f"Adjudication decision {index} schema is invalid.")
        span = _span_key(value, document, description=f"adjudication decision {index}")
        resolution = value["resolution"]
        reason_code = value["reason_code"]
        if (
            resolution not in {"include", "exclude"}
            or not isinstance(reason_code, str)
            or not _ID_RE.fullmatch(reason_code)
        ):
            raise EnronGoldAnnotationError(f"Adjudication decision {index} value is invalid.")
        if span in decisions:
            raise EnronGoldAnnotationError("Adjudication decision spans must be unique.")
        decisions[span] = resolution
    return decisions


def _span_key(value: Mapping[str, Any], document: Mapping[str, Any], *, description: str) -> tuple[str, int, int]:
    entity_class = value["entity_class"]
    start = value["start"]
    end = value["end"]
    if (
        entity_class not in ENTITY_CLASSES
        or type(start) is not int
        or type(end) is not int
        or start < 0
        or end <= start
        or end > document["unicode_scalars"]
    ):
        raise EnronGoldAnnotationError(f"{description} coordinates are invalid.")
    return str(entity_class), start, end


def _span_payload(span: tuple[str, int, int]) -> dict[str, Any]:
    return {"entity_class": span[0], "start": span[1], "end": span[2]}


def _bound_document(
    row: Mapping[str, Any],
    documents: Mapping[str, Mapping[str, Any]],
    description: str,
) -> str:
    document_id = _identifier(row["document_id"], "document_id")
    document = documents.get(document_id)
    if document is None or row["text_sha256"] != document["text_sha256"]:
        raise EnronGoldAnnotationError(f"{description} does not bind a sampled document.")
    return document_id


def _identifier(value: Any, description: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise EnronGoldAnnotationError(f"{description} is invalid.")
    return value


def _require_sequence(value: Any, description: str) -> None:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise EnronGoldAnnotationError(f"{description} must be a sequence.")


def _canonical_hash(value: Any) -> str:
    return _hash_bytes(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    )


def _hash_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


__all__ = [
    "ADJUDICATION_SCHEMA_VERSION",
    "ANNOTATION_PASS_SCHEMA_VERSION",
    "ANNOTATION_POLICY",
    "ANNOTATION_REVIEW_SCHEMA_VERSION",
    "ENTITY_CLASSES",
    "GOLD_SCHEMA_VERSION",
    "GOLD_RUN_MANIFEST_SCHEMA_VERSION",
    "GOLD_RUN_RECEIPT_SCHEMA_VERSION",
    "EnronGoldAnnotationError",
    "build_enron_gold",
    "enron_gold_annotation_policy_sha256",
    "finalize_enron_gold_annotations_files",
    "hash_enron_gold_adjudication",
    "public_enron_gold_receipt",
    "verify_enron_gold_annotations",
]

"""Private transactional workflow for Enron v2 bank construction."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sqlite3
import stat
import tempfile
import unicodedata
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from itertools import zip_longest
from pathlib import Path
from typing import Any, cast
from urllib.parse import quote

from . import enron_bank_builder as _bank_builder_module
from . import enron_contract as _enron_contract_module
from .bank import bank_stats, hash_bank
from .enron_annotations import EnronAnnotationError
from .enron_bank_builder import (
    BANK_BUILD_ITERATION_SCHEMA_VERSION,
    BANK_BUILD_MANIFEST_SCHEMA_VERSION,
    BANK_BUILD_TIMESTAMP,
    BANK_CARD_SCHEMA_VERSION,
    CANDIDATE_FUNNEL_SCHEMA_VERSION,
    CANDIDATE_SCHEMA_VERSION,
    ITERATION_POLICIES,
    CandidatePool,
    CuratedIteration,
    EnronBankBuildError,
    EnronBankPolicy,
    _candidate_pool_hash,
    _canonical_hash,
    _canonical_json_bytes,
    _normalize_email,
    _normalize_person_name,
    _person_literal_catalog_key,
    _read_candidate_evidence,
    _validate_policy,
    candidate_funnel,
    curate_enron_iteration,
    mine_enron_candidates,
)
from .enron_conformance import (
    ADVERSARIAL_TAGS,
    NEGATIVE_CASE_SCHEMA_VERSION,
    POSITIVE_CASE_SCHEMA_VERSION,
    EnronConformanceError,
    evaluate_enron_conformance,
)
from .enron_contract import EnronContractValidator, _public_serialization_diagnostics
from .enron_private_io import (
    EnronPrivateIOError,
    PrivateRun,
    iter_strict_jsonl,
    open_private_binary_input,
)
from .enron_quality import (
    DEFAULT_MAX_QUALITY_INPUT_BYTES,
    DEFAULT_MAX_QUALITY_LINE_BYTES,
    DEFAULT_MAX_QUALITY_RECORDS,
    EnronQualityError,
    evaluate_cmu_enron_training_quality,
    evaluate_cmu_enron_training_quality_files,
    evaluate_enron_quality,
)
from .enron_splitting import (
    EnronDevelopmentAdmissionError,
    EnronDevelopmentAdmissionLimits,
    EnronSplitError,
    load_enron_development_split,
)
from .validation import validate_bank

__all__ = [
    "EnronBankBuildOptions",
    "build_enron_intelligence_bank",
    "verify_enron_bank_build",
]

_PUBLIC_CARD_FIELDS = frozenset(
    {
        "schema_version",
        "benchmark_version",
        "artifact_kind",
        "fixture_mode",
        "promotable",
        "nonpromotable_reasons",
        "source",
        "charter",
        "builder",
        "bank",
        "candidate_funnel",
        "iterations",
        "validation",
        "catalog_conformance",
        "independent_auxiliary",
        "privacy",
        "run_sha256",
    }
)
_SHA256_PREFIX = "sha256:"
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_DOCUMENT_ID_RE = re.compile(r"^doc_[0-9a-f]{64}$")
_MAX_PRIVATE_MANIFEST_BYTES = 16 * 1024 * 1024
_MAX_PRIVATE_JSON_BYTES = 64 * 1024 * 1024
_MAX_PRIVATE_JSONL_BYTES = 256 * 1024 * 1024
_MAX_PRIVATE_SQLITE_BYTES = 2 * 1024 * 1024 * 1024
_MAX_PRIVATE_SQLITE_PROJECTION_BYTES = 16 * 1024 * 1024
_MAX_MINING_SQLITE_SCHEMA_CELL_BYTES = 16 * 1024
_MAX_PRIVATE_JSON_INTEGER_DIGITS = 256
_MAX_MINING_DOCUMENT_ID_BYTES = 68
_MAX_MINING_GROUP_ID_BYTES = 71
_MAX_MINING_KIND_BYTES = 32
_MAX_MINING_SOURCE_TYPE_BYTES = 32
_MAX_MINING_OBSERVED_AT_BYTES = 128
_MINING_SQLITE_LENGTH_LIMIT_HEADROOM = 64 * 1024
_MAX_PRIVATE_JSONL_LINE_BYTES = 16 * 1024 * 1024
_MAX_PRIVATE_JSONL_RECORDS = 750_000
_MAX_PRIVATE_TREE_ENTRIES = 256
_MAX_PRIVATE_TREE_DEPTH = 8
_MAX_PRIVATE_COMMIT_MARKER_BYTES = 128
_PRIVATE_COMMIT_MARKER_SHA256 = _SHA256_PREFIX + hashlib.sha256(b"nerb.enron.private-run.v2\n").hexdigest()

_REQUIRED_ARTIFACT_NAMES = {
    "iteration_01_bank": f"banks/{ITERATION_POLICIES[0].id}.json",
    "iteration_02_bank": f"banks/{ITERATION_POLICIES[1].id}.json",
    "iteration_03_bank": f"banks/{ITERATION_POLICIES[2].id}.json",
    "selected_bank": "bank.json",
    "candidates": "candidates.jsonl",
    "candidate_funnel": "candidate-funnel.json",
    "collision_report": "collision-report.json",
    "iterations": "iterations.jsonl",
    "validation_documents": "validation/documents.jsonl",
    "validation_slices": "validation/slices.jsonl",
    "validation_unsupported": "validation/unsupported.jsonl",
    "validation_gold_01": "validation/gold-iteration-01.jsonl",
    "validation_quality_01": "validation/quality-iteration-01.json",
    "validation_structural_01": "validation/structural-iteration-01.json",
    "validation_gold_02": "validation/gold-iteration-02.jsonl",
    "validation_quality_02": "validation/quality-iteration-02.json",
    "validation_structural_02": "validation/structural-iteration-02.json",
    "validation_gold_03": "validation/gold-iteration-03.jsonl",
    "validation_quality_03": "validation/quality-iteration-03.json",
    "validation_structural_03": "validation/structural-iteration-03.json",
    "conformance_positive": "conformance/positive.jsonl",
    "conformance_negative": "conformance/negative.jsonl",
    "conformance_result": "conformance/result.json",
    "mining_spool": "mining.sqlite3",
    "bank_card": "bank-card.json",
}
_OPTIONAL_CMU_ARTIFACT_NAMES = {
    "cmu_catalog_bindings": "auxiliary/cmu-train-catalog-bindings.jsonl",
    "cmu_quality": "auxiliary/cmu-train-quality.json",
}


def _closed_card_object(properties: Mapping[str, Any], *, required: Sequence[str] | None = None) -> dict[str, Any]:
    fields = tuple(properties)
    return {
        "type": "object",
        "required": list(fields if required is None else required),
        "properties": dict(properties),
        "additionalProperties": False,
    }


_CARD_STRING = {"type": "string", "minLength": 1, "maxLength": 4_096}
_CARD_HASH = {"type": "string", "pattern": r"^sha256:[0-9a-f]{64}$"}
_CARD_COUNT = {"type": "integer", "minimum": 0}
_CARD_POSITIVE_COUNT = {"type": "integer", "minimum": 1}
_CARD_RATIO = {"type": "number", "minimum": 0.0, "maximum": 1.0}
_CARD_OPTIONAL_RATIO = {"anyOf": [_CARD_RATIO, {"type": "null"}]}
_CARD_STAT_COUNTS = _closed_card_object({"entities": _CARD_COUNT, "names": _CARD_COUNT, "patterns": _CARD_COUNT})
_CARD_STATS = _closed_card_object(
    {
        "totals": _CARD_STAT_COUNTS,
        "active_totals": _CARD_STAT_COUNTS,
        "by_status": _closed_card_object(
            {
                "active": _CARD_STAT_COUNTS,
                "draft": _CARD_STAT_COUNTS,
                "inactive": _CARD_STAT_COUNTS,
                "deprecated": _CARD_STAT_COUNTS,
            }
        ),
        "by_kind": _closed_card_object({"literal": _CARD_COUNT, "regex": _CARD_COUNT}),
    }
)
_CARD_SOURCE = _closed_card_object(
    {
        "dataset_id": _CARD_STRING,
        "dataset_revision": _CARD_STRING,
        "dataset_split": _CARD_STRING,
        "development_manifest_sha256": _CARD_HASH,
        "full_split_manifest_sha256": _CARD_HASH,
        "split_policy_sha256": _CARD_HASH,
        "preparation_manifest_sha256": _CARD_HASH,
        "train_artifact_sha256": _CARD_HASH,
        "train_records": _CARD_POSITIVE_COUNT,
        "train_groups": _CARD_POSITIVE_COUNT,
        "validation_artifact_sha256": _CARD_HASH,
        "validation_records": _CARD_POSITIVE_COUNT,
        "validation_groups": _CARD_POSITIVE_COUNT,
        "development_memberships_sha256": _CARD_HASH,
        "sealed_test_accessed": {"const": False},
    }
)
_CARD_CHARTER_ENTITY_CLASS = _closed_card_object(
    {"id": _CARD_STRING, "user_value": _CARD_STRING, "label_source": _CARD_STRING, "active_scope": _CARD_STRING}
)
_CARD_CHARTER = _closed_card_object(
    {
        "id": _CARD_STRING,
        "primary_user_value": _CARD_STRING,
        "recall_priority": {"const": True},
        "guarantee_boundary": _CARD_STRING,
        "entity_classes": {
            "type": "array",
            "minItems": 4,
            "maxItems": 4,
            "items": _CARD_CHARTER_ENTITY_CLASS,
        },
    }
)
_CARD_BUILDER = _closed_card_object(
    {
        "policy_sha256": _CARD_HASH,
        "source_sha256": _CARD_HASH,
        "candidate_source_sha256": _CARD_HASH,
        "candidate_ledger_sha256": _CARD_HASH,
        "train_records": _CARD_POSITIVE_COUNT,
        "observations": _CARD_COUNT,
        "iteration_count": {"const": 3},
        "selected_iteration_id": {"const": "iteration_02_email_recall"},
    }
)
_CARD_BANK = _closed_card_object(
    {
        "id": _CARD_STRING,
        "version": _CARD_STRING,
        "canonical_sha256": _CARD_HASH,
        "artifact_sha256": _CARD_HASH,
        "canonical_json_bytes": _CARD_POSITIVE_COUNT,
        "stats": _CARD_STATS,
    }
)
_CARD_FUNNEL_COUNTS = _closed_card_object(
    {"total": _CARD_COUNT, "active": _CARD_COUNT, "draft": _CARD_COUNT, "rejected": _CARD_COUNT}
)
_CARD_FUNNEL = _closed_card_object(
    {
        "schema_version": {"const": CANDIDATE_FUNNEL_SCHEMA_VERSION},
        "total_candidates": _CARD_POSITIVE_COUNT,
        "by_decision": _closed_card_object({"active": _CARD_COUNT, "draft": _CARD_COUNT, "rejected": _CARD_COUNT}),
        "by_type": {
            "type": "object",
            "required": ["contact_fallback", "phone_fallback"],
            "properties": {
                name: _CARD_FUNNEL_COUNTS
                for name in (
                    "contact",
                    "contact_fallback",
                    "organization_domain",
                    "person_alias",
                    "phone_fallback",
                )
            },
            "additionalProperties": False,
        },
        "by_primary_reason": {
            "type": "object",
            "minProperties": 1,
            "propertyNames": {"type": "string", "minLength": 1, "maxLength": 256},
            "additionalProperties": _CARD_COUNT,
        },
    }
)
_CARD_ITERATION = _closed_card_object(
    {
        "schema_version": {"const": BANK_BUILD_ITERATION_SCHEMA_VERSION},
        "id": _CARD_STRING,
        "parent_id": {"anyOf": [_CARD_STRING, {"type": "null"}]},
        "policy_sha256": _CARD_HASH,
        "bank_sha256": _CARD_HASH,
        "validation_protocol_sha256": _CARD_HASH,
        "catalog_binding_sha256": _CARD_HASH,
        "quality_run_sha256": _CARD_HASH,
        "contact_labeled_spans": _CARD_POSITIVE_COUNT,
        "contact_labeled_true_positive": _CARD_COUNT,
        "contact_labeled_false_negative": _CARD_COUNT,
        "contact_labeled_recall": _CARD_RATIO,
        "contact_cataloged_false_negative": _CARD_COUNT,
        "contact_cataloged_wrong_canonical": _CARD_COUNT,
        "person_labeled_spans": {"anyOf": [_CARD_COUNT, {"type": "null"}]},
        "person_cataloged_false_negative": {"anyOf": [_CARD_COUNT, {"type": "null"}]},
        "person_cataloged_wrong_canonical": {"anyOf": [_CARD_COUNT, {"type": "null"}]},
        "open_world_metrics_supported": {"const": False},
        "utility_metrics_supported": {"const": False},
        "active_patterns": _CARD_POSITIVE_COUNT,
        "canonical_json_bytes": _CARD_POSITIVE_COUNT,
        "decision": {"type": "string", "enum": ["keep", "discard"]},
        "decision_reason_code": _CARD_STRING,
        "selected": {"type": "boolean"},
    }
)
_CARD_VALIDATION_SLICE_FIELDS = {
    "documents": _CARD_COUNT,
    "documents_with_sensitive_gold": _CARD_COUNT,
    "gold_spans": _CARD_COUNT,
    "true_positive": _CARD_COUNT,
    "false_negative": _CARD_COUNT,
    "cataloged_gold_spans": _CARD_COUNT,
    "cataloged_true_positive": _CARD_COUNT,
    "cataloged_false_negative": _CARD_COUNT,
    "cataloged_wrong_canonical": _CARD_COUNT,
    "labeled_span_recall": _CARD_OPTIONAL_RATIO,
    "catalog_coverage": _CARD_OPTIONAL_RATIO,
    "cataloged_recall": _CARD_OPTIONAL_RATIO,
    "open_world_recall": {"type": "null"},
    "precision": {"type": "null"},
    "over_redaction_rate": {"type": "null"},
    "negative_document_false_alarm_rate": {"type": "null"},
}
_CARD_VALIDATION_SLICE = _closed_card_object(_CARD_VALIDATION_SLICE_FIELDS)
_CARD_UNSUPPORTED_VALIDATION_SLICE = _closed_card_object(
    {"evaluated": {"const": False}, "reason_code": _CARD_STRING, **_CARD_VALIDATION_SLICE_FIELDS}
)
_CARD_VALIDATION = _closed_card_object(
    {
        "label_strength": {"const": "structured_weak"},
        "protocol_sha256": _CARD_HASH,
        "quality_run_sha256": _CARD_HASH,
        "contact": _CARD_VALIDATION_SLICE,
        "person": {"oneOf": [_CARD_VALIDATION_SLICE, _CARD_UNSUPPORTED_VALIDATION_SLICE]},
        "open_world_metrics_supported": {"const": False},
        "utility_metrics_supported": {"const": False},
        "unsupported_reason_code": {"const": "independent_exhaustive_validation_labels_unavailable"},
    }
)
_CARD_CONFORMANCE = _closed_card_object(
    {
        "evaluated": {"const": True},
        "label_artifact_id": _CARD_STRING,
        "passed": {"const": True},
        "active_patterns": _CARD_POSITIVE_COUNT,
        "patterns_with_positive_cases": _CARD_POSITIVE_COUNT,
        "approved_positive_cases": _CARD_POSITIVE_COUNT,
        "correctly_mapped": _CARD_COUNT,
        "missed": _CARD_COUNT,
        "wrong_canonical": _CARD_COUNT,
        "recall": _CARD_RATIO,
        "negative_cases": _CARD_POSITIVE_COUNT,
        "unexpected_negative_matches": _CARD_COUNT,
        "positive_cases_artifact": _closed_card_object(
            {"id": _CARD_STRING, "sha256": _CARD_HASH, "bytes": _CARD_POSITIVE_COUNT}
        ),
        "negative_cases_artifact": _closed_card_object(
            {"id": _CARD_STRING, "sha256": _CARD_HASH, "bytes": _CARD_POSITIVE_COUNT}
        ),
        "policy_sha256": _CARD_HASH,
    }
)
_CARD_AUXILIARY_METRICS = _closed_card_object(
    {
        name: _CARD_OPTIONAL_RATIO
        for name in (
            "precision",
            "open_world_recall",
            "f1",
            "catalog_coverage",
            "cataloged_recall",
            "document_leak_rate",
            "cataloged_document_leak_rate",
            "sensitive_character_recall",
            "sensitive_character_leak_rate",
            "negative_document_false_alarm_rate",
            "over_redaction_rate",
        )
    }
)
_CARD_AUXILIARY = {
    "oneOf": [
        _closed_card_object({"evaluated": {"const": False}, "reason_code": {"const": "annotation_run_not_supplied"}}),
        _closed_card_object(
            {
                "evaluated": {"const": True},
                "scope": {"const": "cmu_meetings_person_train_auxiliary_nonpromotable"},
                "label_strength": _CARD_STRING,
                "annotation_completeness": _CARD_STRING,
                "documents": _CARD_POSITIVE_COUNT,
                "documents_with_sensitive_gold": _CARD_COUNT,
                "documents_with_any_miss": _CARD_COUNT,
                "documents_with_cataloged_gold": _CARD_COUNT,
                "documents_with_any_cataloged_miss": _CARD_COUNT,
                "documents_with_any_leaked_character": _CARD_COUNT,
                "gold_spans": _CARD_COUNT,
                "predicted_spans": _CARD_COUNT,
                "true_positive": _CARD_COUNT,
                "false_negative": _CARD_COUNT,
                "false_positive": _CARD_COUNT,
                "cataloged_gold_spans": _CARD_COUNT,
                "cataloged_true_positive": _CARD_COUNT,
                "cataloged_false_negative": _CARD_COUNT,
                "cataloged_wrong_canonical": _CARD_COUNT,
                "sensitive_gold_characters": _CARD_COUNT,
                "covered_sensitive_characters": _CARD_COUNT,
                "leaked_sensitive_characters": _CARD_COUNT,
                "predicted_characters": _CARD_COUNT,
                "over_redacted_characters": _CARD_COUNT,
                "evaluated_characters": _CARD_COUNT,
                "negative_documents": _CARD_COUNT,
                "negative_documents_with_predictions": _CARD_COUNT,
                "metrics": _CARD_AUXILIARY_METRICS,
                "protocol_sha256": _CARD_HASH,
                "run_sha256": _CARD_HASH,
                "nonpromotable": {"const": True},
            }
        ),
    ]
}
_CARD_PRIVACY = _closed_card_object(
    {
        "status": {"const": "passed"},
        "raw_text_included": {"const": False},
        "direct_identifiers_included": {"const": False},
        "private_paths_included": {"const": False},
        "scanner": {"const": "nerb.enron_bank_workflow.public_card_scan.v2"},
        "scanner_source_sha256": _CARD_HASH,
        "violation_count": {"const": 0},
        "report_sha256": _CARD_HASH,
    }
)
_PUBLIC_CARD_SCHEMA = _closed_card_object(
    {
        "schema_version": {"const": BANK_CARD_SCHEMA_VERSION},
        "benchmark_version": _CARD_STRING,
        "artifact_kind": {"const": "aggregate_private_bank_build"},
        "fixture_mode": {"type": "boolean"},
        "promotable": {"const": False},
        "nonpromotable_reasons": {
            "type": "array",
            "minItems": 3,
            "maxItems": 4,
            "uniqueItems": True,
            "items": {
                "type": "string",
                "enum": [
                    "fixture_development_split",
                    "main_validation_independent_exhaustive_labels_unavailable",
                    "main_validation_utility_metrics_unsupported",
                    "sealed_final_test_unopened",
                ],
            },
        },
        "source": _CARD_SOURCE,
        "charter": _CARD_CHARTER,
        "builder": _CARD_BUILDER,
        "bank": _CARD_BANK,
        "candidate_funnel": _CARD_FUNNEL,
        "iterations": {"type": "array", "minItems": 3, "maxItems": 3, "items": _CARD_ITERATION},
        "validation": _CARD_VALIDATION,
        "catalog_conformance": _CARD_CONFORMANCE,
        "independent_auxiliary": _CARD_AUXILIARY,
        "privacy": _CARD_PRIVACY,
        "run_sha256": _CARD_HASH,
    }
)
_PUBLIC_CARD_VALIDATOR = EnronContractValidator(_PUBLIC_CARD_SCHEMA)
_AUXILIARY_CARD_VALIDATOR = EnronContractValidator(_CARD_AUXILIARY)
_EXPECTED_CARD_CHARTER: dict[str, Any] = {
    "id": "privacy_first_enron_intelligence_v2",
    "primary_user_value": "prevent_sensitive_contact_and_person_name_leakage",
    "recall_priority": True,
    "guarantee_boundary": "active_catalog_patterns_only",
    "entity_classes": [
        {
            "id": "contact",
            "user_value": "known_contact_identity_and_unknown_structured_email_discovery",
            "label_source": "train_and_validation_structured_headers",
            "active_scope": "recurring_exact_addresses_plus_bounded_unknown_email_fallback",
        },
        {
            "id": "person",
            "user_value": "canonical_person_identity_from_observed_full_name_aliases",
            "label_source": (
                "train_display_names_sender_body_confirmed_local_parts_and_auxiliary_independent_person_labels"
            ),
            "active_scope": "recurring_unique_address_anchored_full_names",
        },
        {
            "id": "organization_domain",
            "user_value": "organization_domain_intelligence",
            "label_source": "train_structured_headers",
            "active_scope": "draft_until_exact_domain_boundary_is_expressible",
        },
        {
            "id": "phone_number",
            "user_value": "unknown_structured_phone_discovery",
            "label_source": "synthetic_only",
            "active_scope": "draft_because_independent_negative_evidence_is_unavailable",
        },
    ],
}


def _card_charter() -> dict[str, Any]:
    return {
        **_EXPECTED_CARD_CHARTER,
        "entity_classes": [dict(item) for item in _EXPECTED_CARD_CHARTER["entity_classes"]],
    }


@dataclass(frozen=True, slots=True)
class EnronBankBuildOptions:
    development_run: Path
    output_dir: Path
    annotation_run: Path | None = None
    cmu_catalog_bindings_path: Path | None = None
    benchmark_version: str = "enron-v2"
    created_at: str = BANK_BUILD_TIMESTAMP
    policy: EnronBankPolicy = EnronBankPolicy()
    allow_unignored_output: bool = False


@dataclass(frozen=True, slots=True)
class _ValidationProjection:
    documents: tuple[dict[str, Any], ...]
    spans: tuple[dict[str, Any], ...]
    slices: tuple[dict[str, Any], ...]
    unsupported: tuple[dict[str, Any], ...]
    artifact_sha256: str
    records: int


@dataclass(frozen=True, slots=True)
class _PrivateEntryIdentity:
    kind: str
    device: int
    inode: int
    mode: int
    link_count: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True, slots=True)
class _PrivateFileFingerprint:
    identity: _PrivateEntryIdentity
    sha256: str
    records: int | None = None


def build_enron_intelligence_bank(options: EnronBankBuildOptions) -> dict[str, Any]:
    """Build three validation-only iterations and commit one private selected run."""

    if not isinstance(options, EnronBankBuildOptions):
        raise EnronBankBuildError("Bank-build options are invalid.")
    if (options.annotation_run is None) != (options.cmu_catalog_bindings_path is None):
        raise EnronBankBuildError(
            "Auxiliary CMU annotation run and reviewed catalog-binding JSONL must be supplied together."
        )
    if not isinstance(options.policy, EnronBankPolicy):
        raise EnronBankBuildError("Bank-build policy is invalid.")
    _validate_policy(options.policy)
    admission_limits = EnronDevelopmentAdmissionLimits(
        max_train_records=options.policy.max_train_records,
        max_train_artifact_bytes=options.policy.max_train_artifact_bytes,
        max_validation_records=options.policy.max_validation_records,
        max_validation_artifact_bytes=options.policy.max_validation_artifact_bytes,
        max_development_memberships_bytes=options.policy.max_development_memberships_bytes,
        max_development_samples_bytes=options.policy.max_development_samples_bytes,
    )
    try:
        development = load_enron_development_split(
            Path(options.development_run),
            admission_limits=admission_limits,
        )
    except EnronDevelopmentAdmissionError:
        raise EnronBankBuildError("Development split exceeds the bank-build admission limits.") from None
    except (EnronPrivateIOError, EnronSplitError):
        raise EnronBankBuildError("Development split could not be loaded safely.") from None
    source_binding = _source_binding(development, options.benchmark_version)
    if source_binding["benchmark_version"] != options.benchmark_version:
        raise EnronBankBuildError("Development split benchmark version does not match the build target.")
    _preflight_source_capacity(source_binding, options.policy)

    try:
        validation = _validation_projection(
            _paired_role(
                development.iter_validation_records(),
                development.iter_validation_memberships(),
                role="validation",
            ),
            source_binding=source_binding,
            policy=options.policy,
        )
        with PrivateRun(
            Path(options.output_dir),
            allow_unignored_output=options.allow_unignored_output,
        ) as run:
            with run.open_binary("mining.sqlite3"):
                pass
            pool = mine_enron_candidates(
                _paired_role(
                    development.iter_train_records(),
                    development.iter_train_memberships(),
                    role="train",
                ),
                sqlite_path=run.stage_dir / "mining.sqlite3",
                train_artifact_sha256=str(source_binding["train_artifact_sha256"]),
                policy=options.policy,
            )
            implementation_sha256 = _builder_implementation_sha256()
            curated = tuple(
                _bind_curated_iteration(
                    curate_enron_iteration(
                        pool,
                        policy=options.policy,
                        iteration=iteration,
                        source_binding=source_binding,
                        created_at=options.created_at,
                        retain_candidate_ledger=iteration == ITERATION_POLICIES[1],
                    ),
                    pool=pool,
                    policy=options.policy,
                    implementation_sha256=implementation_sha256,
                )
                for iteration in ITERATION_POLICIES
            )
            evaluated = tuple(_evaluate_iteration(item, validation, options.policy) for item in curated)
            iteration_records = _decide_iterations(evaluated)
            selected = curated[1]
            selected_record = iteration_records[1]
            if selected_record["decision"] != "keep" or selected_record["selected"] is not True:
                raise EnronBankBuildError("Frozen iteration selection did not select the bounded email-recall bank.")

            positive_cases, negative_cases = _conformance_cases(selected.bank)
            try:
                conformance = evaluate_enron_conformance(selected.bank, positive_cases, negative_cases)
            except EnronConformanceError:
                raise EnronBankBuildError("Selected-bank catalog conformance could not be evaluated safely.") from None
            conformance_gate = conformance["catalog_conformance"]
            if conformance_gate["passed"] is not True:
                raise EnronBankBuildError("Selected-bank catalog conformance failed.")

            if options.annotation_run is None:
                cmu_bindings: tuple[dict[str, Any], ...] = ()
                cmu_quality: dict[str, Any] | None = None
            else:
                assert options.cmu_catalog_bindings_path is not None
                cmu_bindings, cmu_quality = _stage_and_evaluate_cmu_auxiliary(
                    run,
                    selected.bank,
                    Path(options.annotation_run),
                    Path(options.cmu_catalog_bindings_path),
                )

            artifacts = _write_private_artifacts(
                run,
                pool=pool,
                curated=curated,
                validation=validation,
                evaluated=evaluated,
                iteration_records=iteration_records,
                selected=selected,
                positive_cases=positive_cases,
                negative_cases=negative_cases,
                conformance=conformance,
                cmu_bindings=cmu_bindings,
                cmu_quality=cmu_quality,
            )
            card = _bank_card(
                options,
                source_binding=source_binding,
                pool=pool,
                selected=selected,
                iteration_records=iteration_records,
                selected_quality=cast(Mapping[str, Any], evaluated[1]["quality"]),
                conformance=conformance,
                cmu_quality=cmu_quality,
                artifacts=artifacts,
            )
            _validate_public_card(card)
            with run.open_binary("bank-card.json") as file:
                file.write(_pretty_json_bytes(card))
            artifacts["bank_card"] = _artifact_descriptor(run.stage_dir / "bank-card.json", "bank_card")
            manifest = _private_manifest(
                options,
                source_binding=source_binding,
                pool=pool,
                card=card,
                artifacts=artifacts,
            )
            with run.open_binary("manifest.json") as file:
                file.write(_pretty_json_bytes(manifest))
            run.commit()
    except EnronSplitError:
        raise EnronBankBuildError("Development split changed or became unsafe during the private bank build.") from None
    except EnronPrivateIOError:
        raise EnronBankBuildError("Private bank-build run failed safely.") from None

    return card


def _bind_curated_iteration(
    curated: CuratedIteration,
    *,
    pool: CandidatePool,
    policy: EnronBankPolicy,
    implementation_sha256: str,
) -> CuratedIteration:
    """Bind an otherwise deterministic curation result to its executable inputs."""

    bank = dict(curated.bank)
    raw_metadata = bank.get("metadata")
    if not isinstance(raw_metadata, Mapping):
        raise EnronBankBuildError("Curated bank metadata is invalid.")
    metadata = dict(raw_metadata)
    metadata["builder_implementation_sha256"] = implementation_sha256
    metadata["candidate_source_sha256"] = pool.source_sha256
    bank["metadata"] = metadata
    if len(_canonical_json_bytes(bank)) > policy.max_bank_json_bytes:
        raise EnronBankBuildError("Curated bank exceeds the canonical JSON byte limit after commitment binding.")
    return CuratedIteration(
        iteration=curated.iteration,
        bank=bank,
        candidates=curated.candidates,
        funnel=curated.funnel,
        collisions=curated.collisions,
    )


def _source_binding(development: Any, benchmark_version: str) -> dict[str, Any]:
    manifest = development.manifest
    if manifest.get("benchmark_version") != benchmark_version:
        raise EnronBankBuildError("Development split benchmark version does not match the build target.")
    preparation = manifest.get("preparation")
    policy = manifest.get("policy")
    roles = manifest.get("development_roles")
    artifacts = manifest.get("artifacts")
    if not all(isinstance(item, Mapping) for item in (preparation, policy, roles, artifacts)):
        raise EnronBankBuildError("Development split binding is invalid.")
    preparation = cast(Mapping[str, Any], preparation)
    policy = cast(Mapping[str, Any], policy)
    roles = cast(Mapping[str, Any], roles)
    artifacts = cast(Mapping[str, Any], artifacts)
    train = roles.get("train")
    validation = roles.get("validation")
    memberships = artifacts.get("memberships")
    if not all(isinstance(item, Mapping) for item in (train, validation, memberships)):
        raise EnronBankBuildError("Development role binding is invalid.")
    train = cast(Mapping[str, Any], train)
    validation = cast(Mapping[str, Any], validation)
    memberships = cast(Mapping[str, Any], memberships)
    return {
        "benchmark_version": manifest["benchmark_version"],
        "dataset_id": preparation.get("dataset_id"),
        "dataset_revision": preparation.get("dataset_revision"),
        "dataset_split": preparation.get("dataset_split"),
        "development_manifest_sha256": development.manifest_sha256,
        "full_split_manifest_sha256": manifest.get("full_split_manifest_sha256"),
        "split_policy_sha256": policy.get("sha256"),
        "preparation_manifest_sha256": preparation.get("manifest_sha256"),
        "train_artifact_sha256": cast(Mapping[str, Any], train.get("artifact"))["sha256"],
        "train_artifact_bytes": cast(Mapping[str, Any], train.get("artifact"))["bytes"],
        "train_records": train.get("records"),
        "train_groups": train.get("groups"),
        "validation_artifact_sha256": cast(Mapping[str, Any], validation.get("artifact"))["sha256"],
        "validation_artifact_bytes": cast(Mapping[str, Any], validation.get("artifact"))["bytes"],
        "validation_records": validation.get("records"),
        "validation_groups": validation.get("groups"),
        "development_memberships_sha256": memberships.get("sha256"),
        "fixture_mode": manifest.get("fixture_mode"),
        "sealed_test_accessed": False,
    }


def _preflight_source_capacity(source_binding: Mapping[str, Any], policy: EnronBankPolicy) -> None:
    """Reject a declared split that cannot fit the reviewed development envelope."""

    _validate_policy(policy)
    limits = (
        ("train_records", policy.max_train_records, "train record count"),
        ("train_artifact_bytes", policy.max_train_artifact_bytes, "train artifact byte count"),
        ("validation_records", policy.max_validation_records, "validation record count"),
        (
            "validation_artifact_bytes",
            policy.max_validation_artifact_bytes,
            "validation artifact byte count",
        ),
    )
    for field, limit, description in limits:
        value = source_binding.get(field)
        if type(value) is not int or value <= 0:
            raise EnronBankBuildError("Development split capacity binding is invalid.")
        if value > limit:
            raise EnronBankBuildError(f"Declared {description} exceeds the bank-build limit.")


def _paired_role(
    records: Iterable[Mapping[str, Any]],
    memberships: Iterable[Mapping[str, Any]],
    *,
    role: str,
) -> Iterator[tuple[Mapping[str, Any], Mapping[str, Any]]]:
    sentinel = object()
    for record, membership in zip_longest(records, memberships, fillvalue=sentinel):
        if record is sentinel or membership is sentinel:
            raise EnronBankBuildError(f"{role.capitalize()} records and memberships differ in length.")
        record_map = cast(Mapping[str, Any], record)
        membership_map = cast(Mapping[str, Any], membership)
        if record_map.get("document_id") != membership_map.get("document_id") or membership_map.get("role") != role:
            raise EnronBankBuildError(f"{role.capitalize()} records and memberships are not aligned.")
        yield record_map, membership_map


def _validation_projection(
    records_and_memberships: Iterable[tuple[Mapping[str, Any], Mapping[str, Any]]],
    *,
    source_binding: Mapping[str, Any],
    policy: EnronBankPolicy,
) -> _ValidationProjection:
    documents: list[dict[str, Any]] = []
    spans: list[dict[str, Any]] = []
    records = 0
    total_entries = 0
    total_spans = 0
    total_text_utf8_bytes = 0
    digest = hashlib.sha256(b"nerb/enron/validation-structured-view/v2\0")
    for record, membership in records_and_memberships:
        records += 1
        if records > policy.max_validation_records:
            raise EnronBankBuildError("Validation record count exceeds the bank-build limit.")
        document_id = str(record["document_id"])
        if membership.get("role") != "validation":
            raise EnronBankBuildError("Validation membership role is invalid.")
        headers = record.get("headers")
        if not isinstance(headers, Mapping):
            raise EnronBankBuildError("Validation structured headers are invalid.")
        text_parts: list[str] = []
        offset = 0
        entry_count = 0
        for field_name in ("from", "to", "cc", "bcc"):
            entries = headers.get(field_name)
            if not isinstance(entries, list):
                raise EnronBankBuildError("Validation structured header field is invalid.")
            for entry in entries:
                entry_count += 1
                total_entries += 1
                if entry_count > policy.max_header_entries_per_document:
                    raise EnronBankBuildError("Validation structured header count exceeds the bank-build limit.")
                if total_entries > policy.max_validation_entries:
                    raise EnronBankBuildError("Validation structured header entries exceed the bank-build limit.")
                if not isinstance(entry, Mapping):
                    raise EnronBankBuildError("Validation structured header entry is invalid.")
                name = entry.get("name")
                address = entry.get("address")
                if not isinstance(name, str) or not isinstance(address, str):
                    raise EnronBankBuildError("Validation structured header values are invalid.")
                if max(len(name.encode("utf-8")), len(address.encode("utf-8"))) > policy.max_candidate_value_bytes:
                    raise EnronBankBuildError("Validation structured header value exceeds the bank-build byte limit.")
                prefix = "\n" if text_parts else ""
                normalized_name_surface = " ".join(name.split())
                normalized_address = _normalize_email(address)
                if normalized_name_surface and normalized_address:
                    segment = f"{prefix}{field_name}: {normalized_name_surface} <{normalized_address}>"
                    name_start = offset + len(prefix) + len(field_name) + 2
                    address_start = name_start + len(normalized_name_surface) + 2
                elif normalized_address:
                    segment = f"{prefix}{field_name}: {normalized_address}"
                    name_start = -1
                    address_start = offset + len(prefix) + len(field_name) + 2
                elif normalized_name_surface:
                    segment = f"{prefix}{field_name}: {normalized_name_surface}"
                    name_start = offset + len(prefix) + len(field_name) + 2
                    address_start = -1
                else:
                    continue
                total_text_utf8_bytes += len(segment.encode("utf-8"))
                if total_text_utf8_bytes > policy.max_validation_text_utf8_bytes:
                    raise EnronBankBuildError("Validation structured text exceeds the bank-build byte limit.")
                text_parts.append(segment)
                if normalized_name_surface and _normalize_person_name(normalized_name_surface):
                    total_spans += 1
                    if total_spans > policy.max_validation_spans:
                        raise EnronBankBuildError("Validation structured spans exceed the bank-build limit.")
                    spans.append(
                        {
                            "document_id": document_id,
                            "entity_class": "person",
                            "start": name_start,
                            "end": name_start + len(normalized_name_surface),
                            "surface": normalized_name_surface,
                        }
                    )
                if normalized_address:
                    total_spans += 1
                    if total_spans > policy.max_validation_spans:
                        raise EnronBankBuildError("Validation structured spans exceed the bank-build limit.")
                    spans.append(
                        {
                            "document_id": document_id,
                            "entity_class": "contact",
                            "start": address_start,
                            "end": address_start + len(normalized_address),
                            "surface": normalized_address,
                        }
                    )
                offset += len(segment)
        text = "".join(text_parts)
        document = {
            "document_id": document_id,
            "text": text,
            "text_view": "structured_headers_v2",
            "split_role": "validation",
        }
        documents.append(document)
        digest.update(_canonical_json_bytes(document))
    if records == 0:
        raise EnronBankBuildError("Validation split is empty.")
    artifact_sha256 = _SHA256_PREFIX + digest.hexdigest()
    document_ids = [str(item["document_id"]) for item in documents]
    view_descriptor = {
        "id": "structured_headers_v2",
        "artifact_sha256": artifact_sha256,
        "content_policy_sha256": _canonical_hash(
            {
                "schema_version": "nerb.enron_structured_header_view.v2",
                "fields": ["from", "to", "cc", "bcc"],
                "serialization": "field_colon_display_name_angle_normalized_address",
                "answer_bearing": True,
                "source_artifact_sha256": source_binding["validation_artifact_sha256"],
            }
        ),
        "document_regions": ["structured_headers"],
        "primary_for_quality": False,
        "answer_bearing_fields_included": True,
    }
    annotation_policy_sha256 = _canonical_hash(
        {
            "schema_version": "nerb.enron_structured_weak_labels.v2",
            "contact": "every_valid_parsed_address",
            "person": "plausible_multi_token_display_name",
            "offset_unit": "unicode_scalar",
        }
    )
    slices = (
        {
            "id": "validation_contact_structured_weak",
            "label_artifact_id": "enron_validation_structured_headers",
            "label_strength": "structured_weak",
            "annotation_scope": {
                "entity_classes": ["contact"],
                "document_regions": ["structured_headers"],
                "span_policy_sha256": annotation_policy_sha256,
                "exclusions": ["invalid_or_missing_parsed_addresses"],
            },
            "annotation_completeness": "exhaustive_within_scope",
            "entity_class": "contact",
            "cohort": "all",
            "split_role": "validation",
            "text_view": "structured_headers_v2",
            "text_view_descriptor": view_descriptor,
            "promotion_gate": False,
            "document_ids": document_ids,
        },
        {
            "id": "validation_person_structured_weak",
            "label_artifact_id": "enron_validation_structured_headers",
            "label_strength": "structured_weak",
            "annotation_scope": {
                "entity_classes": ["person"],
                "document_regions": ["structured_headers"],
                "span_policy_sha256": annotation_policy_sha256,
                "exclusions": ["single_token_role_or_ambiguous_display_names"],
            },
            "annotation_completeness": "partial",
            "entity_class": "person",
            "cohort": "all",
            "split_role": "validation",
            "text_view": "structured_headers_v2",
            "text_view_descriptor": view_descriptor,
            "promotion_gate": False,
            "document_ids": document_ids,
        },
    )
    unsupported = (
        {
            "id": "main_validation_open_world_utility",
            "dimension": "independent_exhaustive_negative",
            "reason_code": "independent_exhaustive_validation_labels_unavailable",
        },
        {
            "id": "validation_phone_quality",
            "dimension": "phone_number",
            "reason_code": "independent_phone_labels_unavailable",
        },
        {
            "id": "validation_organization_quality",
            "dimension": "organization_domain",
            "reason_code": "independent_organization_labels_unavailable",
        },
    )
    return _ValidationProjection(
        documents=tuple(documents),
        spans=tuple(spans),
        slices=slices,
        unsupported=unsupported,
        artifact_sha256=artifact_sha256,
        records=records,
    )


def _evaluate_iteration(
    curated: CuratedIteration,
    validation: _ValidationProjection,
    policy: EnronBankPolicy,
) -> dict[str, Any]:
    structural = validate_bank(curated.bank, level="deep", strict=True, check_engine_compile=True)
    structural_summary = _structural_summary(structural)
    if structural_summary["valid"] is not True or structural_summary["engine_compatible"] is not True:
        raise EnronBankBuildError(f"Iteration {curated.iteration.id} failed private structural validation.")
    gold = _qualified_validation_gold(curated.bank, validation.spans)
    try:
        quality = evaluate_enron_quality(
            curated.bank,
            documents=validation.documents,
            gold_spans=gold,
            slice_specs=validation.slices,
            unsupported_slice_specs=validation.unsupported,
        )
    except EnronQualityError:
        raise EnronBankBuildError(f"Iteration {curated.iteration.id} quality evaluation failed safely.") from None
    contract_codes = set(quality["contract_validation"]["diagnostic_codes"])
    source_metadata = cast(Mapping[str, Any], curated.bank["metadata"])["source"]
    fixture_small_slice_only = (
        isinstance(source_metadata, Mapping)
        and source_metadata.get("fixture_mode") is True
        and contract_codes == {"contract.privacy_small_slice"}
    )
    if quality["evaluated"] is not True or (
        quality["contract_validation"]["valid"] is not True and not fixture_small_slice_only
    ):
        raise EnronBankBuildError(f"Iteration {curated.iteration.id} quality evidence failed closed.")
    return {
        "iteration": curated.iteration,
        "bank": curated.bank,
        "structural": structural_summary,
        "gold": gold,
        "quality": quality,
        "limits": {
            "active_patterns": structural["stats"]["active_totals"]["patterns"],
            "max_active_patterns": policy.max_active_patterns,
            "canonical_json_bytes": len(_canonical_json_bytes(curated.bank)),
            "max_canonical_json_bytes": policy.max_bank_json_bytes,
            "passed": True,
        },
    }


def _structural_summary(structural: Mapping[str, Any]) -> dict[str, Any]:
    diagnostics = structural.get("diagnostics")
    compatibility = structural.get("engine_compatibility")
    if not isinstance(diagnostics, list) or not isinstance(compatibility, Mapping):
        raise EnronBankBuildError("Private structural validation result is invalid.")
    return {
        "valid": structural.get("valid"),
        "hash": structural.get("hash"),
        "stats": structural.get("stats"),
        "diagnostic_codes": sorted(
            {
                str(item["code"])
                for item in diagnostics
                if isinstance(item, Mapping) and isinstance(item.get("code"), str)
            }
        ),
        "engine_compatible": compatibility.get("compatible"),
    }


def _qualified_validation_gold(
    bank: Mapping[str, Any],
    spans: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    contact_exact: dict[str, tuple[str, str, str]] = {}
    person_aliases: dict[str, tuple[str, str, str]] = {}
    entities = bank.get("entities")
    if not isinstance(entities, Mapping):
        raise EnronBankBuildError("Iteration bank entity inventory is invalid.")
    for entity_id in ("contact", "person"):
        entity = entities.get(entity_id)
        if not isinstance(entity, Mapping) or entity.get("status") != "active":
            continue
        names = entity.get("names")
        if not isinstance(names, Mapping):
            continue
        for name_id, name in names.items():
            if not isinstance(name_id, str) or not isinstance(name, Mapping) or name.get("status") != "active":
                continue
            patterns = name.get("patterns")
            if not isinstance(patterns, Mapping):
                continue
            for pattern_id, pattern in patterns.items():
                if (
                    not isinstance(pattern_id, str)
                    or not isinstance(pattern, Mapping)
                    or pattern.get("status") != "active"
                ):
                    continue
                value = pattern.get("value")
                if not isinstance(value, str):
                    continue
                pattern_identity = (entity_id, name_id, pattern_id)
                if entity_id == "contact" and pattern.get("kind") == "literal":
                    normalized = _normalize_email(value)
                    if normalized:
                        contact_exact[normalized] = pattern_identity
                elif entity_id == "person" and pattern.get("kind") == "literal":
                    surface_key = _person_literal_catalog_key(value)
                    if surface_key:
                        if surface_key in person_aliases and person_aliases[surface_key] != pattern_identity:
                            raise EnronBankBuildError("Active person alias maps to multiple canonical identities.")
                        person_aliases[surface_key] = pattern_identity

    gold: list[dict[str, Any]] = []
    for item in spans:
        entity_class = str(item["entity_class"])
        surface = str(item["surface"])
        identity: tuple[str, str, str] | None
        if entity_class == "contact":
            normalized = _normalize_email(surface)
            identity = contact_exact.get(normalized or "")
        elif entity_class == "person":
            identity = person_aliases.get(_person_literal_catalog_key(surface))
        else:  # pragma: no cover - closed projection invariant
            identity = None
        gold.append(
            {
                "document_id": item["document_id"],
                "entity_class": entity_class,
                "start": item["start"],
                "end": item["end"],
                "catalog_identity": (
                    None
                    if identity is None
                    else {"entity_id": identity[0], "name_id": identity[1], "pattern_id": identity[2]}
                ),
            }
        )
    return tuple(gold)


def _decide_iterations(evaluated: Sequence[Mapping[str, Any]]) -> tuple[dict[str, Any], ...]:
    if len(evaluated) != 3:
        raise EnronBankBuildError("Bank build requires exactly three frozen construction iterations.")
    contact_summaries = [_slice_by_id(item["quality"], "validation_contact_structured_weak") for item in evaluated]
    person_summaries = [
        _slice_by_id_or_none(item["quality"], "validation_person_structured_weak") for item in evaluated
    ]
    protocol_sha256s = {str(item["quality"]["protocol_sha256"]) for item in evaluated}
    if len(protocol_sha256s) != 1:
        raise EnronBankBuildError("Validation protocol changed across construction iterations.")
    if contact_summaries[1]["false_negative"] > contact_summaries[0]["false_negative"]:
        raise EnronBankBuildError("Bounded email fallback regressed structured contact recall.")
    if contact_summaries[1]["false_negative"] != 0:
        raise EnronBankBuildError("Selected email fallback leaves structured validation contact misses.")
    if contact_summaries[1]["cataloged_false_negative"] != 0 or contact_summaries[1]["cataloged_wrong_canonical"] != 0:
        raise EnronBankBuildError("Selected bank has a cataloged contact miss or wrong mapping.")
    selected_person = person_summaries[1]
    if selected_person is not None and (
        selected_person["cataloged_false_negative"] != 0 or selected_person["cataloged_wrong_canonical"] != 0
    ):
        raise EnronBankBuildError("Selected bank has a cataloged person miss or wrong mapping.")

    decisions = (
        ("discard", "superseded_by_bounded_email_fallback", False),
        ("keep", "best_supported_privacy_recall_without_unsupported_phone_activation", True),
        ("discard", "independent_phone_negative_evidence_unavailable", False),
    )
    records: list[dict[str, Any]] = []
    for item, contact, person, (decision, reason, selected) in zip(
        evaluated, contact_summaries, person_summaries, decisions, strict=True
    ):
        iteration = item["iteration"]
        quality = cast(Mapping[str, Any], item["quality"])
        records.append(
            {
                "schema_version": BANK_BUILD_ITERATION_SCHEMA_VERSION,
                "id": iteration.id,
                "parent_id": iteration.parent_id,
                "policy_sha256": iteration.sha256,
                "bank_sha256": hash_bank(cast(Mapping[str, Any], item["bank"])),
                "validation_protocol_sha256": quality["protocol_sha256"],
                "catalog_binding_sha256": quality["catalog_binding_sha256"],
                "quality_run_sha256": quality["run_sha256"],
                "contact_labeled_spans": contact["gold_spans"],
                "contact_labeled_true_positive": contact["true_positive"],
                "contact_labeled_false_negative": contact["false_negative"],
                "contact_labeled_recall": _ratio(contact["true_positive"], contact["gold_spans"]),
                "contact_cataloged_false_negative": contact["cataloged_false_negative"],
                "contact_cataloged_wrong_canonical": contact["cataloged_wrong_canonical"],
                "person_labeled_spans": None if person is None else person["gold_spans"],
                "person_cataloged_false_negative": None if person is None else person["cataloged_false_negative"],
                "person_cataloged_wrong_canonical": None if person is None else person["cataloged_wrong_canonical"],
                "open_world_metrics_supported": False,
                "utility_metrics_supported": False,
                "active_patterns": item["structural"]["stats"]["active_totals"]["patterns"],
                "canonical_json_bytes": item["limits"]["canonical_json_bytes"],
                "decision": decision,
                "decision_reason_code": reason,
                "selected": selected,
            }
        )
    return tuple(records)


def _slice_by_id(quality: Mapping[str, Any], slice_id: str) -> Mapping[str, Any]:
    result = _slice_by_id_or_none(quality, slice_id)
    if result is not None:
        return result
    raise EnronBankBuildError(f"Quality result is missing required slice {slice_id}.")


def _slice_by_id_or_none(quality: Mapping[str, Any], slice_id: str) -> Mapping[str, Any] | None:
    payload = quality.get("quality")
    if not isinstance(payload, Mapping):
        raise EnronBankBuildError("Quality result is missing its aggregate payload.")
    for item in cast(Sequence[Mapping[str, Any]], payload.get("slices", ())):
        if item.get("id") == slice_id:
            return item
    return None


def _stage_and_evaluate_cmu_auxiliary(
    run: PrivateRun,
    bank: Mapping[str, Any],
    annotation_run: Path,
    catalog_bindings_path: Path,
) -> tuple[tuple[dict[str, Any], ...], dict[str, Any]]:
    bindings = _load_reviewed_cmu_catalog_bindings(catalog_bindings_path)
    staged_path = run.stage_dir / _OPTIONAL_CMU_ARTIFACT_NAMES["cmu_catalog_bindings"]
    _write_run_jsonl(run, _OPTIONAL_CMU_ARTIFACT_NAMES["cmu_catalog_bindings"], bindings)
    try:
        quality = evaluate_cmu_enron_training_quality_files(
            bank,
            annotation_run_dir=annotation_run,
            catalog_bindings_path=staged_path,
        )
    except (EnronAnnotationError, EnronQualityError):
        raise EnronBankBuildError("Auxiliary CMU quality evaluation failed safely.") from None
    if quality["evaluated"] is not True or quality["contract_validation"]["valid"] is not True:
        raise EnronBankBuildError("Auxiliary CMU quality evaluation failed closed.")
    return bindings, quality


def _load_reviewed_cmu_catalog_bindings(path: Path) -> tuple[dict[str, Any], ...]:
    bindings: list[dict[str, Any]] = []
    total_bytes = 0
    try:
        for _line_no, raw, value in iter_strict_jsonl(path, DEFAULT_MAX_QUALITY_LINE_BYTES):
            total_bytes += len(raw)
            if total_bytes > DEFAULT_MAX_QUALITY_INPUT_BYTES:
                raise EnronBankBuildError("Reviewed CMU catalog-binding JSONL exceeds the cumulative byte limit.")
            bindings.append(dict(value))
            if len(bindings) > DEFAULT_MAX_QUALITY_RECORDS:
                raise EnronBankBuildError("Reviewed CMU catalog-binding JSONL exceeds the record limit.")
    except EnronPrivateIOError:
        raise EnronBankBuildError("Reviewed CMU catalog-binding JSONL could not be read safely.") from None
    return tuple(bindings)


def _person_literal_boundaries_match(text: str, start: int, end: int) -> bool:
    if start < 0 or end <= start or end > len(text):
        return False
    left = start == 0 or _is_unicode_word(text[start - 1]) != _is_unicode_word(text[start])
    right = end == len(text) or _is_unicode_word(text[end - 1]) != _is_unicode_word(text[end])
    return left and right


def _is_unicode_word(value: str) -> bool:
    return value == "_" or value.isalnum() or value in {"\u200c", "\u200d"} or unicodedata.category(value)[0] == "M"


def _conformance_cases(
    bank: Mapping[str, Any],
) -> tuple[tuple[dict[str, Any], ...], tuple[dict[str, Any], ...]]:
    positives: list[dict[str, Any]] = []
    negative_specs: list[tuple[set[str], str, str]] = []
    entities = cast(Mapping[str, Any], bank.get("entities", {}))
    bank_sha256 = hash_bank(bank)
    active: list[dict[str, Any]] = []
    for entity_id, entity in sorted(entities.items()):
        if not isinstance(entity_id, str) or not isinstance(entity, Mapping) or entity.get("status") != "active":
            continue
        for name_id, name in sorted(cast(Mapping[str, Any], entity.get("names", {})).items()):
            if not isinstance(name_id, str) or not isinstance(name, Mapping) or name.get("status") != "active":
                continue
            canonical = str(name["canonical"])
            for pattern_id, pattern in sorted(cast(Mapping[str, Any], name.get("patterns", {})).items()):
                if (
                    not isinstance(pattern_id, str)
                    or not isinstance(pattern, Mapping)
                    or pattern.get("status") != "active"
                ):
                    continue
                kind = str(pattern["kind"])
                if kind == "literal":
                    witness = str(pattern["value"])
                elif entity_id == "contact" and pattern_id == "structured_email":
                    witness = f"unknown.{bank_sha256[7:19]}@example.invalid"
                elif entity_id == "phone_number" and pattern_id == "structured_us_phone":
                    witness = "212-555-0198"
                else:
                    raise EnronBankBuildError("Active regex lacks a frozen conformance witness.")
                active.append(
                    {
                        "entity_id": entity_id,
                        "name_id": name_id,
                        "pattern_id": pattern_id,
                        "pattern_kind": kind,
                        "canonical_name": canonical,
                        "pattern": pattern,
                        "witness": witness,
                    }
                )
    if not active:
        raise EnronBankBuildError("Selected bank has no active patterns for conformance.")

    fallback = next(
        (item for item in active if item["entity_id"] == "contact" and item["pattern_id"] == "structured_email"),
        None,
    )
    for item in active:
        witness = str(item["witness"])
        cased = witness.swapcase()
        _append_conformance_positive(positives, cased, ((item, cased, 0),), {"casing"})

        prefix = "<p>Regards,<br>"
        contextual = prefix + witness + "</p>"
        _append_conformance_positive(
            positives,
            contextual,
            ((item, witness, len(prefix)),),
            {"html", "punctuation", "signature"},
        )

        pattern = cast(Mapping[str, Any], item["pattern"])
        if pattern.get("kind") == "literal" and pattern.get("normalize_whitespace") is True:
            spaced = re.sub(r"\s+", " \t ", witness)
            if spaced != witness:
                _append_conformance_positive(positives, spaced, ((item, spaced, 0),), {"whitespace"})

        if (
            pattern.get("kind") == "literal"
            and pattern.get("left_boundary") == "word"
            and pattern.get("right_boundary") == "word"
        ):
            boundary_text = "x" + witness + "y"
            if item["entity_id"] == "contact" and fallback is not None:
                _append_conformance_positive(
                    positives,
                    boundary_text,
                    ((fallback, boundary_text, 0),),
                    {"boundary"},
                )
            else:
                negative_specs.append(({"boundary"}, boundary_text, "literal_word_boundary"))

    if fallback is not None:
        first = f"first.{bank_sha256[7:19]}@example.invalid"
        second = f"second.{bank_sha256[19:31]}@example.invalid"
        separator = " and "
        overlap_text = first + separator + second
        _append_conformance_positive(
            positives,
            overlap_text,
            (
                (fallback, first, 0),
                (fallback, second, len(first) + len(separator)),
            ),
            {"overlap"},
        )

    negative_specs.extend(
        [
            ({"malformed"}, "missing.domain@localhost", "email_missing_domain_suffix"),
            ({"malformed"}, "contact: @example.invalid", "email_missing_local_part"),
            ({"malformed"}, "name@example..invalid", "email_empty_domain_label"),
            ({"malformed"}, "name@example.123", "email_numeric_top_level_domain"),
            ({"malformed", "whitespace"}, "name @example.invalid", "email_embedded_whitespace"),
            ({"malformed"}, "name@-example.invalid", "email_invalid_domain_label"),
            ({"malformed"}, "price@risk ratio", "email_missing_domain_separator"),
            ({"signature"}, "Call 202-555-0198", "phone_fallback_not_promoted"),
            ({"signature"}, "Call 415.555.0199 x123", "phone_extension_fallback_not_promoted"),
            (
                {"boundary", "unicode"},
                f"Ωunknown.{bank_sha256[7:19]}@example.invalidΩ",
                "unicode_word_boundary",
            ),
        ]
    )
    negatives = tuple(
        {
            "schema_version": NEGATIVE_CASE_SCHEMA_VERSION,
            "case_id": f"negative_{index:08d}",
            "text": text,
            "tags": sorted({"negative", *tags}),
            "reason_code": reason,
        }
        for index, (tags, text, reason) in enumerate(negative_specs)
    )
    covered_tags = {tag for item in (*positives, *negatives) for tag in item["tags"]}
    if covered_tags != set(ADVERSARIAL_TAGS):
        raise EnronBankBuildError("Generated conformance suite does not cover every adversarial tag.")
    return tuple(positives), negatives


def _append_conformance_positive(
    cases: list[dict[str, Any]],
    text: str,
    matches: Sequence[tuple[Mapping[str, Any], str, int]],
    tags: set[str],
) -> None:
    expected: list[dict[str, Any]] = []
    for item, matched, scalar_start in matches:
        byte_start = len(text[:scalar_start].encode("utf-8"))
        expected.append(
            {
                "entity_id": item["entity_id"],
                "name_id": item["name_id"],
                "pattern_id": item["pattern_id"],
                "pattern_kind": item["pattern_kind"],
                "canonical_name": item["canonical_name"],
                "string": matched,
                "start": byte_start,
                "end": byte_start + len(matched.encode("utf-8")),
            }
        )
    cases.append(
        {
            "schema_version": POSITIVE_CASE_SCHEMA_VERSION,
            "case_id": f"pattern_{len(cases):08d}",
            "text": text,
            "tags": sorted(tags),
            "expected": expected,
        }
    )


def _write_private_artifacts(
    run: PrivateRun,
    *,
    pool: CandidatePool,
    curated: Sequence[CuratedIteration],
    validation: _ValidationProjection,
    evaluated: Sequence[Mapping[str, Any]],
    iteration_records: Sequence[Mapping[str, Any]],
    selected: CuratedIteration,
    positive_cases: Sequence[Mapping[str, Any]],
    negative_cases: Sequence[Mapping[str, Any]],
    conformance: Mapping[str, Any],
    cmu_bindings: Sequence[Mapping[str, Any]],
    cmu_quality: Mapping[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    artifacts: dict[str, dict[str, Any]] = {}

    for index, item in enumerate(curated, start=1):
        key = f"iteration_{index:02d}_bank"
        name = f"banks/{item.iteration.id}.json"
        _write_run_json(run, name, item.bank)
        artifacts[key] = _artifact_descriptor(run.stage_dir / name, key, records=1)
    _write_run_json(run, "bank.json", selected.bank)
    artifacts["selected_bank"] = _artifact_descriptor(run.stage_dir / "bank.json", "selected_bank", records=1)

    _write_run_jsonl(run, "candidates.jsonl", selected.candidates)
    artifacts["candidates"] = _artifact_descriptor(
        run.stage_dir / "candidates.jsonl", "candidates", records=len(selected.candidates)
    )
    _write_run_json(run, "candidate-funnel.json", selected.funnel)
    artifacts["candidate_funnel"] = _artifact_descriptor(
        run.stage_dir / "candidate-funnel.json", "candidate_funnel", records=1
    )
    _write_run_json(run, "collision-report.json", selected.collisions)
    artifacts["collision_report"] = _artifact_descriptor(
        run.stage_dir / "collision-report.json", "collision_report", records=1
    )
    _write_run_jsonl(run, "iterations.jsonl", iteration_records)
    artifacts["iterations"] = _artifact_descriptor(
        run.stage_dir / "iterations.jsonl", "iterations", records=len(iteration_records)
    )

    _write_run_jsonl(run, "validation/documents.jsonl", validation.documents)
    artifacts["validation_documents"] = _artifact_descriptor(
        run.stage_dir / "validation/documents.jsonl", "validation_documents", records=len(validation.documents)
    )
    _write_run_jsonl(run, "validation/slices.jsonl", validation.slices)
    artifacts["validation_slices"] = _artifact_descriptor(
        run.stage_dir / "validation/slices.jsonl", "validation_slices", records=len(validation.slices)
    )
    _write_run_jsonl(run, "validation/unsupported.jsonl", validation.unsupported)
    artifacts["validation_unsupported"] = _artifact_descriptor(
        run.stage_dir / "validation/unsupported.jsonl",
        "validation_unsupported",
        records=len(validation.unsupported),
    )
    for index, evaluated_item in enumerate(evaluated, start=1):
        gold_name = f"validation/gold-iteration-{index:02d}.jsonl"
        quality_name = f"validation/quality-iteration-{index:02d}.json"
        structural_name = f"validation/structural-iteration-{index:02d}.json"
        gold = cast(Sequence[Mapping[str, Any]], evaluated_item["gold"])
        _write_run_jsonl(run, gold_name, gold)
        _write_run_json(run, quality_name, evaluated_item["quality"])
        _write_run_json(run, structural_name, evaluated_item["structural"])
        artifacts[f"validation_gold_{index:02d}"] = _artifact_descriptor(
            run.stage_dir / gold_name, f"validation_gold_{index:02d}", records=len(gold)
        )
        artifacts[f"validation_quality_{index:02d}"] = _artifact_descriptor(
            run.stage_dir / quality_name, f"validation_quality_{index:02d}", records=1
        )
        artifacts[f"validation_structural_{index:02d}"] = _artifact_descriptor(
            run.stage_dir / structural_name, f"validation_structural_{index:02d}", records=1
        )

    _write_run_jsonl(run, "conformance/positive.jsonl", positive_cases)
    _write_run_jsonl(run, "conformance/negative.jsonl", negative_cases)
    _write_run_json(run, "conformance/result.json", conformance)
    artifacts["conformance_positive"] = _artifact_descriptor(
        run.stage_dir / "conformance/positive.jsonl", "conformance_positive", records=len(positive_cases)
    )
    artifacts["conformance_negative"] = _artifact_descriptor(
        run.stage_dir / "conformance/negative.jsonl", "conformance_negative", records=len(negative_cases)
    )
    artifacts["conformance_result"] = _artifact_descriptor(
        run.stage_dir / "conformance/result.json", "conformance_result", records=1
    )

    if cmu_quality is not None:
        _write_run_json(run, "auxiliary/cmu-train-quality.json", cmu_quality)
        artifacts["cmu_catalog_bindings"] = _artifact_descriptor(
            run.stage_dir / "auxiliary/cmu-train-catalog-bindings.jsonl",
            "cmu_catalog_bindings",
            records=len(cmu_bindings),
        )
        artifacts["cmu_quality"] = _artifact_descriptor(
            run.stage_dir / "auxiliary/cmu-train-quality.json", "cmu_quality", records=1
        )

    artifacts["mining_spool"] = _artifact_descriptor(
        run.stage_dir / "mining.sqlite3", "mining_spool", records=pool.observations
    )
    return artifacts


def _bank_card(
    options: EnronBankBuildOptions,
    *,
    source_binding: Mapping[str, Any],
    pool: CandidatePool,
    selected: CuratedIteration,
    iteration_records: Sequence[Mapping[str, Any]],
    selected_quality: Mapping[str, Any],
    conformance: Mapping[str, Any],
    cmu_quality: Mapping[str, Any] | None,
    artifacts: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    stats = bank_stats(selected.bank)
    contact = _slice_by_id(selected_quality, "validation_contact_structured_weak")
    person = _slice_by_id_or_none(selected_quality, "validation_person_structured_weak")
    nonpromotable = [
        "sealed_final_test_unopened",
        "main_validation_independent_exhaustive_labels_unavailable",
        "main_validation_utility_metrics_unsupported",
    ]
    if source_binding["fixture_mode"] is True:
        nonpromotable.append("fixture_development_split")
    auxiliary = _independent_auxiliary_summary(cmu_quality)
    card: dict[str, Any] = {
        "schema_version": BANK_CARD_SCHEMA_VERSION,
        "benchmark_version": options.benchmark_version,
        "artifact_kind": "aggregate_private_bank_build",
        "fixture_mode": source_binding["fixture_mode"],
        "promotable": False,
        "nonpromotable_reasons": sorted(nonpromotable),
        "source": {
            key: source_binding[key]
            for key in (
                "dataset_id",
                "dataset_revision",
                "dataset_split",
                "development_manifest_sha256",
                "full_split_manifest_sha256",
                "split_policy_sha256",
                "preparation_manifest_sha256",
                "train_artifact_sha256",
                "train_records",
                "train_groups",
                "validation_artifact_sha256",
                "validation_records",
                "validation_groups",
                "development_memberships_sha256",
                "sealed_test_accessed",
            )
        },
        "charter": _card_charter(),
        "builder": {
            "policy_sha256": options.policy.sha256,
            "source_sha256": _builder_implementation_sha256(),
            "candidate_source_sha256": pool.source_sha256,
            "candidate_ledger_sha256": pool.ledger_sha256,
            "train_records": pool.train_records,
            "observations": pool.observations,
            "iteration_count": len(iteration_records),
            "selected_iteration_id": "iteration_02_email_recall",
        },
        "bank": {
            "id": selected.bank["id"],
            "version": selected.bank["version"],
            "canonical_sha256": hash_bank(selected.bank),
            "artifact_sha256": artifacts["selected_bank"]["sha256"],
            "canonical_json_bytes": len(_canonical_json_bytes(selected.bank)),
            "stats": stats,
        },
        "candidate_funnel": selected.funnel,
        "iterations": [dict(item) for item in iteration_records],
        "validation": {
            "label_strength": "structured_weak",
            "protocol_sha256": selected_quality["protocol_sha256"],
            "quality_run_sha256": selected_quality["run_sha256"],
            "contact": _safe_slice_summary(contact),
            "person": (
                _safe_slice_summary(person)
                if person is not None
                else _unsupported_slice_summary("zero_labeled_person_spans")
            ),
            "open_world_metrics_supported": False,
            "utility_metrics_supported": False,
            "unsupported_reason_code": "independent_exhaustive_validation_labels_unavailable",
        },
        "catalog_conformance": dict(conformance["catalog_conformance"]),
        "independent_auxiliary": auxiliary,
        "privacy": {},
        "run_sha256": "",
    }
    privacy_report = {
        "status": "passed",
        "raw_text_included": False,
        "direct_identifiers_included": False,
        "private_paths_included": False,
        "scanner": "nerb.enron_bank_workflow.public_card_scan.v2",
        "scanner_source_sha256": _public_card_scanner_sha256(),
        "violation_count": 0,
    }
    privacy_report["report_sha256"] = _canonical_hash(privacy_report)
    card["privacy"] = privacy_report
    card["run_sha256"] = _canonical_hash({key: value for key, value in card.items() if key != "run_sha256"})
    return card


def _independent_auxiliary_summary(cmu_quality: Mapping[str, Any] | None) -> dict[str, Any]:
    """Project one private CMU quality run into its canonical public aggregate."""

    if cmu_quality is None:
        return {
            "evaluated": False,
            "reason_code": "annotation_run_not_supplied",
        }
    quality = cmu_quality.get("quality")
    slices = quality.get("slices") if isinstance(quality, Mapping) else None
    if (
        not isinstance(slices, Sequence)
        or isinstance(slices, (str, bytes, bytearray))
        or any(not isinstance(item, Mapping) for item in slices)
    ):
        raise EnronBankBuildError("Auxiliary CMU quality evidence is invalid.")
    matches = [cast(Mapping[str, Any], item) for item in slices if item.get("id") == "cmu_person_all_train"]
    if len(matches) != 1:
        raise EnronBankBuildError("Auxiliary CMU quality evidence is invalid.")
    cmu_slice = matches[0]
    metrics = cmu_slice.get("metrics")
    if not isinstance(metrics, Mapping):
        raise EnronBankBuildError("Auxiliary CMU quality evidence is invalid.")
    summary = {
        "evaluated": True,
        "scope": "cmu_meetings_person_train_auxiliary_nonpromotable",
        "label_strength": cmu_slice.get("label_strength"),
        "annotation_completeness": cmu_slice.get("annotation_completeness"),
        "documents": cmu_slice.get("documents"),
        "documents_with_sensitive_gold": cmu_slice.get("documents_with_sensitive_gold"),
        "documents_with_any_miss": cmu_slice.get("documents_with_any_miss"),
        "documents_with_cataloged_gold": cmu_slice.get("documents_with_cataloged_gold"),
        "documents_with_any_cataloged_miss": cmu_slice.get("documents_with_any_cataloged_miss"),
        "documents_with_any_leaked_character": cmu_slice.get("documents_with_any_leaked_character"),
        "gold_spans": cmu_slice.get("gold_spans"),
        "predicted_spans": cmu_slice.get("predicted_spans"),
        "true_positive": cmu_slice.get("true_positive"),
        "false_negative": cmu_slice.get("false_negative"),
        "false_positive": cmu_slice.get("false_positive"),
        "cataloged_gold_spans": cmu_slice.get("cataloged_gold_spans"),
        "cataloged_true_positive": cmu_slice.get("cataloged_true_positive"),
        "cataloged_false_negative": cmu_slice.get("cataloged_false_negative"),
        "cataloged_wrong_canonical": cmu_slice.get("cataloged_wrong_canonical"),
        "sensitive_gold_characters": cmu_slice.get("sensitive_gold_characters"),
        "covered_sensitive_characters": cmu_slice.get("covered_sensitive_characters"),
        "leaked_sensitive_characters": cmu_slice.get("leaked_sensitive_characters"),
        "predicted_characters": cmu_slice.get("predicted_characters"),
        "over_redacted_characters": cmu_slice.get("over_redacted_characters"),
        "evaluated_characters": cmu_slice.get("evaluated_characters"),
        "negative_documents": cmu_slice.get("negative_documents"),
        "negative_documents_with_predictions": cmu_slice.get("negative_documents_with_predictions"),
        "metrics": dict(metrics),
        "protocol_sha256": cmu_quality.get("protocol_sha256"),
        "run_sha256": cmu_quality.get("run_sha256"),
        "nonpromotable": True,
    }
    try:
        schema_error = next(_AUXILIARY_CARD_VALIDATOR.iter_errors(summary), None)
    except (RecursionError, TypeError, ValueError):
        schema_error = True
    if schema_error is not None:
        raise EnronBankBuildError("Auxiliary CMU quality evidence is invalid.")
    return summary


def _safe_slice_summary(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "documents": item["documents"],
        "documents_with_sensitive_gold": item["documents_with_sensitive_gold"],
        "gold_spans": item["gold_spans"],
        "true_positive": item["true_positive"],
        "false_negative": item["false_negative"],
        "cataloged_gold_spans": item["cataloged_gold_spans"],
        "cataloged_true_positive": item["cataloged_true_positive"],
        "cataloged_false_negative": item["cataloged_false_negative"],
        "cataloged_wrong_canonical": item["cataloged_wrong_canonical"],
        "labeled_span_recall": _ratio(item["true_positive"], item["gold_spans"]),
        "catalog_coverage": item["metrics"]["catalog_coverage"],
        "cataloged_recall": item["metrics"]["cataloged_recall"],
        "open_world_recall": None,
        "precision": None,
        "over_redaction_rate": None,
        "negative_document_false_alarm_rate": None,
    }


def _unsupported_slice_summary(reason_code: str) -> dict[str, Any]:
    return {
        "evaluated": False,
        "reason_code": reason_code,
        "documents": 0,
        "documents_with_sensitive_gold": 0,
        "gold_spans": 0,
        "true_positive": 0,
        "false_negative": 0,
        "cataloged_gold_spans": 0,
        "cataloged_true_positive": 0,
        "cataloged_false_negative": 0,
        "cataloged_wrong_canonical": 0,
        "labeled_span_recall": None,
        "catalog_coverage": None,
        "cataloged_recall": None,
        "open_world_recall": None,
        "precision": None,
        "over_redaction_rate": None,
        "negative_document_false_alarm_rate": None,
    }


def _private_manifest(
    options: EnronBankBuildOptions,
    *,
    source_binding: Mapping[str, Any],
    pool: CandidatePool,
    card: Mapping[str, Any],
    artifacts: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    return {
        "schema_version": BANK_BUILD_MANIFEST_SCHEMA_VERSION,
        "benchmark_version": options.benchmark_version,
        "artifact_kind": "private_enron_bank_build",
        "created_at": options.created_at,
        "source": dict(source_binding),
        "builder": {
            "source_sha256": _builder_implementation_sha256(),
            "policy": options.policy.descriptor(),
            "policy_sha256": options.policy.sha256,
            "candidate_source_sha256": pool.source_sha256,
            "candidate_ledger_sha256": pool.ledger_sha256,
        },
        "selected_bank_sha256": card["bank"]["canonical_sha256"],
        "bank_card_run_sha256": card["run_sha256"],
        "artifacts": {key: dict(value) for key, value in sorted(artifacts.items())},
        "privacy": {
            "private_pii_present": True,
            "public_card_privacy_passed": True,
            "sealed_test_accessed": False,
        },
    }


def _validate_public_card(card: Mapping[str, Any]) -> None:
    try:
        schema_error = next(_PUBLIC_CARD_VALIDATOR.iter_errors(card), None)
    except (RecursionError, TypeError, ValueError):
        schema_error = True
    if schema_error is not None or set(card) != _PUBLIC_CARD_FIELDS:
        raise EnronBankBuildError("Public bank card nested schema is invalid.")

    try:
        privacy_diagnostics = _public_serialization_diagnostics(cast(dict[str, Any], card))
    except (RecursionError, TypeError, ValueError):
        raise EnronBankBuildError(
            "Public bank card privacy scanner could not inspect the serialization safely."
        ) from None
    if privacy_diagnostics:
        raise EnronBankBuildError(
            "Public bank card privacy scanner rejected a direct identifier or private path shape."
        )

    _validate_public_card_invariants(card)
    expected_run = _canonical_hash({key: value for key, value in card.items() if key != "run_sha256"})
    if card.get("run_sha256") != expected_run:
        raise EnronBankBuildError("Public bank card run commitment is invalid.")


def _validate_public_card_invariants(card: Mapping[str, Any]) -> None:
    source = cast(Mapping[str, Any], card["source"])
    builder = cast(Mapping[str, Any], card["builder"])
    bank = cast(Mapping[str, Any], card["bank"])
    stats = cast(Mapping[str, Any], bank["stats"])
    funnel = cast(Mapping[str, Any], card["candidate_funnel"])
    iterations = cast(Sequence[Mapping[str, Any]], card["iterations"])
    validation = cast(Mapping[str, Any], card["validation"])
    conformance = cast(Mapping[str, Any], card["catalog_conformance"])
    auxiliary = cast(Mapping[str, Any], card["independent_auxiliary"])
    privacy = cast(Mapping[str, Any], card["privacy"])

    expected_reasons = {
        "sealed_final_test_unopened",
        "main_validation_independent_exhaustive_labels_unavailable",
        "main_validation_utility_metrics_unsupported",
    }
    if card["fixture_mode"] is True:
        expected_reasons.add("fixture_development_split")
    if (
        card["charter"] != _EXPECTED_CARD_CHARTER
        or card["nonpromotable_reasons"] != sorted(expected_reasons)
        or source["sealed_test_accessed"] is not False
        or builder["train_records"] != source["train_records"]
        or not _card_stats_are_consistent(stats)
        or not _card_funnel_is_consistent(funnel)
        or not _card_iterations_are_consistent(iterations, bank, validation)
        or not _card_validation_is_consistent(validation)
        or not _card_conformance_is_consistent(conformance, bank)
        or not _card_auxiliary_is_consistent(auxiliary)
    ):
        raise EnronBankBuildError("Public bank card semantic invariants are invalid.")

    expected_privacy = _canonical_hash({key: value for key, value in privacy.items() if key != "report_sha256"})
    if privacy["report_sha256"] != expected_privacy:
        raise EnronBankBuildError("Public bank card privacy report commitment is invalid.")
    if privacy["scanner_source_sha256"] != _public_card_scanner_sha256():
        raise EnronBankBuildError("Public bank card privacy scanner implementation commitment is invalid.")


def _card_stats_are_consistent(stats: Mapping[str, Any]) -> bool:
    totals = cast(Mapping[str, int], stats["totals"])
    active_totals = cast(Mapping[str, int], stats["active_totals"])
    by_status = cast(Mapping[str, Mapping[str, int]], stats["by_status"])
    by_kind = cast(Mapping[str, int], stats["by_kind"])
    for field in ("entities", "names", "patterns"):
        if totals[field] != sum(item[field] for item in by_status.values()):
            return False
        if active_totals[field] != by_status["active"][field]:
            return False
    return sum(by_kind.values()) == totals["patterns"]


def _card_funnel_is_consistent(funnel: Mapping[str, Any]) -> bool:
    total = cast(int, funnel["total_candidates"])
    by_decision = cast(Mapping[str, int], funnel["by_decision"])
    by_type = cast(Mapping[str, Mapping[str, int]], funnel["by_type"])
    by_reason = cast(Mapping[str, int], funnel["by_primary_reason"])
    observed_decisions = {name: 0 for name in ("active", "draft", "rejected")}
    for counts in by_type.values():
        if counts["total"] != sum(counts[name] for name in observed_decisions):
            return False
        for name in observed_decisions:
            observed_decisions[name] += counts[name]
    return (
        sum(by_decision.values()) == total
        and sum(item["total"] for item in by_type.values()) == total
        and sum(by_reason.values()) == total
        and observed_decisions == dict(by_decision)
    )


def _card_iterations_are_consistent(
    iterations: Sequence[Mapping[str, Any]],
    bank: Mapping[str, Any],
    validation: Mapping[str, Any],
) -> bool:
    expected = (
        (None, "discard", "superseded_by_bounded_email_fallback", False),
        (
            "iteration_01_catalog",
            "keep",
            "best_supported_privacy_recall_without_unsupported_phone_activation",
            True,
        ),
        ("iteration_02_email_recall", "discard", "independent_phone_negative_evidence_unavailable", False),
    )
    for row, policy, (parent_id, decision, reason, is_selected) in zip(
        iterations, ITERATION_POLICIES, expected, strict=True
    ):
        spans = cast(int, row["contact_labeled_spans"])
        true_positive = cast(int, row["contact_labeled_true_positive"])
        false_negative = cast(int, row["contact_labeled_false_negative"])
        person_values = (
            row["person_labeled_spans"],
            row["person_cataloged_false_negative"],
            row["person_cataloged_wrong_canonical"],
        )
        if (
            row["id"] != policy.id
            or row["parent_id"] != parent_id
            or row["policy_sha256"] != policy.sha256
            or row["decision"] != decision
            or row["decision_reason_code"] != reason
            or row["selected"] is not is_selected
            or spans != true_positive + false_negative
            or row["contact_labeled_recall"] != _ratio(true_positive, spans)
            or row["validation_protocol_sha256"] != validation["protocol_sha256"]
            or (any(value is None for value in person_values) and any(value is not None for value in person_values))
            or (
                all(value is not None for value in person_values)
                and cast(int, person_values[1]) + cast(int, person_values[2]) > cast(int, person_values[0])
            )
        ):
            return False

    selected_iteration = iterations[1]
    contact = cast(Mapping[str, Any], validation["contact"])
    person = cast(Mapping[str, Any], validation["person"])
    stats = cast(Mapping[str, Any], bank["stats"])
    active_stats = cast(Mapping[str, Any], stats["active_totals"])
    if person.get("evaluated") is False:
        person_matches = all(
            selected_iteration[field] is None
            for field in (
                "person_labeled_spans",
                "person_cataloged_false_negative",
                "person_cataloged_wrong_canonical",
            )
        )
    else:
        person_matches = bool(
            selected_iteration["person_labeled_spans"] == person["gold_spans"]
            and selected_iteration["person_cataloged_false_negative"] == person["cataloged_false_negative"]
            and selected_iteration["person_cataloged_wrong_canonical"] == person["cataloged_wrong_canonical"]
        )
    return bool(
        selected_iteration["bank_sha256"] == bank["canonical_sha256"]
        and selected_iteration["quality_run_sha256"] == validation["quality_run_sha256"]
        and selected_iteration["canonical_json_bytes"] == bank["canonical_json_bytes"]
        and selected_iteration["active_patterns"] == active_stats["patterns"]
        and selected_iteration["contact_labeled_spans"] == contact["gold_spans"]
        and selected_iteration["contact_labeled_true_positive"] == contact["true_positive"]
        and selected_iteration["contact_labeled_false_negative"] == contact["false_negative"]
        and selected_iteration["contact_cataloged_false_negative"] == contact["cataloged_false_negative"]
        and selected_iteration["contact_cataloged_wrong_canonical"] == contact["cataloged_wrong_canonical"]
        and person_matches
    )


def _card_validation_is_consistent(validation: Mapping[str, Any]) -> bool:
    contact = cast(Mapping[str, Any], validation["contact"])
    person = cast(Mapping[str, Any], validation["person"])
    if not _card_validation_slice_is_consistent(contact) or contact["gold_spans"] <= 0:
        return False
    if person.get("evaluated") is False:
        count_fields = (
            "documents",
            "documents_with_sensitive_gold",
            "gold_spans",
            "true_positive",
            "false_negative",
            "cataloged_gold_spans",
            "cataloged_true_positive",
            "cataloged_false_negative",
            "cataloged_wrong_canonical",
        )
        ratio_fields = (
            "labeled_span_recall",
            "catalog_coverage",
            "cataloged_recall",
            "open_world_recall",
            "precision",
            "over_redaction_rate",
            "negative_document_false_alarm_rate",
        )
        return all(person[field] == 0 for field in count_fields) and all(
            person[field] is None for field in ratio_fields
        )
    return _card_validation_slice_is_consistent(person)


def _card_validation_slice_is_consistent(item: Mapping[str, Any]) -> bool:
    documents = cast(int, item["documents"])
    sensitive_documents = cast(int, item["documents_with_sensitive_gold"])
    gold = cast(int, item["gold_spans"])
    true_positive = cast(int, item["true_positive"])
    false_negative = cast(int, item["false_negative"])
    cataloged = cast(int, item["cataloged_gold_spans"])
    cataloged_true = cast(int, item["cataloged_true_positive"])
    cataloged_false = cast(int, item["cataloged_false_negative"])
    cataloged_wrong = cast(int, item["cataloged_wrong_canonical"])
    return bool(
        sensitive_documents <= documents
        and gold == true_positive + false_negative
        and cataloged <= gold
        and cataloged == cataloged_true + cataloged_false + cataloged_wrong
        and item["labeled_span_recall"] == _ratio(true_positive, gold)
        and item["catalog_coverage"] == _ratio(cataloged, gold)
        and item["cataloged_recall"] == _ratio(cataloged_true, cataloged)
        and item["open_world_recall"] is None
        and item["precision"] is None
        and item["over_redaction_rate"] is None
        and item["negative_document_false_alarm_rate"] is None
    )


def _card_conformance_is_consistent(conformance: Mapping[str, Any], bank: Mapping[str, Any]) -> bool:
    approved = cast(int, conformance["approved_positive_cases"])
    correctly_mapped = cast(int, conformance["correctly_mapped"])
    missed = cast(int, conformance["missed"])
    wrong = cast(int, conformance["wrong_canonical"])
    stats = cast(Mapping[str, Any], bank["stats"])
    active_stats = cast(Mapping[str, Any], stats["active_totals"])
    return bool(
        conformance["active_patterns"] == active_stats["patterns"]
        and conformance["patterns_with_positive_cases"] == conformance["active_patterns"]
        and approved == correctly_mapped + missed + wrong
        and conformance["recall"] == _ratio(correctly_mapped, approved)
        and missed == 0
        and wrong == 0
        and conformance["unexpected_negative_matches"] == 0
    )


def _card_auxiliary_is_consistent(auxiliary: Mapping[str, Any]) -> bool:
    if auxiliary["evaluated"] is False:
        return True
    documents = cast(int, auxiliary["documents"])
    sensitive_documents = cast(int, auxiliary["documents_with_sensitive_gold"])
    miss_documents = cast(int, auxiliary["documents_with_any_miss"])
    cataloged_documents = cast(int, auxiliary["documents_with_cataloged_gold"])
    catalog_miss_documents = cast(int, auxiliary["documents_with_any_cataloged_miss"])
    leaked_character_documents = cast(int, auxiliary["documents_with_any_leaked_character"])
    true_positive = cast(int, auxiliary["true_positive"])
    false_positive = cast(int, auxiliary["false_positive"])
    false_negative = cast(int, auxiliary["false_negative"])
    gold = cast(int, auxiliary["gold_spans"])
    predicted = cast(int, auxiliary["predicted_spans"])
    cataloged = cast(int, auxiliary["cataloged_gold_spans"])
    cataloged_true = cast(int, auxiliary["cataloged_true_positive"])
    cataloged_false = cast(int, auxiliary["cataloged_false_negative"])
    cataloged_wrong = cast(int, auxiliary["cataloged_wrong_canonical"])
    sensitive_characters = cast(int, auxiliary["sensitive_gold_characters"])
    covered_characters = cast(int, auxiliary["covered_sensitive_characters"])
    leaked_characters = cast(int, auxiliary["leaked_sensitive_characters"])
    predicted_characters = cast(int, auxiliary["predicted_characters"])
    over_redacted_characters = cast(int, auxiliary["over_redacted_characters"])
    evaluated_characters = cast(int, auxiliary["evaluated_characters"])
    negative_documents = cast(int, auxiliary["negative_documents"])
    negative_documents_with_predictions = cast(int, auxiliary["negative_documents_with_predictions"])
    metrics = cast(Mapping[str, Any], auxiliary["metrics"])
    return bool(
        auxiliary["label_strength"] == "independent"
        and auxiliary["annotation_completeness"] == "exhaustive_within_scope"
        and sensitive_documents <= documents
        and miss_documents <= sensitive_documents
        and cataloged_documents <= sensitive_documents
        and catalog_miss_documents <= cataloged_documents
        and leaked_character_documents <= sensitive_documents
        and negative_documents == documents - sensitive_documents
        and negative_documents_with_predictions <= negative_documents
        and gold == true_positive + false_negative
        and predicted == true_positive + false_positive
        and cataloged <= gold
        and cataloged == cataloged_true + cataloged_false + cataloged_wrong
        and cataloged_true + cataloged_wrong <= true_positive
        and sensitive_characters == covered_characters + leaked_characters
        and predicted_characters == covered_characters + over_redacted_characters
        and predicted_characters <= evaluated_characters
        and metrics["precision"] == _ratio(true_positive, predicted)
        and metrics["open_world_recall"] == _ratio(true_positive, gold)
        and metrics["f1"] == _ratio(2 * true_positive, 2 * true_positive + false_positive + false_negative)
        and metrics["catalog_coverage"] == _ratio(cataloged, gold)
        and metrics["cataloged_recall"] == _ratio(cataloged_true, cataloged)
        and metrics["document_leak_rate"] == _ratio(miss_documents, sensitive_documents)
        and metrics["cataloged_document_leak_rate"] == _ratio(catalog_miss_documents, cataloged_documents)
        and metrics["sensitive_character_recall"] == _ratio(covered_characters, sensitive_characters)
        and metrics["sensitive_character_leak_rate"] == _ratio(leaked_characters, sensitive_characters)
        and metrics["negative_document_false_alarm_rate"]
        == _ratio(negative_documents_with_predictions, negative_documents)
        and metrics["over_redaction_rate"] == _ratio(over_redacted_characters, evaluated_characters)
    )


_PRIVATE_MANIFEST_FIELDS = {
    "schema_version",
    "benchmark_version",
    "artifact_kind",
    "created_at",
    "source",
    "builder",
    "selected_bank_sha256",
    "bank_card_run_sha256",
    "artifacts",
    "privacy",
}
_PRIVATE_SOURCE_FIELDS = {
    "benchmark_version",
    "dataset_id",
    "dataset_revision",
    "dataset_split",
    "development_manifest_sha256",
    "full_split_manifest_sha256",
    "split_policy_sha256",
    "preparation_manifest_sha256",
    "train_artifact_sha256",
    "train_artifact_bytes",
    "train_records",
    "train_groups",
    "validation_artifact_sha256",
    "validation_artifact_bytes",
    "validation_records",
    "validation_groups",
    "development_memberships_sha256",
    "fixture_mode",
    "sealed_test_accessed",
}
_CARD_SOURCE_FIELDS = _PRIVATE_SOURCE_FIELDS - {
    "benchmark_version",
    "fixture_mode",
    "train_artifact_bytes",
    "validation_artifact_bytes",
}
_PRIVATE_BUILDER_FIELDS = {
    "source_sha256",
    "policy",
    "policy_sha256",
    "candidate_source_sha256",
    "candidate_ledger_sha256",
}
_POLICY_THRESHOLD_FIELDS = {
    "minimum_contact_groups",
    "minimum_person_alias_groups",
    "minimum_domain_groups",
}
_POLICY_CAPACITY_FIELDS = {
    "max_active_contacts",
    "max_active_people",
    "max_active_person_aliases",
    "max_active_domains",
    "max_draft_per_class",
    "max_active_patterns",
    "max_pattern_utf8_bytes",
    "max_bank_json_bytes",
    "max_train_records",
    "max_train_artifact_bytes",
    "max_validation_records",
    "max_validation_artifact_bytes",
    "max_validation_entries",
    "max_validation_spans",
    "max_validation_text_utf8_bytes",
    "max_development_memberships_bytes",
    "max_development_samples_bytes",
    "max_quality_predictions",
    "max_header_entries_per_document",
    "max_observations",
    "max_unique_candidates",
    "max_candidate_value_bytes",
}


def _validate_private_manifest(manifest: Mapping[str, Any]) -> tuple[Mapping[str, Any], EnronBankPolicy]:
    if (
        set(manifest) != _PRIVATE_MANIFEST_FIELDS
        or manifest.get("schema_version") != BANK_BUILD_MANIFEST_SCHEMA_VERSION
        or manifest.get("artifact_kind") != "private_enron_bank_build"
        or not isinstance(manifest.get("benchmark_version"), str)
        or not manifest.get("benchmark_version")
        or not isinstance(manifest.get("created_at"), str)
        or not manifest.get("created_at")
        or not isinstance(manifest.get("artifacts"), Mapping)
    ):
        raise EnronBankBuildError("Private bank-build manifest is invalid.")
    source = manifest.get("source")
    builder = manifest.get("builder")
    privacy = manifest.get("privacy")
    if (
        not isinstance(source, Mapping)
        or set(source) != _PRIVATE_SOURCE_FIELDS
        or not isinstance(builder, Mapping)
        or set(builder) != _PRIVATE_BUILDER_FIELDS
        or not isinstance(privacy, Mapping)
        or set(privacy)
        != {
            "private_pii_present",
            "public_card_privacy_passed",
            "sealed_test_accessed",
        }
    ):
        raise EnronBankBuildError("Private bank-build manifest nested schema is invalid.")
    string_fields = {"benchmark_version", "dataset_id", "dataset_revision", "dataset_split"}
    count_fields = {
        "train_artifact_bytes",
        "train_records",
        "train_groups",
        "validation_artifact_bytes",
        "validation_records",
        "validation_groups",
    }
    hash_fields = (
        _PRIVATE_SOURCE_FIELDS
        - string_fields
        - count_fields
        - {
            "fixture_mode",
            "sealed_test_accessed",
        }
    )
    if (
        any(not isinstance(source.get(field), str) or not source[field] for field in string_fields)
        or any(type(source.get(field)) is not int or cast(int, source[field]) <= 0 for field in count_fields)
        or any(not _is_sha256(source.get(field)) for field in hash_fields)
        or type(source.get("fixture_mode")) is not bool
        or source.get("sealed_test_accessed") is not False
        or source.get("benchmark_version") != manifest.get("benchmark_version")
        or privacy
        != {
            "private_pii_present": True,
            "public_card_privacy_passed": True,
            "sealed_test_accessed": False,
        }
        or not _is_sha256(manifest.get("selected_bank_sha256"))
        or not _is_sha256(manifest.get("bank_card_run_sha256"))
    ):
        raise EnronBankBuildError("Private bank-build manifest values are invalid.")
    policy = _policy_from_descriptor(builder.get("policy"))
    if (
        any(
            not _is_sha256(builder.get(field))
            for field in (
                "source_sha256",
                "policy_sha256",
                "candidate_source_sha256",
                "candidate_ledger_sha256",
            )
        )
        or builder.get("policy_sha256") != policy.sha256
    ):
        raise EnronBankBuildError("Private bank-build builder commitment is invalid.")
    return source, policy


def _policy_from_descriptor(value: Any) -> EnronBankPolicy:
    if not isinstance(value, Mapping):
        raise EnronBankBuildError("Private bank-build policy descriptor is invalid.")
    expected_fields = set(EnronBankPolicy().descriptor())
    thresholds = value.get("thresholds")
    capacity = value.get("capacity")
    internal_domains = value.get("internal_domains")
    if (
        set(value) != expected_fields
        or not isinstance(thresholds, Mapping)
        or set(thresholds) != _POLICY_THRESHOLD_FIELDS
        or not isinstance(capacity, Mapping)
        or set(capacity) != _POLICY_CAPACITY_FIELDS
        or not isinstance(internal_domains, list)
        or not internal_domains
        or len(internal_domains) != len(set(internal_domains))
        or any(not isinstance(item, str) or not item for item in internal_domains)
        or any(type(thresholds.get(field)) is not int for field in _POLICY_THRESHOLD_FIELDS)
        or any(type(capacity.get(field)) is not int for field in _POLICY_CAPACITY_FIELDS)
    ):
        raise EnronBankBuildError("Private bank-build policy descriptor is invalid.")
    kwargs: dict[str, Any] = {
        "internal_domains": tuple(internal_domains),
        **{field: thresholds[field] for field in _POLICY_THRESHOLD_FIELDS},
        **{field: capacity[field] for field in _POLICY_CAPACITY_FIELDS},
    }
    try:
        policy = EnronBankPolicy(**kwargs)
        _validate_policy(policy)
    except (TypeError, EnronBankBuildError):
        raise EnronBankBuildError("Private bank-build policy descriptor is invalid.") from None
    if policy.descriptor() != value:
        raise EnronBankBuildError("Private bank-build policy descriptor is not canonical.")
    return policy


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _validate_build_commitments(
    manifest: Mapping[str, Any],
    *,
    source: Mapping[str, Any],
    policy: EnronBankPolicy,
    card: Mapping[str, Any],
    bank: Mapping[str, Any],
    artifacts: Mapping[str, Mapping[str, Any]],
) -> bool:
    manifest_builder = cast(Mapping[str, Any], manifest["builder"])
    card_builder = card.get("builder")
    card_source = card.get("source")
    bank_metadata = bank.get("metadata")
    current_implementation = _builder_implementation_sha256()
    if (
        not isinstance(card_builder, Mapping)
        or not isinstance(card_source, Mapping)
        or not isinstance(bank_metadata, Mapping)
        or card.get("benchmark_version") != manifest.get("benchmark_version")
        or source.get("benchmark_version") != manifest.get("benchmark_version")
        or card_source != {field: source[field] for field in _CARD_SOURCE_FIELDS}
        or manifest_builder.get("source_sha256") != current_implementation
        or card_builder.get("source_sha256") != current_implementation
        or bank_metadata.get("builder_implementation_sha256") != current_implementation
        or manifest_builder.get("policy_sha256") != policy.sha256
        or card_builder.get("policy_sha256") != policy.sha256
        or bank_metadata.get("builder_policy_sha256") != policy.sha256
        or manifest_builder.get("candidate_source_sha256") != card_builder.get("candidate_source_sha256")
        or manifest_builder.get("candidate_source_sha256") != bank_metadata.get("candidate_source_sha256")
        or manifest_builder.get("candidate_ledger_sha256") != card_builder.get("candidate_ledger_sha256")
        or manifest_builder.get("candidate_ledger_sha256") != bank_metadata.get("candidate_ledger_sha256")
        or bank_metadata.get("source") != source
        or bank_metadata.get("iteration_id") != ITERATION_POLICIES[1].id
        or bank_metadata.get("iteration_policy_sha256") != ITERATION_POLICIES[1].sha256
        or manifest.get("selected_bank_sha256") != hash_bank(bank)
        or card.get("bank")
        != {
            "id": bank.get("id"),
            "version": bank.get("version"),
            "canonical_sha256": hash_bank(bank),
            "artifact_sha256": artifacts["selected_bank"]["sha256"],
            "canonical_json_bytes": len(_canonical_json_bytes(bank)),
            "stats": bank_stats(bank),
        }
    ):
        raise EnronBankBuildError("Private bank-build commitments are inconsistent.")
    if (
        source.get("sealed_test_accessed") is not False
        or cast(Mapping[str, Any], manifest["privacy"]).get("sealed_test_accessed") is not False
        or card_source.get("sealed_test_accessed") is not False
        or bank_metadata.get("sealed_test_accessed") is not False
    ):
        raise EnronBankBuildError("Private bank-build sealed-test declaration is inconsistent.")
    return False


def verify_enron_bank_build(
    run_dir: Path,
    *,
    annotation_run: Path | None = None,
) -> dict[str, Any]:
    """Deep-verify a committed private build and return aggregate-only evidence."""

    root = _assert_private_run(Path(run_dir))
    initial_tree = _snapshot_private_tree(root)
    initial_marker = _fingerprint_private_artifact(
        root / "COMMITTED",
        max_bytes=_MAX_PRIVATE_COMMIT_MARKER_BYTES,
    )
    initial_manifest = _fingerprint_private_artifact(
        root / "manifest.json",
        max_bytes=_MAX_PRIVATE_MANIFEST_BYTES,
    )
    if (
        initial_tree.get("COMMITTED") != initial_marker.identity
        or initial_marker.sha256 != _PRIVATE_COMMIT_MARKER_SHA256
        or initial_tree.get("manifest.json") != initial_manifest.identity
    ):
        raise EnronBankBuildError("Private bank-build tree changed while verification started.")
    manifest = _read_private_json(
        root / "manifest.json",
        expected_fingerprint=initial_manifest,
        max_bytes=_MAX_PRIVATE_MANIFEST_BYTES,
    )
    if not isinstance(manifest, Mapping):
        raise EnronBankBuildError("Private bank-build manifest is invalid.")
    source, policy = _validate_private_manifest(manifest)
    raw_artifacts = cast(Mapping[str, Any], manifest["artifacts"])
    artifact_names = _expected_artifact_names(raw_artifacts)
    _verify_private_tree_inventory(initial_tree, artifact_names)
    artifacts: dict[str, Mapping[str, Any]] = {}
    artifact_fingerprints: dict[str, _PrivateFileFingerprint] = {}
    for artifact_id, expected_name in artifact_names.items():
        descriptor = raw_artifacts.get(artifact_id)
        if not isinstance(descriptor, Mapping):
            raise EnronBankBuildError("Private artifact descriptor schema is invalid.")
        artifact_fingerprints[artifact_id] = _verify_artifact_descriptor(
            root,
            artifact_id,
            descriptor,
            expected_name=expected_name,
            tree=initial_tree,
        )
        artifacts[artifact_id] = cast(Mapping[str, Any], descriptor)

    card = _read_private_json(
        root / "bank-card.json",
        expected_fingerprint=artifact_fingerprints["bank_card"],
    )
    if not isinstance(card, Mapping):
        raise EnronBankBuildError("Private bank card is invalid.")
    _validate_public_card(card)
    if manifest.get("bank_card_run_sha256") != card.get("run_sha256"):
        raise EnronBankBuildError("Private manifest does not bind the bank card.")

    bank = _read_private_json(
        root / "bank.json",
        expected_fingerprint=artifact_fingerprints["selected_bank"],
    )
    if not isinstance(bank, Mapping):
        raise EnronBankBuildError("Selected private bank is invalid.")
    structural = validate_bank(bank, level="deep", strict=True, check_engine_compile=True)
    if structural["valid"] is not True or structural["engine_compatibility"]["compatible"] is not True:
        raise EnronBankBuildError("Selected private bank failed deep verification.")
    if hash_bank(bank) != manifest.get("selected_bank_sha256") or hash_bank(bank) != card["bank"]["canonical_sha256"]:
        raise EnronBankBuildError("Selected private bank commitment is invalid.")
    sealed_test_accessed = _validate_build_commitments(
        manifest,
        source=source,
        policy=policy,
        card=card,
        bank=bank,
        artifacts=artifacts,
    )

    positive = _read_private_jsonl(
        root / "conformance/positive.jsonl",
        expected_fingerprint=artifact_fingerprints["conformance_positive"],
    )
    negative = _read_private_jsonl(
        root / "conformance/negative.jsonl",
        expected_fingerprint=artifact_fingerprints["conformance_negative"],
    )
    expected_conformance = _read_private_json(
        root / "conformance/result.json",
        expected_fingerprint=artifact_fingerprints["conformance_result"],
    )
    try:
        actual_conformance = evaluate_enron_conformance(bank, positive, negative)
    except EnronConformanceError:
        raise EnronBankBuildError("Private conformance evidence could not be re-evaluated.") from None
    if (
        actual_conformance != expected_conformance
        or actual_conformance["catalog_conformance"] != card["catalog_conformance"]
    ):
        raise EnronBankBuildError("Private conformance evidence changed during verification.")

    documents = _read_private_jsonl(
        root / "validation/documents.jsonl",
        expected_fingerprint=artifact_fingerprints["validation_documents"],
    )
    slices = _read_private_jsonl(
        root / "validation/slices.jsonl",
        expected_fingerprint=artifact_fingerprints["validation_slices"],
    )
    unsupported = _read_private_jsonl(
        root / "validation/unsupported.jsonl",
        expected_fingerprint=artifact_fingerprints["validation_unsupported"],
    )
    iteration_rows = _read_private_jsonl(
        root / "iterations.jsonl",
        expected_fingerprint=artifact_fingerprints["iterations"],
    )
    if len(iteration_rows) != 3:
        raise EnronBankBuildError("Private iteration ledger is incomplete.")

    replayed_pool = _replay_candidate_pool(
        root / "mining.sqlite3",
        train_artifact_sha256=str(source["train_artifact_sha256"]),
        policy=policy,
        expected_fingerprint=artifact_fingerprints["mining_spool"],
    )
    manifest_builder = cast(Mapping[str, Any], manifest["builder"])
    raw_card_builder = card.get("builder")
    if not isinstance(raw_card_builder, Mapping):
        raise EnronBankBuildError("Private bank card builder commitment is invalid.")
    card_builder = cast(Mapping[str, Any], raw_card_builder)
    if (
        replayed_pool.source_sha256 != manifest_builder.get("candidate_source_sha256")
        or replayed_pool.source_sha256 != card_builder.get("candidate_source_sha256")
        or replayed_pool.ledger_sha256 != manifest_builder.get("candidate_ledger_sha256")
        or replayed_pool.ledger_sha256 != card_builder.get("candidate_ledger_sha256")
        or replayed_pool.train_records != card_builder.get("train_records")
        or replayed_pool.train_records != source.get("train_records")
        or replayed_pool.observations != card_builder.get("observations")
        or replayed_pool.observations != artifacts["mining_spool"].get("records")
    ):
        raise EnronBankBuildError("Private mining spool commitments differ from replay.")

    implementation_sha256 = _builder_implementation_sha256()
    replayed_curated = tuple(
        _bind_curated_iteration(
            curate_enron_iteration(
                replayed_pool,
                policy=policy,
                iteration=iteration,
                source_binding=source,
                created_at=str(manifest["created_at"]),
                retain_candidate_ledger=iteration == ITERATION_POLICIES[1],
            ),
            pool=replayed_pool,
            policy=policy,
            implementation_sha256=implementation_sha256,
        )
        for iteration in ITERATION_POLICIES
    )

    iteration_banks: list[dict[str, Any]] = []
    for index in range(1, 4):
        iteration_policy = ITERATION_POLICIES[index - 1]
        iteration_bank = _read_private_json(
            root / f"banks/{iteration_policy.id}.json",
            expected_fingerprint=artifact_fingerprints[f"iteration_{index:02d}_bank"],
        )
        if not isinstance(iteration_bank, Mapping):
            raise EnronBankBuildError("Private iteration artifact is invalid.")
        replayed_bank = replayed_curated[index - 1].bank
        if _canonical_json_bytes(iteration_bank) != _canonical_json_bytes(replayed_bank):
            raise EnronBankBuildError("Private iteration bank differs from replayed mining and curation.")
        iteration_banks.append(replayed_bank)

    replayed_iterations: list[dict[str, Any]] = []
    for index, (iteration_policy, replayed_bank) in enumerate(
        zip(ITERATION_POLICIES, iteration_banks, strict=True),
        start=1,
    ):
        gold = _read_private_jsonl(
            root / f"validation/gold-iteration-{index:02d}.jsonl",
            expected_fingerprint=artifact_fingerprints[f"validation_gold_{index:02d}"],
        )
        expected_quality = _read_private_json(
            root / f"validation/quality-iteration-{index:02d}.json",
            expected_fingerprint=artifact_fingerprints[f"validation_quality_{index:02d}"],
        )
        if not isinstance(expected_quality, Mapping):
            raise EnronBankBuildError("Private iteration artifact is invalid.")
        iteration_structural = validate_bank(
            replayed_bank,
            level="deep",
            strict=True,
            check_engine_compile=True,
        )
        if (
            iteration_structural["valid"] is not True
            or iteration_structural["engine_compatibility"]["compatible"] is not True
        ):
            raise EnronBankBuildError("Private iteration bank failed deep verification.")
        structural_summary = _structural_summary(iteration_structural)
        stored_structural = _read_private_json(
            root / f"validation/structural-iteration-{index:02d}.json",
            expected_fingerprint=artifact_fingerprints[f"validation_structural_{index:02d}"],
        )
        if stored_structural != structural_summary:
            raise EnronBankBuildError("Private structural summary differs from recomputation.")
        try:
            actual_quality = evaluate_enron_quality(
                replayed_bank,
                documents=documents,
                gold_spans=gold,
                slice_specs=slices,
                unsupported_slice_specs=unsupported,
            )
        except EnronQualityError:
            raise EnronBankBuildError("Private validation evidence could not be re-evaluated.") from None
        if actual_quality != expected_quality:
            raise EnronBankBuildError("Private validation evidence changed during verification.")
        if iteration_rows[index - 1]["quality_run_sha256"] != actual_quality["run_sha256"]:
            raise EnronBankBuildError("Private iteration ledger does not bind quality evidence.")
        replayed_iterations.append(
            {
                "iteration": iteration_policy,
                "bank": replayed_bank,
                "quality": actual_quality,
                "structural": structural_summary,
                "limits": {"canonical_json_bytes": len(_canonical_json_bytes(replayed_bank))},
            }
        )

    replayed_ledger = _decide_iterations(replayed_iterations)
    if (
        tuple(iteration_rows) != replayed_ledger
        or card.get("iterations") != [dict(item) for item in replayed_ledger]
        or card_builder.get("selected_iteration_id") != ITERATION_POLICIES[1].id
        or _canonical_json_bytes(bank) != _canonical_json_bytes(iteration_banks[1])
    ):
        raise EnronBankBuildError("Private promotion ledger differs from the replayed decision.")

    cmu_reverified = False
    stored_cmu: Mapping[str, Any] | None = None
    if "cmu_quality" in artifacts:
        raw_stored_cmu = _read_private_json(
            root / "auxiliary/cmu-train-quality.json",
            expected_fingerprint=artifact_fingerprints["cmu_quality"],
        )
        if not isinstance(raw_stored_cmu, Mapping):
            raise EnronBankBuildError("Auxiliary CMU evidence is invalid.")
        stored_cmu = raw_stored_cmu
        bindings = _read_private_jsonl(
            root / "auxiliary/cmu-train-catalog-bindings.jsonl",
            expected_fingerprint=artifact_fingerprints["cmu_catalog_bindings"],
        )
        if annotation_run is not None:
            try:
                actual_cmu = evaluate_cmu_enron_training_quality(
                    bank,
                    annotation_run_dir=annotation_run,
                    catalog_bindings=bindings,
                )
            except (EnronAnnotationError, EnronQualityError):
                raise EnronBankBuildError("Auxiliary CMU evidence could not be re-evaluated.") from None
            if actual_cmu != stored_cmu:
                raise EnronBankBuildError("Auxiliary CMU evidence changed during verification.")
            cmu_reverified = True
    if card.get("independent_auxiliary") != _independent_auxiliary_summary(stored_cmu):
        raise EnronBankBuildError("Public auxiliary summary differs from private CMU evidence.")

    replayed_selected = replayed_curated[1]

    candidates = _read_private_jsonl(
        root / "candidates.jsonl",
        expected_fingerprint=artifact_fingerprints["candidates"],
    )
    actual_funnel = _verify_candidate_ledger(candidates, bank)
    funnel = _read_private_json(
        root / "candidate-funnel.json",
        expected_fingerprint=artifact_fingerprints["candidate_funnel"],
    )
    collisions = _read_private_json(
        root / "collision-report.json",
        expected_fingerprint=artifact_fingerprints["collision_report"],
    )
    if not isinstance(funnel, Mapping) or funnel.get("schema_version") != CANDIDATE_FUNNEL_SCHEMA_VERSION:
        raise EnronBankBuildError("Private candidate funnel is invalid.")
    candidate_count = int(artifacts["candidates"]["records"])
    if candidates != replayed_selected.candidates:
        raise EnronBankBuildError("Private candidate ledger differs from replayed mining and curation.")
    if _canonical_json_bytes(bank) != _canonical_json_bytes(replayed_selected.bank):
        raise EnronBankBuildError("Selected private bank differs from replayed curation.")
    if (
        len(candidates) != candidate_count
        or funnel != actual_funnel
        or funnel != card.get("candidate_funnel")
        or funnel != replayed_selected.funnel
    ):
        raise EnronBankBuildError("Private candidate funnel does not conserve the candidate ledger.")
    if collisions != replayed_selected.collisions:
        raise EnronBankBuildError("Private collision report differs from replayed curation.")

    final_tree = _snapshot_private_tree(root)
    final_marker = _fingerprint_private_artifact(
        root / "COMMITTED",
        max_bytes=_MAX_PRIVATE_COMMIT_MARKER_BYTES,
    )
    final_manifest = _fingerprint_private_artifact(
        root / "manifest.json",
        max_bytes=_MAX_PRIVATE_MANIFEST_BYTES,
    )
    if final_tree != initial_tree or final_marker != initial_marker or final_manifest != initial_manifest:
        raise EnronBankBuildError("Private bank-build tree changed during verification.")

    return {
        "schema_version": "nerb.enron_bank_build_verification.v2",
        "valid": True,
        "benchmark_version": manifest["benchmark_version"],
        "fixture_mode": card["fixture_mode"],
        "promotable": False,
        "bank_sha256": hash_bank(bank),
        "bank_card_run_sha256": card["run_sha256"],
        "candidate_count": candidate_count,
        "iteration_count": len(iteration_rows),
        "selected_iteration_id": card["builder"]["selected_iteration_id"],
        "catalog_conformance_passed": True,
        "validation_reverified": True,
        "cmu_reverified": cmu_reverified,
        "sealed_test_accessed": sealed_test_accessed,
        "privacy": card["privacy"],
    }


_MINING_SQLITE_SCHEMA = {
    "candidate_values": """
        CREATE TABLE candidate_values (
            kind TEXT NOT NULL,
            normalized_value TEXT NOT NULL,
            PRIMARY KEY (kind, normalized_value)
        ) WITHOUT ROWID
    """,
    "observations": """
        CREATE TABLE observations (
            kind TEXT NOT NULL,
            normalized_value TEXT NOT NULL,
            surface TEXT NOT NULL,
            related TEXT NOT NULL,
            source_type TEXT NOT NULL,
            document_id TEXT NOT NULL,
            group_id TEXT NOT NULL,
            observed_at TEXT,
            occurrences INTEGER NOT NULL,
            PRIMARY KEY (kind, normalized_value, surface, related, source_type, document_id)
        ) WITHOUT ROWID
    """,
    "source_projections": """
        CREATE TABLE source_projections (
            document_id TEXT NOT NULL PRIMARY KEY,
            payload BLOB NOT NULL
        ) WITHOUT ROWID
    """,
}
_MINING_SQLITE_COLUMNS = {
    "candidate_values": (
        (0, "kind", "TEXT", 1, None, 1, 0),
        (1, "normalized_value", "TEXT", 1, None, 2, 0),
    ),
    "observations": (
        (0, "kind", "TEXT", 1, None, 1, 0),
        (1, "normalized_value", "TEXT", 1, None, 2, 0),
        (2, "surface", "TEXT", 1, None, 3, 0),
        (3, "related", "TEXT", 1, None, 4, 0),
        (4, "source_type", "TEXT", 1, None, 5, 0),
        (5, "document_id", "TEXT", 1, None, 6, 0),
        (6, "group_id", "TEXT", 1, None, 0, 0),
        (7, "observed_at", "TEXT", 0, None, 0, 0),
        (8, "occurrences", "INTEGER", 1, None, 0, 0),
    ),
    "source_projections": (
        (0, "document_id", "TEXT", 1, None, 1, 0),
        (1, "payload", "BLOB", 1, None, 0, 0),
    ),
}


def _replay_candidate_pool(
    sqlite_path: Path,
    *,
    train_artifact_sha256: str,
    policy: EnronBankPolicy,
    expected_fingerprint: _PrivateFileFingerprint,
) -> CandidatePool:
    """Reconstruct the train candidate pool from a verified private snapshot."""

    try:
        with tempfile.TemporaryDirectory(prefix="nerb-private-mining-spool-") as temporary:
            temporary_path = Path(temporary)
            temporary_path.chmod(0o700)
            snapshot_path = temporary_path / "mining.sqlite3"
            _copy_verified_private_artifact(
                sqlite_path,
                snapshot_path,
                expected_fingerprint=expected_fingerprint,
                max_bytes=_MAX_PRIVATE_SQLITE_BYTES,
            )
            return _replay_candidate_pool_snapshot(
                snapshot_path,
                train_artifact_sha256=train_artifact_sha256,
                policy=policy,
            )
    except EnronBankBuildError:
        raise
    except (OSError, TypeError, ValueError):
        raise EnronBankBuildError("Private mining spool could not be snapshotted safely.") from None


def _replay_candidate_pool_snapshot(
    sqlite_path: Path,
    *,
    train_artifact_sha256: str,
    policy: EnronBankPolicy,
) -> CandidatePool:
    """Replay a process-owned, bounded, immutable SQLite snapshot."""

    uri = f"file:{quote(str(sqlite_path), safe='/')}?mode=ro&immutable=1"
    try:
        connection = sqlite3.connect(uri, uri=True)
    except sqlite3.Error:
        raise EnronBankBuildError("Private mining spool could not be opened read-only.") from None
    try:
        _set_mining_sqlite_length_limit(connection)
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        _preflight_mining_sqlite_schema_cells(connection)
        _validate_mining_sqlite_schema(connection)
        _preflight_mining_sqlite_cells(connection, policy)
        quick_check = connection.execute("PRAGMA quick_check(1)").fetchall()
        if quick_check != [("ok",)]:
            raise EnronBankBuildError("Private mining spool failed its integrity check.")

        source_digest = hashlib.sha256(b"nerb/enron/bank-mining-source/v2\0")
        train_records = 0
        for document_id, payload in _iter_mining_source_projections(connection):
            train_records += 1
            if train_records > policy.max_train_records:
                raise EnronBankBuildError("Private mining spool exceeds the train-record limit.")
            if not isinstance(document_id, str) or _DOCUMENT_ID_RE.fullmatch(document_id) is None:
                raise EnronBankBuildError("Private mining source projection identifier is invalid.")
            if not isinstance(payload, bytes):
                raise EnronBankBuildError("Private mining source projection payload is invalid.")
            if len(payload) > _MAX_PRIVATE_SQLITE_PROJECTION_BYTES:
                raise EnronBankBuildError("Private mining source projection exceeds its byte limit.")
            try:
                projection = json.loads(
                    payload,
                    object_pairs_hook=_reject_duplicate_keys,
                    parse_constant=_reject_constant,
                    parse_float=_parse_finite_float,
                    parse_int=_parse_bounded_private_int,
                )
            except (OverflowError, RecursionError, TypeError, ValueError, UnicodeError):
                raise EnronBankBuildError("Private mining source projection payload is invalid.") from None
            if (
                not isinstance(projection, Mapping)
                or set(projection)
                != {
                    "document_id",
                    "group_id",
                    "observed_at",
                    "structured_entries",
                    "sender_body_aliases",
                }
                or projection.get("document_id") != document_id
                or not _is_sha256(projection.get("group_id"))
                or (projection.get("observed_at") is not None and not isinstance(projection.get("observed_at"), str))
                or (
                    isinstance(projection.get("observed_at"), str)
                    and len(cast(str, projection["observed_at"]).encode("utf-8")) > _MAX_MINING_OBSERVED_AT_BYTES
                )
                or type(projection.get("structured_entries")) is not int
                or cast(int, projection["structured_entries"]) < 0
                or type(projection.get("sender_body_aliases")) is not int
                or cast(int, projection["sender_body_aliases"]) < 0
                or _canonical_json_bytes(projection) != payload
            ):
                raise EnronBankBuildError("Private mining source projection is not canonical.")
            source_digest.update(payload)
        if train_records == 0:
            raise EnronBankBuildError("Private mining spool has no train source projections.")

        malformed_observation = connection.execute(
            """
            SELECT 1
            FROM observations
            WHERE typeof(kind) != 'text'
               OR kind NOT IN ('contact', 'organization_domain', 'person_alias')
               OR typeof(normalized_value) != 'text' OR length(normalized_value) = 0
               OR typeof(surface) != 'text' OR length(surface) = 0
               OR typeof(related) != 'text'
               OR typeof(source_type) != 'text'
               OR source_type NOT IN (
                    'structured_header', 'structured_display_name', 'sender_body_local_link'
               )
               OR (kind IN ('contact', 'organization_domain') AND source_type != 'structured_header')
               OR (kind = 'person_alias' AND source_type NOT IN (
                    'structured_display_name', 'sender_body_local_link'
               ))
               OR (kind = 'person_alias' AND length(related) = 0)
               OR (kind != 'person_alias' AND length(related) != 0)
               OR typeof(document_id) != 'text' OR length(document_id) = 0
               OR typeof(group_id) != 'text' OR length(group_id) = 0
               OR (observed_at IS NOT NULL AND typeof(observed_at) != 'text')
               OR typeof(occurrences) != 'integer' OR occurrences <= 0
            LIMIT 1
            """
        ).fetchone()
        malformed_candidate = connection.execute(
            """
            SELECT 1
            FROM candidate_values
            WHERE typeof(kind) != 'text'
               OR kind NOT IN ('contact', 'organization_domain', 'person_alias')
               OR typeof(normalized_value) != 'text'
               OR length(normalized_value) = 0
            LIMIT 1
            """
        ).fetchone()
        source_mismatch = connection.execute(
            """
            SELECT 1
            FROM observations AS observation
            LEFT JOIN source_projections AS source
              ON source.document_id = observation.document_id
            WHERE source.document_id IS NULL
               OR observation.group_id != json_extract(CAST(source.payload AS TEXT), '$.group_id')
               OR NOT (
                    (observation.observed_at IS NULL
                     AND json_type(CAST(source.payload AS TEXT), '$.observed_at') = 'null')
                    OR observation.observed_at = json_extract(
                        CAST(source.payload AS TEXT), '$.observed_at'
                    )
               )
            LIMIT 1
            """
        ).fetchone()
        missing_candidate = connection.execute(
            """
            SELECT kind, normalized_value FROM observations
            EXCEPT
            SELECT kind, normalized_value FROM candidate_values
            LIMIT 1
            """
        ).fetchone()
        unused_candidate = connection.execute(
            """
            SELECT kind, normalized_value FROM candidate_values
            EXCEPT
            SELECT kind, normalized_value FROM observations
            LIMIT 1
            """
        ).fetchone()
        if any(
            item is not None
            for item in (
                malformed_observation,
                malformed_candidate,
                source_mismatch,
                missing_candidate,
                unused_candidate,
            )
        ):
            raise EnronBankBuildError("Private mining spool relational invariants are invalid.")

        observation_row = connection.execute(
            "SELECT COUNT(*), COALESCE(SUM(occurrences), 0) FROM observations"
        ).fetchone()
        candidate_row = connection.execute("SELECT COUNT(*) FROM candidate_values").fetchone()
        if observation_row is None or candidate_row is None:
            raise EnronBankBuildError("Private mining spool counts are invalid.")
        observations = int(observation_row[1])
        unique_candidates = int(candidate_row[0])
        if (
            observations <= 0
            or observations > policy.max_observations
            or unique_candidates <= 0
            or unique_candidates > policy.max_unique_candidates
        ):
            raise EnronBankBuildError("Private mining spool exceeds its candidate limits.")

        evidence = _read_candidate_evidence(connection)
        if len(evidence) != unique_candidates:
            raise EnronBankBuildError("Private mining candidate evidence is incomplete.")
        ledger_sha256 = _candidate_pool_hash(evidence, train_artifact_sha256, policy.sha256)
        return CandidatePool(
            contacts=tuple(item for item in evidence if item.kind == "contact"),
            person_aliases=tuple(item for item in evidence if item.kind == "person_alias"),
            organization_domains=tuple(item for item in evidence if item.kind == "organization_domain"),
            train_records=train_records,
            observations=observations,
            source_sha256=_SHA256_PREFIX + source_digest.hexdigest(),
            ledger_sha256=ledger_sha256,
        )
    except EnronBankBuildError:
        raise
    except (OverflowError, sqlite3.Error, TypeError, UnicodeError, ValueError):
        raise EnronBankBuildError("Private mining spool could not be replayed safely.") from None
    finally:
        connection.close()


def _preflight_mining_sqlite_cells(connection: sqlite3.Connection, policy: EnronBankPolicy) -> None:
    """Reject unsafe cell types and sizes through scalar SQL before Python receives private cell contents."""

    source_violation = connection.execute(
        """
        SELECT 1
        FROM source_projections
        WHERE typeof(document_id) != 'text'
           OR length(CAST(document_id AS BLOB)) != ?
           OR typeof(payload) != 'blob'
           OR length(payload) > ?
        LIMIT 1
        """,
        (_MAX_MINING_DOCUMENT_ID_BYTES, _MAX_PRIVATE_SQLITE_PROJECTION_BYTES),
    ).fetchone()
    candidate_violation = connection.execute(
        """
        SELECT 1
        FROM candidate_values
        WHERE typeof(kind) != 'text'
           OR length(CAST(kind AS BLOB)) = 0
           OR length(CAST(kind AS BLOB)) > ?
           OR typeof(normalized_value) != 'text'
           OR length(CAST(normalized_value AS BLOB)) = 0
           OR length(CAST(normalized_value AS BLOB)) > ?
        LIMIT 1
        """,
        (_MAX_MINING_KIND_BYTES, policy.max_candidate_value_bytes),
    ).fetchone()
    observation_violation = connection.execute(
        """
        SELECT 1
        FROM observations
        WHERE typeof(kind) != 'text'
           OR length(CAST(kind AS BLOB)) = 0
           OR length(CAST(kind AS BLOB)) > ?
           OR typeof(normalized_value) != 'text'
           OR length(CAST(normalized_value AS BLOB)) = 0
           OR length(CAST(normalized_value AS BLOB)) > ?
           OR typeof(surface) != 'text'
           OR length(CAST(surface AS BLOB)) = 0
           OR length(CAST(surface AS BLOB)) > ?
           OR typeof(related) != 'text'
           OR length(CAST(related AS BLOB)) > ?
           OR typeof(source_type) != 'text'
           OR length(CAST(source_type AS BLOB)) = 0
           OR length(CAST(source_type AS BLOB)) > ?
           OR typeof(document_id) != 'text'
           OR length(CAST(document_id AS BLOB)) != ?
           OR typeof(group_id) != 'text'
           OR length(CAST(group_id AS BLOB)) != ?
           OR (
                observed_at IS NOT NULL
                AND (
                    typeof(observed_at) != 'text'
                    OR length(CAST(observed_at AS BLOB)) > ?
                )
           )
        LIMIT 1
        """,
        (
            _MAX_MINING_KIND_BYTES,
            policy.max_candidate_value_bytes,
            policy.max_candidate_value_bytes,
            policy.max_candidate_value_bytes,
            _MAX_MINING_SOURCE_TYPE_BYTES,
            _MAX_MINING_DOCUMENT_ID_BYTES,
            _MAX_MINING_GROUP_ID_BYTES,
            _MAX_MINING_OBSERVED_AT_BYTES,
        ),
    ).fetchone()
    if any(item is not None for item in (source_violation, candidate_violation, observation_violation)):
        raise EnronBankBuildError("Private mining spool cell exceeds its closed type or resource limit.")


def _set_mining_sqlite_length_limit(connection: sqlite3.Connection) -> bool:
    setlimit = getattr(connection, "setlimit", None)
    limit_category = getattr(sqlite3, "SQLITE_LIMIT_LENGTH", None)
    if callable(setlimit) and isinstance(limit_category, int):
        setlimit(
            limit_category,
            _MAX_PRIVATE_SQLITE_PROJECTION_BYTES + _MINING_SQLITE_LENGTH_LIMIT_HEADROOM,
        )
        return True
    return False


def _iter_mining_source_projections(connection: sqlite3.Connection) -> Iterator[tuple[Any, Any]]:
    rows = connection.execute("SELECT document_id, payload FROM source_projections ORDER BY document_id")
    yield from rows


def _preflight_mining_sqlite_schema_cells(connection: sqlite3.Connection) -> None:
    """Bound schema text through scalar SQL before Python receives private schema cells."""

    violation = connection.execute(
        """
        SELECT 1
        FROM sqlite_schema
        WHERE typeof(type) != 'text'
           OR length(CAST(type AS BLOB)) > ?
           OR typeof(name) != 'text'
           OR length(CAST(name AS BLOB)) > ?
           OR typeof(tbl_name) != 'text'
           OR length(CAST(tbl_name AS BLOB)) > ?
           OR typeof(sql) != 'text'
           OR length(CAST(sql AS BLOB)) > ?
        LIMIT 1
        """,
        (_MAX_MINING_KIND_BYTES,) * 3 + (_MAX_MINING_SQLITE_SCHEMA_CELL_BYTES,),
    ).fetchone()
    if violation is not None:
        raise EnronBankBuildError("Private mining spool schema cell exceeds its closed type or resource limit.")


def _iter_mining_sqlite_schema_rows(connection: sqlite3.Connection) -> list[tuple[Any, ...]]:
    return connection.execute("SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name").fetchmany(
        len(_MINING_SQLITE_SCHEMA) + 1
    )


def _validate_mining_sqlite_schema(connection: sqlite3.Connection) -> None:
    rows = _iter_mining_sqlite_schema_rows(connection)
    if len(rows) != len(_MINING_SQLITE_SCHEMA):
        raise EnronBankBuildError("Private mining spool schema inventory is invalid.")
    expected_sql = {name: " ".join(statement.split()) for name, statement in _MINING_SQLITE_SCHEMA.items()}
    for object_type, name, table_name, statement in rows:
        if (
            object_type != "table"
            or name not in expected_sql
            or table_name != name
            or not isinstance(statement, str)
            or " ".join(statement.split()) != expected_sql[name]
        ):
            raise EnronBankBuildError("Private mining spool schema is invalid.")
        expected_columns = _MINING_SQLITE_COLUMNS[name]
        columns = connection.execute(f"PRAGMA table_xinfo({name})").fetchmany(len(expected_columns) + 1)
        if tuple(columns) != expected_columns:
            raise EnronBankBuildError("Private mining spool table layout is invalid.")
        indexes = connection.execute(f"PRAGMA index_list({name})").fetchmany(2)
        if len(indexes) != 1 or indexes[0][2:] != (1, "pk", 0):
            raise EnronBankBuildError("Private mining spool primary-key layout is invalid.")


def _verify_candidate_ledger(
    candidates: Sequence[Mapping[str, Any]],
    bank: Mapping[str, Any],
) -> dict[str, Any]:
    expected_fields = {
        "schema_version",
        "candidate_id",
        "candidate_type",
        "normalized_value",
        "surfaces",
        "related_values",
        "decision",
        "primary_reason_code",
        "secondary_reason_codes",
        "evidence",
        "bank_ref",
    }
    allowed_types = {
        "contact",
        "contact_fallback",
        "organization_domain",
        "person_alias",
        "phone_fallback",
    }
    seen_ids: set[str] = set()
    seen_pattern_refs: set[tuple[str, str, str]] = set()
    entities = bank.get("entities")
    if not isinstance(entities, Mapping):
        raise EnronBankBuildError("Private candidate ledger bank binding is invalid.")
    for row in candidates:
        if set(row) != expected_fields or row.get("schema_version") != CANDIDATE_SCHEMA_VERSION:
            raise EnronBankBuildError("Private candidate ledger schema is invalid.")
        candidate_id = row.get("candidate_id")
        candidate_type = row.get("candidate_type")
        decision = row.get("decision")
        reason = row.get("primary_reason_code")
        if (
            not isinstance(candidate_id, str)
            or not candidate_id
            or candidate_id in seen_ids
            or candidate_type not in allowed_types
            or decision not in {"active", "draft", "rejected"}
            or not isinstance(reason, str)
            or not reason
            or not isinstance(row.get("surfaces"), list)
            or not isinstance(row.get("related_values"), list)
            or not isinstance(row.get("secondary_reason_codes"), list)
            or not isinstance(row.get("evidence"), Mapping)
        ):
            raise EnronBankBuildError("Private candidate ledger values are invalid.")
        surfaces = cast(list[Any], row["surfaces"])
        related_values = cast(list[Any], row["related_values"])
        secondary_reasons = cast(list[Any], row["secondary_reason_codes"])
        if (
            any(
                not isinstance(surface, Mapping)
                or set(surface) != {"value", "observations"}
                or not isinstance(surface.get("value"), str)
                or type(surface.get("observations")) is not int
                or int(surface["observations"]) <= 0
                for surface in surfaces
            )
            or any(not isinstance(value, str) for value in related_values)
            or any(not isinstance(value, str) for value in secondary_reasons)
        ):
            raise EnronBankBuildError("Private candidate ledger evidence surfaces are invalid.")
        seen_ids.add(candidate_id)
        bank_ref = row.get("bank_ref")
        if decision == "rejected":
            if bank_ref is not None:
                raise EnronBankBuildError("Rejected private candidate unexpectedly references the bank.")
            continue
        if not isinstance(bank_ref, Mapping) or set(bank_ref) != {"entity_id", "name_id", "pattern_ids"}:
            raise EnronBankBuildError("Retained private candidate is missing its bank reference.")
        entity_id = bank_ref.get("entity_id")
        name_id = bank_ref.get("name_id")
        pattern_ids = bank_ref.get("pattern_ids")
        if (
            not isinstance(entity_id, str)
            or not isinstance(name_id, str)
            or not isinstance(pattern_ids, list)
            or not pattern_ids
            or len(pattern_ids) != len(set(pattern_ids))
            or any(not isinstance(item, str) for item in pattern_ids)
        ):
            raise EnronBankBuildError("Private candidate bank reference is invalid.")
        entity = entities.get(entity_id)
        names = entity.get("names") if isinstance(entity, Mapping) else None
        name = names.get(name_id) if isinstance(names, Mapping) else None
        patterns = name.get("patterns") if isinstance(name, Mapping) else None
        if not isinstance(patterns, Mapping):
            raise EnronBankBuildError("Private candidate bank reference does not resolve.")
        for pattern_id in pattern_ids:
            pattern = patterns.get(pattern_id)
            if not isinstance(pattern, Mapping) or pattern.get("status") != decision:
                raise EnronBankBuildError("Private candidate lifecycle differs from its bank pattern.")
            pattern_ref = (entity_id, name_id, pattern_id)
            if pattern_ref in seen_pattern_refs:
                raise EnronBankBuildError("Private bank pattern is referenced by multiple candidates.")
            seen_pattern_refs.add(pattern_ref)
            metadata = pattern.get("metadata")
            if (
                not isinstance(metadata, Mapping)
                or metadata.get("review_status") != decision
                or metadata.get("curation_reason_code") != reason
            ):
                raise EnronBankBuildError("Private candidate rationale differs from its bank pattern.")
            normalized_value = row.get("normalized_value")
            pattern_value = pattern.get("value")
            if candidate_type == "contact":
                corresponds = (
                    isinstance(normalized_value, str) and _normalize_email(str(pattern_value)) == normalized_value
                )
            elif candidate_type == "person_alias":
                corresponds = (
                    isinstance(normalized_value, str)
                    and isinstance(pattern_value, str)
                    and _person_literal_catalog_key(pattern_value) == normalized_value
                )
            elif candidate_type == "organization_domain":
                corresponds = (
                    isinstance(normalized_value, str)
                    and isinstance(pattern_value, str)
                    and pattern_value == "@" + normalized_value
                )
            else:
                corresponds = normalized_value is None and pattern.get("kind") == "regex"
            if not corresponds:
                raise EnronBankBuildError("Private candidate normalized value differs from its bank pattern.")
            evidence = cast(Mapping[str, Any], row["evidence"])
            if candidate_type in {"contact", "person_alias", "organization_domain"} and metadata.get(
                "evidence_sha256"
            ) != evidence.get("evidence_sha256"):
                raise EnronBankBuildError("Private candidate evidence commitment differs from its bank pattern.")
            if candidate_type == "person_alias" and decision == "active":
                contact_ref = metadata.get("contact_ref")
                contact_entity = entities.get("contact")
                contact_names = contact_entity.get("names") if isinstance(contact_entity, Mapping) else None
                contact_name = contact_names.get(contact_ref) if isinstance(contact_names, Mapping) else None
                if (
                    not isinstance(contact_ref, str)
                    or not isinstance(contact_name, Mapping)
                    or contact_name.get("status") not in {"active", "draft"}
                ):
                    raise EnronBankBuildError("Active person candidate contact reference does not resolve.")
    try:
        return candidate_funnel(candidates)
    except (KeyError, TypeError, ValueError):
        raise EnronBankBuildError("Private candidate funnel could not be recomputed safely.") from None


def _assert_private_run(path: Path) -> Path:
    try:
        root = path.expanduser()
        if any(part == os.pardir for part in root.parts):
            raise EnronBankBuildError("Private bank-build path must not contain parent traversal.")
        if not root.is_absolute():
            root = Path.cwd() / root
    except (OSError, RuntimeError, TypeError, ValueError):
        raise EnronBankBuildError("Private bank-build path is invalid.") from None
    try:
        root_fd = _open_private_directory(root)
        try:
            info = os.fstat(root_fd)
        finally:
            os.close(root_fd)
    except (OSError, ValueError):
        raise EnronBankBuildError("Private bank-build run does not exist safely.") from None
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
        raise EnronBankBuildError("Private bank-build root is not a private regular directory.")
    marker = root / "COMMITTED"
    try:
        with open_private_binary_input(marker) as file:
            marker_info = os.fstat(file.fileno())
            payload = file.read(128)
    except (EnronPrivateIOError, OSError):
        raise EnronBankBuildError("Private bank-build commit marker is invalid.") from None
    if (
        not stat.S_ISREG(marker_info.st_mode)
        or stat.S_ISLNK(marker_info.st_mode)
        or marker_info.st_nlink != 1
        or stat.S_IMODE(marker_info.st_mode) & 0o077
        or payload != b"nerb.enron.private-run.v2\n"
    ):
        raise EnronBankBuildError("Private bank-build commit marker is invalid.")
    return root


def _open_private_directory(path: Path) -> int:
    if path.anchor == "" or len(path.parts) < 2:
        raise EnronBankBuildError("Private bank-build path must identify a directory.")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    current_fd: int | None = None
    try:
        current_fd = os.open(path.anchor, flags)
        for component in path.parts[1:]:
            before = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
                raise EnronBankBuildError("Private bank-build path components must be non-symlink directories.")
            next_fd = os.open(component, flags, dir_fd=current_fd)
            after = os.fstat(next_fd)
            if not stat.S_ISDIR(after.st_mode) or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                os.close(next_fd)
                raise EnronBankBuildError("Private bank-build directory changed while it was opened.")
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except EnronBankBuildError:
        if current_fd is not None:
            os.close(current_fd)
        raise
    except (OSError, TypeError, ValueError):
        if current_fd is not None:
            try:
                os.close(current_fd)
            except OSError:
                pass
        raise EnronBankBuildError("Private bank-build directory could not be opened safely.") from None


def _snapshot_private_tree(root: Path) -> dict[str, _PrivateEntryIdentity]:
    entries: dict[str, _PrivateEntryIdentity] = {}
    root_fd = _open_private_directory(root)
    try:
        root_identity = _private_entry_identity(os.fstat(root_fd), kind="directory")
        _require_private_entry(root_identity)
        entries["."] = root_identity
        _snapshot_private_directory(root_fd, relative="", depth=0, entries=entries)
        if _private_entry_identity(os.fstat(root_fd), kind="directory") != root_identity:
            raise EnronBankBuildError("Private bank-build root changed while it was inspected.")
    except EnronBankBuildError:
        raise
    except (OSError, TypeError, ValueError):
        raise EnronBankBuildError("Private bank-build tree could not be inspected safely.") from None
    finally:
        os.close(root_fd)
    return entries


def _snapshot_private_directory(
    directory_fd: int,
    *,
    relative: str,
    depth: int,
    entries: dict[str, _PrivateEntryIdentity],
) -> None:
    try:
        names: list[str] = []
        with os.scandir(directory_fd) as iterator:
            for entry in iterator:
                if len(entries) + len(names) >= _MAX_PRIVATE_TREE_ENTRIES:
                    raise EnronBankBuildError("Private bank-build tree exceeds its entry limit.")
                names.append(entry.name)
        names.sort()
    except EnronBankBuildError:
        raise
    except OSError:
        raise EnronBankBuildError("Private bank-build directory could not be listed safely.") from None
    for name in names:
        if len(entries) >= _MAX_PRIVATE_TREE_ENTRIES:
            raise EnronBankBuildError("Private bank-build tree exceeds its entry limit.")
        if not isinstance(name, str) or name in {os.curdir, os.pardir} or "/" in name:
            raise EnronBankBuildError("Private bank-build entry name is invalid.")
        entry_name = f"{relative}/{name}" if relative else name
        try:
            before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError:
            raise EnronBankBuildError("Private bank-build entry could not be inspected safely.") from None
        if stat.S_ISLNK(before.st_mode):
            raise EnronBankBuildError("Private bank-build tree must not contain symlinks.")
        if stat.S_ISDIR(before.st_mode):
            if depth >= _MAX_PRIVATE_TREE_DEPTH:
                raise EnronBankBuildError("Private bank-build tree exceeds its depth limit.")
            flags = (
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
            )
            try:
                child_fd = os.open(name, flags, dir_fd=directory_fd)
            except OSError:
                raise EnronBankBuildError("Private bank-build directory could not be opened safely.") from None
            try:
                after = os.fstat(child_fd)
                if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                    raise EnronBankBuildError("Private bank-build directory changed while it was opened.")
                identity = _private_entry_identity(after, kind="directory")
                _require_private_entry(identity)
                entries[entry_name] = identity
                _snapshot_private_directory(
                    child_fd,
                    relative=entry_name,
                    depth=depth + 1,
                    entries=entries,
                )
                if _private_entry_identity(os.fstat(child_fd), kind="directory") != identity:
                    raise EnronBankBuildError("Private bank-build directory changed while it was inspected.")
            finally:
                os.close(child_fd)
            continue
        if not stat.S_ISREG(before.st_mode):
            raise EnronBankBuildError("Private bank-build tree contains a non-regular entry.")
        identity = _private_entry_identity(before, kind="file")
        _require_private_entry(identity)
        entries[entry_name] = identity


def _private_entry_identity(info: os.stat_result, *, kind: str) -> _PrivateEntryIdentity:
    return _PrivateEntryIdentity(
        kind=kind,
        device=info.st_dev,
        inode=info.st_ino,
        mode=stat.S_IMODE(info.st_mode),
        link_count=info.st_nlink,
        size=info.st_size,
        modified_ns=info.st_mtime_ns,
        changed_ns=info.st_ctime_ns,
    )


def _require_private_entry(identity: _PrivateEntryIdentity) -> None:
    if identity.mode & 0o077:
        raise EnronBankBuildError("Private bank-build tree contains a non-private entry.")
    if identity.kind == "file" and identity.link_count != 1:
        raise EnronBankBuildError("Private bank-build files must not have multiple hard links.")


def _expected_artifact_names(raw_artifacts: Mapping[str, Any]) -> dict[str, str]:
    artifact_ids = set(raw_artifacts)
    required_ids = set(_REQUIRED_ARTIFACT_NAMES)
    with_cmu_ids = required_ids | set(_OPTIONAL_CMU_ARTIFACT_NAMES)
    if artifact_ids == required_ids:
        return dict(_REQUIRED_ARTIFACT_NAMES)
    if artifact_ids == with_cmu_ids:
        return {**_REQUIRED_ARTIFACT_NAMES, **_OPTIONAL_CMU_ARTIFACT_NAMES}
    raise EnronBankBuildError("Private bank-build artifact inventory is invalid.")


def _verify_private_tree_inventory(
    tree: Mapping[str, _PrivateEntryIdentity],
    artifact_names: Mapping[str, str],
) -> None:
    expected_files = {"COMMITTED", "manifest.json", *artifact_names.values()}
    expected_directories: set[str] = set()
    for name in expected_files:
        parts = Path(name).parts[:-1]
        for length in range(1, len(parts) + 1):
            expected_directories.add(Path(*parts[:length]).as_posix())
    observed_files = {name for name, identity in tree.items() if identity.kind == "file"}
    observed_directories = {name for name, identity in tree.items() if name != "." and identity.kind == "directory"}
    if observed_files != expected_files or observed_directories != expected_directories:
        raise EnronBankBuildError("Private bank-build file inventory is invalid.")


def _fingerprint_private_artifact(
    path: Path,
    *,
    max_bytes: int,
    jsonl_record_limit: int | None = None,
) -> _PrivateFileFingerprint:
    digest = hashlib.sha256()
    observed_bytes = 0
    records: int | None = 0 if jsonl_record_limit is not None else None
    try:
        with open_private_binary_input(path) as file:
            before = _private_entry_identity(os.fstat(file.fileno()), kind="file")
            _require_private_entry(before)
            if before.size > max_bytes:
                raise EnronBankBuildError("Private artifact exceeds its resource limit.")
            if jsonl_record_limit is None:
                while chunk := file.read(min(1024 * 1024, max_bytes - observed_bytes + 1)):
                    observed_bytes += len(chunk)
                    if observed_bytes > max_bytes:
                        raise EnronBankBuildError("Private artifact exceeds its resource limit.")
                    digest.update(chunk)
            else:
                while raw := file.readline(_MAX_PRIVATE_JSONL_LINE_BYTES + 1):
                    if len(raw) > _MAX_PRIVATE_JSONL_LINE_BYTES:
                        raise EnronBankBuildError("Private JSONL artifact line exceeds its byte limit.")
                    observed_bytes += len(raw)
                    if observed_bytes > max_bytes:
                        raise EnronBankBuildError("Private artifact exceeds its resource limit.")
                    digest.update(raw)
                    assert records is not None
                    records += 1
                    if records > jsonl_record_limit:
                        raise EnronBankBuildError("Private JSONL artifact exceeds its record limit.")
            after = _private_entry_identity(os.fstat(file.fileno()), kind="file")
    except EnronBankBuildError:
        raise
    except (EnronPrivateIOError, OSError, OverflowError):
        raise EnronBankBuildError("Private artifact could not be fingerprinted safely.") from None
    if before != after or observed_bytes != after.size:
        raise EnronBankBuildError("Private artifact changed while it was fingerprinted.")
    return _PrivateFileFingerprint(
        identity=after,
        sha256=_SHA256_PREFIX + digest.hexdigest(),
        records=records,
    )


def _verify_artifact_descriptor(
    root: Path,
    artifact_id: str,
    descriptor: Mapping[str, Any],
    *,
    expected_name: str,
    tree: Mapping[str, _PrivateEntryIdentity],
) -> _PrivateFileFingerprint:
    if set(descriptor) != {"id", "name", "sha256", "bytes", "records"} or descriptor.get("id") != artifact_id:
        raise EnronBankBuildError("Private artifact descriptor schema is invalid.")
    name = descriptor.get("name")
    if name != expected_name:
        raise EnronBankBuildError("Private artifact name is invalid.")
    assert isinstance(name, str)
    relative = Path(name)
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {os.curdir, os.pardir} for part in relative.parts)
        or relative.as_posix() != name
    ):
        raise EnronBankBuildError("Private artifact name is unsafe.")
    sha256 = descriptor.get("sha256")
    byte_count = descriptor.get("bytes")
    record_count = descriptor.get("records")
    if (
        not isinstance(sha256, str)
        or _SHA256_RE.fullmatch(sha256) is None
        or type(byte_count) is not int
        or byte_count < 0
        or type(record_count) is not int
        or record_count < 0
    ):
        raise EnronBankBuildError("Private artifact descriptor values are invalid.")
    path = root / relative
    expected_identity = tree.get(name)
    if expected_identity is None or expected_identity.kind != "file":
        raise EnronBankBuildError("Private artifact is missing.") from None
    byte_limit = _private_artifact_byte_limit(name)
    if (
        byte_count > byte_limit
        or expected_identity.size > byte_limit
        or byte_count != expected_identity.size
        or (name.endswith(".jsonl") and record_count > _MAX_PRIVATE_JSONL_RECORDS)
    ):
        raise EnronBankBuildError("Private artifact descriptor exceeds its resource limit.")
    fingerprint = _fingerprint_private_artifact(
        path,
        max_bytes=byte_limit,
        jsonl_record_limit=_MAX_PRIVATE_JSONL_RECORDS if name.endswith(".jsonl") else None,
    )
    if (
        fingerprint.identity != expected_identity
        or byte_count != fingerprint.identity.size
        or sha256 != fingerprint.sha256
    ):
        raise EnronBankBuildError("Private artifact descriptor does not match its file.")
    if name.endswith(".jsonl") and fingerprint.records != record_count:
        raise EnronBankBuildError("Private JSONL artifact count is invalid.")
    return fingerprint


def _write_run_json(run: PrivateRun, name: str, value: Mapping[str, Any]) -> None:
    with run.open_binary(name) as file:
        file.write(_pretty_json_bytes(value))


def _write_run_jsonl(run: PrivateRun, name: str, values: Sequence[Mapping[str, Any]]) -> None:
    if len(values) > _MAX_PRIVATE_JSONL_RECORDS:
        raise EnronBankBuildError("Private JSONL artifact exceeds the record limit.")
    with run.open_binary(name) as file:
        for value in values:
            line = _canonical_json_bytes(value) + b"\n"
            if len(line) > _MAX_PRIVATE_JSONL_LINE_BYTES:
                raise EnronBankBuildError("Private JSONL artifact line exceeds the byte limit.")
            file.write(line)


def _artifact_descriptor(path: Path, artifact_id: str, *, records: int = 0) -> dict[str, Any]:
    size = path.stat().st_size
    if size > _private_artifact_byte_limit(path.name):
        raise EnronBankBuildError("Private artifact exceeds its byte limit.")
    if path.name.endswith(".jsonl") and records > _MAX_PRIVATE_JSONL_RECORDS:
        raise EnronBankBuildError("Private artifact exceeds its record limit.")
    return {
        "id": artifact_id,
        "name": path.name
        if path.parent.name not in {"banks", "validation", "conformance", "auxiliary"}
        else (f"{path.parent.name}/{path.name}"),
        "sha256": _hash_private_file(path),
        "bytes": size,
        "records": records,
    }


def _private_artifact_byte_limit(name: str) -> int:
    if name.endswith(".jsonl"):
        return _MAX_PRIVATE_JSONL_BYTES
    if name.endswith(".sqlite3"):
        return _MAX_PRIVATE_SQLITE_BYTES
    return _MAX_PRIVATE_JSON_BYTES


def _builder_implementation_sha256() -> str:
    digest = hashlib.sha256(b"nerb/enron/bank-builder-implementation/v2\0")
    sources = (
        ("candidate_builder", Path(_bank_builder_module.__file__)),
        ("workflow", Path(__file__)),
    )
    for label, path in sources:
        try:
            payload = path.read_bytes()
        except OSError:
            raise EnronBankBuildError("Bank-builder implementation could not be fingerprinted safely.") from None
        digest.update(label.encode("ascii") + b"\0")
        digest.update(hashlib.sha256(payload).digest())
    return _SHA256_PREFIX + digest.hexdigest()


def _public_card_scanner_sha256() -> str:
    digest = hashlib.sha256(b"nerb/enron/public-card-scanner/v2\0")
    sources = (
        ("contract_scanner", Path(_enron_contract_module.__file__)),
        ("workflow_wrapper", Path(__file__)),
    )
    for label, path in sources:
        try:
            payload = path.read_bytes()
        except OSError:
            raise EnronBankBuildError("Public-card scanner implementation could not be fingerprinted safely.") from None
        digest.update(label.encode("ascii") + b"\0")
        digest.update(hashlib.sha256(payload).digest())
    return _SHA256_PREFIX + digest.hexdigest()


def _hash_private_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with open_private_binary_input(path) as file:
            while chunk := file.read(1024 * 1024):
                digest.update(chunk)
    except (EnronPrivateIOError, OSError):
        raise EnronBankBuildError("Private artifact could not be hashed safely.") from None
    return _SHA256_PREFIX + digest.hexdigest()


def _copy_verified_private_artifact(
    source: Path,
    destination: Path,
    *,
    expected_fingerprint: _PrivateFileFingerprint,
    max_bytes: int,
) -> None:
    """Copy one exact verified inode into a process-owned private snapshot."""

    digest = hashlib.sha256()
    observed_bytes = 0
    destination_fd: int | None = None
    try:
        with open_private_binary_input(source) as file:
            before = _private_entry_identity(os.fstat(file.fileno()), kind="file")
            _require_private_entry(before)
            if before != expected_fingerprint.identity:
                raise EnronBankBuildError("Private artifact changed during verification.")
            if before.size > max_bytes:
                raise EnronBankBuildError("Private artifact exceeds its resource limit.")
            destination_fd = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            os.fchmod(destination_fd, 0o600)
            with os.fdopen(destination_fd, "wb", buffering=0) as snapshot:
                destination_fd = None
                while chunk := file.read(min(1024 * 1024, max_bytes - observed_bytes + 1)):
                    observed_bytes += len(chunk)
                    if observed_bytes > max_bytes:
                        raise EnronBankBuildError("Private artifact exceeds its resource limit.")
                    digest.update(chunk)
                    snapshot.write(chunk)
                snapshot.flush()
                os.fsync(snapshot.fileno())
            after = _private_entry_identity(os.fstat(file.fileno()), kind="file")
    except EnronBankBuildError:
        raise
    except (EnronPrivateIOError, OSError, OverflowError):
        raise EnronBankBuildError("Private artifact could not be snapshotted safely.") from None
    finally:
        if destination_fd is not None:
            try:
                os.close(destination_fd)
            except OSError:
                pass
    observed = _PrivateFileFingerprint(
        identity=after,
        sha256=_SHA256_PREFIX + digest.hexdigest(),
    )
    if before != after or observed_bytes != after.size or observed != expected_fingerprint:
        raise EnronBankBuildError("Private artifact changed during verification.")


def _read_private_json(
    path: Path,
    *,
    expected_fingerprint: _PrivateFileFingerprint | None = None,
    max_bytes: int = _MAX_PRIVATE_JSON_BYTES,
) -> Any:
    payload = _read_verified_private_bytes(
        path,
        expected_fingerprint=expected_fingerprint,
        max_bytes=max_bytes,
        description="JSON",
    )
    try:
        return json.loads(
            payload,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
            parse_float=_parse_finite_float,
            parse_int=_parse_bounded_private_int,
        )
    except (OverflowError, RecursionError, TypeError, ValueError, UnicodeError):
        raise EnronBankBuildError("Private JSON artifact is invalid.") from None


def _read_verified_private_bytes(
    path: Path,
    *,
    expected_fingerprint: _PrivateFileFingerprint | None,
    max_bytes: int,
    description: str,
) -> bytes:
    digest = hashlib.sha256()
    chunks: list[bytes] = []
    observed_bytes = 0
    try:
        with open_private_binary_input(path) as file:
            before = _private_entry_identity(os.fstat(file.fileno()), kind="file")
            _require_private_entry(before)
            _require_expected_private_identity(before, expected_fingerprint)
            if before.size > max_bytes:
                raise EnronBankBuildError(f"Private {description} artifact exceeds the byte limit.")
            while chunk := file.read(min(1024 * 1024, max_bytes - observed_bytes + 1)):
                observed_bytes += len(chunk)
                if observed_bytes > max_bytes:
                    raise EnronBankBuildError(f"Private {description} artifact exceeds the byte limit.")
                digest.update(chunk)
                chunks.append(chunk)
            after = _private_entry_identity(os.fstat(file.fileno()), kind="file")
    except EnronBankBuildError:
        raise
    except (EnronPrivateIOError, OSError, OverflowError):
        raise EnronBankBuildError(f"Private {description} artifact could not be read safely.") from None
    _require_expected_private_consumption(
        before=before,
        after=after,
        observed_bytes=observed_bytes,
        sha256=_SHA256_PREFIX + digest.hexdigest(),
        records=None,
        expected_fingerprint=expected_fingerprint,
    )
    return b"".join(chunks)


def _read_private_jsonl(
    path: Path,
    *,
    expected_fingerprint: _PrivateFileFingerprint | None = None,
) -> tuple[dict[str, Any], ...]:
    rows: list[dict[str, Any]] = []
    digest = hashlib.sha256()
    observed_bytes = 0
    try:
        with open_private_binary_input(path) as file:
            before = _private_entry_identity(os.fstat(file.fileno()), kind="file")
            _require_private_entry(before)
            _require_expected_private_identity(before, expected_fingerprint)
            if before.size > _MAX_PRIVATE_JSONL_BYTES:
                raise EnronBankBuildError("Private JSONL artifact exceeds the byte limit.")
            while raw := file.readline(_MAX_PRIVATE_JSONL_LINE_BYTES + 1):
                if len(raw) > _MAX_PRIVATE_JSONL_LINE_BYTES:
                    raise EnronBankBuildError("Private JSONL artifact line exceeds the byte limit.")
                observed_bytes += len(raw)
                if observed_bytes > _MAX_PRIVATE_JSONL_BYTES:
                    raise EnronBankBuildError("Private JSONL artifact exceeds the byte limit.")
                digest.update(raw)
                if len(rows) >= _MAX_PRIVATE_JSONL_RECORDS:
                    raise EnronBankBuildError("Private JSONL artifact exceeds the record limit.")
                try:
                    row = json.loads(
                        raw,
                        object_pairs_hook=_reject_duplicate_keys,
                        parse_constant=_reject_constant,
                        parse_float=_parse_finite_float,
                        parse_int=_parse_bounded_private_int,
                    )
                except (OverflowError, RecursionError, TypeError, ValueError, UnicodeError):
                    raise EnronBankBuildError("Private JSONL artifact is invalid.") from None
                if not isinstance(row, dict):
                    raise EnronBankBuildError("Private JSONL artifact is not canonical.")
                try:
                    canonical = _canonical_json_bytes(row) + b"\n"
                except (EnronBankBuildError, OverflowError, RecursionError, TypeError, ValueError, UnicodeError):
                    raise EnronBankBuildError("Private JSONL artifact is invalid.") from None
                if raw != canonical:
                    raise EnronBankBuildError("Private JSONL artifact is not canonical.")
                rows.append(row)
            after = _private_entry_identity(os.fstat(file.fileno()), kind="file")
    except EnronBankBuildError:
        raise
    except (EnronPrivateIOError, OSError, OverflowError):
        raise EnronBankBuildError("Private JSONL artifact could not be read safely.") from None
    _require_expected_private_consumption(
        before=before,
        after=after,
        observed_bytes=observed_bytes,
        sha256=_SHA256_PREFIX + digest.hexdigest(),
        records=len(rows),
        expected_fingerprint=expected_fingerprint,
    )
    return tuple(rows)


def _require_expected_private_identity(
    observed: _PrivateEntryIdentity,
    expected_fingerprint: _PrivateFileFingerprint | None,
) -> None:
    if expected_fingerprint is not None and observed != expected_fingerprint.identity:
        raise EnronBankBuildError("Private artifact changed during verification.")


def _require_expected_private_consumption(
    *,
    before: _PrivateEntryIdentity,
    after: _PrivateEntryIdentity,
    observed_bytes: int,
    sha256: str,
    records: int | None,
    expected_fingerprint: _PrivateFileFingerprint | None,
) -> None:
    if before != after or observed_bytes != after.size:
        raise EnronBankBuildError("Private artifact changed while it was read.")
    if expected_fingerprint is not None and (
        after != expected_fingerprint.identity
        or sha256 != expected_fingerprint.sha256
        or (expected_fingerprint.records is not None and records != expected_fingerprint.records)
    ):
        raise EnronBankBuildError("Private artifact changed during verification.")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError("nonfinite value")


def _parse_finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("nonfinite value")
    return parsed


def _parse_bounded_private_int(value: str) -> int:
    digits = value[1:] if value.startswith("-") else value
    if len(digits) > _MAX_PRIVATE_JSON_INTEGER_DIGITS:
        raise ValueError("integer digit limit")
    try:
        return int(value)
    except (OverflowError, ValueError):
        raise ValueError("invalid integer") from None


def _pretty_json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise EnronBankBuildError("Private JSON value could not be serialized safely.") from None


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None

"""Executable, privacy-safe contracts for the Enron benchmark-v2 evidence boundary.

The schemas close every object and the semantic verifier recomputes aggregate claims without reading private corpus
text. A promoted or verifier-passed bundle must be checked with its exact manifest, the previously published final-test
lineage prefix, and any content-addressed timing samples that are not embedded in the evidence JSON.
"""

from __future__ import annotations

import json
import math
import os
import re
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from hashlib import sha256
from pathlib import Path, PurePosixPath, PureWindowsPath
from stat import S_ISREG
from statistics import median
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError
from jsonschema.validators import extend

from .diagnostics import DIAGNOSTIC_ERROR, Diagnostic, diagnostic, has_errors

ENRON_MANIFEST_SCHEMA_VERSION = "nerb.enron_manifest.v2"
ENRON_EVIDENCE_SCHEMA_VERSION = "nerb.enron_evidence.v2"
ENRON_CHARTER_VERSION = "2"
ENRON_VERIFIER_ID = "nerb-enron-contract"
ENRON_VERIFIER_VERSION = "2.0.0"
MAX_CONTRACT_BYTES = 64 * 1024 * 1024
MAX_SAFE_INTEGER = 2**63 - 1
MAX_FINITE_CONTRACT_NUMBER = 1e300
MIN_SAMPLE_SECONDS = 1e-9
MAX_SAMPLE_SECONDS = 24 * 60 * 60
MIN_PUBLIC_SLICE_DOCUMENTS = 5
SHA256_PATTERN = r"^sha256:[0-9a-f]{64}$"
GIT_COMMIT_PATTERN = r"^[0-9a-f]{40}$"
LABEL_STRENGTHS = ("independent", "structured_weak", "synthetic_conformance", "unlabeled")
ANNOTATION_COMPLETENESS = ("exhaustive_within_scope", "partial", "not_applicable")
CHARACTER_POSITION_SEMANTICS = "document_id_unicode_scalar_index"
MATCHING_SEMANTICS = "one_to_one_exact_span_and_class"
PERFORMANCE_PHASES = (
    "source_build",
    "cold_compile",
    "helper_cache_miss",
    "helper_cache_hit",
    "direct_bank_scan",
    "end_to_end",
)


def _is_json_array(_checker: Any, value: Any) -> bool:
    return isinstance(value, list)


def _is_json_integer(_checker: Any, value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_json_number(_checker: Any, value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    return isinstance(value, float) and math.isfinite(value)


def _is_json_object(_checker: Any, value: Any) -> bool:
    return isinstance(value, dict)


_TYPE_CHECKER = Draft202012Validator.TYPE_CHECKER.redefine_many(
    {
        "array": _is_json_array,
        "integer": _is_json_integer,
        "number": _is_json_number,
        "object": _is_json_object,
    }
)
EnronContractValidator = extend(Draft202012Validator, type_checker=_TYPE_CHECKER)


def _closed_object(required: Sequence[str], properties: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "type": "object",
        "required": list(required),
        "properties": dict(properties),
        "additionalProperties": False,
    }


_HASH = {"type": "string", "pattern": SHA256_PATTERN}
_NONNEGATIVE_INTEGER = {"type": "integer", "minimum": 0, "maximum": MAX_SAFE_INTEGER}
_POSITIVE_INTEGER = {"type": "integer", "minimum": 1, "maximum": MAX_SAFE_INTEGER}
_FINITE_NUMBER = {
    "type": "number",
    "minimum": -MAX_FINITE_CONTRACT_NUMBER,
    "maximum": MAX_FINITE_CONTRACT_NUMBER,
}
_NONNEGATIVE_NUMBER = {"type": "number", "minimum": 0, "maximum": MAX_FINITE_CONTRACT_NUMBER}
_POSITIVE_NUMBER = {"type": "number", "exclusiveMinimum": 0, "maximum": MAX_FINITE_CONTRACT_NUMBER}
_UNIT_METRIC = {"anyOf": [{"type": "number", "minimum": 0, "maximum": 1}, {"type": "null"}]}
_NONNEGATIVE_METRIC = {"anyOf": [_NONNEGATIVE_NUMBER, {"type": "null"}]}
_TIMESTAMP = {"type": "string", "minLength": 1}
_ARTIFACT_KIND = {"type": "string", "enum": ["real_benchmark", "synthetic_fixture"]}
_STRING_ARRAY = {
    "type": "array",
    "uniqueItems": True,
    "items": {"type": "string", "minLength": 1},
}

_ARTIFACT_REF = _closed_object(
    ("id", "sha256", "bytes"),
    {"id": {"type": "string", "minLength": 1}, "sha256": _HASH, "bytes": _NONNEGATIVE_INTEGER},
)
_EVALUATOR = _closed_object(
    ("id", "version", "source_sha256", "label_schema_sha256"),
    {
        "id": {"type": "string", "minLength": 1},
        "version": {"type": "string", "minLength": 1},
        "source_sha256": _HASH,
        "label_schema_sha256": _HASH,
    },
)
_VERIFIER_IDENTITY = _closed_object(
    ("id", "version", "source_sha256"),
    {
        "id": {"const": ENRON_VERIFIER_ID},
        "version": {"const": ENRON_VERIFIER_VERSION},
        "source_sha256": _HASH,
    },
)
_SOURCE = _closed_object(
    ("id", "revision", "owner", "access", "content_sha256", "input_records"),
    {
        "id": {"type": "string", "minLength": 1},
        "revision": {"type": "string", "minLength": 1},
        "owner": {"type": "string", "minLength": 1},
        "access": {"type": "string", "minLength": 1},
        "content_sha256": _HASH,
        "input_records": _POSITIVE_INTEGER,
    },
)
_SOFTWARE = _closed_object(
    ("package_version", "engine_version", "git_commit", "git_dirty"),
    {
        "package_version": {"type": "string", "minLength": 1},
        "engine_version": {"type": "string", "minLength": 1},
        "git_commit": {"type": "string", "pattern": GIT_COMMIT_PATTERN},
        "git_dirty": {"type": "boolean"},
    },
)
_COMMAND = _closed_object(
    ("id", "argv", "cwd", "timeout_seconds", "exit_status", "elapsed_seconds"),
    {
        "id": {"type": "string", "minLength": 1},
        "argv": {"type": "array", "minItems": 1, "items": {"type": "string", "minLength": 1}},
        "cwd": {"type": "string", "minLength": 1},
        "timeout_seconds": {"anyOf": [_POSITIVE_NUMBER, {"type": "null"}]},
        "exit_status": {"type": "integer", "minimum": -255, "maximum": 255},
        "elapsed_seconds": _NONNEGATIVE_NUMBER,
    },
)
_ENVIRONMENT = _closed_object(
    ("os", "architecture", "python", "cpu_count", "cpu_model", "memory_bytes"),
    {
        "os": {"type": "string", "minLength": 1},
        "architecture": {"type": "string", "minLength": 1},
        "python": {"type": "string", "minLength": 1},
        "cpu_count": _POSITIVE_INTEGER,
        "cpu_model": {"type": "string", "minLength": 1},
        "memory_bytes": _POSITIVE_INTEGER,
    },
)
_PRIVACY = _closed_object(
    (
        "status",
        "raw_text_included",
        "direct_identifiers_included",
        "scanner",
        "scanner_source_sha256",
        "report_sha256",
        "violation_count",
    ),
    {
        "status": {"type": "string", "enum": ["passed", "failed", "not_run"]},
        "raw_text_included": {"type": "boolean"},
        "direct_identifiers_included": {"type": "boolean"},
        "scanner": {"type": "string", "minLength": 1},
        "scanner_source_sha256": _HASH,
        "report_sha256": _HASH,
        "violation_count": _NONNEGATIVE_INTEGER,
    },
)
_SPLIT_ROLE = _closed_object(
    ("records", "groups", "artifact"),
    {"records": _POSITIVE_INTEGER, "groups": _POSITIVE_INTEGER, "artifact": _ARTIFACT_REF},
)
_SPLITS = _closed_object(
    (
        "manifest_sha256",
        "policy_sha256",
        "leakage_audit_sha256",
        "leakage_groups_crossing",
        "test_sealed",
        "seed",
        "roles",
    ),
    {
        "manifest_sha256": _HASH,
        "policy_sha256": _HASH,
        "leakage_audit_sha256": _HASH,
        "leakage_groups_crossing": _NONNEGATIVE_INTEGER,
        "test_sealed": {"type": "boolean"},
        "seed": {"type": "string", "minLength": 1},
        "roles": _closed_object(
            ("train", "validation", "test"),
            {"train": _SPLIT_ROLE, "validation": _SPLIT_ROLE, "test": _SPLIT_ROLE},
        ),
    },
)
_BANK = _closed_object(
    (
        "id",
        "canonical_hash",
        "artifact_sha256",
        "active_entities",
        "active_names",
        "active_patterns",
        "canonical_json_bytes",
        "native_source_bytes",
    ),
    {
        "id": {"type": "string", "minLength": 1},
        "canonical_hash": _HASH,
        "artifact_sha256": _HASH,
        "active_entities": _POSITIVE_INTEGER,
        "active_names": _POSITIVE_INTEGER,
        "active_patterns": _POSITIVE_INTEGER,
        "canonical_json_bytes": _POSITIVE_INTEGER,
        "native_source_bytes": _POSITIVE_INTEGER,
    },
)
_ANNOTATION_SCOPE = _closed_object(
    ("entity_classes", "document_regions", "span_policy_sha256", "exclusions"),
    {
        "entity_classes": {**_STRING_ARRAY, "minItems": 1},
        "document_regions": {**_STRING_ARRAY, "minItems": 1},
        "span_policy_sha256": _HASH,
        "exclusions": _STRING_ARRAY,
    },
)
_LABEL_ARTIFACT = _closed_object(
    (
        "id",
        "label_strength",
        "annotation_scope",
        "annotation_completeness",
        "roles",
        "artifact",
        "span_count",
    ),
    {
        "id": {"type": "string", "minLength": 1},
        "label_strength": {"type": "string", "enum": list(LABEL_STRENGTHS)},
        "annotation_scope": _ANNOTATION_SCOPE,
        "annotation_completeness": {"type": "string", "enum": list(ANNOTATION_COMPLETENESS)},
        "roles": {
            "type": "array",
            "minItems": 1,
            "uniqueItems": True,
            "items": {"type": "string", "enum": ["train", "validation", "test"]},
        },
        "artifact": _ARTIFACT_REF,
        "span_count": _NONNEGATIVE_INTEGER,
    },
)
_PREPARATION = _closed_object(
    ("cleaning_policy_sha256", "grouping_policy_sha256", "output_records", "prepared_artifact"),
    {
        "cleaning_policy_sha256": _HASH,
        "grouping_policy_sha256": _HASH,
        "output_records": _POSITIVE_INTEGER,
        "prepared_artifact": _ARTIFACT_REF,
    },
)

ENRON_MANIFEST_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://nerb.dev/schemas/enron-manifest.v2.schema.json",
    "title": "NERB Enron benchmark v2 manifest",
    **_closed_object(
        (
            "schema_version",
            "charter_version",
            "artifact_kind",
            "benchmark_version",
            "created_at",
            "evaluator",
            "verifier",
            "source",
            "preparation",
            "splits",
            "bank",
            "thresholds_sha256",
            "performance_manifest_sha256",
            "labels",
            "software",
            "commands",
            "environment",
            "privacy",
        ),
        {
            "schema_version": {"const": ENRON_MANIFEST_SCHEMA_VERSION},
            "charter_version": {"const": ENRON_CHARTER_VERSION},
            "artifact_kind": _ARTIFACT_KIND,
            "benchmark_version": {"type": "string", "minLength": 1},
            "created_at": _TIMESTAMP,
            "evaluator": _EVALUATOR,
            "verifier": _VERIFIER_IDENTITY,
            "source": _SOURCE,
            "preparation": _PREPARATION,
            "splits": _SPLITS,
            "bank": _BANK,
            "thresholds_sha256": _HASH,
            "performance_manifest_sha256": _HASH,
            "labels": {"type": "array", "minItems": 1, "items": _LABEL_ARTIFACT},
            "software": _SOFTWARE,
            "commands": {"type": "array", "minItems": 1, "items": _COMMAND},
            "environment": _ENVIRONMENT,
            "privacy": _PRIVACY,
        },
    ),
}

_QUALITY_METRICS = _closed_object(
    (
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
    ),
    {
        "precision": _UNIT_METRIC,
        "open_world_recall": _UNIT_METRIC,
        "f1": _UNIT_METRIC,
        "catalog_coverage": _UNIT_METRIC,
        "cataloged_recall": _UNIT_METRIC,
        "document_leak_rate": _UNIT_METRIC,
        "cataloged_document_leak_rate": _UNIT_METRIC,
        "sensitive_character_recall": _UNIT_METRIC,
        "sensitive_character_leak_rate": _UNIT_METRIC,
        "negative_document_false_alarm_rate": _UNIT_METRIC,
        "over_redaction_rate": _UNIT_METRIC,
    },
)
_QUALITY_SLICE = _closed_object(
    (
        "id",
        "label_artifact_id",
        "label_strength",
        "annotation_scope",
        "annotation_completeness",
        "entity_class",
        "cohort",
        "split_role",
        "text_view",
        "promotion_gate",
        "documents",
        "documents_with_sensitive_gold",
        "documents_with_any_miss",
        "documents_with_cataloged_gold",
        "documents_with_any_cataloged_miss",
        "documents_with_any_leaked_character",
        "gold_spans",
        "predicted_spans",
        "true_positive",
        "false_positive",
        "false_negative",
        "cataloged_gold_spans",
        "cataloged_true_positive",
        "cataloged_false_negative",
        "cataloged_wrong_canonical",
        "sensitive_gold_characters",
        "covered_sensitive_characters",
        "leaked_sensitive_characters",
        "predicted_characters",
        "over_redacted_characters",
        "evaluated_characters",
        "negative_documents",
        "negative_documents_with_predictions",
        "metrics",
    ),
    {
        "id": {"type": "string", "minLength": 1},
        "label_artifact_id": {"type": "string", "minLength": 1},
        "label_strength": {"type": "string", "enum": list(LABEL_STRENGTHS)},
        "annotation_scope": _ANNOTATION_SCOPE,
        "annotation_completeness": {"type": "string", "enum": list(ANNOTATION_COMPLETENESS)},
        "entity_class": {"type": "string", "minLength": 1},
        "cohort": {"type": "string", "minLength": 1},
        "split_role": {"type": "string", "enum": ["train", "validation", "test"]},
        "text_view": {"type": "string", "minLength": 1},
        "promotion_gate": {"type": "boolean"},
        **{
            field: _NONNEGATIVE_INTEGER
            for field in (
                "documents",
                "documents_with_sensitive_gold",
                "documents_with_any_miss",
                "documents_with_cataloged_gold",
                "documents_with_any_cataloged_miss",
                "documents_with_any_leaked_character",
                "gold_spans",
                "predicted_spans",
                "true_positive",
                "false_positive",
                "false_negative",
                "cataloged_gold_spans",
                "cataloged_true_positive",
                "cataloged_false_negative",
                "cataloged_wrong_canonical",
                "sensitive_gold_characters",
                "covered_sensitive_characters",
                "leaked_sensitive_characters",
                "predicted_characters",
                "over_redacted_characters",
                "evaluated_characters",
                "negative_documents",
                "negative_documents_with_predictions",
            )
        },
        "metrics": _QUALITY_METRICS,
    },
)
_OPTIONAL_ARTIFACT_REF = {"anyOf": [_ARTIFACT_REF, {"type": "null"}]}
_CONFORMANCE = _closed_object(
    (
        "evaluated",
        "label_artifact_id",
        "active_patterns",
        "patterns_with_positive_cases",
        "approved_positive_cases",
        "correctly_mapped",
        "missed",
        "wrong_canonical",
        "negative_cases",
        "unexpected_negative_matches",
        "positive_cases_artifact",
        "negative_cases_artifact",
        "recall",
        "passed",
    ),
    {
        "evaluated": {"type": "boolean"},
        "label_artifact_id": {"anyOf": [{"type": "string", "minLength": 1}, {"type": "null"}]},
        "active_patterns": _NONNEGATIVE_INTEGER,
        "patterns_with_positive_cases": _NONNEGATIVE_INTEGER,
        "approved_positive_cases": _NONNEGATIVE_INTEGER,
        "correctly_mapped": _NONNEGATIVE_INTEGER,
        "missed": _NONNEGATIVE_INTEGER,
        "wrong_canonical": _NONNEGATIVE_INTEGER,
        "negative_cases": _NONNEGATIVE_INTEGER,
        "unexpected_negative_matches": _NONNEGATIVE_INTEGER,
        "positive_cases_artifact": _OPTIONAL_ARTIFACT_REF,
        "negative_cases_artifact": _OPTIONAL_ARTIFACT_REF,
        "recall": _UNIT_METRIC,
        "passed": {"type": "boolean"},
    },
)
_PERFORMANCE_STATS = _closed_object(
    (
        "sample_count",
        "median_seconds",
        "p95_seconds",
        "p99_seconds",
        "mad_seconds",
        "documents_per_second",
        "mib_per_second",
    ),
    {
        "sample_count": {"type": "integer", "minimum": 5, "maximum": MAX_SAFE_INTEGER},
        "median_seconds": _POSITIVE_NUMBER,
        "p95_seconds": _NONNEGATIVE_METRIC,
        "p99_seconds": _NONNEGATIVE_METRIC,
        "mad_seconds": _NONNEGATIVE_NUMBER,
        "documents_per_second": _POSITIVE_NUMBER,
        "mib_per_second": _POSITIVE_NUMBER,
    },
)
_PERFORMANCE_BANK = _closed_object(
    (
        "id",
        "kind",
        "bank_hash",
        "active_entities",
        "active_names",
        "active_patterns",
        "canonical_json_bytes",
        "native_source_bytes",
    ),
    {
        "id": {"type": "string", "minLength": 1},
        "kind": {"type": "string", "enum": ["evaluated_bank", "synthetic_scale"]},
        "bank_hash": _HASH,
        "active_entities": _POSITIVE_INTEGER,
        "active_names": _POSITIVE_INTEGER,
        "active_patterns": _POSITIVE_INTEGER,
        "canonical_json_bytes": _POSITIVE_INTEGER,
        "native_source_bytes": _POSITIVE_INTEGER,
    },
)
_PERFORMANCE_WORKLOAD = _closed_object(
    (
        "id",
        "phase",
        "promotion_gate",
        "workload_sha256",
        "bank_hash",
        "warmups",
        "documents",
        "bytes",
        "matches",
        "concurrency",
        "hit_density",
        "process_model",
        "median_method",
        "percentile_method",
        "samples_seconds",
        "samples_ref",
        "stats",
        "peak_rss_bytes",
    ),
    {
        "id": {"type": "string", "minLength": 1},
        "phase": {"type": "string", "enum": list(PERFORMANCE_PHASES)},
        "promotion_gate": {"type": "boolean"},
        "workload_sha256": _HASH,
        "bank_hash": _HASH,
        "warmups": _NONNEGATIVE_INTEGER,
        "documents": _POSITIVE_INTEGER,
        "bytes": _POSITIVE_INTEGER,
        "matches": _NONNEGATIVE_INTEGER,
        "concurrency": _POSITIVE_INTEGER,
        "hit_density": {"type": "string", "enum": ["negative", "sparse", "normal", "dense"]},
        "process_model": {"type": "string", "enum": ["fresh_process_per_sample", "reused_process"]},
        "median_method": {"const": "standard_even_average"},
        "percentile_method": {"const": "nearest_rank"},
        "samples_seconds": {
            "type": "array",
            "items": {
                "type": "number",
                "minimum": MIN_SAMPLE_SECONDS,
                "maximum": MAX_SAMPLE_SECONDS,
            },
        },
        "samples_ref": _OPTIONAL_ARTIFACT_REF,
        "stats": _PERFORMANCE_STATS,
        "peak_rss_bytes": {"anyOf": [_NONNEGATIVE_INTEGER, {"type": "null"}]},
    },
)
_PERFORMANCE_WORKLOAD["allOf"] = [
    {
        "oneOf": [
            {"properties": {"samples_seconds": {"minItems": 5}, "samples_ref": {"type": "null"}}},
            {"properties": {"samples_seconds": {"maxItems": 0}, "samples_ref": _ARTIFACT_REF}},
        ]
    }
]
_FROZEN_TARGET = _closed_object(
    (
        "frozen_at",
        "bank_hash",
        "evaluator_source_sha256",
        "split_manifest_sha256",
        "thresholds_sha256",
        "performance_manifest_sha256",
        "git_commit",
    ),
    {
        "frozen_at": _TIMESTAMP,
        "bank_hash": _HASH,
        "evaluator_source_sha256": _HASH,
        "split_manifest_sha256": _HASH,
        "thresholds_sha256": _HASH,
        "performance_manifest_sha256": _HASH,
        "git_commit": {"type": "string", "pattern": GIT_COMMIT_PATTERN},
    },
)
_TEST_LINEAGE_ENTRY = _closed_object(
    (
        "sequence",
        "benchmark_version",
        "accessed_at",
        "outcome",
        "aggregate_artifact",
        "frozen_target",
        "predecessor_benchmark_version",
        "changes_informed_by_predecessor",
        "previous_entry_sha256",
        "entry_sha256",
    ),
    {
        "sequence": _POSITIVE_INTEGER,
        "benchmark_version": {"type": "string", "minLength": 1},
        "accessed_at": _TIMESTAMP,
        "outcome": {"type": "string", "enum": ["passed", "failed", "aborted"]},
        "aggregate_artifact": _ARTIFACT_REF,
        "frozen_target": _FROZEN_TARGET,
        "predecessor_benchmark_version": {"anyOf": [{"type": "string", "minLength": 1}, {"type": "null"}]},
        "changes_informed_by_predecessor": _STRING_ARRAY,
        "previous_entry_sha256": {"anyOf": [_HASH, {"type": "null"}]},
        "entry_sha256": _HASH,
    },
)
_TEST_ACCESS = _closed_object(
    (
        "benchmark_version",
        "optimization_roles",
        "current_version_access_count",
        "current_version_accessed_at",
        "frozen_target",
        "lineage",
        "lineage_head_sha256",
    ),
    {
        "benchmark_version": {"type": "string", "minLength": 1},
        "optimization_roles": {
            "type": "array",
            "uniqueItems": True,
            "items": {"type": "string", "enum": ["train", "validation", "test"]},
        },
        "current_version_access_count": {"type": "integer", "minimum": 0, "maximum": 1},
        "current_version_accessed_at": {"anyOf": [_TIMESTAMP, {"type": "null"}]},
        "frozen_target": _FROZEN_TARGET,
        "lineage": {"type": "array", "items": _TEST_LINEAGE_ENTRY},
        "lineage_head_sha256": {"anyOf": [_HASH, {"type": "null"}]},
    },
)
_GATE_VALUE = {
    "anyOf": [
        _FINITE_NUMBER,
        {"type": "boolean"},
        {"type": "string", "minLength": 1},
        {"type": "null"},
    ]
}
_GATE_CHECK = _closed_object(
    ("id", "category", "target", "operator", "threshold", "actual", "passed"),
    {
        "id": {"type": "string", "minLength": 1},
        "category": {
            "type": "string",
            "enum": ["quality", "catalog_conformance", "performance", "privacy", "provenance"],
        },
        "target": {"type": "string", "pattern": r"^/"},
        "operator": {"type": "string", "enum": ["gte", "lte", "eq"]},
        "threshold": _GATE_VALUE,
        "actual": _GATE_VALUE,
        "passed": {"type": "boolean"},
    },
)
_CLAIM_SCOPE = _closed_object(
    ("entity_class", "cohort", "split_role", "text_view"),
    {
        "entity_class": {"anyOf": [{"type": "string", "minLength": 1}, {"type": "null"}]},
        "cohort": {"anyOf": [{"type": "string", "minLength": 1}, {"type": "null"}]},
        "split_role": {"anyOf": [{"type": "string", "enum": ["train", "validation", "test"]}, {"type": "null"}]},
        "text_view": {"anyOf": [{"type": "string", "minLength": 1}, {"type": "null"}]},
    },
)
_CLAIM = _closed_object(
    (
        "id",
        "kind",
        "metric",
        "value",
        "label_strength",
        "annotation_completeness",
        "quality_slice_id",
        "performance_workload_id",
        "scope",
        "source_revision",
        "bank_hash",
        "evaluator_source_sha256",
        "environment_sha256",
    ),
    {
        "id": {"type": "string", "minLength": 1},
        "kind": {"type": "string", "enum": ["catalog_conformance", "open_world_quality", "performance"]},
        "metric": {
            "type": "string",
            "enum": [
                "catalog_conformance_recall",
                "precision",
                "open_world_recall",
                "f1",
                "document_leak_rate",
                "sensitive_character_recall",
                "sensitive_character_leak_rate",
                "negative_document_false_alarm_rate",
                "over_redaction_rate",
                "direct_bank_scan_median_seconds",
                "direct_bank_scan_p95_seconds",
                "direct_bank_scan_p99_seconds",
                "direct_bank_scan_mib_per_second",
            ],
        },
        "value": _NONNEGATIVE_NUMBER,
        "label_strength": {"type": "string", "enum": list(LABEL_STRENGTHS)},
        "annotation_completeness": {"type": "string", "enum": list(ANNOTATION_COMPLETENESS)},
        "quality_slice_id": {"anyOf": [{"type": "string", "minLength": 1}, {"type": "null"}]},
        "performance_workload_id": {"anyOf": [{"type": "string", "minLength": 1}, {"type": "null"}]},
        "scope": _CLAIM_SCOPE,
        "source_revision": {"type": "string", "minLength": 1},
        "bank_hash": _HASH,
        "evaluator_source_sha256": _HASH,
        "environment_sha256": _HASH,
    },
)
_VERIFIER_RESULT = _closed_object(
    ("id", "version", "source_sha256", "passed"),
    {
        "id": {"const": ENRON_VERIFIER_ID},
        "version": {"const": ENRON_VERIFIER_VERSION},
        "source_sha256": _HASH,
        "passed": {"type": "boolean"},
    },
)

ENRON_EVIDENCE_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://nerb.dev/schemas/enron-evidence.v2.schema.json",
    "title": "NERB Enron benchmark v2 evidence",
    **_closed_object(
        (
            "schema_version",
            "charter_version",
            "artifact_kind",
            "created_at",
            "manifest_sha256",
            "evaluator",
            "source",
            "preparation",
            "splits",
            "bank",
            "software",
            "commands",
            "environment",
            "privacy",
            "quality",
            "catalog_conformance",
            "test_access",
            "performance",
            "performance_manifest_sha256",
            "thresholds_sha256",
            "promotion",
            "verifier",
        ),
        {
            "schema_version": {"const": ENRON_EVIDENCE_SCHEMA_VERSION},
            "charter_version": {"const": ENRON_CHARTER_VERSION},
            "artifact_kind": _ARTIFACT_KIND,
            "created_at": _TIMESTAMP,
            "manifest_sha256": _HASH,
            "evaluator": _EVALUATOR,
            "source": _SOURCE,
            "preparation": _PREPARATION,
            "splits": _SPLITS,
            "bank": _BANK,
            "software": _SOFTWARE,
            "commands": {"type": "array", "minItems": 1, "items": _COMMAND},
            "environment": _ENVIRONMENT,
            "privacy": _PRIVACY,
            "quality": _closed_object(
                ("evaluated", "matching_semantics", "character_position_semantics", "slices"),
                {
                    "evaluated": {"type": "boolean"},
                    "matching_semantics": {"const": MATCHING_SEMANTICS},
                    "character_position_semantics": {"const": CHARACTER_POSITION_SEMANTICS},
                    "slices": {"type": "array", "items": _QUALITY_SLICE},
                },
            ),
            "catalog_conformance": _CONFORMANCE,
            "test_access": _TEST_ACCESS,
            "performance": _closed_object(
                ("evaluated", "banks", "workloads"),
                {
                    "evaluated": {"type": "boolean"},
                    "banks": {"type": "array", "items": _PERFORMANCE_BANK},
                    "workloads": {"type": "array", "items": _PERFORMANCE_WORKLOAD},
                },
            ),
            "performance_manifest_sha256": _HASH,
            "thresholds_sha256": _HASH,
            "promotion": _closed_object(
                ("passed", "checks", "claims"),
                {
                    "passed": {"type": "boolean"},
                    "checks": {
                        "type": "array",
                        "minItems": 1,
                        "items": _GATE_CHECK,
                    },
                    "claims": {"type": "array", "items": _CLAIM},
                },
            ),
            "verifier": _VERIFIER_RESULT,
        },
    ),
}

MANIFEST_VALIDATOR = EnronContractValidator(ENRON_MANIFEST_SCHEMA)
EVIDENCE_VALIDATOR = EnronContractValidator(ENRON_EVIDENCE_SCHEMA)
Draft202012Validator.check_schema(ENRON_MANIFEST_SCHEMA)
Draft202012Validator.check_schema(ENRON_EVIDENCE_SCHEMA)


def _canonical_payload(value: Any) -> bytes:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return payload.encode("utf-8")


def _canonical_hash(value: Any) -> str:
    return "sha256:" + sha256(_canonical_payload(value)).hexdigest()


def hash_enron_manifest(manifest: Mapping[str, Any]) -> str:
    """Return the canonical SHA-256 identifier for a manifest object."""
    return _canonical_hash(manifest)


def hash_enron_environment(environment: Mapping[str, Any]) -> str:
    return _canonical_hash(environment)


def hash_enron_samples(samples: Sequence[float]) -> str:
    normalized = _normalize_samples(samples)
    if normalized is None:
        raise ValueError("Enron performance samples must be finite, strictly positive, and bounded.")
    return _canonical_hash(normalized)


def hash_enron_workload(workload: Mapping[str, Any]) -> str:
    fields = (
        "id",
        "phase",
        "promotion_gate",
        "bank_hash",
        "warmups",
        "documents",
        "bytes",
        "matches",
        "concurrency",
        "hit_density",
        "process_model",
        "median_method",
        "percentile_method",
    )
    return _canonical_hash({field: workload[field] for field in fields})


def hash_enron_performance_manifest(performance: Mapping[str, Any]) -> str:
    banks = sorted(performance["banks"], key=lambda value: str(value["id"]))
    workloads = [
        {"id": item["id"], "workload_sha256": hash_enron_workload(item)}
        for item in sorted(performance["workloads"], key=lambda value: str(value["id"]))
    ]
    return _canonical_hash({"banks": banks, "workloads": workloads})


def hash_enron_thresholds(checks: Sequence[Mapping[str, Any]]) -> str:
    configuration = [
        {
            "id": item["id"],
            "category": item["category"],
            "target": item["target"],
            "operator": item["operator"],
            "threshold": item["threshold"],
        }
        for item in sorted(checks, key=lambda value: str(value["id"]))
    ]
    return _canonical_hash(configuration)


def hash_enron_test_lineage_entry(entry: Mapping[str, Any]) -> str:
    return _canonical_hash({key: value for key, value in entry.items() if key != "entry_sha256"})


def validate_enron_manifest(manifest: Any) -> dict[str, Any]:
    """Validate manifest structure, split integrity, provenance, and public serialization safety."""
    diagnostics = _schema_diagnostics(MANIFEST_VALIDATOR, manifest)
    if not diagnostics and isinstance(manifest, Mapping):
        diagnostics.extend(_manifest_diagnostics(manifest))
        diagnostics.extend(_privacy_diagnostics(manifest["privacy"], "/privacy"))
        diagnostics.extend(_command_diagnostics(manifest["commands"], "/commands"))
        diagnostics.extend(_public_serialization_diagnostics(manifest))
    return _result(diagnostics)


def validate_enron_evidence(
    evidence: Any,
    *,
    manifest: Mapping[str, Any] | None = None,
    trusted_lineage_prefix: Sequence[Mapping[str, Any]] | None = None,
    referenced_samples: Mapping[str, Sequence[float]] | None = None,
) -> dict[str, Any]:
    """Validate evidence and recompute its privacy, claim, lineage, gate, and performance semantics."""
    diagnostics = _schema_diagnostics(EVIDENCE_VALIDATOR, evidence)
    if diagnostics or not isinstance(evidence, Mapping):
        return _result(diagnostics)

    quality = evidence["quality"]
    conformance = evidence["catalog_conformance"]
    performance = evidence["performance"]
    promotion = evidence["promotion"]
    diagnostics.extend(_privacy_diagnostics(evidence["privacy"], "/privacy"))
    diagnostics.extend(_command_diagnostics(evidence["commands"], "/commands"))
    diagnostics.extend(_public_serialization_diagnostics(evidence))
    diagnostics.extend(_evidence_provenance_diagnostics(evidence))
    diagnostics.extend(_quality_diagnostics(quality, manifest=manifest))
    diagnostics.extend(_conformance_diagnostics(conformance, evidence["bank"], manifest=manifest))
    diagnostics.extend(
        _test_access_diagnostics(evidence, manifest=manifest, trusted_lineage_prefix=trusted_lineage_prefix)
    )
    diagnostics.extend(_performance_diagnostics(performance, evidence["bank"], referenced_samples))
    diagnostics.extend(_gate_diagnostics(evidence))
    diagnostics.extend(_promotion_diagnostics(evidence))
    if manifest is not None:
        diagnostics.extend(_binding_diagnostics(evidence, manifest))
    elif promotion["passed"] or evidence["verifier"]["passed"]:
        diagnostics.append(
            _error(
                "contract.manifest_required",
                "/manifest_sha256",
                "Promoted or verifier-passed evidence requires the exact bound manifest.",
            )
        )
    if evidence["verifier"]["passed"] and diagnostics:
        diagnostics.append(
            _error("contract.forged_verifier", "/verifier/passed", "Verifier status cannot pass with contract errors.")
        )
    if promotion["passed"] and diagnostics:
        diagnostics.append(
            _error("contract.forged_promotion", "/promotion/passed", "Promotion cannot pass with contract errors.")
        )
    return _result(diagnostics)


def load_enron_manifest(path: str | Path) -> dict[str, Any]:
    """Securely load and validate one benchmark-v2 manifest JSON object."""
    value = _load_contract_json(path)
    result = validate_enron_manifest(value)
    if not result["valid"]:
        raise ValueError(f"Invalid Enron v2 manifest: {result['diagnostics'][0]['message']}")
    return value


def load_enron_evidence(
    path: str | Path,
    *,
    manifest: Mapping[str, Any] | None = None,
    trusted_lineage_prefix: Sequence[Mapping[str, Any]] | None = None,
    referenced_samples: Mapping[str, Sequence[float]] | None = None,
) -> dict[str, Any]:
    """Securely load and semantically validate one benchmark-v2 evidence JSON object."""
    value = _load_contract_json(path)
    result = validate_enron_evidence(
        value,
        manifest=manifest,
        trusted_lineage_prefix=trusted_lineage_prefix,
        referenced_samples=referenced_samples,
    )
    if not result["valid"]:
        raise ValueError(f"Invalid Enron v2 evidence: {result['diagnostics'][0]['message']}")
    return value


def _manifest_diagnostics(manifest: Mapping[str, Any]) -> list[Diagnostic]:
    diagnostics = _timestamp_diagnostics(manifest["created_at"], "/created_at")
    diagnostics.extend(_split_diagnostics(manifest["source"], manifest["preparation"], manifest["splits"], "/splits"))
    diagnostics.extend(_duplicate_id_diagnostics(manifest["commands"], "/commands", "command"))
    diagnostics.extend(_duplicate_id_diagnostics(manifest["labels"], "/labels", "label artifact"))
    if manifest["artifact_kind"] == "real_benchmark" and manifest["software"]["git_commit"] == "0" * 40:
        diagnostics.append(
            _error(
                "contract.placeholder_release_identity",
                "/software/git_commit",
                "Real benchmark manifests cannot use the synthetic all-zero commit identity.",
            )
        )
    for index, label in enumerate(manifest["labels"]):
        path = f"/labels/{index}"
        strength = label["label_strength"]
        completeness = label["annotation_completeness"]
        if strength == "unlabeled":
            if completeness != "not_applicable" or label["span_count"] != 0:
                diagnostics.append(
                    _error(
                        "contract.unlabeled_annotation_state",
                        path,
                        "Unlabeled artifacts require not_applicable completeness and zero spans.",
                    )
                )
        elif completeness == "not_applicable" or label["span_count"] == 0:
            diagnostics.append(
                _error(
                    "contract.empty_labeled_artifact",
                    path,
                    "Labeled artifacts require applicable completeness and nonzero span support.",
                )
            )
        if strength == "synthetic_conformance" and completeness != "exhaustive_within_scope":
            diagnostics.append(
                _error(
                    "contract.incomplete_conformance_labels",
                    f"{path}/annotation_completeness",
                    "Synthetic conformance labels must be exhaustive within their declared scope.",
                )
            )
    return diagnostics


def _evidence_provenance_diagnostics(evidence: Mapping[str, Any]) -> list[Diagnostic]:
    diagnostics = _timestamp_diagnostics(evidence["created_at"], "/created_at")
    diagnostics.extend(_split_diagnostics(evidence["source"], evidence["preparation"], evidence["splits"], "/splits"))
    diagnostics.extend(_duplicate_id_diagnostics(evidence["commands"], "/commands", "command"))
    if evidence["performance_manifest_sha256"] != hash_enron_performance_manifest(evidence["performance"]):
        diagnostics.append(
            _error(
                "contract.performance_manifest_hash",
                "/performance_manifest_sha256",
                "Performance-manifest hash does not match declared banks and workload descriptors.",
            )
        )
    if evidence["artifact_kind"] == "synthetic_fixture" and (
        evidence["promotion"]["passed"] or evidence["verifier"]["passed"]
    ):
        diagnostics.append(
            _error(
                "contract.synthetic_fixture_claim",
                "/artifact_kind",
                "Synthetic fixtures are non-claimable and cannot be verifier-passed or promoted.",
            )
        )
    if evidence["artifact_kind"] == "real_benchmark" and evidence["software"]["git_commit"] == "0" * 40:
        diagnostics.append(
            _error(
                "contract.placeholder_release_identity",
                "/software/git_commit",
                "Real benchmark evidence cannot use the synthetic all-zero commit identity.",
            )
        )
    return diagnostics


def _split_diagnostics(
    source: Mapping[str, Any], preparation: Mapping[str, Any], splits: Mapping[str, Any], path: str
) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    if splits["leakage_groups_crossing"] != 0:
        diagnostics.append(
            _error("contract.split_leakage", f"{path}/leakage_groups_crossing", "Leakage groups cross splits.")
        )
    if splits["test_sealed"] is not True:
        diagnostics.append(_error("contract.test_not_sealed", f"{path}/test_sealed", "Final test must be sealed."))
    role_records = 0
    for role, value in splits["roles"].items():
        role_records += value["records"]
        if value["groups"] > value["records"]:
            diagnostics.append(
                _error(
                    "contract.split_group_bounds",
                    f"{path}/roles/{role}/groups",
                    "Split groups cannot exceed split records.",
                )
            )
    if role_records != preparation["output_records"]:
        diagnostics.append(
            _error(
                "contract.split_record_total",
                f"{path}/roles",
                "Train, validation, and test records must equal prepared output records.",
            )
        )
    if preparation["output_records"] > source["input_records"]:
        diagnostics.append(
            _error(
                "contract.preparation_record_bounds",
                "/preparation/output_records",
                "Prepared output records cannot exceed source input records.",
            )
        )
    return diagnostics


def _quality_diagnostics(quality: Mapping[str, Any], *, manifest: Mapping[str, Any] | None) -> list[Diagnostic]:
    slices = quality["slices"]
    if not quality["evaluated"]:
        return (
            []
            if not slices
            else [
                _error(
                    "contract.not_evaluated_has_slices",
                    "/quality/slices",
                    "Unevaluated quality must not contain slices.",
                )
            ]
        )
    diagnostics: list[Diagnostic] = []
    if not slices:
        return [_error("contract.empty_quality", "/quality/slices", "Evaluated quality requires non-empty slices.")]
    diagnostics.extend(_duplicate_id_diagnostics(slices, "/quality/slices", "quality slice"))
    labels: dict[str, Mapping[str, Any]] = {}
    if manifest is not None and validate_enron_manifest(manifest)["valid"]:
        labels = {str(item["id"]): item for item in manifest["labels"]}
    for index, item in enumerate(slices):
        path = f"/quality/slices/{index}"
        if item["label_strength"] in {"unlabeled", "synthetic_conformance"}:
            diagnostics.append(
                _error(
                    "contract.unsupported_quality_strength",
                    f"{path}/label_strength",
                    "Unlabeled and synthetic-conformance evidence cannot produce natural-text quality slices.",
                )
            )
        if item["entity_class"] not in item["annotation_scope"]["entity_classes"]:
            diagnostics.append(
                _error(
                    "contract.annotation_scope_mismatch",
                    f"{path}/entity_class",
                    "Slice entity class is outside its declared annotation scope.",
                )
            )
        label = labels.get(str(item["label_artifact_id"]))
        if labels and label is None:
            diagnostics.append(
                _error(
                    "contract.unknown_label_artifact",
                    f"{path}/label_artifact_id",
                    "Quality slice does not reference a bound manifest label artifact.",
                )
            )
        elif label is not None:
            expected_fields = {
                "label_strength": label["label_strength"],
                "annotation_scope": label["annotation_scope"],
                "annotation_completeness": label["annotation_completeness"],
            }
            for field, expected in expected_fields.items():
                if item[field] != expected:
                    diagnostics.append(
                        _error(
                            "contract.label_binding_mismatch",
                            f"{path}/{field}",
                            "Quality slice differs from its bound manifest label artifact.",
                        )
                    )
            if item["split_role"] not in label["roles"]:
                diagnostics.append(
                    _error(
                        "contract.label_role_mismatch",
                        f"{path}/split_role",
                        "Quality slice role is not covered by its bound label artifact.",
                    )
                )
        diagnostics.extend(_slice_diagnostics(item, path))
    return diagnostics


def _slice_diagnostics(item: Mapping[str, Any], path: str) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    open_world_eligible = (
        item["label_strength"] == "independent" and item["annotation_completeness"] == "exhaustive_within_scope"
    )
    if item["annotation_completeness"] == "not_applicable":
        diagnostics.append(
            _error(
                "contract.invalid_quality_completeness",
                f"{path}/annotation_completeness",
                "Natural-text quality requires applicable annotation completeness.",
            )
        )
    if item["promotion_gate"] and (not open_world_eligible or item["split_role"] != "test"):
        diagnostics.append(
            _error(
                "contract.invalid_quality_gate",
                f"{path}/promotion_gate",
                "Promotion-gated quality requires independent exhaustive final-test evidence.",
            )
        )
    if item["documents"] < MIN_PUBLIC_SLICE_DOCUMENTS:
        diagnostics.append(
            _error(
                "contract.privacy_small_slice",
                f"{path}/documents",
                f"Public aggregate slices require at least {MIN_PUBLIC_SLICE_DOCUMENTS} documents.",
            )
        )
    if not open_world_eligible:
        unsupported_counts = (
            "false_positive",
            "sensitive_gold_characters",
            "covered_sensitive_characters",
            "leaked_sensitive_characters",
            "predicted_characters",
            "over_redacted_characters",
            "evaluated_characters",
            "negative_documents",
            "negative_documents_with_predictions",
            "documents_with_any_leaked_character",
        )
        if any(item[field] != 0 for field in unsupported_counts):
            diagnostics.append(
                _error(
                    "contract.ineligible_open_world_counts",
                    path,
                    "Partial or non-independent labels may report labeled-span diagnostics, not "
                    "FP/character/utility counts.",
                )
            )
    expected_counts = {
        "gold_spans": item["true_positive"] + item["false_negative"],
        "predicted_spans": item["true_positive"] + item["false_positive"],
        "cataloged_gold_spans": (
            item["cataloged_true_positive"] + item["cataloged_false_negative"] + item["cataloged_wrong_canonical"]
        ),
        "sensitive_gold_characters": item["covered_sensitive_characters"] + item["leaked_sensitive_characters"],
        "predicted_characters": item["covered_sensitive_characters"] + item["over_redacted_characters"],
    }
    for field, expected in expected_counts.items():
        if item[field] != expected:
            diagnostics.append(
                _error("contract.count_arithmetic", f"{path}/{field}", f"Expected {expected} from component counts.")
            )
    bounds = (
        ("documents_with_sensitive_gold", "documents"),
        ("documents_with_sensitive_gold", "gold_spans"),
        ("documents_with_any_miss", "documents_with_sensitive_gold"),
        ("documents_with_cataloged_gold", "documents_with_sensitive_gold"),
        ("documents_with_cataloged_gold", "cataloged_gold_spans"),
        ("documents_with_any_cataloged_miss", "documents_with_cataloged_gold"),
        ("documents_with_any_leaked_character", "documents_with_sensitive_gold"),
        ("cataloged_gold_spans", "gold_spans"),
        ("cataloged_true_positive", "true_positive"),
        ("cataloged_false_negative", "false_negative"),
        ("cataloged_wrong_canonical", "true_positive"),
        ("covered_sensitive_characters", "sensitive_gold_characters"),
        ("sensitive_gold_characters", "evaluated_characters"),
        ("predicted_characters", "evaluated_characters"),
        ("negative_documents_with_predictions", "negative_documents"),
        ("negative_documents", "documents"),
    )
    for numerator, denominator in bounds:
        if item[numerator] > item[denominator]:
            diagnostics.append(
                _error("contract.count_bounds", f"{path}/{numerator}", f"Must not exceed {denominator}.")
            )
    if open_world_eligible and item["documents_with_sensitive_gold"] + item["negative_documents"] != item["documents"]:
        diagnostics.append(
            _error(
                "contract.document_partition",
                f"{path}/documents",
                "Exhaustive slices must partition documents into sensitive-positive and negative documents.",
            )
        )
    diagnostics.extend(
        _zero_nonzero_diagnostics(
            item["false_negative"], item["documents_with_any_miss"], f"{path}/documents_with_any_miss", "span misses"
        )
    )
    diagnostics.extend(
        _zero_nonzero_diagnostics(
            item["gold_spans"],
            item["documents_with_sensitive_gold"],
            f"{path}/documents_with_sensitive_gold",
            "gold sensitive spans",
        )
    )
    diagnostics.extend(
        _zero_nonzero_diagnostics(
            item["cataloged_gold_spans"],
            item["documents_with_cataloged_gold"],
            f"{path}/documents_with_cataloged_gold",
            "cataloged gold spans",
        )
    )
    catalog_misses = item["cataloged_false_negative"] + item["cataloged_wrong_canonical"]
    diagnostics.extend(
        _zero_nonzero_diagnostics(
            catalog_misses,
            item["documents_with_any_cataloged_miss"],
            f"{path}/documents_with_any_cataloged_miss",
            "cataloged misses or wrong mappings",
        )
    )
    diagnostics.extend(
        _zero_nonzero_diagnostics(
            item["leaked_sensitive_characters"],
            item["documents_with_any_leaked_character"],
            f"{path}/documents_with_any_leaked_character",
            "leaked sensitive characters",
        )
    )
    for document_field, event_count in (
        ("documents_with_any_miss", item["false_negative"]),
        ("documents_with_any_cataloged_miss", catalog_misses),
        ("documents_with_any_leaked_character", item["leaked_sensitive_characters"]),
        ("negative_documents_with_predictions", item["false_positive"]),
    ):
        if item[document_field] > event_count:
            diagnostics.append(
                _error(
                    "contract.document_event_bounds",
                    f"{path}/{document_field}",
                    "Documents containing an event cannot exceed the corresponding event count.",
                )
            )
    if item["sensitive_gold_characters"] + item["over_redacted_characters"] > item["evaluated_characters"]:
        diagnostics.append(
            _error(
                "contract.character_universe_bounds",
                f"{path}/evaluated_characters",
                "Gold-sensitive and over-redacted document-disjoint positions must fit the evaluated universe.",
            )
        )
    metrics = item["metrics"]
    open_world_metrics = {
        "precision": _ratio(item["true_positive"], item["predicted_spans"]),
        "open_world_recall": _ratio(item["true_positive"], item["gold_spans"]),
        "f1": _f1(item["true_positive"], item["false_positive"], item["false_negative"]),
        "document_leak_rate": _ratio(item["documents_with_any_miss"], item["documents_with_sensitive_gold"]),
        "cataloged_document_leak_rate": _ratio(
            item["documents_with_any_cataloged_miss"], item["documents_with_cataloged_gold"]
        ),
        "sensitive_character_recall": _ratio(item["covered_sensitive_characters"], item["sensitive_gold_characters"]),
        "sensitive_character_leak_rate": _ratio(item["leaked_sensitive_characters"], item["sensitive_gold_characters"]),
        "negative_document_false_alarm_rate": _ratio(
            item["negative_documents_with_predictions"], item["negative_documents"]
        ),
        "over_redaction_rate": _ratio(item["over_redacted_characters"], item["evaluated_characters"]),
    }
    expected_metrics = {
        **{field: value if open_world_eligible else None for field, value in open_world_metrics.items()},
        "catalog_coverage": _ratio(item["cataloged_gold_spans"], item["gold_spans"]),
        "cataloged_recall": _ratio(item["cataloged_true_positive"], item["cataloged_gold_spans"]),
    }
    for field, expected in expected_metrics.items():
        if not _same_metric(metrics[field], expected):
            diagnostics.append(
                _error(
                    "contract.metric_arithmetic",
                    f"{path}/metrics/{field}",
                    f"Expected {expected!r} from integer counts.",
                )
            )
    return diagnostics


def _conformance_diagnostics(
    value: Mapping[str, Any], bank: Mapping[str, Any], *, manifest: Mapping[str, Any] | None
) -> list[Diagnostic]:
    if not value["evaluated"]:
        nonzero = any(
            value[field]
            for field in (
                "active_patterns",
                "patterns_with_positive_cases",
                "approved_positive_cases",
                "correctly_mapped",
                "missed",
                "wrong_canonical",
                "negative_cases",
                "unexpected_negative_matches",
            )
        )
        if (
            nonzero
            or value["label_artifact_id"] is not None
            or value["positive_cases_artifact"] is not None
            or value["negative_cases_artifact"] is not None
            or value["recall"] is not None
            or value["passed"]
        ):
            return [
                _error(
                    "contract.invalid_unevaluated_conformance",
                    "/catalog_conformance",
                    "Unevaluated conformance must be empty and fail closed.",
                )
            ]
        return []
    diagnostics: list[Diagnostic] = []
    support = value["approved_positive_cases"]
    if value["label_artifact_id"] is None:
        diagnostics.append(
            _error(
                "contract.missing_conformance_label",
                "/catalog_conformance/label_artifact_id",
                "Evaluated conformance requires a bound synthetic-conformance label artifact.",
            )
        )
    elif manifest is not None and validate_enron_manifest(manifest)["valid"]:
        labels = {str(item["id"]): item for item in manifest["labels"]}
        label = labels.get(str(value["label_artifact_id"]))
        if (
            label is None
            or label["label_strength"] != "synthetic_conformance"
            or label["annotation_completeness"] != "exhaustive_within_scope"
            or label["artifact"] != value["positive_cases_artifact"]
            or label["span_count"] != support
        ):
            diagnostics.append(
                _error(
                    "contract.conformance_label_binding",
                    "/catalog_conformance/label_artifact_id",
                    "Conformance cases differ from their exhaustive bound manifest label artifact.",
                )
            )
    if value["active_patterns"] != bank["active_patterns"]:
        diagnostics.append(
            _error(
                "contract.conformance_bank_mismatch",
                "/catalog_conformance/active_patterns",
                "Conformance active-pattern count must equal the evaluated bank.",
            )
        )
    if value["patterns_with_positive_cases"] != value["active_patterns"]:
        diagnostics.append(
            _error(
                "contract.incomplete_pattern_support",
                "/catalog_conformance/patterns_with_positive_cases",
                "Every active pattern requires approved positive support.",
            )
        )
    if support < value["patterns_with_positive_cases"]:
        diagnostics.append(
            _error(
                "contract.pattern_case_support",
                "/catalog_conformance/approved_positive_cases",
                "Approved positive cases must provide at least one case per supported active pattern.",
            )
        )
    if value["active_patterns"] <= 0 or support <= 0 or value["negative_cases"] <= 0:
        diagnostics.append(
            _error(
                "contract.empty_conformance",
                "/catalog_conformance/approved_positive_cases",
                "Conformance requires active patterns plus positive and negative/adversarial cases.",
            )
        )
    if value["positive_cases_artifact"] is None or value["negative_cases_artifact"] is None:
        diagnostics.append(
            _error(
                "contract.missing_conformance_artifact",
                "/catalog_conformance",
                "Evaluated conformance requires content-addressed positive and negative case artifacts.",
            )
        )
    if support != value["correctly_mapped"] + value["missed"] + value["wrong_canonical"]:
        diagnostics.append(
            _error(
                "contract.conformance_arithmetic",
                "/catalog_conformance/approved_positive_cases",
                "Positive cases must equal correct + missed + wrong canonical.",
            )
        )
    expected = _ratio(value["correctly_mapped"], support)
    if not _same_metric(value["recall"], expected):
        diagnostics.append(
            _error("contract.metric_arithmetic", "/catalog_conformance/recall", f"Expected {expected!r}.")
        )
    if value["unexpected_negative_matches"] > value["negative_cases"]:
        diagnostics.append(
            _error(
                "contract.conformance_negative_bounds",
                "/catalog_conformance/unexpected_negative_matches",
                "Unexpected negative matches cannot exceed negative cases.",
            )
        )
    should_pass = (
        support > 0
        and value["negative_cases"] > 0
        and value["active_patterns"] == bank["active_patterns"]
        and value["patterns_with_positive_cases"] == value["active_patterns"]
        and support >= value["patterns_with_positive_cases"]
        and value["positive_cases_artifact"] is not None
        and value["negative_cases_artifact"] is not None
        and value["missed"] == 0
        and value["wrong_canonical"] == 0
        and value["unexpected_negative_matches"] == 0
        and expected == 1.0
    )
    if value["passed"] != should_pass:
        diagnostics.append(
            _error(
                "contract.conformance_gate",
                "/catalog_conformance/passed",
                "Conformance pass requires nonzero support, 100% recall, zero wrong mappings, "
                "and zero negative matches.",
            )
        )
    return diagnostics


def _test_access_diagnostics(
    evidence: Mapping[str, Any],
    *,
    manifest: Mapping[str, Any] | None,
    trusted_lineage_prefix: Sequence[Mapping[str, Any]] | None,
) -> list[Diagnostic]:
    access = evidence["test_access"]
    diagnostics: list[Diagnostic] = []
    if "test" in access["optimization_roles"]:
        diagnostics.append(
            _error(
                "contract.test_optimized",
                "/test_access/optimization_roles",
                "Final test cannot be an optimization role.",
            )
        )
    count = access["current_version_access_count"]
    if (count == 0) != (access["current_version_accessed_at"] is None):
        diagnostics.append(
            _error(
                "contract.test_access_timestamp",
                "/test_access/current_version_accessed_at",
                "Test access timestamp must agree with access count.",
            )
        )
    frozen = access["frozen_target"]
    expected = {
        "bank_hash": evidence["bank"]["canonical_hash"],
        "evaluator_source_sha256": evidence["evaluator"]["source_sha256"],
        "split_manifest_sha256": evidence["splits"]["manifest_sha256"],
        "thresholds_sha256": evidence["thresholds_sha256"],
        "performance_manifest_sha256": evidence["performance_manifest_sha256"],
        "git_commit": evidence["software"]["git_commit"],
    }
    for field, value in expected.items():
        if frozen[field] != value:
            diagnostics.append(
                _error(
                    "contract.freeze_mismatch",
                    f"/test_access/frozen_target/{field}",
                    "Frozen test target does not match evidence provenance.",
                )
            )
    diagnostics.extend(_timestamp_diagnostics(frozen["frozen_at"], "/test_access/frozen_target/frozen_at"))
    if manifest is not None and validate_enron_manifest(manifest)["valid"]:
        if access["benchmark_version"] != manifest["benchmark_version"]:
            diagnostics.append(
                _error(
                    "contract.benchmark_version_mismatch",
                    "/test_access/benchmark_version",
                    "Evidence benchmark version differs from its bound manifest.",
                )
            )
        manifest_created = _parse_timestamp(manifest["created_at"])
        frozen_at = _parse_timestamp(frozen["frozen_at"])
        if manifest_created is not None and frozen_at is not None and frozen_at < manifest_created:
            diagnostics.append(
                _error(
                    "contract.freeze_timestamp_order",
                    "/test_access/frozen_target/frozen_at",
                    "Frozen target cannot predate its manifest.",
                )
            )

    lineage = access["lineage"]
    current_entries: list[Mapping[str, Any]] = []
    seen_versions: set[str] = set()
    previous_entry: Mapping[str, Any] | None = None
    previous_accessed_at: datetime | None = None
    for index, entry in enumerate(lineage):
        path = f"/test_access/lineage/{index}"
        if entry["sequence"] != index + 1:
            diagnostics.append(
                _error("contract.lineage_sequence", f"{path}/sequence", "Lineage sequence must be contiguous.")
            )
        version = str(entry["benchmark_version"])
        if version in seen_versions:
            diagnostics.append(
                _error(
                    "contract.test_reused",
                    f"{path}/benchmark_version",
                    "Each benchmark version may access its sealed final test at most once.",
                )
            )
        seen_versions.add(version)
        if version == access["benchmark_version"]:
            current_entries.append(entry)
        expected_entry_hash = hash_enron_test_lineage_entry(entry)
        if entry["entry_sha256"] != expected_entry_hash:
            diagnostics.append(
                _error(
                    "contract.lineage_hash_mismatch",
                    f"{path}/entry_sha256",
                    "Lineage entry hash does not match its canonical content.",
                )
            )
        accessed_at = _parse_timestamp(entry["accessed_at"])
        diagnostics.extend(_timestamp_diagnostics(entry["accessed_at"], f"{path}/accessed_at"))
        entry_frozen_at = _parse_timestamp(entry["frozen_target"]["frozen_at"])
        diagnostics.extend(
            _timestamp_diagnostics(entry["frozen_target"]["frozen_at"], f"{path}/frozen_target/frozen_at")
        )
        if entry_frozen_at is not None and accessed_at is not None and accessed_at < entry_frozen_at:
            diagnostics.append(
                _error(
                    "contract.test_before_freeze",
                    f"{path}/accessed_at",
                    "Final-test access cannot predate the frozen target.",
                )
            )
        if previous_accessed_at is not None and accessed_at is not None and accessed_at <= previous_accessed_at:
            diagnostics.append(
                _error(
                    "contract.lineage_timestamp_order",
                    f"{path}/accessed_at",
                    "Lineage access timestamps must be strictly increasing.",
                )
            )
        previous_accessed_at = accessed_at or previous_accessed_at
        if previous_entry is None:
            if (
                entry["previous_entry_sha256"] is not None
                or entry["predecessor_benchmark_version"] is not None
                or entry["changes_informed_by_predecessor"]
            ):
                diagnostics.append(
                    _error(
                        "contract.lineage_origin",
                        path,
                        "The first lineage entry cannot claim a predecessor.",
                    )
                )
        else:
            if entry["previous_entry_sha256"] != previous_entry["entry_sha256"]:
                diagnostics.append(
                    _error(
                        "contract.lineage_predecessor_hash",
                        f"{path}/previous_entry_sha256",
                        "Lineage entry does not link the previous published entry hash.",
                    )
                )
            if entry["predecessor_benchmark_version"] != previous_entry["benchmark_version"]:
                diagnostics.append(
                    _error(
                        "contract.lineage_predecessor_version",
                        f"{path}/predecessor_benchmark_version",
                        "Successor benchmark does not name the prior benchmark version.",
                    )
                )
            if not entry["changes_informed_by_predecessor"]:
                diagnostics.append(
                    _error(
                        "contract.lineage_missing_disclosure",
                        f"{path}/changes_informed_by_predecessor",
                        "Successor benchmarks must disclose changes informed by the prior outcome.",
                    )
                )
        if entry["aggregate_artifact"]["bytes"] <= 0:
            diagnostics.append(
                _error(
                    "contract.empty_test_outcome",
                    f"{path}/aggregate_artifact/bytes",
                    "Every final-test access requires a non-empty privacy-safe aggregate outcome.",
                )
            )
        previous_entry = entry

    expected_head = lineage[-1]["entry_sha256"] if lineage else None
    if access["lineage_head_sha256"] != expected_head:
        diagnostics.append(
            _error(
                "contract.lineage_head_mismatch",
                "/test_access/lineage_head_sha256",
                "Lineage head must equal the final entry hash, or null for an empty lineage.",
            )
        )
    if len(current_entries) != count:
        diagnostics.append(
            _error(
                "contract.test_access_count",
                "/test_access/current_version_access_count",
                "Current-version access count must equal its lineage entry count.",
            )
        )
    if count == 1 and len(current_entries) == 1:
        current = current_entries[0]
        if lineage[-1] is not current:
            diagnostics.append(
                _error(
                    "contract.lineage_current_not_head",
                    "/test_access/lineage",
                    "The current benchmark access must be the append-only lineage head.",
                )
            )
        if access["current_version_accessed_at"] != current["accessed_at"]:
            diagnostics.append(
                _error(
                    "contract.test_access_timestamp",
                    "/test_access/current_version_accessed_at",
                    "Current access timestamp must equal its lineage entry.",
                )
            )
        if access["frozen_target"] != current["frozen_target"]:
            diagnostics.append(
                _error(
                    "contract.current_lineage_freeze_mismatch",
                    "/test_access/frozen_target",
                    "Current frozen target must equal the current lineage entry.",
                )
            )
        evidence_created = _parse_timestamp(evidence["created_at"])
        accessed_at = _parse_timestamp(current["accessed_at"])
        if evidence_created is not None and accessed_at is not None and evidence_created < accessed_at:
            diagnostics.append(
                _error(
                    "contract.evidence_timestamp_order",
                    "/created_at",
                    "Evidence cannot predate its final-test access.",
                )
            )
        if evidence["promotion"]["passed"] and current["outcome"] != "passed":
            diagnostics.append(
                _error(
                    "contract.failed_test_promotion",
                    f"/test_access/lineage/{len(lineage) - 1}/outcome",
                    "Failed or aborted final-test outcomes cannot be promoted.",
                )
            )

    if trusted_lineage_prefix is None:
        if evidence["promotion"]["passed"] or evidence["verifier"]["passed"]:
            diagnostics.append(
                _error(
                    "contract.trusted_lineage_required",
                    "/test_access/lineage",
                    "Verifier-passed evidence requires the previously published trusted lineage prefix.",
                )
            )
    else:
        expected_prefix_length = len(lineage) - count
        if len(trusted_lineage_prefix) != expected_prefix_length or list(trusted_lineage_prefix) != list(
            lineage[:expected_prefix_length]
        ):
            diagnostics.append(
                _error(
                    "contract.lineage_not_append_only",
                    "/test_access/lineage",
                    "Evidence lineage is not an exact append of the trusted published prefix.",
                )
            )
    return diagnostics


def _performance_diagnostics(
    performance: Mapping[str, Any],
    bank: Mapping[str, Any],
    referenced_samples: Mapping[str, Sequence[float]] | None,
) -> list[Diagnostic]:
    banks = performance["banks"]
    workloads = performance["workloads"]
    if not performance["evaluated"]:
        return (
            []
            if not workloads and not banks
            else [
                _error(
                    "contract.not_evaluated_has_workloads",
                    "/performance",
                    "Unevaluated performance must not contain banks or workloads.",
                )
            ]
        )
    if not workloads or not banks:
        return [
            _error(
                "contract.empty_performance",
                "/performance",
                "Evaluated performance requires declared banks and workloads.",
            )
        ]
    diagnostics: list[Diagnostic] = []
    diagnostics.extend(_duplicate_id_diagnostics(banks, "/performance/banks", "performance bank"))
    diagnostics.extend(_duplicate_id_diagnostics(workloads, "/performance/workloads", "performance workload"))
    bank_by_hash = {str(item["bank_hash"]): item for item in banks}
    evaluated_banks = [item for item in banks if item["kind"] == "evaluated_bank"]
    if len(evaluated_banks) != 1:
        diagnostics.append(
            _error(
                "contract.evaluated_performance_bank",
                "/performance/banks",
                "Performance requires exactly one evaluated-bank descriptor.",
            )
        )
    else:
        descriptor = evaluated_banks[0]
        expected_descriptor = {
            "bank_hash": bank["canonical_hash"],
            "active_entities": bank["active_entities"],
            "active_names": bank["active_names"],
            "active_patterns": bank["active_patterns"],
            "canonical_json_bytes": bank["canonical_json_bytes"],
            "native_source_bytes": bank["native_source_bytes"],
        }
        if any(descriptor[field] != expected for field, expected in expected_descriptor.items()):
            diagnostics.append(
                _error(
                    "contract.performance_bank_mismatch",
                    "/performance/banks",
                    "Evaluated performance-bank descriptor differs from evidence bank provenance.",
                )
            )
    for index, workload in enumerate(workloads):
        path = f"/performance/workloads/{index}"
        if workload["bank_hash"] not in bank_by_hash:
            diagnostics.append(
                _error(
                    "contract.unknown_performance_bank",
                    f"{path}/bank_hash",
                    "Performance workload references an undeclared bank descriptor.",
                )
            )
        if workload["workload_sha256"] != hash_enron_workload(workload):
            diagnostics.append(
                _error(
                    "contract.workload_hash_mismatch",
                    f"{path}/workload_sha256",
                    "Workload hash does not match its canonical descriptor.",
                )
            )
        if workload["phase"] == "cold_compile" and workload["process_model"] != "fresh_process_per_sample":
            diagnostics.append(
                _error(
                    "contract.cold_compile_process_model",
                    f"{path}/process_model",
                    "Cold compile requires a fresh process for every sample.",
                )
            )
        if workload["phase"] == "direct_bank_scan" and workload["process_model"] != "reused_process":
            diagnostics.append(
                _error(
                    "contract.direct_scan_process_model",
                    f"{path}/process_model",
                    "Direct Bank scans require a reused compiled process.",
                )
            )
        samples = workload["samples_seconds"]
        resolved_samples: Sequence[float] | None = samples
        if not samples:
            sample_ref = workload["samples_ref"]
            resolved_samples = None if referenced_samples is None else referenced_samples.get(sample_ref["id"])
            if resolved_samples is None:
                diagnostics.append(
                    _error(
                        "contract.performance_samples_unavailable",
                        f"{path}/samples_ref",
                        "Referenced raw samples must be supplied to the semantic verifier.",
                    )
                )
                continue
        if resolved_samples is None:
            continue
        normalized_samples = _normalize_samples(resolved_samples)
        if len(resolved_samples) < 5 or normalized_samples is None:
            diagnostics.append(
                _error(
                    "contract.performance_sample_support",
                    f"{path}/samples_seconds",
                    "Performance requires at least five finite, strictly positive, bounded samples.",
                )
            )
            continue
        if not samples and (
            workload["samples_ref"]["bytes"] != len(_canonical_payload(normalized_samples))
            or hash_enron_samples(normalized_samples) != workload["samples_ref"]["sha256"]
        ):
            diagnostics.append(
                _error(
                    "contract.performance_sample_hash",
                    f"{path}/samples_ref",
                    "Resolved samples do not match the non-empty content-addressed sample reference.",
                )
            )
        stats = workload["stats"]
        expected = _sample_statistics(normalized_samples, workload["documents"], workload["bytes"])
        for field, value in expected.items():
            if not _same_metric(stats[field], value):
                diagnostics.append(
                    _error(
                        "contract.performance_arithmetic",
                        f"{path}/stats/{field}",
                        f"Expected {value!r} from raw samples.",
                    )
                )
        if workload["promotion_gate"] and (
            workload["phase"] != "direct_bank_scan"
            or workload["bank_hash"] != bank["canonical_hash"]
            or len(normalized_samples) < 100
        ):
            diagnostics.append(
                _error(
                    "contract.invalid_performance_gate",
                    f"{path}/promotion_gate",
                    "Promoted performance requires at least 100 direct reused-Bank samples on the evaluated bank.",
                )
            )
    unused_bank_hashes = set(bank_by_hash) - {str(item["bank_hash"]) for item in workloads}
    if unused_bank_hashes:
        diagnostics.append(
            _error(
                "contract.unused_performance_bank",
                "/performance/banks",
                "Every declared performance bank must be exercised by at least one workload.",
            )
        )
    return diagnostics


def _gate_diagnostics(evidence: Mapping[str, Any]) -> list[Diagnostic]:
    promotion = evidence["promotion"]
    diagnostics: list[Diagnostic] = []
    checks = promotion["checks"]
    diagnostics.extend(_duplicate_id_diagnostics(checks, "/promotion/checks", "promotion check"))
    seen_targets: set[str] = set()
    if evidence["thresholds_sha256"] != hash_enron_thresholds(checks):
        diagnostics.append(
            _error(
                "contract.threshold_hash_mismatch",
                "/thresholds_sha256",
                "Threshold hash does not match the canonical declared check configuration.",
            )
        )
    allowed_prefixes = {
        "quality": ("/quality/",),
        "catalog_conformance": ("/catalog_conformance/",),
        "performance": ("/performance/",),
        "privacy": ("/privacy/",),
        "provenance": ("/software/", "/splits/", "/bank/", "/source/", "/preparation/"),
    }
    for index, check in enumerate(checks):
        path = f"/promotion/checks/{index}"
        if check["target"] in seen_targets:
            diagnostics.append(
                _error(
                    "contract.duplicate_gate_target",
                    f"{path}/target",
                    "Promotion gate targets must be unique.",
                )
            )
        seen_targets.add(str(check["target"]))
        if not check["target"].startswith(allowed_prefixes[check["category"]]):
            diagnostics.append(
                _error(
                    "contract.gate_category_target",
                    f"{path}/target",
                    "Gate target is outside its declared evidence category.",
                )
            )
            continue
        try:
            actual = _resolve_pointer(evidence, check["target"])
        except (KeyError, IndexError, TypeError, ValueError):
            diagnostics.append(
                _error("contract.gate_target", f"{path}/target", "Gate target does not resolve to evidence.")
            )
            continue
        if not _same_scalar(check["actual"], actual):
            diagnostics.append(
                _error(
                    "contract.gate_actual",
                    f"{path}/actual",
                    "Declared gate actual value differs from the targeted evidence value.",
                )
            )
        expected_pass = _compare_gate(actual, check["operator"], check["threshold"])
        if expected_pass is None:
            diagnostics.append(
                _error(
                    "contract.gate_comparison",
                    path,
                    "Gate operator and values do not form a valid finite comparison.",
                )
            )
        elif check["passed"] != expected_pass:
            diagnostics.append(
                _error(
                    "contract.gate_result",
                    f"{path}/passed",
                    "Gate result does not match the recomputed comparison.",
                )
            )
    return diagnostics


def _promotion_diagnostics(evidence: Mapping[str, Any]) -> list[Diagnostic]:
    promotion = evidence["promotion"]
    diagnostics = _claim_diagnostics(evidence)
    if not promotion["passed"]:
        return diagnostics
    requirements = {
        "quality evaluated": evidence["quality"]["evaluated"],
        "catalog conformance passed": evidence["catalog_conformance"]["passed"],
        "performance evaluated": evidence["performance"]["evaluated"],
        "privacy passed": evidence["privacy"]["status"] == "passed",
        "verifier passed": evidence["verifier"]["passed"],
        "all declared checks passed": all(item["passed"] for item in promotion["checks"]),
        "clean git state": evidence["software"]["git_dirty"] is False,
        "one-shot final test": evidence["test_access"]["current_version_access_count"] == 1,
        "real benchmark artifact": evidence["artifact_kind"] == "real_benchmark",
        "structured claims": bool(promotion["claims"]),
    }
    for name, passed in requirements.items():
        if not passed:
            diagnostics.append(
                _error("contract.promotion_prerequisite", "/promotion/passed", f"Promotion requires {name}.")
            )
    quality_gate_indices = [index for index, item in enumerate(evidence["quality"]["slices"]) if item["promotion_gate"]]
    if not quality_gate_indices:
        diagnostics.append(
            _error(
                "contract.missing_quality_gate",
                "/quality/slices",
                "Promotion requires an independent exhaustive final-test quality gate slice.",
            )
        )
    required_gate_specs: dict[str, tuple[str, Any | None]] = {
        "/catalog_conformance/passed": ("eq", True),
        "/privacy/status": ("eq", "passed"),
        "/software/git_dirty": ("eq", False),
    }
    quality_metric_fields = (
        "open_world_recall",
        "catalog_coverage",
        "cataloged_recall",
        "document_leak_rate",
        "sensitive_character_recall",
        "sensitive_character_leak_rate",
        "negative_document_false_alarm_rate",
        "over_redaction_rate",
    )
    for index in quality_gate_indices:
        item = evidence["quality"]["slices"][index]
        if (
            item["gold_spans"] <= 0
            or item["cataloged_gold_spans"] <= 0
            or item["cataloged_false_negative"] != 0
            or item["cataloged_wrong_canonical"] != 0
            or item["documents_with_any_cataloged_miss"] != 0
        ):
            diagnostics.append(
                _error(
                    "contract.natural_catalog_gate",
                    f"/quality/slices/{index}",
                    "Promoted slices require nonzero gold plus zero cataloged misses and wrong mappings.",
                )
            )
        for field in (
            "cataloged_false_negative",
            "cataloged_wrong_canonical",
            "documents_with_any_cataloged_miss",
        ):
            required_gate_specs[f"/quality/slices/{index}/{field}"] = ("eq", 0)
        for field in quality_metric_fields:
            operator = (
                "gte"
                if field in {"open_world_recall", "catalog_coverage", "cataloged_recall", "sensitive_character_recall"}
                else "lte"
            )
            required_gate_specs[f"/quality/slices/{index}/metrics/{field}"] = (operator, None)
    performance_gate_indices = [
        index for index, item in enumerate(evidence["performance"]["workloads"]) if item["promotion_gate"]
    ]
    workload_phases = {str(item["phase"]) for item in evidence["performance"]["workloads"]}
    missing_phases = sorted(set(PERFORMANCE_PHASES) - workload_phases)
    if missing_phases:
        diagnostics.append(
            _error(
                "contract.missing_performance_phase",
                "/performance/workloads",
                "Promoted evidence is missing performance phases: " + ", ".join(missing_phases),
            )
        )
    scale_shapes = {
        int(item["active_patterns"]) for item in evidence["performance"]["banks"] if item["kind"] == "synthetic_scale"
    }
    required_scale_shapes = {1_000, 10_000, 25_000, 100_000}
    if not required_scale_shapes <= scale_shapes:
        diagnostics.append(
            _error(
                "contract.missing_scale_shape",
                "/performance/banks",
                "Promoted evidence requires 1k, 10k, 25k, and 100k synthetic scale-bank descriptors.",
            )
        )
    hit_densities = {str(item["hit_density"]) for item in evidence["performance"]["workloads"]}
    if not {"negative", "sparse", "normal", "dense"} <= hit_densities:
        diagnostics.append(
            _error(
                "contract.missing_hit_density",
                "/performance/workloads",
                "Promoted evidence requires negative, sparse, normal, and dense hit-density workloads.",
            )
        )
    concurrencies = {int(item["concurrency"]) for item in evidence["performance"]["workloads"]}
    if 1 not in concurrencies or not any(value > 1 for value in concurrencies):
        diagnostics.append(
            _error(
                "contract.missing_concurrency_shape",
                "/performance/workloads",
                "Promoted evidence requires both serial and concurrent workloads.",
            )
        )
    if not performance_gate_indices:
        diagnostics.append(
            _error(
                "contract.missing_performance_gate",
                "/performance/workloads",
                "Promotion requires a decision-grade direct reused-Bank performance workload.",
            )
        )
    for index in performance_gate_indices:
        item = evidence["performance"]["workloads"][index]
        if item["peak_rss_bytes"] is None:
            diagnostics.append(
                _error(
                    "contract.missing_peak_rss",
                    f"/performance/workloads/{index}/peak_rss_bytes",
                    "Promoted performance workloads require peak RSS evidence.",
                )
            )
        required_gate_specs.update(
            {
                f"/performance/workloads/{index}/stats/median_seconds": ("lte", None),
                f"/performance/workloads/{index}/stats/p95_seconds": ("lte", None),
                f"/performance/workloads/{index}/stats/p99_seconds": ("lte", None),
                f"/performance/workloads/{index}/stats/mib_per_second": ("gte", None),
                f"/performance/workloads/{index}/peak_rss_bytes": ("lte", None),
            }
        )
    checks_by_target = {str(item["target"]): item for item in promotion["checks"]}
    missing_targets = sorted(set(required_gate_specs) - set(checks_by_target))
    if missing_targets:
        diagnostics.append(
            _error(
                "contract.missing_required_gate",
                "/promotion/checks",
                "Missing required promotion gate targets: " + ", ".join(missing_targets),
            )
        )
    for target, (operator, exact_threshold) in required_gate_specs.items():
        check = checks_by_target.get(target)
        if check is None:
            continue
        if check["operator"] != operator or (
            exact_threshold is not None and not _same_scalar(check["threshold"], exact_threshold)
        ):
            diagnostics.append(
                _error(
                    "contract.required_gate_semantics",
                    "/promotion/checks",
                    f"Required gate {target} must use {operator} with its mandated threshold semantics.",
                )
            )
    claim_metrics = {str(item["metric"]) for item in promotion["claims"]}
    required_claim_metrics = {
        "catalog_conformance_recall",
        "open_world_recall",
        "direct_bank_scan_p99_seconds",
        "direct_bank_scan_mib_per_second",
    }
    if not required_claim_metrics <= claim_metrics:
        diagnostics.append(
            _error(
                "contract.missing_required_claim",
                "/promotion/claims",
                "Promotion is missing required structured privacy, guarantee, or performance claims.",
            )
        )
    return diagnostics


def _claim_diagnostics(evidence: Mapping[str, Any]) -> list[Diagnostic]:
    claims = evidence["promotion"]["claims"]
    diagnostics = _duplicate_id_diagnostics(claims, "/promotion/claims", "claim")
    slices = {str(item["id"]): item for item in evidence["quality"]["slices"]}
    workloads = {str(item["id"]): item for item in evidence["performance"]["workloads"]}
    expected_environment_hash = hash_enron_environment(evidence["environment"])
    common_expected = {
        "source_revision": evidence["source"]["revision"],
        "evaluator_source_sha256": evidence["evaluator"]["source_sha256"],
        "environment_sha256": expected_environment_hash,
    }
    quality_metrics = {
        "precision",
        "open_world_recall",
        "f1",
        "document_leak_rate",
        "sensitive_character_recall",
        "sensitive_character_leak_rate",
        "negative_document_false_alarm_rate",
        "over_redaction_rate",
    }
    performance_metrics = {
        "direct_bank_scan_median_seconds": "median_seconds",
        "direct_bank_scan_p95_seconds": "p95_seconds",
        "direct_bank_scan_p99_seconds": "p99_seconds",
        "direct_bank_scan_mib_per_second": "mib_per_second",
    }
    null_scope = {"entity_class": None, "cohort": None, "split_role": None, "text_view": None}
    for index, claim in enumerate(claims):
        path = f"/promotion/claims/{index}"
        for field, expected in common_expected.items():
            if claim[field] != expected:
                diagnostics.append(
                    _error(
                        "contract.claim_provenance",
                        f"{path}/{field}",
                        "Claim provenance differs from its evidence bundle.",
                    )
                )
        if claim["kind"] == "catalog_conformance":
            valid = (
                claim["metric"] == "catalog_conformance_recall"
                and claim["quality_slice_id"] is None
                and claim["performance_workload_id"] is None
                and claim["scope"] == null_scope
                and claim["label_strength"] == "synthetic_conformance"
                and claim["annotation_completeness"] == "exhaustive_within_scope"
                and claim["bank_hash"] == evidence["bank"]["canonical_hash"]
                and _same_metric(claim["value"], evidence["catalog_conformance"]["recall"])
            )
        elif claim["kind"] == "open_world_quality":
            item = slices.get(str(claim["quality_slice_id"]))
            expected_scope = (
                None
                if item is None
                else {
                    "entity_class": item["entity_class"],
                    "cohort": item["cohort"],
                    "split_role": item["split_role"],
                    "text_view": item["text_view"],
                }
            )
            expected_value = (
                None if item is None or claim["metric"] not in quality_metrics else item["metrics"][claim["metric"]]
            )
            valid = (
                item is not None
                and claim["metric"] in quality_metrics
                and claim["performance_workload_id"] is None
                and claim["scope"] == expected_scope
                and claim["label_strength"] == item["label_strength"] == "independent"
                and claim["annotation_completeness"] == item["annotation_completeness"] == "exhaustive_within_scope"
                and claim["bank_hash"] == evidence["bank"]["canonical_hash"]
                and expected_value is not None
                and _same_metric(claim["value"], expected_value)
            )
        else:
            workload = workloads.get(str(claim["performance_workload_id"]))
            stat_field = performance_metrics.get(str(claim["metric"]))
            expected_value = None if workload is None or stat_field is None else workload["stats"][stat_field]
            valid = (
                workload is not None
                and workload["phase"] == "direct_bank_scan"
                and claim["metric"] in performance_metrics
                and claim["quality_slice_id"] is None
                and claim["scope"] == null_scope
                and claim["label_strength"] == "unlabeled"
                and claim["annotation_completeness"] == "not_applicable"
                and claim["bank_hash"] == workload["bank_hash"]
                and expected_value is not None
                and _same_metric(claim["value"], expected_value)
            )
        if not valid:
            diagnostics.append(
                _error(
                    "contract.unsupported_claim",
                    path,
                    "Structured claim exceeds or differs from its exact supporting evidence.",
                )
            )
    return diagnostics


def _binding_diagnostics(evidence: Mapping[str, Any], manifest: Mapping[str, Any]) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    manifest_result = validate_enron_manifest(manifest)
    if not manifest_result["valid"]:
        return [_error("contract.invalid_manifest_binding", "/manifest_sha256", "Bound manifest is invalid.")]
    if evidence["manifest_sha256"] != hash_enron_manifest(manifest):
        diagnostics.append(
            _error(
                "contract.manifest_hash_mismatch", "/manifest_sha256", "Evidence does not bind the supplied manifest."
            )
        )
    for field in ("thresholds_sha256", "performance_manifest_sha256"):
        if evidence[field] != manifest[field]:
            diagnostics.append(
                _error(
                    "contract.provenance_mismatch",
                    f"/{field}",
                    f"Evidence {field} differs from the supplied manifest.",
                )
            )
    for field in (
        "artifact_kind",
        "evaluator",
        "source",
        "preparation",
        "splits",
        "bank",
        "software",
        "environment",
        "privacy",
    ):
        if evidence[field] != manifest[field]:
            diagnostics.append(
                _error(
                    "contract.provenance_mismatch", f"/{field}", f"Evidence {field} differs from the supplied manifest."
                )
            )
    evidence_verifier = {field: evidence["verifier"][field] for field in ("id", "version", "source_sha256")}
    if evidence_verifier != manifest["verifier"]:
        diagnostics.append(
            _error(
                "contract.provenance_mismatch",
                "/verifier",
                "Evidence verifier identity differs from the supplied manifest.",
            )
        )
    evidence_created = _parse_timestamp(evidence["created_at"])
    manifest_created = _parse_timestamp(manifest["created_at"])
    if evidence_created is not None and manifest_created is not None and evidence_created < manifest_created:
        diagnostics.append(
            _error(
                "contract.evidence_timestamp_order",
                "/created_at",
                "Evidence creation cannot predate its bound manifest.",
            )
        )
    return diagnostics


def _privacy_diagnostics(value: Mapping[str, Any], path: str) -> list[Diagnostic]:
    should_pass = (
        not value["raw_text_included"] and not value["direct_identifiers_included"] and value["violation_count"] == 0
    )
    if value["status"] == "passed" and not should_pass:
        return [
            _error(
                "contract.forged_privacy_pass",
                f"{path}/status",
                "Privacy cannot pass with raw text, direct identifiers, or violations.",
            )
        ]
    return []


def _command_diagnostics(commands: Sequence[Mapping[str, Any]], path: str) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    for command_index, command in enumerate(commands):
        values = [("cwd", command["cwd"]), *((f"argv/{index}", value) for index, value in enumerate(command["argv"]))]
        for value_path, value in values:
            if _contains_unsafe_command_path(value):
                diagnostics.append(
                    _error(
                        "contract.private_absolute_path",
                        f"{path}/{command_index}/{value_path}",
                        "Public commands must use sanitized repository-relative paths without traversal or file URIs.",
                    )
                )
    return diagnostics


def _contains_unsafe_command_path(value: str) -> bool:
    candidates = [value]
    if "=" in value:
        candidates.append(value.split("=", 1)[1])
    for candidate in candidates:
        lowered = candidate.lower()
        if lowered.startswith(("file://", "~/", "~\\")):
            return True
        if PurePosixPath(candidate).is_absolute() or PureWindowsPath(candidate).is_absolute():
            return True
        if ".." in PurePosixPath(candidate).parts or ".." in PureWindowsPath(candidate).parts:
            return True
    return False


_EMAIL_PATTERN = re.compile(r"(?i)(?<![\w.+-])[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}(?![\w.-])")
_PRIVATE_PATH_PATTERN = re.compile(
    r"(?i)(?:file://|/(?:users|home|private|var/folders)/[^\s\"']+|[a-z]:\\users\\[^\s\"']+|\\\\[^\s\"']+)"
)


def _public_serialization_diagnostics(value: Mapping[str, Any]) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    for path, text in _iter_strings(value):
        if _EMAIL_PATTERN.search(text):
            diagnostics.append(
                _error(
                    "contract.public_direct_identifier",
                    path,
                    "Public contract serialization contains an email-address-shaped direct identifier.",
                )
            )
        if _PRIVATE_PATH_PATTERN.search(text):
            diagnostics.append(
                _error(
                    "contract.public_private_path",
                    path,
                    "Public contract serialization contains a private local-path shape.",
                )
            )
    return diagnostics


def _iter_strings(value: Any, path: str = "") -> Iterable[tuple[str, str]]:
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, Mapping):
        for key, item in value.items():
            escaped = str(key).replace("~", "~0").replace("/", "~1")
            yield from _iter_strings(item, f"{path}/{escaped}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _iter_strings(item, f"{path}/{index}")


def _normalize_samples(samples: Sequence[Any]) -> list[float] | None:
    normalized: list[float] = []
    for value in samples:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        try:
            parsed = float(value)
        except (OverflowError, ValueError):
            return None
        if not math.isfinite(parsed) or not MIN_SAMPLE_SECONDS <= parsed <= MAX_SAMPLE_SECONDS:
            return None
        normalized.append(parsed)
    return normalized


def _sample_statistics(samples: Sequence[float], documents: int, byte_count: int) -> dict[str, float | int | None]:
    ordered = sorted(float(item) for item in samples)
    median_seconds = float(median(ordered))
    deviations = [abs(item - median_seconds) for item in ordered]
    return {
        "sample_count": len(ordered),
        "median_seconds": median_seconds,
        "p95_seconds": _nearest_rank(ordered, 0.95) if len(ordered) >= 20 else None,
        "p99_seconds": _nearest_rank(ordered, 0.99) if len(ordered) >= 100 else None,
        "mad_seconds": float(median(deviations)),
        "documents_per_second": documents / median_seconds,
        "mib_per_second": byte_count / (1024 * 1024) / median_seconds,
    }


def _nearest_rank(values: Sequence[float], probability: float) -> float:
    index = max(0, math.ceil(probability * len(values)) - 1)
    return values[index]


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _f1(true_positive: int, false_positive: int, false_negative: int) -> float | None:
    denominator = 2 * true_positive + false_positive + false_negative
    return (2 * true_positive) / denominator if denominator else None


def _same_metric(actual: Any, expected: Any) -> bool:
    if actual is None or expected is None:
        return actual is expected
    return math.isclose(float(actual), float(expected), rel_tol=1e-9, abs_tol=1e-12)


def _same_scalar(actual: Any, expected: Any) -> bool:
    if isinstance(actual, bool) or isinstance(expected, bool):
        return type(actual) is type(expected) and actual == expected
    if isinstance(actual, (int, float)) and isinstance(expected, (int, float)):
        return _same_metric(actual, expected)
    return type(actual) is type(expected) and actual == expected


def _compare_gate(actual: Any, operator: str, threshold: Any) -> bool | None:
    if operator == "eq":
        return _same_scalar(actual, threshold)
    if (
        isinstance(actual, bool)
        or isinstance(threshold, bool)
        or not isinstance(actual, (int, float))
        or not isinstance(threshold, (int, float))
    ):
        return None
    try:
        actual_value = float(actual)
        threshold_value = float(threshold)
    except (OverflowError, ValueError):
        return None
    if not math.isfinite(actual_value) or not math.isfinite(threshold_value):
        return None
    return actual_value >= threshold_value if operator == "gte" else actual_value <= threshold_value


def _resolve_pointer(value: Any, pointer: str) -> Any:
    if not pointer.startswith("/") or pointer == "/":
        raise ValueError(pointer)
    current = value
    for raw_part in pointer[1:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping):
            current = current[part]
        elif isinstance(current, list):
            current = current[int(part)]
        else:
            raise TypeError(pointer)
    if isinstance(current, (Mapping, list)):
        raise TypeError(pointer)
    return current


def _parse_timestamp(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None and parsed.utcoffset() is not None else None


def _timestamp_diagnostics(value: str, path: str) -> list[Diagnostic]:
    if _parse_timestamp(value) is None:
        return [_error("contract.invalid_timestamp", path, "Timestamp must be timezone-aware RFC 3339/ISO 8601.")]
    return []


def _duplicate_id_diagnostics(values: Sequence[Mapping[str, Any]], path: str, description: str) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    seen: set[str] = set()
    for index, value in enumerate(values):
        identifier = str(value["id"])
        if identifier in seen:
            diagnostics.append(
                _error(
                    "contract.duplicate_id",
                    f"{path}/{index}/id",
                    f"Duplicate {description} ID {identifier!r}.",
                )
            )
        seen.add(identifier)
    return diagnostics


def _zero_nonzero_diagnostics(total: int, documents: int, path: str, description: str) -> list[Diagnostic]:
    if (total == 0) != (documents == 0):
        return [
            _error(
                "contract.document_event_consistency",
                path,
                f"Document count must be zero exactly when {description} are zero.",
            )
        ]
    return []


def _schema_diagnostics(validator: Any, value: Any) -> list[Diagnostic]:
    return [_schema_error(item) for item in sorted(validator.iter_errors(value), key=_schema_sort_key)]


def _schema_error(error: ValidationError) -> Diagnostic:
    return _error(f"contract.schema.{error.validator}", _pointer(error.absolute_path), error.message)


def _schema_sort_key(error: ValidationError) -> tuple[str, str]:
    return (_pointer(error.absolute_path), error.message)


def _pointer(parts: Iterable[Any]) -> str:
    values = [str(part).replace("~", "~0").replace("/", "~1") for part in parts]
    return "/" + "/".join(values) if values else ""


def _error(code: str, path: str, message: str) -> Diagnostic:
    return diagnostic(DIAGNOSTIC_ERROR, code, path, message)


def _result(diagnostics: list[Diagnostic]) -> dict[str, Any]:
    ordered = sorted(diagnostics, key=lambda item: (str(item["path"]), str(item["code"]), str(item["message"])))
    return {"valid": not has_errors(ordered), "diagnostics": ordered}


def _load_contract_json(path: str | Path) -> dict[str, Any]:
    source = Path(path).expanduser()
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        before = source.lstat()
    except OSError as exc:
        raise ValueError("Contract path could not be inspected.") from exc
    if not S_ISREG(before.st_mode):
        raise ValueError("Contract path must be a regular non-symlink file.")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0) | nofollow
    try:
        descriptor = os.open(source, flags)
    except OSError as exc:
        raise ValueError("Contract path could not be opened as a regular non-symlink file.") from exc
    try:
        info = os.fstat(descriptor)
        if not S_ISREG(info.st_mode):
            raise ValueError("Contract path must be a regular non-symlink file.")
        if nofollow == 0 and (before.st_dev, before.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError("Contract path changed while it was being opened.")
        if info.st_size > MAX_CONTRACT_BYTES:
            raise ValueError(f"Contract file exceeds the {MAX_CONTRACT_BYTES}-byte limit.")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, MAX_CONTRACT_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_CONTRACT_BYTES:
                raise ValueError(f"Contract file exceeds the {MAX_CONTRACT_BYTES}-byte limit.")
        payload = b"".join(chunks).decode("utf-8")
    finally:
        os.close(descriptor)
    value = json.loads(payload, parse_constant=_reject_constant, object_pairs_hook=_reject_duplicate_keys)
    if not isinstance(value, dict):
        raise ValueError("Contract file must contain a JSON object.")
    return value


def _reject_constant(value: str) -> None:
    raise ValueError(f"Contract JSON contains non-finite value {value}.")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"Contract JSON contains duplicate key {key!r}.")
        value[key] = item
    return value


__all__ = [
    "ANNOTATION_COMPLETENESS",
    "CHARACTER_POSITION_SEMANTICS",
    "ENRON_CHARTER_VERSION",
    "ENRON_EVIDENCE_SCHEMA",
    "ENRON_EVIDENCE_SCHEMA_VERSION",
    "ENRON_MANIFEST_SCHEMA",
    "ENRON_MANIFEST_SCHEMA_VERSION",
    "ENRON_VERIFIER_ID",
    "ENRON_VERIFIER_VERSION",
    "MATCHING_SEMANTICS",
    "hash_enron_environment",
    "hash_enron_manifest",
    "hash_enron_performance_manifest",
    "hash_enron_samples",
    "hash_enron_test_lineage_entry",
    "hash_enron_thresholds",
    "hash_enron_workload",
    "load_enron_evidence",
    "load_enron_manifest",
    "validate_enron_evidence",
    "validate_enron_manifest",
]

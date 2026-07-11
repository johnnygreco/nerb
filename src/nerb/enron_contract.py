"""Executable, privacy-safe contracts for the Enron benchmark-v2 evidence boundary.

The schemas close every object and the semantic verifier recomputes aggregate claims without reading private corpus
text. A promoted or verifier-passed bundle must be checked with its exact manifest, the previously published final-test
lineage prefix, and any external content-addressed timing samples and privacy-safe input inventories.
"""

from __future__ import annotations

import json
import math
import os
import re
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from fractions import Fraction
from hashlib import sha256
from heapq import nsmallest
from html import unescape as unescape_html
from pathlib import Path, PurePosixPath, PureWindowsPath
from stat import S_ISREG
from statistics import median
from typing import Any, NoReturn
from unicodedata import decimal as unicode_decimal
from unicodedata import normalize as normalize_unicode
from urllib.parse import unquote, urlsplit

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError
from jsonschema.validators import extend

from .diagnostics import DIAGNOSTIC_ERROR, Diagnostic, diagnostic, has_errors

ENRON_MANIFEST_SCHEMA_VERSION = "nerb.enron_manifest.v2"
ENRON_EVIDENCE_SCHEMA_VERSION = "nerb.enron_evidence.v2"
ENRON_CHARTER_VERSION = "2"
ENRON_VERIFIER_ID = "nerb-enron-contract"
ENRON_VERIFIER_VERSION = "2.2.0"
MAX_CONTRACT_BYTES = 16 * 1024 * 1024
MAX_CONTRACT_DEPTH = 100
MAX_CONTRACT_NODES = 250_000
MAX_COLLECTION_ITEMS = 10_000
MAX_REFERENCED_ITEMS = 250_000
MAX_DIAGNOSTICS = 100
MAX_ID_CHARS = 256
MAX_STRING_CHARS = 4 * 1024
MAX_TOTAL_STRING_CHARS = MAX_CONTRACT_BYTES
MAX_PUBLIC_DECODE_ROUNDS = 8
MAX_SAFE_INTEGER = 2**63 - 1
MAX_FINITE_CONTRACT_NUMBER = 1e300
MIN_SAMPLE_SECONDS = 1e-9
MAX_SAMPLE_SECONDS = 24 * 60 * 60
MIN_PUBLIC_SLICE_DOCUMENTS = 5
MIN_DECISION_GRADE_DOCUMENTS = 100
MIN_DECISION_GRADE_GOLD_SPANS = 100
MIN_DECISION_GRADE_NEGATIVE_DOCUMENTS = 20
MIN_DECISION_GRADE_SENSITIVE_CHARACTERS = 500
MIN_QUALITY_THRESHOLDS = {
    "open_world_recall": 0.95,
    "catalog_coverage": 0.80,
    "cataloged_recall": 1.0,
    "sensitive_character_recall": 0.98,
}
MAX_QUALITY_THRESHOLDS = {
    "document_leak_rate": 0.05,
    "sensitive_character_leak_rate": 0.02,
    "negative_document_false_alarm_rate": 0.50,
    "over_redaction_rate": 0.05,
}
SHA256_PATTERN = r"^sha256:[0-9a-f]{64}$"
GIT_COMMIT_PATTERN = r"^[0-9a-f]{40}$"
ZERO_SHA256 = "sha256:" + "0" * 64
LABEL_STRENGTHS = ("independent", "structured_weak", "synthetic_conformance", "unlabeled")
LABEL_ROLES = ("train", "validation", "test", "conformance")
ANNOTATION_COMPLETENESS = ("exhaustive_within_scope", "partial", "not_applicable")
CHARACTER_POSITION_SEMANTICS = "document_id_unicode_scalar_index"
MATCHING_SEMANTICS = "one_to_one_exact_span_and_class"
PERFORMANCE_PHASES = (
    "source_profile",
    "source_build",
    "cold_compile",
    "helper_cache_miss",
    "helper_cache_hit",
    "direct_bank_scan",
    "end_to_end",
)
PERFORMANCE_PHASE_PROCESS_MODELS = {
    "source_profile": "fresh_process_per_sample",
    "source_build": "fresh_process_per_sample",
    "cold_compile": "fresh_process_per_sample",
    "helper_cache_miss": "fresh_process_per_sample",
    "helper_cache_hit": "reused_process",
    "direct_bank_scan": "reused_process",
    "end_to_end": "fresh_process_per_sample",
}
PERFORMANCE_SETUP_PHASES = frozenset({"source_profile", "source_build", "cold_compile"})
PERFORMANCE_GATE_STAT_FIELDS = {
    "sample_count",
    "median_seconds",
    "p95_seconds",
    "p99_seconds",
    "mad_seconds",
    "documents_per_second",
    "mib_per_second",
    "records_per_second",
    "seconds_per_document",
}
PERFORMANCE_SCALE_PATTERNS = (1_000, 10_000, 25_000, 100_000)
MIN_DECISION_GRADE_SETUP_SAMPLES = 20
MIN_DECISION_GRADE_SCAN_SAMPLES = 100
MIN_DECISION_GRADE_WARMUPS = 3
MAX_COMPARISON_NOISE_FLOOR = 0.25
MAX_HEADLINE_DOCUMENT_P99_SECONDS = 0.05
MIN_HEADLINE_DOCUMENTS_PER_SECOND = 100.0
MIN_HEADLINE_MIB_PER_SECOND = 1.0
MAX_HEADLINE_PEAK_RSS_BYTES = 8 * 1024**3


def _is_json_array(_checker: Any, value: Any) -> bool:
    return isinstance(value, list)


def _is_json_integer(_checker: Any, value: Any) -> bool:
    return type(value) is int


def _is_json_number(_checker: Any, value: Any) -> bool:
    if type(value) is int:
        return True
    return type(value) is float and math.isfinite(value)


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
    {"id": {"type": "string", "minLength": 1}, "sha256": _HASH, "bytes": _POSITIVE_INTEGER},
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
        "artifact_bytes",
        "active_entities",
        "active_names",
        "active_aliases",
        "active_patterns",
        "canonical_json_bytes",
        "native_source_bytes",
    ),
    {
        "id": {"type": "string", "minLength": 1},
        "canonical_hash": _HASH,
        "artifact_sha256": _HASH,
        "artifact_bytes": _POSITIVE_INTEGER,
        "active_entities": _POSITIVE_INTEGER,
        "active_names": _POSITIVE_INTEGER,
        "active_aliases": _NONNEGATIVE_INTEGER,
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
_LABEL_ROLE_POPULATION = _closed_object(
    ("role", "documents", "spans"),
    {
        "role": {"type": "string", "enum": list(LABEL_ROLES)},
        "documents": _POSITIVE_INTEGER,
        "spans": _NONNEGATIVE_INTEGER,
    },
)
_ANNOTATION_PROVENANCE = _closed_object(
    (
        "protocol_sha256",
        "producer_id",
        "reviewer_id",
        "independently_reviewed",
        "adjudication_artifact",
    ),
    {
        "protocol_sha256": _HASH,
        "producer_id": {"type": "string", "minLength": 1},
        "reviewer_id": {"anyOf": [{"type": "string", "minLength": 1}, {"type": "null"}]},
        "independently_reviewed": {"type": "boolean"},
        "adjudication_artifact": {"anyOf": [_ARTIFACT_REF, {"type": "null"}]},
    },
)
_LABEL_ARTIFACT = _closed_object(
    (
        "id",
        "label_strength",
        "annotation_scope",
        "annotation_completeness",
        "roles",
        "role_populations",
        "annotation_provenance",
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
            "items": {"type": "string", "enum": list(LABEL_ROLES)},
        },
        "role_populations": {"type": "array", "minItems": 1, "items": _LABEL_ROLE_POPULATION},
        "annotation_provenance": _ANNOTATION_PROVENANCE,
        "artifact": _ARTIFACT_REF,
        "span_count": _NONNEGATIVE_INTEGER,
    },
)
_PREPARED_TEXT_VIEW = _closed_object(
    (
        "id",
        "artifact_sha256",
        "content_policy_sha256",
        "document_regions",
        "primary_for_quality",
        "answer_bearing_fields_included",
    ),
    {
        "id": {"type": "string", "minLength": 1},
        "artifact_sha256": _HASH,
        "content_policy_sha256": _HASH,
        "document_regions": {**_STRING_ARRAY, "minItems": 1},
        "primary_for_quality": {"type": "boolean"},
        "answer_bearing_fields_included": {"type": "boolean"},
    },
)
_PREPARATION = _closed_object(
    ("cleaning_policy_sha256", "grouping_policy_sha256", "output_records", "prepared_artifact", "text_views"),
    {
        "cleaning_policy_sha256": _HASH,
        "grouping_policy_sha256": _HASH,
        "output_records": _POSITIVE_INTEGER,
        "prepared_artifact": _ARTIFACT_REF,
        "text_views": {"type": "array", "minItems": 1, "items": _PREPARED_TEXT_VIEW},
    },
)
_QUALITY_PLAN_SLICE = _closed_object(
    (
        "id",
        "label_artifact_id",
        "split_role",
        "entity_class",
        "cohort",
        "text_view",
        "promotion_gate",
        "documents",
        "documents_with_sensitive_gold",
        "negative_documents",
        "gold_spans",
        "cataloged_gold_spans",
        "documents_with_cataloged_gold",
        "sensitive_gold_characters",
        "evaluated_characters",
    ),
    {
        "id": {"type": "string", "minLength": 1},
        "label_artifact_id": {"type": "string", "minLength": 1},
        "split_role": {"type": "string", "enum": ["train", "validation", "test"]},
        "entity_class": {"type": "string", "minLength": 1},
        "cohort": {"type": "string", "minLength": 1},
        "text_view": {"type": "string", "minLength": 1},
        "promotion_gate": {"type": "boolean"},
        "documents": _POSITIVE_INTEGER,
        "documents_with_sensitive_gold": _NONNEGATIVE_INTEGER,
        "negative_documents": _NONNEGATIVE_INTEGER,
        "gold_spans": _NONNEGATIVE_INTEGER,
        "cataloged_gold_spans": _NONNEGATIVE_INTEGER,
        "documents_with_cataloged_gold": _NONNEGATIVE_INTEGER,
        "sensitive_gold_characters": _NONNEGATIVE_INTEGER,
        "evaluated_characters": _NONNEGATIVE_INTEGER,
    },
)
_CONFORMANCE_PLAN = _closed_object(
    (
        "label_artifact_id",
        "positive_cases_artifact",
        "positive_cases",
        "negative_cases_artifact",
        "negative_cases",
        "policy_sha256",
    ),
    {
        "label_artifact_id": {"type": "string", "minLength": 1},
        "positive_cases_artifact": _ARTIFACT_REF,
        "positive_cases": _POSITIVE_INTEGER,
        "negative_cases_artifact": _ARTIFACT_REF,
        "negative_cases": _POSITIVE_INTEGER,
        "policy_sha256": _HASH,
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
            "quality_plan",
            "conformance_plan",
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
            "quality_plan": {"type": "array", "minItems": 1, "items": _QUALITY_PLAN_SLICE},
            "conformance_plan": _CONFORMANCE_PLAN,
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
        "policy_sha256",
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
        "policy_sha256": {"anyOf": [_HASH, {"type": "null"}]},
        "recall": _UNIT_METRIC,
        "passed": {"type": "boolean"},
    },
)
ENRON_QUALITY_OUTPUT_SCHEMA = _closed_object(
    ("evaluated", "matching_semantics", "character_position_semantics", "slices"),
    {
        "evaluated": {"type": "boolean"},
        "matching_semantics": {"const": MATCHING_SEMANTICS},
        "character_position_semantics": {"const": CHARACTER_POSITION_SEMANTICS},
        "slices": {"type": "array", "items": _QUALITY_SLICE},
    },
)
ENRON_CONFORMANCE_OUTPUT_SCHEMA = _CONFORMANCE
_PERFORMANCE_STATS = _closed_object(
    (
        "sample_count",
        "median_seconds",
        "p95_seconds",
        "p99_seconds",
        "mad_seconds",
        "documents_per_second",
        "mib_per_second",
        "records_per_second",
        "seconds_per_document",
    ),
    {
        "sample_count": {"type": "integer", "minimum": 5, "maximum": MAX_SAFE_INTEGER},
        "median_seconds": _POSITIVE_NUMBER,
        "p95_seconds": _NONNEGATIVE_METRIC,
        "p99_seconds": _NONNEGATIVE_METRIC,
        "mad_seconds": _NONNEGATIVE_NUMBER,
        "documents_per_second": {"anyOf": [_POSITIVE_NUMBER, {"type": "null"}]},
        "mib_per_second": {"anyOf": [_POSITIVE_NUMBER, {"type": "null"}]},
        "records_per_second": _NONNEGATIVE_METRIC,
        "seconds_per_document": {"anyOf": [_POSITIVE_NUMBER, {"type": "null"}]},
    },
)
_PERFORMANCE_GENERATOR = _closed_object(
    ("id", "version", "source_sha256", "spec_sha256", "seed"),
    {
        "id": {"type": "string", "minLength": 1},
        "version": {"type": "string", "minLength": 1},
        "source_sha256": _HASH,
        "spec_sha256": _HASH,
        "seed": {"type": "string", "minLength": 1},
    },
)
_OPTIONAL_PERFORMANCE_GENERATOR = {"anyOf": [_PERFORMANCE_GENERATOR, {"type": "null"}]}
_PERFORMANCE_BANK_TAXON = _closed_object(
    ("entity_class", "entities", "canonical_names", "aliases", "literal_patterns", "regex_patterns"),
    {
        "entity_class": {"type": "string", "minLength": 1},
        "entities": _NONNEGATIVE_INTEGER,
        "canonical_names": _NONNEGATIVE_INTEGER,
        "aliases": _NONNEGATIVE_INTEGER,
        "literal_patterns": _NONNEGATIVE_INTEGER,
        "regex_patterns": _NONNEGATIVE_INTEGER,
    },
)
_PERFORMANCE_BANK_COMPOSITION = _closed_object(
    ("taxonomy",),
    {"taxonomy": {"type": "array", "minItems": 1, "items": _PERFORMANCE_BANK_TAXON}},
)
_PERFORMANCE_BANK = _closed_object(
    (
        "id",
        "kind",
        "bank_hash",
        "artifact",
        "generator",
        "composition",
        "descriptor_sha256",
        "active_entities",
        "active_names",
        "active_aliases",
        "active_patterns",
        "canonical_json_bytes",
        "native_source_bytes",
    ),
    {
        "id": {"type": "string", "minLength": 1},
        "kind": {"type": "string", "enum": ["evaluated_bank", "synthetic_scale"]},
        "bank_hash": _HASH,
        "artifact": _ARTIFACT_REF,
        "generator": _OPTIONAL_PERFORMANCE_GENERATOR,
        "composition": _PERFORMANCE_BANK_COMPOSITION,
        "descriptor_sha256": _HASH,
        "active_entities": _POSITIVE_INTEGER,
        "active_names": _POSITIVE_INTEGER,
        "active_aliases": _NONNEGATIVE_INTEGER,
        "active_patterns": _POSITIVE_INTEGER,
        "canonical_json_bytes": _POSITIVE_INTEGER,
        "native_source_bytes": _POSITIVE_INTEGER,
    },
)
_PERFORMANCE_LENGTH_DISTRIBUTION = _closed_object(
    ("minimum_bytes", "p50_bytes", "p95_bytes", "p99_bytes", "maximum_bytes", "mean_bytes"),
    {
        "minimum_bytes": _NONNEGATIVE_INTEGER,
        "p50_bytes": _NONNEGATIVE_INTEGER,
        "p95_bytes": _NONNEGATIVE_INTEGER,
        "p99_bytes": _NONNEGATIVE_INTEGER,
        "maximum_bytes": _NONNEGATIVE_INTEGER,
        "mean_bytes": _NONNEGATIVE_NUMBER,
    },
)
_PERFORMANCE_HIT_DISTRIBUTION = _closed_object(
    (
        "negative_documents",
        "documents_with_records",
        "minimum_records",
        "p50_records",
        "p95_records",
        "p99_records",
        "maximum_records",
        "mean_records",
    ),
    {
        "negative_documents": _NONNEGATIVE_INTEGER,
        "documents_with_records": _NONNEGATIVE_INTEGER,
        "minimum_records": _NONNEGATIVE_INTEGER,
        "p50_records": _NONNEGATIVE_INTEGER,
        "p95_records": _NONNEGATIVE_INTEGER,
        "p99_records": _NONNEGATIVE_INTEGER,
        "maximum_records": _NONNEGATIVE_INTEGER,
        "mean_records": _NONNEGATIVE_NUMBER,
    },
)
_PERFORMANCE_INPUT = _closed_object(
    (
        "id",
        "kind",
        "bank_id",
        "bank_hash",
        "artifact",
        "inventory_ref",
        "generator",
        "documents",
        "bytes",
        "records",
        "hit_density",
        "size_cohort",
        "document_length_distribution",
        "hit_distribution",
        "descriptor_sha256",
    ),
    {
        "id": {"type": "string", "minLength": 1},
        "kind": {"type": "string", "enum": ["real_input", "synthetic_input"]},
        "bank_id": {"type": "string", "minLength": 1},
        "bank_hash": _HASH,
        "artifact": _ARTIFACT_REF,
        "inventory_ref": _ARTIFACT_REF,
        "generator": _OPTIONAL_PERFORMANCE_GENERATOR,
        "documents": _POSITIVE_INTEGER,
        "bytes": _POSITIVE_INTEGER,
        "records": _NONNEGATIVE_INTEGER,
        "hit_density": {"type": "string", "enum": ["negative", "sparse", "normal", "dense"]},
        "size_cohort": {"type": "string", "enum": ["small", "medium", "large", "huge"]},
        "document_length_distribution": _PERFORMANCE_LENGTH_DISTRIBUTION,
        "hit_distribution": _PERFORMANCE_HIT_DISTRIBUTION,
        "descriptor_sha256": _HASH,
    },
)
_OPTIONAL_BASELINE_ID = {
    "anyOf": [{"type": "string", "minLength": 1}, {"type": "null"}],
}
_OPTIONAL_PERFORMANCE_ID = {
    "anyOf": [{"type": "string", "minLength": 1}, {"type": "null"}],
}
_OPTIONAL_HASH = {"anyOf": [_HASH, {"type": "null"}]}
_PERFORMANCE_HARNESS = _closed_object(
    (
        "id",
        "phase",
        "command_id",
        "source_sha256",
        "operation_spec_sha256",
        "source_artifact",
        "descriptor_sha256",
    ),
    {
        "id": {"type": "string", "minLength": 1},
        "phase": {"type": "string", "enum": list(PERFORMANCE_PHASES)},
        "command_id": {"type": "string", "minLength": 1},
        "source_sha256": _HASH,
        "operation_spec_sha256": _HASH,
        "source_artifact": _OPTIONAL_ARTIFACT_REF,
        "descriptor_sha256": _HASH,
    },
)
_PERFORMANCE_WORKLOAD = _closed_object(
    (
        "id",
        "phase",
        "promotion_gate",
        "decision_grade",
        "workload_sha256",
        "harness_id",
        "harness_sha256",
        "bank_id",
        "bank_hash",
        "input_id",
        "input_sha256",
        "baseline_id",
        "warmups",
        "sample_unit",
        "work_per_sample",
        "concurrency",
        "process_model",
        "median_method",
        "percentile_method",
        "samples_seconds",
        "samples_ref",
        "stats",
        "records_per_sample",
        "rss_samples_bytes",
        "peak_rss_bytes",
    ),
    {
        "id": {"type": "string", "minLength": 1},
        "phase": {"type": "string", "enum": list(PERFORMANCE_PHASES)},
        "promotion_gate": {"type": "boolean"},
        "decision_grade": {"type": "boolean"},
        "workload_sha256": _HASH,
        "harness_id": {"type": "string", "minLength": 1},
        "harness_sha256": _HASH,
        "bank_id": {"type": "string", "minLength": 1},
        "bank_hash": _HASH,
        "input_id": _OPTIONAL_PERFORMANCE_ID,
        "input_sha256": _OPTIONAL_HASH,
        "baseline_id": _OPTIONAL_BASELINE_ID,
        "warmups": _NONNEGATIVE_INTEGER,
        "sample_unit": {"type": "string", "enum": ["operation", "whole_input", "document"]},
        "work_per_sample": _POSITIVE_INTEGER,
        "concurrency": {"type": "integer", "minimum": 1, "maximum": 1024},
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
        "records_per_sample": {"anyOf": [_NONNEGATIVE_INTEGER, {"type": "null"}]},
        "rss_samples_bytes": {"type": "array", "items": _POSITIVE_INTEGER},
        "peak_rss_bytes": {"anyOf": [_POSITIVE_INTEGER, {"type": "null"}]},
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
_PERFORMANCE_BASELINE_CAPABILITIES = _closed_object(
    ("literal_patterns", "regex_patterns", "aliases", "canonical_mapping", "unicode"),
    {
        "literal_patterns": {"type": "boolean"},
        "regex_patterns": {"type": "boolean"},
        "aliases": {"type": "boolean"},
        "canonical_mapping": {"type": "boolean"},
        "unicode": {"type": "boolean"},
    },
)
_PERFORMANCE_BASELINE = _closed_object(
    ("id", "name", "version", "source_sha256", "capabilities", "semantic_equivalence", "descriptor_sha256"),
    {
        "id": {"type": "string", "minLength": 1},
        "name": {"type": "string", "minLength": 1},
        "version": {"type": "string", "minLength": 1},
        "source_sha256": _HASH,
        "capabilities": _PERFORMANCE_BASELINE_CAPABILITIES,
        "semantic_equivalence": {"type": "string", "enum": ["exact", "subset", "not_equivalent"]},
        "descriptor_sha256": _HASH,
    },
)
_PERFORMANCE_COMPARISON = _closed_object(
    (
        "id",
        "candidate_workload_id",
        "baseline_workload_id",
        "comparison_kind",
        "metric",
        "direction",
        "candidate_value",
        "baseline_value",
        "relative_degradation",
        "noise_multiplier",
        "noise_method",
        "noise_floor",
        "regression_tolerance",
        "result",
        "comparison_plan_sha256",
    ),
    {
        "id": {"type": "string", "minLength": 1},
        "candidate_workload_id": {"type": "string", "minLength": 1},
        "baseline_workload_id": {"type": "string", "minLength": 1},
        "comparison_kind": {"type": "string", "enum": ["same_path_stability", "cross_path_value"]},
        "metric": {
            "type": "string",
            "enum": [
                "median_seconds",
                "p95_seconds",
                "p99_seconds",
                "documents_per_second",
                "mib_per_second",
                "records_per_second",
                "seconds_per_document",
            ],
        },
        "direction": {"type": "string", "enum": ["lower_is_better", "higher_is_better"]},
        "candidate_value": _NONNEGATIVE_NUMBER,
        "baseline_value": _POSITIVE_NUMBER,
        "relative_degradation": _FINITE_NUMBER,
        "noise_multiplier": {"type": "number", "minimum": 1, "maximum": 5},
        "noise_method": {
            "type": "string",
            "enum": ["independent_mad", "paired_relative_mad", "paired_block_ratio_mad"],
        },
        "noise_floor": _NONNEGATIVE_NUMBER,
        "regression_tolerance": {"type": "number", "minimum": 0, "maximum": 0.1},
        "result": {"type": "string", "enum": ["improved", "equivalent_within_noise", "regressed"]},
        "comparison_plan_sha256": _HASH,
    },
)
_PERFORMANCE_VALUE_COMPONENT = _closed_object(
    (
        "id",
        "side",
        "application",
        "category",
        "source",
        "description",
        "workload_id",
        "assumption_sha256",
        "value",
    ),
    {
        "id": {"type": "string", "minLength": 1},
        "side": {"type": "string", "enum": ["candidate", "baseline"]},
        "application": {"type": "string", "enum": ["fixed", "per_unit"]},
        "category": {
            "type": "string",
            "enum": [
                "source_curation",
                "source_profiling",
                "bank_build",
                "cold_compile",
                "scan",
                "external_call",
                "labor",
                "hardware",
                "other",
            ],
        },
        "source": {
            "type": "string",
            "enum": [
                "workload_median_seconds",
                "workload_seconds_per_document",
                "workload_seconds_per_scan",
                "workload_seconds_per_mib",
                "workload_seconds_per_record",
                "declared_assumption",
            ],
        },
        "description": {"type": "string", "minLength": 1},
        "workload_id": _OPTIONAL_PERFORMANCE_ID,
        "assumption_sha256": _OPTIONAL_HASH,
        "value": _NONNEGATIVE_NUMBER,
    },
)
_PERFORMANCE_BREAKEVEN = _closed_object(
    (
        "id",
        "parameter_name",
        "parameter_unit",
        "value_unit",
        "minimum_units",
        "maximum_units",
        "components",
        "candidate_fixed_value",
        "baseline_fixed_value",
        "candidate_value_per_unit",
        "baseline_value_per_unit",
        "result",
        "breakeven_units",
        "model_plan_sha256",
    ),
    {
        "id": {"type": "string", "minLength": 1},
        "parameter_name": {"type": "string", "minLength": 1},
        "parameter_unit": {"type": "string", "enum": ["document", "scan", "mib", "record"]},
        "value_unit": {"type": "string", "enum": ["seconds", "usd"]},
        "minimum_units": _NONNEGATIVE_INTEGER,
        "maximum_units": _POSITIVE_INTEGER,
        "components": {"type": "array", "minItems": 4, "items": _PERFORMANCE_VALUE_COMPONENT},
        "candidate_fixed_value": _NONNEGATIVE_NUMBER,
        "baseline_fixed_value": _NONNEGATIVE_NUMBER,
        "candidate_value_per_unit": _NONNEGATIVE_NUMBER,
        "baseline_value_per_unit": _NONNEGATIVE_NUMBER,
        "result": {
            "type": "string",
            "enum": ["candidate_already_better", "finite_breakeven", "no_breakeven_within_range"],
        },
        "breakeven_units": {"anyOf": [_NONNEGATIVE_INTEGER, {"type": "null"}]},
        "model_plan_sha256": _HASH,
    },
)
_PERFORMANCE_OUTPUT = _closed_object(
    (
        "evaluated",
        "banks",
        "inputs",
        "harnesses",
        "workloads",
        "baselines",
        "comparisons",
        "breakeven_models",
    ),
    {
        "evaluated": {"type": "boolean"},
        "banks": {"type": "array", "items": _PERFORMANCE_BANK},
        "inputs": {"type": "array", "items": _PERFORMANCE_INPUT},
        "harnesses": {"type": "array", "items": _PERFORMANCE_HARNESS},
        "workloads": {"type": "array", "items": _PERFORMANCE_WORKLOAD},
        "baselines": {"type": "array", "items": _PERFORMANCE_BASELINE},
        "comparisons": {"type": "array", "items": _PERFORMANCE_COMPARISON},
        "breakeven_models": {"type": "array", "items": _PERFORMANCE_BREAKEVEN},
    },
)
ENRON_PERFORMANCE_OUTPUT_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://nerb.dev/schemas/enron-performance-output.v2.schema.json",
    "title": "NERB Enron benchmark v2 standalone performance output",
    **_PERFORMANCE_OUTPUT,
}
_FROZEN_TARGET = _closed_object(
    (
        "frozen_at",
        "manifest_sha256",
        "bank_hash",
        "evaluator_source_sha256",
        "split_manifest_sha256",
        "test_artifact_sha256",
        "thresholds_sha256",
        "performance_manifest_sha256",
        "git_commit",
    ),
    {
        "frozen_at": _TIMESTAMP,
        "manifest_sha256": _HASH,
        "bank_hash": _HASH,
        "evaluator_source_sha256": _HASH,
        "split_manifest_sha256": _HASH,
        "test_artifact_sha256": _HASH,
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
        "benchmark_version",
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
                "catalog_coverage",
                "cataloged_recall",
                "document_leak_rate",
                "cataloged_document_leak_rate",
                "sensitive_character_recall",
                "sensitive_character_leak_rate",
                "negative_document_false_alarm_rate",
                "over_redaction_rate",
                "direct_bank_scan_median_seconds",
                "direct_bank_scan_p95_seconds",
                "direct_bank_scan_p99_seconds",
                "direct_bank_scan_mib_per_second",
                "direct_bank_scan_records_per_second",
                "direct_bank_scan_seconds_per_document",
            ],
        },
        "value": _NONNEGATIVE_NUMBER,
        "label_strength": {"type": "string", "enum": list(LABEL_STRENGTHS)},
        "annotation_completeness": {"type": "string", "enum": list(ANNOTATION_COMPLETENESS)},
        "quality_slice_id": {"anyOf": [{"type": "string", "minLength": 1}, {"type": "null"}]},
        "performance_workload_id": {"anyOf": [{"type": "string", "minLength": 1}, {"type": "null"}]},
        "scope": _CLAIM_SCOPE,
        "benchmark_version": {"type": "string", "minLength": 1},
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
            "performance": _PERFORMANCE_OUTPUT,
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


def _apply_schema_resource_limits(schema: Any, field_name: str | None = None) -> None:
    """Add public size limits to every collection and string-bearing schema node."""
    if isinstance(schema, list):
        for item in schema:
            _apply_schema_resource_limits(item, field_name)
        return
    if not isinstance(schema, dict):
        return

    schema_type = schema.get("type")
    if schema_type == "array":
        schema.setdefault("maxItems", MAX_COLLECTION_ITEMS)
    elif schema_type == "object":
        schema.setdefault("maxProperties", MAX_COLLECTION_ITEMS)
    elif schema_type == "string":
        maximum = MAX_ID_CHARS if field_name == "id" or (field_name or "").endswith("_id") else MAX_STRING_CHARS
        schema["maxLength"] = min(int(schema.get("maxLength", maximum)), maximum)

    for key, item in schema.items():
        if key == "properties" and isinstance(item, dict):
            for property_name, property_schema in item.items():
                _apply_schema_resource_limits(property_schema, property_name)
        else:
            _apply_schema_resource_limits(item, field_name)


_apply_schema_resource_limits(ENRON_MANIFEST_SCHEMA)
_apply_schema_resource_limits(ENRON_EVIDENCE_SCHEMA)
_apply_schema_resource_limits(ENRON_QUALITY_OUTPUT_SCHEMA)
_apply_schema_resource_limits(ENRON_CONFORMANCE_OUTPUT_SCHEMA)
_apply_schema_resource_limits(ENRON_PERFORMANCE_OUTPUT_SCHEMA)

MANIFEST_VALIDATOR = EnronContractValidator(ENRON_MANIFEST_SCHEMA)
EVIDENCE_VALIDATOR = EnronContractValidator(ENRON_EVIDENCE_SCHEMA)
QUALITY_OUTPUT_VALIDATOR = EnronContractValidator(ENRON_QUALITY_OUTPUT_SCHEMA)
CONFORMANCE_OUTPUT_VALIDATOR = EnronContractValidator(ENRON_CONFORMANCE_OUTPUT_SCHEMA)
PERFORMANCE_OUTPUT_VALIDATOR = EnronContractValidator(ENRON_PERFORMANCE_OUTPUT_SCHEMA)
Draft202012Validator.check_schema(ENRON_MANIFEST_SCHEMA)
Draft202012Validator.check_schema(ENRON_EVIDENCE_SCHEMA)
Draft202012Validator.check_schema(ENRON_QUALITY_OUTPUT_SCHEMA)
Draft202012Validator.check_schema(ENRON_CONFORMANCE_OUTPUT_SCHEMA)
Draft202012Validator.check_schema(ENRON_PERFORMANCE_OUTPUT_SCHEMA)


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


def hash_enron_performance_inventory(inventory: Sequence[Mapping[str, int]]) -> str:
    normalized = _normalize_performance_inventory(inventory)
    if normalized is None:
        raise ValueError("Enron performance inventory rows require bounded nonnegative integer bytes and records.")
    return _canonical_hash(normalized)


def summarize_enron_performance_inventory(inventory: Sequence[Mapping[str, int]]) -> dict[str, Any]:
    """Return the canonical privacy-safe denominators and distributions for an input inventory."""
    normalized = _normalize_performance_inventory(inventory)
    if normalized is None:
        raise ValueError("Enron performance inventory rows require bounded nonnegative integer bytes and records.")
    return _performance_inventory_summary(normalized)


def calculate_enron_performance_statistics(
    samples: Sequence[float],
    input_descriptor: Mapping[str, Any] | None,
    *,
    phase: str,
    sample_unit: str,
    work_per_sample: int,
    records_per_sample: int | None = None,
) -> dict[str, float | int | None]:
    """Calculate workload statistics with the exact verifier percentile policy for a performance phase."""
    normalized = _normalize_samples(samples)
    if normalized is None or len(normalized) < 5:
        raise ValueError("Enron performance statistics require at least five finite, positive, bounded samples.")
    if phase not in PERFORMANCE_PHASES:
        raise ValueError(f"Unsupported Enron performance phase: {phase!r}.")
    if sample_unit not in {"operation", "whole_input", "document"}:
        raise ValueError(f"Unsupported Enron performance sample unit: {sample_unit!r}.")
    if type(work_per_sample) is not int or work_per_sample < 1:
        raise ValueError("Enron performance work_per_sample must be a positive integer.")
    if records_per_sample is not None and (type(records_per_sample) is not int or records_per_sample < 0):
        raise ValueError("Enron performance records_per_sample must be a nonnegative integer or null.")
    return _sample_statistics(
        normalized,
        input_descriptor,
        phase,
        sample_unit,
        work_per_sample,
        records_per_sample=records_per_sample,
    )


def calculate_enron_performance_comparison(
    candidate_statistics: Mapping[str, Any],
    baseline_statistics: Mapping[str, Any],
    *,
    metric: str,
    noise_multiplier: float,
    regression_tolerance: float,
    noise_method: str = "independent_mad",
    candidate_samples: Sequence[float] | None = None,
    baseline_samples: Sequence[float] | None = None,
) -> dict[str, float | str]:
    """Calculate the verifier's noise-aware comparison outputs from two raw-sample statistic sets."""
    lower_is_better = {"median_seconds", "p95_seconds", "p99_seconds", "seconds_per_document"}
    supported_metrics = lower_is_better | {"documents_per_second", "mib_per_second", "records_per_second"}
    if metric not in supported_metrics:
        raise ValueError(f"Unsupported Enron performance comparison metric: {metric!r}.")
    numeric_values = {
        "candidate_value": candidate_statistics.get(metric),
        "baseline_value": baseline_statistics.get(metric),
        "candidate_median": candidate_statistics.get("median_seconds"),
        "baseline_median": baseline_statistics.get("median_seconds"),
        "candidate_mad": candidate_statistics.get("mad_seconds"),
        "baseline_mad": baseline_statistics.get("mad_seconds"),
        "noise_multiplier": noise_multiplier,
        "regression_tolerance": regression_tolerance,
    }
    parsed_values: dict[str, float] = {}
    for name, value in numeric_values.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("Enron performance comparisons require finite numeric statistics and policy values.")
        try:
            parsed = float(value)
        except (OverflowError, TypeError, ValueError) as exc:
            raise ValueError(
                "Enron performance comparisons require finite numeric statistics and policy values."
            ) from exc
        if not math.isfinite(parsed) or abs(parsed) > MAX_FINITE_CONTRACT_NUMBER:
            raise ValueError("Enron performance comparisons require finite numeric statistics and policy values.")
        parsed_values[name] = parsed
    candidate_value = parsed_values["candidate_value"]
    baseline_value = parsed_values["baseline_value"]
    candidate_median = parsed_values["candidate_median"]
    baseline_median = parsed_values["baseline_median"]
    candidate_mad = parsed_values["candidate_mad"]
    baseline_mad = parsed_values["baseline_mad"]
    if (
        candidate_value < 0
        or baseline_value <= 0
        or candidate_median <= 0
        or baseline_median <= 0
        or candidate_mad < 0
        or baseline_mad < 0
        or not 1 <= noise_multiplier <= 5
        or not 0 <= regression_tolerance <= 0.1
    ):
        raise ValueError("Enron performance comparison statistics or policy values are outside supported bounds.")
    direction = "lower_is_better" if metric in lower_is_better else "higher_is_better"
    relative_degradation = (
        (candidate_value - baseline_value) / baseline_value
        if direction == "lower_is_better"
        else (baseline_value - candidate_value) / baseline_value
    )
    if noise_method == "independent_mad":
        if candidate_samples is not None or baseline_samples is not None:
            raise ValueError("Independent-MAD comparisons do not accept paired raw samples.")
        noise_floor = max(candidate_mad / candidate_median, baseline_mad / baseline_median) * noise_multiplier
    elif noise_method == "paired_relative_mad":
        normalized_candidate = _normalize_samples(candidate_samples) if candidate_samples is not None else None
        normalized_baseline = _normalize_samples(baseline_samples) if baseline_samples is not None else None
        if (
            metric not in lower_is_better
            or normalized_candidate is None
            or normalized_baseline is None
            or len(normalized_candidate) < 5
            or len(normalized_candidate) != len(normalized_baseline)
        ):
            raise ValueError("Paired-relative-MAD comparisons require aligned positive timing samples.")
        paired_relative = [
            (candidate - baseline) / baseline
            for candidate, baseline in zip(normalized_candidate, normalized_baseline, strict=True)
        ]
        paired_center = float(median(paired_relative))
        paired_mad = float(median(abs(value - paired_center) for value in paired_relative))
        noise_floor = paired_mad * noise_multiplier
    elif noise_method == "paired_block_ratio_mad":
        normalized_candidate = _normalize_samples(candidate_samples) if candidate_samples is not None else None
        normalized_baseline = _normalize_samples(baseline_samples) if baseline_samples is not None else None
        if (
            normalized_candidate is None
            or normalized_baseline is None
            or len(normalized_candidate) < 5
            or len(normalized_candidate) != len(normalized_baseline)
        ):
            raise ValueError("Paired-block-ratio-MAD comparisons require aligned positive timing samples.")
        paired_ratios = [
            candidate / baseline for candidate, baseline in zip(normalized_candidate, normalized_baseline, strict=True)
        ]
        paired_center = float(median(paired_ratios))
        paired_mad = float(median(abs(value - paired_center) for value in paired_ratios))
        noise_floor = (paired_mad / paired_center) * noise_multiplier
        if not math.isfinite(noise_floor) or noise_floor > MAX_FINITE_CONTRACT_NUMBER:
            raise ValueError("Paired-block-ratio-MAD comparison dispersion is outside supported bounds.")
    else:
        raise ValueError("Unsupported Enron performance comparison noise method.")
    boundary = noise_floor + regression_tolerance
    result = (
        "regressed"
        if relative_degradation > boundary
        else "improved"
        if relative_degradation < -boundary
        else "equivalent_within_noise"
    )
    return {
        "direction": direction,
        "candidate_value": candidate_value,
        "baseline_value": baseline_value,
        "relative_degradation": relative_degradation,
        "noise_floor": noise_floor,
        "result": result,
    }


def calculate_enron_breakeven(
    candidate_fixed_value: float,
    baseline_fixed_value: float,
    candidate_value_per_unit: float,
    baseline_value_per_unit: float,
    *,
    minimum_units: int,
    maximum_units: int,
) -> dict[str, int | str | None]:
    """Calculate the verifier's bounded additive breakeven result."""
    values = (
        candidate_fixed_value,
        baseline_fixed_value,
        candidate_value_per_unit,
        baseline_value_per_unit,
    )
    normalized_values: list[float] = []
    for value in values:
        if type(value) not in (int, float):
            raise ValueError("Enron breakeven inputs must be finite, nonnegative, and bounded.")
        try:
            normalized = float(value)
        except (OverflowError, TypeError, ValueError) as exc:
            raise ValueError("Enron breakeven inputs must be finite, nonnegative, and bounded.") from exc
        if not math.isfinite(normalized) or normalized < 0 or normalized > MAX_FINITE_CONTRACT_NUMBER:
            raise ValueError("Enron breakeven inputs must be finite, nonnegative, and bounded.")
        normalized_values.append(normalized)
    if (
        type(minimum_units) is not int
        or type(maximum_units) is not int
        or minimum_units < 0
        or maximum_units < 1
        or minimum_units > maximum_units
        or maximum_units > MAX_SAFE_INTEGER
    ):
        raise ValueError("Enron breakeven unit bounds must be ordered nonnegative integers.")
    normalized_candidate_fixed, normalized_baseline_fixed, normalized_candidate_unit, normalized_baseline_unit = (
        normalized_values
    )
    result = _breakeven_result(
        normalized_candidate_fixed,
        normalized_baseline_fixed,
        normalized_candidate_unit,
        normalized_baseline_unit,
        minimum_units,
        maximum_units,
    )
    if result is None:
        raise ValueError("Enron breakeven inputs must be finite, nonnegative, and bounded.")
    outcome, units = result
    return {"result": outcome, "breakeven_units": units}


def hash_enron_performance_bank(bank: Mapping[str, Any]) -> str:
    return _canonical_hash({key: value for key, value in bank.items() if key != "descriptor_sha256"})


def hash_enron_performance_input(input_descriptor: Mapping[str, Any]) -> str:
    return _canonical_hash({key: value for key, value in input_descriptor.items() if key != "descriptor_sha256"})


def hash_enron_performance_harness(harness: Mapping[str, Any]) -> str:
    return _canonical_hash({key: value for key, value in harness.items() if key != "descriptor_sha256"})


def hash_enron_performance_baseline(baseline: Mapping[str, Any]) -> str:
    return _canonical_hash({key: value for key, value in baseline.items() if key != "descriptor_sha256"})


def hash_enron_performance_comparison_plan(comparison: Mapping[str, Any]) -> str:
    plan_fields = (
        "id",
        "candidate_workload_id",
        "baseline_workload_id",
        "comparison_kind",
        "metric",
        "direction",
        "noise_multiplier",
        "noise_method",
        "regression_tolerance",
    )
    return _canonical_hash({field: comparison[field] for field in plan_fields})


def hash_enron_breakeven_plan(model: Mapping[str, Any]) -> str:
    plan_fields = (
        "id",
        "parameter_name",
        "parameter_unit",
        "value_unit",
        "minimum_units",
        "maximum_units",
    )
    component_fields = (
        "id",
        "side",
        "application",
        "category",
        "source",
        "description",
        "workload_id",
        "assumption_sha256",
    )
    components = []
    for component in sorted(model["components"], key=lambda item: str(item["id"])):
        plan = {field: component[field] for field in component_fields}
        if component["source"] == "declared_assumption":
            plan["value"] = component["value"]
        components.append(plan)
    return _canonical_hash({**{field: model[field] for field in plan_fields}, "components": components})


def hash_enron_workload(workload: Mapping[str, Any]) -> str:
    fields = (
        "id",
        "phase",
        "promotion_gate",
        "decision_grade",
        "harness_id",
        "harness_sha256",
        "bank_id",
        "bank_hash",
        "input_id",
        "input_sha256",
        "baseline_id",
        "warmups",
        "sample_unit",
        "work_per_sample",
        "concurrency",
        "process_model",
        "median_method",
        "percentile_method",
    )
    return _canonical_hash({field: workload[field] for field in fields})


def hash_enron_performance_manifest(performance: Mapping[str, Any]) -> str:
    banks = [
        {"id": item["id"], "descriptor_sha256": hash_enron_performance_bank(item)}
        for item in sorted(performance["banks"], key=lambda value: str(value["id"]))
    ]
    inputs = [
        {"id": item["id"], "descriptor_sha256": hash_enron_performance_input(item)}
        for item in sorted(performance["inputs"], key=lambda value: str(value["id"]))
    ]
    harnesses = [
        {"id": item["id"], "descriptor_sha256": hash_enron_performance_harness(item)}
        for item in sorted(performance["harnesses"], key=lambda value: str(value["id"]))
    ]
    workloads = [
        {"id": item["id"], "workload_sha256": hash_enron_workload(item)}
        for item in sorted(performance["workloads"], key=lambda value: str(value["id"]))
    ]
    baselines = [
        {"id": item["id"], "descriptor_sha256": hash_enron_performance_baseline(item)}
        for item in sorted(performance["baselines"], key=lambda value: str(value["id"]))
    ]
    comparisons = [
        {"id": item["id"], "comparison_plan_sha256": hash_enron_performance_comparison_plan(item)}
        for item in sorted(performance["comparisons"], key=lambda value: str(value["id"]))
    ]
    breakeven_models = [
        {"id": item["id"], "model_plan_sha256": hash_enron_breakeven_plan(item)}
        for item in sorted(performance["breakeven_models"], key=lambda value: str(value["id"]))
    ]
    return _canonical_hash(
        {
            "banks": banks,
            "inputs": inputs,
            "harnesses": harnesses,
            "workloads": workloads,
            "baselines": baselines,
            "comparisons": comparisons,
            "breakeven_models": breakeven_models,
        }
    )


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


def validate_enron_performance_output(performance: Any) -> dict[str, Any]:
    """Validate the closed standalone performance shape without evidence-context semantic bindings."""

    diagnostics = _structure_diagnostics(performance)
    if diagnostics:
        return _result(diagnostics)
    return _result(_schema_diagnostics(PERFORMANCE_OUTPUT_VALIDATOR, performance))


def validate_enron_quality_output(quality: Any) -> dict[str, Any]:
    """Validate a standalone quality executor projection and recompute every metric."""

    diagnostics = _structure_diagnostics(quality)
    if diagnostics:
        return _result(diagnostics)
    diagnostics = _schema_diagnostics(QUALITY_OUTPUT_VALIDATOR, quality)
    if not diagnostics and isinstance(quality, Mapping):
        diagnostics.extend(_quality_diagnostics(quality, manifest=None))
    return _result(diagnostics)


def validate_enron_conformance_output(conformance: Any, *, active_patterns: int) -> dict[str, Any]:
    """Validate a standalone catalog-conformance projection against its active bank size."""

    diagnostics = _structure_diagnostics(conformance)
    if diagnostics:
        return _result(diagnostics)
    diagnostics = _schema_diagnostics(CONFORMANCE_OUTPUT_VALIDATOR, conformance)
    if type(active_patterns) is not int or active_patterns < 0 or active_patterns > MAX_SAFE_INTEGER:
        diagnostics.append(
            _error(
                "contract.invalid_active_pattern_count",
                "/active_patterns",
                "Standalone conformance validation requires a bounded nonnegative active-pattern count.",
            )
        )
    elif not diagnostics and isinstance(conformance, Mapping):
        diagnostics.extend(_conformance_diagnostics(conformance, {"active_patterns": active_patterns}, manifest=None))
    return _result(diagnostics)


def validate_enron_manifest(manifest: Any) -> dict[str, Any]:
    """Validate manifest structure, split integrity, provenance, and public serialization safety."""
    diagnostics = _structure_diagnostics(manifest)
    if diagnostics:
        return _result(diagnostics)
    diagnostics = _schema_diagnostics(MANIFEST_VALIDATOR, manifest)
    if not diagnostics and isinstance(manifest, Mapping):
        diagnostics.extend(_manifest_diagnostics(manifest))
        diagnostics.extend(_privacy_diagnostics(manifest["privacy"], "/privacy"))
        diagnostics.extend(_command_diagnostics(manifest["commands"], "/commands"))
        diagnostics.extend(_public_serialization_diagnostics(manifest))
        if manifest["artifact_kind"] == "real_benchmark":
            diagnostics.extend(_placeholder_hash_diagnostics(manifest))
    return _result(diagnostics)


def validate_enron_evidence(
    evidence: Any,
    *,
    manifest: Mapping[str, Any] | None = None,
    trusted_lineage_prefix: Sequence[Mapping[str, Any]] | None = None,
    referenced_samples: Mapping[str, Sequence[float]] | None = None,
    referenced_input_inventories: Mapping[str, Sequence[Mapping[str, int]]] | None = None,
) -> dict[str, Any]:
    """Validate evidence and recompute its privacy, claim, lineage, gate, and performance semantics."""
    diagnostics = _structure_diagnostics(evidence)
    if diagnostics:
        return _result(diagnostics)
    diagnostics = _schema_diagnostics(EVIDENCE_VALIDATOR, evidence)
    if diagnostics or not isinstance(evidence, Mapping):
        return _result(diagnostics)

    quality = evidence["quality"]
    conformance = evidence["catalog_conformance"]
    performance = evidence["performance"]
    promotion = evidence["promotion"]
    recomputed_performance_stats: dict[str, Mapping[str, Any]] = {}
    sample_resolver = referenced_samples if _is_external_resolver(referenced_samples) else None
    inventory_resolver = referenced_input_inventories if _is_external_resolver(referenced_input_inventories) else None
    if referenced_samples is not None and sample_resolver is None:
        diagnostics.append(
            _error(
                "contract.performance_sample_resolver_shape",
                "/performance/workloads",
                "Referenced sample resolver must be a mapping of artifact ids to bounded sample sequences.",
            )
        )
    if referenced_input_inventories is not None and inventory_resolver is None:
        diagnostics.append(
            _error(
                "contract.performance_inventory_resolver_shape",
                "/performance/inputs",
                "Referenced inventory resolver must be a mapping of artifact ids to bounded inventory sequences.",
            )
        )
    diagnostics.extend(_privacy_diagnostics(evidence["privacy"], "/privacy"))
    diagnostics.extend(_command_diagnostics(evidence["commands"], "/commands"))
    diagnostics.extend(_public_serialization_diagnostics(evidence))
    if evidence["artifact_kind"] == "real_benchmark":
        diagnostics.extend(_placeholder_hash_diagnostics(evidence))
    diagnostics.extend(_evidence_provenance_diagnostics(evidence))
    diagnostics.extend(_quality_diagnostics(quality, manifest=manifest))
    diagnostics.extend(_conformance_diagnostics(conformance, evidence["bank"], manifest=manifest))
    diagnostics.extend(
        _test_access_diagnostics(evidence, manifest=manifest, trusted_lineage_prefix=trusted_lineage_prefix)
    )
    diagnostics.extend(
        _performance_diagnostics(
            performance,
            evidence["bank"],
            evidence["source"],
            evidence["splits"],
            evidence["commands"],
            sample_resolver,
            inventory_resolver,
            recomputed_performance_stats,
            promotion_passed=promotion["passed"] or evidence["verifier"]["passed"],
        )
    )
    diagnostics.extend(_gate_diagnostics(evidence, recomputed_performance_stats))
    diagnostics.extend(_promotion_diagnostics(evidence, recomputed_performance_stats))
    if promotion["passed"] or evidence["verifier"]["passed"]:
        diagnostics.extend(_decision_grade_diagnostics(evidence, manifest))
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


def _is_external_resolver(value: Any) -> bool:
    return (
        type(value) is dict
        and len(value) <= MAX_COLLECTION_ITEMS
        and all(type(key) is str and len(key) <= MAX_STRING_CHARS for key in value)
    )


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
    referenced_input_inventories: Mapping[str, Sequence[Mapping[str, int]]] | None = None,
) -> dict[str, Any]:
    """Securely load and semantically validate one benchmark-v2 evidence JSON object."""
    value = _load_contract_json(path)
    result = validate_enron_evidence(
        value,
        manifest=manifest,
        trusted_lineage_prefix=trusted_lineage_prefix,
        referenced_samples=referenced_samples,
        referenced_input_inventories=referenced_input_inventories,
    )
    if not result["valid"]:
        raise ValueError(f"Invalid Enron v2 evidence: {result['diagnostics'][0]['message']}")
    return value


def _manifest_diagnostics(manifest: Mapping[str, Any]) -> list[Diagnostic]:
    diagnostics = _timestamp_diagnostics(manifest["created_at"], "/created_at")
    diagnostics.extend(_split_diagnostics(manifest["source"], manifest["preparation"], manifest["splits"], "/splits"))
    diagnostics.extend(_duplicate_id_diagnostics(manifest["commands"], "/commands", "command"))
    diagnostics.extend(_duplicate_id_diagnostics(manifest["labels"], "/labels", "label artifact"))
    text_views = manifest["preparation"]["text_views"]
    diagnostics.extend(_duplicate_id_diagnostics(text_views, "/preparation/text_views", "prepared text view"))
    primary_views = [item for item in text_views if item["primary_for_quality"]]
    if len(primary_views) != 1:
        diagnostics.append(
            _error(
                "contract.primary_quality_view",
                "/preparation/text_views",
                "Preparation must designate exactly one primary natural-content quality view.",
            )
        )
    diagnostics.extend(_duplicate_id_diagnostics(manifest["quality_plan"], "/quality_plan", "quality-plan slice"))
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
        annotation_provenance = label["annotation_provenance"]
        populations = label["role_populations"]
        population_roles = [str(item["role"]) for item in populations]
        if len(population_roles) != len(set(population_roles)):
            diagnostics.append(
                _error(
                    "contract.duplicate_label_population_role",
                    f"{path}/role_populations",
                    "A label artifact may declare at most one population per split role.",
                )
            )
        if set(population_roles) != set(label["roles"]):
            diagnostics.append(
                _error(
                    "contract.label_population_roles",
                    f"{path}/role_populations",
                    "Label population roles must exactly equal the artifact's declared roles.",
                )
            )
        if sum(int(item["spans"]) for item in populations) != label["span_count"]:
            diagnostics.append(
                _error(
                    "contract.label_population_spans",
                    f"{path}/span_count",
                    "Label span count must equal the sum of its per-role populations.",
                )
            )
        for population_index, population in enumerate(populations):
            role = str(population["role"])
            if role != "conformance" and population["documents"] > manifest["splits"]["roles"][role]["records"]:
                diagnostics.append(
                    _error(
                        "contract.label_population_bounds",
                        f"{path}/role_populations/{population_index}/documents",
                        "Label population documents cannot exceed the bound split artifact record count.",
                    )
                )
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
        if strength == "synthetic_conformance" and label["roles"] != ["conformance"]:
            diagnostics.append(
                _error(
                    "contract.conformance_label_role",
                    f"{path}/roles",
                    "Synthetic conformance labels must use the dedicated non-corpus conformance role.",
                )
            )
        if strength != "synthetic_conformance" and "conformance" in label["roles"]:
            diagnostics.append(
                _error(
                    "contract.natural_label_role",
                    f"{path}/roles",
                    "Natural-text labels cannot use the synthetic conformance role.",
                )
            )
        if strength in {"independent", "structured_weak"} and len(label["annotation_scope"]["entity_classes"]) != 1:
            diagnostics.append(
                _error(
                    "contract.natural_label_entity_population",
                    f"{path}/annotation_scope/entity_classes",
                    "Each natural-text label artifact must expose one entity class so its populations are exact.",
                )
            )
        review_is_separate = (
            annotation_provenance["reviewer_id"] is not None
            and annotation_provenance["reviewer_id"] != annotation_provenance["producer_id"]
            and annotation_provenance["adjudication_artifact"] is not None
        )
        if annotation_provenance["independently_reviewed"] != review_is_separate:
            diagnostics.append(
                _error(
                    "contract.annotation_review_provenance",
                    f"{path}/annotation_provenance",
                    "Independent review requires distinct producer/reviewer ids and adjudication evidence.",
                )
            )
        if strength in {"independent", "synthetic_conformance"} and not review_is_separate:
            diagnostics.append(
                _error(
                    "contract.annotation_independence",
                    f"{path}/annotation_provenance",
                    "Independent and conformance labels require separately reviewed annotation provenance.",
                )
            )
    diagnostics.extend(_manifest_quality_plan_diagnostics(manifest))
    diagnostics.extend(_manifest_conformance_plan_diagnostics(manifest))
    diagnostics.extend(_bank_provenance_diagnostics(manifest["bank"], "/bank"))
    return diagnostics


def _manifest_quality_plan_diagnostics(manifest: Mapping[str, Any]) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    labels = {str(item["id"]): item for item in manifest["labels"]}
    text_views = {str(item["id"]): item for item in manifest["preparation"]["text_views"]}
    primary_views = [item for item in text_views.values() if item["primary_for_quality"]]
    primary_view = primary_views[0] if len(primary_views) == 1 else None
    descriptor_keys: set[tuple[str, str, str, str, str]] = set()
    planned_label_ids: set[str] = set()
    for index, item in enumerate(manifest["quality_plan"]):
        path = f"/quality_plan/{index}"
        label_id = str(item["label_artifact_id"])
        label = labels.get(label_id)
        text_view = text_views.get(str(item["text_view"]))
        key = (
            label_id,
            str(item["split_role"]),
            str(item["entity_class"]),
            str(item["cohort"]),
            str(item["text_view"]),
        )
        if key in descriptor_keys:
            diagnostics.append(
                _error(
                    "contract.duplicate_quality_plan_descriptor",
                    path,
                    "Quality-plan descriptors must be unique beyond their public IDs.",
                )
            )
        descriptor_keys.add(key)
        if label is None:
            diagnostics.append(
                _error(
                    "contract.unknown_quality_plan_label",
                    f"{path}/label_artifact_id",
                    "Quality plan references an undeclared label artifact.",
                )
            )
        else:
            planned_label_ids.add(label_id)
            if item["split_role"] not in label["roles"]:
                diagnostics.append(
                    _error(
                        "contract.quality_plan_label_role",
                        f"{path}/split_role",
                        "Quality-plan split role is outside the bound label population.",
                    )
                )
            if item["entity_class"] not in label["annotation_scope"]["entity_classes"]:
                diagnostics.append(
                    _error(
                        "contract.quality_plan_entity_class",
                        f"{path}/entity_class",
                        "Quality-plan entity class is outside the bound annotation scope.",
                    )
                )
            populations = {str(population["role"]): population for population in label["role_populations"]}
            population = populations.get(str(item["split_role"]))
            if (
                population is None
                or item["documents"] > population["documents"]
                or item["gold_spans"] > population["spans"]
            ):
                diagnostics.append(
                    _error(
                        "contract.quality_plan_population_bounds",
                        path,
                        "Frozen quality denominators must fit the bound role-specific label population.",
                    )
                )
            elif item["cohort"] == "all" and (
                item["documents"] != population["documents"] or item["gold_spans"] != population["spans"]
            ):
                diagnostics.append(
                    _error(
                        "contract.quality_plan_population_exactness",
                        path,
                        "An all-document quality plan must equal its complete bound label population.",
                    )
                )
        open_world_eligible = (
            label is not None
            and label["label_strength"] == "independent"
            and label["annotation_completeness"] == "exhaustive_within_scope"
        )
        invalid_denominators = (
            item["documents_with_sensitive_gold"] > item["documents"]
            or item["cataloged_gold_spans"] > item["gold_spans"]
            or item["documents_with_cataloged_gold"] > item["documents_with_sensitive_gold"]
            or (item["gold_spans"] == 0) != (item["documents_with_sensitive_gold"] == 0)
            or (item["cataloged_gold_spans"] == 0) != (item["documents_with_cataloged_gold"] == 0)
        )
        if open_world_eligible:
            invalid_denominators = invalid_denominators or (
                item["documents_with_sensitive_gold"] + item["negative_documents"] != item["documents"]
                or item["sensitive_gold_characters"] > item["evaluated_characters"]
                or (item["gold_spans"] == 0) != (item["sensitive_gold_characters"] == 0)
            )
        else:
            invalid_denominators = invalid_denominators or any(
                item[field] != 0
                for field in ("negative_documents", "sensitive_gold_characters", "evaluated_characters")
            )
        if invalid_denominators:
            diagnostics.append(
                _error(
                    "contract.quality_plan_denominators",
                    path,
                    "Frozen quality document, span, and character denominators are internally inconsistent.",
                )
            )
        if text_view is None:
            diagnostics.append(
                _error(
                    "contract.unknown_quality_text_view",
                    f"{path}/text_view",
                    "Quality plan references an undeclared prepared text view.",
                )
            )
        elif label is not None and not set(label["annotation_scope"]["document_regions"]) <= set(
            text_view["document_regions"]
        ):
            diagnostics.append(
                _error(
                    "contract.quality_view_regions",
                    f"{path}/text_view",
                    "Prepared text view does not contain every region in the bound annotation scope.",
                )
            )
        if item["promotion_gate"] and label is not None and primary_view is not None:
            annotation_scope = label["annotation_scope"]
            if (
                set(annotation_scope["document_regions"]) != set(primary_view["document_regions"])
                or annotation_scope["exclusions"]
            ):
                diagnostics.append(
                    _error(
                        "contract.quality_gate_annotation_scope",
                        f"{path}/label_artifact_id",
                        "A quality-plan gate must annotate every region in the exact primary view without exclusions.",
                    )
                )
        if item["promotion_gate"] and (
            label is None
            or label["label_strength"] != "independent"
            or label["annotation_completeness"] != "exhaustive_within_scope"
            or item["split_role"] != "test"
            or item["cohort"] != "all"
            or text_view is None
            or not text_view["primary_for_quality"]
        ):
            diagnostics.append(
                _error(
                    "contract.invalid_quality_plan_gate",
                    f"{path}/promotion_gate",
                    "A quality-plan gate must cover the all-document independent exhaustive primary final-test view.",
                )
            )
        if item["promotion_gate"] and label is not None:
            populations = {str(population["role"]): population for population in label["role_populations"]}
            population = populations.get("test")
            if (
                population is None
                or population["documents"] != manifest["splits"]["roles"]["test"]["records"]
                or item["documents"] != manifest["splits"]["roles"]["test"]["records"]
            ):
                diagnostics.append(
                    _error(
                        "contract.quality_gate_test_population",
                        f"{path}/label_artifact_id",
                        "A quality-plan gate must label every document in the bound final-test split artifact.",
                    )
                )
            if (
                item["documents"] < MIN_DECISION_GRADE_DOCUMENTS
                or item["gold_spans"] < MIN_DECISION_GRADE_GOLD_SPANS
                or item["negative_documents"] < MIN_DECISION_GRADE_NEGATIVE_DOCUMENTS
                or item["sensitive_gold_characters"] < MIN_DECISION_GRADE_SENSITIVE_CHARACTERS
            ):
                diagnostics.append(
                    _error(
                        "contract.quality_gate_minimum_support",
                        path,
                        "A quality-plan gate lacks the minimum frozen document, span, negative, or character support.",
                    )
                )
    expected_planned_labels = {
        str(item["id"]) for item in manifest["labels"] if item["label_strength"] in {"independent", "structured_weak"}
    }
    if planned_label_ids != expected_planned_labels:
        diagnostics.append(
            _error(
                "contract.quality_plan_label_set",
                "/quality_plan",
                "Quality plan must cover every natural-text labeled artifact and no other label kind.",
            )
        )
    return diagnostics


def _manifest_conformance_plan_diagnostics(manifest: Mapping[str, Any]) -> list[Diagnostic]:
    plan = manifest["conformance_plan"]
    labels = {str(item["id"]): item for item in manifest["labels"]}
    label = labels.get(str(plan["label_artifact_id"]))
    diagnostics: list[Diagnostic] = []
    if (
        label is None
        or label["label_strength"] != "synthetic_conformance"
        or label["annotation_completeness"] != "exhaustive_within_scope"
        or label["artifact"] != plan["positive_cases_artifact"]
        or label["span_count"] != plan["positive_cases"]
    ):
        diagnostics.append(
            _error(
                "contract.conformance_plan_label_binding",
                "/conformance_plan/label_artifact_id",
                "Conformance plan must exactly bind its exhaustive synthetic positive-case label artifact.",
            )
        )
    if plan["positive_cases"] < manifest["bank"]["active_patterns"]:
        diagnostics.append(
            _error(
                "contract.conformance_plan_support",
                "/conformance_plan/positive_cases",
                "Conformance plan requires at least one approved positive case per active pattern.",
            )
        )
    positive = plan["positive_cases_artifact"]
    negative = plan["negative_cases_artifact"]
    if positive["id"] == negative["id"] or positive["sha256"] == negative["sha256"]:
        diagnostics.append(
            _error(
                "contract.conformance_plan_artifact_overlap",
                "/conformance_plan",
                "Positive and negative conformance cases must be distinct content-addressed artifacts.",
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
        evidence["promotion"]["passed"] or evidence["verifier"]["passed"] or bool(evidence["promotion"]["claims"])
    ):
        diagnostics.append(
            _error(
                "contract.synthetic_fixture_claim",
                "/artifact_kind",
                "Synthetic fixtures cannot carry claims, pass verification, or be promoted.",
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
    diagnostics.extend(_bank_provenance_diagnostics(evidence["bank"], "/bank"))
    return diagnostics


def _bank_provenance_diagnostics(bank: Mapping[str, Any], path: str) -> list[Diagnostic]:
    if bank["active_aliases"] > bank["active_names"]:
        return [
            _error(
                "contract.bank_alias_bounds",
                f"{path}/active_aliases",
                "Active aliases cannot exceed all active canonical names plus aliases.",
            )
        ]
    return []


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
    role_artifact_ids: list[str] = []
    role_artifact_hashes: list[str] = []
    for role, value in splits["roles"].items():
        role_records += value["records"]
        role_artifact_ids.append(str(value["artifact"]["id"]))
        role_artifact_hashes.append(str(value["artifact"]["sha256"]))
        if value["groups"] > value["records"]:
            diagnostics.append(
                _error(
                    "contract.split_group_bounds",
                    f"{path}/roles/{role}/groups",
                    "Split groups cannot exceed split records.",
                )
            )
    if len(set(role_artifact_ids)) != len(role_artifact_ids) or len(set(role_artifact_hashes)) != len(
        role_artifact_hashes
    ):
        diagnostics.append(
            _error(
                "contract.split_artifact_overlap",
                f"{path}/roles",
                "Train, validation, and sealed-test roles must bind distinct content-addressed artifacts.",
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
    quality_plan: dict[str, Mapping[str, Any]] = {}
    if manifest is not None and validate_enron_manifest(manifest)["valid"]:
        labels = {str(item["id"]): item for item in manifest["labels"]}
        quality_plan = {str(item["id"]): item for item in manifest["quality_plan"]}
        if [str(item["id"]) for item in slices] != [str(item["id"]) for item in manifest["quality_plan"]]:
            diagnostics.append(
                _error(
                    "contract.quality_plan_order",
                    "/quality/slices",
                    "Quality evidence must preserve the exact frozen manifest plan order and membership.",
                )
            )
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
        planned = quality_plan.get(str(item["id"]))
        if quality_plan and planned is None:
            diagnostics.append(
                _error(
                    "contract.unknown_quality_plan_slice",
                    f"{path}/id",
                    "Quality evidence does not reference a frozen manifest quality-plan descriptor.",
                )
            )
        elif planned is not None:
            planned_fields = (
                "label_artifact_id",
                "split_role",
                "entity_class",
                "cohort",
                "text_view",
                "promotion_gate",
                "documents",
                "documents_with_sensitive_gold",
                "negative_documents",
                "gold_spans",
                "cataloged_gold_spans",
                "documents_with_cataloged_gold",
                "sensitive_gold_characters",
                "evaluated_characters",
            )
            if any(item[field] != planned[field] for field in planned_fields):
                diagnostics.append(
                    _error(
                        "contract.quality_plan_binding",
                        path,
                        "Quality evidence differs from its frozen manifest slice descriptor.",
                    )
                )
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
            populations = {str(population["role"]): population for population in label["role_populations"]}
            population = populations.get(str(item["split_role"]))
            if population is None:
                diagnostics.append(
                    _error(
                        "contract.missing_label_population",
                        f"{path}/split_role",
                        "Quality slice has no bound label population for its split role.",
                    )
                )
            else:
                if item["documents"] > population["documents"] or item["gold_spans"] > population["spans"]:
                    diagnostics.append(
                        _error(
                            "contract.quality_population_bounds",
                            path,
                            "Quality counts exceed the bound role-specific label population.",
                        )
                    )
                if item["cohort"] == "all" and (
                    item["documents"] != population["documents"] or item["gold_spans"] != population["spans"]
                ):
                    diagnostics.append(
                        _error(
                            "contract.quality_population_exactness",
                            path,
                            "An all-document cohort must exactly equal its bound role-specific document and "
                            "span population.",
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
                "Public aggregate slices do not meet the minimum document count.",
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
                _error(
                    "contract.count_arithmetic",
                    f"{path}/{field}",
                    "Count does not match its declared component counts.",
                )
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
                _error(
                    "contract.count_bounds",
                    f"{path}/{numerator}",
                    "Count exceeds its declared containing total.",
                )
            )
    if item["cataloged_true_positive"] + item["cataloged_wrong_canonical"] > item["true_positive"]:
        diagnostics.append(
            _error(
                "contract.cataloged_true_positive_partition",
                f"{path}/cataloged_true_positive",
                "Correctly and incorrectly canonicalized cataloged matches must fit the true-positive span set.",
            )
        )
    if item["predicted_spans"] == 0 and any(
        item[field] != 0
        for field in ("predicted_characters", "covered_sensitive_characters", "over_redacted_characters")
    ):
        diagnostics.append(
            _error(
                "contract.empty_prediction_character_set",
                f"{path}/predicted_characters",
                "Zero predicted spans require an empty predicted-character position set.",
            )
        )
    if item["sensitive_gold_characters"] == 0 and (
        item["covered_sensitive_characters"] != 0 or item["leaked_sensitive_characters"] != 0
    ):
        diagnostics.append(
            _error(
                "contract.empty_sensitive_character_set",
                f"{path}/sensitive_gold_characters",
                "Zero sensitive-gold characters require empty covered and leaked character sets.",
            )
        )
    if item["false_negative"] == 0 and (
        item["leaked_sensitive_characters"] != 0 or item["documents_with_any_leaked_character"] != 0
    ):
        diagnostics.append(
            _error(
                "contract.exact_recall_character_consistency",
                f"{path}/leaked_sensitive_characters",
                "Perfect exact-span recall requires zero leaked sensitive-character positions.",
            )
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
                    "Metric does not match the recomputed integer-count value.",
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
            or value["policy_sha256"] is not None
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
        plan = manifest["conformance_plan"]
        expected_plan_fields = {
            "label_artifact_id": plan["label_artifact_id"],
            "positive_cases_artifact": plan["positive_cases_artifact"],
            "approved_positive_cases": plan["positive_cases"],
            "negative_cases_artifact": plan["negative_cases_artifact"],
            "negative_cases": plan["negative_cases"],
            "policy_sha256": plan["policy_sha256"],
        }
        if any(value[field] != expected for field, expected in expected_plan_fields.items()):
            diagnostics.append(
                _error(
                    "contract.conformance_plan_binding",
                    "/catalog_conformance",
                    "Conformance evidence differs from its frozen manifest case artifacts, counts, or policy.",
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
    if (
        value["positive_cases_artifact"] is None
        or value["negative_cases_artifact"] is None
        or value["policy_sha256"] is None
    ):
        diagnostics.append(
            _error(
                "contract.missing_conformance_artifact",
                "/catalog_conformance",
                "Evaluated conformance requires positive and negative case artifacts plus a frozen policy hash.",
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
            _error(
                "contract.metric_arithmetic",
                "/catalog_conformance/recall",
                "Metric does not match the recomputed count value.",
            )
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
        and value["policy_sha256"] is not None
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
    has_test_aggregate = _has_test_role_aggregate(evidence, manifest)
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
        "manifest_sha256": evidence["manifest_sha256"],
        "bank_hash": evidence["bank"]["canonical_hash"],
        "evaluator_source_sha256": evidence["evaluator"]["source_sha256"],
        "split_manifest_sha256": evidence["splits"]["manifest_sha256"],
        "test_artifact_sha256": evidence["splits"]["roles"]["test"]["artifact"]["sha256"],
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
    seen_test_artifacts: set[str] = set()
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
        test_artifact_sha256 = str(entry["frozen_target"]["test_artifact_sha256"])
        if test_artifact_sha256 in seen_test_artifacts:
            diagnostics.append(
                _error(
                    "contract.test_population_reused",
                    f"{path}/frozen_target/test_artifact_sha256",
                    "A sealed final-test artifact may be accessed by only one benchmark version.",
                )
            )
        seen_test_artifacts.add(test_artifact_sha256)
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
    if has_test_aggregate and count != 1:
        diagnostics.append(
            _error(
                "contract.test_aggregate_without_access",
                "/test_access/current_version_access_count",
                "Every current-version final-test aggregate requires exactly one recorded sealed-test access.",
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
        prefix_values = list(trusted_lineage_prefix) if type(trusted_lineage_prefix) in (list, tuple) else None
        prefix_valid = (
            prefix_values is not None
            and not _structure_diagnostics(prefix_values)
            and all(type(item) is dict for item in prefix_values)
        )
        if not prefix_valid:
            diagnostics.append(
                _error(
                    "contract.trusted_lineage_shape",
                    "/test_access/lineage",
                    "Trusted lineage prefix must be a bounded sequence of JSON objects.",
                )
            )
        elif prefix_values is not None and (
            len(prefix_values) != expected_prefix_length or prefix_values != list(lineage[:expected_prefix_length])
        ):
            diagnostics.append(
                _error(
                    "contract.lineage_not_append_only",
                    "/test_access/lineage",
                    "Evidence lineage is not an exact append of the trusted published prefix.",
                )
            )
    return diagnostics


def _has_test_role_aggregate(evidence: Mapping[str, Any], manifest: Mapping[str, Any] | None) -> bool:
    if any(item["split_role"] == "test" for item in evidence["quality"]["slices"]):
        return True
    if any(item["scope"]["split_role"] == "test" for item in evidence["promotion"]["claims"]):
        return True
    return False


def _performance_diagnostics(
    performance: Mapping[str, Any],
    bank: Mapping[str, Any],
    source: Mapping[str, Any],
    splits: Mapping[str, Any],
    commands: Sequence[Mapping[str, Any]],
    referenced_samples: Mapping[str, Sequence[float]] | None,
    referenced_input_inventories: Mapping[str, Sequence[Mapping[str, int]]] | None,
    recomputed_statistics: dict[str, Mapping[str, Any]],
    *,
    promotion_passed: bool,
) -> list[Diagnostic]:
    banks = performance["banks"]
    inputs = performance["inputs"]
    harnesses = performance["harnesses"]
    workloads = performance["workloads"]
    baselines = performance["baselines"]
    comparisons = performance["comparisons"]
    breakeven_models = performance["breakeven_models"]
    collections = (banks, inputs, harnesses, workloads, baselines, comparisons, breakeven_models)
    if not performance["evaluated"]:
        return (
            []
            if not any(collections)
            else [
                _error(
                    "contract.not_evaluated_has_workloads",
                    "/performance",
                    "Unevaluated performance must not contain descriptors, workloads, or derived results.",
                )
            ]
        )
    if not workloads or not banks or not inputs or not harnesses:
        return [
            _error(
                "contract.empty_performance",
                "/performance",
                "Evaluated performance requires declared banks, inputs, harnesses, and workloads.",
            )
        ]
    diagnostics: list[Diagnostic] = []
    diagnostics.extend(_duplicate_id_diagnostics(banks, "/performance/banks", "performance bank"))
    diagnostics.extend(_duplicate_id_diagnostics(inputs, "/performance/inputs", "performance input"))
    diagnostics.extend(_duplicate_id_diagnostics(harnesses, "/performance/harnesses", "performance harness"))
    diagnostics.extend(_duplicate_id_diagnostics(workloads, "/performance/workloads", "performance workload"))
    diagnostics.extend(_duplicate_id_diagnostics(baselines, "/performance/baselines", "performance baseline"))
    diagnostics.extend(_duplicate_id_diagnostics(comparisons, "/performance/comparisons", "performance comparison"))
    diagnostics.extend(_duplicate_id_diagnostics(breakeven_models, "/performance/breakeven_models", "breakeven model"))
    for collection, path in (
        (banks, "/performance/banks"),
        (inputs, "/performance/inputs"),
        (harnesses, "/performance/harnesses"),
        (workloads, "/performance/workloads"),
        (baselines, "/performance/baselines"),
        (comparisons, "/performance/comparisons"),
        (breakeven_models, "/performance/breakeven_models"),
    ):
        identifiers = [str(item["id"]) for item in collection]
        if identifiers != sorted(identifiers):
            diagnostics.append(
                _error(
                    "contract.performance_descriptor_order",
                    path,
                    "Performance descriptor collections must use canonical identifier order.",
                )
            )
    bank_by_id = {str(item["id"]): item for item in banks}
    bank_hashes = [str(item["bank_hash"]) for item in banks]
    if len(bank_hashes) != len(set(bank_hashes)):
        diagnostics.append(
            _error(
                "contract.duplicate_performance_bank_hash",
                "/performance/banks",
                "Every performance-bank descriptor must have a unique canonical bank hash.",
            )
        )
    bank_artifact_hashes = [str(item["artifact"]["sha256"]) for item in banks]
    if len(bank_artifact_hashes) != len(set(bank_artifact_hashes)):
        diagnostics.append(
            _error(
                "contract.duplicate_performance_bank_artifact",
                "/performance/banks",
                "Every performance-bank descriptor must bind a distinct content-addressed bank artifact.",
            )
        )
    for index, descriptor in enumerate(banks):
        diagnostics.extend(_performance_bank_diagnostics(descriptor, f"/performance/banks/{index}"))
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
            "active_aliases": bank["active_aliases"],
            "active_patterns": bank["active_patterns"],
            "canonical_json_bytes": bank["canonical_json_bytes"],
            "native_source_bytes": bank["native_source_bytes"],
            "artifact": {
                "sha256": bank["artifact_sha256"],
                "bytes": bank["artifact_bytes"],
            },
        }
        if any(
            descriptor[field] != expected for field, expected in expected_descriptor.items() if field != "artifact"
        ) or any(
            descriptor["artifact"][field] != expected for field, expected in expected_descriptor["artifact"].items()
        ):
            diagnostics.append(
                _error(
                    "contract.performance_bank_mismatch",
                    "/performance/banks",
                    "Evaluated performance-bank descriptor differs from evidence bank provenance.",
                )
            )
    input_by_id = {str(item["id"]): item for item in inputs}
    resolved_inventory_ids: set[str] = set()
    referenced_item_count = 0
    inventory_cache: dict[str, tuple[str, int, dict[str, Any]] | None] = {}
    inventory_budget_exceeded: set[str] = set()
    for index, input_descriptor in enumerate(inputs):
        path = f"/performance/inputs/{index}"
        diagnostics.extend(_performance_input_diagnostics(input_descriptor, bank_by_id, path))
        inventory_id = str(input_descriptor["inventory_ref"]["id"])
        if referenced_input_inventories is not None and inventory_id in referenced_input_inventories:
            if inventory_id not in inventory_cache and inventory_id not in inventory_budget_exceeded:
                resolved_inventory = referenced_input_inventories[inventory_id]
                inventory_items = len(resolved_inventory) if type(resolved_inventory) in (list, tuple) else 0
                if referenced_item_count + inventory_items > MAX_REFERENCED_ITEMS:
                    inventory_budget_exceeded.add(inventory_id)
                else:
                    referenced_item_count += inventory_items
                    inventory_cache[inventory_id] = _prepare_performance_inventory(resolved_inventory)
            if inventory_id in inventory_budget_exceeded:
                diagnostics.append(
                    _error(
                        "contract.performance_reference_budget",
                        f"{path}/inventory_ref",
                        "Referenced performance artifacts exceed the aggregate item budget.",
                    )
                )
                continue
            inventory_diagnostics = _performance_inventory_diagnostics(
                input_descriptor,
                inventory_cache[inventory_id],
                path,
            )
            diagnostics.extend(inventory_diagnostics)
            if not inventory_diagnostics:
                resolved_inventory_ids.add(inventory_id)
    baseline_by_id = {str(item["id"]): item for item in baselines}
    for index, baseline in enumerate(baselines):
        path = f"/performance/baselines/{index}"
        if baseline["descriptor_sha256"] != hash_enron_performance_baseline(baseline):
            diagnostics.append(
                _error(
                    "contract.performance_baseline_hash",
                    f"{path}/descriptor_sha256",
                    "Baseline identity and capability descriptor hash does not match its canonical content.",
                )
            )
        if baseline["semantic_equivalence"] == "exact" and not all(baseline["capabilities"].values()):
            diagnostics.append(
                _error(
                    "contract.performance_baseline_capability",
                    f"{path}/capabilities",
                    "Exact baselines must support every benchmark literal, regex, alias, mapping, and Unicode feature.",
                )
            )
    command_ids = {str(item["id"]) for item in commands}
    harness_by_id = {str(item["id"]): item for item in harnesses}
    for index, harness in enumerate(harnesses):
        path = f"/performance/harnesses/{index}"
        if harness["descriptor_sha256"] != hash_enron_performance_harness(harness):
            diagnostics.append(
                _error(
                    "contract.performance_harness_hash",
                    f"{path}/descriptor_sha256",
                    "Harness hash does not match its command, source, operation specification, and phase.",
                )
            )
        if harness["command_id"] not in command_ids:
            diagnostics.append(
                _error(
                    "contract.performance_harness_command",
                    f"{path}/command_id",
                    "Performance harness must bind an exact declared command.",
                )
            )
        source_artifact = harness["source_artifact"]
        phase = str(harness["phase"])
        source_artifact_required = phase in {"source_profile", "source_build"}
        if (source_artifact is not None) != source_artifact_required:
            diagnostics.append(
                _error(
                    "contract.performance_harness_source_artifact",
                    f"{path}/source_artifact",
                    "Source profiling and source building require a content-addressed source artifact; "
                    "other phases do not.",
                )
            )
        elif phase == "source_profile" and source_artifact != splits["roles"]["train"]["artifact"]:
            diagnostics.append(
                _error(
                    "contract.performance_harness_source_binding",
                    f"{path}/source_artifact",
                    "Source profiling must bind the exact frozen train-split artifact.",
                )
            )
        elif phase == "source_build" and source_artifact != splits["roles"]["train"]["artifact"]:
            diagnostics.append(
                _error(
                    "contract.performance_harness_source_binding",
                    f"{path}/source_artifact",
                    "Source building must bind the exact frozen train-split artifact.",
                )
            )
    sample_cache: dict[str, tuple[list[float], int, str] | None] = {}
    sample_budget_exceeded: set[str] = set()
    resolved_samples_by_workload: dict[str, list[float]] = {}
    for index, workload in enumerate(workloads):
        path = f"/performance/workloads/{index}"
        harness = harness_by_id.get(str(workload["harness_id"]))
        if (
            harness is None
            or harness["descriptor_sha256"] != workload["harness_sha256"]
            or harness["phase"] != workload["phase"]
        ):
            diagnostics.append(
                _error(
                    "contract.unknown_performance_harness",
                    f"{path}/harness_id",
                    "Workload must bind the exact frozen harness descriptor for its measured phase.",
                )
            )
        workload_bank = bank_by_id.get(str(workload["bank_id"]))
        if workload_bank is None or workload_bank["bank_hash"] != workload["bank_hash"]:
            diagnostics.append(
                _error(
                    "contract.unknown_performance_bank",
                    f"{path}/bank_id",
                    "Performance workload bank id and hash must reference the same declared descriptor.",
                )
            )
        setup_phase = workload["phase"] in {"source_profile", "source_build", "cold_compile"}
        input_descriptor = None if workload["input_id"] is None else input_by_id.get(str(workload["input_id"]))
        if setup_phase and (workload["input_id"] is not None or workload["input_sha256"] is not None):
            diagnostics.append(
                _error(
                    "contract.setup_phase_input",
                    f"{path}/input_id",
                    "Source-profile, bank-build, and cold-compile workloads cannot borrow scan-input denominators.",
                )
            )
        if not setup_phase and (
            input_descriptor is None
            or input_descriptor["descriptor_sha256"] != workload["input_sha256"]
            or input_descriptor["bank_id"] != workload["bank_id"]
            or input_descriptor["bank_hash"] != workload["bank_hash"]
        ):
            diagnostics.append(
                _error(
                    "contract.unknown_performance_input",
                    f"{path}/input_id",
                    "Scan-bearing workloads must bind an input descriptor for the exact bank id and hash.",
                )
            )
        baseline_id = workload["baseline_id"]
        if baseline_id is not None and str(baseline_id) not in baseline_by_id:
            diagnostics.append(
                _error(
                    "contract.unknown_performance_baseline",
                    f"{path}/baseline_id",
                    "Performance workload references an undeclared baseline identity.",
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
        expected_process_model = PERFORMANCE_PHASE_PROCESS_MODELS[str(workload["phase"])]
        if workload["process_model"] != expected_process_model:
            diagnostics.append(
                _error(
                    "contract.performance_phase_process_model",
                    f"{path}/process_model",
                    "Performance phase uses an invalid timing-isolation process model.",
                )
            )
        invalid_sample_unit = (
            (setup_phase and workload["sample_unit"] != "operation")
            or (
                workload["phase"] in {"helper_cache_miss", "helper_cache_hit", "end_to_end"}
                and workload["sample_unit"] != "whole_input"
            )
            or (workload["phase"] == "direct_bank_scan" and workload["sample_unit"] == "operation")
        )
        if invalid_sample_unit:
            diagnostics.append(
                _error(
                    "contract.performance_phase_sample_unit",
                    f"{path}/sample_unit",
                    "Performance sample units must match bank setup, whole-input, or direct document work.",
                )
            )
        if workload["phase"] == "direct_bank_scan" and workload["warmups"] < 1:
            diagnostics.append(
                _error(
                    "contract.performance_warmups",
                    f"{path}/warmups",
                    "Reused direct Bank scans require at least one untimed warmup.",
                )
            )
        if workload["baseline_id"] is not None and (workload["promotion_gate"] or workload["decision_grade"]):
            diagnostics.append(
                _error(
                    "contract.baseline_decision_grade",
                    f"{path}/baseline_id",
                    "Baseline cells cannot be NERB promotion or decision-grade cells.",
                )
            )
        samples = workload["samples_seconds"]
        resolved_samples: Sequence[float] | None = samples
        normalized_samples: list[float] | None = None
        resolved_sample_bytes: int | None = None
        resolved_sample_sha256: str | None = None
        if not samples:
            sample_ref = workload["samples_ref"]
            sample_id = str(sample_ref["id"])
            if referenced_samples is None or sample_id not in referenced_samples:
                diagnostics.append(
                    _error(
                        "contract.performance_samples_unavailable",
                        f"{path}/samples_ref",
                        "Referenced raw samples must be supplied to the semantic verifier.",
                    )
                )
                continue
            if sample_id not in sample_cache and sample_id not in sample_budget_exceeded:
                resolved_reference = referenced_samples[sample_id]
                sample_items = len(resolved_reference) if type(resolved_reference) in (list, tuple) else 0
                if referenced_item_count + sample_items > MAX_REFERENCED_ITEMS:
                    sample_budget_exceeded.add(sample_id)
                else:
                    referenced_item_count += sample_items
                    sample_cache[sample_id] = _prepare_performance_samples(resolved_reference)
            if sample_id in sample_budget_exceeded:
                diagnostics.append(
                    _error(
                        "contract.performance_reference_budget",
                        f"{path}/samples_ref",
                        "Referenced performance artifacts exceed the aggregate item budget.",
                    )
                )
                continue
            prepared_samples = sample_cache[sample_id]
            if prepared_samples is None:
                diagnostics.append(
                    _error(
                        "contract.performance_sample_support",
                        f"{path}/samples_seconds",
                        "Performance requires at least five finite, strictly positive, bounded samples.",
                    )
                )
                continue
            resolved_samples, resolved_sample_bytes, resolved_sample_sha256 = prepared_samples
            normalized_samples = resolved_samples
        if resolved_samples is None:
            continue
        if normalized_samples is None:
            normalized_samples = _normalize_samples(resolved_samples)
        if normalized_samples is None or len(normalized_samples) < 5:
            diagnostics.append(
                _error(
                    "contract.performance_sample_support",
                    f"{path}/samples_seconds",
                    "Performance requires at least five finite, strictly positive, bounded samples.",
                )
            )
            continue
        resolved_samples_by_workload[str(workload["id"])] = normalized_samples
        if not samples and (
            workload["samples_ref"]["bytes"] != resolved_sample_bytes
            or resolved_sample_sha256 != workload["samples_ref"]["sha256"]
        ):
            diagnostics.append(
                _error(
                    "contract.performance_sample_hash",
                    f"{path}/samples_ref",
                    "Resolved samples do not match the non-empty content-addressed sample reference.",
                )
            )
        if workload["sample_unit"] != "operation" and input_descriptor is None:
            continue
        if workload["sample_unit"] == "document" and input_descriptor is not None:
            measured_documents = len(normalized_samples) * workload["work_per_sample"]
            if measured_documents < input_descriptor["documents"] or measured_documents % input_descriptor["documents"]:
                diagnostics.append(
                    _error(
                        "contract.document_sample_coverage",
                        f"{path}/sample_unit",
                        "Document timing samples must cover one or more complete balanced passes over the input.",
                    )
                )
        rss_samples = workload["rss_samples_bytes"]
        if (workload["peak_rss_bytes"] is None) != (not rss_samples) or (
            workload["peak_rss_bytes"] is not None
            and (len(rss_samples) != len(normalized_samples) or max(rss_samples) != workload["peak_rss_bytes"])
        ):
            diagnostics.append(
                _error(
                    "contract.performance_rss_samples",
                    f"{path}/rss_samples_bytes",
                    "Peak RSS must be the maximum of one positive memory sample per timing sample.",
                )
            )
        stats = workload["stats"]
        records_per_sample = workload["records_per_sample"]
        expected_inventory_records = (
            None
            if input_descriptor is None or workload["sample_unit"] != "whole_input"
            else input_descriptor["records"] * workload["work_per_sample"]
        )
        baseline = None if workload["baseline_id"] is None else baseline_by_id.get(str(workload["baseline_id"]))
        records_must_match_inventory = baseline is None or baseline["semantic_equivalence"] == "exact"
        if (workload["sample_unit"] == "whole_input") != (records_per_sample is not None) or (
            records_per_sample is not None
            and records_must_match_inventory
            and records_per_sample != expected_inventory_records
        ):
            diagnostics.append(
                _error(
                    "contract.performance_record_denominator",
                    f"{path}/records_per_sample",
                    "Whole-input record throughput must use the observed stable count; exact NERB paths must match the "
                    "bound input inventory.",
                )
            )
        expected = _sample_statistics(
            normalized_samples,
            input_descriptor,
            str(workload["phase"]),
            workload["sample_unit"],
            workload["work_per_sample"],
            records_per_sample=records_per_sample,
        )
        recomputed_statistics[str(workload["id"])] = expected
        for field, value in expected.items():
            if not _same_metric(stats[field], value):
                diagnostics.append(
                    _error(
                        "contract.performance_arithmetic",
                        f"{path}/stats/{field}",
                        "Statistic does not match the recomputed raw-sample value.",
                    )
                )
        warm_path = workload["process_model"] == "reused_process"
        minimum_samples = (
            MIN_DECISION_GRADE_SETUP_SAMPLES
            if workload["phase"] in PERFORMANCE_SETUP_PHASES
            else MIN_DECISION_GRADE_SCAN_SAMPLES
        )
        if workload["decision_grade"] and (
            workload["baseline_id"] is not None
            or (warm_path and workload["warmups"] < MIN_DECISION_GRADE_WARMUPS)
            or (not warm_path and workload["warmups"] != 0)
            or len(normalized_samples) < minimum_samples
            or workload["work_per_sample"] != 1
            or workload["peak_rss_bytes"] is None
        ):
            diagnostics.append(
                _error(
                    "contract.invalid_decision_grade_workload",
                    f"{path}/decision_grade",
                    "Decision-grade cells require one-unit work, phase-correct warmups, phase-specific sample support, "
                    "and peak RSS.",
                )
            )
        if workload["promotion_gate"] and (
            not workload["decision_grade"]
            or workload["bank_hash"] != bank["canonical_hash"]
            or workload["phase"] != "direct_bank_scan"
            or workload["work_per_sample"] != 1
        ):
            diagnostics.append(
                _error(
                    "contract.invalid_performance_gate",
                    f"{path}/promotion_gate",
                    "Headline gates must be decision-grade direct scans of the evaluated Bank.",
                )
            )
    used_bank_ids = {str(item["bank_id"]) for item in workloads}
    if set(bank_by_id) - used_bank_ids:
        diagnostics.append(
            _error(
                "contract.unused_performance_bank",
                "/performance/banks",
                "Every declared performance bank must be exercised by at least one workload.",
            )
        )
    used_input_ids = {str(item["input_id"]) for item in workloads}
    if set(input_by_id) - used_input_ids:
        diagnostics.append(
            _error(
                "contract.unused_performance_input",
                "/performance/inputs",
                "Every declared performance input must be exercised by at least one workload.",
            )
        )
    used_harness_ids = {str(item["harness_id"]) for item in workloads}
    if set(harness_by_id) - used_harness_ids:
        diagnostics.append(
            _error(
                "contract.unused_performance_harness",
                "/performance/harnesses",
                "Every frozen performance harness must be exercised by at least one workload.",
            )
        )
    used_baseline_ids = {str(item["baseline_id"]) for item in workloads if item["baseline_id"] is not None}
    if set(baseline_by_id) - used_baseline_ids:
        diagnostics.append(
            _error(
                "contract.unused_performance_baseline",
                "/performance/baselines",
                "Every declared baseline identity must be exercised by at least one workload.",
            )
        )
    if promotion_passed:
        decision_input_ids = {
            str(item["input_id"])
            for item in workloads
            if item["decision_grade"] and str(item["input_id"]) in input_by_id
        }
        missing_inventories = sorted(
            item_id
            for item_id in decision_input_ids
            if str(input_by_id[item_id]["inventory_ref"]["id"]) not in resolved_inventory_ids
        )
        if missing_inventories:
            diagnostics.append(
                _error(
                    "contract.performance_inventory_unavailable",
                    "/performance/inputs",
                    "Promoted decision-grade denominators require all referenced input inventories.",
                )
            )
    diagnostics.extend(
        _performance_comparison_diagnostics(
            comparisons,
            workloads,
            baseline_by_id,
            harness_by_id,
            recomputed_statistics,
            resolved_samples_by_workload,
        )
    )
    diagnostics.extend(_performance_breakeven_diagnostics(breakeven_models, workloads, recomputed_statistics))
    return diagnostics


def _performance_bank_diagnostics(descriptor: Mapping[str, Any], path: str) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    if descriptor["descriptor_sha256"] != hash_enron_performance_bank(descriptor):
        diagnostics.append(
            _error(
                "contract.performance_bank_descriptor_hash",
                f"{path}/descriptor_sha256",
                "Performance-bank descriptor hash does not match its canonical content.",
            )
        )
    generator_required = descriptor["kind"] == "synthetic_scale"
    if (descriptor["generator"] is not None) != generator_required:
        diagnostics.append(
            _error(
                "contract.performance_bank_generator",
                f"{path}/generator",
                "Synthetic scale banks require a versioned generator; evaluated banks bind their real artifact.",
            )
        )
    taxonomy = descriptor["composition"]["taxonomy"]
    taxon_ids = [str(item["entity_class"]) for item in taxonomy]
    if len(taxon_ids) != len(set(taxon_ids)):
        diagnostics.append(
            _error(
                "contract.duplicate_bank_taxon",
                f"{path}/composition/taxonomy",
                "Bank taxonomy ids must be unique.",
            )
        )
    totals = {
        "active_entities": sum(int(item["entities"]) for item in taxonomy),
        "active_names": sum(int(item["canonical_names"]) + int(item["aliases"]) for item in taxonomy),
        "active_aliases": sum(int(item["aliases"]) for item in taxonomy),
        "active_patterns": sum(int(item["literal_patterns"]) + int(item["regex_patterns"]) for item in taxonomy),
    }
    if any(descriptor[field] != expected for field, expected in totals.items()):
        diagnostics.append(
            _error(
                "contract.performance_bank_composition",
                f"{path}/composition",
                "Taxonomy, canonical-name/alias, and literal/regex totals must equal the bank descriptor totals.",
            )
        )
    return diagnostics


def _performance_input_diagnostics(
    descriptor: Mapping[str, Any], bank_by_id: Mapping[str, Mapping[str, Any]], path: str
) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    if descriptor["descriptor_sha256"] != hash_enron_performance_input(descriptor):
        diagnostics.append(
            _error(
                "contract.performance_input_descriptor_hash",
                f"{path}/descriptor_sha256",
                "Performance-input descriptor hash does not match its canonical content.",
            )
        )
    bound_bank = bank_by_id.get(str(descriptor["bank_id"]))
    if bound_bank is None or bound_bank["bank_hash"] != descriptor["bank_hash"]:
        diagnostics.append(
            _error(
                "contract.performance_input_bank",
                f"{path}/bank_id",
                "Performance input must bind an exact bank id and hash because record counts are bank-specific.",
            )
        )
    generator_required = descriptor["kind"] == "synthetic_input"
    if (descriptor["generator"] is not None) != generator_required:
        diagnostics.append(
            _error(
                "contract.performance_input_generator",
                f"{path}/generator",
                "Synthetic inputs require a versioned generator; real inputs must be content-addressed without one.",
            )
        )
    if descriptor["artifact"]["bytes"] != descriptor["bytes"]:
        diagnostics.append(
            _error(
                "contract.performance_input_artifact",
                f"{path}/artifact/bytes",
                "Input byte denominator must equal the content-addressed input artifact size.",
            )
        )
    lengths = descriptor["document_length_distribution"]
    length_order = [
        lengths[field] for field in ("minimum_bytes", "p50_bytes", "p95_bytes", "p99_bytes", "maximum_bytes")
    ]
    hits = descriptor["hit_distribution"]
    hit_order = [
        hits[field] for field in ("minimum_records", "p50_records", "p95_records", "p99_records", "maximum_records")
    ]
    if (
        length_order != sorted(length_order)
        or hit_order != sorted(hit_order)
        or not _same_metric(lengths["mean_bytes"], descriptor["bytes"] / descriptor["documents"])
        or not _same_metric(hits["mean_records"], descriptor["records"] / descriptor["documents"])
        or not lengths["minimum_bytes"] <= lengths["mean_bytes"] <= lengths["maximum_bytes"]
        or not hits["minimum_records"] <= hits["mean_records"] <= hits["maximum_records"]
        or hits["negative_documents"] + hits["documents_with_records"] != descriptor["documents"]
        or (descriptor["records"] == 0) != (hits["documents_with_records"] == 0)
    ):
        diagnostics.append(
            _error(
                "contract.performance_input_distribution",
                path,
                "Document-length and hit distributions must reconcile to document, byte, and record totals.",
            )
        )
    expected_density = _classify_hit_density(descriptor["records"], descriptor["documents"])
    if descriptor["hit_density"] != expected_density:
        diagnostics.append(
            _error(
                "contract.performance_hit_density",
                f"{path}/hit_density",
                "Hit density does not match its deterministic records-per-document classification.",
            )
        )
    expected_size = _classify_size_cohort(descriptor["bytes"], descriptor["documents"])
    if descriptor["size_cohort"] != expected_size:
        diagnostics.append(
            _error(
                "contract.performance_size_cohort",
                f"{path}/size_cohort",
                "Document size cohort does not match the deterministic mean-byte classification.",
            )
        )
    return diagnostics


def _prepare_performance_inventory(
    inventory: Sequence[Mapping[str, int]],
) -> tuple[str, int, dict[str, Any]] | None:
    normalized = _normalize_performance_inventory(inventory)
    if normalized is None:
        return None
    payload = _canonical_payload(normalized)
    return "sha256:" + sha256(payload).hexdigest(), len(payload), _performance_inventory_summary(normalized)


def _performance_inventory_diagnostics(
    descriptor: Mapping[str, Any], prepared: tuple[str, int, Mapping[str, Any]] | None, path: str
) -> list[Diagnostic]:
    if prepared is None:
        return [
            _error(
                "contract.performance_inventory_shape",
                f"{path}/inventory_ref",
                "Referenced inventory must contain only bounded nonnegative integer bytes and records per document.",
            )
        ]
    inventory_sha256, inventory_bytes, expected = prepared
    inventory_ref = descriptor["inventory_ref"]
    if inventory_ref["sha256"] != inventory_sha256 or inventory_ref["bytes"] != inventory_bytes:
        return [
            _error(
                "contract.performance_inventory_hash",
                f"{path}/inventory_ref",
                "Referenced input inventory does not match its content-addressed reference.",
            )
        ]
    fields = (
        "documents",
        "bytes",
        "records",
        "hit_density",
        "size_cohort",
        "document_length_distribution",
        "hit_distribution",
    )
    if any(descriptor[field] != expected[field] for field in fields):
        return [
            _error(
                "contract.performance_inventory_arithmetic",
                path,
                "Input denominators and distributions differ from the referenced per-document inventory.",
            )
        ]
    return []


def _performance_comparison_diagnostics(
    comparisons: Sequence[Mapping[str, Any]],
    workloads: Sequence[Mapping[str, Any]],
    baseline_by_id: Mapping[str, Mapping[str, Any]],
    harness_by_id: Mapping[str, Mapping[str, Any]],
    recomputed_statistics: Mapping[str, Mapping[str, Any]],
    resolved_samples_by_workload: Mapping[str, Sequence[float]],
) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    workload_by_id = {str(item["id"]): item for item in workloads}
    comparison_keys = [
        (str(item["candidate_workload_id"]), str(item["baseline_workload_id"]), str(item["metric"]))
        for item in comparisons
    ]
    if len(comparison_keys) != len(set(comparison_keys)):
        diagnostics.append(
            _error(
                "contract.duplicate_performance_comparison_metric",
                "/performance/comparisons",
                "A candidate/baseline workload pair may declare at most one comparison for each metric.",
            )
        )
    for index, comparison in enumerate(comparisons):
        path = f"/performance/comparisons/{index}"
        if comparison["comparison_plan_sha256"] != hash_enron_performance_comparison_plan(comparison):
            diagnostics.append(
                _error(
                    "contract.performance_comparison_hash",
                    f"{path}/comparison_plan_sha256",
                    "Comparison plan hash does not match its frozen candidate, baseline, metric, and noise policy.",
                )
            )
        candidate = workload_by_id.get(str(comparison["candidate_workload_id"]))
        baseline = workload_by_id.get(str(comparison["baseline_workload_id"]))
        baseline_identity = None if baseline is None else baseline_by_id.get(str(baseline["baseline_id"]))
        candidate_harness = None if candidate is None else harness_by_id.get(str(candidate["harness_id"]))
        baseline_harness = None if baseline is None else harness_by_id.get(str(baseline["harness_id"]))
        comparable_fields = (
            "phase",
            "bank_id",
            "bank_hash",
            "input_id",
            "input_sha256",
            "warmups",
            "sample_unit",
            "work_per_sample",
            "concurrency",
            "process_model",
            "median_method",
            "percentile_method",
        )
        comparison_kind = str(comparison["comparison_kind"])
        same_path_valid = (
            comparison_kind == "same_path_stability"
            and candidate is not None
            and baseline is not None
            and candidate["baseline_id"] is None
            and baseline["baseline_id"] is not None
            and baseline_identity is not None
            and baseline_identity["semantic_equivalence"] == "exact"
            and candidate_harness is not None
            and baseline_harness is not None
            and candidate_harness["operation_spec_sha256"] == baseline_harness["operation_spec_sha256"]
            and candidate_harness["source_artifact"] == baseline_harness["source_artifact"]
            and candidate["stats"]["sample_count"] == baseline["stats"]["sample_count"]
            and all(candidate[field] == baseline[field] for field in comparable_fields)
            and comparison["noise_method"]
            == ("paired_relative_mad" if candidate["sample_unit"] == "document" else "independent_mad")
        )
        cross_fields = (
            "bank_id",
            "bank_hash",
            "input_id",
            "input_sha256",
            "sample_unit",
            "work_per_sample",
            "concurrency",
            "median_method",
            "percentile_method",
        )
        allowed_cross_phases = {
            ("direct_bank_scan", "helper_cache_miss"),
            ("direct_bank_scan", "helper_cache_hit"),
            ("direct_bank_scan", "end_to_end"),
            ("helper_cache_hit", "helper_cache_miss"),
        }
        cross_path_valid = (
            comparison_kind == "cross_path_value"
            and candidate is not None
            and baseline is not None
            and candidate["baseline_id"] is None
            and baseline["baseline_id"] is None
            and candidate["decision_grade"] is True
            and baseline["decision_grade"] is True
            and candidate["sample_unit"] == "whole_input"
            and candidate["stats"]["sample_count"] == baseline["stats"]["sample_count"]
            and (candidate["phase"], baseline["phase"]) in allowed_cross_phases
            and all(candidate[field] == baseline[field] for field in cross_fields)
            and comparison["noise_method"] == "paired_block_ratio_mad"
        )
        if not same_path_valid and not cross_path_valid:
            diagnostics.append(
                _error(
                    "contract.incomparable_performance_baseline",
                    path,
                    "Comparison must be either an identical exact same-path stability control or an allowed exact-"
                    "semantics whole-input cache-value pair.",
                )
            )
            continue
        assert candidate is not None and baseline is not None
        metric = str(comparison["metric"])
        candidate_stats = recomputed_statistics.get(str(candidate["id"]), candidate["stats"])
        baseline_stats = recomputed_statistics.get(str(baseline["id"]), baseline["stats"])
        try:
            expected = calculate_enron_performance_comparison(
                candidate_stats,
                baseline_stats,
                metric=metric,
                noise_multiplier=float(comparison["noise_multiplier"]),
                regression_tolerance=float(comparison["regression_tolerance"]),
                noise_method=str(comparison["noise_method"]),
                candidate_samples=(
                    resolved_samples_by_workload.get(str(candidate["id"]))
                    if comparison["noise_method"] in {"paired_relative_mad", "paired_block_ratio_mad"}
                    else None
                ),
                baseline_samples=(
                    resolved_samples_by_workload.get(str(baseline["id"]))
                    if comparison["noise_method"] in {"paired_relative_mad", "paired_block_ratio_mad"}
                    else None
                ),
            )
        except ValueError:
            diagnostics.append(
                _error(
                    "contract.unsupported_performance_comparison",
                    path,
                    "Comparison metric lacks supported nonzero raw-sample statistics.",
                )
            )
            continue
        if float(expected["noise_floor"]) > MAX_COMPARISON_NOISE_FLOOR:
            diagnostics.append(
                _error(
                    "contract.unstable_performance_comparison",
                    path,
                    "Decision-grade comparison noise exceeds the benchmark-v2 stability ceiling.",
                )
            )
        if any(not _same_scalar(comparison[field], value) for field, value in expected.items()):
            diagnostics.append(
                _error(
                    "contract.performance_comparison_arithmetic",
                    path,
                    "Noise-aware comparison differs from the bound raw-sample statistics.",
                )
            )
    return diagnostics


def _performance_breakeven_diagnostics(
    models: Sequence[Mapping[str, Any]],
    workloads: Sequence[Mapping[str, Any]],
    recomputed_statistics: Mapping[str, Mapping[str, Any]],
) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    workload_by_id = {str(item["id"]): item for item in workloads}
    for index, model in enumerate(models):
        path = f"/performance/breakeven_models/{index}"
        if model["model_plan_sha256"] != hash_enron_breakeven_plan(model):
            diagnostics.append(
                _error(
                    "contract.performance_breakeven_hash",
                    f"{path}/model_plan_sha256",
                    "Breakeven plan hash does not match its frozen components and parameter policy.",
                )
            )
        components = model["components"]
        component_ids = [str(item["id"]) for item in components]
        if len(component_ids) != len(set(component_ids)) or component_ids != sorted(component_ids):
            diagnostics.append(
                _error(
                    "contract.breakeven_component_ids",
                    f"{path}/components",
                    "Breakeven components require unique ids in canonical order.",
                )
            )
        resolved_components: list[tuple[Mapping[str, Any], float]] = []
        referenced_bank_hashes: set[str] = set()
        for component_index, component in enumerate(components):
            component_path = f"{path}/components/{component_index}"
            expected_value = _breakeven_component_value(component, model, workload_by_id, recomputed_statistics)
            if expected_value is None:
                diagnostics.append(
                    _error(
                        "contract.invalid_breakeven_component",
                        component_path,
                        "Breakeven component source, unit, side, and workload binding are inconsistent.",
                    )
                )
                continue
            if not _same_metric(component["value"], expected_value):
                diagnostics.append(
                    _error(
                        "contract.breakeven_component_arithmetic",
                        f"{component_path}/value",
                        "Breakeven component value differs from its frozen assumption or workload statistic.",
                    )
                )
            resolved_components.append((component, expected_value))
            workload_id = component["workload_id"]
            if workload_id is not None:
                referenced_bank_hashes.add(str(workload_by_id[str(workload_id)]["bank_hash"]))
        coverage = {(str(item["side"]), str(item["application"])) for item, _ in resolved_components}
        if (
            coverage
            != {
                ("candidate", "fixed"),
                ("candidate", "per_unit"),
                ("baseline", "fixed"),
                ("baseline", "per_unit"),
            }
            or len(referenced_bank_hashes) > 1
            or model["minimum_units"] > model["maximum_units"]
        ):
            diagnostics.append(
                _error(
                    "contract.invalid_breakeven_model",
                    path,
                    "Breakeven models require both sides' fixed/marginal components on one bank and a valid range.",
                )
            )
        totals = {
            (side, application): sum(
                value
                for component, value in resolved_components
                if component["side"] == side and component["application"] == application
            )
            for side in ("candidate", "baseline")
            for application in ("fixed", "per_unit")
        }
        if any(not math.isfinite(value) or value > MAX_FINITE_CONTRACT_NUMBER for value in totals.values()):
            diagnostics.append(
                _error(
                    "contract.breakeven_numeric_bounds",
                    path,
                    "Breakeven component totals must remain finite and bounded.",
                )
            )
            continue
        try:
            breakeven = calculate_enron_breakeven(
                totals[("candidate", "fixed")],
                totals[("baseline", "fixed")],
                totals[("candidate", "per_unit")],
                totals[("baseline", "per_unit")],
                minimum_units=int(model["minimum_units"]),
                maximum_units=int(model["maximum_units"]),
            )
        except ValueError:
            diagnostics.append(
                _error(
                    "contract.breakeven_numeric_bounds",
                    path,
                    "Breakeven projection arithmetic must remain finite and bounded.",
                )
            )
            continue
        expected = {
            "candidate_fixed_value": totals[("candidate", "fixed")],
            "baseline_fixed_value": totals[("baseline", "fixed")],
            "candidate_value_per_unit": totals[("candidate", "per_unit")],
            "baseline_value_per_unit": totals[("baseline", "per_unit")],
            **breakeven,
        }
        if any(not _same_scalar(model[field], value) for field, value in expected.items()):
            diagnostics.append(
                _error(
                    "contract.performance_breakeven_arithmetic",
                    path,
                    "Parameterized breakeven result differs from its additive frozen components.",
                )
            )
    return diagnostics


def _breakeven_component_value(
    component: Mapping[str, Any],
    model: Mapping[str, Any],
    workload_by_id: Mapping[str, Mapping[str, Any]],
    recomputed_statistics: Mapping[str, Mapping[str, Any]],
) -> float | None:
    source = str(component["source"])
    category = str(component["category"])
    workload_id = component["workload_id"]
    assumption_sha256 = component["assumption_sha256"]
    if source == "declared_assumption":
        if (
            workload_id is not None
            or assumption_sha256 is None
            or category
            in {
                "source_profiling",
                "bank_build",
                "cold_compile",
                "scan",
            }
        ):
            return None
        return float(component["value"])
    if model["value_unit"] != "seconds" or workload_id is None or assumption_sha256 is not None:
        return None
    workload = workload_by_id.get(str(workload_id))
    if workload is None:
        return None
    workload_statistics = recomputed_statistics.get(str(workload["id"]), workload["stats"])
    candidate_side = component["side"] == "candidate"
    baseline_scan_alternative = (
        not candidate_side
        and category == "scan"
        and workload["baseline_id"] is None
        and workload["phase"] in {"helper_cache_miss", "end_to_end"}
    )
    shared_acquisition_cost = (
        not candidate_side
        and component["application"] == "fixed"
        and category in {"source_profiling", "bank_build"}
        and workload["baseline_id"] is None
    )
    if (
        not baseline_scan_alternative
        and not shared_acquisition_cost
        and candidate_side != (workload["baseline_id"] is None)
    ):
        return None
    if source == "workload_median_seconds":
        expected_phase = {
            "source_profiling": "source_profile",
            "bank_build": "source_build",
            "cold_compile": "cold_compile",
        }.get(category)
        if component["application"] != "fixed" or expected_phase is None or workload["phase"] != expected_phase:
            return None
        return float(workload_statistics["median_seconds"])
    allowed_scan_phases = {"direct_bank_scan"} if candidate_side else {"helper_cache_miss", "end_to_end"}
    if component["application"] != "per_unit" or category != "scan" or workload["phase"] not in allowed_scan_phases:
        return None
    metric_by_source = {
        "workload_seconds_per_document": ("document", "seconds_per_document"),
        "workload_seconds_per_scan": ("scan", "median_seconds"),
        "workload_seconds_per_mib": ("mib", "mib_per_second"),
        "workload_seconds_per_record": ("record", "records_per_second"),
    }
    expected_unit, metric = metric_by_source[source]
    if model["parameter_unit"] != expected_unit:
        return None
    metric_value = workload_statistics[metric]
    if metric_value is None or metric_value <= 0:
        return None
    if source in {"workload_seconds_per_mib", "workload_seconds_per_record"}:
        return 1.0 / float(metric_value)
    if source == "workload_seconds_per_scan":
        return float(metric_value) / int(workload["work_per_sample"])
    return float(metric_value)


def _scale_composition_matches_evaluated(
    scale_bank: Mapping[str, Any], evaluated_bank: Mapping[str, Any], *, tolerance: float = 0.10
) -> bool:
    scale_taxonomy = {str(item["entity_class"]): item for item in scale_bank["composition"]["taxonomy"]}
    evaluated_taxonomy = {str(item["entity_class"]): item for item in evaluated_bank["composition"]["taxonomy"]}
    if set(scale_taxonomy) != set(evaluated_taxonomy):
        return False

    def share(item: Mapping[str, Any], field: str, total: int) -> float:
        return float(item[field]) / total if total else 0.0

    scale_aliases = sum(int(item["aliases"]) for item in scale_taxonomy.values())
    evaluated_aliases = sum(int(item["aliases"]) for item in evaluated_taxonomy.values())
    scale_regex = sum(int(item["regex_patterns"]) for item in scale_taxonomy.values())
    evaluated_regex = sum(int(item["regex_patterns"]) for item in evaluated_taxonomy.values())
    global_pairs = (
        (scale_aliases / scale_bank["active_names"], evaluated_aliases / evaluated_bank["active_names"]),
        (scale_regex / scale_bank["active_patterns"], evaluated_regex / evaluated_bank["active_patterns"]),
        (
            scale_bank["active_names"] / scale_bank["active_patterns"],
            evaluated_bank["active_names"] / evaluated_bank["active_patterns"],
        ),
        (
            scale_bank["active_entities"] / scale_bank["active_patterns"],
            evaluated_bank["active_entities"] / evaluated_bank["active_patterns"],
        ),
    )
    if any(abs(scale_value - evaluated_value) > tolerance for scale_value, evaluated_value in global_pairs):
        return False
    for entity_class, scale_item in scale_taxonomy.items():
        evaluated_item = evaluated_taxonomy[entity_class]
        proportions = (
            (
                share(scale_item, "entities", int(scale_bank["active_entities"])),
                share(evaluated_item, "entities", int(evaluated_bank["active_entities"])),
            ),
            (
                share(scale_item, "canonical_names", int(scale_bank["active_names"])),
                share(evaluated_item, "canonical_names", int(evaluated_bank["active_names"])),
            ),
            (
                share(scale_item, "aliases", int(scale_bank["active_names"])),
                share(evaluated_item, "aliases", int(evaluated_bank["active_names"])),
            ),
            (
                share(scale_item, "literal_patterns", int(scale_bank["active_patterns"])),
                share(evaluated_item, "literal_patterns", int(evaluated_bank["active_patterns"])),
            ),
            (
                share(scale_item, "regex_patterns", int(scale_bank["active_patterns"])),
                share(evaluated_item, "regex_patterns", int(evaluated_bank["active_patterns"])),
            ),
        )
        if any(abs(scale_value - evaluated_value) > tolerance for scale_value, evaluated_value in proportions):
            return False
    return True


def _performance_promotion_diagnostics(
    evidence: Mapping[str, Any],
) -> tuple[list[Diagnostic], dict[str, tuple[str, Any | None]]]:
    diagnostics: list[Diagnostic] = []
    performance = evidence["performance"]
    banks = performance["banks"]
    inputs = {str(item["id"]): item for item in performance["inputs"]}
    workloads = performance["workloads"]
    evaluated_bank = next((item for item in banks if item["kind"] == "evaluated_bank"), None)
    promotion_indices = [index for index, item in enumerate(workloads) if item["promotion_gate"]]
    latency_indices = [index for index in promotion_indices if workloads[index]["sample_unit"] == "document"]
    throughput_indices = [index for index in promotion_indices if workloads[index]["sample_unit"] == "whole_input"]
    if len(latency_indices) != 1:
        diagnostics.append(
            _error(
                "contract.performance_latency_headline_gate",
                "/performance/workloads",
                "Promotion requires exactly one per-document latency headline on the evaluated bank.",
            )
        )
    if len(throughput_indices) != 1:
        diagnostics.append(
            _error(
                "contract.performance_throughput_headline_gate",
                "/performance/workloads",
                "Promotion requires exactly one whole-input throughput headline on the evaluated bank.",
            )
        )
    headline_indices = latency_indices + throughput_indices
    for index in headline_indices:
        item = workloads[index]
        if (
            evaluated_bank is None
            or item["bank_id"] != evaluated_bank["id"]
            or item["bank_hash"] != evaluated_bank["bank_hash"]
            or item["phase"] != "direct_bank_scan"
            or item["process_model"] != "reused_process"
            or item["work_per_sample"] != 1
            or inputs.get(str(item["input_id"]), {}).get("kind") != "real_input"
            or item["baseline_id"] is not None
            or not item["decision_grade"]
            or item["warmups"] < MIN_DECISION_GRADE_WARMUPS
            or item["stats"]["sample_count"] < MIN_DECISION_GRADE_SCAN_SAMPLES
            or item["peak_rss_bytes"] is None
        ):
            diagnostics.append(
                _error(
                    "contract.invalid_performance_headline",
                    f"/performance/workloads/{index}",
                    "Headline performance must be a decision-grade direct scan of one real evaluated-bank input.",
                )
            )
    if (
        len(headline_indices) == 2
        and workloads[headline_indices[0]]["input_id"] != workloads[headline_indices[1]]["input_id"]
    ):
        diagnostics.append(
            _error(
                "contract.performance_headline_input_mismatch",
                "/performance/workloads",
                "Latency and throughput headlines must measure the exact same content-addressed real input.",
            )
        )

    decision_indices = [index for index, item in enumerate(workloads) if item["decision_grade"]]
    required_gate_specs: dict[str, tuple[str, Any | None]] = {}
    for index in decision_indices:
        item = workloads[index]
        path = f"/performance/workloads/{index}"
        required_gate_specs.update(
            {
                f"{path}/stats/median_seconds": ("lte", None),
                f"{path}/stats/p95_seconds": ("lte", None),
                f"{path}/peak_rss_bytes": ("lte", None),
            }
        )
        if item["phase"] in PERFORMANCE_SETUP_PHASES:
            required_gate_specs[f"{path}/stats/mad_seconds"] = ("lte", None)
        else:
            required_gate_specs[f"{path}/stats/p99_seconds"] = ("lte", None)
        if item["sample_unit"] == "document":
            required_gate_specs[f"{path}/stats/seconds_per_document"] = ("lte", None)
        elif item["sample_unit"] == "whole_input":
            required_gate_specs.update(
                {
                    f"{path}/stats/documents_per_second": ("gte", None),
                    f"{path}/stats/mib_per_second": ("gte", None),
                }
            )

    missing_phases = []
    for phase in PERFORMANCE_PHASES:
        phase_cells = [
            item
            for item in workloads
            if item["decision_grade"]
            and item["baseline_id"] is None
            and evaluated_bank is not None
            and item["bank_id"] == evaluated_bank["id"]
            and item["bank_hash"] == evaluated_bank["bank_hash"]
            and item["phase"] == phase
        ]
        if not phase_cells:
            missing_phases.append(phase)
    if missing_phases:
        diagnostics.append(
            _error(
                "contract.missing_performance_phase",
                "/performance/workloads",
                "Promoted evaluated-bank evidence is missing a decision-grade lifecycle phase.",
            )
        )
    scale_banks: dict[int, list[Mapping[str, Any]]] = {}
    required_scale_descriptors: list[Mapping[str, Any]] = []
    for item in banks:
        if item["kind"] == "synthetic_scale":
            scale_banks.setdefault(int(item["active_patterns"]), []).append(item)
    for pattern_count in PERFORMANCE_SCALE_PATTERNS:
        descriptors = scale_banks.get(pattern_count, [])
        if len(descriptors) != 1:
            diagnostics.append(
                _error(
                    "contract.missing_scale_shape",
                    "/performance/banks",
                    "Promotion requires exactly one content-addressed bank for every required matcher-pattern scale.",
                )
            )
            continue
        descriptor = descriptors[0]
        required_scale_descriptors.append(descriptor)
        if evaluated_bank is not None and not _scale_composition_matches_evaluated(descriptor, evaluated_bank):
            diagnostics.append(
                _error(
                    "contract.unrealistic_scale_bank",
                    "/performance/banks",
                    "Synthetic matcher-pattern scale composition must preserve the evaluated taxonomy and "
                    "name/alias/literal/regex proportions.",
                )
            )
        cells = [
            item
            for item in workloads
            if item["bank_id"] == descriptor["id"]
            and item["bank_hash"] == descriptor["bank_hash"]
            and item["phase"] == "direct_bank_scan"
            and item["decision_grade"]
            and item["baseline_id"] is None
            and item["sample_unit"] == "whole_input"
            and inputs.get(str(item["input_id"]), {}).get("kind") == "synthetic_input"
        ]
        if not cells:
            diagnostics.append(
                _error(
                    "contract.missing_scale_decision_cell",
                    "/performance/workloads",
                    "Every required scale bank needs a direct decision-grade workload cell.",
                )
            )
    if len(required_scale_descriptors) == len(PERFORMANCE_SCALE_PATTERNS) and all(
        descriptor["generator"] is not None for descriptor in required_scale_descriptors
    ):
        generator_families = {
            (
                descriptor["generator"]["id"],
                descriptor["generator"]["version"],
                descriptor["generator"]["source_sha256"],
                descriptor["generator"]["spec_sha256"],
            )
            for descriptor in required_scale_descriptors
        }
        if len(generator_families) != 1:
            diagnostics.append(
                _error(
                    "contract.uncontrolled_scale_generator_family",
                    "/performance/banks",
                    "Required scale banks must share one versioned generator implementation and specification.",
                )
            )
    direct_cells = [
        (item, inputs[str(item["input_id"])])
        for item in workloads
        if item["decision_grade"]
        and item["baseline_id"] is None
        and item["phase"] == "direct_bank_scan"
        and str(item["input_id"]) in inputs
    ]
    scale_patterns_by_bank_id = {
        str(item["id"]): int(item["active_patterns"]) for item in banks if item["kind"] == "synthetic_scale"
    }
    scale_families: dict[tuple[Any, ...], set[int]] = {}
    concurrency_families: dict[tuple[Any, ...], set[int]] = {}
    density_families: dict[tuple[Any, ...], set[str]] = {}
    size_families: dict[tuple[Any, ...], set[str]] = {}
    for item, input_descriptor in direct_cells:
        generator = input_descriptor["generator"]
        generator_family = (
            input_descriptor["kind"],
            None if generator is None else (generator["id"], generator["version"], generator["source_sha256"]),
        )
        sample_shape = (
            item["harness_id"],
            item["harness_sha256"],
            item["sample_unit"],
            int(item["work_per_sample"]),
            item["process_model"],
            int(item["warmups"]),
            int(item["stats"]["sample_count"]),
        )
        scale_pattern_count = scale_patterns_by_bank_id.get(str(item["bank_id"]))
        if (
            scale_pattern_count is not None
            and input_descriptor["kind"] == "synthetic_input"
            and input_descriptor["hit_density"] == "negative"
            and input_descriptor["size_cohort"] == "medium"
            and item["sample_unit"] == "whole_input"
            and item["concurrency"] == 1
        ):
            input_shape = _canonical_hash(
                {
                    "artifact": {
                        "sha256": input_descriptor["artifact"]["sha256"],
                        "bytes": input_descriptor["artifact"]["bytes"],
                    },
                    "inventory_ref": {
                        "sha256": input_descriptor["inventory_ref"]["sha256"],
                        "bytes": input_descriptor["inventory_ref"]["bytes"],
                    },
                    "documents": input_descriptor["documents"],
                    "bytes": input_descriptor["bytes"],
                    "records": input_descriptor["records"],
                    "document_length_distribution": input_descriptor["document_length_distribution"],
                    "hit_distribution": input_descriptor["hit_distribution"],
                }
            )
            scale_families.setdefault((input_shape, int(item["concurrency"]), *sample_shape), set()).add(
                scale_pattern_count
            )
        concurrency_key = (
            item["bank_id"],
            item["bank_hash"],
            item["input_id"],
            item["input_sha256"],
            *sample_shape,
        )
        concurrency_families.setdefault(concurrency_key, set()).add(int(item["concurrency"]))
        if input_descriptor["kind"] == "synthetic_input":
            density_key = (
                item["bank_id"],
                item["bank_hash"],
                input_descriptor["size_cohort"],
                int(input_descriptor["documents"]),
                int(input_descriptor["bytes"]),
                _canonical_hash(input_descriptor["document_length_distribution"]),
                generator_family,
                int(item["concurrency"]),
                *sample_shape,
            )
            density_families.setdefault(density_key, set()).add(str(input_descriptor["hit_density"]))
            size_key = (
                item["bank_id"],
                item["bank_hash"],
                input_descriptor["hit_density"],
                int(input_descriptor["documents"]),
                int(input_descriptor["records"]),
                _canonical_hash(input_descriptor["hit_distribution"]),
                generator_family,
                int(item["concurrency"]),
                *sample_shape,
            )
            size_families.setdefault(size_key, set()).add(str(input_descriptor["size_cohort"]))

    if not any(set(PERFORMANCE_SCALE_PATTERNS) <= values for values in scale_families.values()):
        diagnostics.append(
            _error(
                "contract.uncontrolled_scale_sweep",
                "/performance/workloads",
                "Matcher-pattern scale evidence must hold one canonical negative, medium, serial whole-input workload "
                "shape constant.",
            )
        )
    if not any(1 in values and any(value > 1 for value in values) for values in concurrency_families.values()):
        diagnostics.append(
            _error(
                "contract.uncontrolled_concurrency_sweep",
                "/performance/workloads",
                "Concurrency evidence must pair serial and concurrent cells on the exact same bank, input, and work.",
            )
        )
    if not any({"negative", "sparse", "normal", "dense"} <= values for values in density_families.values()):
        diagnostics.append(
            _error(
                "contract.uncontrolled_density_sweep",
                "/performance/workloads",
                "Density evidence requires generated inputs with one bank, size, generator family, concurrency, "
                "and work.",
            )
        )
    if not any({"small", "medium", "large", "huge"} <= values for values in size_families.values()):
        diagnostics.append(
            _error(
                "contract.uncontrolled_size_sweep",
                "/performance/workloads",
                "Size evidence requires generated inputs with one bank, density, generator family, concurrency, "
                "and work.",
            )
        )
    concurrencies = {int(workloads[index]["concurrency"]) for index in decision_indices}
    if any(value > evidence["environment"]["cpu_count"] for value in concurrencies):
        diagnostics.append(
            _error(
                "contract.performance_concurrency_bounds",
                "/performance/workloads",
                "Decision-grade concurrency cannot exceed the recorded machine CPU count.",
            )
        )
    if any(
        workloads[index]["peak_rss_bytes"] is not None
        and workloads[index]["peak_rss_bytes"] > evidence["environment"]["memory_bytes"]
        for index in decision_indices
    ):
        diagnostics.append(
            _error(
                "contract.performance_memory_bounds",
                "/performance/workloads",
                "Decision-grade peak RSS cannot exceed the recorded machine memory capacity.",
            )
        )
    command_by_id = {str(item["id"]): item for item in evidence["commands"]}
    harness_by_id = {str(item["id"]): item for item in performance["harnesses"]}
    required_command_workload_ids = {str(workloads[index]["id"]) for index in decision_indices}
    required_command_workload_ids.update(
        str(comparison["baseline_workload_id"])
        for comparison in performance["comparisons"]
        if str(comparison["candidate_workload_id"]) in required_command_workload_ids
    )
    required_command_workloads = [
        workload for workload in workloads if str(workload["id"]) in required_command_workload_ids
    ]
    decision_commands = [
        command_by_id.get(str(harness_by_id[str(workload["harness_id"])]["command_id"]))
        for workload in required_command_workloads
        if str(workload["harness_id"]) in harness_by_id
    ]
    if len(decision_commands) != len(required_command_workloads) or any(
        command is None or command["exit_status"] != 0 for command in decision_commands
    ):
        diagnostics.append(
            _error(
                "contract.performance_command_failure",
                "/commands",
                "Decision-grade performance and its exact baselines require successful declared harness commands.",
            )
        )
    workload_by_id = {str(item["id"]): item for item in workloads}
    baseline_by_id = {str(item["id"]): item for item in performance["baselines"]}
    comparisons = performance["comparisons"]
    for index in decision_indices:
        candidate = workloads[index]
        tail_metric = "p95_seconds" if candidate["phase"] in PERFORMANCE_SETUP_PHASES else "p99_seconds"
        required_metrics = {tail_metric}
        if candidate["sample_unit"] == "whole_input":
            required_metrics.add("mib_per_second")
        candidate_comparisons = [
            item
            for item in comparisons
            if item["candidate_workload_id"] == candidate["id"] and item["comparison_kind"] == "same_path_stability"
        ]
        observed_metrics = {str(item["metric"]) for item in candidate_comparisons}
        baseline_cells = [workload_by_id.get(str(item["baseline_workload_id"])) for item in candidate_comparisons]
        if (
            not required_metrics <= observed_metrics
            or any(item["result"] == "regressed" for item in candidate_comparisons)
            or any(
                cell is None
                or cell["stats"]["sample_count"]
                < (
                    MIN_DECISION_GRADE_SETUP_SAMPLES
                    if candidate["phase"] in PERFORMANCE_SETUP_PHASES
                    else MIN_DECISION_GRADE_SCAN_SAMPLES
                )
                or cell["baseline_id"] not in baseline_by_id
                or baseline_by_id[str(cell["baseline_id"])]["semantic_equivalence"] != "exact"
                for cell in baseline_cells
            )
        ):
            diagnostics.append(
                _error(
                    "contract.performance_regression_coverage",
                    f"/performance/workloads/{index}",
                    "Every decision cell requires a supported phase-appropriate, non-regressed, same-machine exact-"
                    "baseline tail comparison, plus throughput comparison for whole-input work.",
                )
            )

    value_models = performance["breakeven_models"]
    required_component_roles = {
        ("candidate", "fixed", "source_curation"),
        ("candidate", "fixed", "source_profiling"),
        ("candidate", "fixed", "bank_build"),
        ("candidate", "fixed", "cold_compile"),
        ("candidate", "per_unit", "scan"),
        ("baseline", "fixed", "source_curation"),
        ("baseline", "fixed", "source_profiling"),
        ("baseline", "fixed", "bank_build"),
        ("baseline", "per_unit", "scan"),
    }
    acceptable_value_model = False
    decision_workload_ids = {str(workloads[index]["id"]) for index in decision_indices}
    for model in value_models:
        components_by_role: dict[tuple[str, str, str], list[Mapping[str, Any]]] = {}
        for component in model["components"]:
            role = (str(component["side"]), str(component["application"]), str(component["category"]))
            components_by_role.setdefault(role, []).append(component)
        required_components = {role: components_by_role.get(role, []) for role in required_component_roles}
        if set(components_by_role) != required_component_roles or any(
            len(items) != 1 for items in required_components.values()
        ):
            continue
        curation = required_components[("candidate", "fixed", "source_curation")][0]
        source_profiling = required_components[("candidate", "fixed", "source_profiling")][0]
        bank_build = required_components[("candidate", "fixed", "bank_build")][0]
        cold_compile = required_components[("candidate", "fixed", "cold_compile")][0]
        candidate_scan = required_components[("candidate", "per_unit", "scan")][0]
        baseline_curation = required_components[("baseline", "fixed", "source_curation")][0]
        baseline_source_profiling = required_components[("baseline", "fixed", "source_profiling")][0]
        baseline_bank_build = required_components[("baseline", "fixed", "bank_build")][0]
        baseline_scan = required_components[("baseline", "per_unit", "scan")][0]
        source_profiling_workload = workload_by_id.get(str(source_profiling["workload_id"]))
        bank_build_workload = workload_by_id.get(str(bank_build["workload_id"]))
        cold_compile_workload = workload_by_id.get(str(cold_compile["workload_id"]))
        candidate_scan_workload = workload_by_id.get(str(candidate_scan["workload_id"]))
        baseline_scan_workload = workload_by_id.get(str(baseline_scan["workload_id"]))
        value_pair_fields = (
            "bank_id",
            "bank_hash",
            "input_id",
            "input_sha256",
            "work_per_sample",
            "concurrency",
        )
        candidate_control_comparisons = (
            []
            if candidate_scan_workload is None
            else [
                item
                for item in comparisons
                if item["candidate_workload_id"] == candidate_scan_workload["id"]
                and item["metric"] == "p99_seconds"
                and item["comparison_kind"] == "same_path_stability"
            ]
        )
        baseline_control_comparisons = (
            []
            if baseline_scan_workload is None
            else [
                item
                for item in comparisons
                if item["candidate_workload_id"] == baseline_scan_workload["id"]
                and item["metric"] == "p99_seconds"
                and item["comparison_kind"] == "same_path_stability"
            ]
        )
        has_same_path_controls = (
            len(candidate_control_comparisons) == 1
            and candidate_control_comparisons[0]["result"] != "regressed"
            and workload_by_id[str(candidate_control_comparisons[0]["baseline_workload_id"])]["baseline_id"]
            in baseline_by_id
            and baseline_by_id[
                str(workload_by_id[str(candidate_control_comparisons[0]["baseline_workload_id"])]["baseline_id"])
            ]["semantic_equivalence"]
            == "exact"
            and len(baseline_control_comparisons) == 1
            and baseline_control_comparisons[0]["result"] != "regressed"
            and workload_by_id[str(baseline_control_comparisons[0]["baseline_workload_id"])]["baseline_id"]
            in baseline_by_id
            and baseline_by_id[
                str(workload_by_id[str(baseline_control_comparisons[0]["baseline_workload_id"])]["baseline_id"])
            ]["semantic_equivalence"]
            == "exact"
        )
        measured_workloads = [
            workload_by_id.get(str(component["workload_id"]))
            for component in model["components"]
            if component["source"] != "declared_assumption"
        ]
        all_measured_on_evaluated_bank = evaluated_bank is not None and all(
            item is not None
            and item["bank_id"] == evaluated_bank["id"]
            and item["bank_hash"] == evaluated_bank["bank_hash"]
            for item in measured_workloads
        )
        promoted_throughput_workload = workloads[throughput_indices[0]] if len(throughput_indices) == 1 else None
        cache_value_comparisons = (
            []
            if candidate_scan_workload is None or baseline_scan_workload is None
            else [
                item
                for item in comparisons
                if item["candidate_workload_id"] == candidate_scan_workload["id"]
                and item["baseline_workload_id"] == baseline_scan_workload["id"]
                and item["comparison_kind"] == "cross_path_value"
                and item["metric"] == "p99_seconds"
            ]
        )
        shared_acquisition_pairs = (
            (curation, baseline_curation),
            (source_profiling, baseline_source_profiling),
            (bank_build, baseline_bank_build),
        )
        shared_acquisition_fields = ("category", "source", "workload_id", "assumption_sha256", "value")
        shared_acquisition_cancels = all(
            all(candidate_component[field] == baseline_component[field] for field in shared_acquisition_fields)
            for candidate_component, baseline_component in shared_acquisition_pairs
        )
        if (
            model["parameter_unit"] == "document"
            and model["value_unit"] == "seconds"
            and curation["source"] == "declared_assumption"
            and curation["value"] > 0
            and shared_acquisition_cancels
            and source_profiling_workload is not None
            and str(source_profiling_workload["id"]) in decision_workload_ids
            and source_profiling_workload["phase"] == "source_profile"
            and source_profiling["source"] == "workload_median_seconds"
            and bank_build_workload is not None
            and str(bank_build_workload["id"]) in decision_workload_ids
            and bank_build_workload["phase"] == "source_build"
            and cold_compile_workload is not None
            and str(cold_compile_workload["id"]) in decision_workload_ids
            and cold_compile_workload["phase"] == "cold_compile"
            and candidate_scan_workload is not None
            and str(candidate_scan_workload["id"]) in decision_workload_ids
            and candidate_scan_workload["phase"] == "direct_bank_scan"
            and candidate_scan_workload["sample_unit"] == "whole_input"
            and promoted_throughput_workload is not None
            and candidate_scan_workload["id"] == promoted_throughput_workload["id"]
            and candidate_scan["source"] == "workload_seconds_per_document"
            and baseline_scan_workload is not None
            and baseline_scan_workload["phase"] in {"helper_cache_miss", "end_to_end"}
            and baseline_scan_workload["sample_unit"] == "whole_input"
            and all(candidate_scan_workload[field] == baseline_scan_workload[field] for field in value_pair_fields)
            and baseline_scan_workload["baseline_id"] is None
            and baseline_scan["source"] == "workload_seconds_per_document"
            and has_same_path_controls
            and len(cache_value_comparisons) == 1
            and cache_value_comparisons[0]["result"] != "regressed"
            and all_measured_on_evaluated_bank
            and model["result"] in {"candidate_already_better", "finite_breakeven"}
        ):
            acceptable_value_model = True
            break
    if not acceptable_value_model:
        diagnostics.append(
            _error(
                "contract.missing_breakeven_value_model",
                "/performance/breakeven_models",
                "Promotion requires an evaluated-bank document-value model that records identical shared curation, "
                "profiling, and build costs on both cache paths, then separates one-time compile, promoted direct "
                "reuse, and an exact NERB uncached or end-to-end alternative with independent same-path controls.",
            )
        )
    return diagnostics, required_gate_specs


def _gate_diagnostics(
    evidence: Mapping[str, Any], recomputed_statistics: Mapping[str, Mapping[str, Any]]
) -> list[Diagnostic]:
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
        if check["category"] == "performance" and not _supported_performance_gate_target(check["target"]):
            diagnostics.append(
                _error(
                    "contract.gate_target",
                    f"{path}/target",
                    "Performance gates must target a recomputed workload statistic or raw peak RSS.",
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
        if not _same_json_scalar(check["actual"], actual):
            diagnostics.append(
                _error(
                    "contract.gate_actual",
                    f"{path}/actual",
                    "Declared gate actual value differs from the targeted evidence value.",
                )
            )
        comparison_actual = _recomputed_gate_value(evidence, check["target"], actual, recomputed_statistics)
        expected_pass = _compare_gate(comparison_actual, check["operator"], check["threshold"])
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
                    "Gate result does not match the recomputed source-value comparison.",
                )
            )
    return diagnostics


def _supported_performance_gate_target(target: str) -> bool:
    parts = target.split("/")
    if len(parts) == 5 and parts[1:3] == ["performance", "workloads"]:
        return parts[3].isdigit() and parts[4] == "peak_rss_bytes"
    return (
        len(parts) == 6
        and parts[1:3] == ["performance", "workloads"]
        and parts[3].isdigit()
        and parts[4] == "stats"
        and parts[5] in PERFORMANCE_GATE_STAT_FIELDS
    )


def _recomputed_gate_value(
    evidence: Mapping[str, Any],
    target: str,
    stored_value: Any,
    recomputed_statistics: Mapping[str, Mapping[str, Any]],
) -> Any:
    parts = target.split("/")
    if len(parts) == 6 and parts[1:3] == ["quality", "slices"] and parts[4] == "metrics":
        try:
            item = evidence["quality"]["slices"][int(parts[3])]
        except (IndexError, TypeError, ValueError):
            return stored_value
        metric_value = _quality_gate_metric_value(item, parts[5])
        return stored_value if metric_value is _UNSUPPORTED_GATE_SOURCE else metric_value
    if target == "/catalog_conformance/recall":
        conformance = evidence["catalog_conformance"]
        support = conformance["approved_positive_cases"]
        return Fraction(conformance["correctly_mapped"], support) if support else None
    if len(parts) == 6 and parts[1:3] == ["performance", "workloads"] and parts[4] == "stats":
        return _recomputed_performance_gate_value(
            evidence,
            parts[3],
            parts[5],
            stored_value,
            recomputed_statistics,
        )
    return stored_value


_UNSUPPORTED_GATE_SOURCE = object()


def _quality_gate_metric_value(item: Mapping[str, Any], field: str) -> Fraction | None | object:
    open_world_eligible = (
        item["label_strength"] == "independent" and item["annotation_completeness"] == "exhaustive_within_scope"
    )
    open_world_fields = {
        "precision",
        "open_world_recall",
        "f1",
        "document_leak_rate",
        "cataloged_document_leak_rate",
        "sensitive_character_recall",
        "sensitive_character_leak_rate",
        "negative_document_false_alarm_rate",
        "over_redaction_rate",
    }
    if field in open_world_fields and not open_world_eligible:
        return None
    ratios = {
        "precision": (item["true_positive"], item["predicted_spans"]),
        "open_world_recall": (item["true_positive"], item["gold_spans"]),
        "f1": (
            2 * item["true_positive"],
            2 * item["true_positive"] + item["false_positive"] + item["false_negative"],
        ),
        "catalog_coverage": (item["cataloged_gold_spans"], item["gold_spans"]),
        "cataloged_recall": (item["cataloged_true_positive"], item["cataloged_gold_spans"]),
        "document_leak_rate": (item["documents_with_any_miss"], item["documents_with_sensitive_gold"]),
        "cataloged_document_leak_rate": (
            item["documents_with_any_cataloged_miss"],
            item["documents_with_cataloged_gold"],
        ),
        "sensitive_character_recall": (
            item["covered_sensitive_characters"],
            item["sensitive_gold_characters"],
        ),
        "sensitive_character_leak_rate": (
            item["leaked_sensitive_characters"],
            item["sensitive_gold_characters"],
        ),
        "negative_document_false_alarm_rate": (
            item["negative_documents_with_predictions"],
            item["negative_documents"],
        ),
        "over_redaction_rate": (item["over_redacted_characters"], item["evaluated_characters"]),
    }
    ratio = ratios.get(field)
    if ratio is None:
        return _UNSUPPORTED_GATE_SOURCE
    numerator, denominator = ratio
    return Fraction(numerator, denominator) if denominator else None


def _recomputed_performance_gate_value(
    evidence: Mapping[str, Any],
    workload_index: str,
    field: str,
    stored_value: Any,
    recomputed_statistics: Mapping[str, Mapping[str, Any]],
) -> Any:
    try:
        workload = evidence["performance"]["workloads"][int(workload_index)]
    except (IndexError, TypeError, ValueError):
        return stored_value
    statistics = recomputed_statistics.get(str(workload["id"]))
    if statistics is None:
        return stored_value
    return statistics[field] if field in statistics else stored_value


def _decision_grade_diagnostics(evidence: Mapping[str, Any], manifest: Mapping[str, Any] | None) -> list[Diagnostic]:
    promotion = evidence["promotion"]
    diagnostics: list[Diagnostic] = []
    current_version = evidence["test_access"]["benchmark_version"]
    lineage = evidence["test_access"]["lineage"]
    current_lineage_passed = (
        evidence["test_access"]["current_version_access_count"] == 1
        and bool(lineage)
        and lineage[-1]["benchmark_version"] == current_version
        and lineage[-1]["outcome"] == "passed"
    )
    manifest_bound = (
        manifest is not None
        and validate_enron_manifest(manifest)["valid"]
        and evidence["manifest_sha256"] == hash_enron_manifest(manifest)
    )
    requirements = {
        "quality evaluated": evidence["quality"]["evaluated"],
        "catalog conformance evaluated": evidence["catalog_conformance"]["evaluated"],
        "catalog conformance passed": evidence["catalog_conformance"]["passed"],
        "performance evaluated": evidence["performance"]["evaluated"],
        "privacy passed": evidence["privacy"]["status"] == "passed",
        "all declared checks passed": all(item["passed"] for item in promotion["checks"]),
        "clean git state": evidence["software"]["git_dirty"] is False,
        "one-shot final test": evidence["test_access"]["current_version_access_count"] == 1,
        "matching passed current lineage": current_lineage_passed,
        "real benchmark artifact": evidence["artifact_kind"] == "real_benchmark",
        "exact valid manifest binding": manifest_bound,
    }
    for passed in requirements.values():
        if not passed:
            diagnostics.append(
                _error(
                    "contract.decision_grade_prerequisite",
                    "/verifier/passed" if evidence["verifier"]["passed"] else "/promotion/passed",
                    "A required decision-grade verification prerequisite is missing or false.",
                )
            )
    required_gate_specs: dict[str, tuple[str, Any | None]] = {
        "/catalog_conformance/passed": ("eq", True),
        "/privacy/status": ("eq", "passed"),
        "/software/git_dirty": ("eq", False),
    }
    quality_diagnostics, quality_gate_specs = _quality_decision_grade_diagnostics(evidence, manifest)
    diagnostics.extend(quality_diagnostics)
    required_gate_specs.update(quality_gate_specs)
    performance_diagnostics, performance_gate_specs = _performance_promotion_diagnostics(evidence)
    diagnostics.extend(performance_diagnostics)
    required_gate_specs.update(performance_gate_specs)
    practical_performance_bounds: dict[str, tuple[str, float]] = {}
    performance_inputs = {str(item["id"]): item for item in evidence["performance"]["inputs"]}
    for index, workload in enumerate(evidence["performance"]["workloads"]):
        if (
            not workload["decision_grade"]
            or workload["baseline_id"] is not None
            or workload["phase"] != "direct_bank_scan"
        ):
            continue
        path = f"/performance/workloads/{index}"
        practical_performance_bounds[f"{path}/peak_rss_bytes"] = ("lte", float(MAX_HEADLINE_PEAK_RSS_BYTES))
        if workload["sample_unit"] == "document":
            practical_performance_bounds[f"{path}/stats/p99_seconds"] = (
                "lte",
                MAX_HEADLINE_DOCUMENT_P99_SECONDS,
            )
        elif workload["sample_unit"] == "whole_input":
            practical_performance_bounds[f"{path}/stats/documents_per_second"] = (
                "gte",
                MIN_HEADLINE_DOCUMENTS_PER_SECOND,
            )
            practical_performance_bounds[f"{path}/stats/mib_per_second"] = (
                "gte",
                MIN_HEADLINE_MIB_PER_SECOND,
            )
            input_descriptor = performance_inputs.get(str(workload["input_id"]))
            if input_descriptor is not None:
                tail_seconds_bound = min(
                    float(input_descriptor["documents"]) / MIN_HEADLINE_DOCUMENTS_PER_SECOND,
                    (float(input_descriptor["bytes"]) / (1024 * 1024)) / MIN_HEADLINE_MIB_PER_SECOND,
                )
                practical_performance_bounds[f"{path}/stats/p99_seconds"] = ("lte", tail_seconds_bound)
    checks_by_target = {str(item["target"]): item for item in promotion["checks"]}
    missing_targets = sorted(set(required_gate_specs) - set(checks_by_target))
    if missing_targets:
        diagnostics.append(
            _error(
                "contract.missing_required_gate",
                "/promotion/checks",
                "Required promotion gate targets are missing.",
            )
        )
    for target, (operator, exact_threshold) in required_gate_specs.items():
        check = checks_by_target.get(target)
        if check is None:
            continue
        if check["operator"] != operator or (
            exact_threshold is not None and not _same_json_scalar(check["threshold"], exact_threshold)
        ):
            diagnostics.append(
                _error(
                    "contract.required_gate_semantics",
                    "/promotion/checks",
                    "Required gate does not use its mandated operator and threshold semantics.",
                )
            )
        threshold = check["threshold"]
        if "/quality/slices/" in target and "/metrics/" in target:
            valid_unit_threshold = (
                isinstance(threshold, (int, float))
                and not isinstance(threshold, bool)
                and (
                    (operator == "gte" and 0 < float(threshold) <= 1)
                    or (operator == "lte" and 0 <= float(threshold) < 1)
                )
            )
            if not valid_unit_threshold:
                diagnostics.append(
                    _error(
                        "contract.vacuous_quality_threshold",
                        "/promotion/checks",
                        "Decision-grade quality thresholds must be non-vacuous values inside the unit interval.",
                    )
                )
            elif isinstance(threshold, (int, float)) and not isinstance(threshold, bool):
                metric = target.rsplit("/", 1)[-1]
                policy_floor = MIN_QUALITY_THRESHOLDS.get(metric)
                policy_ceiling = MAX_QUALITY_THRESHOLDS.get(metric)
                if (policy_floor is not None and float(threshold) < policy_floor) or (
                    policy_ceiling is not None and float(threshold) > policy_ceiling
                ):
                    diagnostics.append(
                        _error(
                            "contract.quality_threshold_policy",
                            "/promotion/checks",
                            "Privacy thresholds may tighten but cannot weaken the benchmark-v2 policy bounds.",
                        )
                    )
        elif target.startswith("/performance/workloads/") and exact_threshold is None:
            if isinstance(threshold, bool) or not isinstance(threshold, (int, float)) or float(threshold) <= 0:
                diagnostics.append(
                    _error(
                        "contract.vacuous_performance_threshold",
                        "/promotion/checks",
                        "Decision-grade performance thresholds must be strictly positive.",
                    )
                )
            elif target in practical_performance_bounds:
                policy_operator, policy_bound = practical_performance_bounds[target]
                weak_policy = (policy_operator == "lte" and float(threshold) > policy_bound) or (
                    policy_operator == "gte" and float(threshold) < policy_bound
                )
                if weak_policy:
                    diagnostics.append(
                        _error(
                            "contract.performance_threshold_policy",
                            "/promotion/checks",
                            "Direct-scan thresholds may tighten but cannot weaken practical latency, throughput, "
                            "or RSS bounds at any required scale.",
                        )
                    )
    return diagnostics


def _promotion_diagnostics(
    evidence: Mapping[str, Any], recomputed_statistics: Mapping[str, Mapping[str, Any]]
) -> list[Diagnostic]:
    promotion = evidence["promotion"]
    diagnostics = _claim_diagnostics(evidence, recomputed_statistics)
    if promotion["claims"] and not evidence["verifier"]["passed"]:
        diagnostics.append(
            _error(
                "contract.unverified_claims",
                "/promotion/claims",
                "Public structured claims require a passed decision-grade verifier result.",
            )
        )
    if not promotion["passed"]:
        return diagnostics
    if not evidence["verifier"]["passed"]:
        diagnostics.append(
            _error(
                "contract.promotion_prerequisite",
                "/promotion/passed",
                "Promotion requires an independently passed verifier result.",
            )
        )
    if not promotion["claims"]:
        diagnostics.append(
            _error(
                "contract.promotion_prerequisite",
                "/promotion/claims",
                "Promotion requires structured claims bound to exact decision-grade support.",
            )
        )
    claims = promotion["claims"]
    quality_claim_metrics = {
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
    }
    missing_quality_support = any(
        not quality_claim_metrics
        <= {str(claim["metric"]) for claim in claims if claim["quality_slice_id"] == item["id"]}
        for item in evidence["quality"]["slices"]
        if item["promotion_gate"]
    )
    workload_by_id = {str(item["id"]): item for item in evidence["performance"]["workloads"]}
    has_document_tail = any(
        claim["metric"] == "direct_bank_scan_p99_seconds"
        and claim["performance_workload_id"] in workload_by_id
        and workload_by_id[str(claim["performance_workload_id"])]["sample_unit"] == "document"
        for claim in claims
    )
    has_whole_input_throughput = any(
        claim["metric"] == "direct_bank_scan_mib_per_second"
        and claim["performance_workload_id"] in workload_by_id
        and workload_by_id[str(claim["performance_workload_id"])]["sample_unit"] == "whole_input"
        for claim in claims
    )
    has_catalog_claim = any(claim["metric"] == "catalog_conformance_recall" for claim in claims)
    if missing_quality_support or not has_document_tail or not has_whole_input_throughput or not has_catalog_claim:
        diagnostics.append(
            _error(
                "contract.missing_required_claim",
                "/promotion/claims",
                "Promotion is missing required structured privacy, guarantee, or performance claims.",
            )
        )
    return diagnostics


def _quality_decision_grade_diagnostics(
    evidence: Mapping[str, Any], manifest: Mapping[str, Any] | None
) -> tuple[list[Diagnostic], dict[str, tuple[str, Any | None]]]:
    diagnostics: list[Diagnostic] = []
    required_gate_specs: dict[str, tuple[str, Any | None]] = {}
    slices = evidence["quality"]["slices"]
    gate_indices = [index for index, item in enumerate(slices) if item["promotion_gate"]]
    if not gate_indices:
        diagnostics.append(
            _error(
                "contract.missing_quality_gate",
                "/quality/slices",
                "Decision-grade evidence requires an independent exhaustive final-test quality gate slice.",
            )
        )
    manifest_valid = manifest is not None and validate_enron_manifest(manifest)["valid"]
    primary_view: Mapping[str, Any] | None = None
    if manifest_valid and manifest is not None:
        bound_primary_view: Mapping[str, Any] = next(
            item for item in manifest["preparation"]["text_views"] if item["primary_for_quality"]
        )
        primary_view = bound_primary_view
        planned_gate_ids = {str(item["id"]) for item in manifest["quality_plan"] if item["promotion_gate"]}
        observed_gate_ids = {str(slices[index]["id"]) for index in gate_indices}
        if observed_gate_ids != planned_gate_ids:
            diagnostics.append(
                _error(
                    "contract.quality_gate_plan_set",
                    "/quality/slices",
                    "Decision-grade evidence must evaluate every and only frozen quality-plan gate descriptor.",
                )
            )
        if bound_primary_view["answer_bearing_fields_included"]:
            diagnostics.append(
                _error(
                    "contract.answer_bearing_quality_view",
                    "/preparation/text_views",
                    "The primary promoted quality view must attest that answer-bearing fields were excluded.",
                )
            )
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
    for index in gate_indices:
        item = slices[index]
        path = f"/quality/slices/{index}"
        if (
            item["label_strength"] != "independent"
            or item["annotation_completeness"] != "exhaustive_within_scope"
            or item["split_role"] != "test"
            or item["cohort"] != "all"
        ):
            diagnostics.append(
                _error(
                    "contract.invalid_quality_gate",
                    f"{path}/promotion_gate",
                    "Decision-grade quality must use the all-document independent exhaustive final-test cohort.",
                )
            )
        if primary_view is not None and item["text_view"] != primary_view["id"]:
            diagnostics.append(
                _error(
                    "contract.quality_gate_primary_view",
                    f"{path}/text_view",
                    "Decision-grade quality must use the manifest's exact primary prepared natural-content view.",
                )
            )
        if primary_view is not None and (
            set(item["annotation_scope"]["document_regions"]) != set(primary_view["document_regions"])
            or item["annotation_scope"]["exclusions"]
        ):
            diagnostics.append(
                _error(
                    "contract.quality_gate_annotation_scope",
                    f"{path}/annotation_scope",
                    "Decision-grade quality must annotate every region in the exact primary view without exclusions.",
                )
            )
        if (
            manifest_valid
            and manifest is not None
            and item["documents"] != manifest["splits"]["roles"]["test"]["records"]
        ):
            diagnostics.append(
                _error(
                    "contract.quality_gate_split_population",
                    f"{path}/documents",
                    "Decision-grade quality must aggregate the entire bound final-test split artifact.",
                )
            )
        if (
            item["gold_spans"] <= 0
            or item["cataloged_gold_spans"] <= 0
            or item["negative_documents"] <= 0
            or item["evaluated_characters"] <= 0
            or item["cataloged_false_negative"] != 0
            or item["cataloged_wrong_canonical"] != 0
            or item["documents_with_any_cataloged_miss"] != 0
        ):
            diagnostics.append(
                _error(
                    "contract.natural_catalog_gate",
                    path,
                    "Decision-grade slices require positive gold/negative support plus zero cataloged misses and "
                    "wrong mappings.",
                )
            )
        for field in (
            "cataloged_false_negative",
            "cataloged_wrong_canonical",
            "documents_with_any_cataloged_miss",
        ):
            required_gate_specs[f"{path}/{field}"] = ("eq", 0)
        for field in quality_metric_fields:
            operator = (
                "gte"
                if field in {"open_world_recall", "catalog_coverage", "cataloged_recall", "sensitive_character_recall"}
                else "lte"
            )
            required_gate_specs[f"{path}/metrics/{field}"] = (operator, None)
    return diagnostics, required_gate_specs


def _claim_diagnostics(
    evidence: Mapping[str, Any], recomputed_statistics: Mapping[str, Mapping[str, Any]]
) -> list[Diagnostic]:
    claims = evidence["promotion"]["claims"]
    diagnostics = _duplicate_id_diagnostics(claims, "/promotion/claims", "claim")
    decision_grade = evidence["promotion"]["passed"] or evidence["verifier"]["passed"]
    slices = {str(item["id"]): item for item in evidence["quality"]["slices"]}
    workloads = {str(item["id"]): item for item in evidence["performance"]["workloads"]}
    expected_environment_hash = hash_enron_environment(evidence["environment"])
    common_expected = {
        "benchmark_version": evidence["test_access"]["benchmark_version"],
        "source_revision": evidence["source"]["revision"],
        "evaluator_source_sha256": evidence["evaluator"]["source_sha256"],
        "environment_sha256": expected_environment_hash,
    }
    quality_metrics = {
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
    }
    higher_is_better_quality = {
        "precision",
        "open_world_recall",
        "f1",
        "catalog_coverage",
        "cataloged_recall",
        "sensitive_character_recall",
    }
    performance_metrics = {
        "direct_bank_scan_median_seconds": "median_seconds",
        "direct_bank_scan_p95_seconds": "p95_seconds",
        "direct_bank_scan_p99_seconds": "p99_seconds",
        "direct_bank_scan_mib_per_second": "mib_per_second",
        "direct_bank_scan_records_per_second": "records_per_second",
        "direct_bank_scan_seconds_per_document": "seconds_per_document",
    }
    document_metrics = {
        "direct_bank_scan_median_seconds",
        "direct_bank_scan_p95_seconds",
        "direct_bank_scan_p99_seconds",
        "direct_bank_scan_seconds_per_document",
    }
    throughput_metrics = {
        "direct_bank_scan_mib_per_second",
        "direct_bank_scan_records_per_second",
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
            conformance = evidence["catalog_conformance"]
            conformance_support = conformance["approved_positive_cases"]
            canonical_conformance_value = (
                Fraction(conformance["correctly_mapped"], conformance_support) if conformance_support else None
            )
            valid = (
                claim["metric"] == "catalog_conformance_recall"
                and claim["quality_slice_id"] is None
                and claim["performance_workload_id"] is None
                and claim["scope"] == null_scope
                and claim["label_strength"] == "synthetic_conformance"
                and claim["annotation_completeness"] == "exhaustive_within_scope"
                and claim["bank_hash"] == evidence["bank"]["canonical_hash"]
                and _claim_value_supported(
                    claim["value"],
                    conformance["recall"],
                    canonical_conformance_value,
                    higher_is_better=True,
                )
                and (not decision_grade or evidence["catalog_conformance"]["passed"])
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
            canonical_quality_value = (
                _UNSUPPORTED_GATE_SOURCE
                if item is None or claim["metric"] not in quality_metrics
                else _quality_gate_metric_value(item, str(claim["metric"]))
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
                and _claim_value_supported(
                    claim["value"],
                    expected_value,
                    canonical_quality_value,
                    higher_is_better=claim["metric"] in higher_is_better_quality,
                )
                and (not decision_grade or item["promotion_gate"])
            )
        else:
            workload = workloads.get(str(claim["performance_workload_id"]))
            stat_field = performance_metrics.get(str(claim["metric"]))
            expected_value = None if workload is None or stat_field is None else workload["stats"][stat_field]
            canonical_stats = None if workload is None else recomputed_statistics.get(str(workload["id"]))
            canonical_performance_value = (
                None if canonical_stats is None or stat_field is None else canonical_stats[stat_field]
            )
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
                and _claim_value_supported(
                    claim["value"],
                    expected_value,
                    canonical_performance_value,
                    higher_is_better=claim["metric"] in throughput_metrics,
                )
                and (
                    (claim["metric"] in document_metrics and workload["sample_unit"] == "document")
                    or (claim["metric"] in throughput_metrics and workload["sample_unit"] == "whole_input")
                )
                and (
                    not decision_grade
                    or (
                        workload["promotion_gate"]
                        and workload["decision_grade"]
                        and workload["bank_hash"] == evidence["bank"]["canonical_hash"]
                    )
                )
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


def _claim_value_supported(
    claimed_value: Any,
    stored_value: Any,
    canonical_value: Any,
    *,
    higher_is_better: bool,
) -> bool:
    if (
        canonical_value is _UNSUPPORTED_GATE_SOURCE
        or canonical_value is None
        or not _same_json_scalar(claimed_value, stored_value)
        or not _same_metric(claimed_value, canonical_value)
    ):
        return False
    if isinstance(canonical_value, Fraction):
        try:
            exact_claim = Fraction(str(claimed_value))
        except (ValueError, ZeroDivisionError):
            return False
        return exact_claim <= canonical_value if higher_is_better else exact_claim >= canonical_value
    return claimed_value <= canonical_value if higher_is_better else claimed_value >= canonical_value


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
                    "Evidence field differs from the supplied manifest.",
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
        "commands",
        "environment",
        "privacy",
    ):
        if evidence[field] != manifest[field]:
            diagnostics.append(
                _error(
                    "contract.provenance_mismatch",
                    f"/{field}",
                    "Evidence field differs from the supplied manifest.",
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
                if len(diagnostics) > MAX_DIAGNOSTICS:
                    return diagnostics
    return diagnostics


def _contains_unsafe_command_path(value: str) -> bool:
    return _contains_unsafe_path_text(value)


def _contains_unsafe_path_text(value: str, *, depth: int = 0) -> bool:
    decoded, converged = _normalize_public_text(value)
    if not converged:
        return True
    local_path_text, url_payloads = _partition_http_url_text(decoded)
    if _contains_unsafe_local_path(local_path_text):
        return True
    nested_payloads = [payload for payload in url_payloads if payload]
    if depth >= 4:
        return bool(nested_payloads)
    return any(_contains_unsafe_path_text(payload, depth=depth + 1) for payload in nested_payloads)


def _contains_unsafe_local_path(value: str) -> bool:
    value = normalize_unicode("NFKC", value).translate(_DEFAULT_IGNORABLE_TRANSLATION)
    if _EMBEDDED_POSIX_PATH_PATTERN.search(value):
        return True
    if _ATTACHED_OPTION_PATH_PATTERN.search(value):
        return True
    if "file://" in value.lower():
        return True
    candidates = [value, *re.split(r"[\s=,:;\[\](){}]+", value)]
    for candidate in candidates:
        candidate = candidate.strip().strip("\"'")
        lowered = candidate.lower()
        if lowered.startswith(("~/", "~\\")):
            return True
        if _WINDOWS_LOCAL_PATH_PATTERN.search(candidate):
            return True
        windows_path = PureWindowsPath(candidate)
        if PurePosixPath(candidate).is_absolute() or windows_path.drive or windows_path.root:
            return True
        if ".." in PurePosixPath(candidate).parts or ".." in windows_path.parts:
            return True
    return False


_STRUCTURED_SSN_PATTERN = re.compile(r"(?<![0-9])[0-9]{3}[- ][0-9]{2}[- ][0-9]{4}(?![0-9])")
_STRUCTURED_PHONE_PATTERN = re.compile(
    r"(?<![0-9])(?:\+?1[ .+-]*)?(?:"
    r"\([0-9]{3}\)[ .+-]*[0-9]{3}[ .+-]*[0-9]{4}"
    r"|[0-9]{3}[ .+-]+[0-9]{3}[ .+-]+[0-9]{4})(?![0-9])"
)
_COMPACT_US_PHONE_PATTERN = re.compile(r"(?<![^\W_])(?:1[0-9]{10}|[0-9]{10})(?![^\W_])")
_E164_PHONE_PATTERN = re.compile(r"(?<![0-9+])\+[0-9]{8,15}(?![0-9])")
_INTERNATIONAL_PHONE_CANDIDATE_PATTERN = re.compile(r"(?<![0-9+])\+[0-9() .+-]+")
_DOCUMENT_IDENTIFIER_PATTERN = re.compile(
    r"(?<![^\W_])doc_[0-9a-f]{64}(?![^\W_])",
    re.IGNORECASE,
)
_HTTP_URL_PATTERN = re.compile(
    r"(?i)https?://(?:\[[0-9a-f:.]+\]|[^/\s\"'<>,;\[\]{}]+)(?::[0-9]+)?"
    r"(?:(?:/|[?#])[^\s\"'<>,;\]}]*)?"
)
_WINDOWS_LOCAL_PATH_PATTERN = re.compile(
    r"(?i)(?:(?<![a-z0-9_])[a-z]:(?:[\\/][^\s\"']*|[^\s\"']*)|\\\\[^\s\"']+|"
    r"(?<![\\a-z0-9_])\\[a-z0-9_.-][^\s\"']*)"
)
_EMBEDDED_POSIX_PATH_PATTERN = re.compile(r"(?<![A-Za-z0-9._~%+\-/])/(?!/)[^\s\"']+")
_ATTACHED_OPTION_PATH_PATTERN = re.compile(
    r"(?:^|[\s=,:;\[\](){}])(?:-[A-Za-z][A-Za-z0-9_-]*?|--[A-Za-z][A-Za-z0-9_-]*?)"
    r"(?:/|~[/\\]|\.\.[/\\]|[A-Za-z]:[/\\]|\\\\)[^\s\"']*"
)
_STRUCTURED_IDENTIFIER_TRANSLATION = str.maketrans(
    {
        "\u00a0": " ",
        "\u2010": "-",
        "\u2011": "-",
        "\u2012": "-",
        "\u2013": "-",
        "\u2014": "-",
        "\u2015": "-",
        "\u202f": " ",
        "\u2212": "-",
    }
)
_DEFAULT_IGNORABLE_RANGES = (
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)
_DEFAULT_IGNORABLE_TRANSLATION = dict.fromkeys(
    codepoint for start, end in _DEFAULT_IGNORABLE_RANGES for codepoint in range(start, end + 1)
)


def _partition_http_url_text(value: str) -> tuple[str, list[str]]:
    """Remove remote paths but retain URL query and fragment text for local-path checks."""
    pieces: list[str] = []
    payloads: list[str] = []
    offset = 0
    for match in _HTTP_URL_PATTERN.finditer(value):
        url = match.group(0)
        try:
            parsed = urlsplit(url)
        except ValueError:
            continue
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            continue
        pieces.extend((value[offset : match.start()], " "))
        offset = match.end()
        payloads.extend((parsed.query, parsed.fragment))
    pieces.append(value[offset:])
    return "".join(pieces), payloads


def _public_text_transform(value: str) -> str:
    compatible = normalize_unicode("NFKC", value)
    without_ignorables = compatible.translate(_DEFAULT_IGNORABLE_TRANSLATION)
    return unquote(unescape_html(without_ignorables))


def _normalize_public_text(value: str) -> tuple[str, bool]:
    for _ in range(MAX_PUBLIC_DECODE_ROUNDS):
        decoded = _public_text_transform(value)
        if len(decoded) > MAX_STRING_CHARS:
            return value, False
        if decoded == value:
            return value, True
        value = decoded
    probe = _public_text_transform(value)
    return value, len(probe) <= MAX_STRING_CHARS and probe == value


def _normalized_structured_identifier_text(value: str) -> str:
    compatible = normalize_unicode("NFKC", value)
    without_ignorables = compatible.translate(_DEFAULT_IGNORABLE_TRANSLATION)
    translated = without_ignorables.translate(_STRUCTURED_IDENTIFIER_TRANSLATION)
    normalized: list[str] = []
    for character in translated:
        try:
            normalized.append(str(unicode_decimal(character)))
        except ValueError:
            normalized.append(character)
    return "".join(normalized)


def _contains_international_phone(value: str) -> bool:
    return any(
        8 <= sum(character.isdigit() for character in match.group(0)) <= 15
        for match in _INTERNATIONAL_PHONE_CANDIDATE_PATTERN.finditer(value)
    )


def _public_serialization_diagnostics(value: Mapping[str, Any]) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    for path, text in _iter_public_serialization_strings(value):
        normalized_text, converged = _normalize_public_text(text)
        if not converged:
            diagnostics.append(
                _error(
                    "contract.public_ambiguous_encoding",
                    path,
                    "Public contract serialization exceeds the bounded reversible-encoding normalization policy.",
                )
            )
            if len(diagnostics) > MAX_DIAGNOSTICS:
                return diagnostics
            continue
        _, url_payloads = _partition_http_url_text(normalized_text)
        identifier_texts = [_normalized_structured_identifier_text(item) for item in (normalized_text, *url_payloads)]
        if any("@" in item or _DOCUMENT_IDENTIFIER_PATTERN.search(item) for item in identifier_texts):
            diagnostics.append(
                _error(
                    "contract.public_direct_identifier",
                    path,
                    "Public contract serialization contains a direct identifier shape.",
                )
            )
            if len(diagnostics) > MAX_DIAGNOSTICS:
                return diagnostics
        if any(
            _STRUCTURED_SSN_PATTERN.search(item)
            or _STRUCTURED_PHONE_PATTERN.search(item)
            or _COMPACT_US_PHONE_PATTERN.search(item)
            or _E164_PHONE_PATTERN.search(item)
            or _contains_international_phone(item)
            for item in identifier_texts
        ):
            diagnostics.append(
                _error(
                    "contract.public_structured_identifier",
                    path,
                    "Public contract serialization contains a conservative SSN- or phone-shaped identifier.",
                )
            )
            if len(diagnostics) > MAX_DIAGNOSTICS:
                return diagnostics
        is_gate_pointer = bool(re.fullmatch(r"/promotion/checks/\d+/target", path))
        if not is_gate_pointer and _contains_unsafe_path_text(normalized_text):
            diagnostics.append(
                _error(
                    "contract.public_private_path",
                    path,
                    "Public contract serialization contains a private local-path shape.",
                )
            )
            if len(diagnostics) > MAX_DIAGNOSTICS:
                return diagnostics
    return diagnostics


def _iter_public_serialization_strings(value: Any) -> Iterable[tuple[str, str]]:
    """Yield values with their JSON pointers and mapping keys with privacy-safe synthetic pointers."""

    yield from _iter_strings(value)
    stack: list[tuple[Any, int]] = [(value, 0)]
    containers: set[int] = set()
    key_index = 0
    while stack:
        item, depth = stack.pop()
        if depth > MAX_CONTRACT_DEPTH:
            raise RecursionError
        if type(item) is dict:
            if id(item) in containers:
                raise RecursionError
            containers.add(id(item))
            children = []
            for key in sorted(item):
                if type(key) is not str:
                    raise TypeError
                yield f"/@mapping-key/{key_index}", key
                key_index += 1
                children.append((item[key], depth + 1))
            stack.extend(reversed(children))
        elif type(item) is list:
            if id(item) in containers:
                raise RecursionError
            containers.add(id(item))
            stack.extend((child, depth + 1) for child in reversed(item))


def _placeholder_hash_diagnostics(value: Mapping[str, Any]) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    for path, text in _iter_strings(value):
        if text == ZERO_SHA256:
            diagnostics.append(
                _error(
                    "contract.placeholder_content_hash",
                    path,
                    "Real benchmark artifacts cannot use an all-zero content hash.",
                )
            )
            if len(diagnostics) > MAX_DIAGNOSTICS:
                return diagnostics
    return diagnostics


def _iter_strings(value: Any, path: str = "") -> Iterable[tuple[str, str]]:
    stack: list[tuple[Any, str, int]] = [(value, path, 0)]
    containers: set[int] = set()
    while stack:
        item, item_path, depth = stack.pop()
        if depth > MAX_CONTRACT_DEPTH:
            raise RecursionError
        if type(item) is str:
            yield item_path, item
        elif type(item) is dict:
            if id(item) in containers:
                raise RecursionError
            containers.add(id(item))
            children = []
            for key in sorted(item):
                child = item[key]
                escaped = key.replace("~", "~0").replace("/", "~1")
                children.append((child, f"{item_path}/{escaped}", depth + 1))
            stack.extend(reversed(children))
        elif type(item) is list:
            if id(item) in containers:
                raise RecursionError
            containers.add(id(item))
            stack.extend((child, f"{item_path}/{index}", depth + 1) for index, child in reversed(list(enumerate(item))))


def _normalize_samples(samples: Sequence[Any]) -> list[float] | None:
    if type(samples) not in (list, tuple):
        return None
    try:
        if len(samples) > MAX_COLLECTION_ITEMS:
            return None
    except (OverflowError, TypeError):
        return None
    normalized: list[float] = []
    for value in samples:
        if type(value) not in (int, float):
            return None
        try:
            parsed = float(value)
        except (OverflowError, ValueError):
            return None
        if not math.isfinite(parsed) or not MIN_SAMPLE_SECONDS <= parsed <= MAX_SAMPLE_SECONDS:
            return None
        normalized.append(parsed)
    return normalized


def _prepare_performance_samples(samples: Sequence[Any]) -> tuple[list[float], int, str] | None:
    normalized = _normalize_samples(samples)
    if normalized is None:
        return None
    payload = _canonical_payload(normalized)
    return normalized, len(payload), "sha256:" + sha256(payload).hexdigest()


def _normalize_performance_inventory(
    inventory: Sequence[Mapping[str, Any]],
) -> list[dict[str, int]] | None:
    if type(inventory) not in (list, tuple):
        return None
    try:
        if len(inventory) > MAX_COLLECTION_ITEMS:
            return None
    except (OverflowError, TypeError):
        return None
    normalized: list[dict[str, int]] = []
    for row in inventory:
        if type(row) is not dict or set(row) != {"bytes", "records"}:
            return None
        byte_count = row["bytes"]
        record_count = row["records"]
        if (
            type(byte_count) is not int
            or type(record_count) is not int
            or not 0 <= byte_count <= MAX_SAFE_INTEGER
            or not 0 <= record_count <= MAX_SAFE_INTEGER
        ):
            return None
        normalized.append({"bytes": byte_count, "records": record_count})
    return normalized or None


def _performance_inventory_summary(inventory: Sequence[Mapping[str, int]]) -> dict[str, Any]:
    byte_counts = sorted(int(row["bytes"]) for row in inventory)
    record_counts = sorted(int(row["records"]) for row in inventory)
    documents = len(inventory)
    byte_count = sum(byte_counts)
    records = sum(record_counts)
    return {
        "documents": documents,
        "bytes": byte_count,
        "records": records,
        "hit_density": _classify_hit_density(records, documents),
        "size_cohort": _classify_size_cohort(byte_count, documents),
        "document_length_distribution": {
            "minimum_bytes": byte_counts[0],
            "p50_bytes": _integer_nearest_rank(byte_counts, 0.50),
            "p95_bytes": _integer_nearest_rank(byte_counts, 0.95),
            "p99_bytes": _integer_nearest_rank(byte_counts, 0.99),
            "maximum_bytes": byte_counts[-1],
            "mean_bytes": byte_count / documents,
        },
        "hit_distribution": {
            "negative_documents": sum(value == 0 for value in record_counts),
            "documents_with_records": sum(value > 0 for value in record_counts),
            "minimum_records": record_counts[0],
            "p50_records": _integer_nearest_rank(record_counts, 0.50),
            "p95_records": _integer_nearest_rank(record_counts, 0.95),
            "p99_records": _integer_nearest_rank(record_counts, 0.99),
            "maximum_records": record_counts[-1],
            "mean_records": records / documents,
        },
    }


def _classify_hit_density(records: int, documents: int) -> str:
    records_per_document = records / documents
    if records == 0:
        return "negative"
    if records_per_document < 0.1:
        return "sparse"
    if records_per_document <= 2:
        return "normal"
    return "dense"


def _classify_size_cohort(byte_count: int, documents: int) -> str:
    mean_bytes = byte_count / documents
    if mean_bytes < 1_024:
        return "small"
    if mean_bytes < 16 * 1_024:
        return "medium"
    if mean_bytes < 256 * 1_024:
        return "large"
    return "huge"


def _integer_nearest_rank(values: Sequence[int], probability: float) -> int:
    index = max(0, math.ceil(probability * len(values)) - 1)
    return values[index]


def _sample_statistics(
    samples: Sequence[float],
    input_descriptor: Mapping[str, Any] | None,
    phase: str,
    sample_unit: str,
    work_per_sample: int,
    *,
    records_per_sample: int | None = None,
) -> dict[str, float | int | None]:
    ordered = sorted(float(item) for item in samples)
    median_seconds = float(median(ordered))
    deviations = [abs(item - median_seconds) for item in ordered]
    documents_per_sample: float | int | None
    documents_per_second: float | None
    mib_per_second: float | None
    records_per_second: float | None
    if sample_unit == "operation":
        documents_per_sample = None
        documents_per_second = None
        mib_per_second = None
        records_per_second = None
    elif sample_unit == "whole_input" and input_descriptor is not None:
        whole_input_documents = int(input_descriptor["documents"]) * work_per_sample
        documents_per_sample = whole_input_documents
        bytes_per_sample = input_descriptor["bytes"] * work_per_sample
        resolved_records_per_sample = (
            input_descriptor["records"] * work_per_sample if records_per_sample is None else records_per_sample
        )
        documents_per_second = whole_input_documents / median_seconds
        mib_per_second = bytes_per_sample / (1024 * 1024) / median_seconds
        records_per_second = resolved_records_per_sample / median_seconds
    elif input_descriptor is not None:
        documents_per_sample = work_per_sample
        documents_per_second = None
        mib_per_second = None
        records_per_second = None
    else:
        raise ValueError("Scan performance statistics require a bound input descriptor.")
    return {
        "sample_count": len(ordered),
        "median_seconds": median_seconds,
        "p95_seconds": _nearest_rank(ordered, 0.95) if len(ordered) >= 20 else None,
        "p99_seconds": (
            _nearest_rank(ordered, 0.99)
            if phase not in PERFORMANCE_SETUP_PHASES and len(ordered) >= MIN_DECISION_GRADE_SCAN_SAMPLES
            else None
        ),
        "mad_seconds": float(median(deviations)),
        "documents_per_second": documents_per_second,
        "mib_per_second": mib_per_second,
        "records_per_second": records_per_second,
        "seconds_per_document": (None if documents_per_sample is None else median_seconds / documents_per_sample),
    }


def _breakeven_result(
    candidate_fixed_value: float,
    baseline_fixed_value: float,
    candidate_value_per_unit: float,
    baseline_value_per_unit: float,
    minimum_units: int,
    maximum_units: int,
) -> tuple[str, int | None] | None:
    values = (
        candidate_fixed_value,
        baseline_fixed_value,
        candidate_value_per_unit,
        baseline_value_per_unit,
    )
    try:
        if any(not math.isfinite(value) or value < 0 or value > MAX_FINITE_CONTRACT_NUMBER for value in values):
            return None
        candidate_at_minimum = candidate_fixed_value + minimum_units * candidate_value_per_unit
        baseline_at_minimum = baseline_fixed_value + minimum_units * baseline_value_per_unit
    except (OverflowError, TypeError, ValueError):
        return None
    if (
        not math.isfinite(candidate_at_minimum)
        or not math.isfinite(baseline_at_minimum)
        or candidate_at_minimum > MAX_FINITE_CONTRACT_NUMBER
        or baseline_at_minimum > MAX_FINITE_CONTRACT_NUMBER
    ):
        return None
    if candidate_at_minimum <= baseline_at_minimum:
        return "candidate_already_better", minimum_units
    marginal_advantage = baseline_value_per_unit - candidate_value_per_unit
    if marginal_advantage <= 0:
        return "no_breakeven_within_range", None
    try:
        crossing_value = (candidate_fixed_value - baseline_fixed_value) / marginal_advantage
    except (OverflowError, ZeroDivisionError):
        return None
    if not math.isfinite(crossing_value):
        return None
    crossing = math.ceil(crossing_value)
    crossing = max(minimum_units, crossing)
    if crossing <= maximum_units:
        return "finite_breakeven", crossing
    return "no_breakeven_within_range", None


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


def _same_json_scalar(actual: Any, expected: Any) -> bool:
    if isinstance(actual, bool) or isinstance(expected, bool):
        return type(actual) is type(expected) and actual == expected
    if isinstance(actual, (int, float)) and isinstance(expected, (int, float)):
        return actual == expected
    return type(actual) is type(expected) and actual == expected


def _compare_gate(actual: Any, operator: str, threshold: Any) -> bool | None:
    if isinstance(actual, Fraction):
        if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
            return None
        try:
            threshold_value = float(threshold)
            exact_threshold = Fraction(str(threshold))
        except (OverflowError, ValueError, ZeroDivisionError):
            return None
        if not math.isfinite(threshold_value):
            return None
        if operator == "eq":
            return actual == exact_threshold
        return actual >= exact_threshold if operator == "gte" else actual <= exact_threshold
    if operator == "eq":
        return _same_json_scalar(actual, threshold)
    if (
        isinstance(actual, bool)
        or isinstance(threshold, bool)
        or not isinstance(actual, (int, float))
        or not isinstance(threshold, (int, float))
    ):
        return None
    if (isinstance(actual, float) and not math.isfinite(actual)) or (
        isinstance(threshold, float) and not math.isfinite(threshold)
    ):
        return None
    return actual >= threshold if operator == "gte" else actual <= threshold


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


def _duplicate_id_diagnostics(values: Sequence[Mapping[str, Any]], path: str, _description: str) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    seen: set[str] = set()
    for index, value in enumerate(values):
        identifier = str(value["id"])
        if identifier in seen:
            diagnostics.append(
                _error(
                    "contract.duplicate_id",
                    f"{path}/{index}/id",
                    "Duplicate IDs are not allowed.",
                )
            )
        seen.add(identifier)
    return diagnostics


def _zero_nonzero_diagnostics(total: int, documents: int, path: str, _description: str) -> list[Diagnostic]:
    if (total == 0) != (documents == 0):
        return [
            _error(
                "contract.document_event_consistency",
                path,
                "Document count and event count must be zero together.",
            )
        ]
    return []


def _structure_diagnostics(value: Any) -> list[Diagnostic]:
    """Reject non-JSON, cyclic, or oversized structures before recursive schema validation."""
    stack: list[tuple[Any, int]] = [(value, 0)]
    containers: set[int] = set()
    node_count = 0
    string_chars = 0

    while stack:
        item, depth = stack.pop()
        node_count += 1
        if depth > MAX_CONTRACT_DEPTH or node_count > MAX_CONTRACT_NODES:
            return [_resource_limit_error()]
        if type(item) is str:
            string_chars += len(item)
            if len(item) > MAX_STRING_CHARS or string_chars > MAX_TOTAL_STRING_CHARS:
                return [_resource_limit_error()]
            continue
        if item is None or type(item) is bool:
            continue
        if type(item) is int:
            if abs(item) > MAX_FINITE_CONTRACT_NUMBER:
                return [_resource_limit_error()]
            continue
        if type(item) is float:
            if not math.isfinite(item) or abs(item) > MAX_FINITE_CONTRACT_NUMBER:
                return [_resource_limit_error()]
            continue
        if type(item) is list:
            if id(item) in containers or len(item) > MAX_COLLECTION_ITEMS:
                return [_resource_limit_error()]
            containers.add(id(item))
            stack.extend((child, depth + 1) for child in reversed(item))
            continue
        if type(item) is dict:
            if id(item) in containers or len(item) > MAX_COLLECTION_ITEMS:
                return [_resource_limit_error()]
            containers.add(id(item))
            children: list[Any] = []
            for key, child in item.items():
                if type(key) is not str:
                    return [_resource_limit_error()]
                string_chars += len(key)
                if len(key) > MAX_STRING_CHARS or string_chars > MAX_TOTAL_STRING_CHARS:
                    return [_resource_limit_error()]
                children.append(child)
            stack.extend((child, depth + 1) for child in reversed(children))
            continue
        return [_resource_limit_error()]
    return []


def _resource_limit_error() -> Diagnostic:
    return _error(
        "contract.resource_limits",
        "",
        "Contract JSON exceeds structural safety limits.",
    )


def _schema_diagnostics(validator: Any, value: Any) -> list[Diagnostic]:
    try:
        errors = nsmallest(MAX_DIAGNOSTICS + 1, validator.iter_errors(value), key=_schema_sort_key)
    except RecursionError:
        return [_resource_limit_error()]
    return [_schema_error(item) for item in errors]


def _schema_error(error: ValidationError) -> Diagnostic:
    return _error(
        f"contract.schema.{error.validator}",
        _pointer(error.absolute_path),
        "Contract value violates the declared schema constraint.",
    )


def _schema_sort_key(error: ValidationError) -> tuple[str, str]:
    return (_pointer(error.absolute_path), str(error.validator))


def _pointer(parts: Iterable[Any]) -> str:
    values = [str(part).replace("~", "~0").replace("/", "~1") for part in parts]
    return "/" + "/".join(values) if values else ""


def _error(code: str, path: str, message: str) -> Diagnostic:
    return diagnostic(DIAGNOSTIC_ERROR, code, path, message)


def _result(diagnostics: list[Diagnostic]) -> dict[str, Any]:
    ordered = sorted(diagnostics, key=lambda item: (str(item["path"]), str(item["code"]), str(item["message"])))
    if len(ordered) > MAX_DIAGNOSTICS:
        ordered = ordered[:MAX_DIAGNOSTICS]
        ordered.append(
            _error(
                "contract.diagnostics_truncated",
                "",
                "Additional contract diagnostics were omitted after the deterministic limit.",
            )
        )
    return {"valid": not has_errors(ordered), "diagnostics": ordered}


_JSON_NUMBER_TOKEN = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")


def _preflight_json_structure(payload: str) -> None:
    index = 0
    node_count = 0
    root_state = "value"
    stack: list[dict[str, Any]] = []

    def fail() -> NoReturn:
        raise _ContractJSONValueError("Contract file must contain valid bounded JSON.")

    def skip_whitespace(position: int) -> int:
        while position < len(payload) and payload[position] in " \t\r\n":
            position += 1
        return position

    def scan_string(position: int) -> int:
        position += 1
        while position < len(payload):
            character = payload[position]
            if character == '"':
                return position + 1
            if character == "\\":
                position += 1
                if position >= len(payload):
                    fail()
                escape = payload[position]
                if escape == "u":
                    digits = payload[position + 1 : position + 5]
                    if len(digits) != 4 or any(character not in "0123456789abcdefABCDEF" for character in digits):
                        fail()
                    position += 5
                    continue
                if escape not in '"\\/bfnrt':
                    fail()
            elif ord(character) < 0x20:
                fail()
            position += 1
        fail()
        return position

    def consume_value() -> None:
        nonlocal root_state
        if not stack:
            if root_state != "value":
                fail()
            root_state = "done"
            return
        frame = stack[-1]
        if frame["kind"] == "array":
            if frame["state"] != "value_or_end":
                fail()
        elif frame["state"] != "value":
            fail()
        frame["items"] += 1
        if frame["items"] > MAX_COLLECTION_ITEMS:
            raise _ContractJSONValueError("Contract JSON collection exceeds the collection-size limit.")
        frame["state"] = "comma_or_end"

    def scan_value(position: int) -> int:
        nonlocal node_count
        if position >= len(payload):
            fail()
        if len(stack) > MAX_CONTRACT_DEPTH:
            raise _ContractJSONValueError("Contract JSON exceeds the depth limit.")
        character = payload[position]
        node_count += 1
        if node_count > MAX_CONTRACT_NODES:
            raise _ContractJSONValueError("Contract JSON exceeds the node-count limit.")
        consume_value()
        if character in "[{":
            stack.append(
                {
                    "kind": "array" if character == "[" else "object",
                    "state": "value_or_end" if character == "[" else "key_or_end",
                    "items": 0,
                }
            )
            return position + 1
        if character == '"':
            return scan_string(position)
        for literal in ("true", "false", "null"):
            if payload.startswith(literal, position):
                return position + len(literal)
        for constant in ("NaN", "Infinity", "-Infinity"):
            if payload.startswith(constant, position):
                return position + len(constant)
        number = _JSON_NUMBER_TOKEN.match(payload, position)
        if number is None:
            fail()
        return number.end()

    while True:
        index = skip_whitespace(index)
        if not stack:
            if root_state == "done":
                if index != len(payload):
                    fail()
                return
            index = scan_value(index)
            continue
        frame = stack[-1]
        state = frame["state"]
        if frame["kind"] == "object":
            if state == "key_or_end":
                if index < len(payload) and payload[index] == "}":
                    stack.pop()
                    index += 1
                elif index < len(payload) and payload[index] == '"':
                    index = scan_string(index)
                    frame["state"] = "colon"
                else:
                    fail()
            elif state == "colon":
                if index >= len(payload) or payload[index] != ":":
                    fail()
                frame["state"] = "value"
                index += 1
            elif state == "value":
                index = scan_value(index)
            elif index < len(payload) and payload[index] == ",":
                frame["state"] = "key_or_end"
                index += 1
            elif index < len(payload) and payload[index] == "}":
                stack.pop()
                index += 1
            else:
                fail()
        elif state == "value_or_end":
            if index < len(payload) and payload[index] == "]":
                stack.pop()
                index += 1
            else:
                index = scan_value(index)
        elif index < len(payload) and payload[index] == ",":
            frame["state"] = "value_or_end"
            index += 1
        elif index < len(payload) and payload[index] == "]":
            stack.pop()
            index += 1
        else:
            fail()


def _load_contract_json(path: str | Path) -> dict[str, Any]:
    try:
        source = Path(path).expanduser()
    except (OSError, RuntimeError, TypeError, ValueError):
        raise ValueError("Contract path is invalid.") from None
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        before = source.lstat()
    except (OSError, ValueError):
        raise ValueError("Contract path could not be inspected.") from None
    if not S_ISREG(before.st_mode):
        raise ValueError("Contract path must be a regular non-symlink file.")
    flags = (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0) | nofollow
    )
    try:
        descriptor = os.open(source, flags)
    except (OSError, ValueError):
        raise ValueError("Contract path could not be opened as a regular non-symlink file.") from None
    try:
        info = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError("Contract path changed while it was being opened.")
        if not S_ISREG(info.st_mode):
            raise ValueError("Contract path must be a regular non-symlink file.")
        if info.st_size > MAX_CONTRACT_BYTES:
            raise ValueError("Contract file exceeds the size limit.")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, MAX_CONTRACT_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_CONTRACT_BYTES:
                raise ValueError("Contract file exceeds the size limit.")
        encoded_payload = b"".join(chunks)
    except OSError:
        raise ValueError("Contract file could not be read safely.") from None
    finally:
        os.close(descriptor)
    try:
        payload = encoded_payload.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Contract file must contain valid UTF-8 JSON.") from None
    try:
        _preflight_json_structure(payload)
        value = json.loads(payload, parse_constant=_reject_constant, object_pairs_hook=_reject_duplicate_keys)
    except _ContractJSONValueError:
        raise
    except (RecursionError, ValueError):
        raise ValueError("Contract file must contain valid bounded JSON.") from None
    if not isinstance(value, dict):
        raise ValueError("Contract file must contain a JSON object.")
    if _structure_diagnostics(value):
        raise ValueError("Contract JSON exceeds structural safety limits.")
    return value


class _ContractJSONValueError(ValueError):
    pass


def _reject_constant(value: str) -> None:
    raise _ContractJSONValueError("Contract JSON contains a non-finite number.")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    if len(pairs) > MAX_COLLECTION_ITEMS:
        raise _ContractJSONValueError("Contract JSON object exceeds the collection-size limit.")
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _ContractJSONValueError("Contract JSON contains a duplicate key.")
        value[key] = item
    return value


__all__ = [
    "ANNOTATION_COMPLETENESS",
    "CHARACTER_POSITION_SEMANTICS",
    "ENRON_CHARTER_VERSION",
    "ENRON_CONFORMANCE_OUTPUT_SCHEMA",
    "ENRON_EVIDENCE_SCHEMA",
    "ENRON_EVIDENCE_SCHEMA_VERSION",
    "ENRON_MANIFEST_SCHEMA",
    "ENRON_MANIFEST_SCHEMA_VERSION",
    "ENRON_PERFORMANCE_OUTPUT_SCHEMA",
    "ENRON_QUALITY_OUTPUT_SCHEMA",
    "ENRON_VERIFIER_ID",
    "ENRON_VERIFIER_VERSION",
    "MATCHING_SEMANTICS",
    "calculate_enron_breakeven",
    "calculate_enron_performance_comparison",
    "calculate_enron_performance_statistics",
    "hash_enron_environment",
    "hash_enron_breakeven_plan",
    "hash_enron_manifest",
    "hash_enron_performance_bank",
    "hash_enron_performance_baseline",
    "hash_enron_performance_comparison_plan",
    "hash_enron_performance_harness",
    "hash_enron_performance_input",
    "hash_enron_performance_inventory",
    "hash_enron_performance_manifest",
    "hash_enron_samples",
    "hash_enron_test_lineage_entry",
    "hash_enron_thresholds",
    "hash_enron_workload",
    "load_enron_evidence",
    "load_enron_manifest",
    "summarize_enron_performance_inventory",
    "validate_enron_evidence",
    "validate_enron_conformance_output",
    "validate_enron_manifest",
    "validate_enron_performance_output",
    "validate_enron_quality_output",
]

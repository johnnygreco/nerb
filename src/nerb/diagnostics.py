from __future__ import annotations

from typing import Any

DIAGNOSTIC_ERROR = "error"
DIAGNOSTIC_WARNING = "warning"
DIAGNOSTIC_INFO = "info"

SCHEMA_REQUIRED = "schema.required"
SCHEMA_ADDITIONAL_PROPERTY = "schema.additional_property"
SCHEMA_MIN_PROPERTIES = "schema.min_properties"
SCHEMA_TYPE = "schema.type"
ID_INVALID = "id.invalid"
FLAGS_DUPLICATE = "flags.duplicate"
FLAGS_UNSUPPORTED = "flags.unsupported"
JSON_PARSE = "json.parse"
ENGINE_UNSUPPORTED = "engine.unsupported"
EVAL_NEGATIVE_FAILED = "eval.negative_failed"
EVAL_POSITIVE_FAILED = "eval.positive_failed"
EVAL_RECORD_INVALID = "eval.record_invalid"
EVAL_REFS_LARGE = "eval_refs.large"
EVAL_REF_TOO_LARGE = "eval.ref_too_large"
EVAL_REF_UNRESOLVED = "eval.ref_unresolved"
EVAL_REF_UNSUPPORTED = "eval.ref_unsupported"
METADATA_LARGE = "metadata.large"
METADATA_TOO_LARGE = "metadata.too_large"
PATCH_INVALID = "patch.invalid"
REGEX_COMPILE_ERROR = "regex.compile_error"
REGEX_EXPENSIVE_PROBE = "regex.expensive_probe"
REGEX_EXPENSIVE_STATIC = "regex.expensive_static"
REGEX_LITERAL_CANDIDATE = "regex.literal_candidate"
REGEX_MATCHES_EMPTY = "regex.matches_empty"
REGEX_NORMALIZATION_COMPILE_ERROR = "regex.normalization_compile_error"
REGEX_NORMALIZED_CHANGED = "regex.normalized_changed"
REGEX_SHORT_UNBOUNDED = "regex.short_unbounded"
REPORT_EXPECTED_MISSING = "report.expected_missing"

Diagnostic = dict[str, Any]

__all__ = [
    "DIAGNOSTIC_ERROR",
    "DIAGNOSTIC_INFO",
    "DIAGNOSTIC_WARNING",
    "FLAGS_DUPLICATE",
    "FLAGS_UNSUPPORTED",
    "ENGINE_UNSUPPORTED",
    "EVAL_NEGATIVE_FAILED",
    "EVAL_POSITIVE_FAILED",
    "EVAL_RECORD_INVALID",
    "EVAL_REFS_LARGE",
    "EVAL_REF_TOO_LARGE",
    "EVAL_REF_UNRESOLVED",
    "EVAL_REF_UNSUPPORTED",
    "ID_INVALID",
    "JSON_PARSE",
    "METADATA_LARGE",
    "METADATA_TOO_LARGE",
    "PATCH_INVALID",
    "REGEX_COMPILE_ERROR",
    "REGEX_EXPENSIVE_PROBE",
    "REGEX_EXPENSIVE_STATIC",
    "REGEX_LITERAL_CANDIDATE",
    "REGEX_MATCHES_EMPTY",
    "REGEX_NORMALIZATION_COMPILE_ERROR",
    "REGEX_NORMALIZED_CHANGED",
    "REGEX_SHORT_UNBOUNDED",
    "REPORT_EXPECTED_MISSING",
    "SCHEMA_ADDITIONAL_PROPERTY",
    "SCHEMA_MIN_PROPERTIES",
    "SCHEMA_REQUIRED",
    "SCHEMA_TYPE",
    "Diagnostic",
    "diagnostic",
    "has_errors",
]


def diagnostic(
    severity: str,
    code: str,
    path: str,
    message: str,
    *,
    why: str | None = None,
    suggested_fix: str | None = None,
    suggested_patch: list[dict[str, Any]] | None = None,
    metadata: dict[str, Any] | None = None,
) -> Diagnostic:
    """Build a JSON-compatible diagnostic object with stable core fields."""
    item: Diagnostic = {"severity": severity, "code": code, "path": path, "message": message}
    if why is not None:
        item["why"] = why
    if suggested_fix is not None:
        item["suggested_fix"] = suggested_fix
    if suggested_patch is not None:
        item["suggested_patch"] = suggested_patch
    if metadata is not None:
        item["metadata"] = metadata
    return item


def has_errors(diagnostics: list[Diagnostic]) -> bool:
    return any(item.get("severity") == DIAGNOSTIC_ERROR for item in diagnostics)

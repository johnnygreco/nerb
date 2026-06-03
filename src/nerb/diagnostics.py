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
JSON_PARSE = "json.parse"

Diagnostic = dict[str, Any]

__all__ = [
    "DIAGNOSTIC_ERROR",
    "DIAGNOSTIC_INFO",
    "DIAGNOSTIC_WARNING",
    "FLAGS_DUPLICATE",
    "ID_INVALID",
    "JSON_PARSE",
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
) -> Diagnostic:
    """Build a JSON-compatible diagnostic object with stable core fields."""
    item: Diagnostic = {"severity": severity, "code": code, "path": path, "message": message}
    if why is not None:
        item["why"] = why
    if suggested_fix is not None:
        item["suggested_fix"] = suggested_fix
    if suggested_patch is not None:
        item["suggested_patch"] = suggested_patch
    return item


def has_errors(diagnostics: list[Diagnostic]) -> bool:
    return any(item.get("severity") == DIAGNOSTIC_ERROR for item in diagnostics)

from __future__ import annotations

import json
import math
import re
from collections.abc import Iterable, Mapping
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError
from jsonschema.validators import extend

from .diagnostics import (
    DIAGNOSTIC_ERROR,
    DIAGNOSTIC_WARNING,
    METADATA_LARGE,
    METADATA_TOO_LARGE,
    SCHEMA_ADDITIONAL_PROPERTY,
    SCHEMA_MIN_PROPERTIES,
    SCHEMA_REQUIRED,
    SCHEMA_TYPE,
    Diagnostic,
    diagnostic,
    has_errors,
)
from .schema import (
    ID_PATTERN,
    MAX_DESCRIPTION_LENGTH,
    MAX_PATTERN_VALUE_LENGTH,
    METADATA_ERROR_BYTES,
    METADATA_WARNING_BYTES,
    UNICODE_NORMALIZATION_VALUES,
)

REPLACEMENT_DB_SCHEMA_VERSION = "nerb.replacements.v1"
REPLACEMENT_ASSIGNMENT_SCOPES = ("name", "canonical", "surface")
REPLACEMENT_MODES = ("pseudonym", "redact")
REPLACEMENT_COLLISION_POLICIES = ("error",)
MAX_STORED_ORIGINAL_SURFACES = 5
MAX_REDACTION_TEMPLATE_LENGTH = 200

JSON_VALUE_SCHEMA: dict[str, Any] = {
    "anyOf": [
        {"type": "null"},
        {"type": "boolean"},
        {"type": "number"},
        {"type": "string"},
        {"type": "array", "items": {"$ref": "#/$defs/json_value"}},
        {"type": "object", "additionalProperties": {"$ref": "#/$defs/json_value"}},
    ],
}

METADATA_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": {"$ref": "#/$defs/json_value"},
}


def _is_json_array(_checker: Any, instance: Any) -> bool:
    return isinstance(instance, list)


def _is_json_integer(_checker: Any, instance: Any) -> bool:
    return isinstance(instance, int) and not isinstance(instance, bool)


def _is_json_number(_checker: Any, instance: Any) -> bool:
    return isinstance(instance, (int, float)) and not isinstance(instance, bool) and math.isfinite(instance)


def _is_json_object(_checker: Any, instance: Any) -> bool:
    return isinstance(instance, dict) and all(isinstance(key, str) for key in instance)


JSON_TYPE_CHECKER = Draft202012Validator.TYPE_CHECKER.redefine_many(
    {
        "array": _is_json_array,
        "integer": _is_json_integer,
        "number": _is_json_number,
        "object": _is_json_object,
    }
)
ReplacementDbSchemaValidator = extend(Draft202012Validator, type_checker=JSON_TYPE_CHECKER)

POLICY_PROPERTIES: dict[str, Any] = {
    "unicode_normalization": {"type": "string", "enum": list(UNICODE_NORMALIZATION_VALUES)},
    "assignment_scope": {"type": "string", "enum": list(REPLACEMENT_ASSIGNMENT_SCOPES)},
    "replacement_mode": {"type": "string", "enum": list(REPLACEMENT_MODES)},
    "redaction_template": {
        "type": "string",
        "minLength": 1,
        "maxLength": MAX_REDACTION_TEMPLATE_LENGTH,
    },
    "collision_policy": {"type": "string", "enum": list(REPLACEMENT_COLLISION_POLICIES)},
    "store_originals": {"type": "boolean"},
    "allow_new_assignments": {"type": "boolean"},
    "replacement_set_id": {"type": "string", "pattern": ID_PATTERN},
}

DEFAULT_POLICY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": [
        "unicode_normalization",
        "assignment_scope",
        "replacement_mode",
        "redaction_template",
        "collision_policy",
        "store_originals",
        "allow_new_assignments",
    ],
    "properties": POLICY_PROPERTIES,
    "additionalProperties": False,
}

ENTITY_POLICY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "minProperties": 1,
    "properties": POLICY_PROPERTIES,
    "additionalProperties": False,
}

CANDIDATE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["id", "value", "metadata"],
    "properties": {
        "id": {"type": "string", "pattern": ID_PATTERN},
        "value": {"type": "string", "minLength": 1, "maxLength": MAX_PATTERN_VALUE_LENGTH},
        "metadata": METADATA_SCHEMA,
    },
    "additionalProperties": False,
}

REPLACEMENT_SET_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["description", "reuse", "candidates"],
    "properties": {
        "description": {"type": "string", "maxLength": MAX_DESCRIPTION_LENGTH},
        "reuse": {"type": "boolean"},
        "candidates": {"type": "array", "items": CANDIDATE_SCHEMA},
        "metadata": METADATA_SCHEMA,
    },
    "additionalProperties": False,
}

IDENTITY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["scope", "fingerprint"],
    "properties": {
        "scope": {"type": "string", "enum": list(REPLACEMENT_ASSIGNMENT_SCOPES)},
        "name_id": {"type": "string", "minLength": 1},
        "canonical_name": {"type": "string", "minLength": 1},
        "surface": {"type": "string", "minLength": 1},
        "fingerprint": {"type": "string", "minLength": 1},
    },
    "additionalProperties": False,
}

ORIGINAL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "canonical": {"type": "string", "minLength": 1},
        "surfaces": {
            "type": "array",
            "items": {"type": "string", "minLength": 1},
            "maxItems": MAX_STORED_ORIGINAL_SURFACES,
        },
    },
    "additionalProperties": False,
}

ASSIGNMENT_REPLACEMENT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["mode", "value"],
    "properties": {
        "mode": {"type": "string", "enum": list(REPLACEMENT_MODES)},
        "value": {"type": "string", "minLength": 1, "maxLength": MAX_PATTERN_VALUE_LENGTH},
        "set_id": {"type": "string", "pattern": ID_PATTERN},
        "candidate_id": {"type": "string", "pattern": ID_PATTERN},
    },
    "additionalProperties": False,
}

REDACTION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["token", "ordinal"],
    "properties": {
        "token": {"type": "string", "minLength": 1, "maxLength": MAX_PATTERN_VALUE_LENGTH},
        "ordinal": {"type": "integer", "minimum": 1},
    },
    "additionalProperties": False,
}

ASSIGNMENT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": [
        "assignment_key",
        "entity_id",
        "identity",
        "replacement",
        "created_at",
        "updated_at",
        "use_count",
        "metadata",
    ],
    "properties": {
        "assignment_key": {"type": "string", "minLength": 1},
        "entity_id": {"type": "string", "pattern": ID_PATTERN},
        "identity": IDENTITY_SCHEMA,
        "original": ORIGINAL_SCHEMA,
        "replacement": ASSIGNMENT_REPLACEMENT_SCHEMA,
        "redaction": REDACTION_SCHEMA,
        "created_at": {"type": "string"},
        "updated_at": {"type": "string"},
        "use_count": {"type": "integer", "minimum": 0},
        "metadata": METADATA_SCHEMA,
    },
    "additionalProperties": False,
}

REPLACEMENT_DB_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://nerb.dev/schemas/replacements.v1.schema.json",
    "title": "NERB Replacement Database",
    "$defs": {"json_value": JSON_VALUE_SCHEMA},
    "type": "object",
    "required": [
        "schema_version",
        "id",
        "description",
        "version",
        "created_at",
        "updated_at",
        "metadata",
        "defaults",
        "entities",
        "replacement_sets",
        "assignments",
    ],
    "properties": {
        "schema_version": {"type": "string", "const": REPLACEMENT_DB_SCHEMA_VERSION},
        "id": {"type": "string", "pattern": ID_PATTERN},
        "description": {"type": "string", "maxLength": MAX_DESCRIPTION_LENGTH},
        "version": {"type": "integer", "minimum": 1},
        "created_at": {"type": "string"},
        "updated_at": {"type": "string"},
        "metadata": METADATA_SCHEMA,
        "defaults": DEFAULT_POLICY_SCHEMA,
        "entities": {
            "type": "object",
            "propertyNames": {"pattern": ID_PATTERN},
            "additionalProperties": ENTITY_POLICY_SCHEMA,
        },
        "replacement_sets": {
            "type": "object",
            "propertyNames": {"pattern": ID_PATTERN},
            "additionalProperties": REPLACEMENT_SET_SCHEMA,
        },
        "assignments": {
            "type": "object",
            "additionalProperties": ASSIGNMENT_SCHEMA,
        },
    },
    "additionalProperties": False,
}

REPLACEMENT_DB_SCHEMA_VALIDATOR = ReplacementDbSchemaValidator(REPLACEMENT_DB_SCHEMA)
Draft202012Validator.check_schema(REPLACEMENT_DB_SCHEMA)

__all__ = [
    "MAX_STORED_ORIGINAL_SURFACES",
    "REPLACEMENT_ASSIGNMENT_SCOPES",
    "REPLACEMENT_COLLISION_POLICIES",
    "REPLACEMENT_DB_SCHEMA",
    "REPLACEMENT_DB_SCHEMA_VALIDATOR",
    "REPLACEMENT_DB_SCHEMA_VERSION",
    "REPLACEMENT_MODES",
    "validate_replacement_db_schema",
]


def _json_pointer(parts: Iterable[Any]) -> str:
    escaped = [str(part).replace("~", "~0").replace("/", "~1") for part in parts]
    return "/" + "/".join(escaped) if escaped else ""


def _additional_properties(error: ValidationError) -> list[str]:
    if isinstance(error.instance, Mapping) and isinstance(error.schema, Mapping):
        allowed_properties = set(error.schema.get("properties", {}))
        if allowed_properties:
            return sorted(
                str(property_name) for property_name in error.instance if property_name not in allowed_properties
            )
    return re.findall(r"'([^']+)'", error.message)


def _required_property(error: ValidationError) -> str | None:
    match = re.search(r"'([^']+)' is a required property", error.message)
    return match.group(1) if match else None


def _diagnostic_code(error: ValidationError) -> str:
    if error.validator == "required":
        return SCHEMA_REQUIRED
    if error.validator == "additionalProperties":
        return SCHEMA_ADDITIONAL_PROPERTY
    if error.validator == "minProperties":
        return SCHEMA_MIN_PROPERTIES
    if error.validator == "type":
        return SCHEMA_TYPE
    return f"schema.{error.validator}"


def _diagnostic_path(error: ValidationError) -> str:
    if error.validator == "required":
        missing_property = _required_property(error)
        if missing_property is not None:
            return _json_pointer([*error.path, missing_property])
    if error.validator == "additionalProperties":
        properties = _additional_properties(error)
        if len(properties) == 1:
            return _json_pointer([*error.path, properties[0]])
    return _json_pointer(error.path)


def _schema_diagnostic(error: ValidationError) -> Diagnostic:
    return diagnostic(DIAGNOSTIC_ERROR, _diagnostic_code(error), _diagnostic_path(error), error.message)


def _additional_property_diagnostic(error: ValidationError, property_name: str) -> Diagnostic:
    path = _json_pointer([*error.path, property_name])
    return diagnostic(
        DIAGNOSTIC_ERROR,
        SCHEMA_ADDITIONAL_PROPERTY,
        path,
        f"Additional property {property_name!r} is not allowed.",
    )


def _schema_sort_key(error: ValidationError) -> tuple[str, str, str]:
    return (_diagnostic_path(error), _diagnostic_code(error), error.message)


def _iter_schema_diagnostics(replacement_db: Any) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    for error in sorted(REPLACEMENT_DB_SCHEMA_VALIDATOR.iter_errors(replacement_db), key=_schema_sort_key):
        if error.validator == "propertyNames":
            continue
        if error.validator == "additionalProperties":
            properties = _additional_properties(error)
            if properties:
                diagnostics.extend(
                    _additional_property_diagnostic(error, property_name) for property_name in properties
                )
                continue
        diagnostics.append(_schema_diagnostic(error))
    return diagnostics


def _metadata_size_diagnostic(path: str, size_bytes: int) -> Diagnostic | None:
    if size_bytes > METADATA_ERROR_BYTES:
        return diagnostic(
            DIAGNOSTIC_ERROR,
            METADATA_TOO_LARGE,
            path,
            f"Metadata exceeds the hard limit of {METADATA_ERROR_BYTES} serialized JSON bytes.",
            metadata={"bytes": size_bytes, "limit": METADATA_ERROR_BYTES},
        )
    if size_bytes > METADATA_WARNING_BYTES:
        return diagnostic(
            DIAGNOSTIC_WARNING,
            METADATA_LARGE,
            path,
            f"Metadata exceeds the review threshold of {METADATA_WARNING_BYTES} serialized JSON bytes.",
            metadata={"bytes": size_bytes, "limit": METADATA_WARNING_BYTES},
        )
    return None


def _iter_resource_limit_diagnostics(replacement_db: Any) -> Iterable[Diagnostic]:
    def visit(value: Any, path: list[Any]) -> Iterable[Diagnostic]:
        if isinstance(value, Mapping):
            metadata = value.get("metadata")
            if isinstance(metadata, Mapping):
                try:
                    payload = json.dumps(
                        metadata,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    )
                except (TypeError, ValueError):
                    payload = None
                if payload is not None:
                    metadata_diagnostic = _metadata_size_diagnostic(
                        _json_pointer([*path, "metadata"]),
                        len(payload.encode("utf-8")),
                    )
                    if metadata_diagnostic is not None:
                        yield metadata_diagnostic

            for key, child in value.items():
                if key == "metadata":
                    continue
                yield from visit(child, [*path, key])
        elif isinstance(value, list):
            for index, child in enumerate(value):
                yield from visit(child, [*path, index])

    yield from visit(replacement_db, [])


def validate_replacement_db_schema(replacement_db: Any) -> dict[str, Any]:
    """Validate a replacement database object against the v1 JSON Schema layer."""
    diagnostics = [*_iter_schema_diagnostics(replacement_db), *_iter_resource_limit_diagnostics(replacement_db)]
    diagnostics.sort(key=lambda item: (item["path"], item["severity"], item["code"], item["message"]))
    return {"valid": not has_errors(diagnostics), "diagnostics": diagnostics}

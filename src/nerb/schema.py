from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from .diagnostics import (
    DIAGNOSTIC_ERROR,
    DIAGNOSTIC_WARNING,
    FLAGS_DUPLICATE,
    ID_INVALID,
    SCHEMA_ADDITIONAL_PROPERTY,
    SCHEMA_MIN_PROPERTIES,
    SCHEMA_REQUIRED,
    SCHEMA_TYPE,
    Diagnostic,
    diagnostic,
    has_errors,
)

SCHEMA_VERSION = "nerb.bank.v1"
ID_PATTERN = r"^[a-z][a-z0-9_]{0,79}$"
ID_RE = re.compile(ID_PATTERN)
STATUS_VALUES = ("draft", "active", "inactive", "deprecated")
UNICODE_NORMALIZATION_VALUES = ("none", "NFC", "NFKC")
REGEX_FLAG_ORDER = ("ASCII", "IGNORECASE", "MULTILINE", "DOTALL", "VERBOSE")

EVAL_REFS_SCHEMA: dict[str, Any] = {
    "type": "array",
    "items": {"type": "string", "minLength": 1},
}

METADATA_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": True,
}

REGEX_FLAGS_SCHEMA: dict[str, Any] = {
    "type": "array",
    "items": {"type": "string", "enum": list(REGEX_FLAG_ORDER)},
}

LITERAL_BOUNDARY_SCHEMA: dict[str, Any] = {"type": "string", "enum": ["none", "word"]}

PATTERN_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["kind", "value", "description", "status", "priority", "metadata"],
    "properties": {
        "kind": {"type": "string", "enum": ["literal", "regex"]},
        "value": {"type": "string", "minLength": 1},
        "description": {"type": "string"},
        "status": {"type": "string", "enum": list(STATUS_VALUES)},
        "priority": {"type": "integer"},
        "regex_flags": REGEX_FLAGS_SCHEMA,
        "case_sensitive": {"type": "boolean"},
        "normalize_whitespace": {"type": "boolean"},
        "left_boundary": LITERAL_BOUNDARY_SCHEMA,
        "right_boundary": LITERAL_BOUNDARY_SCHEMA,
        "metadata": METADATA_SCHEMA,
        "eval_refs": EVAL_REFS_SCHEMA,
    },
    "additionalProperties": False,
    "allOf": [
        {
            "if": {"properties": {"kind": {"const": "regex"}}, "required": ["kind"]},
            "then": {
                "required": ["regex_flags"],
                "not": {
                    "anyOf": [
                        {"required": ["case_sensitive"]},
                        {"required": ["normalize_whitespace"]},
                        {"required": ["left_boundary"]},
                        {"required": ["right_boundary"]},
                    ]
                },
            },
        },
        {
            "if": {"properties": {"kind": {"const": "literal"}}, "required": ["kind"]},
            "then": {
                "required": [
                    "case_sensitive",
                    "normalize_whitespace",
                    "left_boundary",
                    "right_boundary",
                ],
                "not": {"required": ["regex_flags"]},
            },
        },
    ],
}

NAME_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["canonical", "description", "status", "patterns", "metadata"],
    "properties": {
        "canonical": {"type": "string"},
        "description": {"type": "string"},
        "status": {"type": "string", "enum": list(STATUS_VALUES)},
        "patterns": {
            "type": "object",
            "minProperties": 1,
            "propertyNames": {"pattern": ID_PATTERN},
            "additionalProperties": PATTERN_SCHEMA,
        },
        "metadata": METADATA_SCHEMA,
        "eval_refs": EVAL_REFS_SCHEMA,
    },
    "additionalProperties": False,
}

ENTITY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["description", "status", "regex_flags", "names", "metadata"],
    "properties": {
        "description": {"type": "string"},
        "status": {"type": "string", "enum": list(STATUS_VALUES)},
        "regex_flags": REGEX_FLAGS_SCHEMA,
        "names": {
            "type": "object",
            "minProperties": 1,
            "propertyNames": {"pattern": ID_PATTERN},
            "additionalProperties": NAME_SCHEMA,
        },
        "metadata": METADATA_SCHEMA,
        "eval_refs": EVAL_REFS_SCHEMA,
    },
    "additionalProperties": False,
}

BANK_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://nerb.dev/schemas/bank.v1.schema.json",
    "title": "NERB Bank",
    "type": "object",
    "required": [
        "schema_version",
        "id",
        "name",
        "description",
        "version",
        "status",
        "created_at",
        "updated_at",
        "unicode_normalization",
        "default_regex_flags",
        "entities",
        "metadata",
    ],
    "properties": {
        "schema_version": {"type": "string", "const": SCHEMA_VERSION},
        "id": {"type": "string", "pattern": ID_PATTERN},
        "name": {"type": "string"},
        "description": {"type": "string"},
        "version": {"type": "string"},
        "status": {"type": "string", "enum": list(STATUS_VALUES)},
        "created_at": {"type": "string"},
        "updated_at": {"type": "string"},
        "unicode_normalization": {"type": "string", "enum": list(UNICODE_NORMALIZATION_VALUES)},
        "default_regex_flags": REGEX_FLAGS_SCHEMA,
        "entities": {
            "type": "object",
            "minProperties": 1,
            "propertyNames": {"pattern": ID_PATTERN},
            "additionalProperties": ENTITY_SCHEMA,
        },
        "metadata": METADATA_SCHEMA,
        "eval_refs": EVAL_REFS_SCHEMA,
    },
    "additionalProperties": False,
}

BANK_SCHEMA_VALIDATOR = Draft202012Validator(BANK_SCHEMA)
Draft202012Validator.check_schema(BANK_SCHEMA)

__all__ = [
    "BANK_SCHEMA",
    "BANK_SCHEMA_VALIDATOR",
    "ID_PATTERN",
    "ID_RE",
    "REGEX_FLAG_ORDER",
    "SCHEMA_VERSION",
    "STATUS_VALUES",
    "UNICODE_NORMALIZATION_VALUES",
    "validate_bank_schema",
]


def _json_pointer(parts: Iterable[Any]) -> str:
    escaped = [str(part).replace("~", "~0").replace("/", "~1") for part in parts]
    return "/" + "/".join(escaped) if escaped else ""


def _additional_properties(error: ValidationError) -> list[str]:
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
    code = _diagnostic_code(error)
    path = _diagnostic_path(error)
    return diagnostic(DIAGNOSTIC_ERROR, code, path, error.message)


def _schema_sort_key(error: ValidationError) -> tuple[str, str, str]:
    return (_diagnostic_path(error), _diagnostic_code(error), error.message)


def _iter_schema_diagnostics(bank: Any) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    for error in sorted(BANK_SCHEMA_VALIDATOR.iter_errors(bank), key=_schema_sort_key):
        if error.validator == "propertyNames":
            continue
        if error.validator == "pattern" and list(error.path) == ["id"]:
            continue
        diagnostics.append(_schema_diagnostic(error))
    return diagnostics


def _iter_invalid_ids(bank: Any) -> Iterable[Diagnostic]:
    if not isinstance(bank, Mapping):
        return

    bank_id = bank.get("id")
    if isinstance(bank_id, str) and not ID_RE.fullmatch(bank_id):
        yield diagnostic(
            DIAGNOSTIC_ERROR,
            ID_INVALID,
            "/id",
            f"Bank id {bank_id!r} must match {ID_PATTERN}.",
        )

    entities = bank.get("entities")
    if not isinstance(entities, Mapping):
        return

    for entity_id, entity in entities.items():
        entity_path = ["entities", entity_id]
        if not isinstance(entity_id, str) or not ID_RE.fullmatch(entity_id):
            yield diagnostic(
                DIAGNOSTIC_ERROR,
                ID_INVALID,
                _json_pointer(entity_path),
                f"Entity id {entity_id!r} must match {ID_PATTERN}.",
            )
        if not isinstance(entity, Mapping):
            continue

        names = entity.get("names")
        if not isinstance(names, Mapping):
            continue

        for name_id, name in names.items():
            name_path = [*entity_path, "names", name_id]
            if not isinstance(name_id, str) or not ID_RE.fullmatch(name_id):
                yield diagnostic(
                    DIAGNOSTIC_ERROR,
                    ID_INVALID,
                    _json_pointer(name_path),
                    f"Name id {name_id!r} must match {ID_PATTERN}.",
                )
            if not isinstance(name, Mapping):
                continue

            patterns = name.get("patterns")
            if not isinstance(patterns, Mapping):
                continue

            for pattern_id in patterns:
                pattern_path = [*name_path, "patterns", pattern_id]
                if not isinstance(pattern_id, str) or not ID_RE.fullmatch(pattern_id):
                    yield diagnostic(
                        DIAGNOSTIC_ERROR,
                        ID_INVALID,
                        _json_pointer(pattern_path),
                        f"Pattern id {pattern_id!r} must match {ID_PATTERN}.",
                    )


def _duplicate_flags(flags: Any) -> list[str]:
    if not isinstance(flags, list):
        return []
    seen: set[str] = set()
    duplicates: list[str] = []
    for flag in flags:
        if not isinstance(flag, str):
            continue
        if flag in seen and flag not in duplicates:
            duplicates.append(flag)
        seen.add(flag)
    return duplicates


def _duplicate_flag_diagnostic(path: str, duplicates: list[str]) -> Diagnostic:
    duplicate_list = ", ".join(repr(flag) for flag in duplicates)
    return diagnostic(
        DIAGNOSTIC_WARNING,
        FLAGS_DUPLICATE,
        path,
        f"Duplicate regex flags will be removed during canonicalization: {duplicate_list}.",
    )


def _iter_duplicate_flag_diagnostics(bank: Any) -> Iterable[Diagnostic]:
    if not isinstance(bank, Mapping):
        return

    duplicates = _duplicate_flags(bank.get("default_regex_flags"))
    if duplicates:
        yield _duplicate_flag_diagnostic("/default_regex_flags", duplicates)

    entities = bank.get("entities")
    if not isinstance(entities, Mapping):
        return

    for entity_id, entity in entities.items():
        if not isinstance(entity, Mapping):
            continue

        entity_path = ["entities", entity_id]
        duplicates = _duplicate_flags(entity.get("regex_flags"))
        if duplicates:
            yield _duplicate_flag_diagnostic(_json_pointer([*entity_path, "regex_flags"]), duplicates)

        names = entity.get("names")
        if not isinstance(names, Mapping):
            continue

        for name_id, name in names.items():
            if not isinstance(name, Mapping):
                continue

            patterns = name.get("patterns")
            if not isinstance(patterns, Mapping):
                continue

            for pattern_id, pattern in patterns.items():
                if not isinstance(pattern, Mapping):
                    continue
                duplicates = _duplicate_flags(pattern.get("regex_flags"))
                if duplicates:
                    yield _duplicate_flag_diagnostic(
                        _json_pointer(
                            [
                                *entity_path,
                                "names",
                                name_id,
                                "patterns",
                                pattern_id,
                                "regex_flags",
                            ]
                        ),
                        duplicates,
                    )


def validate_bank_schema(bank: Any) -> dict[str, Any]:
    """Validate a bank object against the Milestone 1 JSON Schema layer."""
    diagnostics = [
        *_iter_schema_diagnostics(bank),
        *_iter_invalid_ids(bank),
        *_iter_duplicate_flag_diagnostics(bank),
    ]
    diagnostics.sort(key=lambda item: (item["path"], item["severity"], item["code"], item["message"]))
    return {"valid": not has_errors(diagnostics), "diagnostics": diagnostics}

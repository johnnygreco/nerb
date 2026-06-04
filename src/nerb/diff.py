from __future__ import annotations

import copy
from collections.abc import Iterable, Mapping
from typing import Any

from .bank import canonicalize_bank
from .diagnostics import Diagnostic
from .schema import validate_bank_schema

__all__ = ["diff_banks"]


def diff_banks(old_bank: Mapping[str, Any], new_bank: Mapping[str, Any]) -> dict[str, Any]:
    """Return a deterministic JSON Patch and structural summary for two JSON banks."""
    if not isinstance(old_bank, Mapping) or not isinstance(new_bank, Mapping):
        raise TypeError("diff_banks requires mapping bank objects.")

    old_canonical = canonicalize_bank(old_bank)
    new_canonical = canonicalize_bank(new_bank)
    patch = _json_patch(old_canonical, new_canonical)
    return {
        "patch": patch,
        "summary": _diff_summary(old_canonical, new_canonical, patch),
        "diagnostics": _schema_diagnostics(old_bank, "old_bank") + _schema_diagnostics(new_bank, "new_bank"),
    }


def _json_patch(old_value: Any, new_value: Any, path: str = "") -> list[dict[str, Any]]:
    if isinstance(old_value, Mapping) and isinstance(new_value, Mapping):
        operations: list[dict[str, Any]] = []
        old_keys = set(old_value)
        new_keys = set(new_value)

        for key in sorted(old_keys - new_keys):
            operations.append({"op": "remove", "path": _child_path(path, key)})
        for key in sorted(new_keys - old_keys):
            operations.append({"op": "add", "path": _child_path(path, key), "value": copy.deepcopy(new_value[key])})
        for key in sorted(old_keys & new_keys):
            operations.extend(_json_patch(old_value[key], new_value[key], _child_path(path, key)))
        return operations

    if old_value != new_value:
        return [{"op": "replace", "path": path, "value": copy.deepcopy(new_value)}]
    return []


def _diff_summary(
    old_bank: Mapping[str, Any],
    new_bank: Mapping[str, Any],
    patch: list[dict[str, Any]],
) -> dict[str, int]:
    old_entities = _entity_ids(old_bank)
    new_entities = _entity_ids(new_bank)
    old_names = _name_keys(old_bank)
    new_names = _name_keys(new_bank)
    old_patterns = _pattern_keys(old_bank)
    new_patterns = _pattern_keys(new_bank)

    return {
        "entities_added": len(new_entities - old_entities),
        "entities_removed": len(old_entities - new_entities),
        "entities_changed": _changed_count(
            old_bank,
            new_bank,
            (("entities", entity_id) for entity_id in old_entities & new_entities),
        ),
        "names_added": len(new_names - old_names),
        "names_removed": len(old_names - new_names),
        "names_changed": _changed_count(
            old_bank,
            new_bank,
            (("entities", entity_id, "names", name_id) for entity_id, name_id in old_names & new_names),
        ),
        "patterns_added": len(new_patterns - old_patterns),
        "patterns_removed": len(old_patterns - new_patterns),
        "patterns_changed": _changed_count(
            old_bank,
            new_bank,
            (
                ("entities", entity_id, "names", name_id, "patterns", pattern_id)
                for entity_id, name_id, pattern_id in old_patterns & new_patterns
            ),
        ),
        "top_level_fields_changed": sum(
            1
            for key in sorted((set(old_bank) | set(new_bank)) - {"entities"})
            if old_bank.get(key) != new_bank.get(key)
        ),
        "patch_operations": len(patch),
    }


def _entity_ids(bank: Mapping[str, Any]) -> set[str]:
    entities = bank.get("entities", {})
    if not isinstance(entities, Mapping):
        return set()
    return {entity_id for entity_id in entities if isinstance(entity_id, str)}


def _name_keys(bank: Mapping[str, Any]) -> set[tuple[str, str]]:
    keys: set[tuple[str, str]] = set()
    entities = bank.get("entities", {})
    if not isinstance(entities, Mapping):
        return keys
    for entity_id, entity in entities.items():
        if not isinstance(entity_id, str) or not isinstance(entity, Mapping):
            continue
        names = entity.get("names", {})
        if not isinstance(names, Mapping):
            continue
        keys.update((entity_id, name_id) for name_id in names if isinstance(name_id, str))
    return keys


def _pattern_keys(bank: Mapping[str, Any]) -> set[tuple[str, str, str]]:
    keys: set[tuple[str, str, str]] = set()
    entities = bank.get("entities", {})
    if not isinstance(entities, Mapping):
        return keys
    for entity_id, entity in entities.items():
        if not isinstance(entity_id, str) or not isinstance(entity, Mapping):
            continue
        names = entity.get("names", {})
        if not isinstance(names, Mapping):
            continue
        for name_id, name in names.items():
            if not isinstance(name_id, str) or not isinstance(name, Mapping):
                continue
            patterns = name.get("patterns", {})
            if not isinstance(patterns, Mapping):
                continue
            keys.update((entity_id, name_id, pattern_id) for pattern_id in patterns if isinstance(pattern_id, str))
    return keys


def _changed_count(
    old_bank: Mapping[str, Any],
    new_bank: Mapping[str, Any],
    paths: Iterable[tuple[str, ...]],
) -> int:
    return sum(1 for path in paths if _path_value(old_bank, path) != _path_value(new_bank, path))


def _path_value(bank: Mapping[str, Any], path: tuple[str, ...]) -> Any:
    value: Any = bank
    for part in path:
        if not isinstance(value, Mapping):
            return None
        value = value.get(part)
    return value


def _child_path(parent: str, key: Any) -> str:
    child = str(key).replace("~", "~0").replace("/", "~1")
    return f"{parent}/{child}" if parent else f"/{child}"


def _schema_diagnostics(bank: Mapping[str, Any], label: str) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    for item in validate_bank_schema(bank)["diagnostics"]:
        enriched = dict(item)
        metadata = dict(enriched.get("metadata", {}))
        metadata["bank"] = label
        enriched["metadata"] = metadata
        diagnostics.append(enriched)
    diagnostics.sort(
        key=lambda item: (
            item.get("metadata", {}).get("bank", ""),
            item.get("path", ""),
            item.get("severity", ""),
            item.get("code", ""),
            item.get("message", ""),
        )
    )
    return diagnostics

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .diagnostics import (
    DIAGNOSTIC_ERROR,
    JSON_PARSE,
    SCHEMA_TYPE,
    Diagnostic,
    diagnostic,
    has_errors,
)
from .schema import REGEX_FLAG_ORDER, validate_bank_schema

__all__ = [
    "BankError",
    "BankLoadError",
    "BankSchemaError",
    "bank_stats",
    "canonicalize_bank",
    "hash_bank",
    "load_bank",
]


class BankError(ValueError):
    """Base error for bank loading and schema validation failures."""

    def __init__(self, message: str, diagnostics: list[Diagnostic] | None = None) -> None:
        super().__init__(message)
        self.diagnostics = diagnostics or []


class BankLoadError(BankError):
    """Raised when a bank file cannot be read or parsed as JSON."""


class BankSchemaError(BankError):
    """Raised when a loaded bank does not satisfy the schema layer."""


def load_bank(path: str | Path) -> dict[str, Any]:
    """Load a JSON bank from an explicit file path and validate its schema shape."""
    bank_path = Path(path).expanduser()
    try:
        with bank_path.open(encoding="utf-8") as file:
            bank = json.load(file)
    except json.JSONDecodeError as exc:
        parse_diagnostic = diagnostic(
            DIAGNOSTIC_ERROR,
            JSON_PARSE,
            "",
            f"Could not parse JSON bank {str(bank_path)!r}: {exc.msg} at line {exc.lineno}, column {exc.colno}.",
        )
        raise BankLoadError(f"Could not parse JSON bank {str(bank_path)!r}.", [parse_diagnostic]) from exc
    except OSError as exc:
        load_diagnostic = diagnostic(
            DIAGNOSTIC_ERROR,
            "bank.load_error",
            "",
            f"Could not read JSON bank {str(bank_path)!r}: {exc}.",
        )
        raise BankLoadError(f"Could not read JSON bank {str(bank_path)!r}.", [load_diagnostic]) from exc

    if not isinstance(bank, dict):
        type_diagnostic = diagnostic(
            DIAGNOSTIC_ERROR,
            SCHEMA_TYPE,
            "",
            f"JSON bank {str(bank_path)!r} must be an object at the top level.",
        )
        raise BankSchemaError(f"JSON bank {str(bank_path)!r} must be an object.", [type_diagnostic])

    result = validate_bank_schema(bank)
    diagnostics = result["diagnostics"]
    if has_errors(diagnostics):
        raise BankSchemaError(f"JSON bank {str(bank_path)!r} failed schema validation.", diagnostics)

    return bank


def _canonical_regex_flags(flags: list[Any]) -> list[Any]:
    seen: set[Any] = set()
    known_flags: list[str] = []
    unknown_flags: list[Any] = []
    for flag in flags:
        if flag in seen:
            continue
        seen.add(flag)
        if isinstance(flag, str) and flag in REGEX_FLAG_ORDER:
            known_flags.append(flag)
        else:
            unknown_flags.append(flag)

    known_flags.sort(key=REGEX_FLAG_ORDER.index)
    return [*known_flags, *sorted(unknown_flags, key=repr)]


def _canonicalize(value: Any, *, key: str | None = None) -> Any:
    if isinstance(value, Mapping):
        return {
            item_key: _canonicalize(item_value, key=str(item_key)) for item_key, item_value in sorted(value.items())
        }

    if isinstance(value, list):
        canonical_items = [_canonicalize(item) for item in value]
        if key == "eval_refs":
            return sorted(canonical_items)
        if key in {"default_regex_flags", "regex_flags"}:
            return _canonical_regex_flags(canonical_items)
        return canonical_items

    return copy.deepcopy(value)


def canonicalize_bank(bank: Mapping[str, Any]) -> dict[str, Any]:
    """Return a deterministic copy of a bank without inventing or rewriting semantic fields."""
    canonical = _canonicalize(bank)
    if not isinstance(canonical, dict):
        raise TypeError("Bank canonicalization requires a mapping.")
    return canonical


def hash_bank(bank: Mapping[str, Any]) -> str:
    """Return a sha256 hash computed from canonical JSON."""
    canonical_bank = canonicalize_bank(bank)
    payload = json.dumps(canonical_bank, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def bank_stats(bank: Mapping[str, Any], *, include_engine: bool = False, engine: str = "python_re") -> dict[str, Any]:
    """Return structural bank counts without compiling patterns or running extraction."""
    totals = {"entities": 0, "names": 0, "patterns": 0}
    active_totals = {"entities": 0, "names": 0, "patterns": 0}
    by_status = {
        "draft": {"entities": 0, "names": 0, "patterns": 0},
        "active": {"entities": 0, "names": 0, "patterns": 0},
        "inactive": {"entities": 0, "names": 0, "patterns": 0},
        "deprecated": {"entities": 0, "names": 0, "patterns": 0},
    }
    by_kind = {"literal": 0, "regex": 0}

    bank_is_active = bank.get("status") == "active"
    entities = bank.get("entities", {})
    if isinstance(entities, Mapping):
        totals["entities"] = len(entities)

        for entity in entities.values():
            if not isinstance(entity, Mapping):
                continue

            entity_status = entity.get("status")
            if entity_status in by_status:
                by_status[entity_status]["entities"] += 1
            entity_is_active = bank_is_active and entity_status == "active"
            if entity_is_active:
                active_totals["entities"] += 1

            names = entity.get("names", {})
            if not isinstance(names, Mapping):
                continue
            totals["names"] += len(names)

            for name in names.values():
                if not isinstance(name, Mapping):
                    continue

                name_status = name.get("status")
                if name_status in by_status:
                    by_status[name_status]["names"] += 1
                name_is_active = entity_is_active and name_status == "active"
                if name_is_active:
                    active_totals["names"] += 1

                patterns = name.get("patterns", {})
                if not isinstance(patterns, Mapping):
                    continue
                totals["patterns"] += len(patterns)

                for pattern in patterns.values():
                    if not isinstance(pattern, Mapping):
                        continue

                    pattern_status = pattern.get("status")
                    if pattern_status in by_status:
                        by_status[pattern_status]["patterns"] += 1
                    if name_is_active and pattern_status == "active":
                        active_totals["patterns"] += 1

                    pattern_kind = pattern.get("kind")
                    if pattern_kind in by_kind:
                        by_kind[pattern_kind] += 1

    stats: dict[str, Any] = {
        "totals": totals,
        "active_totals": active_totals,
        "by_status": by_status,
        "by_kind": by_kind,
    }
    if include_engine:
        stats["engine"] = engine
    return stats

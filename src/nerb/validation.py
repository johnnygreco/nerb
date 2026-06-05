from __future__ import annotations

import json
import re
import signal
import threading
import time
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

from .bank import bank_stats, canonicalize_bank, hash_bank
from .diagnostics import (
    DIAGNOSTIC_ERROR,
    DIAGNOSTIC_INFO,
    DIAGNOSTIC_WARNING,
    ENGINE_UNSUPPORTED,
    REGEX_COMPILE_ERROR,
    REGEX_EXPENSIVE_PROBE,
    REGEX_EXPENSIVE_STATIC,
    REGEX_LITERAL_CANDIDATE,
    REGEX_MATCHES_EMPTY,
    REGEX_NORMALIZATION_COMPILE_ERROR,
    REGEX_NORMALIZED_CHANGED,
    REGEX_SHORT_UNBOUNDED,
    Diagnostic,
    diagnostic,
    has_errors,
)
from .schema import REGEX_FLAG_ORDER, validate_bank_schema

VALIDATION_LEVELS = ("basic", "standard", "deep")
VALIDATION_ENGINE = "nerb_engine"
REGEX_FLAGS = {
    "ASCII": re.ASCII,
    "IGNORECASE": re.IGNORECASE,
    "MULTILINE": re.MULTILINE,
    "DOTALL": re.DOTALL,
    "VERBOSE": re.VERBOSE,
}
REGEX_SCOPED_FLAGS = {
    "ASCII": "a",
    "IGNORECASE": "i",
    "MULTILINE": "m",
    "DOTALL": "s",
    "VERBOSE": "x",
}

__all__ = ["VALIDATION_LEVELS", "validate_bank"]
EMPTY_MATCH_PROBES = ("", "a", " a ", "\nword\n")


@dataclass(frozen=True)
class RegexPattern:
    entity_id: str
    name_id: str
    pattern_id: str
    path: str
    value: str
    flags: tuple[str, ...]


class _ProbeTimeout(RuntimeError):
    pass


def _json_pointer(parts: Iterable[Any]) -> str:
    escaped = [str(part).replace("~", "~0").replace("/", "~1") for part in parts]
    return "/" + "/".join(escaped) if escaped else ""


def _diagnostic_sort_key(item: Diagnostic) -> tuple[str, str, str, str]:
    return (
        str(item.get("path", "")),
        str(item.get("severity", "")),
        str(item.get("code", "")),
        str(item.get("message", "")),
    )


def _safe_hash_bank(bank: Mapping[str, Any]) -> str | None:
    try:
        return hash_bank(bank)
    except TypeError:
        return None


def _error_or_warning(strict: bool) -> str:
    return DIAGNOSTIC_ERROR if strict else DIAGNOSTIC_WARNING


def _unique_flags(*flag_sets: Any) -> tuple[str, ...]:
    seen: set[str] = set()
    flags: list[str] = []
    for flag_set in flag_sets:
        if not isinstance(flag_set, Sequence) or isinstance(flag_set, (str, bytes)):
            continue
        for flag in flag_set:
            if isinstance(flag, str) and flag in REGEX_FLAGS and flag not in seen:
                seen.add(flag)
                flags.append(flag)
    return tuple(sorted(flags, key=REGEX_FLAG_ORDER.index))


def _regex_flag_bits(flags: Sequence[str]) -> int:
    compiled_flags = 0
    for flag in flags:
        compiled_flags |= REGEX_FLAGS[flag]
    return compiled_flags


def _scoped_pattern(pattern: str, flags: Sequence[str]) -> str:
    scoped_flags = "".join(REGEX_SCOPED_FLAGS[flag] for flag in flags if flag in REGEX_SCOPED_FLAGS)
    if not scoped_flags:
        return pattern
    return f"(?{scoped_flags}:{pattern})"


def _iter_regex_patterns(bank: Mapping[str, Any]) -> Iterable[RegexPattern]:
    root_flags = bank.get("default_regex_flags", [])
    entities = bank.get("entities", {})
    if not isinstance(entities, Mapping):
        return

    for entity_id, entity in entities.items():
        if not isinstance(entity_id, str) or not isinstance(entity, Mapping):
            continue
        entity_flags = entity.get("regex_flags", [])
        names = entity.get("names", {})
        if not isinstance(names, Mapping):
            continue

        for name_id, name in names.items():
            if not isinstance(name_id, str) or not isinstance(name, Mapping):
                continue
            patterns = name.get("patterns", {})
            if not isinstance(patterns, Mapping):
                continue

            for pattern_id, pattern in patterns.items():
                if not isinstance(pattern_id, str) or not isinstance(pattern, Mapping):
                    continue
                if pattern.get("kind") != "regex" or not isinstance(pattern.get("value"), str):
                    continue
                yield RegexPattern(
                    entity_id=entity_id,
                    name_id=name_id,
                    pattern_id=pattern_id,
                    path=_json_pointer(["entities", entity_id, "names", name_id, "patterns", pattern_id, "value"]),
                    value=pattern["value"],
                    flags=_unique_flags(root_flags, entity_flags, pattern.get("regex_flags", [])),
                )


def _compile_regex(pattern: RegexPattern, value: str | None = None) -> re.Pattern[str]:
    return re.compile(pattern.value if value is None else value, _regex_flag_bits(pattern.flags))


def _standalone_compile(pattern: RegexPattern) -> tuple[re.Pattern[str] | None, Diagnostic | None]:
    try:
        return _compile_regex(pattern), None
    except re.error as exc:
        return None, diagnostic(
            DIAGNOSTIC_WARNING,
            REGEX_COMPILE_ERROR,
            pattern.path,
            f"Regex pattern could not be parsed by Python validation probes: {exc}.",
            metadata={"entity_id": pattern.entity_id, "name_id": pattern.name_id, "pattern_id": pattern.pattern_id},
        )


def _normalization_diagnostics(pattern: RegexPattern, normalization: str) -> list[Diagnostic]:
    if normalization not in {"NFC", "NFKC"}:
        return []

    normalization_form = cast(Literal["NFC", "NFD", "NFKC", "NFKD"], normalization)
    normalized_value = unicodedata.normalize(normalization_form, pattern.value)
    if normalized_value == pattern.value:
        return []

    diagnostics = [
        diagnostic(
            DIAGNOSTIC_WARNING,
            REGEX_NORMALIZED_CHANGED,
            pattern.path,
            f"Regex pattern changes under {normalization} normalization.",
            suggested_fix=(
                "Store the normalized regex value or set unicode_normalization to none if raw regex text is required."
            ),
            metadata={"normalization": normalization},
        )
    ]
    try:
        _compile_regex(pattern, normalized_value)
    except re.error as exc:
        diagnostics.append(
            diagnostic(
                DIAGNOSTIC_WARNING,
                REGEX_NORMALIZATION_COMPILE_ERROR,
                pattern.path,
                f"Regex pattern could not be parsed by Python normalization probes after {normalization}: {exc}.",
                metadata={"normalization": normalization},
            )
        )
    return diagnostics


def _is_literal_like(pattern: str) -> bool:
    escaped = False
    in_character_class = False
    for character in pattern:
        if escaped:
            return False
        if character == "\\":
            escaped = True
            continue
        if character == "[":
            in_character_class = True
            return False
        if character == "]":
            in_character_class = False
            return False
        if not in_character_class and character in ".^$*+?{}[]|()":
            return False
    return bool(pattern.strip())


def _has_unescaped_boundary(pattern: str) -> bool:
    return "\\b" in pattern or pattern.startswith("^") or pattern.endswith("$")


def _count_unescaped(pattern: str, needle: str) -> int:
    escaped = False
    count = 0
    in_character_class = False
    for character in pattern:
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if character == "[":
            in_character_class = True
        elif character == "]":
            in_character_class = False
        elif not in_character_class and character == needle:
            count += 1
    return count


def _split_alternation(text: str) -> list[str]:
    parts: list[str] = []
    start = 0
    escaped = False
    in_character_class = False
    for index, character in enumerate(text):
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if character == "[":
            in_character_class = True
            continue
        if character == "]":
            in_character_class = False
            continue
        if character == "|" and not in_character_class:
            parts.append(text[start:index])
            start = index + 1
    if parts:
        parts.append(text[start:])
    return [part.strip("()?:") for part in parts if part.strip("()?:")]


def _alternation_groups(pattern: str) -> list[list[str]]:
    groups = [_split_alternation(pattern)]
    groups.extend(_split_alternation(match.group(1)) for match in re.finditer(r"\(([^()]*(?:\|[^()]*)+)\)", pattern))
    return [group for group in groups if len(group) >= 2]


def _has_ambiguous_alternation(pattern: str) -> bool:
    for group in _alternation_groups(pattern):
        sorted_group: list[str] = sorted(group, key=lambda item: len(item))
        for index, first in enumerate(sorted_group):
            if not first:
                continue
            if any(second != first and second.startswith(first) for second in sorted_group[index + 1 :]):
                return True
    return False


def _capturing_group_count(pattern: str) -> int:
    escaped = False
    in_character_class = False
    count = 0
    for index, character in enumerate(pattern):
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if character == "[":
            in_character_class = True
            continue
        if character == "]":
            in_character_class = False
            continue
        if character == "(" and not in_character_class:
            next_two = pattern[index + 1 : index + 3]
            if next_two in {"?:", "?=", "?!", "?<"}:
                continue
            count += 1
    return count


def _static_risk_diagnostics(pattern: RegexPattern, *, strict: bool) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    severity = _error_or_warning(strict)
    risks = [
        (
            "nested_quantifier",
            re.search(r"\([^)]*[*+][^)]*\)\s*[*+{]", pattern.value) is not None,
            "Regex contains nested quantifiers that can cause excessive backtracking.",
            "Simplify repeated groups or use a bounded quantifier.",
        ),
        (
            "unbounded_dot_star",
            re.search(r"(?<!\\)\.\*", pattern.value) is not None,
            "Regex contains an unbounded dot-star expression.",
            "Replace dot-star with a narrower character class or a bounded quantifier.",
        ),
        (
            "ambiguous_alternation",
            _has_ambiguous_alternation(pattern.value),
            "Regex contains ambiguous alternation branches.",
            "Order longer alternatives first or make branches mutually exclusive.",
        ),
        (
            "huge_alternation",
            _count_unescaped(pattern.value, "|") + 1 >= 20,
            "Regex contains a large alternation set.",
            "Consider splitting this pattern or using literal patterns for exact aliases.",
        ),
        (
            "repeated_lookaround",
            sum(pattern.value.count(token) for token in ("(?=", "(?!", "(?<=", "(?<!")) >= 3,
            "Regex contains repeated lookaround assertions.",
            "Reduce lookarounds or move context checks into surrounding validation.",
        ),
        (
            "excessive_groups",
            _capturing_group_count(pattern.value) > 50,
            "Regex contains an excessive number of capturing groups.",
            "Use non-capturing groups unless captures are required.",
        ),
    ]
    for risk, triggered, message, suggested_fix in risks:
        if triggered:
            diagnostics.append(
                diagnostic(
                    severity,
                    REGEX_EXPENSIVE_STATIC,
                    pattern.path,
                    message,
                    suggested_fix=suggested_fix,
                    metadata={"risk": risk},
                )
            )

    compact_value = pattern.value.strip()
    if len(compact_value) < 4 and not _has_unescaped_boundary(compact_value):
        diagnostics.append(
            diagnostic(
                severity,
                REGEX_SHORT_UNBOUNDED,
                pattern.path,
                "Short regex pattern may match unrelated text.",
                why="Patterns shorter than 4 characters without boundaries often produce false positives.",
                suggested_fix="Add word boundaries or use a longer phrase.",
            )
        )

    if _is_literal_like(pattern.value):
        diagnostics.append(
            diagnostic(
                DIAGNOSTIC_INFO,
                REGEX_LITERAL_CANDIDATE,
                pattern.path,
                "Regex pattern looks like a literal string.",
                suggested_fix="Use a literal pattern unless regex behavior is required.",
            )
        )

    return diagnostics


def _probe_inputs(limit: int) -> list[str]:
    seeds = [
        "",
        "a",
        "aaaa",
        "aaaaaaaa!",
        "abababab",
        "aaaaaaaaaaaaaaaa!",
        "xxxxxxxxxxxxxxxx",
        "abc abc abc",
        "1111111111",
        "A" * 24 + "!",
        "a" * 32 + "!",
        "abc" * 12,
        " " * 16,
        "\t" * 8,
        "a_b-c.d",
        "Acme Corporation",
        "prefix Acme suffix",
        "0" * 32 + "!",
        "abc123" * 8,
        "a" * 48 + "!",
        "z" * 64,
        "word " * 20,
        "a" * 80 + "!",
        "ab" * 64,
        "a" * 96 + "!",
    ]
    return seeds[:limit]


def _can_use_signal_timeout() -> bool:
    return threading.current_thread() is threading.main_thread() and hasattr(signal, "setitimer")


def _search_with_timeout(compiled: re.Pattern[str], probe: str, timeout_seconds: float) -> float:
    start = time.perf_counter()
    if not _can_use_signal_timeout():
        compiled.search(probe)
        return time.perf_counter() - start

    previous_handler = signal.getsignal(signal.SIGALRM)

    def handle_timeout(_signum: int, _frame: Any) -> None:
        raise _ProbeTimeout

    signal.signal(signal.SIGALRM, handle_timeout)
    signal.setitimer(signal.ITIMER_REAL, timeout_seconds)
    try:
        compiled.search(probe)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0.0)
        signal.signal(signal.SIGALRM, previous_handler)
    return time.perf_counter() - start


def _runtime_probe_diagnostics(
    pattern: RegexPattern,
    compiled: re.Pattern[str],
    *,
    level: str,
    strict: bool,
) -> list[Diagnostic]:
    limit = 25 if level == "deep" else 5
    timeout_seconds = 0.05 if level == "standard" else 0.1
    slow_threshold = timeout_seconds / 2
    for index, probe in enumerate(_probe_inputs(limit)):
        try:
            elapsed = _search_with_timeout(compiled, probe, timeout_seconds)
        except _ProbeTimeout:
            return [
                diagnostic(
                    _error_or_warning(strict),
                    REGEX_EXPENSIVE_PROBE,
                    pattern.path,
                    "Regex exceeded the bounded runtime probe limit.",
                    suggested_fix="Simplify the regex or add tighter bounds before extraction.",
                    metadata={"probe_index": index, "probe_length": len(probe), "timeout_seconds": timeout_seconds},
                )
            ]
        if elapsed > slow_threshold:
            return [
                diagnostic(
                    _error_or_warning(strict),
                    REGEX_EXPENSIVE_PROBE,
                    pattern.path,
                    "Regex was slow during bounded runtime probes.",
                    suggested_fix="Simplify the regex or add tighter bounds before extraction.",
                    metadata={"probe_index": index, "probe_length": len(probe), "elapsed_seconds": round(elapsed, 6)},
                )
            ]
    return []


def _rust_engine_diagnostics(bank: Mapping[str, Any]) -> list[Diagnostic]:
    from .engine import Bank

    try:
        native_bank = Bank.from_source_bytes(
            json.dumps(bank, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(
                "utf-8"
            ),
            format_hint="json",
            use_cache=False,
        )
    except (TypeError, ValueError) as exc:
        return [
            diagnostic(
                DIAGNOSTIC_ERROR,
                "engine.compile_error",
                "",
                f"Rust engine failed to compile the bank: {exc}.",
            )
        ]
    return rust_empty_match_diagnostics(native_bank)


def rust_empty_match_diagnostics(native_bank: Any) -> list[Diagnostic]:
    """Return diagnostics when a Rust-backed bank emits zero-length records."""
    for probe in EMPTY_MATCH_PROBES:
        for record in native_bank.scan_text(probe):
            if int(record["start"]) == int(record["end"]):
                return [
                    diagnostic(
                        DIAGNOSTIC_ERROR,
                        REGEX_MATCHES_EMPTY,
                        "",
                        "Rust engine detector emits a zero-length match.",
                        suggested_fix="Require at least one concrete character in the regex before extraction.",
                        metadata={
                            "entity": record.get("entity"),
                            "canonical_name": record.get("canonical_name"),
                            "surface_name": record.get("surface_name"),
                            "probe": probe,
                        },
                    )
                ]
    return []


def _eval_ref_count(bank: Mapping[str, Any]) -> int:
    count = 0

    def visit(value: Any) -> None:
        nonlocal count
        if isinstance(value, Mapping):
            eval_refs = value.get("eval_refs")
            if isinstance(eval_refs, list):
                count += len(eval_refs)
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(bank)
    return count


def _runtime_validation(
    bank: Mapping[str, Any],
    *,
    level: str,
    engine: str,
    base_path: str | Path | None,
    strict: bool,
    check_engine_compile: bool,
) -> tuple[list[Diagnostic], dict[str, Any]]:
    diagnostics: list[Diagnostic] = []
    engine_compatibility: dict[str, Any] = {
        "engine": engine,
        "compatible": True,
        "regex_patterns": 0,
    }
    if engine != VALIDATION_ENGINE:
        diagnostics.append(
            diagnostic(
                DIAGNOSTIC_ERROR,
                ENGINE_UNSUPPORTED,
                "",
                f"Validation engine {engine!r} is not supported; expected {VALIDATION_ENGINE!r}.",
            )
        )
        engine_compatibility["compatible"] = False
        return diagnostics, engine_compatibility

    regex_patterns = list(_iter_regex_patterns(bank))
    engine_compatibility["regex_patterns"] = len(regex_patterns)
    engine_compatibility["runtime_probes"] = {
        "enabled": level in {"standard", "deep"},
        "max_per_regex": 25 if level == "deep" else 5 if level == "standard" else 0,
    }
    if level == "deep":
        engine_compatibility["eval_refs"] = {
            "count": _eval_ref_count(bank),
            "base_path": str(Path(base_path).expanduser()) if base_path is not None else None,
            "runner": "deferred",
        }

    normalization = bank.get("unicode_normalization", "none")
    if not isinstance(normalization, str):
        normalization = "none"

    for pattern in regex_patterns:
        diagnostics.extend(_normalization_diagnostics(pattern, normalization))
        compiled, compile_diagnostic = _standalone_compile(pattern)
        if compile_diagnostic is not None:
            diagnostics.append(compile_diagnostic)
            continue
        if compiled is None:
            continue

        if level in {"standard", "deep"}:
            diagnostics.extend(_static_risk_diagnostics(pattern, strict=strict))
            diagnostics.extend(_runtime_probe_diagnostics(pattern, compiled, level=level, strict=strict))

    if check_engine_compile:
        diagnostics.extend(_rust_engine_diagnostics(bank))

    engine_compatibility["compatible"] = not has_errors(diagnostics)
    return diagnostics, engine_compatibility


def validate_bank(
    bank: Any,
    *,
    level: str = "standard",
    engine: str = VALIDATION_ENGINE,
    base_path: str | Path | None = None,
    strict: bool = False,
    check_engine_compile: bool = True,
) -> dict[str, Any]:
    """Validate a JSON bank with schema checks plus bounded runtime regex diagnostics."""
    if level not in VALIDATION_LEVELS:
        raise ValueError(f"Validation level must be one of {', '.join(VALIDATION_LEVELS)}.")

    schema_result = validate_bank_schema(bank)
    diagnostics = list(schema_result["diagnostics"])

    if isinstance(bank, Mapping):
        candidate_bank = canonicalize_bank(bank)
    else:
        candidate_bank = bank

    if has_errors(diagnostics) or not isinstance(candidate_bank, Mapping):
        stats = bank_stats(candidate_bank) if isinstance(candidate_bank, Mapping) else {}
        diagnostics.sort(key=_diagnostic_sort_key)
        return {
            "valid": False,
            "bank": candidate_bank,
            "hash": _safe_hash_bank(candidate_bank) if isinstance(candidate_bank, Mapping) else None,
            "diagnostics": diagnostics,
            "stats": stats,
            "engine_compatibility": {"engine": engine, "compatible": False},
        }

    runtime_diagnostics, engine_compatibility = _runtime_validation(
        candidate_bank,
        level=level,
        engine=engine,
        base_path=base_path,
        strict=strict,
        check_engine_compile=check_engine_compile,
    )
    diagnostics.extend(runtime_diagnostics)
    diagnostics.sort(key=_diagnostic_sort_key)

    stats = bank_stats(candidate_bank, include_engine=True, engine=engine)
    if level == "deep":
        stats["eval_refs"] = {"count": _eval_ref_count(candidate_bank), "runner": "deferred"}

    return {
        "valid": not has_errors(diagnostics),
        "bank": candidate_bank,
        "hash": hash_bank(candidate_bank),
        "diagnostics": diagnostics,
        "stats": stats,
        "engine_compatibility": engine_compatibility,
    }

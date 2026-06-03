from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from .bank import canonicalize_bank, hash_bank
from .diagnostics import Diagnostic, has_errors
from .records import MatchRecord, PatternIdentity
from .schema import STATUS_VALUES, validate_bank_schema

DEFAULT_INCLUDE_STATUSES = ("active",)
DEFAULT_ENGINE_NAME = "python_re"
DEFAULT_MAX_TEXT_BYTES = 10 * 1024 * 1024
DEFAULT_MAX_BATCH_DOCUMENTS = 100
DEFAULT_MAX_BATCH_TEXT_BYTES = 25 * 1024 * 1024

__all__ = [
    "DEFAULT_BATCH_DOCUMENTS",
    "DEFAULT_COMBINED_TEXT_BYTES",
    "DEFAULT_ENGINE_NAME",
    "DEFAULT_INCLUDE_STATUSES",
    "DEFAULT_MAX_BATCH_DOCUMENTS",
    "DEFAULT_MAX_BATCH_TEXT_BYTES",
    "DEFAULT_MAX_TEXT_BYTES",
    "DEFAULT_TEXT_BYTES",
    "CompiledBank",
    "CompiledBankCacheKey",
    "EnginePattern",
    "ExtractionError",
    "Matcher",
    "clear_compiled_bank_cache",
    "compile_bank",
    "compiled_bank_cache_info",
    "resolve_extraction_options",
]

DEFAULT_TEXT_BYTES = DEFAULT_MAX_TEXT_BYTES
DEFAULT_BATCH_DOCUMENTS = DEFAULT_MAX_BATCH_DOCUMENTS
DEFAULT_COMBINED_TEXT_BYTES = DEFAULT_MAX_BATCH_TEXT_BYTES


class ExtractionError(ValueError):
    """Raised when JSON-bank extraction cannot proceed."""

    def __init__(self, message: str, diagnostics: list[Diagnostic] | None = None) -> None:
        super().__init__(message)
        self.diagnostics = diagnostics or []


class Matcher(Protocol):
    name: str
    version: str

    def finditer(self, text: str) -> list[MatchRecord]:
        """Return raw extraction records for text."""


@dataclass(frozen=True)
class EnginePattern:
    identity: PatternIdentity
    value: str
    regex_flags: tuple[str, ...] = ()
    case_sensitive: bool = True
    normalize_whitespace: bool = False
    left_boundary: str = "none"
    right_boundary: str = "none"


@dataclass(frozen=True)
class CompiledBankCacheKey:
    bank_hash: str
    engine_name: str
    engine_version: str
    include_statuses: tuple[str, ...]
    engine_options: str
    normalization: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "bank_hash": self.bank_hash,
            "engine_name": self.engine_name,
            "engine_version": self.engine_version,
            "include_statuses": list(self.include_statuses),
            "engine_options": json.loads(self.engine_options),
            "normalization": self.normalization,
        }


@dataclass(frozen=True)
class CompiledBank:
    bank: dict[str, Any]
    bank_hash: str
    normalization: str
    include_statuses: tuple[str, ...]
    engine_name: str
    engine_version: str
    matchers: tuple[Matcher, ...]
    cache_key: CompiledBankCacheKey

    def finditer(self, text: str) -> list[MatchRecord]:
        records: list[MatchRecord] = []
        for matcher in self.matchers:
            records.extend(matcher.finditer(text))
        return records


@dataclass(frozen=True)
class ResolvedExtractionOptions:
    include_statuses: tuple[str, ...]
    engine: str
    engine_options: dict[str, Any]
    max_text_bytes: int
    max_batch_documents: int
    max_batch_text_bytes: int


_COMPILED_BANK_CACHE: dict[CompiledBankCacheKey, CompiledBank] = {}
_CACHE_HITS = 0
_CACHE_MISSES = 0


def resolve_extraction_options(options: Mapping[str, Any] | None) -> ResolvedExtractionOptions:
    options = options or {}
    include_statuses = options.get("include_statuses", DEFAULT_INCLUDE_STATUSES)
    if not isinstance(include_statuses, Sequence) or isinstance(include_statuses, (str, bytes)):
        raise ExtractionError("Extraction option include_statuses must be a sequence of statuses.")

    status_values = list(include_statuses)
    if not status_values:
        raise ExtractionError("Extraction option include_statuses must not be empty.")
    invalid_statuses = [
        status for status in status_values if not isinstance(status, str) or status not in STATUS_VALUES
    ]
    if invalid_statuses:
        raise ExtractionError(
            f"Extraction option include_statuses must contain only valid status strings: {', '.join(STATUS_VALUES)}."
        )
    statuses = tuple(sorted(set(status_values)))

    engine = str(options.get("engine", DEFAULT_ENGINE_NAME))
    engine_options = options.get("engine_options", {})
    if not isinstance(engine_options, Mapping):
        raise ExtractionError("Extraction option engine_options must be an object.")

    return ResolvedExtractionOptions(
        include_statuses=statuses,
        engine=engine,
        engine_options=dict(engine_options),
        max_text_bytes=_positive_int_option(options, "max_text_bytes", DEFAULT_MAX_TEXT_BYTES),
        max_batch_documents=_positive_int_option(options, "max_batch_documents", DEFAULT_MAX_BATCH_DOCUMENTS),
        max_batch_text_bytes=_positive_int_option(options, "max_batch_text_bytes", DEFAULT_MAX_BATCH_TEXT_BYTES),
    )


def _positive_int_option(options: Mapping[str, Any], key: str, default: int) -> int:
    value = options.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ExtractionError(f"Extraction option {key} must be a positive integer.")
    return value


def compile_bank(bank: Mapping[str, Any], *, options: Mapping[str, Any] | None = None) -> tuple[CompiledBank, bool]:
    global _CACHE_HITS, _CACHE_MISSES

    resolved = resolve_extraction_options(options)
    if resolved.engine != DEFAULT_ENGINE_NAME:
        raise ExtractionError("Extraction engine must be 'python_re' for this milestone.")

    schema_result = validate_bank_schema(bank)
    diagnostics = schema_result["diagnostics"]
    if has_errors(diagnostics):
        raise ExtractionError("Bank failed schema validation and cannot be extracted.", diagnostics)

    from .validation import validate_bank

    validation_result = validate_bank(bank, level="standard", engine=resolved.engine)
    validation_diagnostics = validation_result["diagnostics"]
    if has_errors(validation_diagnostics):
        raise ExtractionError("Bank failed runtime validation and cannot be extracted.", validation_diagnostics)

    canonical_bank = canonicalize_bank(bank)
    bank_hash = hash_bank(canonical_bank)
    normalization = str(canonical_bank["unicode_normalization"])

    from .literal_engine import LiteralMatcher
    from .python_re_engine import PythonReEngine

    engine_options = _canonical_options(resolved.engine_options)
    cache_key = CompiledBankCacheKey(
        bank_hash=bank_hash,
        engine_name=PythonReEngine.name,
        engine_version=PythonReEngine.version,
        include_statuses=resolved.include_statuses,
        engine_options=engine_options,
        normalization=normalization,
    )
    cached = _COMPILED_BANK_CACHE.get(cache_key)
    if cached is not None:
        _CACHE_HITS += 1
        return cached, True

    regex_patterns, literal_patterns = _eligible_patterns(canonical_bank, resolved.include_statuses)
    compiled = CompiledBank(
        bank=canonical_bank,
        bank_hash=bank_hash,
        normalization=normalization,
        include_statuses=resolved.include_statuses,
        engine_name=PythonReEngine.name,
        engine_version=PythonReEngine.version,
        matchers=(
            PythonReEngine(regex_patterns, normalization=normalization),
            LiteralMatcher(literal_patterns, normalization=normalization),
        ),
        cache_key=cache_key,
    )
    _COMPILED_BANK_CACHE[cache_key] = compiled
    _CACHE_MISSES += 1
    return compiled, False


def clear_compiled_bank_cache() -> None:
    global _CACHE_HITS, _CACHE_MISSES
    _COMPILED_BANK_CACHE.clear()
    _CACHE_HITS = 0
    _CACHE_MISSES = 0


def compiled_bank_cache_info() -> dict[str, Any]:
    return {"size": len(_COMPILED_BANK_CACHE), "hits": _CACHE_HITS, "misses": _CACHE_MISSES}


def _canonical_options(options: Mapping[str, Any]) -> str:
    try:
        return json.dumps(options, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ExtractionError("Extraction option engine_options must be JSON-compatible.") from exc


def _eligible_patterns(
    bank: Mapping[str, Any],
    include_statuses: tuple[str, ...],
) -> tuple[tuple[EnginePattern, ...], tuple[EnginePattern, ...]]:
    regex_patterns: list[EnginePattern] = []
    literal_patterns: list[EnginePattern] = []
    root_flags = bank.get("default_regex_flags", [])

    if bank.get("status") not in include_statuses:
        return (), ()

    entities = bank.get("entities", {})
    if not isinstance(entities, Mapping):
        return (), ()

    for entity_id, entity in entities.items():
        if not isinstance(entity_id, str) or not isinstance(entity, Mapping):
            continue
        if entity.get("status") not in include_statuses:
            continue
        entity_flags = entity.get("regex_flags", [])
        names = entity.get("names", {})
        if not isinstance(names, Mapping):
            continue
        for name_id, name in names.items():
            if not isinstance(name_id, str) or not isinstance(name, Mapping):
                continue
            if name.get("status") not in include_statuses:
                continue
            patterns = name.get("patterns", {})
            if not isinstance(patterns, Mapping):
                continue
            for pattern_id, pattern in patterns.items():
                if not isinstance(pattern_id, str) or not isinstance(pattern, Mapping):
                    continue
                if pattern.get("status") not in include_statuses:
                    continue
                kind = pattern.get("kind")
                if kind not in {"literal", "regex"} or not isinstance(pattern.get("value"), str):
                    continue
                engine_pattern = EnginePattern(
                    identity=PatternIdentity(
                        entity_id=entity_id,
                        name_id=name_id,
                        pattern_id=pattern_id,
                        pattern_kind=kind,
                        canonical_name=str(name.get("canonical", "")),
                    ),
                    value=pattern["value"],
                    regex_flags=_unique_flags(root_flags, entity_flags, pattern.get("regex_flags", [])),
                    case_sensitive=bool(pattern.get("case_sensitive", True)),
                    normalize_whitespace=bool(pattern.get("normalize_whitespace", False)),
                    left_boundary=str(pattern.get("left_boundary", "none")),
                    right_boundary=str(pattern.get("right_boundary", "none")),
                )
                if kind == "regex":
                    regex_patterns.append(engine_pattern)
                else:
                    literal_patterns.append(engine_pattern)

    return tuple(regex_patterns), tuple(literal_patterns)


def _unique_flags(*flag_sets: Any) -> tuple[str, ...]:
    from .schema import REGEX_FLAG_ORDER

    seen: set[str] = set()
    flags: list[str] = []
    for flag_set in flag_sets:
        if not isinstance(flag_set, Sequence) or isinstance(flag_set, (str, bytes)):
            continue
        for flag in flag_set:
            if isinstance(flag, str) and flag in REGEX_FLAG_ORDER and flag not in seen:
                seen.add(flag)
                flags.append(flag)
    return tuple(sorted(flags, key=REGEX_FLAG_ORDER.index))

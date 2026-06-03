from __future__ import annotations

import re
from collections import defaultdict

from .engines import EnginePattern, ExtractionError
from .normalization import normalize_pattern, transform_text
from .records import MatchRecord, record_sort_key, serialize_record
from .schema import REGEX_FLAG_ORDER

PYTHON_RE_FLAGS = {
    "ASCII": re.ASCII,
    "IGNORECASE": re.IGNORECASE,
    "MULTILINE": re.MULTILINE,
    "DOTALL": re.DOTALL,
    "VERBOSE": re.VERBOSE,
}
PYTHON_RE_SCOPED_FLAGS = {
    "ASCII": "a",
    "IGNORECASE": "i",
    "MULTILINE": "m",
    "DOTALL": "s",
    "VERBOSE": "x",
}

__all__ = ["PythonReEngine"]


class PythonReEngine:
    name = "python_re"
    version = "1"

    def __init__(self, patterns: tuple[EnginePattern, ...], *, normalization: str) -> None:
        self.normalization = normalization
        self._patterns = patterns
        self.entity_shards = self._compile_entity_shards(patterns)
        self._compiled_patterns = tuple(self._compile_pattern(pattern) for pattern in patterns)

    def finditer(self, text: str) -> list[MatchRecord]:
        transform = transform_text(text, self.normalization)
        records: list[MatchRecord] = []

        for pattern, compiled in self._compiled_patterns:
            internal_group_name = _internal_group_name(pattern)
            for match in compiled.finditer(transform.transformed_text):
                start, end = match.span(internal_group_name)
                if start < 0 or end < start:
                    continue
                captures = _user_captures(match, internal_group_name)
                records.append(serialize_record(pattern.identity, transform, start, end, captures))

        records.sort(key=record_sort_key)
        return records

    def _compile_entity_shards(self, patterns: tuple[EnginePattern, ...]) -> dict[str, re.Pattern[str]]:
        patterns_by_entity: defaultdict[str, list[EnginePattern]] = defaultdict(list)
        for pattern in patterns:
            patterns_by_entity[pattern.identity.entity_id].append(pattern)

        shards: dict[str, re.Pattern[str]] = {}
        for entity_id, entity_patterns in sorted(patterns_by_entity.items()):
            alternatives = []
            for pattern in entity_patterns:
                scoped_pattern = _scoped_pattern(_normalized_value(pattern, self.normalization), pattern.regex_flags)
                alternatives.append(f"(?P<{_internal_group_name(pattern)}>{scoped_pattern})")
            try:
                shards[entity_id] = re.compile("|".join(alternatives))
            except re.error as exc:
                raise ExtractionError(f"Python re entity shard {entity_id!r} failed to compile: {exc}.") from exc
        return shards

    def _compile_pattern(self, pattern: EnginePattern) -> tuple[EnginePattern, re.Pattern[str]]:
        value = _normalized_value(pattern, self.normalization)
        wrapped = f"(?=(?P<{_internal_group_name(pattern)}>{_scoped_pattern(value, pattern.regex_flags)}))"
        try:
            return pattern, re.compile(wrapped)
        except re.error as exc:
            raise ExtractionError(
                "Python re pattern failed to compile after NERB wrapping: "
                f"{pattern.identity.entity_id}/{pattern.identity.name_id}/{pattern.identity.pattern_id}: {exc}."
            ) from exc


def _normalized_value(pattern: EnginePattern, normalization: str) -> str:
    return normalize_pattern(pattern.value, normalization)


def _internal_group_name(pattern: EnginePattern) -> str:
    return f"nerb__{pattern.identity.entity_id}__{pattern.identity.name_id}__{pattern.identity.pattern_id}"


def _scoped_pattern(pattern: str, flags: tuple[str, ...]) -> str:
    ordered_flags = tuple(flag for flag in REGEX_FLAG_ORDER if flag in flags)
    scoped_flags = "".join(PYTHON_RE_SCOPED_FLAGS[flag] for flag in ordered_flags)
    if not scoped_flags:
        return pattern
    return f"(?{scoped_flags}:{pattern})"


def _user_captures(match: re.Match[str], internal_group_name: str) -> dict[str, tuple[int, int]]:
    captures: dict[str, tuple[int, int]] = {}
    for group_name in sorted(match.re.groupindex):
        if group_name == internal_group_name:
            continue
        start, end = match.span(group_name)
        if start == -1 and end == -1:
            continue
        captures[group_name] = (start, end)
    return captures

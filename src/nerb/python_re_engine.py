from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass

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


@dataclass(frozen=True)
class RegexShardPattern:
    pattern: EnginePattern
    internal_group_name: str
    user_capture_names: tuple[str, ...]


@dataclass(frozen=True)
class RegexEntityShard:
    entity_id: str
    regex: re.Pattern[str]
    patterns: tuple[RegexShardPattern, ...]


class PythonReEngine:
    name = "python_re"
    version = "1"

    def __init__(self, patterns: tuple[EnginePattern, ...], *, normalization: str) -> None:
        self.normalization = normalization
        self._patterns = patterns
        self.entity_shards = self._compile_entity_shards(patterns)

    def finditer(self, text: str) -> list[MatchRecord]:
        transform = transform_text(text, self.normalization)
        records: list[MatchRecord] = []

        for shard in self.entity_shards:
            for match in shard.regex.finditer(transform.transformed_text):
                for shard_pattern in shard.patterns:
                    internal_start, internal_end = match.span(shard_pattern.internal_group_name)
                    if internal_start == -1 and internal_end == -1:
                        continue
                    start = match.start()
                    end = internal_start
                    if end < start:
                        continue
                    captures = _user_captures(match, shard_pattern.user_capture_names)
                    records.append(serialize_record(shard_pattern.pattern.identity, transform, start, end, captures))

        records.sort(key=record_sort_key)
        return records

    def _compile_entity_shards(self, patterns: tuple[EnginePattern, ...]) -> tuple[RegexEntityShard, ...]:
        patterns_by_entity: defaultdict[str, list[EnginePattern]] = defaultdict(list)
        for pattern in patterns:
            patterns_by_entity[pattern.identity.entity_id].append(pattern)

        shards: list[RegexEntityShard] = []
        for entity_id, entity_patterns in sorted(patterns_by_entity.items()):
            shard_patterns: list[RegexShardPattern] = []
            alternatives: list[str] = []
            for pattern in entity_patterns:
                normalized = _normalized_value(pattern, self.normalization)
                rewritten, user_capture_names = _rewrite_numeric_backrefs(normalized, _generated_group_prefix(pattern))
                scoped_pattern = _scoped_pattern(rewritten, pattern.regex_flags)
                internal_group_name = _internal_group_name(pattern)
                alternatives.append(f"(?:(?=(?:{scoped_pattern})(?P<{internal_group_name}>))|)")
                shard_patterns.append(
                    RegexShardPattern(
                        pattern=pattern,
                        internal_group_name=internal_group_name,
                        user_capture_names=user_capture_names,
                    )
                )
            try:
                shards.append(
                    RegexEntityShard(
                        entity_id=entity_id,
                        regex=re.compile("".join(alternatives)),
                        patterns=tuple(shard_patterns),
                    )
                )
            except re.error as exc:
                raise ExtractionError(f"Python re entity shard {entity_id!r} failed to compile: {exc}.") from exc
        return tuple(shards)


def _normalized_value(pattern: EnginePattern, normalization: str) -> str:
    return normalize_pattern(pattern.value, normalization)


def _internal_group_name(pattern: EnginePattern) -> str:
    return f"nerb__{pattern.identity.entity_id}__{pattern.identity.name_id}__{pattern.identity.pattern_id}"


def _generated_group_prefix(pattern: EnginePattern) -> str:
    return f"nerb_ug__{pattern.identity.entity_id}__{pattern.identity.name_id}__{pattern.identity.pattern_id}__"


def _scoped_pattern(pattern: str, flags: tuple[str, ...]) -> str:
    ordered_flags = tuple(flag for flag in REGEX_FLAG_ORDER if flag in flags)
    scoped_flags = "".join(PYTHON_RE_SCOPED_FLAGS[flag] for flag in ordered_flags)
    if not scoped_flags:
        return pattern
    return f"(?{scoped_flags}:{pattern})"


def _user_captures(match: re.Match[str], user_capture_names: tuple[str, ...]) -> dict[str, tuple[int, int]]:
    captures: dict[str, tuple[int, int]] = {}
    for group_name in user_capture_names:
        start, end = match.span(group_name)
        if start == -1 and end == -1:
            continue
        captures[group_name] = (start, end)
    return captures


def _rewrite_numeric_backrefs(pattern: str, generated_prefix: str) -> tuple[str, tuple[str, ...]]:
    rewritten: list[str] = []
    capture_number_to_name: dict[int, str] = {}
    user_capture_names: list[str] = []
    capture_number = 0
    index = 0
    in_character_class = False

    while index < len(pattern):
        character = pattern[index]
        if character == "\\":
            if in_character_class:
                rewritten.append(pattern[index : min(index + 2, len(pattern))])
                index = min(index + 2, len(pattern))
                continue
            replacement, index = _rewrite_escape(pattern, index, capture_number_to_name)
            rewritten.append(replacement)
            continue

        if character == "[":
            in_character_class = True
            rewritten.append(character)
            index += 1
            continue
        if character == "]" and in_character_class:
            in_character_class = False
            rewritten.append(character)
            index += 1
            continue

        if character == "(" and not in_character_class:
            group_replacement, next_index, capture_name = _rewrite_group_start(
                pattern,
                index,
                generated_prefix,
                capture_number + 1,
                capture_number_to_name,
            )
            if capture_name is not None:
                capture_number += 1
                capture_number_to_name[capture_number] = capture_name
                if not capture_name.startswith(generated_prefix):
                    user_capture_names.append(capture_name)
            rewritten.append(group_replacement)
            index = next_index
            continue

        rewritten.append(character)
        index += 1

    return "".join(rewritten), tuple(sorted(user_capture_names))


def _rewrite_escape(pattern: str, index: int, capture_number_to_name: dict[int, str]) -> tuple[str, int]:
    next_index = index + 1
    if next_index >= len(pattern):
        return "\\", next_index

    escaped = pattern[next_index]
    if not escaped.isdigit() or escaped == "0":
        return pattern[index : next_index + 1], next_index + 1

    end = next_index + 1
    while end < len(pattern) and pattern[end].isdigit():
        end += 1

    digits = pattern[next_index:end]
    capture_number = int(digits)
    capture_name = capture_number_to_name.get(capture_number)
    if capture_name is None:
        return pattern[index:end], end
    return f"(?P={capture_name})", end


def _rewrite_group_start(
    pattern: str,
    index: int,
    generated_prefix: str,
    next_capture_number: int,
    capture_number_to_name: dict[int, str],
) -> tuple[str, int, str | None]:
    if pattern.startswith("(?P<", index):
        end = pattern.find(">", index + 4)
        if end == -1:
            return "(", index + 1, None
        capture_name = pattern[index + 4 : end]
        return pattern[index : end + 1], end + 1, capture_name

    if pattern.startswith("(?(", index):
        end = pattern.find(")", index + 3)
        if end == -1:
            return "(", index + 1, None
        condition = pattern[index + 3 : end]
        if condition.isdigit():
            conditional_capture_name = capture_number_to_name.get(int(condition))
            if conditional_capture_name is not None:
                return f"(?({conditional_capture_name})", end + 1, None
        return pattern[index : end + 1], end + 1, None

    if pattern.startswith("(?", index):
        return "(?", index + 2, None

    capture_name = f"{generated_prefix}g{next_capture_number}"
    return f"(?P<{capture_name}>", index + 1, capture_name

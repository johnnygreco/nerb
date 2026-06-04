from __future__ import annotations

import re
from collections import defaultdict, deque
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from .engines import EnginePattern, ExtractionError
from .normalization import TextTransform, transform_text
from .records import MatchRecord, record_sort_key, serialize_record

__all__ = ["LiteralMatcher"]


@dataclass(frozen=True)
class _ExactLiteral:
    pattern: EnginePattern
    value: str


@dataclass(frozen=True)
class _AutomatonNode:
    transitions: Mapping[str, int]
    fail: int
    outputs: tuple[int, ...]


@dataclass
class _MutableAutomatonNode:
    transitions: dict[str, int]
    fail: int
    outputs: list[int]


@dataclass(frozen=True)
class _LiteralAutomaton:
    casefold: bool
    literals: tuple[_ExactLiteral, ...]
    nodes: tuple[_AutomatonNode, ...]

    @classmethod
    def compile(cls, literals: tuple[_ExactLiteral, ...], *, casefold: bool) -> _LiteralAutomaton:
        mutable_nodes = [_MutableAutomatonNode(transitions={}, fail=0, outputs=[])]

        for literal_index, literal in enumerate(literals):
            state = 0
            for character in literal.value:
                next_state = mutable_nodes[state].transitions.get(character)
                if next_state is None:
                    next_state = len(mutable_nodes)
                    mutable_nodes[state].transitions[character] = next_state
                    mutable_nodes.append(_MutableAutomatonNode(transitions={}, fail=0, outputs=[]))
                state = next_state
            mutable_nodes[state].outputs.append(literal_index)

        queue: deque[int] = deque()
        queue.extend(mutable_nodes[0].transitions.values())

        while queue:
            state = queue.popleft()

            for character, next_state in mutable_nodes[state].transitions.items():
                queue.append(next_state)

                fail_state = mutable_nodes[state].fail
                while fail_state and character not in mutable_nodes[fail_state].transitions:
                    fail_state = mutable_nodes[fail_state].fail

                next_fail = mutable_nodes[fail_state].transitions.get(character, 0)
                mutable_nodes[next_state].fail = next_fail
                mutable_nodes[next_state].outputs.extend(mutable_nodes[next_fail].outputs)

        nodes = tuple(
            _AutomatonNode(
                transitions=MappingProxyType(dict(node.transitions)),
                fail=node.fail,
                outputs=tuple(node.outputs),
            )
            for node in mutable_nodes
        )
        return cls(casefold=casefold, literals=literals, nodes=nodes)

    @property
    def pattern_count(self) -> int:
        return len(self.literals)

    def finditer(self, transform: TextTransform) -> list[MatchRecord]:
        records: list[MatchRecord] = []
        state = 0
        transformed_text = transform.transformed_text

        for index, character in enumerate(transformed_text):
            while state and character not in self.nodes[state].transitions:
                state = self.nodes[state].fail
            state = self.nodes[state].transitions.get(character, 0)

            for literal_index in self.nodes[state].outputs:
                literal = self.literals[literal_index]
                end = index + 1
                start = end - len(literal.value)
                if start < 0 or not _matches_boundaries(literal.pattern, transformed_text, start, end):
                    continue
                records.append(serialize_record(literal.pattern.identity, transform, start, end, {}))

        return records


@dataclass(frozen=True)
class _CompiledLiteralRegex:
    pattern: EnginePattern
    regex: re.Pattern[str]


@dataclass(frozen=True)
class LiteralEntityShard:
    entity_id: str
    automatons: tuple[_LiteralAutomaton, ...]
    regex_fallbacks: tuple[_CompiledLiteralRegex, ...]

    @property
    def pattern_count(self) -> int:
        return self.exact_pattern_count + self.regex_fallback_pattern_count

    @property
    def exact_pattern_count(self) -> int:
        return sum(automaton.pattern_count for automaton in self.automatons)

    @property
    def regex_fallback_pattern_count(self) -> int:
        return len(self.regex_fallbacks)

    def finditer(
        self,
        text: str,
        *,
        normalization: str,
        transforms: dict[bool, TextTransform],
    ) -> list[MatchRecord]:
        records: list[MatchRecord] = []
        for automaton in self.automatons:
            transform = _transform_for(text, normalization=normalization, casefold=automaton.casefold, cache=transforms)
            records.extend(automaton.finditer(transform))

        for fallback in self.regex_fallbacks:
            transform = _transform_for(
                text,
                normalization=normalization,
                casefold=not fallback.pattern.case_sensitive,
                cache=transforms,
            )
            for match in fallback.regex.finditer(transform.transformed_text):
                start, end = match.span(1)
                if start < 0 or end < start:
                    continue
                records.append(serialize_record(fallback.pattern.identity, transform, start, end, {}))
        return records


class LiteralMatcher:
    name = "literal"
    version = "1"

    def __init__(self, patterns: tuple[EnginePattern, ...], *, normalization: str) -> None:
        self.normalization = normalization
        self.pattern_count = len(patterns)
        self.entity_shards = self._compile_entity_shards(patterns)

    def finditer(self, text: str) -> list[MatchRecord]:
        records: list[MatchRecord] = []
        transforms: dict[bool, TextTransform] = {}

        for shard in self.entity_shards:
            records.extend(shard.finditer(text, normalization=self.normalization, transforms=transforms))

        records.sort(key=record_sort_key)
        return records

    def _compile_entity_shards(self, patterns: tuple[EnginePattern, ...]) -> tuple[LiteralEntityShard, ...]:
        exact_by_entity_casefold: defaultdict[tuple[str, bool], list[_ExactLiteral]] = defaultdict(list)
        fallback_by_entity: defaultdict[str, list[EnginePattern]] = defaultdict(list)

        for pattern in patterns:
            casefold = not pattern.case_sensitive
            transformed_literal = transform_text(
                pattern.value,
                self.normalization,
                casefold=casefold,
            ).transformed_text
            if _needs_regex_fallback(pattern, transformed_literal):
                fallback_by_entity[pattern.identity.entity_id].append(pattern)
            else:
                exact_by_entity_casefold[(pattern.identity.entity_id, casefold)].append(
                    _ExactLiteral(pattern=pattern, value=transformed_literal)
                )

        entity_ids = sorted(
            {
                *[entity_id for entity_id, _casefold in exact_by_entity_casefold],
                *fallback_by_entity.keys(),
            }
        )
        shards: list[LiteralEntityShard] = []
        for entity_id in entity_ids:
            automatons = []
            for casefold in (False, True):
                literals = tuple(exact_by_entity_casefold.get((entity_id, casefold), ()))
                if literals:
                    automatons.append(_LiteralAutomaton.compile(literals, casefold=casefold))
            regex_fallbacks = tuple(self._compile_regex_fallback(pattern) for pattern in fallback_by_entity[entity_id])
            shards.append(
                LiteralEntityShard(
                    entity_id=entity_id,
                    automatons=tuple(automatons),
                    regex_fallbacks=regex_fallbacks,
                )
            )
        return tuple(shards)

    def _compile_regex_fallback(self, pattern: EnginePattern) -> _CompiledLiteralRegex:
        transformed_literal = transform_text(
            pattern.value,
            self.normalization,
            casefold=not pattern.case_sensitive,
        ).transformed_text
        literal_pattern = _literal_regex(
            transformed_literal,
            normalize_whitespace=pattern.normalize_whitespace,
            left_boundary=pattern.left_boundary,
            right_boundary=pattern.right_boundary,
        )
        try:
            return _CompiledLiteralRegex(pattern=pattern, regex=re.compile(f"(?=({literal_pattern}))"))
        except re.error as exc:
            raise ExtractionError(
                "Literal pattern failed to compile in the regex fallback: "
                f"{pattern.identity.entity_id}/{pattern.identity.name_id}/{pattern.identity.pattern_id}: {exc}."
            ) from exc


def _transform_for(
    text: str,
    *,
    normalization: str,
    casefold: bool,
    cache: dict[bool, TextTransform],
) -> TextTransform:
    transform = cache.get(casefold)
    if transform is None:
        transform = transform_text(text, normalization, casefold=casefold)
        cache[casefold] = transform
    return transform


def _needs_regex_fallback(pattern: EnginePattern, transformed_literal: str) -> bool:
    return pattern.normalize_whitespace and any(character.isspace() for character in transformed_literal)


def _is_word_character(character: str) -> bool:
    return character == "_" or character.isalnum()


def _word_boundary_at(text: str, index: int) -> bool:
    before = index > 0 and _is_word_character(text[index - 1])
    after = index < len(text) and _is_word_character(text[index])
    return before != after


def _matches_boundaries(pattern: EnginePattern, text: str, start: int, end: int) -> bool:
    if pattern.left_boundary == "word" and not _word_boundary_at(text, start):
        return False
    return pattern.right_boundary != "word" or _word_boundary_at(text, end)


def _literal_regex(
    literal: str,
    *,
    normalize_whitespace: bool,
    left_boundary: str,
    right_boundary: str,
) -> str:
    parts: list[str] = []
    index = 0
    while index < len(literal):
        character = literal[index]
        if normalize_whitespace and character.isspace():
            while index < len(literal) and literal[index].isspace():
                index += 1
            parts.append(r"\s+")
            continue
        parts.append(re.escape(character))
        index += 1

    body = "".join(parts)
    if left_boundary == "word":
        body = r"\b" + body
    if right_boundary == "word":
        body += r"\b"
    return body

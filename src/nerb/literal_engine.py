from __future__ import annotations

import re

from .engines import EnginePattern, ExtractionError
from .normalization import transform_text
from .records import MatchRecord, record_sort_key, serialize_record

__all__ = ["LiteralMatcher"]


class LiteralMatcher:
    name = "literal"
    version = "1"

    def __init__(self, patterns: tuple[EnginePattern, ...], *, normalization: str) -> None:
        self.normalization = normalization
        self._compiled_patterns = tuple(self._compile_pattern(pattern) for pattern in patterns)

    def finditer(self, text: str) -> list[MatchRecord]:
        records: list[MatchRecord] = []
        by_casefold = {
            False: transform_text(text, self.normalization),
            True: transform_text(text, self.normalization, casefold=True),
        }

        for pattern, compiled in self._compiled_patterns:
            transform = by_casefold[not pattern.case_sensitive]
            for match in compiled.finditer(transform.transformed_text):
                start, end = match.span(1)
                if start < 0 or end < start:
                    continue
                records.append(serialize_record(pattern.identity, transform, start, end, {}))

        records.sort(key=record_sort_key)
        return records

    def _compile_pattern(self, pattern: EnginePattern) -> tuple[EnginePattern, re.Pattern[str]]:
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
            return pattern, re.compile(f"(?=({literal_pattern}))")
        except re.error as exc:
            raise ExtractionError(
                "Literal pattern failed to compile in the regex fallback: "
                f"{pattern.identity.entity_id}/{pattern.identity.name_id}/{pattern.identity.pattern_id}: {exc}."
            ) from exc


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

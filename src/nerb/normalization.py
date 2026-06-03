from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from typing import Literal, cast

NormalizationMode = Literal["none", "NFC", "NFKC"]
UnicodeNormalizeForm = Literal["NFC", "NFD", "NFKC", "NFKD"]
OffsetSpan = tuple[int, int]

__all__ = ["NormalizationMode", "TextTransform", "normalize_pattern", "transform_text"]


@dataclass(frozen=True)
class TextTransform:
    """Text transformed for matching plus offsets back to the original input."""

    original_text: str
    transformed_text: str
    offset_map: list[OffsetSpan]

    def original_span(self, start: int, end: int) -> OffsetSpan:
        if start < 0 or end < start or end > len(self.transformed_text):
            raise ValueError("Transformed span is outside the transformed text.")

        if start == end:
            position = self.original_position(start)
            return (position, position)

        return (self.offset_map[start][0], self.offset_map[end - 1][1])

    def original_position(self, index: int) -> int:
        if index < 0 or index > len(self.transformed_text):
            raise ValueError("Transformed position is outside the transformed text.")
        if not self.offset_map:
            return 0
        if index == len(self.transformed_text):
            return self.offset_map[-1][1]
        return self.offset_map[index][0]


def _normalize_cluster(cluster: str, mode: str) -> str:
    if mode == "none":
        return cluster
    if mode not in {"NFC", "NFKC"}:
        raise ValueError("unicode_normalization must be one of none, NFC, or NFKC.")
    return unicodedata.normalize(cast(UnicodeNormalizeForm, mode), cluster)


def _iter_clusters(text: str) -> list[tuple[str, int, int]]:
    clusters: list[tuple[str, int, int]] = []
    start = 0
    for index, character in enumerate(text):
        if index > start and unicodedata.combining(character) == 0:
            clusters.append((text[start:index], start, index))
            start = index
    if text:
        clusters.append((text[start:], start, len(text)))
    return clusters


def transform_text(text: str, mode: str, *, casefold: bool = False) -> TextTransform:
    transformed_parts: list[str] = []
    offset_map: list[OffsetSpan] = []

    for cluster, start, end in _iter_clusters(text):
        normalized_cluster = _normalize_cluster(cluster, mode)
        for character in normalized_cluster:
            output = character.casefold() if casefold else character
            transformed_parts.append(output)
            offset_map.extend((start, end) for _ in output)

    return TextTransform(text, "".join(transformed_parts), offset_map)


def normalize_pattern(pattern: str, mode: str) -> str:
    if mode == "none":
        return pattern
    if mode not in {"NFC", "NFKC"}:
        raise ValueError("unicode_normalization must be one of none, NFC, or NFKC.")
    return unicodedata.normalize(cast(UnicodeNormalizeForm, mode), pattern)

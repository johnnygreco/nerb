from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .normalization import TextTransform

__all__ = ["CaptureRecord", "MatchRecord", "record_sort_key", "serialize_record"]

CaptureRecord = dict[str, int | str]
MatchRecord = dict[str, Any]


@dataclass(frozen=True)
class PatternIdentity:
    entity_id: str
    name_id: str
    pattern_id: str
    pattern_kind: str
    canonical_name: str


def serialize_record(
    identity: PatternIdentity,
    transform: TextTransform,
    transformed_start: int,
    transformed_end: int,
    captures: dict[str, tuple[int, int]],
) -> MatchRecord:
    start, end = transform.original_span(transformed_start, transformed_end)
    return {
        "entity_id": identity.entity_id,
        "entity": identity.entity_id,
        "name_id": identity.name_id,
        "name": identity.canonical_name,
        "pattern_id": identity.pattern_id,
        "pattern_kind": identity.pattern_kind,
        "string": transform.original_text[start:end],
        "start": start,
        "end": end,
        "captures": {
            capture_name: _serialize_capture(transform, capture_start, capture_end)
            for capture_name, (capture_start, capture_end) in sorted(captures.items())
        },
    }


def _serialize_capture(transform: TextTransform, start: int, end: int) -> CaptureRecord:
    original_start, original_end = transform.original_span(start, end)
    return {
        "string": transform.original_text[original_start:original_end],
        "start": original_start,
        "end": original_end,
    }


def record_sort_key(record: MatchRecord) -> tuple[int, int, str, str, str, str]:
    return (
        int(record["start"]),
        int(record["end"]),
        str(record["entity_id"]),
        str(record["name_id"]),
        str(record["pattern_id"]),
        str(record["string"]),
    )

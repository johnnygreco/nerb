from __future__ import annotations

from typing import Any

__all__ = ["MatchRecord", "record_sort_key"]

MatchRecord = dict[str, Any]


def record_sort_key(record: MatchRecord) -> tuple[int, int, str, str, str, str]:
    return (
        int(record["start"]),
        int(record["end"]),
        str(record["entity_id"]),
        str(record["name_id"]),
        str(record["pattern_id"]),
        str(record["string"]),
    )

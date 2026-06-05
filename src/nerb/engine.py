from __future__ import annotations

import importlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from .config import FLAGS_KEY, PatternConfig

OffsetUnit = Literal["byte", "char"]

__all__ = ["Bank"]


class Bank:
    """High-level Python wrapper around the native Rust NERB bank."""

    def __init__(self, native_bank: Any) -> None:
        self._native = native_bank

    @classmethod
    def from_source_bytes(
        cls,
        source: bytes,
        *,
        format_hint: str | None = None,
        compile_options_json: str | None = None,
    ) -> Bank:
        native_engine = importlib.import_module("nerb._engine")

        return cls(
            native_engine.Bank.from_source_bytes(
                source,
                format_hint=format_hint,
                compile_options_json=compile_options_json,
            )
        )

    @classmethod
    def from_canonical_json_bytes(cls, source: bytes, *, compile_options_json: str | None = None) -> Bank:
        native_engine = importlib.import_module("nerb._engine")

        return cls(native_engine.Bank.from_canonical_json_bytes(source, compile_options_json=compile_options_json))

    @classmethod
    def from_path(
        cls,
        path: str | Path,
        *,
        format_hint: str | None = None,
        compile_options_json: str | None = None,
    ) -> Bank:
        source_path = Path(path).expanduser()
        return cls.from_source_bytes(
            source_path.read_bytes(),
            format_hint=format_hint,
            compile_options_json=compile_options_json,
        )

    @classmethod
    def from_config(
        cls,
        pattern_config: PatternConfig,
        *,
        selected_entity: str | None = None,
        word_boundaries: bool = False,
        compile_options_json: str | None = None,
    ) -> Bank:
        source = _config_to_jsonl_source(
            pattern_config,
            selected_entity=selected_entity,
            word_boundaries=word_boundaries,
        )
        return cls.from_source_bytes(source, format_hint="jsonl", compile_options_json=compile_options_json)

    def to_canonical_json_bytes(self) -> bytes:
        return self._native.to_canonical_json_bytes()

    def metadata(self) -> dict[str, Any]:
        return dict(self._native.metadata())

    def scan_bytes(self, haystack: bytes | bytearray | memoryview) -> list[dict[str, Any]]:
        text_bytes = bytes(haystack)
        raw = self._native.scan_bytes(text_bytes)
        return _project_raw_matches(self.metadata(), raw, text_bytes, offset_unit="byte")

    def scan_text(self, text: str, *, offsets: OffsetUnit = "byte") -> list[dict[str, Any]]:
        if not isinstance(text, str):
            raise TypeError("Bank.scan_text text must be a string.")
        if offsets not in {"byte", "char"}:
            raise ValueError('Bank.scan_text offsets must be "byte" or "char".')

        text_bytes = text.encode("utf-8")
        raw = self._native.scan_bytes(text_bytes)
        records = _project_raw_matches(self.metadata(), raw, text_bytes, offset_unit="byte")
        if offsets == "byte":
            return records
        return _project_char_offsets(records, text)

    def scan_path(self, path: str | Path) -> list[dict[str, Any]]:
        source_path = Path(path).expanduser()
        return self.scan_bytes(source_path.read_bytes())


def _config_to_jsonl_source(
    pattern_config: PatternConfig,
    *,
    selected_entity: str | None,
    word_boundaries: bool,
) -> bytes:
    rows = []
    for entity, entity_config in pattern_config.items():
        if selected_entity is not None and entity != selected_entity:
            continue
        flags = _flag_list(entity_config.get(FLAGS_KEY, []))
        priority = 0
        for canonical_name, regex in entity_config.items():
            if canonical_name == FLAGS_KEY:
                continue
            wrapped_regex = rf"\b(?:{regex})\b" if word_boundaries else str(regex)
            rows.append(
                {
                    "entity": entity,
                    "canonical_name": canonical_name,
                    "surface_name": canonical_name,
                    "regex": wrapped_regex,
                    "flags": flags,
                    "priority": priority,
                }
            )
            priority += 1

    if not rows:
        raise ValueError("Rust-backed Bank requires at least one detector pattern.")

    return ("\n".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")) for row in rows) + "\n").encode(
        "utf-8"
    )


def _flag_list(raw_flags: Any) -> list[str]:
    if raw_flags is None:
        return []
    if isinstance(raw_flags, str):
        return [raw_flags]
    if isinstance(raw_flags, list):
        return [str(flag) for flag in raw_flags]
    return [str(raw_flags)]


def _project_raw_matches(
    metadata: Mapping[str, Any],
    raw: Any,
    text_bytes: bytes,
    *,
    offset_unit: OffsetUnit,
) -> list[dict[str, Any]]:
    detectors = {detector["detector_index"]: detector for detector in metadata["detectors"]}
    records: list[dict[str, Any]] = []
    for index in range(len(raw)):
        detector_index, start, end = raw[index]
        detector = detectors[detector_index]
        records.append(
            {
                "entity": detector["entity"],
                "canonical_name": detector["canonical_name"],
                "surface_name": detector["surface_name"],
                "string": text_bytes[start:end].decode("utf-8"),
                "start": start,
                "end": end,
                "offset_unit": offset_unit,
            }
        )
    records.sort(key=_record_sort_key)
    return records


def _project_char_offsets(records: list[dict[str, Any]], text: str) -> list[dict[str, Any]]:
    byte_to_char = _byte_to_char_offset_map(text)
    projected: list[dict[str, Any]] = []
    for record in records:
        start = byte_to_char[record["start"]]
        end = byte_to_char[record["end"]]
        projected.append(
            {
                **record,
                "string": text[start:end],
                "start": start,
                "end": end,
                "offset_unit": "char",
            }
        )
    projected.sort(key=_record_sort_key)
    return projected


def _byte_to_char_offset_map(text: str) -> dict[int, int]:
    byte_to_char = {0: 0}
    byte_offset = 0
    for char_offset, character in enumerate(text, start=1):
        byte_offset += len(character.encode("utf-8"))
        byte_to_char[byte_offset] = char_offset
    return byte_to_char


def _record_sort_key(record: Mapping[str, Any]) -> tuple[int, int, str, str, str, str]:
    return (
        int(record["start"]),
        int(record["end"]),
        str(record["entity"]),
        str(record["canonical_name"]),
        str(record["surface_name"]),
        str(record["string"]),
    )

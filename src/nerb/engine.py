from __future__ import annotations

import importlib
import json
import sys
import sysconfig
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from threading import RLock
from typing import Any, Literal

from .config import FLAGS_KEY, PatternConfig

OffsetUnit = Literal["byte", "char"]

__all__ = ["Bank", "BankCacheKey", "bank_cache_info", "clear_bank_cache"]


@dataclass(frozen=True)
class BankCacheKey:
    bank_hash: str
    schema_version: int
    semantic_version: str
    engine_name: str
    engine_version: str
    canonical_engine: str
    compile_options_json: str
    target_triple: str
    platform: str
    pointer_width: int
    endian: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "bank_hash": self.bank_hash,
            "schema_version": self.schema_version,
            "semantic_version": self.semantic_version,
            "engine_name": self.engine_name,
            "engine_version": self.engine_version,
            "canonical_engine": self.canonical_engine,
            "compile_options": json.loads(self.compile_options_json),
            "target_triple": self.target_triple,
            "platform": self.platform,
            "pointer_width": self.pointer_width,
            "endian": self.endian,
        }


@dataclass(frozen=True)
class _BankSourceCacheKey:
    source_sha256: str
    source_size: int
    format_hint: str | None
    compile_options_json: str
    semantic_version: str
    engine_name: str
    engine_version: str
    target_triple: str
    platform: str
    pointer_width: int
    endian: str


_BANK_CACHE_LOCK = RLock()
_BANK_CACHE: dict[BankCacheKey, Any] = {}
_SOURCE_CACHE_KEYS: dict[_BankSourceCacheKey, BankCacheKey] = {}
_CACHE_HITS = 0
_CACHE_MISSES = 0


class Bank:
    """High-level Python wrapper around the native Rust NERB bank."""

    def __init__(self, native_bank: Any, *, cache_key: BankCacheKey | None = None, cache_hit: bool = False) -> None:
        self._native = native_bank
        self._cache_key = cache_key
        self._cache_hit = cache_hit

    @classmethod
    def from_source_bytes(
        cls,
        source: bytes,
        *,
        format_hint: str | None = None,
        compile_options_json: str | None = None,
        use_cache: bool = True,
    ) -> Bank:
        native_engine = importlib.import_module("nerb._engine")
        source_bytes = bytes(source)
        normalized_options = _canonical_compile_options_json(compile_options_json)
        native_options = None if normalized_options == "{}" else normalized_options

        if not use_cache:
            native_bank = native_engine.Bank.from_source_bytes(
                source_bytes,
                format_hint=format_hint,
                compile_options_json=native_options,
            )
            return cls(native_bank)

        source_key = _source_cache_key(
            native_engine,
            source_bytes,
            format_hint=format_hint,
            compile_options_json=normalized_options,
        )
        with _BANK_CACHE_LOCK:
            cached_key = _SOURCE_CACHE_KEYS.get(source_key)
            if cached_key is not None:
                cached_bank = _BANK_CACHE.get(cached_key)
                if cached_bank is not None:
                    _record_cache_hit()
                    return cls(cached_bank, cache_key=cached_key, cache_hit=True)

        native_bank = native_engine.Bank.from_source_bytes(
            source_bytes,
            format_hint=format_hint,
            compile_options_json=native_options,
        )
        cache_key = _cache_key_from_metadata(native_engine, native_bank.metadata())
        with _BANK_CACHE_LOCK:
            cached_bank = _BANK_CACHE.get(cache_key)
            if cached_bank is not None:
                _SOURCE_CACHE_KEYS[source_key] = cache_key
                _record_cache_hit()
                return cls(cached_bank, cache_key=cache_key, cache_hit=True)

            _BANK_CACHE[cache_key] = native_bank
            _SOURCE_CACHE_KEYS[source_key] = cache_key
            _record_cache_miss()
        return cls(native_bank, cache_key=cache_key, cache_hit=False)

    @classmethod
    def from_canonical_json_bytes(
        cls,
        source: bytes,
        *,
        compile_options_json: str | None = None,
        use_cache: bool = True,
    ) -> Bank:
        return cls.from_source_bytes(
            source,
            format_hint="canonical_json",
            compile_options_json=compile_options_json,
            use_cache=use_cache,
        )

    @classmethod
    def from_path(
        cls,
        path: str | Path,
        *,
        format_hint: str | None = None,
        compile_options_json: str | None = None,
        use_cache: bool = True,
    ) -> Bank:
        source_path = Path(path).expanduser()
        return cls.from_source_bytes(
            source_path.read_bytes(),
            format_hint=format_hint,
            compile_options_json=compile_options_json,
            use_cache=use_cache,
        )

    @classmethod
    def from_config(
        cls,
        pattern_config: PatternConfig,
        *,
        selected_entity: str | None = None,
        word_boundaries: bool = False,
        compile_options_json: str | None = None,
        use_cache: bool = True,
    ) -> Bank:
        source = _config_to_jsonl_source(
            pattern_config,
            selected_entity=selected_entity,
        )
        compile_options_json = _compile_options_with_word_boundaries(compile_options_json, word_boundaries)
        return cls.from_source_bytes(
            source,
            format_hint="jsonl",
            compile_options_json=compile_options_json,
            use_cache=use_cache,
        )

    def cache_metadata(self) -> dict[str, Any]:
        return {
            "enabled": self._cache_key is not None,
            "hit": self._cache_hit,
            "key": self._cache_key.to_dict() if self._cache_key is not None else None,
        }

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


def clear_bank_cache() -> None:
    global _CACHE_HITS, _CACHE_MISSES
    with _BANK_CACHE_LOCK:
        _BANK_CACHE.clear()
        _SOURCE_CACHE_KEYS.clear()
        _CACHE_HITS = 0
        _CACHE_MISSES = 0


def bank_cache_info() -> dict[str, Any]:
    with _BANK_CACHE_LOCK:
        return {
            "size": len(_BANK_CACHE),
            "source_key_count": len(_SOURCE_CACHE_KEYS),
            "hits": _CACHE_HITS,
            "misses": _CACHE_MISSES,
            "keys": [key.to_dict() for key in _BANK_CACHE],
        }


def _record_cache_hit() -> None:
    global _CACHE_HITS
    _CACHE_HITS += 1


def _record_cache_miss() -> None:
    global _CACHE_MISSES
    _CACHE_MISSES += 1


def _source_cache_key(
    native_engine: Any,
    source: bytes,
    *,
    format_hint: str | None,
    compile_options_json: str,
) -> _BankSourceCacheKey:
    return _BankSourceCacheKey(
        source_sha256=sha256(source).hexdigest(),
        source_size=len(source),
        format_hint=_normalize_format_hint(format_hint),
        compile_options_json=compile_options_json,
        semantic_version=str(native_engine.__version__),
        engine_name=str(native_engine.ENGINE_NAME),
        engine_version=str(native_engine.__version__),
        target_triple=_target_triple(),
        platform=sysconfig.get_platform(),
        pointer_width=_pointer_width(),
        endian=sys.byteorder,
    )


def _cache_key_from_metadata(native_engine: Any, metadata: Mapping[str, Any]) -> BankCacheKey:
    defaults = dict(metadata["defaults"])
    compile_options = dict(metadata["compile_options"])
    return BankCacheKey(
        bank_hash=str(metadata["bank_hash"]),
        schema_version=int(metadata["schema"]),
        semantic_version=str(native_engine.__version__),
        engine_name=str(native_engine.ENGINE_NAME),
        engine_version=str(native_engine.__version__),
        canonical_engine=str(defaults["engine"]),
        compile_options_json=json.dumps(compile_options, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
        target_triple=_target_triple(),
        platform=sysconfig.get_platform(),
        pointer_width=_pointer_width(),
        endian=sys.byteorder,
    )


def _target_triple() -> str:
    multiarch = sysconfig.get_config_var("MULTIARCH")
    if multiarch:
        return str(multiarch)
    return sysconfig.get_platform()


def _pointer_width() -> int:
    return 64 if sys.maxsize > 2**32 else 32


def _normalize_format_hint(format_hint: str | None) -> str | None:
    if format_hint is None:
        return None
    normalized = format_hint.strip().lower().replace("-", "_")
    return normalized or None


def _canonical_compile_options_json(compile_options_json: str | None) -> str:
    if compile_options_json is None:
        return "{}"
    options = _load_compile_options_json(compile_options_json)
    if not isinstance(options, dict):
        raise ValueError("compile_options_json must decode to a JSON object.")
    return json.dumps(options, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _load_compile_options_json(compile_options_json: str) -> Any:
    return json.loads(
        compile_options_json,
        object_pairs_hook=_reject_duplicate_json_object_keys,
        parse_constant=_reject_non_finite_json_constant,
    )


def _reject_duplicate_json_object_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"compile_options_json must not contain duplicate key {key!r}.")
        result[key] = value
    return result


def _reject_non_finite_json_constant(constant: str) -> None:
    raise ValueError(f"compile_options_json must not contain non-finite value {constant}.")


def _config_to_jsonl_source(
    pattern_config: PatternConfig,
    *,
    selected_entity: str | None,
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
            rows.append(
                {
                    "entity": entity,
                    "canonical_name": canonical_name,
                    "surface_name": canonical_name,
                    "regex": str(regex),
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


def _compile_options_with_word_boundaries(compile_options_json: str | None, enabled: bool) -> str | None:
    if not enabled:
        return compile_options_json

    if compile_options_json is None:
        options: dict[str, Any] = {}
    else:
        options_value = _load_compile_options_json(compile_options_json)
        if not isinstance(options_value, dict):
            raise ValueError("compile_options_json must decode to a JSON object.")
        options = dict(options_value)

    options["word_boundaries"] = True
    return json.dumps(options, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


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

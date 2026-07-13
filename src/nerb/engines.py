from __future__ import annotations

import hashlib
import importlib
import json
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, cast

from .bank import bank_stats, canonicalize_bank, hash_bank
from .diagnostics import DIAGNOSTIC_ERROR, Diagnostic, diagnostic, has_errors
from .engine import Bank
from .records import MatchRecord, record_sort_key
from .schema import STATUS_VALUES, validate_bank_schema

DEFAULT_INCLUDE_STATUSES = ("active",)
DEFAULT_ENGINE_NAME = "nerb_engine"
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
    "ExtractionError",
    "compile_bank_with_report",
    "extraction_execution_sha256",
    "extraction_semantics_sha256",
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


@lru_cache(maxsize=1)
def extraction_execution_sha256() -> str:
    """Fingerprint the Python scan adapters and loaded native engine binary."""

    from . import bank as bank_module
    from . import engine as engine_module
    from . import records as records_module

    native_module = importlib.import_module("nerb._engine")
    sources = (
        ("bank.py", bank_module.__file__),
        ("engine.py", engine_module.__file__),
        ("engines.py", __file__),
        ("records.py", records_module.__file__),
        ("native_engine", getattr(native_module, "__file__", None)),
    )
    descriptors: list[dict[str, Any]] = []
    try:
        for logical_id, source_path in sources:
            if not isinstance(source_path, str) or not source_path:
                raise OSError
            payload = Path(source_path).read_bytes()
            descriptors.append(
                {
                    "id": logical_id,
                    "bytes": len(payload),
                    "sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
                }
            )
    except OSError:
        raise ExtractionError("Extraction execution sources could not be fingerprinted safely.") from None
    return (
        "sha256:"
        + hashlib.sha256(
            json.dumps(
                {
                    "schema_version": "nerb.extraction_execution.v1",
                    "sources": descriptors,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
    )


@lru_cache(maxsize=1)
def extraction_semantics_sha256() -> str:
    """Fingerprint platform-neutral Python and native extraction semantics."""

    from . import bank as bank_module
    from . import engine as engine_module
    from . import records as records_module

    native_module = importlib.import_module("nerb._engine")
    native_build_source_sha256 = getattr(native_module, "BUILD_SOURCE_SHA256", None)
    if (
        not isinstance(native_build_source_sha256, str)
        or not native_build_source_sha256.startswith("sha256:")
        or len(native_build_source_sha256) != 71
    ):
        raise ExtractionError("Native extraction build-source identity is unavailable.")
    sources = (
        ("bank.py", bank_module.__file__),
        ("engine.py", engine_module.__file__),
        ("engines.py", __file__),
        ("records.py", records_module.__file__),
    )
    payloads: dict[str, bytes] = {}
    try:
        for logical_id, source_path in sources:
            if not isinstance(source_path, str) or not source_path:
                raise OSError
            payloads[logical_id] = Path(source_path).read_bytes()
    except OSError:
        raise ExtractionError("Extraction semantic sources could not be fingerprinted safely.") from None
    return _extraction_semantics_hash(payloads, native_build_source_sha256)


def _extraction_semantics_hash(source_payloads: Mapping[str, bytes], native_build_source_sha256: str) -> str:
    descriptors = []
    for logical_id in sorted(source_payloads):
        normalized = _normalized_lf_source(source_payloads[logical_id])
        descriptors.append(
            {
                "id": logical_id,
                "bytes": len(normalized),
                "sha256": "sha256:" + hashlib.sha256(normalized).hexdigest(),
            }
        )
    payload = {
        "schema_version": "nerb.extraction_semantics.v1",
        "python_sources": descriptors,
        "native_build_source_sha256": native_build_source_sha256,
    }
    return (
        "sha256:"
        + hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    )


def _normalized_lf_source(payload: bytes) -> bytes:
    normalized = payload.replace(b"\r\n", b"\n")
    if b"\r" in normalized:
        raise ExtractionError("Extraction semantic source contains a bare carriage return.")
    return normalized


@dataclass(frozen=True)
class ResolvedExtractionOptions:
    include_statuses: tuple[str, ...]
    engine: str
    engine_options: dict[str, Any]
    max_text_bytes: int
    max_batch_documents: int
    max_batch_text_bytes: int


@dataclass(frozen=True)
class _DetectorIdentity:
    entity_id: str
    name_id: str
    pattern_id: str
    pattern_kind: str
    canonical_name: str


@dataclass(frozen=True)
class CompiledBank:
    bank: dict[str, Any]
    extractable_bank: dict[str, Any] | None
    bank_hash: str
    normalization: str
    include_statuses: tuple[str, ...]
    engine_name: str
    engine_version: str
    engine_options: dict[str, Any]
    native_bank: Bank | None
    cache_metadata: dict[str, Any]
    detector_index: Mapping[tuple[str, str, str], _DetectorIdentity]

    def finditer(self, text: str, *, max_matches: int | None = None) -> list[MatchRecord]:
        if self.native_bank is None:
            return []

        records = [
            _enrich_json_bank_record(record, self.detector_index)
            for record in self.native_bank.scan_text(text, max_matches=max_matches)
        ]
        records.sort(key=record_sort_key)
        return records


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
    if engine != DEFAULT_ENGINE_NAME:
        raise ExtractionError(f"Extraction engine must be {DEFAULT_ENGINE_NAME!r}.")

    engine_options = options.get("engine_options", {})
    if not isinstance(engine_options, Mapping):
        raise ExtractionError("Extraction option engine_options must be an object.")
    engine_options_dict = dict(engine_options)
    match_mode = engine_options_dict.get("match_mode")
    if match_mode is not None:
        if match_mode != "entity_independent":
            raise ExtractionError(
                f"Public JSON-bank extraction only supports match_mode 'entity_independent'; got {match_mode!r}."
            )
        del engine_options_dict["match_mode"]

    return ResolvedExtractionOptions(
        include_statuses=statuses,
        engine=engine,
        engine_options=engine_options_dict,
        max_text_bytes=_positive_int_option(options, "max_text_bytes", DEFAULT_MAX_TEXT_BYTES),
        max_batch_documents=_positive_int_option(options, "max_batch_documents", DEFAULT_MAX_BATCH_DOCUMENTS),
        max_batch_text_bytes=_positive_int_option(options, "max_batch_text_bytes", DEFAULT_MAX_BATCH_TEXT_BYTES),
    )


def compile_bank(bank: Mapping[str, Any], *, options: Mapping[str, Any] | None = None) -> tuple[CompiledBank, bool]:
    resolved = resolve_extraction_options(options)

    schema_result = validate_bank_schema(bank)
    diagnostics = schema_result["diagnostics"]
    if has_errors(diagnostics):
        raise ExtractionError("Bank failed schema validation and cannot be extracted.", diagnostics)

    try:
        canonical_bank = canonicalize_bank(bank)
    except TypeError as exc:
        raise ExtractionError("Bank failed schema validation and cannot be extracted.", diagnostics) from exc

    if canonical_bank.get("status") not in resolved.include_statuses:
        raise ExtractionError(
            f"Bank status {canonical_bank.get('status')!r} is not included in extraction statuses "
            f"{list(resolved.include_statuses)!r}."
        )

    extractable_bank = _filter_extractable_bank(canonical_bank, resolved.include_statuses)
    if extractable_bank is None:
        return _uncompiled_bank(canonical_bank, resolved, hash_bank(canonical_bank)), False

    compile_options_json = _canonical_options(resolved.engine_options)
    try:
        native_bank = Bank.from_source_bytes(
            _json_source(extractable_bank),
            format_hint="json",
            compile_options_json=compile_options_json,
        )
    except ValueError as exc:
        diagnostics = [
            diagnostic(
                DIAGNOSTIC_ERROR,
                "engine.compile_error",
                "",
                f"Rust engine failed to compile the bank: {exc}.",
            )
        ]
        message = f"Bank failed Rust engine validation and cannot be extracted: {exc}."
        raise ExtractionError(message, diagnostics) from exc

    from .validation import rust_empty_match_diagnostics

    empty_match_diagnostics = rust_empty_match_diagnostics(native_bank)
    if empty_match_diagnostics:
        raise ExtractionError("Bank failed runtime validation and cannot be extracted.", empty_match_diagnostics)

    compiled = _compiled_bank_from_native(
        canonical_bank,
        extractable_bank,
        resolved,
        native_bank,
        detector_index=_json_bank_detector_index(extractable_bank),
    )
    return compiled, bool(compiled.cache_metadata.get("hit"))


def compile_bank_with_report(
    bank: Mapping[str, Any],
    *,
    options: Mapping[str, Any] | None = None,
) -> tuple[CompiledBank, bool, dict[str, Any]]:
    report: dict[str, Any] = {
        "schema_version": "nerb.json_bank_compile_report.v1",
        "source": {
            "canonical_bank_hash": None,
            "canonical_json_bytes": None,
            "extractable_json_bytes": None,
            "bank_stats": None,
            "extractable_stats": None,
        },
        "stages": {},
        "native": None,
    }

    stage_start = time.perf_counter()
    resolved = resolve_extraction_options(options)
    report["stages"]["options_resolution"] = _stage(time.perf_counter() - stage_start)

    stage_start = time.perf_counter()
    schema_result = validate_bank_schema(bank)
    report["stages"]["schema_validation"] = _stage(time.perf_counter() - stage_start)
    diagnostics = schema_result["diagnostics"]
    if has_errors(diagnostics):
        raise ExtractionError("Bank failed schema validation and cannot be extracted.", diagnostics)

    stage_start = time.perf_counter()
    try:
        canonical_bank = canonicalize_bank(bank)
    except TypeError as exc:
        raise ExtractionError("Bank failed schema validation and cannot be extracted.", diagnostics) from exc
    report["stages"]["python_canonicalize"] = _stage(time.perf_counter() - stage_start)

    stage_start = time.perf_counter()
    canonical_json_bytes = _json_source(canonical_bank)
    report["source"]["canonical_json_bytes"] = len(canonical_json_bytes)
    report["stages"]["canonical_json_serialization"] = _stage(time.perf_counter() - stage_start)

    stage_start = time.perf_counter()
    bank_hash = "sha256:" + hashlib.sha256(canonical_json_bytes).hexdigest()
    report["source"]["canonical_bank_hash"] = bank_hash
    report["stages"]["stable_hash"] = _stage(time.perf_counter() - stage_start)

    report["source"]["bank_stats"] = bank_stats(canonical_bank)

    stage_start = time.perf_counter()
    if canonical_bank.get("status") not in resolved.include_statuses:
        raise ExtractionError(
            f"Bank status {canonical_bank.get('status')!r} is not included in extraction statuses "
            f"{list(resolved.include_statuses)!r}."
        )
    report["stages"]["status_gate"] = _stage(time.perf_counter() - stage_start)

    stage_start = time.perf_counter()
    extractable_bank = _filter_extractable_bank(canonical_bank, resolved.include_statuses)
    report["stages"]["extractable_bank_filter"] = _stage(time.perf_counter() - stage_start)
    if extractable_bank is None:
        report["stages"]["compile_options_json"] = _unavailable_stage("no extractable active patterns")
        report["stages"]["extractable_json_serialization"] = _unavailable_stage("no extractable active patterns")
        report["stages"]["native_bank_from_source"] = _unavailable_stage("no extractable active patterns")
        report["stages"]["runtime_validation"] = _unavailable_stage("no extractable active patterns")
        report["stages"]["metadata_projection"] = _unavailable_stage("no extractable active patterns")
        report["stages"]["detector_index"] = _unavailable_stage("no extractable active patterns")
        return _uncompiled_bank(canonical_bank, resolved, bank_hash), False, report

    report["source"]["extractable_stats"] = bank_stats(extractable_bank)

    stage_start = time.perf_counter()
    compile_options_json = _canonical_options(resolved.engine_options)
    report["stages"]["compile_options_json"] = _stage(time.perf_counter() - stage_start)

    stage_start = time.perf_counter()
    extractable_source = _json_source(extractable_bank)
    report["source"]["extractable_json_bytes"] = len(extractable_source)
    report["stages"]["extractable_json_serialization"] = _stage(time.perf_counter() - stage_start)

    stage_start = time.perf_counter()
    try:
        native_bank, native_report = Bank.from_source_bytes_with_report(
            extractable_source,
            format_hint="json",
            compile_options_json=compile_options_json,
        )
    except ValueError as exc:
        diagnostics = [
            diagnostic(
                DIAGNOSTIC_ERROR,
                "engine.compile_error",
                "",
                f"Rust engine failed to compile the bank: {exc}.",
            )
        ]
        message = f"Bank failed Rust engine validation and cannot be extracted: {exc}."
        raise ExtractionError(message, diagnostics) from exc
    report["stages"]["native_bank_from_source"] = _native_bank_from_source_stage(
        time.perf_counter() - stage_start,
        native_report,
    )
    report["native"] = native_report

    from .validation import rust_empty_match_diagnostics

    stage_start = time.perf_counter()
    empty_match_diagnostics = rust_empty_match_diagnostics(native_bank)
    report["stages"]["runtime_validation"] = _stage(time.perf_counter() - stage_start)
    if empty_match_diagnostics:
        raise ExtractionError("Bank failed runtime validation and cannot be extracted.", empty_match_diagnostics)

    stage_start = time.perf_counter()
    cache_metadata = native_bank.cache_metadata()
    report["stages"]["metadata_projection"] = _stage(time.perf_counter() - stage_start)

    stage_start = time.perf_counter()
    detector_index = _json_bank_detector_index(extractable_bank)
    report["stages"]["detector_index"] = _stage(time.perf_counter() - stage_start)

    compiled = _compiled_bank_from_native(
        canonical_bank,
        extractable_bank,
        resolved,
        native_bank,
        cache_metadata=cache_metadata,
        detector_index=detector_index,
    )
    return compiled, bool(cache_metadata.get("hit")), report


def _uncompiled_bank(
    canonical_bank: dict[str, Any],
    resolved: ResolvedExtractionOptions,
    bank_hash: str,
) -> CompiledBank:
    return CompiledBank(
        bank=canonical_bank,
        extractable_bank=None,
        bank_hash=bank_hash,
        normalization=str(canonical_bank.get("unicode_normalization", "none")),
        include_statuses=resolved.include_statuses,
        engine_name=DEFAULT_ENGINE_NAME,
        engine_version="uncompiled",
        engine_options=resolved.engine_options,
        native_bank=None,
        cache_metadata={"enabled": False, "hit": False, "key": None},
        detector_index={},
    )


def _compiled_bank_from_native(
    canonical_bank: dict[str, Any],
    extractable_bank: dict[str, Any],
    resolved: ResolvedExtractionOptions,
    native_bank: Bank,
    *,
    detector_index: Mapping[tuple[str, str, str], _DetectorIdentity],
    cache_metadata: dict[str, Any] | None = None,
) -> CompiledBank:
    cache_metadata = native_bank.cache_metadata() if cache_metadata is None else cache_metadata
    cache_key = cache_metadata.get("key") if isinstance(cache_metadata, Mapping) else None
    engine_version = "unknown"
    if isinstance(cache_key, Mapping) and isinstance(cache_key.get("engine_version"), str):
        engine_version = cache_key["engine_version"]

    metadata = native_bank.metadata()
    return CompiledBank(
        bank=canonical_bank,
        extractable_bank=extractable_bank,
        bank_hash=str(metadata["bank_hash"]),
        normalization=str(canonical_bank.get("unicode_normalization", "none")),
        include_statuses=resolved.include_statuses,
        engine_name=str(metadata["engine"]),
        engine_version=engine_version,
        engine_options=resolved.engine_options,
        native_bank=native_bank,
        cache_metadata=cache_metadata,
        detector_index=detector_index,
    )


def _positive_int_option(options: Mapping[str, Any], key: str, default: int) -> int:
    value = options.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ExtractionError(f"Extraction option {key} must be a positive integer.")
    return value


def _canonical_options(options: Mapping[str, Any]) -> str:
    try:
        return json.dumps(options, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ExtractionError("Extraction option engine_options must be JSON-compatible.") from exc


def _stage(
    seconds: float,
    *,
    exclusive: bool = True,
    includes: list[str] | None = None,
    note: str | None = None,
) -> dict[str, Any]:
    stage: dict[str, Any] = {"available": True, "seconds": _seconds(seconds), "exclusive": exclusive}
    if includes is not None:
        stage["includes"] = includes
    if note is not None:
        stage["note"] = note
    return stage


def _unavailable_stage(note: str) -> dict[str, Any]:
    return {"available": False, "seconds": None, "exclusive": None, "note": note}


def _native_bank_from_source_stage(seconds: float, native_report: Mapping[str, Any]) -> dict[str, Any]:
    native_stages = native_report.get("stages")
    native_compile = native_stages.get("native_compile") if isinstance(native_stages, Mapping) else None
    native_constructed = isinstance(native_compile, Mapping) and native_compile.get("available") is True
    if native_constructed:
        return _stage(
            seconds,
            exclusive=False,
            includes=[
                "python_cache_lookup",
                "rust_source_parse",
                "rust_canonicalization",
                "stable_hash",
                "matcher_compile",
            ],
            note="Includes the Python Bank cache wrapper and one native Rust construction call.",
        )
    return _stage(
        seconds,
        exclusive=False,
        includes=[
            "native_engine_import",
            "source_bytes_copy",
            "compile_options_normalize",
            "source_cache_key",
            "cache_lookup",
        ],
        note="Source-cache hit reused a compiled bank; Rust construction was skipped.",
    )


def _seconds(value: float) -> float:
    return round(value, 9)


def _json_source(bank: Mapping[str, Any]) -> bytes:
    return json.dumps(bank, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _filter_extractable_bank(bank: Mapping[str, Any], include_statuses: tuple[str, ...]) -> dict[str, Any] | None:
    filtered = dict(bank)
    filtered_entities: dict[str, Any] = {}

    entities = bank.get("entities", {})
    if not isinstance(entities, Mapping):
        return None

    for entity_id, entity in entities.items():
        if not isinstance(entity_id, str) or not isinstance(entity, Mapping):
            continue
        if entity.get("status") not in include_statuses:
            continue

        filtered_names: dict[str, Any] = {}
        names = entity.get("names", {})
        if not isinstance(names, Mapping):
            continue
        for name_id, name in names.items():
            if not isinstance(name_id, str) or not isinstance(name, Mapping):
                continue
            if name.get("status") not in include_statuses:
                continue

            filtered_patterns: dict[str, Any] = {}
            patterns = name.get("patterns", {})
            if not isinstance(patterns, Mapping):
                continue
            for pattern_id, pattern in patterns.items():
                if not isinstance(pattern_id, str) or not isinstance(pattern, Mapping):
                    continue
                if pattern.get("status") in include_statuses:
                    filtered_patterns[pattern_id] = dict(pattern)

            if filtered_patterns:
                filtered_name = dict(name)
                filtered_name["patterns"] = filtered_patterns
                filtered_names[name_id] = filtered_name

        if filtered_names:
            filtered_entity = dict(entity)
            filtered_entity["names"] = filtered_names
            filtered_entities[entity_id] = filtered_entity

    if not filtered_entities:
        return None

    filtered["entities"] = filtered_entities
    return filtered


def _json_bank_detector_index(bank: Mapping[str, Any]) -> dict[tuple[str, str, str], _DetectorIdentity]:
    index: dict[tuple[str, str, str], _DetectorIdentity] = {}
    entities = bank.get("entities", {})
    if not isinstance(entities, Mapping):
        return index

    for entity_id, entity in sorted(entities.items()):
        if not isinstance(entity_id, str) or not isinstance(entity, Mapping):
            continue
        entity_map = cast(Mapping[str, Any], entity)
        names = entity_map.get("names", {})
        if not isinstance(names, Mapping):
            continue
        for name_id, name in sorted(names.items()):
            if not isinstance(name_id, str) or not isinstance(name, Mapping):
                continue
            name_map = cast(Mapping[str, Any], name)
            canonical_name = str(name_map.get("canonical", ""))
            patterns = name_map.get("patterns", {})
            if not isinstance(patterns, Mapping):
                continue
            for pattern_id, pattern in sorted(patterns.items()):
                if not isinstance(pattern_id, str) or not isinstance(pattern, Mapping):
                    continue
                pattern_map = cast(Mapping[str, Any], pattern)
                pattern_kind = str(pattern_map.get("kind", ""))
                surface_name = str(pattern_map.get("value")) if pattern_kind == "literal" else pattern_id
                key = (entity_id, canonical_name, surface_name)
                identity = _DetectorIdentity(
                    entity_id=entity_id,
                    name_id=name_id,
                    pattern_id=pattern_id,
                    pattern_kind=pattern_kind,
                    canonical_name=canonical_name,
                )
                previous_identity = index.get(key)
                if previous_identity is not None and previous_identity != identity:
                    raise ExtractionError(
                        "JSON-bank detector metadata is ambiguous for Rust engine record projection: "
                        f"{entity_id}/{canonical_name}/{surface_name} maps to multiple source detectors."
                    )
                index[key] = identity

    return index


def _enrich_json_bank_record(
    record: Mapping[str, Any],
    detector_index: Mapping[tuple[str, str, str], _DetectorIdentity],
) -> MatchRecord:
    key = (
        str(record["entity"]),
        str(record["canonical_name"]),
        str(record["surface_name"]),
    )
    identity = detector_index.get(key)
    if identity is None:
        raise ExtractionError(
            f"Rust engine record could not be mapped back to JSON-bank detector metadata: {key[0]}/{key[1]}/{key[2]}."
        )

    return {
        **dict(record),
        "entity_id": identity.entity_id,
        "name_id": identity.name_id,
        "pattern_id": identity.pattern_id,
        "pattern_kind": identity.pattern_kind,
        "captures": {},
    }

"""Bounded, aggregate-only worker used by the Enron performance harness.

The worker accepts one JSON request on stdin, or newline-delimited requests when
``--json-lines`` is supplied.  Artifact contents, scan text, match strings,
detector names, paths, and exception messages are never written to either output
stream.  The only successful observation is a count plus a domain-separated
correctness digest.

This module intentionally does not run the full Enron bank builder.  Bank builds
need output lifecycle and timeout ownership from the outer orchestrator; a
``source_build`` request therefore returns the stable ``operation_unsupported``
code instead of misrepresenting compilation as construction.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib
import json
import math
import os
import re
import stat
import sys
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Protocol, cast

import yaml

from .bank import hash_bank
from .config import PatternConfig, validate_pattern_config
from .engine import Bank, clear_bank_cache
from .engines import CompiledBank, compile_bank_with_report
from .enron_private_io import EnronPrivateIOError, is_owner_only_private_mode, open_private_binary_input

try:  # pragma: no cover - import availability is platform-dependent.
    _resource: Any = importlib.import_module("resource")
except ImportError:  # pragma: no cover - exercised through the injectable helper.
    _resource = None


REQUEST_SCHEMA_VERSION = "nerb.enron_performance_worker_request.v1"
RESULT_SCHEMA_VERSION = "nerb.enron_performance_worker_result.v1"
DEFAULT_MAX_REQUEST_BYTES = 64 * 1024
DEFAULT_MAX_RESULT_BYTES = 4 * 1024
DEFAULT_MAX_BANK_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_INPUT_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_INVENTORY_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_PROFILE_BYTES = 2 * 1024 * 1024 * 1024
DEFAULT_MAX_DOCUMENTS = 10_000
DEFAULT_MAX_TOTAL_RECORDS = 5_000_000
DEFAULT_MAX_RECORDS_PER_DOCUMENT = 999_999
DEFAULT_MAX_WARMUPS = 1_000
DEFAULT_MAX_CONCURRENCY = 8
DEFAULT_MAX_PATH_BYTES = 4_096
DEFAULT_MAX_PROFILE_LINE_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_PROFILE_RECORDS = 750_000
DEFAULT_SEEN_WORKLOADS = 512
_MAX_RESULT_INTEGER = (1 << 63) - 1

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_NONCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_GENERIC_EMAIL_RE = re.compile(
    r"(?i)(?<![a-z0-9.!#$%&'*+/=?^_`{|}~-])"
    r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+\.[a-z]{2,63}"
    r"(?![a-z0-9.-])"
)

Operation = Literal[
    "source_profile",
    "source_build",
    "bank_compile",
    "direct_bank_scan",
    "json_helper_scan",
    "json_adapter_scan",
    "config_engine_scan",
    "generic_regex_scan",
    "python_literal_scan",
]
_OPERATIONS = frozenset(
    {
        "source_profile",
        "source_build",
        "bank_compile",
        "direct_bank_scan",
        "json_helper_scan",
        "json_adapter_scan",
        "config_engine_scan",
        "generic_regex_scan",
        "python_literal_scan",
    }
)
_NATIVE_BANK_FORMATS = frozenset({"native_json", "native_jsonl"})
_BANK_FORMATS = frozenset({"json_bank_active", *_NATIVE_BANK_FORMATS})
_CACHE_MODES = frozenset({"disabled", "miss", "hit"})

ErrorCode = Literal[
    "artifact_changed",
    "artifact_invalid",
    "artifact_too_large",
    "correctness_mismatch",
    "internal_error",
    "input_inventory_invalid",
    "operation_failed",
    "operation_invalid",
    "operation_unsupported",
    "record_limit_exceeded",
    "request_encoding",
    "request_json",
    "request_schema",
    "request_shape",
    "request_too_large",
    "workload_mismatch",
]

__all__ = [
    "DEFAULT_MAX_REQUEST_BYTES",
    "DEFAULT_MAX_RESULT_BYTES",
    "REQUEST_SCHEMA_VERSION",
    "RESULT_SCHEMA_VERSION",
    "EnronPerformanceWorker",
    "encode_worker_result",
    "main",
    "normalize_peak_rss",
]


class _StrictJSONError(ValueError):
    pass


class _WorkerError(ValueError):
    def __init__(self, code: ErrorCode) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class _ArtifactRef:
    path: Path
    sha256: str
    bytes: int
    identity: Mapping[str, int | str]

    def semantic_descriptor(self) -> dict[str, Any]:
        # The digest is process-private, so binding the approved path cannot leak
        # it and prevents a reused state from reading a prior request's location.
        return {
            "path": str(self.path),
            "sha256": self.sha256,
            "bytes": self.bytes,
            "identity": dict(self.identity),
        }


@dataclass(frozen=True, slots=True)
class _Request:
    nonce: str
    workload_sha256: str
    operation: Operation
    warmups: int
    artifacts: Mapping[str, _ArtifactRef]
    parameters: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class _InventoryRow:
    bytes: int
    records: int


@dataclass(frozen=True, slots=True)
class _Observation:
    record_count: int
    correctness_sha256: str
    correctness_matches: bool = True


@dataclass(frozen=True, slots=True)
class _MeasuredObservation:
    elapsed_ns: int
    observation: _Observation


class _Operation(Protocol):
    def before_sample(self) -> None: ...

    def observe(self) -> _MeasuredObservation: ...

    def finish_warmups(self) -> None: ...

    def close(self) -> None: ...


@dataclass(slots=True)
class _PreparedOperation:
    observe_callback: Callable[[], _Observation]
    measure_callback: Callable[[], _MeasuredObservation] | None = None
    before_callback: Callable[[], None] = lambda: None
    finish_warmups_callback: Callable[[], None] = lambda: None
    close_callback: Callable[[], None] = lambda: None

    def before_sample(self) -> None:
        self.before_callback()

    def observe(self) -> _MeasuredObservation:
        if self.measure_callback is not None:
            return self.measure_callback()
        start = time.perf_counter_ns()
        observation = self.observe_callback()
        return _MeasuredObservation(_elapsed_since(start), observation)

    def finish_warmups(self) -> None:
        self.finish_warmups_callback()

    def close(self) -> None:
        self.close_callback()


@dataclass(frozen=True, slots=True)
class _PreparedDocuments:
    bytes_documents: tuple[bytes, ...] | None
    text_documents: tuple[str, ...] | None
    inventory: tuple[_InventoryRow, ...]
    binding: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class _LiteralPattern:
    identity: tuple[str, str, str]
    value: str
    case_sensitive: bool


class EnronPerformanceWorker:
    """Validate requests and retain at most one prepared benchmark workload."""

    def __init__(self, *, max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES) -> None:
        if isinstance(max_request_bytes, bool) or not isinstance(max_request_bytes, int) or max_request_bytes <= 0:
            raise ValueError("Worker request limit must be a positive integer.")
        self.max_request_bytes = max_request_bytes
        self._current_key: tuple[str, str] | None = None
        self._current_operation: _Operation | None = None
        self._seen_specs: OrderedDict[str, str] = OrderedDict()

    def close(self) -> None:
        if self._current_operation is not None:
            self._current_operation.close()
        clear_bank_cache()
        self._current_key = None
        self._current_operation = None

    def process_bytes(self, raw: bytes) -> dict[str, Any]:
        """Process one bounded request without propagating sensitive exceptions."""

        nonce, workload_sha256 = _safe_correlation_fields(raw, self.max_request_bytes)
        if len(raw) > self.max_request_bytes:
            return _result(nonce, workload_sha256, error_code="request_too_large")
        try:
            request_value = _load_strict_json(raw)
            request = _validate_request(request_value)
            nonce = request.nonce
            workload_sha256 = request.workload_sha256
        except UnicodeDecodeError:
            return _result(nonce, workload_sha256, error_code="request_encoding")
        except _StrictJSONError:
            return _result(nonce, workload_sha256, error_code="request_json")
        except _WorkerError as exc:
            return _result(nonce, workload_sha256, error_code=exc.code)
        except BaseException:
            return _result(nonce, workload_sha256, error_code="internal_error")

        elapsed_ns: int | None = None
        observation: _Observation | None = None
        try:
            with _discard_process_output():
                operation, prepared_now = self._operation_for(request)
                if prepared_now:
                    for _ in range(request.warmups):
                        operation.before_sample()
                        operation.observe()
                    operation.finish_warmups()
                operation.before_sample()
                measured = operation.observe()
                observation = measured.observation
                elapsed_ns = measured.elapsed_ns
            if observation.correctness_matches is not True:
                return _result(
                    nonce,
                    workload_sha256,
                    error_code="correctness_mismatch",
                    elapsed_ns=elapsed_ns,
                    observation=observation,
                )
            return _result(
                nonce,
                workload_sha256,
                elapsed_ns=elapsed_ns,
                observation=observation,
            )
        except _WorkerError as exc:
            return _result(
                nonce,
                workload_sha256,
                error_code=exc.code,
                elapsed_ns=elapsed_ns,
                observation=observation,
            )
        except BaseException:
            return _result(
                nonce,
                workload_sha256,
                error_code="operation_failed",
                elapsed_ns=elapsed_ns,
                observation=observation,
            )

    def _operation_for(self, request: _Request) -> tuple[_Operation, bool]:
        if request.operation == "source_build":
            raise _WorkerError("operation_unsupported")

        spec_sha256 = _request_spec_sha256(request)
        prior = self._seen_specs.get(request.workload_sha256)
        if prior is not None and prior != spec_sha256:
            raise _WorkerError("workload_mismatch")
        self._seen_specs[request.workload_sha256] = spec_sha256
        self._seen_specs.move_to_end(request.workload_sha256)
        while len(self._seen_specs) > DEFAULT_SEEN_WORKLOADS:
            self._seen_specs.popitem(last=False)

        key = (request.workload_sha256, spec_sha256)
        if key == self._current_key and self._current_operation is not None:
            return self._current_operation, False

        if self._current_operation is not None:
            self._current_operation.close()
        clear_bank_cache()
        self._current_key = None
        self._current_operation = None
        operation = _prepare_operation(request)
        self._current_key = key
        self._current_operation = operation
        return operation, True


def _prepare_operation(request: _Request) -> _Operation:
    if request.operation == "source_profile":
        return _prepare_source_profile(request)
    if request.operation == "bank_compile":
        return _prepare_bank_compile(request)
    if request.operation == "direct_bank_scan":
        return _prepare_direct_bank_scan(request)
    if request.operation == "json_helper_scan":
        return _prepare_json_helper_scan(request)
    if request.operation == "json_adapter_scan":
        return _prepare_json_adapter_scan(request)
    if request.operation == "config_engine_scan":
        return _prepare_config_engine_scan(request)
    if request.operation == "generic_regex_scan":
        return _prepare_generic_regex_scan(request)
    if request.operation == "python_literal_scan":
        return _prepare_python_literal_scan(request)
    raise _WorkerError("operation_invalid")


def _file_identity(info: os.stat_result) -> dict[str, int | str]:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or not is_owner_only_private_mode(stat.S_IMODE(info.st_mode))
    ):
        raise _WorkerError("artifact_changed")
    return {
        "kind": "file",
        "device": info.st_dev,
        "inode": info.st_ino,
        "mode": stat.S_IMODE(info.st_mode),
        "link_count": info.st_nlink,
        "size": info.st_size,
        "modified_ns": info.st_mtime_ns,
        "changed_ns": info.st_ctime_ns,
    }


def _require_artifact_identity(file: Any, reference: _ArtifactRef) -> None:
    try:
        observed = _file_identity(os.fstat(file.fileno()))
    except OSError:
        raise _WorkerError("artifact_invalid") from None
    if observed != reference.identity:
        raise _WorkerError("artifact_changed")


def _prepare_source_profile(request: _Request) -> _Operation:
    source = request.artifacts["source"]
    max_line_bytes = cast(int, request.parameters["max_line_bytes"])
    max_records = cast(int, request.parameters["max_records"])
    if source.bytes > DEFAULT_MAX_PROFILE_BYTES:
        raise _WorkerError("artifact_too_large")

    def observe() -> _Observation:
        digest = hashlib.sha256(b"nerb/enron/performance/source-profile/v1\0")
        digest.update(source.sha256.encode("ascii"))
        total_bytes = 0
        records = 0
        raw_sha = hashlib.sha256()
        try:
            with open_private_binary_input(source.path) as file:
                _require_artifact_identity(file, source)
                while raw := file.readline(max_line_bytes + 1):
                    if len(raw) > max_line_bytes:
                        raise _WorkerError("artifact_invalid")
                    records += 1
                    if records > max_records:
                        raise _WorkerError("record_limit_exceeded")
                    total_bytes += len(raw)
                    if total_bytes > source.bytes:
                        raise _WorkerError("artifact_changed")
                    raw_sha.update(raw)
                    try:
                        value = _load_strict_json(raw)
                    except (UnicodeDecodeError, _StrictJSONError):
                        raise _WorkerError("artifact_invalid") from None
                    if not isinstance(value, Mapping):
                        raise _WorkerError("artifact_invalid")
                    canonical = _canonical_json_bytes(value)
                    _digest_frame(digest, canonical)
                _require_artifact_identity(file, source)
        except (EnronPrivateIOError, OSError, OverflowError):
            raise _WorkerError("artifact_invalid") from None
        if total_bytes != source.bytes or "sha256:" + raw_sha.hexdigest() != source.sha256:
            raise _WorkerError("artifact_changed")
        digest.update(records.to_bytes(8, "big"))
        digest.update(total_bytes.to_bytes(8, "big"))
        return _Observation(records, "sha256:" + digest.hexdigest())

    return _PreparedOperation(observe)


def _prepare_bank_compile(request: _Request) -> _Operation:
    bank_ref = request.artifacts["bank"]
    bank_format = cast(str, request.parameters["bank_format"])
    cache_mode = cast(str, request.parameters["cache_mode"])
    source = _read_bound_artifact(bank_ref, DEFAULT_MAX_BANK_BYTES)

    if bank_format == "json_bank_active":
        bank = _json_bank(source)
        canonical_bank_sha256 = hash_bank(bank)

        def compile_once() -> CompiledBank:
            compiled, _cache_hit, _report = compile_bank_with_report(bank)
            if compiled.native_bank is None:
                raise _WorkerError("operation_failed")
            return compiled

        def observe_compile() -> _Observation:
            compiled = compile_once()
            assert compiled.native_bank is not None
            return _compile_observation(
                _bank_binding(compiled.native_bank, canonical_bank_sha256=canonical_bank_sha256)
            )

        def measure_compile() -> _MeasuredObservation:
            start = time.perf_counter_ns()
            compiled = compile_once()
            elapsed_ns = _elapsed_since(start)
            assert compiled.native_bank is not None
            observation = _compile_observation(
                _bank_binding(compiled.native_bank, canonical_bank_sha256=canonical_bank_sha256)
            )
            return _MeasuredObservation(elapsed_ns, observation)

        if cache_mode == "disabled":
            raise _WorkerError("request_shape")
        before = clear_bank_cache if cache_mode == "miss" else _no_op
        if cache_mode == "hit":
            clear_bank_cache()
            compile_once()
        return _PreparedOperation(observe_compile, measure_callback=measure_compile, before_callback=before)

    format_hint = "json" if bank_format == "native_json" else "jsonl"

    def compile_native() -> Bank:
        return Bank.from_source_bytes(
            source,
            format_hint=format_hint,
            use_cache=cache_mode != "disabled",
        )

    def observe_native() -> _Observation:
        return _compile_observation(_bank_binding(compile_native()))

    def measure_native() -> _MeasuredObservation:
        start = time.perf_counter_ns()
        native = compile_native()
        elapsed_ns = _elapsed_since(start)
        return _MeasuredObservation(elapsed_ns, _compile_observation(_bank_binding(native)))

    before = clear_bank_cache if cache_mode == "miss" else _no_op
    if cache_mode == "hit":
        clear_bank_cache()
        compile_native()
    return _PreparedOperation(observe_native, measure_callback=measure_native, before_callback=before)


def _prepare_direct_bank_scan(request: _Request) -> _Operation:
    bank_ref = request.artifacts["bank"]
    bank_format = cast(str, request.parameters["bank_format"])
    concurrency = cast(int, request.parameters["concurrency"])
    source = _read_bound_artifact(bank_ref, DEFAULT_MAX_BANK_BYTES)
    documents = _load_documents(request, want_text=False)
    assert documents.bytes_documents is not None
    byte_documents = documents.bytes_documents

    if bank_format == "json_bank_active":
        bank = _json_bank(source)
        clear_bank_cache()
        compiled, _cache_hit, _report = compile_bank_with_report(bank)
        native = compiled.native_bank
        if native is None:
            raise _WorkerError("operation_failed")
        bank_binding = _bank_binding(native, canonical_bank_sha256=compiled.bank_hash)
    else:
        native = Bank.from_source_bytes(
            source,
            format_hint="json" if bank_format == "native_json" else "jsonl",
            use_cache=False,
        )
        bank_binding = _bank_binding(native)

    def scan(index: int, document: bytes) -> Sequence[Mapping[str, Any]]:
        expected = documents.inventory[index].records
        return native.scan_bytes(document, max_matches=expected + 1)

    binding = _scan_binding(request.operation, bank_binding, documents.binding)
    sample_unit = cast(str, request.parameters["sample_unit"])
    if sample_unit == "document":
        if concurrency != 1:
            raise _WorkerError("request_shape")
        cursor = [0]

        def scan_document() -> tuple[int, Sequence[Mapping[str, Any]]]:
            index = cursor[0]
            records = scan(index, byte_documents[index])
            cursor[0] = (index + 1) % len(byte_documents)
            return index, records

        def finish_document(index: int, records: Sequence[Mapping[str, Any]]) -> _Observation:
            return _scan_results_observation(
                [records],
                inventory=documents.inventory,
                document_indices=[index],
                binding=binding,
                identity=_native_record_identity,
                verify_expected=True,
            )

        def observe_document() -> _Observation:
            index, records = scan_document()
            return finish_document(index, records)

        def measure_document() -> _MeasuredObservation:
            start = time.perf_counter_ns()
            index, records = scan_document()
            elapsed_ns = _elapsed_since(start)
            return _MeasuredObservation(elapsed_ns, finish_document(index, records))

        return _PreparedOperation(
            observe_document,
            measure_callback=measure_document,
            finish_warmups_callback=lambda: cursor.__setitem__(0, 0),
        )

    return _scan_operation(
        bytes_documents=byte_documents,
        inventory=documents.inventory,
        binding=binding,
        concurrency=concurrency,
        scan=scan,
        identity=_native_record_identity,
        verify_expected=True,
    )


def _prepare_json_helper_scan(request: _Request) -> _Operation:
    bank_ref = request.artifacts["bank"]
    source = _read_bound_artifact(bank_ref, DEFAULT_MAX_BANK_BYTES)
    bank = _json_bank(source)
    cache_mode = cast(str, request.parameters["cache_mode"])
    input_mode = cast(str, request.parameters["input_mode"])
    concurrency = cast(int, request.parameters["concurrency"])

    clear_bank_cache()
    if cache_mode == "hit":
        primed, _cache_hit, _report = compile_bank_with_report(bank)
        if primed.native_bank is None:
            raise _WorkerError("operation_failed")
    prepared_documents = _load_documents(request, want_text=True) if input_mode == "prepared" else None

    executor = (
        ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="nerb-helper") if concurrency > 1 else None
    )

    def run_helper() -> tuple[_PreparedDocuments, list[Sequence[Mapping[str, Any]]], Any]:
        if input_mode == "end_to_end":
            runtime_bank = _json_bank(_read_bound_artifact(bank_ref, DEFAULT_MAX_BANK_BYTES))
            documents = _load_documents(request, want_text=True)
        else:
            runtime_bank = bank
            assert prepared_documents is not None
            documents = prepared_documents
        assert documents.text_documents is not None
        compiled, _cache_hit, _compile_report = compile_bank_with_report(runtime_bank)
        if compiled.native_bank is None:
            raise _WorkerError("operation_failed")

        def scan(item: tuple[int, str]) -> Sequence[Mapping[str, Any]]:
            index, document = item
            expected = documents.inventory[index].records
            return compiled.finditer(document, max_matches=expected + 1)

        indexed = list(enumerate(documents.text_documents))
        if executor is None:
            results = [scan(item) for item in indexed]
        else:
            results = list(executor.map(scan, indexed))
        return documents, results, compiled

    def finish_helper(
        documents: _PreparedDocuments,
        results: Sequence[Sequence[Mapping[str, Any]]],
        compiled: Any,
    ) -> _Observation:
        bank_binding = _bank_binding(compiled.native_bank, canonical_bank_sha256=compiled.bank_hash)
        return _scan_results_observation(
            results,
            inventory=documents.inventory,
            document_indices=list(range(len(documents.inventory))),
            binding=_scan_binding(request.operation, bank_binding, documents.binding),
            identity=_adapter_record_identity,
            verify_expected=True,
        )

    def observe() -> _Observation:
        return finish_helper(*run_helper())

    def measure() -> _MeasuredObservation:
        start = time.perf_counter_ns()
        documents, results, compiled = run_helper()
        elapsed_ns = _elapsed_since(start)
        return _MeasuredObservation(elapsed_ns, finish_helper(documents, results, compiled))

    return _PreparedOperation(
        observe,
        measure_callback=measure,
        before_callback=clear_bank_cache if cache_mode == "miss" else _no_op,
        close_callback=executor.shutdown if executor is not None else _no_op,
    )


def _prepare_json_adapter_scan(request: _Request) -> _Operation:
    source = _read_bound_artifact(request.artifacts["bank"], DEFAULT_MAX_BANK_BYTES)
    bank = _json_bank(source)
    documents = _load_documents(request, want_text=True)
    assert documents.text_documents is not None
    clear_bank_cache()
    compiled, _cache_hit, _report = compile_bank_with_report(bank)
    if compiled.native_bank is None:
        raise _WorkerError("operation_failed")
    bank_binding = _bank_binding(compiled.native_bank, canonical_bank_sha256=compiled.bank_hash)
    binding = _scan_binding(request.operation, bank_binding, documents.binding)
    concurrency = cast(int, request.parameters["concurrency"])

    def scan(index: int, document: str) -> Sequence[Mapping[str, Any]]:
        expected = documents.inventory[index].records
        return compiled.finditer(document, max_matches=expected + 1)

    return _scan_operation(
        text_documents=documents.text_documents,
        inventory=documents.inventory,
        binding=binding,
        concurrency=concurrency,
        scan=scan,
        identity=_adapter_record_identity,
        verify_expected=True,
    )


def _prepare_config_engine_scan(request: _Request) -> _Operation:
    source = _read_bound_artifact(request.artifacts["config"], DEFAULT_MAX_BANK_BYTES)
    config = _yaml_config(source)
    documents = _load_documents(request, want_text=False)
    assert documents.bytes_documents is not None
    clear_bank_cache()
    bank = Bank.from_config(
        config,
        word_boundaries=cast(bool, request.parameters["word_boundaries"]),
        use_cache=False,
    )
    binding = _scan_binding(request.operation, _bank_binding(bank), documents.binding)
    concurrency = cast(int, request.parameters["concurrency"])

    def scan(index: int, document: bytes) -> Sequence[Mapping[str, Any]]:
        expected = documents.inventory[index].records
        return bank.scan_bytes(document, max_matches=expected + 1)

    return _scan_operation(
        bytes_documents=documents.bytes_documents,
        inventory=documents.inventory,
        binding=binding,
        concurrency=concurrency,
        scan=scan,
        identity=_native_record_identity,
        verify_expected=True,
    )


def _prepare_generic_regex_scan(request: _Request) -> _Operation:
    documents = _load_documents(request, want_text=True)
    assert documents.text_documents is not None
    concurrency = cast(int, request.parameters["concurrency"])
    max_records = cast(int, request.parameters["max_records"])
    binding = _scan_binding(
        request.operation,
        {"pattern_set": cast(str, request.parameters["pattern_set"]), "semantic_equivalence": "not_equivalent"},
        documents.binding,
    )

    def scan(_index: int, document: str) -> Sequence[tuple[int, int]]:
        records: list[tuple[int, int]] = []
        for match in _GENERIC_EMAIL_RE.finditer(document):
            records.append((match.start(), match.end()))
            if len(records) > max_records:
                raise _WorkerError("record_limit_exceeded")
        return records

    return _scan_operation(
        text_documents=documents.text_documents,
        inventory=documents.inventory,
        binding=binding,
        concurrency=concurrency,
        scan=scan,
        identity=_tuple_record_identity,
        verify_expected=False,
    )


def _prepare_python_literal_scan(request: _Request) -> _Operation:
    source = _read_bound_artifact(request.artifacts["bank"], DEFAULT_MAX_BANK_BYTES)
    bank = _json_bank(source)
    patterns = _active_literal_patterns(bank)
    documents = _load_documents(request, want_text=True)
    assert documents.text_documents is not None
    concurrency = cast(int, request.parameters["concurrency"])
    max_records = cast(int, request.parameters["max_records"])
    binding = _scan_binding(
        request.operation,
        {
            "canonical_bank_sha256": hash_bank(bank),
            "literal_patterns": len(patterns),
            "semantic_equivalence": "not_equivalent",
        },
        documents.binding,
    )

    def scan(_index: int, document: str) -> Sequence[tuple[Any, ...]]:
        records: list[tuple[Any, ...]] = []
        folded_document: str | None = None
        for pattern in patterns:
            if pattern.case_sensitive:
                haystack = document
                needle = pattern.value
            else:
                if folded_document is None:
                    folded_document = document.casefold()
                haystack = folded_document
                needle = pattern.value.casefold()
            start = 0
            while True:
                found = haystack.find(needle, start)
                if found < 0:
                    break
                end = found + len(needle)
                records.append((found, end, *pattern.identity))
                if len(records) > max_records:
                    raise _WorkerError("record_limit_exceeded")
                start = end if end > found else found + 1
        records.sort(
            key=lambda item: tuple(str(value) if index >= 2 else int(value) for index, value in enumerate(item))
        )
        return records

    return _scan_operation(
        text_documents=documents.text_documents,
        inventory=documents.inventory,
        binding=binding,
        concurrency=concurrency,
        scan=scan,
        identity=_tuple_record_identity,
        verify_expected=False,
    )


def _scan_operation(
    *,
    inventory: tuple[_InventoryRow, ...],
    binding: Mapping[str, Any],
    concurrency: int,
    scan: Callable[[int, Any], Sequence[Any]],
    identity: Callable[[Any], tuple[Any, ...]],
    verify_expected: bool,
    bytes_documents: tuple[bytes, ...] | None = None,
    text_documents: tuple[str, ...] | None = None,
) -> _Operation:
    documents: Sequence[Any]
    if bytes_documents is not None:
        documents = bytes_documents
    elif text_documents is not None:
        documents = text_documents
    else:  # pragma: no cover - internal invariant.
        raise _WorkerError("internal_error")

    executor = ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="nerb-perf") if concurrency > 1 else None

    def run_scan() -> list[Sequence[Any]]:
        if executor is None:
            return [scan(index, document) for index, document in enumerate(documents)]
        return list(executor.map(lambda item: scan(item[0], item[1]), enumerate(documents)))

    def finish_scan(results: Sequence[Sequence[Any]]) -> _Observation:
        return _scan_results_observation(
            results,
            inventory=inventory,
            document_indices=list(range(len(inventory))),
            binding=binding,
            identity=identity,
            verify_expected=verify_expected,
        )

    def observe() -> _Observation:
        return finish_scan(run_scan())

    def measure() -> _MeasuredObservation:
        start = time.perf_counter_ns()
        results = run_scan()
        elapsed_ns = _elapsed_since(start)
        return _MeasuredObservation(elapsed_ns, finish_scan(results))

    return _PreparedOperation(
        observe,
        measure_callback=measure,
        close_callback=executor.shutdown if executor is not None else _no_op,
    )


def _scan_results_observation(
    results: Sequence[Sequence[Any]],
    *,
    inventory: Sequence[_InventoryRow],
    document_indices: Sequence[int],
    binding: Mapping[str, Any],
    identity: Callable[[Any], tuple[Any, ...]],
    verify_expected: bool,
) -> _Observation:
    if len(results) != len(document_indices):
        raise _WorkerError("internal_error")
    digest = hashlib.sha256(b"nerb/enron/performance/scan-observation/v1\0")
    _digest_frame(digest, _canonical_json_bytes(binding))
    total = 0
    matches = True
    for index, records in zip(document_indices, results):
        count = len(records)
        total += count
        if total > DEFAULT_MAX_TOTAL_RECORDS:
            raise _WorkerError("record_limit_exceeded")
        expected = inventory[index].records
        if verify_expected and count != expected:
            matches = False
        digest.update(index.to_bytes(8, "big"))
        digest.update(count.to_bytes(8, "big"))
        for record in records:
            for field in identity(record):
                _digest_frame(digest, _identity_bytes(field))
    return _Observation(total, "sha256:" + digest.hexdigest(), matches)


def _load_documents(request: _Request, *, want_text: bool) -> _PreparedDocuments:
    input_ref = request.artifacts["input"]
    inventory_ref = request.artifacts["inventory"]
    raw_inventory = _read_bound_artifact(inventory_ref, DEFAULT_MAX_INVENTORY_BYTES)
    try:
        inventory_value = _load_strict_json(raw_inventory)
    except (UnicodeDecodeError, _StrictJSONError):
        raise _WorkerError("input_inventory_invalid") from None
    if not isinstance(inventory_value, list) or not 1 <= len(inventory_value) <= DEFAULT_MAX_DOCUMENTS:
        raise _WorkerError("input_inventory_invalid")
    try:
        canonical_inventory = _canonical_json_bytes(inventory_value)
    except _WorkerError:
        raise _WorkerError("input_inventory_invalid") from None
    if canonical_inventory != raw_inventory:
        raise _WorkerError("input_inventory_invalid")

    rows: list[_InventoryRow] = []
    expected_bytes = 0
    expected_records = 0
    for value in inventory_value:
        if not isinstance(value, Mapping) or set(value) != {"bytes", "records"}:
            raise _WorkerError("input_inventory_invalid")
        byte_count = _checked_int(
            value.get("bytes"),
            minimum=0,
            maximum=DEFAULT_MAX_INPUT_BYTES,
            error_code="input_inventory_invalid",
        )
        record_count = _checked_int(
            value.get("records"),
            minimum=0,
            maximum=DEFAULT_MAX_RECORDS_PER_DOCUMENT,
            error_code="input_inventory_invalid",
        )
        expected_bytes += byte_count
        expected_records += record_count
        if expected_bytes > DEFAULT_MAX_INPUT_BYTES or expected_records > DEFAULT_MAX_TOTAL_RECORDS:
            raise _WorkerError("input_inventory_invalid")
        rows.append(_InventoryRow(byte_count, record_count))
    if expected_bytes != input_ref.bytes:
        raise _WorkerError("input_inventory_invalid")

    raw_input = _read_bound_artifact(input_ref, DEFAULT_MAX_INPUT_BYTES)
    byte_documents: list[bytes] = []
    text_documents: list[str] = []
    position = 0
    for row in rows:
        next_position = position + row.bytes
        document = raw_input[position:next_position]
        try:
            text = document.decode("utf-8")
        except UnicodeDecodeError:
            raise _WorkerError("input_inventory_invalid") from None
        if want_text:
            text_documents.append(text)
        else:
            byte_documents.append(document)
        position = next_position
    if position != len(raw_input):  # Defensive duplicate of the descriptor and inventory checks.
        raise _WorkerError("input_inventory_invalid")

    return _PreparedDocuments(
        bytes_documents=None if want_text else tuple(byte_documents),
        text_documents=tuple(text_documents) if want_text else None,
        inventory=tuple(rows),
        binding={
            "input_sha256": input_ref.sha256,
            "input_bytes": input_ref.bytes,
            "inventory_sha256": inventory_ref.sha256,
            "documents": len(rows),
            "expected_records": expected_records,
        },
    )


def _read_bound_artifact(reference: _ArtifactRef, maximum_bytes: int) -> bytes:
    if reference.bytes > maximum_bytes:
        raise _WorkerError("artifact_too_large")
    try:
        with open_private_binary_input(reference.path) as file:
            _require_artifact_identity(file, reference)
            data = file.read(reference.bytes + 1)
            _require_artifact_identity(file, reference)
    except (EnronPrivateIOError, OSError, OverflowError):
        raise _WorkerError("artifact_invalid") from None
    if len(data) != reference.bytes:
        raise _WorkerError("artifact_changed")
    if "sha256:" + hashlib.sha256(data).hexdigest() != reference.sha256:
        raise _WorkerError("artifact_changed")
    return data


def _json_bank(source: bytes) -> dict[str, Any]:
    try:
        value = _load_strict_json(source)
    except (UnicodeDecodeError, _StrictJSONError):
        raise _WorkerError("artifact_invalid") from None
    if not isinstance(value, dict):
        raise _WorkerError("artifact_invalid")
    return cast(dict[str, Any], value)


def _yaml_config(source: bytes) -> PatternConfig:
    try:
        value = yaml.load(source.decode("utf-8"), Loader=getattr(yaml, "CSafeLoader", yaml.SafeLoader))
        return validate_pattern_config(value)
    except (UnicodeDecodeError, yaml.YAMLError, TypeError, ValueError):
        raise _WorkerError("artifact_invalid") from None


def _active_literal_patterns(bank: Mapping[str, Any]) -> tuple[_LiteralPattern, ...]:
    if bank.get("status") != "active":
        return ()
    patterns: list[_LiteralPattern] = []
    entities = bank.get("entities")
    if not isinstance(entities, Mapping):
        raise _WorkerError("artifact_invalid")
    for entity_id, entity in sorted(entities.items()):
        if not isinstance(entity_id, str) or not isinstance(entity, Mapping):
            continue
        entity_map = cast(Mapping[str, Any], entity)
        if entity_map.get("status") != "active":
            continue
        names = entity_map.get("names")
        if not isinstance(names, Mapping):
            continue
        for name_id, name in sorted(names.items()):
            if not isinstance(name_id, str) or not isinstance(name, Mapping):
                continue
            name_map = cast(Mapping[str, Any], name)
            if name_map.get("status") != "active":
                continue
            raw_patterns = name_map.get("patterns")
            if not isinstance(raw_patterns, Mapping):
                continue
            for pattern_id, pattern in sorted(raw_patterns.items()):
                if not isinstance(pattern_id, str) or not isinstance(pattern, Mapping):
                    continue
                pattern_map = cast(Mapping[str, Any], pattern)
                pattern_value = pattern_map.get("value")
                if (
                    pattern_map.get("status") != "active"
                    or pattern_map.get("kind") != "literal"
                    or not isinstance(pattern_value, str)
                    or not pattern_value
                ):
                    continue
                patterns.append(
                    _LiteralPattern(
                        (entity_id, name_id, pattern_id),
                        pattern_value,
                        pattern_map.get("case_sensitive") is True,
                    )
                )
    return tuple(patterns)


def _bank_binding(bank: Bank, *, canonical_bank_sha256: str | None = None) -> dict[str, Any]:
    metadata = bank.metadata()
    match_mode = metadata.get("match_mode")
    if not isinstance(match_mode, Mapping):
        match_mode = {}
    native_hash = metadata.get("bank_hash")
    if not isinstance(native_hash, str) or _SHA256_RE.fullmatch(native_hash) is None:
        raise _WorkerError("operation_failed")
    return {
        "canonical_bank_sha256": canonical_bank_sha256 or native_hash,
        "native_bank_sha256": native_hash,
        "engine": str(metadata.get("engine", "")),
        "schema": _runtime_int(metadata.get("schema"), minimum=0, maximum=1_000_000),
        "entity_count": _runtime_int(metadata.get("entity_count"), minimum=0, maximum=100_000),
        "pattern_count": _runtime_int(metadata.get("pattern_count"), minimum=0, maximum=100_000),
        "match_mode": str(match_mode.get("name", "")),
        "match_mode_status": str(match_mode.get("status", "")),
    }


def _compile_observation(binding: Mapping[str, Any]) -> _Observation:
    count = _runtime_int(binding.get("pattern_count"), minimum=0, maximum=100_000)
    digest = hashlib.sha256(b"nerb/enron/performance/compile-observation/v1\0")
    _digest_frame(digest, _canonical_json_bytes(binding))
    return _Observation(count, "sha256:" + digest.hexdigest())


def _scan_binding(_operation: Operation, bank: Mapping[str, Any], documents: Mapping[str, Any]) -> dict[str, Any]:
    # Operation identity is deliberately excluded: semantically exact native
    # and JSON-adapter paths must produce the same correctness commitment.
    return {"bank": dict(bank), "documents": dict(documents)}


def _native_record_identity(record: Any) -> tuple[Any, ...]:
    if not isinstance(record, Mapping):
        raise _WorkerError("operation_failed")
    return (
        _runtime_int(record.get("start"), minimum=0, maximum=sys.maxsize),
        _runtime_int(record.get("end"), minimum=0, maximum=sys.maxsize),
        _bounded_identity_string(record.get("entity")),
        _bounded_identity_string(record.get("canonical_name")),
        _bounded_identity_string(record.get("surface_name")),
    )


def _adapter_record_identity(record: Any) -> tuple[Any, ...]:
    # Enriched adapter records retain the native canonical fields.  Hash those
    # shared semantics so direct Bank reuse and helper paths can be compared
    # without exposing surfaces or detector identifiers.
    return _native_record_identity(record)


def _tuple_record_identity(record: Any) -> tuple[Any, ...]:
    if not isinstance(record, tuple) or not 2 <= len(record) <= 8:
        raise _WorkerError("operation_failed")
    return record


def _bounded_identity_string(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 4_096:
        raise _WorkerError("operation_failed")
    return value


def _identity_bytes(value: Any) -> bytes:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return b"i" + value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        if len(encoded) > 4_096:
            raise _WorkerError("operation_failed")
        return b"s" + encoded
    raise _WorkerError("operation_failed")


def _validate_request(value: Any) -> _Request:
    if not isinstance(value, Mapping):
        raise _WorkerError("request_shape")
    required = {"schema_version", "nonce", "workload_sha256", "operation", "warmups", "artifacts", "parameters"}
    if set(value) != required:
        raise _WorkerError("request_shape")
    if value.get("schema_version") != REQUEST_SCHEMA_VERSION:
        raise _WorkerError("request_schema")

    nonce = value.get("nonce")
    workload_sha256 = value.get("workload_sha256")
    operation = value.get("operation")
    if not isinstance(nonce, str) or _NONCE_RE.fullmatch(nonce) is None:
        raise _WorkerError("request_shape")
    if not isinstance(workload_sha256, str) or _SHA256_RE.fullmatch(workload_sha256) is None:
        raise _WorkerError("request_shape")
    if not isinstance(operation, str) or operation not in _OPERATIONS:
        raise _WorkerError("operation_invalid")
    warmups = _bounded_int(value.get("warmups"), minimum=0, maximum=DEFAULT_MAX_WARMUPS)

    raw_artifacts = value.get("artifacts")
    raw_parameters = value.get("parameters")
    if not isinstance(raw_artifacts, Mapping) or not isinstance(raw_parameters, Mapping):
        raise _WorkerError("request_shape")
    artifact_names, parameter_validators = _operation_shape(cast(Operation, operation))
    if set(raw_artifacts) != artifact_names or set(raw_parameters) != set(parameter_validators):
        raise _WorkerError("request_shape")
    artifacts = {str(name): _artifact_ref(raw_artifacts[name]) for name in artifact_names}
    parameters = {name: validator(raw_parameters[name]) for name, validator in parameter_validators.items()}
    return _Request(
        nonce=nonce,
        workload_sha256=workload_sha256,
        operation=cast(Operation, operation),
        warmups=warmups,
        artifacts=artifacts,
        parameters=parameters,
    )


def _operation_shape(operation: Operation) -> tuple[set[str], dict[str, Callable[[Any], Any]]]:
    def concurrency(value: Any) -> int:
        return _bounded_int(value, minimum=1, maximum=DEFAULT_MAX_CONCURRENCY)

    def record_limit(value: Any) -> int:
        return _bounded_int(value, minimum=1, maximum=DEFAULT_MAX_TOTAL_RECORDS)

    if operation == "source_profile":
        return {"source"}, {
            "max_line_bytes": lambda value: _bounded_int(value, minimum=1, maximum=DEFAULT_MAX_PROFILE_LINE_BYTES),
            "max_records": lambda value: _bounded_int(value, minimum=1, maximum=DEFAULT_MAX_PROFILE_RECORDS),
        }
    if operation == "source_build":
        return set(), {}
    if operation == "bank_compile":
        return {"bank"}, {
            "bank_format": lambda value: _enum_string(value, _BANK_FORMATS),
            "cache_mode": lambda value: _enum_string(value, _CACHE_MODES),
        }
    if operation == "direct_bank_scan":
        return {"bank", "input", "inventory"}, {
            "bank_format": lambda value: _enum_string(value, _BANK_FORMATS),
            "concurrency": concurrency,
            "sample_unit": lambda value: _enum_string(value, frozenset({"document", "whole_input"})),
        }
    if operation == "json_helper_scan":
        return {"bank", "input", "inventory"}, {
            "cache_mode": lambda value: _enum_string(value, frozenset({"hit", "miss"})),
            "concurrency": concurrency,
            "input_mode": lambda value: _enum_string(value, frozenset({"end_to_end", "prepared"})),
        }
    if operation == "json_adapter_scan":
        return {"bank", "input", "inventory"}, {"concurrency": concurrency}
    if operation == "config_engine_scan":
        return {"config", "input", "inventory"}, {
            "concurrency": concurrency,
            "word_boundaries": _strict_bool,
        }
    if operation == "generic_regex_scan":
        return {"input", "inventory"}, {
            "concurrency": concurrency,
            "max_records": record_limit,
            "pattern_set": lambda value: _enum_string(value, frozenset({"email_format_v1"})),
        }
    if operation == "python_literal_scan":
        return {"bank", "input", "inventory"}, {
            "concurrency": concurrency,
            "max_records": record_limit,
        }
    raise _WorkerError("operation_invalid")


def _artifact_ref(value: Any) -> _ArtifactRef:
    if not isinstance(value, Mapping) or set(value) != {"path", "sha256", "bytes", "identity"}:
        raise _WorkerError("request_shape")
    raw_path = value.get("path")
    raw_sha256 = value.get("sha256")
    try:
        path_bytes = raw_path.encode("utf-8") if isinstance(raw_path, str) else b""
    except UnicodeError:
        raise _WorkerError("request_shape") from None
    if (
        not isinstance(raw_path, str)
        or not raw_path
        or "\0" in raw_path
        or len(path_bytes) > DEFAULT_MAX_PATH_BYTES
        or not Path(raw_path).is_absolute()
        or any(part == os.pardir for part in Path(raw_path).parts)
        or not isinstance(raw_sha256, str)
        or _SHA256_RE.fullmatch(raw_sha256) is None
    ):
        raise _WorkerError("request_shape")
    byte_count = _bounded_int(value.get("bytes"), minimum=0, maximum=DEFAULT_MAX_PROFILE_BYTES)
    raw_identity = value.get("identity")
    identity_keys = {
        "kind",
        "device",
        "inode",
        "mode",
        "link_count",
        "size",
        "modified_ns",
        "changed_ns",
    }
    if not isinstance(raw_identity, Mapping) or set(raw_identity) != identity_keys:
        raise _WorkerError("request_shape")
    numeric = {key: raw_identity.get(key) for key in identity_keys - {"kind"}}
    if (
        raw_identity.get("kind") != "file"
        or any(type(item) is not int or item < 0 for item in numeric.values())
        or not is_owner_only_private_mode(cast(int, raw_identity.get("mode")))
        or raw_identity.get("link_count") != 1
        or raw_identity.get("size") != byte_count
    ):
        raise _WorkerError("request_shape")
    return _ArtifactRef(Path(raw_path), raw_sha256, byte_count, dict(raw_identity))


def _request_spec_sha256(request: _Request) -> str:
    value = {
        "operation": request.operation,
        "artifacts": {name: reference.semantic_descriptor() for name, reference in sorted(request.artifacts.items())},
        "parameters": dict(request.parameters),
    }
    return "sha256:" + hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _safe_correlation_fields(raw: bytes, limit: int) -> tuple[str | None, str | None]:
    if len(raw) > limit:
        return None, None
    try:
        value = _load_strict_json(raw)
    except BaseException:
        return None, None
    if not isinstance(value, Mapping):
        return None, None
    nonce = value.get("nonce")
    workload = value.get("workload_sha256")
    safe_nonce = nonce if isinstance(nonce, str) and _NONCE_RE.fullmatch(nonce) is not None else None
    safe_workload = workload if isinstance(workload, str) and _SHA256_RE.fullmatch(workload) is not None else None
    return safe_nonce, safe_workload


def _bounded_int(value: Any, *, minimum: int, maximum: int) -> int:
    return _checked_int(value, minimum=minimum, maximum=maximum, error_code="request_shape")


def _runtime_int(value: Any, *, minimum: int, maximum: int) -> int:
    return _checked_int(value, minimum=minimum, maximum=maximum, error_code="operation_failed")


def _checked_int(value: Any, *, minimum: int, maximum: int, error_code: ErrorCode) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise _WorkerError(error_code)
    return value


def _strict_bool(value: Any) -> bool:
    if not isinstance(value, bool):
        raise _WorkerError("request_shape")
    return value


def _enum_string(value: Any, choices: frozenset[str]) -> str:
    if not isinstance(value, str) or value not in choices:
        raise _WorkerError("request_shape")
    return value


def _load_strict_json(raw: bytes) -> Any:
    text = raw.decode("utf-8")

    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in values:
            if key in result:
                raise _StrictJSONError
            result[key] = item
        return result

    def reject_constant(_value: str) -> Any:
        raise _StrictJSONError

    def parse_int(value: str) -> int:
        if len(value.lstrip("-")) > 20:
            raise _StrictJSONError
        return int(value)

    def parse_float(value: str) -> float:
        if len(value) > 128:
            raise _StrictJSONError
        parsed = float(value)
        if not math.isfinite(parsed):
            raise _StrictJSONError
        return parsed

    try:
        return json.loads(
            text,
            object_pairs_hook=pairs,
            parse_constant=reject_constant,
            parse_float=parse_float,
            parse_int=parse_int,
        )
    except _StrictJSONError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError):
        raise _StrictJSONError from None


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise _WorkerError("operation_failed") from None


def _digest_frame(digest: Any, value: bytes) -> None:
    digest.update(len(value).to_bytes(8, "big"))
    digest.update(value)


def _elapsed_since(start_ns: int) -> int:
    elapsed_ns = time.perf_counter_ns() - start_ns
    if not 0 <= elapsed_ns <= _MAX_RESULT_INTEGER:
        raise _WorkerError("operation_failed")
    return elapsed_ns


def normalize_peak_rss(
    raw_value: Any,
    *,
    platform_name: str | None = None,
) -> tuple[int | None, str]:
    """Normalize ``ru_maxrss`` to bytes without guessing on unknown platforms."""

    platform_value = sys.platform if platform_name is None else platform_name
    if platform_value not in {"linux", "darwin"}:
        return None, "unsupported_platform"
    if isinstance(raw_value, bool) or not isinstance(raw_value, (int, float)):
        return None, "invalid_value"
    if isinstance(raw_value, int):
        if raw_value < 0:
            return None, "invalid_value"
        value = raw_value
    else:
        if not math.isfinite(raw_value) or raw_value < 0 or not raw_value.is_integer():
            return None, "invalid_value"
        value = int(raw_value)
    multiplier = 1024 if platform_value == "linux" else 1
    if value > _MAX_RESULT_INTEGER // multiplier:
        return None, "invalid_value"
    return value * multiplier, "supported"


def _peak_rss() -> tuple[int | None, str]:
    if _resource is None:
        return None, "resource_unavailable"
    try:
        usage = _resource.getrusage(_resource.RUSAGE_SELF)
        return normalize_peak_rss(usage.ru_maxrss)
    except BaseException:
        return None, "resource_unavailable"


def _result(
    nonce: str | None,
    workload_sha256: str | None,
    *,
    error_code: ErrorCode | None = None,
    elapsed_ns: int | None = None,
    observation: _Observation | None = None,
) -> dict[str, Any]:
    peak_rss_bytes, peak_rss_status = _peak_rss()
    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "nonce": nonce,
        "workload_sha256": workload_sha256,
        "pid": os.getpid(),
        "status": "ok" if error_code is None else "error",
        "error_code": error_code,
        "elapsed_ns": elapsed_ns,
        "peak_rss_bytes": peak_rss_bytes,
        "peak_rss_status": peak_rss_status,
        "record_count": None if observation is None else observation.record_count,
        "correctness_sha256": None if observation is None else observation.correctness_sha256,
    }


def encode_worker_result(result: Mapping[str, Any]) -> bytes:
    raw = _canonical_json_bytes(result) + b"\n"
    if len(raw) > DEFAULT_MAX_RESULT_BYTES:
        fallback = _result(None, None, error_code="internal_error")
        raw = _canonical_json_bytes(fallback) + b"\n"
    if len(raw) > DEFAULT_MAX_RESULT_BYTES:  # pragma: no cover - fixed-shape invariant.
        raise RuntimeError("Worker result exceeds its fixed byte limit.")
    return raw


@contextlib.contextmanager
def _discard_process_output():
    with open(os.devnull, "w", encoding="utf-8") as sink:
        with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            yield


def _no_op() -> None:
    return None


def _write_result(result: Mapping[str, Any]) -> None:
    payload = encode_worker_result(result)
    stdout = getattr(sys.stdout, "buffer", None)
    if stdout is None:  # pragma: no cover - ordinary processes always expose a binary buffer.
        sys.stdout.write(payload.decode("ascii"))
        sys.stdout.flush()
        return
    stdout.write(payload)
    stdout.flush()


def _read_one_request(limit: int) -> bytes:
    stdin = getattr(sys.stdin, "buffer", None)
    if stdin is None:  # pragma: no cover - ordinary processes always expose a binary buffer.
        return sys.stdin.read(limit + 1).encode("utf-8")
    return stdin.read(limit + 1)


def _drain_oversized_line(stdin: Any, line: bytes) -> None:
    if line.endswith(b"\n"):
        return
    while True:
        chunk = stdin.readline(DEFAULT_MAX_REQUEST_BYTES + 1)
        if not chunk or chunk.endswith(b"\n"):
            return


def _run_json_lines(worker: EnronPerformanceWorker) -> None:
    stdin = getattr(sys.stdin, "buffer", None)
    if stdin is None:  # pragma: no cover - ordinary processes always expose a binary buffer.
        raise SystemExit(2)
    while True:
        raw = stdin.readline(worker.max_request_bytes + 1)
        if not raw:
            return
        if len(raw) > worker.max_request_bytes:
            _drain_oversized_line(stdin, raw)
            _write_result(_result(None, None, error_code="request_too_large"))
            continue
        _write_result(worker.process_bytes(raw))


def main(argv: Sequence[str] | None = None) -> None:
    arguments = list(sys.argv[1:] if argv is None else argv)
    worker = EnronPerformanceWorker()
    try:
        if not arguments:
            _write_result(worker.process_bytes(_read_one_request(worker.max_request_bytes)))
            return
        if arguments == ["--json-lines"]:
            _run_json_lines(worker)
            return
        _write_result(_result(None, None, error_code="request_shape"))
    finally:
        try:
            worker.close()
        except BaseException:
            pass


if __name__ == "__main__":  # pragma: no cover - exercised by subprocess tests.
    main()

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

import nerb.enron_performance_worker as worker_module
from nerb.enron_performance_fixtures import make_enron_performance_bank_fixture
from nerb.enron_performance_worker import (
    REQUEST_SCHEMA_VERSION,
    RESULT_SCHEMA_VERSION,
    EnronPerformanceWorker,
    encode_worker_result,
    normalize_peak_rss,
)


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _artifact(path: Path, value: bytes) -> dict[str, Any]:
    path.write_bytes(value)
    path.chmod(0o600)
    info = path.stat()
    return {
        "path": str(path.resolve()),
        "sha256": _sha256(value),
        "bytes": len(value),
        "identity": {
            "kind": "file",
            "device": info.st_dev,
            "inode": info.st_ino,
            "mode": 0o600,
            "link_count": info.st_nlink,
            "size": info.st_size,
            "modified_ns": info.st_mtime_ns,
            "changed_ns": info.st_ctime_ns,
        },
    }


def _input_artifacts(
    tmp_path: Path,
    documents: list[bytes],
    records: list[int],
    *,
    prefix: str = "input",
) -> dict[str, dict[str, Any]]:
    assert len(documents) == len(records)
    inventory = [{"bytes": len(document), "records": count} for document, count in zip(documents, records)]
    return {
        "input": _artifact(tmp_path / f"{prefix}.bin", b"".join(documents)),
        "inventory": _artifact(tmp_path / f"{prefix}-inventory.json", _canonical(inventory)),
    }


def _request(
    operation: str,
    *,
    artifacts: dict[str, Any],
    parameters: dict[str, Any],
    workload: str,
    nonce: str = "sample-1",
    warmups: int = 0,
) -> dict[str, Any]:
    return {
        "schema_version": REQUEST_SCHEMA_VERSION,
        "nonce": nonce,
        "workload_sha256": _sha256(workload.encode("utf-8")),
        "operation": operation,
        "warmups": warmups,
        "artifacts": artifacts,
        "parameters": parameters,
    }


def _run(worker: EnronPerformanceWorker, request: dict[str, Any]) -> dict[str, Any]:
    return worker.process_bytes(_canonical(request))


def _json_bank(test_data_path: Path, *, draft_value: str = "DRAFT_PRIVATE_VALUE") -> dict[str, Any]:
    bank = json.loads((test_data_path / "minimal_bank.json").read_text(encoding="utf-8"))
    bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["draft_private"] = {
        "kind": "literal",
        "value": draft_value,
        "description": "Inactive privacy fixture.",
        "status": "draft",
        "priority": 101,
        "case_sensitive": True,
        "normalize_whitespace": False,
        "left_boundary": "none",
        "right_boundary": "none",
        "metadata": {},
    }
    return bank


def _evaluated_bank_descriptor() -> dict[str, Any]:
    return {
        "id": "evaluated_enron_bank",
        "bank_hash": "sha256:" + "1" * 64,
        "active_entities": 2,
        "active_names": 628,
        "active_aliases": 127,
        "active_patterns": 628,
        "composition": {
            "taxonomy": [
                {
                    "entity_class": "contact",
                    "entities": 1,
                    "canonical_names": 501,
                    "aliases": 0,
                    "literal_patterns": 500,
                    "regex_patterns": 1,
                },
                {
                    "entity_class": "person",
                    "entities": 1,
                    "canonical_names": 0,
                    "aliases": 127,
                    "literal_patterns": 127,
                    "regex_patterns": 0,
                },
            ]
        },
    }


def _bank_and_inputs(
    tmp_path: Path,
    test_data_path: Path,
    *,
    draft_value: str = "DRAFT_PRIVATE_VALUE",
    prefix: str = "fixture",
) -> tuple[dict[str, Any], dict[str, Any]]:
    bank = _json_bank(test_data_path, draft_value=draft_value)
    bank_ref = _artifact(tmp_path / f"{prefix}-bank.json", _canonical(bank))
    inputs = _input_artifacts(
        tmp_path,
        [f"Acme Corp and {draft_value}".encode(), b"nothing here"],
        [1, 0],
        prefix=prefix,
    )
    return bank_ref, inputs


def _direct_request(
    bank: dict[str, Any],
    inputs: dict[str, Any],
    *,
    workload: str,
    nonce: str = "sample-1",
    concurrency: int = 1,
    sample_unit: str = "whole_input",
    warmups: int = 0,
) -> dict[str, Any]:
    return _request(
        "direct_bank_scan",
        artifacts={"bank": bank, **inputs},
        parameters={
            "bank_format": "json_bank_active",
            "concurrency": concurrency,
            "sample_unit": sample_unit,
        },
        workload=workload,
        nonce=nonce,
        warmups=warmups,
    )


def test_direct_scan_filters_drafts_and_emits_deterministic_aggregate_only_result(
    tmp_path: Path, test_data_path: Path
) -> None:
    bank, inputs = _bank_and_inputs(tmp_path, test_data_path)
    worker = EnronPerformanceWorker()
    first_request = _direct_request(bank, inputs, workload="direct", warmups=1)
    second_request = {**first_request, "nonce": "sample-2"}

    first = _run(worker, first_request)
    second = _run(worker, second_request)

    assert first["schema_version"] == RESULT_SCHEMA_VERSION
    assert first["status"] == second["status"] == "ok"
    assert first["record_count"] == second["record_count"] == 1
    assert first["correctness_sha256"] == second["correctness_sha256"]
    assert isinstance(first["elapsed_ns"], int) and first["elapsed_ns"] >= 0
    serialized = encode_worker_result(first).decode("ascii")
    assert "Acme Corp" not in serialized
    assert "DRAFT_PRIVATE_VALUE" not in serialized
    assert str(tmp_path) not in serialized


def test_direct_worker_consumes_generated_native_source_and_canonical_fixture(tmp_path: Path) -> None:
    fixture = make_enron_performance_bank_fixture(
        active_patterns=1_000,
        evaluated_bank=_evaluated_bank_descriptor(),
    )
    native_bank = _artifact(tmp_path / fixture.source_filename.replace("/", "-"), fixture.source_bytes)
    canonical_bank = _artifact(tmp_path / fixture.canonical_filename.replace("/", "-"), fixture.canonical_bytes)
    inputs = _input_artifacts(tmp_path, [b"neutral benchmark text"], [0], prefix="native-jsonl")
    worker = EnronPerformanceWorker()

    native_result = _run(
        worker,
        _request(
            "direct_bank_scan",
            artifacts={"bank": native_bank, **inputs},
            parameters={"bank_format": "native_jsonl", "concurrency": 1, "sample_unit": "whole_input"},
            workload="native-jsonl",
        ),
    )
    canonical_result = _run(
        worker,
        _request(
            "direct_bank_scan",
            artifacts={"bank": canonical_bank, **inputs},
            parameters={"bank_format": "native_json", "concurrency": 1, "sample_unit": "whole_input"},
            workload="native-json",
        ),
    )

    assert native_result["status"] == canonical_result["status"] == "ok"
    assert native_result["record_count"] == canonical_result["record_count"] == 0
    assert native_result["correctness_sha256"] == canonical_result["correctness_sha256"]


def test_full_canonical_bank_hash_binds_inactive_catalog_changes(tmp_path: Path, test_data_path: Path) -> None:
    first_bank, first_inputs = _bank_and_inputs(tmp_path, test_data_path, prefix="first")
    second_bank, second_inputs = _bank_and_inputs(
        tmp_path,
        test_data_path,
        draft_value="DIFFERENT_DRAFT_PRIVATE_VALUE",
        prefix="second",
    )
    worker = EnronPerformanceWorker()

    first = _run(worker, _direct_request(first_bank, first_inputs, workload="first"))
    second = _run(worker, _direct_request(second_bank, second_inputs, workload="second"))

    assert first["record_count"] == second["record_count"] == 1
    assert first["correctness_sha256"] != second["correctness_sha256"]


def test_document_sample_cursor_resets_after_one_time_warmups_and_wraps(tmp_path: Path, test_data_path: Path) -> None:
    bank, inputs = _bank_and_inputs(tmp_path, test_data_path)
    worker = EnronPerformanceWorker()
    request = _direct_request(
        bank,
        inputs,
        workload="document-cursor",
        sample_unit="document",
        warmups=1,
    )

    results = [_run(worker, {**request, "nonce": f"sample-{index}"}) for index in range(1, 4)]

    assert [result["status"] for result in results] == ["ok", "ok", "ok"]
    assert [result["record_count"] for result in results] == [1, 0, 1]
    assert results[0]["correctness_sha256"] == results[2]["correctness_sha256"]
    assert results[0]["correctness_sha256"] != results[1]["correctness_sha256"]


def test_whole_input_concurrency_preserves_count_and_correctness_digest(tmp_path: Path, test_data_path: Path) -> None:
    bank, inputs = _bank_and_inputs(tmp_path, test_data_path)
    worker = EnronPerformanceWorker()

    sequential = _run(worker, _direct_request(bank, inputs, workload="sequential", concurrency=1))
    concurrent = _run(worker, _direct_request(bank, inputs, workload="concurrent", concurrency=2, warmups=1))

    assert sequential["status"] == concurrent["status"] == "ok"
    assert sequential["record_count"] == concurrent["record_count"] == 1
    assert sequential["correctness_sha256"] == concurrent["correctness_sha256"]


def test_scan_elapsed_time_excludes_correctness_digest_work(
    tmp_path: Path,
    test_data_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bank, inputs = _bank_and_inputs(tmp_path, test_data_path)
    ticks = iter((1_000, 1_075))
    monkeypatch.setattr(worker_module.time, "perf_counter_ns", lambda: next(ticks))

    result = _run(EnronPerformanceWorker(), _direct_request(bank, inputs, workload="timing-boundary"))

    assert result["status"] == "ok"
    assert result["elapsed_ns"] == 75


@pytest.mark.parametrize("cache_mode", ["miss", "hit"])
@pytest.mark.parametrize("input_mode", ["prepared", "end_to_end"])
def test_json_helper_scan_times_compile_or_cache_lookup_plus_full_scan(
    tmp_path: Path,
    test_data_path: Path,
    cache_mode: str,
    input_mode: str,
) -> None:
    bank, inputs = _bank_and_inputs(tmp_path, test_data_path, prefix=f"{cache_mode}-{input_mode}")
    request = _request(
        "json_helper_scan",
        artifacts={"bank": bank, **inputs},
        parameters={"cache_mode": cache_mode, "concurrency": 1, "input_mode": input_mode},
        workload=f"helper-{cache_mode}-{input_mode}",
        warmups=1,
    )

    result = _run(EnronPerformanceWorker(), request)

    assert result["status"] == "ok"
    assert result["record_count"] == 1
    assert isinstance(result["elapsed_ns"], int)


@pytest.mark.parametrize(
    ("cache_mode", "input_mode", "expected_compile_calls"),
    [
        ("hit", "prepared", 2),
        ("miss", "prepared", 1),
        ("miss", "end_to_end", 1),
    ],
)
def test_helper_miss_and_end_to_end_do_not_prime_an_untimed_compile(
    cache_mode: str,
    input_mode: str,
    expected_compile_calls: int,
    tmp_path: Path,
    test_data_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bank, inputs = _bank_and_inputs(tmp_path, test_data_path, prefix=f"compile-count-{cache_mode}-{input_mode}")
    real_compile = worker_module.compile_bank_with_report
    calls = 0

    def counted_compile(value: Any):
        nonlocal calls
        calls += 1
        return real_compile(value)

    monkeypatch.setattr(worker_module, "compile_bank_with_report", counted_compile)
    request = _request(
        "json_helper_scan",
        artifacts={"bank": bank, **inputs},
        parameters={"cache_mode": cache_mode, "concurrency": 1, "input_mode": input_mode},
        workload=f"compile-count-{cache_mode}-{input_mode}",
    )

    result = _run(EnronPerformanceWorker(), request)

    assert result["status"] == "ok"
    assert calls == expected_compile_calls


def test_helper_modes_share_correctness_identity(tmp_path: Path, test_data_path: Path) -> None:
    bank, inputs = _bank_and_inputs(tmp_path, test_data_path)
    worker = EnronPerformanceWorker()
    results = []
    for cache_mode, input_mode in (("miss", "prepared"), ("hit", "prepared"), ("miss", "end_to_end")):
        request = _request(
            "json_helper_scan",
            artifacts={"bank": bank, **inputs},
            parameters={"cache_mode": cache_mode, "concurrency": 1, "input_mode": input_mode},
            workload=f"helper-{cache_mode}-{input_mode}",
        )
        results.append(_run(worker, request))

    assert {result["record_count"] for result in results} == {1}
    assert len({result["correctness_sha256"] for result in results}) == 1


def test_direct_and_helper_paths_share_canonical_correctness_identity(tmp_path: Path, test_data_path: Path) -> None:
    bank, inputs = _bank_and_inputs(tmp_path, test_data_path)
    direct = _run(EnronPerformanceWorker(), _direct_request(bank, inputs, workload="direct-exact"))
    helper = _run(
        EnronPerformanceWorker(),
        _request(
            "json_helper_scan",
            artifacts={"bank": bank, **inputs},
            parameters={"cache_mode": "miss", "concurrency": 1, "input_mode": "prepared"},
            workload="helper-exact",
        ),
    )

    assert direct["status"] == helper["status"] == "ok"
    assert direct["record_count"] == helper["record_count"] == 1
    assert direct["correctness_sha256"] == helper["correctness_sha256"]


@pytest.mark.parametrize("cache_mode", ["disabled", "miss", "hit"])
def test_native_bank_compile_modes_return_same_bound_pattern_count(tmp_path: Path, cache_mode: str) -> None:
    source = _canonical({"CODE": {"Acme": "Acme Corp"}})
    bank = _artifact(tmp_path / f"native-{cache_mode}.json", source)
    request = _request(
        "bank_compile",
        artifacts={"bank": bank},
        parameters={"bank_format": "native_json", "cache_mode": cache_mode},
        workload=f"compile-{cache_mode}",
        warmups=1,
    )

    result = _run(EnronPerformanceWorker(), request)

    assert result["status"] == "ok"
    assert result["record_count"] == 1
    assert result["correctness_sha256"].startswith("sha256:")


def test_adapter_config_and_non_equivalent_exploratory_operations(tmp_path: Path, test_data_path: Path) -> None:
    bank, inputs = _bank_and_inputs(tmp_path, test_data_path)
    config = _artifact(tmp_path / "config.yaml", b"CODE:\n  Acme: Acme Corp\n")
    email_inputs = _input_artifacts(tmp_path, [b"write to person@example.invalid"], [0], prefix="email")
    worker = EnronPerformanceWorker()
    requests = [
        _request(
            "json_adapter_scan",
            artifacts={"bank": bank, **inputs},
            parameters={"concurrency": 1},
            workload="adapter",
        ),
        _request(
            "config_engine_scan",
            artifacts={"config": config, **inputs},
            parameters={"concurrency": 1, "word_boundaries": False},
            workload="config",
        ),
        _request(
            "generic_regex_scan",
            artifacts=email_inputs,
            parameters={"concurrency": 1, "max_records": 10, "pattern_set": "email_format"},
            workload="generic",
        ),
        _request(
            "python_literal_scan",
            artifacts={"bank": bank, **inputs},
            parameters={"concurrency": 1, "max_records": 10},
            workload="python",
        ),
    ]

    results = [_run(worker, request) for request in requests]

    assert [result["status"] for result in results] == ["ok", "ok", "ok", "ok"]
    assert [result["record_count"] for result in results] == [1, 1, 1, 1]


def test_source_profile_is_strict_bounded_and_deterministic(tmp_path: Path) -> None:
    source_bytes = b'{"id":1,"value":"private-one"}\n{"id":2,"value":"private-two"}\n'
    source = _artifact(tmp_path / "private-source.jsonl", source_bytes)
    request = _request(
        "source_profile",
        artifacts={"source": source},
        parameters={"max_line_bytes": 1_024, "max_records": 10},
        workload="profile",
    )
    worker = EnronPerformanceWorker()

    first = _run(worker, request)
    second = _run(worker, {**request, "nonce": "sample-2"})

    assert first["status"] == second["status"] == "ok"
    assert first["record_count"] == second["record_count"] == 2
    assert first["correctness_sha256"] == second["correctness_sha256"]
    assert b"private-one" not in encode_worker_result(first)


def test_source_profile_rejects_same_byte_inode_substitution_before_parsing(
    tmp_path: Path,
) -> None:
    source_path = tmp_path / "private-source.jsonl"
    source_bytes = b'{"id":1,"value":"private-one"}\n'
    source = _artifact(source_path, source_bytes)
    replacement = tmp_path / "replacement.jsonl"
    replacement.write_bytes(source_bytes)
    replacement.chmod(0o600)
    replacement.replace(source_path)
    request = _request(
        "source_profile",
        artifacts={"source": source},
        parameters={"max_line_bytes": 1_024, "max_records": 10},
        workload="profile-substitution",
    )

    result = _run(EnronPerformanceWorker(), request)

    assert result["status"] == "error"
    assert result["error_code"] == "artifact_changed"


def test_source_profile_accepts_owner_read_only_frozen_file(tmp_path: Path) -> None:
    source_path = tmp_path / "read-only-source.jsonl"
    source_bytes = b'{"id":1,"value":"private-one"}\n'
    source = _artifact(source_path, source_bytes)
    source_path.chmod(0o400)
    info = source_path.stat()
    source["identity"] = {
        "kind": "file",
        "device": info.st_dev,
        "inode": info.st_ino,
        "mode": 0o400,
        "link_count": info.st_nlink,
        "size": info.st_size,
        "modified_ns": info.st_mtime_ns,
        "changed_ns": info.st_ctime_ns,
    }
    request = _request(
        "source_profile",
        artifacts={"source": source},
        parameters={"max_line_bytes": 1_024, "max_records": 10},
        workload="profile-read-only",
    )

    result = _run(EnronPerformanceWorker(), request)

    assert result["status"] == "ok"
    assert result["record_count"] == 1


def test_source_build_is_explicitly_unsupported_in_narrow_worker() -> None:
    request = _request("source_build", artifacts={}, parameters={}, workload="source-build")

    result = _run(EnronPerformanceWorker(), request)

    assert result["status"] == "error"
    assert result["error_code"] == "operation_unsupported"


def test_correctness_mismatch_keeps_only_aggregate_observation(tmp_path: Path, test_data_path: Path) -> None:
    bank = _artifact(tmp_path / "bank.json", _canonical(_json_bank(test_data_path)))
    inputs = _input_artifacts(tmp_path, [b"Acme Corp"], [0])
    request = _direct_request(bank, inputs, workload="wrong-count")

    result = _run(EnronPerformanceWorker(), request)

    assert result["status"] == "error"
    assert result["error_code"] == "correctness_mismatch"
    assert result["record_count"] == 1
    assert result["correctness_sha256"].startswith("sha256:")
    assert isinstance(result["elapsed_ns"], int)


@pytest.mark.parametrize(
    ("raw", "error_code"),
    [
        (b"{", "request_json"),
        (b'{"schema_version":NaN}', "request_json"),
        (b'{"schema_version":1e999}', "request_json"),
        (b'{"schema_version":1,"schema_version":2}', "request_json"),
        (_canonical([]), "request_shape"),
    ],
)
def test_malformed_requests_return_stable_sanitized_errors(raw: bytes, error_code: str) -> None:
    result = EnronPerformanceWorker().process_bytes(raw)

    assert result["status"] == "error"
    assert result["error_code"] == error_code
    assert result["nonce"] is None
    assert result["workload_sha256"] is None
    assert result["elapsed_ns"] is None


def test_oversized_request_does_not_echo_correlation_fields() -> None:
    worker = EnronPerformanceWorker(max_request_bytes=32)
    raw = _canonical(
        _request("source_build", artifacts={}, parameters={}, workload="oversized", nonce="sensitive-token")
    )

    result = worker.process_bytes(raw)

    assert result["error_code"] == "request_too_large"
    assert result["nonce"] is None
    assert result["workload_sha256"] is None


def test_same_workload_hash_cannot_reuse_mismatched_spec(tmp_path: Path, test_data_path: Path) -> None:
    bank, inputs = _bank_and_inputs(tmp_path, test_data_path)
    worker = EnronPerformanceWorker()
    first = _direct_request(bank, inputs, workload="same", concurrency=1)
    changed = _direct_request(bank, inputs, workload="same", concurrency=2)

    assert _run(worker, first)["status"] == "ok"
    result = _run(worker, changed)

    assert result["status"] == "error"
    assert result["error_code"] == "workload_mismatch"


def test_reused_state_cannot_cross_to_a_different_approved_path(tmp_path: Path, test_data_path: Path) -> None:
    bank, inputs = _bank_and_inputs(tmp_path, test_data_path)
    copied_bank = _artifact(tmp_path / "copied-bank.json", Path(bank["path"]).read_bytes())
    worker = EnronPerformanceWorker()

    assert _run(worker, _direct_request(bank, inputs, workload="same-path-bound"))["status"] == "ok"
    result = _run(worker, _direct_request(copied_bank, inputs, workload="same-path-bound"))

    assert result["error_code"] == "workload_mismatch"


def test_inventory_and_artifact_bindings_fail_closed(tmp_path: Path, test_data_path: Path) -> None:
    bank = _artifact(tmp_path / "bank.json", _canonical(_json_bank(test_data_path)))
    invalid_utf8 = _input_artifacts(tmp_path, [b"\xff"], [0], prefix="invalid-utf8")
    mismatch = _input_artifacts(tmp_path, [b"Acme Corp"], [1], prefix="mismatch")
    mismatch["inventory"]["bytes"] += 1
    worker = EnronPerformanceWorker()

    invalid_result = _run(worker, _direct_request(bank, invalid_utf8, workload="invalid-utf8"))
    changed_result = _run(worker, _direct_request(bank, mismatch, workload="changed"))

    assert invalid_result["error_code"] == "input_inventory_invalid"
    assert changed_result["error_code"] == "request_shape"


def test_malformed_inventory_values_return_inventory_error(tmp_path: Path, test_data_path: Path) -> None:
    bank = _artifact(tmp_path / "bank.json", _canonical(_json_bank(test_data_path)))
    input_ref = _artifact(tmp_path / "input.bin", b"Acme Corp")
    inventory_ref = _artifact(tmp_path / "inventory.json", _canonical([{"bytes": -1, "records": 1}]))
    request = _direct_request(bank, {"input": input_ref, "inventory": inventory_ref}, workload="bad-inventory")

    result = _run(EnronPerformanceWorker(), request)

    assert result["error_code"] == "input_inventory_invalid"


def test_symlink_artifact_is_rejected_without_echoing_path(tmp_path: Path, test_data_path: Path) -> None:
    source_path = tmp_path / "private-bank.json"
    source = _canonical(_json_bank(test_data_path))
    bank = _artifact(source_path, source)
    link = tmp_path / "private-bank-link.json"
    link.symlink_to(source_path)
    # Resolve the parent but preserve the final symlink component for the no-follow open.
    bank["path"] = str(link.parent.resolve() / link.name)
    inputs = _input_artifacts(tmp_path, [b"Acme Corp"], [1])

    result = _run(EnronPerformanceWorker(), _direct_request(bank, inputs, workload="symlink"))

    assert result["error_code"] == "artifact_invalid"
    assert str(link) not in encode_worker_result(result).decode("ascii")


def test_operation_output_and_exception_payload_are_discarded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    private_value = "person@example.invalid"

    class LeakyOperation:
        def before_sample(self) -> None:
            print(private_value)

        def observe(self):
            print(private_value, file=sys.stderr)
            raise RuntimeError(private_value)

        def finish_warmups(self) -> None:
            return None

        def close(self) -> None:
            return None

    monkeypatch.setattr(worker_module, "_prepare_operation", lambda _request: LeakyOperation())
    source = {
        "path": str((tmp_path / "not-read.jsonl").resolve()),
        "sha256": _sha256(b""),
        "bytes": 0,
        "identity": {
            "kind": "file",
            "device": 0,
            "inode": 0,
            "mode": 0o600,
            "link_count": 1,
            "size": 0,
            "modified_ns": 0,
            "changed_ns": 0,
        },
    }
    request = _request(
        "source_profile",
        artifacts={"source": source},
        parameters={"max_line_bytes": 1, "max_records": 1},
        workload="leaky",
    )

    result = _run(EnronPerformanceWorker(), request)

    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
    assert result["error_code"] == "operation_failed"
    assert private_value not in encode_worker_result(result).decode("ascii")


@pytest.mark.parametrize(
    ("platform_name", "raw", "expected"),
    [
        ("linux", 123, (123 * 1024, "supported")),
        ("darwin", 123, (123, "supported")),
        ("win32", 123, (None, "unsupported_platform")),
        ("linux", float("nan"), (None, "invalid_value")),
        ("darwin", -1, (None, "invalid_value")),
        ("darwin", 10**400, (None, "invalid_value")),
    ],
)
def test_peak_rss_unit_normalization(platform_name: str, raw: Any, expected: tuple[int | None, str]) -> None:
    assert normalize_peak_rss(raw, platform_name=platform_name) == expected


def test_peak_rss_resource_semantics_are_injectable(monkeypatch: pytest.MonkeyPatch) -> None:
    class Usage:
        ru_maxrss = 42

    class Resource:
        RUSAGE_SELF = 0

        @staticmethod
        def getrusage(who: int) -> Usage:
            assert who == 0
            return Usage()

    monkeypatch.setattr(worker_module, "_resource", Resource())
    monkeypatch.setattr(worker_module.sys, "platform", "linux")

    assert worker_module._peak_rss() == (42 * 1024, "supported")


def test_fresh_and_reused_cli_modes_are_bounded_and_correlated(tmp_path: Path, test_data_path: Path) -> None:
    bank, inputs = _bank_and_inputs(tmp_path, test_data_path)
    whole_request = _direct_request(bank, inputs, workload="fresh", nonce="fresh", warmups=1)
    fresh = subprocess.run(
        [sys.executable, "-m", "nerb.enron_performance_worker"],
        input=_canonical(whole_request),
        capture_output=True,
        check=True,
        timeout=30,
    )
    fresh_result = json.loads(fresh.stdout)

    document_request = _direct_request(
        bank,
        inputs,
        workload="reused",
        nonce="reused-1",
        sample_unit="document",
        warmups=1,
    )
    requests = [
        document_request,
        {**document_request, "nonce": "reused-2"},
        {**document_request, "nonce": "reused-3"},
    ]
    reused = subprocess.run(
        [sys.executable, "-m", "nerb.enron_performance_worker", "--json-lines"],
        input=b"".join(_canonical(request) + b"\n" for request in requests),
        capture_output=True,
        check=True,
        timeout=30,
    )
    reused_results = [json.loads(line) for line in reused.stdout.splitlines()]

    assert fresh.stderr == reused.stderr == b""
    assert fresh_result["status"] == "ok"
    assert fresh_result["record_count"] == 1
    assert [result["record_count"] for result in reused_results] == [1, 0, 1]
    assert [result["nonce"] for result in reused_results] == ["reused-1", "reused-2", "reused-3"]
    assert len({result["pid"] for result in reused_results}) == 1
    assert all(len(line) <= worker_module.DEFAULT_MAX_RESULT_BYTES for line in reused.stdout.splitlines(keepends=True))


def test_worker_result_shape_never_contains_unapproved_fields() -> None:
    request = _request("source_build", artifacts={}, parameters={}, workload="shape")
    result = _run(EnronPerformanceWorker(), request)

    assert set(result) == {
        "schema_version",
        "nonce",
        "workload_sha256",
        "pid",
        "status",
        "error_code",
        "elapsed_ns",
        "peak_rss_bytes",
        "peak_rss_status",
        "record_count",
        "correctness_sha256",
    }
    assert len(encode_worker_result(result)) <= worker_module.DEFAULT_MAX_RESULT_BYTES

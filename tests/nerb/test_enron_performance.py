from __future__ import annotations

import hashlib
import json
import math
import os
import shutil
import traceback
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import nerb.enron_performance as performance_module
from nerb.bank import bank_stats, canonicalize_bank, hash_bank
from nerb.enron_contract import (
    PERFORMANCE_PHASE_PROCESS_MODELS,
    PERFORMANCE_SCALE_PATTERNS,
    hash_enron_breakeven_plan,
    hash_enron_performance_bank,
    hash_enron_performance_comparison_plan,
    hash_enron_performance_harness,
    hash_enron_performance_input,
    hash_enron_performance_manifest,
    hash_enron_workload,
    summarize_enron_performance_inventory,
)
from nerb.enron_performance import (
    EnronPerformanceError,
    EnronPerformancePrepareOptions,
    EnronPerformanceRunOptions,
    prepare_enron_performance_manifest,
    run_enron_performance,
    verify_enron_performance_run,
)
from nerb.enron_performance_fixtures import (
    EnronPerformanceBankFixture,
    EnronPerformanceInputFixture,
    EnronPerformanceInventoryRow,
)

_HASH_1 = "sha256:" + "1" * 64
_HASH_2 = "sha256:" + "2" * 64
_GENERATOR = {
    "id": "safe_test_generator",
    "version": "1.0.0",
    "source_sha256": _HASH_1,
    "spec_sha256": _HASH_2,
    "seed": "safe-test-seed",
}


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


def _artifact(identifier: str, payload: bytes) -> dict[str, Any]:
    return {"id": identifier, "sha256": _sha256(payload), "bytes": len(payload)}


def _evaluated_descriptor() -> dict[str, Any]:
    payload = b'{"safe":"evaluated-bank"}'
    descriptor: dict[str, Any] = {
        "id": "evaluated_bank",
        "kind": "evaluated_bank",
        "bank_hash": _sha256(b"evaluated-bank-hash"),
        "artifact": _artifact("evaluated_bank_artifact", payload),
        "generator": None,
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
        "descriptor_sha256": "",
        "active_entities": 2,
        "active_names": 628,
        "active_aliases": 127,
        "active_patterns": 628,
        "canonical_json_bytes": len(payload),
        "native_source_bytes": len(payload),
    }
    descriptor["descriptor_sha256"] = hash_enron_performance_bank(descriptor)
    return descriptor


def _fake_bank_fixtures() -> tuple[EnronPerformanceBankFixture, ...]:
    fixtures: list[EnronPerformanceBankFixture] = []
    for active_patterns in PERFORMANCE_SCALE_PATTERNS:
        identifier = f"scale_{active_patterns}"
        source = _canonical({"SAFE": {identifier: f"TOKEN_{active_patterns}"}})
        canonical = _canonical({"schema": 1, "safe_id": identifier})
        aliases = active_patterns // 5
        contact_patterns = active_patterns - aliases
        descriptor: dict[str, Any] = {
            "id": identifier,
            "kind": "synthetic_scale",
            "bank_hash": _sha256(f"bank:{identifier}".encode()),
            "artifact": _artifact(f"{identifier}_canonical_bank", canonical),
            "generator": dict(_GENERATOR),
            "composition": {
                "taxonomy": [
                    {
                        "entity_class": "contact",
                        "entities": 1,
                        "canonical_names": contact_patterns,
                        "aliases": 0,
                        "literal_patterns": contact_patterns,
                        "regex_patterns": 0,
                    },
                    {
                        "entity_class": "person",
                        "entities": 1,
                        "canonical_names": 0,
                        "aliases": aliases,
                        "literal_patterns": aliases,
                        "regex_patterns": 0,
                    },
                ]
            },
            "descriptor_sha256": "",
            "active_entities": 2,
            "active_names": active_patterns,
            "active_aliases": aliases,
            "active_patterns": active_patterns,
            "canonical_json_bytes": len(canonical),
            "native_source_bytes": len(source),
        }
        descriptor["descriptor_sha256"] = hash_enron_performance_bank(descriptor)
        fixtures.append(
            EnronPerformanceBankFixture(
                id=identifier,
                source_artifact_id=f"{identifier}_native_source",
                source_filename=f"banks/{identifier}.native.jsonl",
                canonical_artifact_id=f"{identifier}_canonical_bank",
                canonical_filename=f"banks/{identifier}.canonical.json",
                source_bytes=source,
                canonical_bytes=canonical,
                source_sha256=_sha256(source),
                bank_hash=descriptor["bank_hash"],
                canonical_sha256=_sha256(canonical),
                descriptor_bytes=_canonical(descriptor),
                preflight_record_count=0,
                _hit_tokens=(),
            )
        )
    return tuple(fixtures)


def _input_descriptor(
    identifier: str,
    *,
    bank: Mapping[str, Any],
    kind: str = "synthetic_input",
    documents: Sequence[bytes] = (b"safe",) * 100,
    records: Sequence[int] | None = None,
) -> tuple[dict[str, Any], bytes, bytes, tuple[EnronPerformanceInventoryRow, ...]]:
    record_counts = tuple(0 for _ in documents) if records is None else tuple(records)
    assert len(documents) == len(record_counts)
    inventory = [
        {"bytes": len(document), "records": record_count}
        for document, record_count in zip(documents, record_counts, strict=True)
    ]
    raw = b"".join(documents)
    inventory_bytes = _canonical(inventory)
    descriptor: dict[str, Any] = {
        "id": identifier,
        "kind": kind,
        "bank_id": bank["id"],
        "bank_hash": bank["bank_hash"],
        "artifact": _artifact(f"{identifier}_documents", raw),
        "inventory_ref": _artifact(f"{identifier}_inventory", inventory_bytes),
        "generator": None if kind == "real_input" else dict(_GENERATOR),
        **summarize_enron_performance_inventory(inventory),
        "descriptor_sha256": "",
    }
    descriptor["descriptor_sha256"] = hash_enron_performance_input(descriptor)
    rows = tuple(
        EnronPerformanceInventoryRow(byte_count=len(document), record_count=record_count)
        for document, record_count in zip(documents, record_counts, strict=True)
    )
    return descriptor, raw, inventory_bytes, rows


def _fake_input_fixtures(
    bank_fixtures: Sequence[EnronPerformanceBankFixture],
) -> tuple[EnronPerformanceInputFixture, ...]:
    bank_by_id = {fixture.id: fixture.descriptor for fixture in bank_fixtures}
    inputs: list[EnronPerformanceInputFixture] = []
    identifiers = [
        *(f"scale_{active_patterns}_input" for active_patterns in PERFORMANCE_SCALE_PATTERNS),
        *(f"density_{density}_input" for density in ("sparse", "normal", "dense")),
        *(f"size_{size}_input" for size in ("small", "large", "huge")),
    ]
    for identifier in identifiers:
        if identifier.startswith("scale_"):
            bank_id = identifier.removesuffix("_input")
        else:
            bank_id = "scale_1000"
        descriptor, raw, inventory_bytes, rows = _input_descriptor(
            identifier,
            bank=bank_by_id[bank_id],
        )
        inputs.append(
            EnronPerformanceInputFixture(
                id=identifier,
                artifact_id=descriptor["artifact"]["id"],
                artifact_filename=f"inputs/{identifier}.raw",
                inventory_id=descriptor["inventory_ref"]["id"],
                inventory_filename=f"inputs/{identifier}.inventory.json",
                artifact_bytes=raw,
                inventory_bytes=inventory_bytes,
                documents=(b"safe",) * 100,
                inventory_rows=rows,
                descriptor_bytes=_canonical(descriptor),
            )
        )
    return tuple(inputs)


def _make_plan(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    monkeypatch.setattr(performance_module, "_source_sha256", lambda _paths: _HASH_1)
    bank_fixtures = _fake_bank_fixtures()
    evaluated = _evaluated_descriptor()
    real_input, _raw, _inventory, _rows = _input_descriptor(
        "real_validation_input",
        bank=evaluated,
        kind="real_input",
    )
    return performance_module._performance_plan(
        benchmark_version="safe-benchmark-v2",
        source_profile_artifact=_artifact("development_train", b"safe-train"),
        source_build_artifact=_artifact("development_train", b"safe-train"),
        evaluated_bank=evaluated,
        bank_fixtures=bank_fixtures,
        real_input=real_input,
        input_fixtures=_fake_input_fixtures(bank_fixtures),
        concurrency=4,
        source_curation_seconds=60.0,
    )


@pytest.fixture
def performance_plan(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    return _make_plan(monkeypatch)


def test_plan_freezes_exact_matrix_controls_comparisons_and_hashes(
    performance_plan: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    repeated = _make_plan(monkeypatch)
    assert repeated == performance_plan
    assert performance_plan["suite"] == "enron_cache_value"
    assert performance_plan["scale_axis"] == "active_matcher_patterns"
    assert performance_plan["catalog_aliases_reported_separately"] is True
    assert performance_plan["plan_sha256"] == performance_module._canonical_hash(
        {key: value for key, value in performance_plan.items() if key != "plan_sha256"}
    )

    decision = performance_plan["profiles"]["decision"]
    performance = decision["performance"]
    workloads = {item["id"]: item for item in performance["workloads"]}
    candidates = [item for item in workloads.values() if not item["id"].startswith(("control_", "explore_"))]
    decision_candidates = [item for item in candidates if item["decision_grade"]]
    controls = [item for item in workloads.values() if item["id"].startswith("control_")]
    exploratory = [item for item in workloads.values() if item["id"].startswith("explore_")]
    assert len(candidates) == 20
    assert len(decision_candidates) == 19
    assert len(controls) == 20
    assert len(exploratory) == 2
    support = workloads["real_direct_cache_value"]
    assert support["decision_grade"] is False
    assert support["promotion_gate"] is False
    assert len(performance["comparisons"]) == 32
    cross_path = [item for item in performance["comparisons"] if item["comparison_kind"] == "cross_path_value"]
    same_path = [item for item in performance["comparisons"] if item["comparison_kind"] == "same_path_stability"]
    assert len(cross_path) == 12
    assert {item["noise_method"] for item in cross_path} == {"paired_block_ratio_mad"}
    assert len(same_path) == 20
    assert {item["noise_method"] for item in same_path} == {"exact_block_swap"}
    assert {item["direction"] for item in same_path} == {"symmetric"}
    assert {item["block_count"] for item in same_path} == {10}
    assert {tuple(item["block_assignment"]) for item in same_path} == {
        performance_module.PERFORMANCE_EXACT_BLOCK_ASSIGNMENT
    }
    assert {item["significance_level"] for item in same_path} == {0.05}
    assert {item["stability_tolerance"] for item in same_path} == {0.05}
    assert len(performance["breakeven_models"]) == 1
    breakeven = performance["breakeven_models"][0]
    assert breakeven["parameter_name"] == "whole_input_scan_requests"
    assert breakeven["parameter_unit"] == "request"
    assert {item["source"] for item in breakeven["components"] if item["category"] == "scan"} == {
        "workload_seconds_per_request"
    }
    assert decision["performance_manifest_sha256"] == hash_enron_performance_manifest(performance)
    assert all(item["workload_sha256"] == hash_enron_workload(item) for item in workloads.values())

    baseline_by_id = {item["id"]: item for item in performance["baselines"]}
    assert baseline_by_id[performance_module.PERFORMANCE_EXACT_CONTROL_ID]["semantic_equivalence"] == "exact"
    assert baseline_by_id[performance_module.PERFORMANCE_UNCACHED_BASELINE_ID]["semantic_equivalence"] == "exact"
    for candidate in candidates:
        control = workloads[f"control_{candidate['id']}"]
        for field in (
            "phase",
            "harness_id",
            "harness_sha256",
            "bank_id",
            "bank_hash",
            "input_id",
            "input_sha256",
            "warmups",
            "sample_unit",
            "work_per_sample",
            "concurrency",
            "process_model",
        ):
            assert control[field] == candidate[field]
    stability_metrics = [
        item["metric"] for item in performance["comparisons"] if item["comparison_kind"] == "same_path_stability"
    ]
    assert stability_metrics.count("median_seconds") == 7
    assert stability_metrics.count("p99_seconds") == 13
    assert {item["samples_per_block"] for item in same_path if item["metric"] == "median_seconds"} == {2, 10}
    assert {item["samples_per_block"] for item in same_path if item["metric"] == "p99_seconds"} == {100}
    assert decision["sample_policy"] == {
        "setup_samples": 20,
        "scan_samples": 1_000,
        "cache_value_samples": 100,
        "document_samples": 1_000,
        "exact_control_blocks": 10,
        "setup_samples_per_block": 2,
        "scan_samples_per_block": 100,
        "cache_value_samples_per_block": 10,
        "document_samples_per_block": 100,
        "warmups": 3,
        "interleaving": "ten_block_exact_swap_with_williams_cross_path",
        "promotable": True,
    }


def test_smoke_plan_is_explicitly_nonpromotable(performance_plan: dict[str, Any]) -> None:
    smoke = performance_plan["profiles"]["smoke"]
    performance = smoke["performance"]
    assert smoke["sample_policy"] == {
        "setup_samples": 5,
        "scan_samples": 5,
        "cache_value_samples": None,
        "document_samples": None,
        "exact_control_blocks": None,
        "setup_samples_per_block": None,
        "scan_samples_per_block": None,
        "cache_value_samples_per_block": None,
        "document_samples_per_block": None,
        "warmups": 3,
        "interleaving": "candidate_only",
        "promotable": False,
    }
    assert len(performance["workloads"]) == 9
    assert not any(item["decision_grade"] or item["promotion_gate"] for item in performance["workloads"])
    assert not any(item["id"].startswith("control_") for item in performance["workloads"])
    assert performance["comparisons"] == []
    assert performance["breakeven_models"] == []
    assert smoke["performance_manifest_sha256"] == hash_enron_performance_manifest(performance)


@pytest.mark.parametrize(
    ("result", "noise_floor", "passed"),
    [
        ("regressed", 0.0, False),
        ("equivalent_within_noise", 0.25, True),
        ("equivalent_within_noise", math.nextafter(0.25, math.inf), False),
    ],
)
def test_decision_summary_enforces_directional_regression_and_cross_path_noise_ceiling(
    result: str,
    noise_floor: float,
    passed: bool,
) -> None:
    performance = {
        "workloads": [
            {
                "id": f"setup_{index}",
                "decision_grade": True,
                "peak_rss_bytes": 1,
                "concurrency": 1,
                "phase": "cold_compile",
                "baseline_id": None,
            }
            for index in range(19)
        ],
        "comparisons": [{"result": result, "noise_floor": noise_floor}],
        "inputs": [],
        "breakeven_models": [{"result": "candidate_already_better"}],
    }
    summary = performance_module._decision_grade_summary(
        performance,
        performance_module.PERFORMANCE_DECISION_THRESHOLDS,
        {"cpu_count": 1, "memory_bytes": 1024},
    )

    assert summary == {
        "passed": passed,
        "failure_codes": [] if passed else ["comparison_regression_or_noise"],
    }


def test_software_records_native_engine_version(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        performance_module.importlib,
        "import_module",
        lambda name: SimpleNamespace(__version__="9.8.7") if name == "nerb._engine" else None,
    )
    monkeypatch.setattr(performance_module, "_git_commit", lambda: "1" * 40)
    monkeypatch.setattr(performance_module, "_git_dirty", lambda: False)

    assert performance_module._software() == {
        "package_version": performance_module.__version__,
        "engine_version": "9.8.7",
        "git_commit": "1" * 40,
        "git_dirty": False,
    }


def test_harness_source_fingerprint_includes_contract_and_all_execution_sources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed_names: list[str] = []

    def source_sha256(paths: Sequence[Path]) -> str:
        observed_names.extend(path.name for path in paths)
        return _HASH_1

    monkeypatch.setattr(performance_module, "_source_sha256", source_sha256)
    monkeypatch.setattr(performance_module, "_builder_implementation_sha256", lambda: _HASH_1)
    monkeypatch.setattr(performance_module, "extraction_execution_sha256", lambda: _HASH_2)

    fingerprint = performance_module._performance_harness_source_sha256()

    assert observed_names == [
        "enron_performance.py",
        "enron_contract.py",
        "enron_performance_worker.py",
        "enron_performance_fixtures.py",
    ]
    assert performance_module._SHA256_RE.fullmatch(fingerprint) is not None


def test_plan_reports_aliases_separately_from_matcher_patterns(performance_plan: dict[str, Any]) -> None:
    banks = {item["id"]: item for item in performance_plan["profiles"]["decision"]["performance"]["banks"]}
    assert banks["evaluated_bank"]["active_aliases"] == 127
    assert banks["evaluated_bank"]["active_patterns"] == 628
    for active_patterns in PERFORMANCE_SCALE_PATTERNS:
        bank = banks[f"scale_{active_patterns}"]
        assert bank["active_patterns"] == active_patterns
        assert bank["active_aliases"] == active_patterns // 5
        assert bank["active_aliases"] != bank["active_patterns"]
        taxonomy = bank["composition"]["taxonomy"]
        assert sum(item["literal_patterns"] + item["regex_patterns"] for item in taxonomy) == active_patterns
        assert sum(item["aliases"] for item in taxonomy) == bank["active_aliases"]


@pytest.mark.parametrize(
    ("sample_count", "expected"),
    [
        (1, ("candidate", "control")),
        (2, ("candidate", "control", "control", "candidate")),
        (
            5,
            (
                "candidate",
                "control",
                "control",
                "candidate",
                "candidate",
                "control",
                "control",
                "candidate",
                "candidate",
                "control",
            ),
        ),
    ],
)
def test_exact_controls_use_balanced_abba_order(sample_count: int, expected: tuple[str, ...]) -> None:
    assert performance_module._interleaved_labels(sample_count) == expected


def test_exact_block_assignment_is_frozen_balanced_and_drives_abba_baab() -> None:
    assignment = performance_module.PERFORMANCE_EXACT_BLOCK_ASSIGNMENT

    assert len(assignment) == 10
    assert assignment.count("candidate_first") == 5
    assert assignment.count("control_first") == 5
    for block_index, first in enumerate(assignment):
        expected = (
            ("candidate", "control", "control", "candidate")
            if first == "candidate_first"
            else ("control", "candidate", "candidate", "control")
        )
        assert performance_module._exact_block_labels(block_index, 2) == expected


def test_exact_cache_value_schedule_balances_paths_inside_each_swap_block() -> None:
    paths = performance_module.PERFORMANCE_EXACT_VALUE_PATHS
    for block_index in range(10):
        schedule = performance_module._exact_value_block_schedule(block_index, 10)
        labels = performance_module._exact_block_labels(block_index, 10)
        rounds = tuple(tuple(schedule[index : index + 4]) for index in range(0, len(schedule), 4))

        assert len(schedule) == 80
        assert all(
            all(identifier.startswith("control_") == (label == "control") for identifier in round_ids)
            for label, round_ids in zip(labels, rounds, strict=True)
        )
        assert all(schedule.count(identifier) == 10 for path in paths for identifier in (path, f"control_{path}"))
        for path in paths:
            positions = [
                position
                for round_ids in rounds
                for position, identifier in enumerate(round_ids)
                if identifier.removeprefix("control_") == path
            ]
            assert sorted(positions) == [0] * 5 + [1] * 5 + [2] * 5 + [3] * 5

    full_schedule = performance_module._exact_value_schedule(10, 10)
    assert len(full_schedule) == 800
    assert all(full_schedule.count(identifier) == 100 for path in paths for identifier in (path, f"control_{path}"))


def test_materialization_recomputes_statistics_comparisons_and_breakeven(
    performance_plan: dict[str, Any],
) -> None:
    performance = performance_plan["profiles"]["decision"]["performance"]
    workload_by_id = {item["id"]: item for item in performance["workloads"]}
    input_by_id = {item["id"]: item for item in performance["inputs"]}
    candidate_plan = workload_by_id["real_direct_throughput"]
    control_plan = workload_by_id["control_real_direct_throughput"]
    candidate_observations = [
        {"elapsed_ns": 1_000_000 + index, "record_count": 0, "peak_rss_bytes": 64 * 1024 * 1024}
        for index in range(1_000)
    ]
    control_observations = [
        {"elapsed_ns": 2_000_000 + index, "record_count": 0, "peak_rss_bytes": 65 * 1024 * 1024}
        for index in range(1_000)
    ]
    candidate = performance_module._materialize_workload(
        candidate_plan,
        candidate_observations,
        input_by_id,
        require_rss=True,
    )
    control = performance_module._materialize_workload(
        control_plan,
        control_observations,
        input_by_id,
        require_rss=True,
    )
    comparison_plan = performance_module._comparison_plan(candidate_plan, control_plan, "p99_seconds")
    comparison = performance_module._materialize_comparison(
        comparison_plan,
        {candidate["id"]: candidate, control["id"]: control},
    )

    assert candidate["stats"]["sample_count"] == 1_000
    assert candidate["stats"]["p99_seconds"] == candidate["samples_seconds"][989]
    assert candidate["peak_rss_bytes"] == 64 * 1024 * 1024
    assert comparison["direction"] == "symmetric"
    assert comparison["result"] == "unstable"

    candidates = {
        identifier: {"id": identifier}
        for identifier in (
            "real_source_profile",
            "real_source_build",
            "real_cold_compile",
            "real_helper_cache_miss",
            "real_direct_throughput",
        )
    }
    breakeven_plan = performance_module._breakeven_plan(
        candidates,
        source_curation_seconds=6.0,
    )
    measured = {
        "real_helper_cache_miss": {"work_per_sample": 1, "stats": {"median_seconds": 1.0}},
        "real_source_build": {"stats": {"median_seconds": 2.0}},
        "real_cold_compile": {"stats": {"median_seconds": 1.0}},
        "real_source_profile": {"stats": {"median_seconds": 1.0}},
        "real_direct_throughput": {"work_per_sample": 1, "stats": {"median_seconds": 0.5}},
    }
    breakeven = performance_module._materialize_breakeven(breakeven_plan, measured)
    assert breakeven["candidate_fixed_value"] == 10.0
    assert breakeven["baseline_fixed_value"] == 9.0
    assert breakeven["candidate_value_per_unit"] == 0.5
    assert breakeven["baseline_value_per_unit"] == 1.0
    assert breakeven["result"] == "finite_breakeven"
    assert breakeven["breakeven_units"] == 2


def _valid_worker_result(request: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": performance_module.RESULT_SCHEMA_VERSION,
        "nonce": request["nonce"],
        "workload_sha256": request["workload_sha256"],
        "pid": 7,
        "status": "ok",
        "error_code": None,
        "elapsed_ns": 123,
        "peak_rss_bytes": 4_096,
        "peak_rss_status": "supported",
        "record_count": 0,
        "correctness_sha256": _HASH_2,
    }


@pytest.mark.parametrize(
    "mutation",
    [
        {"extra_private_text": "SAFE_PRIVATE_FIXTURE_TOKEN"},
        {"nonce": "wrong-nonce"},
        {"status": "error", "error_code": "operation_failed"},
        {"elapsed_ns": 0},
        {"correctness_sha256": "invalid"},
        {"peak_rss_bytes": 0},
        {"peak_rss_status": "unknown"},
    ],
)
def test_worker_result_protocol_rejects_shape_and_binding_changes_without_echoing_payload(
    mutation: dict[str, Any],
) -> None:
    request = {"nonce": "safe-nonce", "workload_sha256": _HASH_1}
    result = {**_valid_worker_result(request), **mutation}
    with pytest.raises(EnronPerformanceError) as error:
        performance_module._decode_worker_result(_canonical(result), request)
    assert "SAFE_PRIVATE_FIXTURE_TOKEN" not in str(error.value)


@pytest.mark.parametrize(
    "payload_mutation",
    [
        lambda payload: payload.replace(
            b'"nonce":"safe-nonce"',
            b'"nonce":"duplicate-safe-value","nonce":"safe-nonce"',
            1,
        ),
        lambda payload: payload.replace(b'"elapsed_ns":123', b'"elapsed_ns":NaN', 1),
    ],
)
def test_worker_result_protocol_rejects_duplicate_keys_and_nonfinite_json(
    payload_mutation: Any,
) -> None:
    request = {"nonce": "safe-nonce", "workload_sha256": _HASH_1}
    payload = payload_mutation(_canonical(_valid_worker_result(request)))
    with pytest.raises(EnronPerformanceError, match="invalid aggregate JSON"):
        performance_module._decode_worker_result(payload, request)


@pytest.mark.parametrize(
    ("peak_rss_bytes", "peak_rss_status"),
    [(None, "supported"), (4_096, "unsupported_platform"), (4_096, "resource_unavailable")],
)
def test_worker_result_protocol_rejects_inconsistent_rss_support(
    peak_rss_bytes: int | None,
    peak_rss_status: str,
) -> None:
    request = {"nonce": "safe-nonce", "workload_sha256": _HASH_1}
    result = {
        **_valid_worker_result(request),
        "peak_rss_bytes": peak_rss_bytes,
        "peak_rss_status": peak_rss_status,
    }
    with pytest.raises(EnronPerformanceError, match="RSS"):
        performance_module._decode_worker_result(_canonical(result), request)


def test_unsupported_rss_is_nonpromotable_but_valid_for_smoke(performance_plan: dict[str, Any]) -> None:
    performance = performance_plan["profiles"]["smoke"]["performance"]
    workload = next(item for item in performance["workloads"] if item["id"] == "real_direct_throughput")
    inputs = {item["id"]: item for item in performance["inputs"]}
    observations = [{"elapsed_ns": 1_000_000, "record_count": 0, "peak_rss_bytes": None} for _ in range(5)]

    materialized = performance_module._materialize_workload(workload, observations, inputs, require_rss=False)
    assert materialized["rss_samples_bytes"] == []
    assert materialized["peak_rss_bytes"] is None
    with pytest.raises(EnronPerformanceError, match="RSS"):
        performance_module._materialize_workload(workload, observations, inputs, require_rss=True)


def test_source_build_worker_never_echoes_exception_text_or_invalid_correlation_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        performance_module,
        "build_enron_intelligence_bank",
        lambda _options: (_ for _ in ()).throw(RuntimeError("SAFE_PRIVATE_FIXTURE_TOKEN")),
    )
    monkeypatch.setattr(performance_module, "_source_build_peak_rss", lambda: (None, "resource_unavailable"))
    monkeypatch.setattr(
        performance_module,
        "_source_build_input_boundary",
        lambda _request: performance_module.contextlib.nullcontext(
            performance_module._SourceBuildInputSnapshot(
                root=tmp_path,
                development_run=tmp_path,
                annotation_run=None,
                cmu_catalog_bindings=None,
            )
        ),
    )
    monkeypatch.setattr(performance_module.tempfile, "gettempdir", lambda: str(tmp_path))
    temporary_root = tmp_path / "nerb-performance-build-test"
    temporary_root.mkdir()
    request: dict[str, Any] = {
        "schema_version": "nerb.enron_performance_source_build_request.v1",
        "nonce": "safe-nonce",
        "workload_sha256": _HASH_1,
        "development_run": str(tmp_path.resolve()),
        "annotation_run": None,
        "cmu_catalog_bindings": None,
        "source_identities": {
            "development_tree": {
                ".": {
                    "kind": "directory",
                    "device": 1,
                    "inode": 1,
                    "mode": 0o700,
                    "link_count": 1,
                    "size": 0,
                    "modified_ns": 1,
                    "changed_ns": 1,
                },
                "manifest.json": {
                    "kind": "file",
                    "device": 1,
                    "inode": 2,
                    "mode": 0o600,
                    "link_count": 1,
                    "size": 0,
                    "modified_ns": 1,
                    "changed_ns": 1,
                },
                "train.jsonl": {
                    "kind": "file",
                    "device": 1,
                    "inode": 3,
                    "mode": 0o600,
                    "link_count": 1,
                    "size": 0,
                    "modified_ns": 1,
                    "changed_ns": 1,
                },
            },
            "development_manifest": {
                "kind": "file",
                "device": 1,
                "inode": 2,
                "mode": 0o600,
                "link_count": 1,
                "size": 0,
                "modified_ns": 1,
                "changed_ns": 1,
            },
            "profile_source": {
                "kind": "file",
                "device": 1,
                "inode": 3,
                "mode": 0o600,
                "link_count": 1,
                "size": 0,
                "modified_ns": 1,
                "changed_ns": 1,
            },
            "annotation_tree": None,
            "bank_build_tree": None,
            "cmu_catalog_bindings": None,
        },
        "benchmark_version": "safe-v2",
        "created_at": "2026-07-11T00:00:00Z",
        "expected_projection_sha256": _HASH_2,
        "output_dir": str((temporary_root / "build").resolve()),
    }
    failed = performance_module._source_build_worker_result(_canonical(request))
    serialized = _canonical(failed).decode("ascii")
    assert failed["error_code"] == "operation_failed"
    assert "SAFE_PRIVATE_FIXTURE_TOKEN" not in serialized
    assert str(tmp_path) not in serialized

    request["nonce"] = "synthetic.person@example.invalid"
    rejected = performance_module._source_build_worker_result(_canonical(request))
    assert rejected["status"] == "error"
    assert rejected["error_code"] == "request_shape"
    assert rejected["nonce"] is None
    assert "@" not in _canonical(rejected).decode("ascii")

    request["nonce"] = "safe-nonce"
    for field in ("development_run", "benchmark_version", "created_at", "output_dir"):
        original = request[field]
        request[field] = 1
        malformed = performance_module._source_build_worker_result(_canonical(request))
        assert malformed["status"] == "error"
        assert malformed["error_code"] == "request_shape"
        assert "@" not in _canonical(malformed).decode("ascii")
        request[field] = original


def test_source_build_worker_rejects_development_root_substitution_before_builder_use(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    development = tmp_path / "development"
    development.mkdir(mode=0o700)
    development.chmod(0o700)
    for name, payload in (("manifest.json", b"{}\n"), ("train.jsonl", b'{"safe":true}\n')):
        (development / name).write_bytes(payload)
        (development / name).chmod(0o600)
    _root, tree = performance_module._snapshot_performance_private_tree(
        development,
        description="Test development run",
    )
    tree_payload = performance_module._private_tree_payload(tree)
    identities = {
        "development_tree": tree_payload,
        "development_manifest": tree_payload["manifest.json"],
        "profile_source": tree_payload["train.jsonl"],
        "annotation_tree": None,
        "bank_build_tree": None,
        "cmu_catalog_bindings": None,
    }
    original = tmp_path / "development-original"
    development.rename(original)
    development.mkdir(mode=0o700)
    development.chmod(0o700)
    for name in ("manifest.json", "train.jsonl"):
        (development / name).write_bytes((original / name).read_bytes())
        (development / name).chmod(0o600)
    temporary_root = tmp_path / "nerb-performance-build-substitution"
    temporary_root.mkdir()
    monkeypatch.setattr(performance_module.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(
        performance_module,
        "build_enron_intelligence_bank",
        lambda _options: pytest.fail("builder consumed a substituted development root"),
    )
    request = {
        "schema_version": "nerb.enron_performance_source_build_request.v1",
        "nonce": "safe-nonce",
        "workload_sha256": _HASH_1,
        "development_run": str(development.resolve()),
        "annotation_run": None,
        "cmu_catalog_bindings": None,
        "source_identities": identities,
        "benchmark_version": "safe-v2",
        "created_at": "2026-07-11T00:00:00Z",
        "expected_projection_sha256": _HASH_2,
        "output_dir": str((temporary_root / "build").resolve()),
    }

    failed = performance_module._source_build_worker_result(_canonical(request))

    assert failed["status"] == "error"
    assert failed["error_code"] == "source_identity_changed"


def test_source_build_worker_uses_complete_immutable_snapshot_during_source_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    development = tmp_path / "development-race"
    development.mkdir(mode=0o700)
    development.chmod(0o700)
    payloads = {
        "COMMITTED": b"nerb.enron.private-run.v2\n",
        "manifest.json": b"{}\n",
        "train.jsonl": b'{"source":"train-safe"}\n',
        "validation.jsonl": b'{"source":"validation-safe"}\n',
        "memberships.jsonl": b'{"source":"memberships-safe"}\n',
        "samples.jsonl": b'{"source":"samples-safe"}\n',
        "split-freeze-receipt.json": b"{}\n",
    }
    for name, payload in payloads.items():
        (development / name).write_bytes(payload)
        (development / name).chmod(0o600)
    (development / "empty-support").mkdir(mode=0o700)
    _root, tree = performance_module._snapshot_performance_private_tree(
        development,
        description="Test development race run",
    )
    tree_payload = performance_module._private_tree_payload(tree)
    identities = {
        "development_tree": tree_payload,
        "development_manifest": tree_payload["manifest.json"],
        "profile_source": tree_payload["train.jsonl"],
        "annotation_tree": None,
        "bank_build_tree": None,
        "cmu_catalog_bindings": None,
    }
    temporary_root = tmp_path / "nerb-performance-build-race"
    temporary_root.mkdir()
    monkeypatch.setattr(performance_module.tempfile, "gettempdir", lambda: str(tmp_path))
    projection = {"safe": True}
    monkeypatch.setattr(performance_module, "_source_build_projection", lambda _card: projection)
    events: list[str] = []
    real_clock = performance_module.time.perf_counter_ns
    real_copy = performance_module._copy_frozen_private_tree

    def observed_clock() -> int:
        events.append("clock")
        return real_clock()

    def observed_copy(*args: Any, **kwargs: Any) -> tuple[dict[str, tuple[str, int]], set[str]]:
        events.append("snapshot")
        return real_copy(*args, **kwargs)

    monkeypatch.setattr(performance_module.time, "perf_counter_ns", observed_clock)
    monkeypatch.setattr(performance_module, "_copy_frozen_private_tree", observed_copy)

    def race_builder(options: Any) -> dict[str, Any]:
        assert options.development_run != development
        assert options.development_run.parent == temporary_root / "inputs"
        for name in ("validation.jsonl", "memberships.jsonl"):
            replacement = tmp_path / f"replacement-{name}"
            replacement.write_bytes(b'{"source":"substituted-private"}\n')
            replacement.chmod(0o600)
            replacement.replace(development / name)
            assert (options.development_run / name).read_bytes() == payloads[name]
        assert (options.development_run / "samples.jsonl").read_bytes() == payloads["samples.jsonl"]
        assert (options.development_run / "empty-support").is_dir()
        assert not any((options.development_run / "empty-support").iterdir())
        return {"bank": {"stats": {"active_totals": {"patterns": 1}}}}

    monkeypatch.setattr(performance_module, "build_enron_intelligence_bank", race_builder)
    request = {
        "schema_version": "nerb.enron_performance_source_build_request.v1",
        "nonce": "safe-nonce",
        "workload_sha256": _HASH_1,
        "development_run": str(development.resolve()),
        "annotation_run": None,
        "cmu_catalog_bindings": None,
        "source_identities": identities,
        "benchmark_version": "safe-v2",
        "created_at": "2026-07-11T00:00:00Z",
        "expected_projection_sha256": performance_module._canonical_hash(projection),
        "output_dir": str((temporary_root / "build").resolve()),
    }

    result = performance_module._source_build_worker_result(_canonical(request))

    assert result["status"] == "ok"
    assert result["error_code"] is None
    assert result["elapsed_ns"] > 0
    assert events.index("clock") < events.index("snapshot")


def test_source_build_parent_removes_private_temp_tree_after_forced_child_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(performance_module.tempfile, "tempdir", str(tmp_path))
    temporary_roots: list[Path] = []

    def fail_after_private_write(
        _command: Sequence[str],
        request: Mapping[str, Any],
        **_kwargs: Any,
    ) -> tuple[bytes, int]:
        output_dir = Path(str(request["output_dir"]))
        output_dir.mkdir(parents=True)
        (output_dir / "private-artifact.json").write_text("private fixture", encoding="utf-8")
        temporary_roots.append(output_dir.parent)
        raise EnronPerformanceError("Source-build performance worker exceeded its fixed boundary.")

    monkeypatch.setattr(performance_module, "_run_bounded_fresh_process", fail_after_private_write)
    with pytest.raises(EnronPerformanceError, match="fixed boundary"):
        performance_module._run_source_build_once(
            {"nonce": "safe-nonce", "workload_sha256": _HASH_1},
            timeout_seconds=0.1,
        )

    assert len(temporary_roots) == 1
    assert not temporary_roots[0].exists()


def test_source_build_parent_resolves_symlinked_system_temp_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_temporary_root = tmp_path / "real-temporary-root"
    real_temporary_root.mkdir()
    alternate_temporary_root = tmp_path / "alternate-temporary-root"
    alternate_temporary_root.mkdir()
    symlinked_temporary_root = tmp_path / "symlinked-temporary-root"
    try:
        symlinked_temporary_root.symlink_to(real_temporary_root, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")
    monkeypatch.setattr(performance_module.tempfile, "tempdir", str(symlinked_temporary_root))
    observed_output_dirs: list[Path] = []

    def capture_resolved_output(
        _command: Sequence[str],
        request: Mapping[str, Any],
        **_kwargs: Any,
    ) -> tuple[bytes, int]:
        output_dir = Path(str(request["output_dir"]))
        output_dir.mkdir()
        (output_dir / "private-artifact.json").write_text("private fixture", encoding="utf-8")
        observed_output_dirs.append(output_dir)
        symlinked_temporary_root.unlink()
        symlinked_temporary_root.symlink_to(alternate_temporary_root, target_is_directory=True)
        raise EnronPerformanceError("Source-build performance worker exited unsuccessfully.")

    monkeypatch.setattr(performance_module, "_run_bounded_fresh_process", capture_resolved_output)
    with pytest.raises(EnronPerformanceError, match="exited unsuccessfully"):
        performance_module._run_source_build_once(
            {"nonce": "safe-nonce", "workload_sha256": _HASH_1},
            timeout_seconds=0.1,
        )

    assert len(observed_output_dirs) == 1
    assert observed_output_dirs[0].parent.parent == real_temporary_root.resolve()
    assert not observed_output_dirs[0].parent.exists()
    assert not any(alternate_temporary_root.iterdir())


def test_evaluated_descriptor_keeps_real_catalog_aliases_truthful(test_data_path: Path) -> None:
    bank = json.loads((test_data_path / "enron_bank_fake.json").read_text(encoding="utf-8"))
    payload = _canonical(bank)
    artifact = performance_module._artifact_from_bytes("evaluated_bank_artifact", "banks/evaluated.json", payload)
    descriptor = performance_module._evaluated_bank_descriptor(bank, artifact, native_source_bytes=321)
    taxonomy = {item["entity_class"]: item for item in descriptor["composition"]["taxonomy"]}

    assert descriptor["active_patterns"] == 3
    assert descriptor["active_aliases"] == 1
    assert descriptor["active_aliases"] != descriptor["active_patterns"]
    assert taxonomy["contact"]["canonical_names"] == 2
    assert taxonomy["contact"]["aliases"] == 0
    assert taxonomy["person"]["canonical_names"] == 0
    assert taxonomy["person"]["aliases"] == 1
    assert descriptor["descriptor_sha256"] == hash_enron_performance_bank(descriptor)


def _prepare_run(
    tmp_path: Path,
    test_data_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    name: str,
    real_fixtures: bool = False,
    snapshot_bank_payload: bytes | None = None,
) -> Path:
    bank_run = tmp_path / f"{name}-bank-build"
    bank_run.mkdir()
    bank = json.loads((test_data_path / "enron_bank_fake.json").read_text(encoding="utf-8"))
    bank_payload = _canonical(bank)
    development_run = tmp_path / f"{name}-development"
    development_run.mkdir(mode=0o700)
    development_run.chmod(0o700)
    train_payload = b'{"safe":"train"}\n'
    (development_run / "train.jsonl").write_bytes(train_payload)
    (development_run / "train.jsonl").chmod(0o600)
    development_manifest_payload = b'{"safe":"development-manifest"}\n'
    (development_run / "manifest.json").write_bytes(development_manifest_payload)
    (development_run / "manifest.json").chmod(0o600)
    development_manifest_sha256 = _sha256(development_manifest_payload)
    stats = bank_stats(bank)
    card = {
        "benchmark_version": "safe-benchmark-v2",
        "fixture_mode": False,
        "promotable": False,
        "run_sha256": _HASH_1,
        "source": {
            "development_manifest_sha256": development_manifest_sha256,
            "train_artifact_sha256": _sha256(train_payload),
            "train_records": 1,
            "sealed_test_accessed": False,
        },
        "builder": {
            "candidate_source_sha256": _HASH_1,
            "candidate_ledger_sha256": _HASH_2,
            "source_sha256": performance_module._builder_implementation_sha256(),
            "policy_sha256": performance_module.EnronBankPolicy().sha256,
        },
        "bank": {
            "artifact_sha256": _sha256(bank_payload),
            "artifact_bytes": len(bank_payload),
            "canonical_sha256": hash_bank(bank),
            "canonical_json_bytes": len(_canonical(canonicalize_bank(bank))),
            "stats": stats,
        },
        "iterations": [
            {
                "id": "selected-safe",
                "selected": True,
                "active_patterns": stats["active_totals"]["patterns"],
            }
        ],
        "catalog_conformance": {
            "active_patterns": stats["active_totals"]["patterns"],
            "approved_positive_cases": 3,
            "correctly_mapped": 3,
            "missed": 0,
            "wrong_canonical": 0,
            "negative_cases": 1,
            "unexpected_negative_matches": 0,
            "passed": True,
        },
        "privacy": {"status": "passed"},
    }
    validation_documents = tuple(
        {"document_id": f"doc_{index:03d}", "text": f"safe validation text {index}"} for index in range(100)
    )
    development = SimpleNamespace(
        manifest={
            "development_roles": {
                "train": {
                    "records": 1,
                    "artifact": {
                        "id": "development_train",
                        "sha256": _sha256(train_payload),
                        "bytes": len(train_payload),
                    },
                }
            }
        },
        manifest_sha256=development_manifest_sha256,
        iter_validation_records=lambda: iter(validation_documents),
        iter_validation_memberships=lambda: iter(
            {"document_id": row["document_id"], "role": "validation"} for row in validation_documents
        ),
    )

    class _SafeNativeBank:
        def scan_bytes(self, document: bytes) -> list[Any]:
            if real_fixtures:
                return []
            document_index = int(document.rsplit(b" ", 1)[-1])
            return [document_index] * (1 + document_index % 3)

    verification = {
        "valid": True,
        "benchmark_version": card["benchmark_version"],
        "fixture_mode": card["fixture_mode"],
        "promotable": card["promotable"],
        "bank_sha256": card["bank"]["canonical_sha256"],
        "bank_card_run_sha256": card.get("run_sha256"),
        "sealed_test_accessed": card["source"]["sealed_test_accessed"],
        "privacy": card["privacy"],
    }
    bank_snapshot = SimpleNamespace(
        summary=verification,
        card=card,
        bank=bank,
        bank_payload=bank_payload if snapshot_bank_payload is None else snapshot_bank_payload,
        validation_plan=SimpleNamespace(),
        policy=performance_module.EnronBankPolicy(),
        build_created_at="2026-07-11T00:00:00Z",
    )
    verification_calls: list[dict[str, Any]] = []

    def verify_snapshot(*_args: Any, **kwargs: Any) -> Any:
        verification_calls.append(kwargs)
        return bank_snapshot

    monkeypatch.setattr(
        performance_module,
        "_verify_enron_bank_build_snapshot",
        verify_snapshot,
    )
    monkeypatch.setattr(performance_module, "load_enron_development_split", lambda _path: development)
    monkeypatch.setattr(
        performance_module,
        "_iter_validation_documents",
        lambda *_args, **_kwargs: iter(validation_documents),
    )
    monkeypatch.setattr(
        performance_module,
        "compile_bank_with_report",
        lambda _bank: (
            SimpleNamespace(native_bank=_SafeNativeBank()),
            False,
            {"source": {"extractable_json_bytes": 321}},
        ),
    )
    if real_fixtures:
        # This test exercises real artifact requests and worker isolation, not
        # scale-topology extrapolation. The tiny committed fixture has one
        # residual regex among only three active patterns; scaling that ratio
        # would create tens of thousands of regex-heavy native shards and is
        # intentionally rejected by the production resource envelope. Use the
        # representative 628-pattern composition covered exhaustively by the
        # fixture-generator tests while keeping the real generators here.
        make_real_bank_fixtures = performance_module.make_enron_performance_bank_fixtures
        representative = _evaluated_descriptor()
        monkeypatch.setattr(
            performance_module,
            "make_enron_performance_bank_fixtures",
            lambda *, evaluated_bank: make_real_bank_fixtures(evaluated_bank=representative),
        )
    else:
        bank_fixtures = _fake_bank_fixtures()
        monkeypatch.setattr(
            performance_module,
            "make_enron_performance_bank_fixtures",
            lambda *, evaluated_bank: bank_fixtures,
        )
        monkeypatch.setattr(
            performance_module,
            "make_enron_performance_input_fixtures",
            lambda fixtures: _fake_input_fixtures(fixtures),
        )
    monkeypatch.setattr(performance_module, "_source_sha256", lambda _paths: _HASH_1)
    output = tmp_path / f"{name}-prepared-output"
    scratch_root = tmp_path / f"{name}-scratch"
    scratch_root.mkdir(mode=0o700)
    summary = prepare_enron_performance_manifest(
        EnronPerformancePrepareOptions(
            bank_build_run=bank_run,
            development_run=development_run,
            output_dir=output,
            scratch_root=scratch_root,
            concurrency=2,
            allow_unignored_output=True,
        )
    )
    assert summary["committed"] is True
    assert summary["banks"] == 5
    assert summary["inputs"] == 11
    assert summary["decision_workloads"] == 42
    assert summary["sealed_test_accessed"] is False
    assert verification_calls == [
        {
            "development_run": development_run,
            "scratch_root": scratch_root,
            "annotation_run": None,
            "max_scratch_bytes": performance_module.DEFAULT_MAX_ENRON_BANK_VERIFY_SCRATCH_BYTES,
        }
    ]
    return output


def test_prepare_rejects_snapshot_bank_bytes_that_do_not_match_verified_card(
    tmp_path: Path,
    test_data_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(EnronPerformanceError, match="differs from its verified bank card"):
        _prepare_run(
            tmp_path,
            test_data_path,
            monkeypatch,
            name="mismatched-snapshot-bank",
            snapshot_bank_payload=b"{}",
        )

    assert not (tmp_path / "mismatched-snapshot-bank-prepared-output").exists()


def test_source_build_complete_request_budget_accepts_exact_limit_and_rejects_one_byte_less(
    tmp_path: Path,
    test_data_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared_path = _prepare_run(tmp_path, test_data_path, monkeypatch, name="source-request-budget")
    prepared = performance_module._load_prepared_performance_run(prepared_path)
    workloads = [
        workload
        for profile in performance_module.PERFORMANCE_PROFILE_IDS
        for workload in prepared.plan["profiles"][profile]["performance"]["workloads"]
        if workload["phase"] == "source_build"
    ]
    reserved_sizes = [
        len(
            _canonical(
                {
                    **performance_module._source_build_request_from_bindings(
                        workload,
                        prepared.plan,
                        prepared.locations,
                        nonce="N" * 128,
                    ),
                    "output_dir": performance_module._reserved_source_build_output_path(),
                }
            )
        )
        for workload in workloads
    ]
    exact_limit = max(reserved_sizes)
    monkeypatch.setattr(performance_module, "DEFAULT_MAX_REQUEST_BYTES", exact_limit)
    performance_module._validate_source_build_request_budget(prepared.plan, prepared.locations)

    monkeypatch.setattr(performance_module, "DEFAULT_MAX_REQUEST_BYTES", exact_limit - 1)
    with pytest.raises(EnronPerformanceError, match="complete worker budget"):
        performance_module._validate_source_build_request_budget(prepared.plan, prepared.locations)
    with pytest.raises(EnronPerformanceError, match="complete worker budget"):
        performance_module._load_prepared_performance_run(prepared_path)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("build_created_at", "x" * (performance_module.MAX_BUILD_TIMESTAMP_BYTES + 1)),
        ("development_run", "/" + "x" * performance_module.MAX_PRIVATE_PATH_BYTES),
    ],
)
def test_private_source_location_strings_have_explicit_utf8_bounds(
    field: str,
    value: str,
    tmp_path: Path,
    test_data_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared_path = _prepare_run(tmp_path, test_data_path, monkeypatch, name=f"source-string-bound-{field}")
    prepared = performance_module._load_prepared_performance_run(prepared_path)
    locations = json.loads(json.dumps(prepared.locations))
    locations[field] = value

    with pytest.raises(EnronPerformanceError, match="invalid"):
        performance_module._validate_performance_locations(locations, prepared.plan)


def _aggregate_observations(
    workload: Mapping[str, Any],
    sample_count: int,
    *,
    control: bool = False,
    sequences: Sequence[int] | None = None,
    reused_pid: int | None = None,
    document_record_counts: Sequence[int] | None = None,
    whole_input_record_count: int = 0,
) -> list[dict[str, Any]]:
    base_identifier = str(workload["id"]).removeprefix("control_")
    digest_group = (
        "exact-real-cache-value"
        if base_identifier in performance_module.PERFORMANCE_EXACT_VALUE_PATHS
        else base_identifier
    )
    base_ns = 2_200_000 if control else 2_000_000
    resolved_sequences = list(range(sample_count)) if sequences is None else list(sequences)
    resolved_reused_pid = (
        10_000 + int.from_bytes(hashlib.sha256(str(workload["id"]).encode()).digest()[:4], "big")
        if reused_pid is None
        else reused_pid
    )
    observations: list[dict[str, Any]] = []
    for index, sequence in enumerate(resolved_sequences):
        if document_record_counts is not None:
            document_index = index % len(document_record_counts)
            record_count = int(document_record_counts[document_index])
            digest = _sha256(f"correctness:{digest_group}:document:{document_index}".encode())
        else:
            record_count = whole_input_record_count if workload["sample_unit"] == "whole_input" else 0
            digest = _sha256(f"correctness:{digest_group}".encode())
        observations.append(
            {
                "sequence": sequence,
                "pid": resolved_reused_pid if workload["process_model"] == "reused_process" else 10_000 + sequence,
                "record_count": record_count,
                "correctness_sha256": digest,
                "elapsed_ns": base_ns + index,
                "peak_rss_bytes": 64 * 1024 * 1024,
            }
        )
    return observations


def _patch_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    inventory_records: dict[str, tuple[int, ...]] = {}

    def block_pid(workload: Mapping[str, Any], block_index: int) -> int:
        base = int.from_bytes(hashlib.sha256(str(workload["id"]).encode()).digest()[:6], "big")
        return 1_000_000 + base * 10 + block_index

    def observation_counts(
        workload: Mapping[str, Any],
        performance: Mapping[str, Any],
        prepared: Any,
    ) -> tuple[tuple[int, ...] | None, int]:
        input_id = workload["input_id"]
        if input_id is None:
            return None, 0
        input_descriptor = next(item for item in performance["inputs"] if item["id"] == input_id)
        if workload["sample_unit"] != "document":
            return None, int(input_descriptor["records"])
        inventory_id = str(input_descriptor["inventory_ref"]["id"])
        if inventory_id not in inventory_records:
            payload = performance_module._read_prepared_artifact(
                prepared,
                inventory_id,
                maximum_bytes=int(input_descriptor["inventory_ref"]["bytes"]),
                description="Test performance inventory",
            )
            inventory = json.loads(payload)
            inventory_records[inventory_id] = tuple(int(item["records"]) for item in inventory)
        return inventory_records[inventory_id], int(input_descriptor["records"])

    def aggregate(
        workload: Mapping[str, Any],
        performance: Mapping[str, Any],
        prepared: Any,
        sample_count: int,
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        document_counts, whole_input_count = observation_counts(workload, performance, prepared)
        return _aggregate_observations(
            workload,
            sample_count,
            document_record_counts=document_counts,
            whole_input_record_count=whole_input_count,
            **kwargs,
        )

    def execute_workload(
        workload: Mapping[str, Any],
        performance: Mapping[str, Any],
        prepared: Any,
        *,
        sample_count: int,
        worker_timeout_seconds: float,
        source_build_timeout_seconds: float,
        sequence_start: int,
    ) -> tuple[list[dict[str, Any]], int]:
        assert worker_timeout_seconds > 0
        assert source_build_timeout_seconds > 0
        sequences = list(range(sequence_start, sequence_start + sample_count))
        return aggregate(
            workload,
            performance,
            prepared,
            sample_count,
            sequences=sequences,
        ), sequence_start + sample_count

    def execute_pair(
        candidate: Mapping[str, Any],
        control: Mapping[str, Any],
        performance: Mapping[str, Any],
        prepared: Any,
        *,
        block_count: int,
        samples_per_block: int,
        worker_timeout_seconds: float,
        source_build_timeout_seconds: float,
        sequence_start: int,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
        assert worker_timeout_seconds > 0
        assert source_build_timeout_seconds > 0
        candidate_results: list[dict[str, Any]] = []
        control_results: list[dict[str, Any]] = []
        sequence = sequence_start
        for block_index in range(block_count):
            labels = performance_module._exact_block_labels(block_index, samples_per_block)
            candidate_sequences = [sequence + index for index, label in enumerate(labels) if label == "candidate"]
            control_sequences = [sequence + index for index, label in enumerate(labels) if label == "control"]
            candidate_results.extend(
                aggregate(
                    candidate,
                    performance,
                    prepared,
                    samples_per_block,
                    sequences=candidate_sequences,
                    reused_pid=block_pid(candidate, block_index),
                )
            )
            control_results.extend(
                aggregate(
                    control,
                    performance,
                    prepared,
                    samples_per_block,
                    control=True,
                    sequences=control_sequences,
                    reused_pid=block_pid(control, block_index),
                )
            )
            sequence += samples_per_block * 2
        return candidate_results, control_results, sequence

    def execute_exact_value_block(
        workloads: Mapping[str, Mapping[str, Any]],
        performance: Mapping[str, Any],
        prepared: Any,
        *,
        block_count: int,
        samples_per_block: int,
        worker_timeout_seconds: float,
        source_build_timeout_seconds: float,
        sequence_start: int,
    ) -> tuple[dict[str, list[dict[str, Any]]], int]:
        assert worker_timeout_seconds > 0
        assert source_build_timeout_seconds > 0
        schedule = performance_module._exact_value_schedule(block_count, samples_per_block)
        results = {identifier: [] for identifier in set(schedule)}
        block_width = samples_per_block * 2 * len(performance_module.PERFORMANCE_EXACT_VALUE_PATHS)
        for offset, identifier in enumerate(schedule):
            block_index = offset // block_width
            observation = aggregate(
                workloads[identifier],
                performance,
                prepared,
                1,
                control=identifier.startswith("control_"),
                sequences=[sequence_start + offset],
                reused_pid=block_pid(workloads[identifier], block_index),
            )[0]
            results[identifier].append(observation)
        return results, sequence_start + len(schedule)

    monkeypatch.setattr(performance_module, "_execute_workload", execute_workload)
    monkeypatch.setattr(performance_module, "_execute_pair", execute_pair)
    monkeypatch.setattr(performance_module, "_execute_exact_value_block", execute_exact_value_block)
    monkeypatch.setattr(
        performance_module,
        "_environment",
        lambda: {
            "os": "SyntheticOS",
            "architecture": "safe-arch",
            "python": "3.13.0",
            "cpu_count": 4,
            "cpu_model": "Safe Test CPU",
            "memory_bytes": 16 * 1024**3,
        },
    )
    monkeypatch.setattr(
        performance_module,
        "_software",
        lambda: {
            "package_version": "0.0.0-safe",
            "engine_version": "safe-engine",
            "git_commit": "0" * 40,
            "git_dirty": False,
        },
    )


def test_prepared_and_smoke_runs_commit_verify_and_detect_artifact_tampering(
    tmp_path: Path, test_data_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name="smoke")
    loaded = performance_module._load_prepared_performance_run(prepared)
    assert loaded.plan["plan_sha256"] == loaded.manifest["plan_sha256"]
    assert str(tmp_path) not in json.dumps(loaded.plan, sort_keys=True)
    _patch_execution(monkeypatch)
    output = tmp_path / "smoke-run"
    report = run_enron_performance(
        EnronPerformanceRunOptions(
            prepared_run=prepared,
            output_dir=output,
            profile="smoke",
            allow_unignored_output=True,
        )
    )

    assert report["decision_grade"] == {"passed": False, "failure_codes": ["smoke_profile_nonpromotable"]}
    assert report["privacy"] == {
        "status": "passed",
        "raw_text_included": False,
        "direct_identifiers_included": False,
        "private_paths_included": False,
        "violation_count": 0,
    }
    verified = verify_enron_performance_run(output)
    assert verified["valid"] is True
    assert verified["profile"] == "smoke"
    assert verified["sealed_test_accessed"] is False

    report_path = output / "report.json"
    report_path.write_bytes(report_path.read_bytes() + b" ")
    with pytest.raises(EnronPerformanceError, match="artifact"):
        verify_enron_performance_run(output)


def _mutate_private_bundle(bundle: Path, mutation: str) -> None:
    if mutation == "root_permissions":
        bundle.chmod(0o750)
    elif mutation == "file_permissions":
        (bundle / "manifest.json").chmod(0o640)
    elif mutation == "hard_link":
        os.link(bundle / "manifest.json", bundle.parent / f"{bundle.name}-manifest-link.json")
    elif mutation == "extra_file":
        extra = bundle / "undeclared-private.json"
        extra.write_text("{}\n", encoding="utf-8")
        extra.chmod(0o600)
    else:  # pragma: no cover - test helper guard.
        raise AssertionError(mutation)


def _set_private_bundle_read_only(bundle: Path, *, read_only: bool) -> None:
    files = [path for path in bundle.rglob("*") if path.is_file()]
    directories = [path for path in bundle.rglob("*") if path.is_dir()]
    for path in files:
        path.chmod(0o400 if read_only else 0o600)
    for path in sorted(directories, key=lambda item: len(item.parts), reverse=read_only):
        path.chmod(0o500 if read_only else 0o700)
    bundle.chmod(0o500 if read_only else 0o700)


@pytest.mark.parametrize("mutation", ["root_permissions", "file_permissions", "hard_link", "extra_file"])
def test_prepared_bundle_rejects_unsafe_or_undeclared_tree_entries(
    mutation: str,
    tmp_path: Path,
    test_data_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name=f"prepared-tree-{mutation}")
    _mutate_private_bundle(prepared, mutation)

    with pytest.raises(EnronPerformanceError):
        performance_module._load_prepared_performance_run(prepared)


@pytest.mark.parametrize("mutation", ["root_permissions", "file_permissions", "hard_link", "extra_file"])
def test_measured_bundle_rejects_unsafe_or_undeclared_tree_entries(
    mutation: str,
    tmp_path: Path,
    test_data_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name=f"evidence-tree-{mutation}")
    _patch_execution(monkeypatch)
    output = tmp_path / f"evidence-tree-{mutation}-run"
    run_enron_performance(
        EnronPerformanceRunOptions(
            prepared_run=prepared,
            output_dir=output,
            profile="smoke",
            allow_unignored_output=True,
        )
    )
    _mutate_private_bundle(output, mutation)

    with pytest.raises(EnronPerformanceError):
        verify_enron_performance_run(output)


def test_prepared_and_measured_bundles_accept_owner_read_only_modes(
    tmp_path: Path,
    test_data_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name="read-only-private-bundles")
    _set_private_bundle_read_only(prepared, read_only=True)
    try:
        loaded = performance_module._load_prepared_performance_run(prepared)
        assert loaded.plan["plan_sha256"] == loaded.manifest["plan_sha256"]
    finally:
        _set_private_bundle_read_only(prepared, read_only=False)

    _patch_execution(monkeypatch)
    output = tmp_path / "read-only-private-evidence"
    run_enron_performance(
        EnronPerformanceRunOptions(
            prepared_run=prepared,
            output_dir=output,
            profile="smoke",
            allow_unignored_output=True,
        )
    )
    _set_private_bundle_read_only(output, read_only=True)
    try:
        assert verify_enron_performance_run(output)["valid"] is True
    finally:
        _set_private_bundle_read_only(output, read_only=False)


def test_prepared_bundle_rejects_directory_substitution_during_descriptor_verification(
    tmp_path: Path,
    test_data_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name="prepared-directory-race")
    replacement = tmp_path / "replacement-inputs"
    shutil.copytree(prepared / "inputs", replacement)
    parked = tmp_path / "parked-inputs"
    original = performance_module._fingerprint_performance_private_file
    substituted = False

    def substitute_directory(
        root: Path,
        relative_path: str,
        tree: Mapping[str, Any],
        **kwargs: Any,
    ) -> Any:
        nonlocal substituted
        if relative_path == "inputs/real-validation.raw" and not substituted:
            (prepared / "inputs").rename(parked)
            replacement.rename(prepared / "inputs")
            substituted = True
        return original(root, relative_path, tree, **kwargs)

    monkeypatch.setattr(performance_module, "_fingerprint_performance_private_file", substitute_directory)

    with pytest.raises(EnronPerformanceError):
        performance_module._load_prepared_performance_run(prepared)
    assert substituted is True


def test_measured_bundle_rejects_file_substitution_during_descriptor_read(
    tmp_path: Path,
    test_data_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name="evidence-file-race")
    _patch_execution(monkeypatch)
    output = tmp_path / "evidence-file-race-run"
    run_enron_performance(
        EnronPerformanceRunOptions(
            prepared_run=prepared,
            output_dir=output,
            profile="smoke",
            allow_unignored_output=True,
        )
    )
    report_path = output / "report.json"
    replacement = tmp_path / "replacement-report.json"
    replacement.write_bytes(report_path.read_bytes())
    replacement.chmod(0o600)
    original = performance_module._read_fingerprinted_private_bytes
    substituted = False

    def substitute_file(path: Path, fingerprint: Any, **kwargs: Any) -> bytes:
        nonlocal substituted
        if path == report_path and not substituted:
            replacement.replace(report_path)
            substituted = True
        return original(path, fingerprint, **kwargs)

    monkeypatch.setattr(performance_module, "_read_fingerprinted_private_bytes", substitute_file)

    with pytest.raises(EnronPerformanceError):
        verify_enron_performance_run(output)
    assert substituted is True


def test_privacy_safe_smoke_routes_real_requests_through_worker_subprocesses(
    tmp_path: Path, test_data_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepare_run(
        tmp_path,
        test_data_path,
        monkeypatch,
        name="real-worker-smoke",
        real_fixtures=True,
    )
    output = tmp_path / "real-worker-smoke-run"
    report = run_enron_performance(
        EnronPerformanceRunOptions(
            prepared_run=prepared,
            output_dir=output,
            profile="smoke",
            allow_unignored_output=True,
        )
    )

    assert report["decision_grade"] == {"passed": False, "failure_codes": ["smoke_profile_nonpromotable"]}
    assert verify_enron_performance_run(output)["valid"] is True


def _rewrite_aggregate_report(output: Path, report: dict[str, Any]) -> None:
    report["run_sha256"] = performance_module._canonical_hash(
        {key: value for key, value in report.items() if key != "run_sha256"}
    )
    payload = performance_module._pretty_json_bytes(report)
    (output / "report.json").write_bytes(payload)
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    artifact = next(item for item in manifest["artifacts"] if item["id"] == "performance_report")
    artifact["sha256"] = _sha256(payload)
    artifact["bytes"] = len(payload)
    manifest["run_sha256"] = report["run_sha256"]
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _rewrite_private_audit(output: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    payload = b"".join(_canonical(item) + b"\n" for item in rows)
    (output / "audit" / "results.jsonl").write_bytes(payload)
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    artifact = next(item for item in manifest["artifacts"] if item["id"] == "performance_audit")
    artifact["sha256"] = _sha256(payload)
    artifact["bytes"] = len(payload)
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _rewrite_rehashed_protocol_mutation(bundle: Path, mutation: str) -> None:
    plan_path = bundle / "plan.json"
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    decision = plan["profiles"]["decision"]
    performance = decision["performance"]
    if mutation == "direct_stability_median":
        comparison = next(
            item
            for item in performance["comparisons"]
            if item["candidate_workload_id"] == "real_direct_throughput"
            and item["comparison_kind"] == "same_path_stability"
        )
        comparison["metric"] = "median_seconds"
        comparison["comparison_plan_sha256"] = hash_enron_performance_comparison_plan(comparison)
    elif mutation == "breakeven_proxy_marginal":
        model = performance["breakeven_models"][0]
        component = next(item for item in model["components"] if item["id"] == "candidate_per_request_direct_reuse")
        component["workload_id"] = "real_direct_cache_value"
        model["model_plan_sha256"] = hash_enron_breakeven_plan(model)
    elif mutation == "decision_proxy_role_swap":
        workloads = {item["id"]: item for item in performance["workloads"]}
        workloads["real_direct_cache_value"]["decision_grade"] = True
        workloads["real_helper_cache_hit"]["decision_grade"] = False
        for identifier in ("real_direct_cache_value", "real_helper_cache_hit"):
            workloads[identifier]["workload_sha256"] = hash_enron_workload(workloads[identifier])
    elif mutation == "harness_descriptor_drift":
        for profile in performance_module.PERFORMANCE_PROFILE_IDS:
            profile_performance = plan["profiles"][profile]["performance"]
            harness = next(item for item in profile_performance["harnesses"] if item["id"] == "cold_compile_harness")
            harness.update(
                {
                    "phase": "direct_bank_scan",
                    "command_id": "alternate_safe_runner",
                    "operation_spec_sha256": _HASH_2,
                }
            )
            harness["descriptor_sha256"] = hash_enron_performance_harness(harness)
            for workload in profile_performance["workloads"]:
                if workload["harness_id"] == harness["id"]:
                    workload["harness_sha256"] = harness["descriptor_sha256"]
                    workload["workload_sha256"] = hash_enron_workload(workload)
            plan["profiles"][profile]["performance_manifest_sha256"] = hash_enron_performance_manifest(
                profile_performance
            )
    elif mutation == "duplicate_harness":
        for profile in performance_module.PERFORMANCE_PROFILE_IDS:
            profile_performance = plan["profiles"][profile]["performance"]
            harness = next(item for item in profile_performance["harnesses"] if item["id"] == "cold_compile_harness")
            profile_performance["harnesses"].append(dict(harness))
            profile_performance["harnesses"].sort(key=lambda item: item["id"])
            plan["profiles"][profile]["performance_manifest_sha256"] = hash_enron_performance_manifest(
                profile_performance
            )
    elif mutation == "harness_source_artifact_drift":
        for profile in performance_module.PERFORMANCE_PROFILE_IDS:
            profile_performance = plan["profiles"][profile]["performance"]
            harness = next(item for item in profile_performance["harnesses"] if item["id"] == "source_profile_harness")
            harness["source_artifact"] = _artifact("alternate_train", b"safe-alternate-train")
            harness["descriptor_sha256"] = hash_enron_performance_harness(harness)
            for workload in profile_performance["workloads"]:
                if workload["harness_id"] == harness["id"]:
                    workload["harness_sha256"] = harness["descriptor_sha256"]
                    workload["workload_sha256"] = hash_enron_workload(workload)
            plan["profiles"][profile]["performance_manifest_sha256"] = hash_enron_performance_manifest(
                profile_performance
            )
    elif mutation == "extra_harness":
        for profile in performance_module.PERFORMANCE_PROFILE_IDS:
            profile_performance = plan["profiles"][profile]["performance"]
            harness = dict(
                next(item for item in profile_performance["harnesses"] if item["id"] == "cold_compile_harness")
            )
            harness["id"] = "extra_safe_harness"
            harness["descriptor_sha256"] = hash_enron_performance_harness(harness)
            profile_performance["harnesses"].append(harness)
            profile_performance["harnesses"].sort(key=lambda item: item["id"])
            plan["profiles"][profile]["performance_manifest_sha256"] = hash_enron_performance_manifest(
                profile_performance
            )
    elif mutation == "missing_harness":
        for profile in performance_module.PERFORMANCE_PROFILE_IDS:
            profile_performance = plan["profiles"][profile]["performance"]
            profile_performance["harnesses"] = [
                item for item in profile_performance["harnesses"] if item["id"] != "python_literal_harness"
            ]
            profile_performance["workloads"] = [
                item for item in profile_performance["workloads"] if item["id"] != "explore_python_literal_scan"
            ]
            profile_performance["baselines"] = [
                item
                for item in profile_performance["baselines"]
                if item["id"] != performance_module.PERFORMANCE_PYTHON_LITERAL_BASELINE_ID
            ]
            plan["profiles"][profile]["performance_manifest_sha256"] = hash_enron_performance_manifest(
                profile_performance
            )
    else:  # pragma: no cover - test helper guard.
        raise AssertionError(mutation)
    if mutation not in {
        "duplicate_harness",
        "extra_harness",
        "harness_descriptor_drift",
        "harness_source_artifact_drift",
        "missing_harness",
    }:
        decision["performance_manifest_sha256"] = hash_enron_performance_manifest(performance)
    plan["plan_sha256"] = performance_module._canonical_hash(
        {key: value for key, value in plan.items() if key != "plan_sha256"}
    )
    plan_payload = performance_module._pretty_json_bytes(plan)
    plan_path.write_bytes(plan_payload)

    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["plan_sha256"] = plan["plan_sha256"]
    plan_artifact = next(item for item in manifest["artifacts"] if item["id"] == "performance_plan")
    plan_artifact["sha256"] = _sha256(plan_payload)
    plan_artifact["bytes"] = len(plan_payload)
    manifest_path.write_bytes(performance_module._pretty_json_bytes(manifest))


@pytest.mark.parametrize(
    "mutation",
    [
        "direct_stability_median",
        "breakeven_proxy_marginal",
        "decision_proxy_role_swap",
        "harness_descriptor_drift",
        "duplicate_harness",
        "harness_source_artifact_drift",
        "extra_harness",
        "missing_harness",
    ],
)
def test_rehashed_protocol_mutations_fail_before_measurement_and_in_deep_verification(
    mutation: str,
    tmp_path: Path,
    test_data_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name=f"protocol-{mutation}")
    _patch_execution(monkeypatch)
    measured = tmp_path / f"protocol-{mutation}-measured"
    run_enron_performance(
        EnronPerformanceRunOptions(
            prepared_run=prepared,
            output_dir=measured,
            profile="decision",
            allow_unignored_output=True,
        )
    )
    assert verify_enron_performance_run(measured)["valid"] is True

    _rewrite_rehashed_protocol_mutation(measured, mutation)
    with pytest.raises(EnronPerformanceError, match="frozen protocol"):
        verify_enron_performance_run(measured)

    _rewrite_rehashed_protocol_mutation(prepared, mutation)

    with pytest.raises(EnronPerformanceError, match="frozen protocol"):
        performance_module._load_prepared_performance_run(prepared)

    def fail_measurement(*_args: Any, **_kwargs: Any) -> Any:
        pytest.fail("measurement started before frozen-protocol validation")

    for name in ("_execute_workload", "_execute_pair", "_execute_exact_value_block"):
        monkeypatch.setattr(performance_module, name, fail_measurement)
    with pytest.raises(EnronPerformanceError, match="frozen protocol"):
        run_enron_performance(
            EnronPerformanceRunOptions(
                prepared_run=prepared,
                output_dir=tmp_path / f"protocol-{mutation}-rejected",
                profile="decision",
                allow_unignored_output=True,
            )
        )


def test_run_verifier_rejects_rehashed_free_text_and_forged_smoke_decision(
    tmp_path: Path, test_data_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name="closed-report")
    _patch_execution(monkeypatch)

    extra_output = tmp_path / "extra-report-field"
    extra_report = run_enron_performance(
        EnronPerformanceRunOptions(
            prepared_run=prepared,
            output_dir=extra_output,
            profile="smoke",
            allow_unignored_output=True,
        )
    )
    extra_report["unexpected_unstructured_text"] = "private free-form content"
    _rewrite_aggregate_report(extra_output, extra_report)
    with pytest.raises(EnronPerformanceError, match="closed envelope"):
        verify_enron_performance_run(extra_output)

    decision_output = tmp_path / "forged-smoke-decision"
    decision_report = run_enron_performance(
        EnronPerformanceRunOptions(
            prepared_run=prepared,
            output_dir=decision_output,
            profile="smoke",
            allow_unignored_output=True,
        )
    )
    decision_report["decision_grade"] = {"passed": True, "failure_codes": []}
    _rewrite_aggregate_report(decision_output, decision_report)
    with pytest.raises(EnronPerformanceError, match="decision-grade"):
        verify_enron_performance_run(decision_output)


def test_run_rejects_workload_concurrency_above_execution_host_before_measurement(
    tmp_path: Path, test_data_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name="undersized-host")
    _patch_execution(monkeypatch)
    monkeypatch.setattr(
        performance_module,
        "_environment",
        lambda: {
            "os": "SyntheticOS",
            "architecture": "safe-arch",
            "python": "3.13.0",
            "cpu_count": 1,
            "cpu_model": "Safe Test CPU",
            "memory_bytes": 16 * 1024**3,
        },
    )
    monkeypatch.setattr(
        performance_module,
        "_execute_workload",
        lambda *_args, **_kwargs: pytest.fail("measurement started before the execution-host capacity check"),
    )

    with pytest.raises(EnronPerformanceError, match="current CPU count"):
        run_enron_performance(
            EnronPerformanceRunOptions(
                prepared_run=prepared,
                output_dir=tmp_path / "undersized-host-run",
                profile="smoke",
                allow_unignored_output=True,
            )
        )


def test_run_rejects_changed_contract_source_before_measurement(
    tmp_path: Path, test_data_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name="stale-harness")
    _patch_execution(monkeypatch)

    def changed_contract_source(paths: Sequence[Path]) -> str:
        assert "enron_contract.py" in {path.name for path in paths}
        return _HASH_2

    monkeypatch.setattr(performance_module, "_source_sha256", changed_contract_source)
    monkeypatch.setattr(
        performance_module,
        "_execute_workload",
        lambda *_args, **_kwargs: pytest.fail("measurement started with a stale harness fingerprint"),
    )

    with pytest.raises(EnronPerformanceError, match="harness source differs"):
        run_enron_performance(
            EnronPerformanceRunOptions(
                prepared_run=prepared,
                output_dir=tmp_path / "stale-harness-run",
                profile="smoke",
                allow_unignored_output=True,
            )
        )


def test_run_rejects_execution_source_change_during_measurement(
    tmp_path: Path, test_data_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name="changing-harness")
    frozen = performance_module._load_prepared_performance_run(prepared)
    frozen_source = frozen.plan["profiles"]["smoke"]["performance"]["harnesses"][0]["source_sha256"]
    _patch_execution(monkeypatch)
    fingerprints = iter((frozen_source, _HASH_2))
    monkeypatch.setattr(performance_module, "_performance_harness_source_sha256", lambda: next(fingerprints))

    with pytest.raises(EnronPerformanceError, match="changed during"):
        run_enron_performance(
            EnronPerformanceRunOptions(
                prepared_run=prepared,
                output_dir=tmp_path / "changing-harness-run",
                profile="smoke",
                allow_unignored_output=True,
            )
        )


@pytest.mark.parametrize(
    ("target", "message"),
    [
        ("evaluated", "evaluated status"),
        ("harness", "harness descriptor"),
        ("baseline", "baseline descriptor"),
    ],
)
def test_run_verifier_rejects_rehashed_unbound_descriptor_commitments(
    target: str,
    message: str,
    tmp_path: Path,
    test_data_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name=f"descriptor-{target}")
    _patch_execution(monkeypatch)
    output = tmp_path / f"descriptor-{target}-run"
    report = run_enron_performance(
        EnronPerformanceRunOptions(
            prepared_run=prepared,
            output_dir=output,
            profile="smoke",
            allow_unignored_output=True,
        )
    )
    if target == "evaluated":
        report["performance"]["evaluated"] = False
    elif target == "harness":
        report["performance"]["harnesses"][0]["descriptor_sha256"] = _HASH_1
    else:
        report["performance"]["baselines"][0]["descriptor_sha256"] = _HASH_1
    _rewrite_aggregate_report(output, report)

    with pytest.raises(EnronPerformanceError, match=message):
        verify_enron_performance_run(output)


def test_run_verifier_rejects_rehashed_peak_rss_that_disagrees_with_raw_samples(
    tmp_path: Path, test_data_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name="rss-aggregate")
    _patch_execution(monkeypatch)
    output = tmp_path / "rss-aggregate-run"
    report = run_enron_performance(
        EnronPerformanceRunOptions(
            prepared_run=prepared,
            output_dir=output,
            profile="decision",
            allow_unignored_output=True,
        )
    )
    decision_workload = next(item for item in report["performance"]["workloads"] if item["decision_grade"])
    decision_workload["peak_rss_bytes"] = max(decision_workload["rss_samples_bytes"]) - 1
    _rewrite_aggregate_report(output, report)

    with pytest.raises(EnronPerformanceError, match="RSS aggregation"):
        verify_enron_performance_run(output)


def test_run_verifier_rejects_rehashed_exact_record_denominator(
    tmp_path: Path, test_data_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name="record-denominator")
    _patch_execution(monkeypatch)
    output = tmp_path / "record-denominator-run"
    report = run_enron_performance(
        EnronPerformanceRunOptions(
            prepared_run=prepared,
            output_dir=output,
            profile="smoke",
            allow_unignored_output=True,
        )
    )
    performance = report["performance"]
    workload = next(item for item in performance["workloads"] if item["id"] == "real_direct_throughput")
    input_descriptor = next(item for item in performance["inputs"] if item["id"] == workload["input_id"])
    workload["records_per_sample"] = 1
    workload["stats"] = performance_module.calculate_enron_performance_statistics(
        workload["samples_seconds"],
        input_descriptor,
        phase=workload["phase"],
        sample_unit=workload["sample_unit"],
        work_per_sample=workload["work_per_sample"],
        records_per_sample=1,
    )
    _rewrite_aggregate_report(output, report)

    audit_path = output / "audit" / "results.jsonl"
    rows = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    audit = next(item for item in rows if item["workload_id"] == workload["id"])
    for sample in audit["samples"]:
        sample["record_count"] = 1
    audit_payload = b"".join(_canonical(item) + b"\n" for item in rows)
    audit_path.write_bytes(audit_payload)
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    audit_artifact = next(item for item in manifest["artifacts"] if item["id"] == "performance_audit")
    audit_artifact["sha256"] = _sha256(audit_payload)
    audit_artifact["bytes"] = len(audit_payload)
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(EnronPerformanceError, match="record denominator"):
        verify_enron_performance_run(output)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("cpu_count", 1, "recorded CPU count"),
        ("memory_bytes", 1, "recorded machine memory"),
    ],
)
def test_run_verifier_rejects_rehashed_execution_host_capacity(
    field: str,
    value: int,
    message: str,
    tmp_path: Path,
    test_data_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name=f"host-{field}")
    _patch_execution(monkeypatch)
    output = tmp_path / f"host-{field}-run"
    report = run_enron_performance(
        EnronPerformanceRunOptions(
            prepared_run=prepared,
            output_dir=output,
            profile="smoke",
            allow_unignored_output=True,
        )
    )
    report["environment"][field] = value
    _rewrite_aggregate_report(output, report)

    with pytest.raises(EnronPerformanceError, match=message):
        verify_enron_performance_run(output)


@pytest.mark.parametrize("field", ["suite", "benchmark_version"])
def test_prepared_manifest_identity_is_bound_to_frozen_plan(
    field: str,
    tmp_path: Path,
    test_data_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name=f"prepared-{field}")
    manifest_path = prepared / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest[field] = f"tampered-{field}"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(EnronPerformanceError, match="manifest"):
        performance_module._load_prepared_performance_run(prepared)


@pytest.mark.parametrize(
    ("artifact_id", "kind"),
    [
        ("performance_plan", "private_locations"),
        ("private_locations", "public_plan"),
        ("real_validation_inventory", "aggregate_report"),
    ],
)
def test_prepared_manifest_rejects_artifact_privacy_reclassification(
    artifact_id: str,
    kind: str,
    tmp_path: Path,
    test_data_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name=f"prepared-kind-{artifact_id}")
    manifest_path = prepared / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    artifact = next(item for item in manifest["artifacts"] if item["id"] == artifact_id)
    artifact["kind"] = kind
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(EnronPerformanceError, match="privacy classification"):
        performance_module._load_prepared_performance_run(prepared)


@pytest.mark.parametrize("field", ["suite", "benchmark_version"])
def test_run_manifest_identity_is_bound_to_frozen_report_and_plan(
    field: str,
    tmp_path: Path,
    test_data_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name=f"run-{field}")
    _patch_execution(monkeypatch)
    output = tmp_path / f"run-identity-{field}"
    run_enron_performance(
        EnronPerformanceRunOptions(
            prepared_run=prepared,
            output_dir=output,
            profile="smoke",
            allow_unignored_output=True,
        )
    )
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest[field] = f"tampered-{field}"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(EnronPerformanceError, match="manifest"):
        verify_enron_performance_run(output)


def test_run_manifest_rejects_private_audit_reclassification(
    tmp_path: Path, test_data_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name="run-kind")
    _patch_execution(monkeypatch)
    output = tmp_path / "run-kind-output"
    run_enron_performance(
        EnronPerformanceRunOptions(
            prepared_run=prepared,
            output_dir=output,
            profile="smoke",
            allow_unignored_output=True,
        )
    )
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    audit = next(item for item in manifest["artifacts"] if item["id"] == "performance_audit")
    audit["kind"] = "aggregate_report"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(EnronPerformanceError, match="privacy classification"):
        verify_enron_performance_run(output)


def test_run_verifier_fails_closed_on_content_addressed_malformed_report(
    tmp_path: Path, test_data_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name="malformed-report")
    _patch_execution(monkeypatch)
    output = tmp_path / "malformed-report-run"
    run_enron_performance(
        EnronPerformanceRunOptions(
            prepared_run=prepared,
            output_dir=output,
            profile="smoke",
            allow_unignored_output=True,
        )
    )
    report_path = output / "report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report.pop("performance")
    report_payload = json.dumps(report, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    report_path.write_bytes(report_payload)
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    report_artifact = next(item for item in manifest["artifacts"] if item["id"] == "performance_report")
    report_artifact["sha256"] = _sha256(report_payload)
    report_artifact["bytes"] = len(report_payload)
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(EnronPerformanceError, match="report"):
        verify_enron_performance_run(output)


def test_run_verifier_fails_closed_on_consistently_rebound_malformed_plan(
    tmp_path: Path, test_data_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name="malformed-plan")
    _patch_execution(monkeypatch)
    output = tmp_path / "malformed-plan-run"
    run_enron_performance(
        EnronPerformanceRunOptions(
            prepared_run=prepared,
            output_dir=output,
            profile="smoke",
            allow_unignored_output=True,
        )
    )
    plan_path = output / "plan.json"
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan.pop("profiles")
    plan["plan_sha256"] = performance_module._canonical_hash(
        {key: value for key, value in plan.items() if key != "plan_sha256"}
    )
    plan_payload = json.dumps(plan, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    plan_path.write_bytes(plan_payload)

    report_path = output / "report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["plan_sha256"] = plan["plan_sha256"]
    report["run_sha256"] = performance_module._canonical_hash(
        {key: value for key, value in report.items() if key != "run_sha256"}
    )
    report_payload = json.dumps(report, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    report_path.write_bytes(report_payload)

    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["plan_sha256"] = plan["plan_sha256"]
    manifest["run_sha256"] = report["run_sha256"]
    plan_artifact = next(item for item in manifest["artifacts"] if item["id"] == "performance_plan")
    plan_artifact["sha256"] = _sha256(plan_payload)
    plan_artifact["bytes"] = len(plan_payload)
    report_artifact = next(item for item in manifest["artifacts"] if item["id"] == "performance_report")
    report_artifact["sha256"] = _sha256(report_payload)
    report_artifact["bytes"] = len(report_payload)
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(EnronPerformanceError, match="plan"):
        verify_enron_performance_run(output)


def test_prepared_manifest_rejects_duplicate_json_keys(
    tmp_path: Path, test_data_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name="duplicate-manifest")
    manifest_path = prepared / "manifest.json"
    payload = manifest_path.read_bytes().replace(
        b'"suite":',
        b'"suite":"duplicate-safe-value","suite":',
        1,
    )
    manifest_path.write_bytes(payload)
    with pytest.raises(EnronPerformanceError, match="strict finite JSON"):
        performance_module._load_prepared_performance_run(prepared)


@pytest.mark.parametrize(
    ("wrapper_name", "implementation_name", "public_message"),
    [
        (
            "_load_prepared_performance_run",
            "_load_prepared_performance_run_impl",
            "Performance preparation failed closed structural verification.",
        ),
        (
            "run_enron_performance",
            "_run_enron_performance_impl",
            "Performance run failed closed structural verification.",
        ),
        (
            "verify_enron_performance_run",
            "_verify_enron_performance_run_impl",
            "Performance run failed closed structural verification.",
        ),
    ],
)
def test_structural_failure_sanitization_discards_sensitive_exception_state(
    wrapper_name: str,
    implementation_name: str,
    public_message: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sensitive_token = "SENSITIVE_PRIVATE_PATH_TOKEN"

    def fail_structurally(_value: Any) -> Any:
        raise ValueError(sensitive_token)

    monkeypatch.setattr(performance_module, implementation_name, fail_structurally)
    wrapper = getattr(performance_module, wrapper_name)
    with pytest.raises(EnronPerformanceError) as caught:
        wrapper(cast(Any, None))

    error = caught.value
    rendered = "".join(traceback.format_exception(type(error), error, error.__traceback__))
    assert str(error) == public_message
    assert error.__cause__ is None
    assert error.__context__ is None
    assert sensitive_token not in str(error)
    assert sensitive_token not in rendered


def test_decision_run_verifier_rejects_exact_control_audit_mismatch(
    tmp_path: Path, test_data_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name="decision")
    _patch_execution(monkeypatch)
    output = tmp_path / "decision-run"
    report = run_enron_performance(
        EnronPerformanceRunOptions(
            prepared_run=prepared,
            output_dir=output,
            profile="decision",
            allow_unignored_output=True,
        )
    )
    assert report["profile"] == "decision"
    assert len([item for item in report["performance"]["workloads"] if item["decision_grade"]]) == 19
    support = next(item for item in report["performance"]["workloads"] if item["id"] == "real_direct_cache_value")
    assert support["decision_grade"] is False
    assert support["promotion_gate"] is False
    inventory = json.loads((output / "inventories" / "real_validation_inventory.json").read_text(encoding="utf-8"))
    assert all(item["records"] > 0 for item in inventory)
    positive_rows = [
        json.loads(line) for line in (output / "audit" / "results.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    latency = next(item for item in positive_rows if item["workload_id"] == "real_direct_latency")
    first_block = latency["samples"][: performance_module.DEFAULT_DOCUMENT_SAMPLES_PER_BLOCK]
    assert [item["record_count"] for item in first_block] == [item["records"] for item in inventory]
    assert len({item["correctness_sha256"] for item in first_block}) == len(inventory)
    assert verify_enron_performance_run(output)["valid"] is True

    audit_path = output / "audit" / "results.jsonl"
    rows = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    control = next(item for item in rows if item["workload_id"].startswith("control_"))
    for sample in control["samples"]:
        sample["correctness_sha256"] = _HASH_1
    audit_payload = b"".join(_canonical(item) + b"\n" for item in rows)
    audit_path.write_bytes(audit_payload)
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    audit_artifact = next(item for item in manifest["artifacts"] if item["id"] == "performance_audit")
    audit_artifact["sha256"] = _sha256(audit_payload)
    audit_artifact["bytes"] = len(audit_payload)
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(EnronPerformanceError, match="exact control correctness sequence"):
        verify_enron_performance_run(output)


def _patched_decision_audit(
    tmp_path: Path,
    test_data_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    name: str,
) -> tuple[Path, list[dict[str, Any]]]:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name=name)
    _patch_execution(monkeypatch)
    output = tmp_path / f"{name}-run"
    run_enron_performance(
        EnronPerformanceRunOptions(
            prepared_run=prepared,
            output_dir=output,
            profile="decision",
            allow_unignored_output=True,
        )
    )
    rows = [json.loads(line) for line in (output / "audit" / "results.jsonl").read_text(encoding="utf-8").splitlines()]
    return output, rows


def test_decision_run_verifier_rejects_document_counts_rebound_away_from_inventory(
    tmp_path: Path, test_data_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output, rows = _patched_decision_audit(
        tmp_path,
        test_data_path,
        monkeypatch,
        name="decision-document-counts",
    )
    by_id = {item["workload_id"]: item for item in rows}
    for identifier in ("real_direct_latency", "control_real_direct_latency"):
        by_id[identifier]["samples"][0]["record_count"] += 1
    _rewrite_private_audit(output, rows)

    with pytest.raises(EnronPerformanceError, match="record counts differ from the frozen inventory"):
        verify_enron_performance_run(output)


def test_decision_run_verifier_rejects_one_document_repeated_as_a_full_block(
    tmp_path: Path, test_data_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output, rows = _patched_decision_audit(
        tmp_path,
        test_data_path,
        monkeypatch,
        name="decision-repeated-document",
    )
    by_id = {item["workload_id"]: item for item in rows}
    repeated_commitment = by_id["real_direct_latency"]["samples"][0]["correctness_sha256"]
    for identifier in ("real_direct_latency", "control_real_direct_latency"):
        for sample in by_id[identifier]["samples"]:
            sample["correctness_sha256"] = repeated_commitment
    _rewrite_private_audit(output, rows)

    with pytest.raises(EnronPerformanceError, match="one index-bound commitment per frozen document"):
        verify_enron_performance_run(output)


def test_decision_run_verifier_rejects_reused_cache_value_cross_path_pid_aliasing(
    tmp_path: Path, test_data_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output, rows = _patched_decision_audit(
        tmp_path,
        test_data_path,
        monkeypatch,
        name="decision-cache-value-pid-alias",
    )
    by_id = {item["workload_id"]: item for item in rows}
    direct_samples = by_id["real_direct_cache_value"]["samples"]
    helper_samples = by_id["real_helper_cache_hit"]["samples"]
    for direct, helper in zip(direct_samples, helper_samples, strict=True):
        helper["pid"] = direct["pid"]
    _rewrite_private_audit(output, rows)

    with pytest.raises(EnronPerformanceError, match="cache-value reused-process isolation"):
        verify_enron_performance_run(output)


def test_decision_run_verifier_rejects_rehashed_cross_path_order_swap(
    tmp_path: Path, test_data_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name="decision-order")
    _patch_execution(monkeypatch)
    output = tmp_path / "decision-order-run"
    run_enron_performance(
        EnronPerformanceRunOptions(
            prepared_run=prepared,
            output_dir=output,
            profile="decision",
            allow_unignored_output=True,
        )
    )
    audit_path = output / "audit" / "results.jsonl"
    rows = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    by_id = {item["workload_id"]: item for item in rows}
    direct = by_id["real_direct_cache_value"]["samples"][0]
    helper_hit = by_id["real_helper_cache_hit"]["samples"][0]
    direct["sequence"], helper_hit["sequence"] = helper_hit["sequence"], direct["sequence"]
    audit_payload = b"".join(_canonical(item) + b"\n" for item in rows)
    audit_path.write_bytes(audit_payload)
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    audit_artifact = next(item for item in manifest["artifacts"] if item["id"] == "performance_audit")
    audit_artifact["sha256"] = _sha256(audit_payload)
    audit_artifact["bytes"] = len(audit_payload)
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(EnronPerformanceError, match="cache-value block ordering"):
        verify_enron_performance_run(output)


def test_decision_run_verifier_rejects_nonchronological_workload_samples(
    tmp_path: Path, test_data_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name="decision-sample-order")
    _patch_execution(monkeypatch)
    output = tmp_path / "decision-sample-order-run"
    run_enron_performance(
        EnronPerformanceRunOptions(
            prepared_run=prepared,
            output_dir=output,
            profile="decision",
            allow_unignored_output=True,
        )
    )
    audit_path = output / "audit" / "results.jsonl"
    rows = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    direct = next(item for item in rows if item["workload_id"] == "real_direct_throughput")
    sequences = [sample["sequence"] for sample in direct["samples"]]
    for sample, sequence in zip(direct["samples"], reversed(sequences), strict=True):
        sample["sequence"] = sequence
    audit_payload = b"".join(_canonical(item) + b"\n" for item in rows)
    audit_path.write_bytes(audit_payload)
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    audit_artifact = next(item for item in manifest["artifacts"] if item["id"] == "performance_audit")
    audit_artifact["sha256"] = _sha256(audit_payload)
    audit_artifact["bytes"] = len(audit_payload)
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(EnronPerformanceError, match="not chronological"):
        verify_enron_performance_run(output)


def test_decision_run_verifier_rejects_reused_candidate_control_pid_aliasing(
    tmp_path: Path, test_data_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name="decision-pid-alias")
    _patch_execution(monkeypatch)
    output = tmp_path / "decision-pid-alias-run"
    run_enron_performance(
        EnronPerformanceRunOptions(
            prepared_run=prepared,
            output_dir=output,
            profile="decision",
            allow_unignored_output=True,
        )
    )
    audit_path = output / "audit" / "results.jsonl"
    rows = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    by_id = {item["workload_id"]: item for item in rows}
    candidate_pid = by_id["real_direct_throughput"]["samples"][0]["pid"]
    for sample in by_id["control_real_direct_throughput"]["samples"]:
        sample["pid"] = candidate_pid
    audit_payload = b"".join(_canonical(item) + b"\n" for item in rows)
    audit_path.write_bytes(audit_payload)
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    audit_artifact = next(item for item in manifest["artifacts"] if item["id"] == "performance_audit")
    audit_artifact["sha256"] = _sha256(audit_payload)
    audit_artifact["bytes"] = len(audit_payload)
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(EnronPerformanceError, match="process isolation"):
        verify_enron_performance_run(output)


def test_execute_pair_rejects_correctness_mismatch_before_materialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = {
        "id": "candidate",
        "process_model": "fresh_process_per_sample",
        "sample_unit": "whole_input",
    }
    control = {
        "id": "control_candidate",
        "process_model": "fresh_process_per_sample",
        "sample_unit": "whole_input",
    }
    results = iter(
        (
            {"record_count": 1, "correctness_sha256": _HASH_1},
            {"record_count": 2, "correctness_sha256": _HASH_2},
        )
    )
    monkeypatch.setattr(performance_module, "_run_one_observation", lambda *_args, **_kwargs: next(results))
    monkeypatch.setattr(
        performance_module,
        "_exact_block_labels",
        lambda _block_index, _count: ("candidate", "control"),
    )
    with pytest.raises(EnronPerformanceError, match="differs from its candidate"):
        performance_module._execute_pair(
            candidate,
            control,
            {},
            cast(Any, None),
            block_count=1,
            samples_per_block=1,
            worker_timeout_seconds=1.0,
            source_build_timeout_seconds=1.0,
            sequence_start=0,
        )


def test_execute_pair_uses_fresh_balanced_reused_sessions_per_exact_block(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = {"id": "candidate", "process_model": "reused_process", "sample_unit": "whole_input"}
    control = {"id": "control_candidate", "process_model": "reused_process", "sample_unit": "whole_input"}
    sessions: list[Any] = []

    class _Session:
        def __init__(self, *, timeout_seconds: float) -> None:
            assert timeout_seconds == 1.0
            self.pid = 50_000 + len(sessions)
            self.closed = False
            sessions.append(self)

        def close(self) -> None:
            self.closed = True

    def observe(_workload: Mapping[str, Any], *_args: Any, session: Any = None, **_kwargs: Any) -> dict[str, Any]:
        assert session is not None
        return {
            "pid": session.pid,
            "record_count": 1,
            "correctness_sha256": _HASH_1,
            "elapsed_ns": 1_000_000,
            "peak_rss_bytes": 64 * 1024 * 1024,
        }

    monkeypatch.setattr(performance_module, "_WorkerSession", _Session)
    monkeypatch.setattr(performance_module, "_run_one_observation", observe)
    candidate_results, control_results, next_sequence = performance_module._execute_pair(
        candidate,
        control,
        {},
        cast(Any, None),
        block_count=10,
        samples_per_block=2,
        worker_timeout_seconds=1.0,
        source_build_timeout_seconds=1.0,
        sequence_start=7,
    )

    assert len(sessions) == 20
    assert all(session.closed for session in sessions)
    assert next_sequence == 47
    for block_index, assignment in enumerate(performance_module.PERFORMANCE_EXACT_BLOCK_ASSIGNMENT):
        candidate_pids = {item["pid"] for item in candidate_results[block_index * 2 : (block_index + 1) * 2]}
        control_pids = {item["pid"] for item in control_results[block_index * 2 : (block_index + 1) * 2]}
        assert len(candidate_pids) == len(control_pids) == 1
        candidate_pid = next(iter(candidate_pids))
        control_pid = next(iter(control_pids))
        assert (candidate_pid < control_pid) is (assignment == "candidate_first")


def test_exact_value_block_preserves_reused_and_fresh_process_models(monkeypatch: pytest.MonkeyPatch) -> None:
    reused_paths = {"real_direct_cache_value", "real_helper_cache_hit"}
    workloads: dict[str, dict[str, Any]] = {
        identifier: {
            "id": identifier,
            "process_model": (
                "reused_process" if identifier.removeprefix("control_") in reused_paths else "fresh_process_per_sample"
            ),
        }
        for path in performance_module.PERFORMANCE_EXACT_VALUE_PATHS
        for identifier in (path, f"control_{path}")
    }
    sessions: list[Any] = []
    calls: list[tuple[str, bool]] = []

    class _Session:
        def __init__(self, *, timeout_seconds: float) -> None:
            assert timeout_seconds == 1.0
            self.closed = False
            self.workload_id: str | None = None
            sessions.append(self)

        def close(self) -> None:
            self.closed = True

    def observe(workload: Mapping[str, Any], *_args: Any, session: Any = None, **_kwargs: Any) -> dict[str, Any]:
        expected_reused = workload["process_model"] == "reused_process"
        calls.append((str(workload["id"]), session is not None))
        assert (session is not None) is expected_reused
        if session is not None:
            if session.workload_id is None:
                session.workload_id = str(workload["id"])
            assert session.workload_id == workload["id"]
        return {"record_count": 1, "correctness_sha256": _HASH_1}

    monkeypatch.setattr(performance_module, "_WorkerSession", _Session)
    monkeypatch.setattr(performance_module, "_run_one_observation", observe)
    results, next_sequence = performance_module._execute_exact_value_block(
        workloads,
        {},
        cast(Any, None),
        block_count=10,
        samples_per_block=4,
        worker_timeout_seconds=1.0,
        source_build_timeout_seconds=1.0,
        sequence_start=7,
    )

    assert [identifier for identifier, _reused in calls] == list(performance_module._exact_value_schedule(10, 4))
    assert set(results) == set(workloads)
    assert all(len(items) == 40 for items in results.values())
    assert next_sequence == 327
    reused_path_order = [path for path in performance_module.PERFORMANCE_EXACT_VALUE_PATHS if path in reused_paths]
    sessions_per_block = len(reused_path_order) * 2
    assert len(sessions) == 10 * sessions_per_block
    assert all(session.closed for session in sessions)
    for block_index, assignment in enumerate(performance_module.PERFORMANCE_EXACT_BLOCK_ASSIGNMENT):
        expected_creation_order = [
            identifier
            for path in reused_path_order
            for identifier in (
                (path, f"control_{path}") if assignment == "candidate_first" else (f"control_{path}", path)
            )
        ]
        block_sessions = sessions[block_index * sessions_per_block : (block_index + 1) * sessions_per_block]
        assert [session.workload_id for session in block_sessions] == expected_creation_order


def test_public_privacy_scanner_accepts_plan_and_rejects_private_paths_and_identifiers(
    performance_plan: dict[str, Any], tmp_path: Path
) -> None:
    assert performance_module._public_serialization_diagnostics(performance_plan) == []
    diagnostics = performance_module._public_serialization_diagnostics(
        {
            "private_path": str((tmp_path / "private-corpus.jsonl").resolve()),
            "identifier": "synthetic.person@example.invalid",
        }
    )
    codes = {item["code"] for item in diagnostics}
    assert "contract.public_private_path" in codes
    assert "contract.public_direct_identifier" in codes


@pytest.mark.parametrize(
    "options",
    [
        EnronPerformancePrepareOptions(Path("bank"), Path("dev"), Path("prep"), Path("out"), real_input_documents=99),
        EnronPerformancePrepareOptions(Path("bank"), Path("dev"), Path("prep"), Path("out"), concurrency=1),
        EnronPerformancePrepareOptions(
            Path("bank"),
            Path("dev"),
            Path("prep"),
            Path("out"),
            max_scratch_bytes=performance_module.MIN_ENRON_BANK_VERIFY_SCRATCH_BYTES - 1,
        ),
        EnronPerformancePrepareOptions(
            Path("bank"),
            Path("dev"),
            Path("prep"),
            Path("out"),
            source_curation_seconds=float("nan"),
        ),
    ],
)
def test_prepare_rejects_invalid_options_before_loading_private_runs(options: EnronPerformancePrepareOptions) -> None:
    with pytest.raises(EnronPerformanceError):
        prepare_enron_performance_manifest(options)


@pytest.mark.parametrize(
    "options",
    [
        EnronPerformanceRunOptions(Path("prepared"), Path("out"), profile=cast(Any, "unknown")),
        EnronPerformanceRunOptions(Path("prepared"), Path("out"), smoke_samples=4),
        EnronPerformanceRunOptions(Path("prepared"), Path("out"), worker_timeout_seconds=0),
        EnronPerformanceRunOptions(Path("prepared"), Path("out"), source_build_timeout_seconds=float("inf")),
    ],
)
def test_run_rejects_invalid_options_before_loading_prepared_run(options: EnronPerformanceRunOptions) -> None:
    with pytest.raises(EnronPerformanceError):
        run_enron_performance(options)


def test_orchestrators_reject_non_option_objects() -> None:
    with pytest.raises(EnronPerformanceError, match="preparation options"):
        prepare_enron_performance_manifest(cast(Any, object()))
    with pytest.raises(EnronPerformanceError, match="run options"):
        run_enron_performance(cast(Any, object()))


def test_phase_process_models_are_reflected_in_warmup_policy(performance_plan: dict[str, Any]) -> None:
    workloads = performance_plan["profiles"]["decision"]["performance"]["workloads"]
    candidates = [item for item in workloads if item["decision_grade"]]
    for workload in candidates:
        expected_model = PERFORMANCE_PHASE_PROCESS_MODELS[workload["phase"]]
        assert workload["process_model"] == expected_model
        assert workload["warmups"] == (3 if expected_model == "reused_process" else 0)


def test_real_document_selection_consumes_one_shot_iterable_once() -> None:
    class OneShotRows:
        def __init__(self) -> None:
            self.iterations = 0

        def __iter__(self):
            self.iterations += 1
            if self.iterations != 1:
                raise AssertionError("validation population was iterated more than once")
            for index in range(10_000):
                yield {
                    "document_id": f"doc_{index:064x}",
                    "text": f"bounded validation document {index}",
                }

    rows = OneShotRows()
    selected = performance_module._select_real_documents(rows, count=100, seed="bounded-one-shot")

    assert len(selected) == 100
    assert rows.iterations == 1

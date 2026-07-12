from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest


def _load_gate_report_module():
    module_path = Path(__file__).parents[2] / "scripts" / "rust_engine_gate_report.py"
    spec = importlib.util.spec_from_file_location("rust_engine_gate_report", module_path)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _measurement(*, count: int = 1, seconds: float = 0.01, stable: bool = True) -> dict[str, Any]:
    return {
        "count": count,
        "count_stable": stable,
        "warmup_matches_measured": stable,
        "median_seconds": seconds,
        "min_seconds": seconds,
    }


def _memory_child_payload(*, iterations: int = 1, dense_bytes: int = 128, count: int = 128) -> dict[str, Any]:
    samples = [0.001] * iterations
    return {
        "status": "measured",
        "dense_probe_bytes": dense_bytes,
        "iterations": iterations,
        "all_overlaps_raw": {
            "count": count,
            "counts": [count] * iterations,
            "count_stable": True,
            "warmup_counts": [count],
            "warmup_matches_measured": True,
            "samples_seconds": samples,
            "sample_count": iterations,
            "warmup_iterations": 1,
            "median_seconds": 0.001,
            "min_seconds": 0.001,
        },
        "match_buffer_capacity_after_scan": count,
        "max_rss_kib_process_start": 10_000,
        "max_rss_kib_before_compile": 10_000,
        "max_rss_kib_after_compile": 11_000,
        "max_rss_kib_after_scan": 12_500,
        "max_rss_kib_compile_delta": 1_000,
        "max_rss_kib_scan_delta": 1_500,
        "max_rss_kib_growth": 2_500,
    }


def _expected_mode_metadata() -> dict[str, dict[str, Any]]:
    return {
        "entity_independent": {
            "name": "entity_independent",
            "status": "production_default",
            "production_default": True,
            "internal_only": False,
        },
        "all_overlaps": {
            "name": "all_overlaps",
            "status": "internal_prototype",
            "production_default": False,
            "internal_only": True,
        },
        "global_leftmost": {
            "name": "global_leftmost",
            "status": "internal_benchmark_only",
            "production_default": False,
            "internal_only": True,
        },
    }


def test_rust_engine_gate_report_quick_mode_returns_passing_json_compatible_shape_with_nonbinding_rss():
    gate_report = _load_gate_report_module()

    report = gate_report.gate_report(
        iterations=1,
        target_bytes=10_000,
        dense_bytes=128,
        memory_budget_kib=gate_report.MAX_PROTOCOL_INTEGER,
        memory_absolute_budget_kib=gate_report.MAX_PROTOCOL_INTEGER,
    )

    assert report["overall"]["passed"] is True, json.dumps(report, sort_keys=True)
    assert report["overall"]["correctness_passed"] is True
    assert report["overall"]["timing_eligible"] is False
    assert report["overall"]["timing_status"] == "informational_insufficient_samples"
    assert report["overall"]["timing_passed"] is None
    assert report["overall"]["included_sections"] == {
        "performance": True,
        "memory": True,
        "mode_strategy": True,
    }
    assert report["overall"]["external_required_sections"] == [
        "conformance",
        "distribution",
        "bank_owner_cardinality",
    ]
    assert report["conformance"]["passed"] is None
    assert report["conformance"]["included_in_overall"] is False
    assert report["performance"]["passed"] is True
    assert report["performance"]["correctness_passed"] is True
    assert report["performance"]["timing_eligible"] is False
    assert report["performance"]["timing_passed"] is None
    assert report["mode_strategy"]["passed"] is True
    assert report["mode_strategy"]["correctness_passed"] is True
    assert report["mode_strategy"]["timing_eligible"] is False
    assert report["mode_strategy"]["timing_passed"] is None
    assert report["memory"]["passed"] is True
    assert report["memory"]["memory_budget_kib"] == gate_report.MAX_PROTOCOL_INTEGER
    assert report["memory"]["memory_absolute_budget_kib"] == gate_report.MAX_PROTOCOL_INTEGER
    assert report["distribution"]["passed"] is None
    assert report["distribution"]["included_in_overall"] is False
    assert report["distribution"]["checked_by"] == "make build and GitHub Actions wheel matrix external validation"
    assert "CPython 3.10-3.14 wheels" in report["distribution"]["supported_strategy"]
    assert report["bank_owner_cardinality"]["passed"] is None
    assert report["bank_owner_cardinality"]["included_in_overall"] is False
    assert report["mode_strategy"]["decision"] == "entity_independent remains the production default"
    assert report["mode_strategy"]["dense_probe"]["all_overlaps_reconstructed_matches_entity_independent"] is True
    assert report["mode_strategy"]["entity_cardinality_sweep"]["validated_entity_count_ceiling"] == 1000
    assert report["mode_strategy"]["entity_cardinality_sweep"]["dense_entity_count_ceiling"] == 64
    assert report["mode_strategy"]["entity_cardinality_sweep"]["medium_bank_entity_count"] == 1000
    assert report["mode_strategy"]["entity_cardinality_sweep"]["medium_bank_document_bytes_floor"] == 100_000
    assert report["mode_strategy"]["entity_cardinality_sweep"]["entity_counts"] == [2, 8, 32, 64, 1000]
    assert report["mode_strategy"]["entity_cardinality_sweep"]["routine_entity_counts"] == [2, 64, 1000]
    assert set(report["mode_strategy"]["entity_cardinality_sweep"]["performance"]["criteria"]) == {
        "max_dense_entity_independent_scan_seconds_under_ceiling",
        "dense_entity_independent_scaling_ratio_under_ceiling",
        "routine_max_entity_independent_scan_seconds_under_ceiling",
        "routine_max_to_2_entity_scan_seconds_ratio_under_ceiling",
        "medium_bank_compile_seconds_under_ceiling",
        "medium_bank_raw_scan_seconds_under_ceiling",
        "medium_bank_scan_project_seconds_under_ceiling",
        "medium_bank_scan_project_throughput_floor",
        "medium_bank_to_routine_max_entity_scan_seconds_ratio_under_ceiling",
    }
    assert report["mode_strategy"]["entity_cardinality_sweep"]["timing_eligible"] is False
    assert report["mode_strategy"]["entity_cardinality_sweep"]["timing_passed"] is None
    assert [case["entity_count"] for case in report["mode_strategy"]["entity_cardinality_sweep"]["dense_cases"]] == [
        2,
        8,
        32,
        64,
    ]
    assert [
        case["document_bytes"] for case in report["mode_strategy"]["entity_cardinality_sweep"]["routine_size_cases"]
    ] == [10_000, 10_000]
    assert report["mode_strategy"]["entity_cardinality_sweep"]["medium_bank_baseline_case"]["entity_count"] == 64
    assert report["mode_strategy"]["entity_cardinality_sweep"]["medium_bank_baseline_case"]["document_bytes"] == 100_000
    assert report["mode_strategy"]["entity_cardinality_sweep"]["medium_bank_case"]["entity_count"] == 1000
    assert report["mode_strategy"]["entity_cardinality_sweep"]["medium_bank_case"]["pattern_count"] == 8000
    assert report["mode_strategy"]["entity_cardinality_sweep"]["medium_bank_case"]["document_bytes"] == 100_000
    assert report["mode_strategy"]["entity_cardinality_sweep"]["medium_bank_case"]["passed"] is True
    assert (
        report["mode_strategy"]["entity_cardinality_sweep"]["medium_bank_case"]["workload"]
        == "medium_bank_sparse_no_match"
    )
    assert report["performance"]["literal_heavy"]["native_public_records_equal"] is True
    assert report["performance"]["regex_heavy"]["native_public_records_equal"] is True
    assert report["performance"]["mixed"]["native_public_records_equal"] is True
    assert report["performance"]["corpus_size"]["text_bytes"] == [10_000]
    assert report["performance"]["corpus_size"]["passed"] is True
    assert "source_parse_jsonl" in report["performance"]["small_bank_floor"]["measurements"]
    assert report["performance"]["small_bank_floor"]["criteria"]["native_public_records_equal"] is True
    assert report["performance"]["small_bank_floor"]["timing_eligible"] is False
    assert report["performance"]["small_bank_floor"]["timing_passed"] is None
    scan_measurement = report["performance"]["small_bank_floor"]["measurements"]["rust_entity_independent_scan_project"]
    assert scan_measurement["sample_count"] == 1
    assert scan_measurement["warmup_iterations"] == 1
    assert scan_measurement["samples_seconds"] == [scan_measurement["median_seconds"]]


def test_workload_pass_criteria_fail_on_rust_scan_project_regression():
    gate_report = _load_gate_report_module()

    criteria = gate_report._workload_pass_criteria(
        native_public_records_equal=True,
        text_bytes=100_000,
        rust_native_scan_project=_measurement(seconds=0.02),
        rust_entity_scan=_measurement(seconds=0.001),
        rust_entity_scan_project=_measurement(seconds=0.02),
        rust_all_overlaps_scan=_measurement(),
        rust_global_scan=_measurement(),
        rust_public_cache_lookup={"cache_hit_verified": True},
        thresholds={
            "rust_scan_project_seconds_ceiling": 0.01,
            "rust_raw_scan_seconds_ceiling": 0.01,
            "rust_scan_project_bytes_per_second_floor": 1_000_000.0,
        },
    )

    assert criteria["native_public_records_equal"] is True
    assert criteria["rust_scan_project_under_ceiling"] is False
    assert all(criteria.values()) is False


def test_single_sample_timing_outlier_is_informational_but_correctness_still_gates():
    gate_report = _load_gate_report_module()

    timing_outlier = gate_report._gate_summary(
        {
            "native_public_records_equal": True,
            "cache_hit_verified": True,
            "mode_metadata_expected": True,
        },
        {"rust_scan_project_throughput_floor": False},
        sample_count=1,
    )

    assert timing_outlier["timing_eligible"] is False
    assert timing_outlier["timing_status"] == "informational_insufficient_samples"
    assert timing_outlier["timing_observed_passed"] is False
    assert timing_outlier["timing_passed"] is None
    assert timing_outlier["passed"] is True

    for failed_criterion in (
        "native_public_records_equal",
        "cache_hit_verified",
        "mode_metadata_expected",
    ):
        correctness = {
            "native_public_records_equal": True,
            "cache_hit_verified": True,
            "mode_metadata_expected": True,
        }
        correctness[failed_criterion] = False
        failed = gate_report._gate_summary(correctness, {"timing": True}, sample_count=1)
        assert failed["correctness_passed"] is False
        assert failed["passed"] is False


def test_five_samples_keep_existing_timing_thresholds_hard_gated():
    gate_report = _load_gate_report_module()

    failed = gate_report._gate_summary({"records_equal": True}, {"throughput_floor": False}, sample_count=5)

    assert gate_report.MIN_TIMING_SAMPLES == 5
    assert failed["timing_eligible"] is True
    assert failed["timing_status"] == "failed"
    assert failed["timing_passed"] is False
    assert failed["passed"] is False


def test_measurement_retains_raw_samples_and_median_resists_one_scheduler_outlier():
    gate_report = _load_gate_report_module()
    samples = [0.001_001, 0.001_002, 0.050_123, 0.001_003, 0.001_004]

    measurement = gate_report._measurement(
        samples,
        [7, 7, 7, 7, 7],
        warmup_counts=[7],
        warmup_iterations=1,
    )
    gate = gate_report._gate_summary(
        {"record_count_stable": measurement["count_stable"]},
        {"under_ceiling": measurement["median_seconds"] < 0.002},
        sample_count=measurement["sample_count"],
    )

    assert measurement["samples_seconds"] == samples
    assert measurement["median_seconds"] == 0.001_003
    assert measurement["min_seconds"] == 0.001_001
    assert measurement["sample_count"] == 5
    assert measurement["warmup_iterations"] == 1
    assert gate["timing_eligible"] is True
    assert gate["timing_passed"] is True
    assert gate["passed"] is True


def test_measure_runs_one_untimed_warmup():
    gate_report = _load_gate_report_module()
    calls = 0

    def operation() -> list[int]:
        nonlocal calls
        calls += 1
        return [1]

    measurement = gate_report._measure(operation, iterations=2)

    assert calls == 3
    assert measurement["sample_count"] == 2
    assert measurement["warmup_iterations"] == 1
    assert measurement["warmup_counts"] == [1]
    assert measurement["warmup_matches_measured"] is True


def test_untimed_warmup_result_mismatch_fails_cold_correctness_even_with_stable_counts():
    gate_report = _load_gate_report_module()
    calls = 0

    def operation() -> list[int]:
        nonlocal calls
        calls += 1
        return [0] if calls == 1 else [1]

    measurement = gate_report._measure(operation, iterations=1)
    gate = gate_report._gate_summary(
        {
            "record_count_stable": measurement["count_stable"],
            "warmup_matches_measured": measurement["warmup_matches_measured"],
        },
        {"timing": True},
        sample_count=measurement["sample_count"],
    )

    assert measurement["count_stable"] is True
    assert measurement["warmup_matches_measured"] is False
    assert gate["timing_eligible"] is False
    assert gate["correctness_passed"] is False
    assert gate["passed"] is False


def test_mode_pass_criteria_fail_on_reconstruction_tuple_mismatch():
    gate_report = _load_gate_report_module()

    criteria = gate_report._mode_pass_criteria(
        entity=_measurement(count=4),
        raw=_measurement(count=8),
        reconstructed=_measurement(count=4),
        global_leftmost=_measurement(count=2),
        entity_tuples=[(0, 0, 4), (1, 0, 4)],
        reconstructed_tuples=[(0, 0, 4), (1, 4, 8)],
        metadata=_expected_mode_metadata(),
    )

    assert criteria["all_overlaps_reconstructs_exact_default_tuples"] is False
    assert all(criteria.values()) is False


def test_entity_cardinality_sweep_fails_when_routine_case_fails(monkeypatch):
    gate_report = _load_gate_report_module()

    def dense_case(entity_count: int, _iterations: int) -> dict[str, Any]:
        return {
            "entity_count": entity_count,
            "correctness_passed": True,
            "passed": True,
            "entity_independent": _measurement(seconds=0.001),
        }

    def routine_case(entity_count: int, _iterations: int, target_bytes: int) -> dict[str, Any]:
        return {
            "entity_count": entity_count,
            "document_bytes": target_bytes,
            "correctness_passed": entity_count != 64,
            "passed": entity_count != 64,
            "entity_independent": _measurement(seconds=0.001),
        }

    def medium_bank_case(entity_count: int, _iterations: int, target_bytes: int) -> dict[str, Any]:
        return {
            "entity_count": entity_count,
            "document_bytes": target_bytes,
            "correctness_passed": True,
            "passed": True,
            "rust_entity_independent_compile": _measurement(seconds=0.001),
            "entity_independent": _measurement(seconds=0.001),
            "entity_independent_scan_project": _measurement(seconds=0.001),
            "rust_scan_project_bytes_per_second": 10_000_000.0,
            "criteria": {
                "compile_seconds_under_ceiling": True,
                "rust_raw_scan_seconds_under_ceiling": True,
                "rust_scan_project_seconds_under_ceiling": True,
                "rust_scan_project_throughput_floor": True,
            },
        }

    monkeypatch.setattr(gate_report, "_entity_cardinality_case", dense_case)
    monkeypatch.setattr(gate_report, "_entity_cardinality_routine_case", routine_case)
    monkeypatch.setattr(gate_report, "_medium_bank_cardinality_case", medium_bank_case)

    sweep = gate_report._entity_cardinality_sweep(iterations=1, target_bytes=10_000)

    assert sweep["routine_size_cases"][-1]["passed"] is False
    assert sweep["passed"] is False


def test_memory_report_from_child_fails_when_isolated_probe_exceeds_budget():
    gate_report = _load_gate_report_module()

    report = gate_report._memory_report_from_child(
        _memory_child_payload(),
        memory_budget_kib=2_000,
    )

    assert report["passed"] is False
    assert report["criteria"]["max_rss_growth_within_budget"] is False


def test_memory_child_failure_does_not_embed_subprocess_output(monkeypatch):
    gate_report = _load_gate_report_module()
    secret = "private-child-diagnostic"

    def failed_run(*_args, **kwargs):
        kwargs["stdout"].write(secret.encode("utf-8"))
        kwargs["stderr"].write(secret.encode("utf-8"))
        return subprocess.CompletedProcess(args=["memory-child"], returncode=2)

    monkeypatch.setattr(gate_report.subprocess, "run", failed_run)

    report = gate_report._run_memory_child(iterations=1, dense_bytes=128)

    assert report == {
        "status": "failed",
        "returncode": 2,
        "error": "memory child exited nonzero",
        "stdout_bytes": len(secret),
        "stderr_bytes": len(secret),
        "diagnostic_output_included": False,
    }
    assert secret not in json.dumps(report)


def test_memory_child_output_is_bounded_without_loading_or_returning_content(monkeypatch):
    gate_report = _load_gate_report_module()

    def oversized_run(*_args, **kwargs):
        kwargs["stdout"].write(b"x" * (gate_report.MAX_MEMORY_CHILD_OUTPUT_BYTES + 1))
        return subprocess.CompletedProcess(args=["memory-child"], returncode=0)

    monkeypatch.setattr(gate_report.subprocess, "run", oversized_run)

    report = gate_report._run_memory_child(iterations=1, dense_bytes=128)

    assert report["status"] == "failed"
    assert report["error"] == "memory child output exceeded the byte bound"
    assert report["stdout_bytes"] == gate_report.MAX_MEMORY_CHILD_OUTPUT_BYTES + 1
    assert report["diagnostic_output_included"] is False
    assert "xxx" not in json.dumps(report)


def test_memory_child_malformed_measured_payload_fails_closed(monkeypatch):
    gate_report = _load_gate_report_module()

    def malformed_run(*_args, **kwargs):
        kwargs["stdout"].write(b'{"status":"measured"}')
        return subprocess.CompletedProcess(args=["memory-child"], returncode=0)

    monkeypatch.setattr(gate_report.subprocess, "run", malformed_run)

    report = gate_report._run_memory_child(iterations=1, dense_bytes=128)
    summarized = gate_report._memory_report_from_child(
        {"status": "measured"},
        memory_budget_kib=2_000,
    )

    assert report["status"] == "failed"
    assert report["error"] == "memory child payload has an invalid object shape"
    assert summarized["status"] == "failed"
    assert summarized["passed"] is False
    assert summarized["diagnostic_output_included"] is False


def test_gate_report_rejects_unbounded_iteration_requests():
    gate_report = _load_gate_report_module()

    with pytest.raises(ValueError, match="between 1"):
        gate_report.gate_report(
            iterations=gate_report.MAX_GATE_ITERATIONS + 1,
            target_bytes=10_000,
            dense_bytes=128,
        )


def test_max_rss_kib_normalizes_darwin_bytes(monkeypatch):
    gate_report = _load_gate_report_module()

    class Usage:
        ru_maxrss = 12_345

    monkeypatch.setattr(gate_report.resource, "getrusage", lambda _target: Usage())
    monkeypatch.setattr(gate_report.platform, "system", lambda: "Darwin")

    assert gate_report._max_rss_kib() == 13

    monkeypatch.setattr(gate_report.platform, "system", lambda: "Linux")

    assert gate_report._max_rss_kib() == 12_345


def test_external_required_sections_are_excluded_from_overall_pass():
    gate_report = _load_gate_report_module()

    report = gate_report._overall_report(
        {
            "conformance": {"passed": None, "included_in_overall": False},
            "performance": {"passed": True, "included_in_overall": True},
            "memory": {"passed": True, "included_in_overall": True},
            "mode_strategy": {"passed": True, "included_in_overall": True},
            "distribution": {"passed": None, "included_in_overall": False},
        }
    )

    assert report == {
        "passed": True,
        "correctness_passed": True,
        "timing_eligible": False,
        "timing_status": "not_applicable",
        "timing_passed": None,
        "timing_observed_passed": None,
        "included_sections": {"performance": True, "memory": True, "mode_strategy": True},
        "external_required_sections": ["conformance", "distribution"],
    }


def test_bank_owner_cardinality_report_fails_when_growth_exceeds_validated_range():
    gate_report = _load_gate_report_module()

    report = gate_report._bank_owner_cardinality_report(
        entity_count=1000,
        growth_entity_count=1001,
        note="test signoff",
    )

    assert report["included_in_overall"] is True
    assert report["passed"] is False
    assert report["criteria"]["current_entity_count_within_validated_range"] is True
    assert report["criteria"]["growth_entity_count_within_validated_range"] is False


def test_bank_owner_cardinality_report_passes_at_medium_bank_target():
    gate_report = _load_gate_report_module()

    report = gate_report._bank_owner_cardinality_report(
        entity_count=1000,
        growth_entity_count=1000,
        note="representative synthetic medium bank",
    )

    assert report["included_in_overall"] is True
    assert report["passed"] is True
    assert report["validated_entity_count_ceiling"] == 1000
    assert report["criteria"]["current_entity_count_within_validated_range"] is True
    assert report["criteria"]["growth_entity_count_within_validated_range"] is True


def test_gate_report_cli_exits_nonzero_when_measured_gate_fails():
    module_path = Path(__file__).parents[2] / "scripts" / "rust_engine_gate_report.py"

    completed = subprocess.run(
        [
            sys.executable,
            str(module_path),
            "--iterations",
            "1",
            "--target-bytes",
            "10000",
            "--dense-bytes",
            "128",
            "--memory-absolute-budget-kib",
            "1",
        ],
        capture_output=True,
        check=False,
        text=True,
    )

    assert completed.returncode == 1
    report = json.loads(completed.stdout)
    assert report["overall"]["passed"] is False
    assert report["memory"]["passed"] is False
    assert completed.stderr == ""

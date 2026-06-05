from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


def _load_gate_report_module():
    module_path = Path(__file__).parents[2] / "scripts" / "rust_engine_gate_report.py"
    spec = importlib.util.spec_from_file_location("rust_engine_gate_report", module_path)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _measurement(*, count: int = 1, seconds: float = 0.01, stable: bool = True) -> dict[str, Any]:
    return {"count": count, "count_stable": stable, "median_seconds": seconds, "min_seconds": seconds}


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


def test_rust_engine_gate_report_quick_mode_returns_passing_json_compatible_shape():
    gate_report = _load_gate_report_module()

    report = gate_report.gate_report(iterations=1, target_bytes=10_000, dense_bytes=128)

    assert report["overall"]["passed"] is True
    assert report["overall"]["included_sections"] == {
        "performance": True,
        "memory": True,
        "mode_strategy": True,
    }
    assert report["overall"]["external_required_sections"] == ["conformance", "distribution"]
    assert report["conformance"]["passed"] is None
    assert report["conformance"]["included_in_overall"] is False
    assert report["performance"]["passed"] is True
    assert report["mode_strategy"]["passed"] is True
    assert report["memory"]["passed"] is True
    assert report["distribution"]["passed"] is None
    assert report["distribution"]["included_in_overall"] is False
    assert report["distribution"]["checked_by"] == "make build external validation"
    assert report["mode_strategy"]["decision"] == "entity_independent remains the production default"
    assert report["mode_strategy"]["dense_probe"]["all_overlaps_reconstructed_matches_entity_independent"] is True
    assert report["mode_strategy"]["entity_cardinality_sweep"]["entity_counts"] == [2, 8, 32]
    assert report["mode_strategy"]["entity_cardinality_sweep"]["performance"]["criteria"] == {
        "max_entity_independent_scan_seconds_under_ceiling": True,
        "entity_independent_scaling_ratio_under_ceiling": True,
        "routine_32_entity_independent_scan_seconds_under_ceiling": True,
        "routine_32_to_2_entity_scan_seconds_ratio_under_ceiling": True,
    }
    assert [case["entity_count"] for case in report["mode_strategy"]["entity_cardinality_sweep"]["dense_cases"]] == [
        2,
        8,
        32,
    ]
    assert [
        case["document_bytes"] for case in report["mode_strategy"]["entity_cardinality_sweep"]["routine_size_cases"]
    ] == [10_000, 10_000]
    assert report["performance"]["literal_heavy"]["native_public_records_equal"] is True
    assert report["performance"]["regex_heavy"]["native_public_records_equal"] is True
    assert "source_parse_jsonl" in report["performance"]["small_bank_floor"]["measurements"]
    assert report["performance"]["small_bank_floor"]["criteria"]["native_public_records_equal"] is True
    assert report["performance"]["small_bank_floor"]["criteria"]["rust_scan_project_under_ceiling"] is True


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
            "passed": True,
            "entity_independent": _measurement(seconds=0.001),
        }

    def routine_case(entity_count: int, _iterations: int, target_bytes: int) -> dict[str, Any]:
        return {
            "entity_count": entity_count,
            "document_bytes": target_bytes,
            "passed": entity_count != 32,
            "entity_independent": _measurement(seconds=0.001),
        }

    monkeypatch.setattr(gate_report, "_entity_cardinality_case", dense_case)
    monkeypatch.setattr(gate_report, "_entity_cardinality_routine_case", routine_case)

    sweep = gate_report._entity_cardinality_sweep(iterations=1, target_bytes=10_000)

    assert sweep["routine_size_cases"][-1]["passed"] is False
    assert sweep["passed"] is False


def test_memory_report_from_child_fails_when_isolated_probe_exceeds_budget():
    gate_report = _load_gate_report_module()

    report = gate_report._memory_report_from_child(
        {
            "status": "measured",
            "dense_probe_bytes": 128,
            "iterations": 1,
            "all_overlaps_raw": _measurement(count=128),
            "match_buffer_capacity_after_scan": 128,
            "max_rss_kib_process_start": 10_000,
            "max_rss_kib_before_compile": 10_000,
            "max_rss_kib_after_compile": 11_000,
            "max_rss_kib_after_scan": 12_500,
            "max_rss_kib_compile_delta": 1_000,
            "max_rss_kib_scan_delta": 1_500,
            "max_rss_kib_growth": 2_500,
        },
        memory_budget_kib=2_000,
    )

    assert report["passed"] is False
    assert report["criteria"]["max_rss_growth_within_budget"] is False


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
        "included_sections": {"performance": True, "memory": True, "mode_strategy": True},
        "external_required_sections": ["conformance", "distribution"],
    }


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

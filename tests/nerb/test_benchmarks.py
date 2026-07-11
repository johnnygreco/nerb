from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from nerb import (
    ExtractionError,
    benchmark_bank,
    benchmark_fixture_profiles,
    make_benchmark_fixture_profile,
    regress_bank,
)
from nerb.benchmarks import BENCHMARK_PROFILE_IDS, make_synthetic_bank
from nerb.diagnostics import EVAL_POSITIVE_FAILED

EXPECTED_BENCHMARK_PROFILES = {
    "small": {
        "workload": "small_bank",
        "active_totals": {"entities": 2, "names": 4, "patterns": 8},
        "by_kind": {"literal": 4, "regex": 4},
        "bank_profile": "mixed",
        "target_documents": ["target_literal", "target_regex", "target_mixed"],
        "record_counts": {"baseline": 1, "target": 16, "stress": 16},
    },
    "literal_heavy": {
        "workload": "realistic_literal_heavy",
        "active_totals": {"entities": 6, "names": 24, "patterns": 72},
        "by_kind": {"literal": 72, "regex": 0},
        "bank_profile": "mostly_literal",
        "target_documents": ["target_literal", "target_regex", "target_mixed"],
        "record_counts": {"baseline": 1, "target": 24, "stress": 24},
    },
    "regex_heavy": {
        "workload": "regex_heavy",
        "active_totals": {"entities": 4, "names": 12, "patterns": 36},
        "by_kind": {"literal": 0, "regex": 36},
        "bank_profile": "mostly_regex",
        "target_documents": ["target_literal", "target_regex", "target_mixed"],
        "record_counts": {"baseline": 1, "target": 16, "stress": 16},
    },
    "mixed": {
        "workload": "mixed_literal_regex",
        "active_totals": {"entities": 4, "names": 16, "patterns": 64},
        "by_kind": {"literal": 32, "regex": 32},
        "bank_profile": "mixed",
        "target_documents": ["target_literal", "target_regex", "target_mixed"],
        "record_counts": {"baseline": 1, "target": 24, "stress": 24},
    },
    "adversarial_smoke": {
        "workload": "adversarial_smoke",
        "active_totals": {"entities": 3, "names": 5, "patterns": 8},
        "by_kind": {"literal": 4, "regex": 4},
        "bank_profile": "mixed",
        "target_documents": ["adversarial_dense_hits", "adversarial_near_miss", "adversarial_mixed"],
        "record_counts": {"baseline": 4, "target": 52, "stress": 52},
    },
}


@pytest.fixture
def minimal_bank(test_data_path) -> dict[str, Any]:
    with open(test_data_path / "minimal_bank.json", encoding="utf-8") as file:
        return json.load(file)


def _regex_pattern(value: str, *, benchmark_text: str) -> dict[str, Any]:
    return {
        "kind": "regex",
        "value": value,
        "description": "Benchmark regex fixture.",
        "status": "active",
        "priority": 50,
        "regex_flags": [],
        "metadata": {"benchmark_text": benchmark_text},
    }


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> str:
    path.write_text("\n".join(json.dumps(record, separators=(",", ":")) for record in records) + "\n", encoding="utf-8")
    return path.name


def _benchmark_projection(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "profile": result["bank"]["profile"],
        "options": result["options"],
        "summary_profile": result["summary"]["profile"],
        "tiers": {
            tier: {
                "document_ids": [document["document_id"] for document in tier_result["documents"]],
                "bytes": tier_result["bytes"],
                "record_count": tier_result["record_count"],
                "record_counts_by_run": tier_result["record_counts_by_run"],
                "record_count_stable": tier_result["record_count_stable"],
            }
            for tier, tier_result in result["tiers"].items()
        },
    }


def test_benchmark_bank_reports_cache_compile_and_deterministic_tier_counts(minimal_bank):
    options = {"benchmark_iterations": 2, "stress_multiplier": 2}

    first = benchmark_bank(minimal_bank, options=options)
    second = benchmark_bank(minimal_bank, options=options)

    assert first["compile"]["cache"]["cold_hit"] is False
    assert first["compile"]["cache"]["warm_hit"] is True
    assert first["compile"]["cold"]["source"]["canonical_json_bytes"] > 0
    assert first["compile"]["cold"]["source"]["extractable_json_bytes"] > 0
    assert first["compile"]["cold"]["native"]["cache"]["hit"] is False
    assert first["compile"]["warm"]["native"]["cache"]["hit"] is True
    assert first["summary"]["cache_hit_verified"] is True
    assert first["summary"]["warm_cached_compile_seconds"] == first["compile"]["warm_cached_compile_seconds"]
    assert first["environment"]["python"]
    assert first["environment"]["executable_name"]
    assert "executable" not in first["environment"]
    assert first["bank"]["size"]["canonical_json_bytes"] == first["compile"]["cold"]["source"]["canonical_json_bytes"]
    assert first["stages"]["compile_cache"]["cache_hit_verified"] is True
    assert first["stages"]["compile_cache"]["exclusive"] is False
    assert first["stages"]["compile_cache"]["includes"] == [
        "canonicalize",
        "schema_validation",
        "runtime_validation",
        "cache_lookup",
        "rust_bank_compile",
    ]
    assert first["stages"]["input_parse"]["available"] is False
    assert first["stages"]["input_parse"]["seconds"] is None
    assert first["stages"]["input_parse"]["note"]
    assert first["stages"]["compile_construction"]["cold"]["schema_validation"]["available"] is True
    assert first["stages"]["compile_construction"]["native_warm"]["native_compile"]["available"] is False
    assert "matcher_compile" in first["compile"]["cold"]["stages"]["native_bank_from_source"]["includes"]
    assert "matcher_compile" not in first["compile"]["warm"]["stages"]["native_bank_from_source"]["includes"]
    assert "Rust construction was skipped" in first["compile"]["warm"]["stages"]["native_bank_from_source"]["note"]
    assert set(first["tiers"]) == {"baseline", "target", "stress"}
    assert all(tier["record_count_stable"] is True for tier in first["tiers"].values())
    assert all(
        set(tier["stages"]) == {"document_prepare_seconds", "scan_project_sort_seconds"}
        for tier in first["tiers"].values()
    )
    assert first["bank"]["profile"]["profile"] == "mostly_literal"
    assert _benchmark_projection(first) == _benchmark_projection(second)


def test_benchmark_fixture_profiles_manifest_is_json_compatible_and_explicit():
    manifest = benchmark_fixture_profiles()

    assert json.loads(json.dumps(manifest, allow_nan=False)) == manifest
    assert tuple(BENCHMARK_PROFILE_IDS) == tuple(EXPECTED_BENCHMARK_PROFILES)
    assert tuple(manifest["profile_ids"]) == BENCHMARK_PROFILE_IDS
    assert set(manifest["profiles"]) == set(BENCHMARK_PROFILE_IDS)
    assert manifest["gate"] == {
        "stage": "smoke",
        "thresholds_configured": False,
        "threshold_status": "deferred_until_native_engine_modes",
        "required_profiles": list(BENCHMARK_PROFILE_IDS),
        "required_tiers": ["baseline", "target", "stress"],
        "required_result_sections": [
            "bank",
            "engine",
            "options",
            "stages",
            "compile",
            "tiers",
            "summary",
            "environment",
        ],
        "requires_cache_hit_verified": True,
        "requires_stable_record_counts": True,
    }
    assert manifest["profiles"]["adversarial_smoke"]["workload"] == "adversarial_smoke"


@pytest.mark.parametrize("profile_id", EXPECTED_BENCHMARK_PROFILES)
def test_benchmark_fixture_profile_runs_with_stable_smoke_shape(profile_id):
    fixture = make_benchmark_fixture_profile(profile_id)
    expected = EXPECTED_BENCHMARK_PROFILES[profile_id]

    assert json.loads(json.dumps(fixture, allow_nan=False)) == fixture
    assert make_benchmark_fixture_profile(profile_id) == fixture
    assert fixture["id"] == profile_id
    assert fixture["workload"] == expected["workload"]
    assert set(fixture["documents"]) == {"baseline", "target", "stress"}
    assert fixture["options"]["benchmark_profile_id"] == profile_id

    result = benchmark_bank(fixture["bank"], documents=fixture["documents"], options=fixture["options"])

    assert json.loads(json.dumps(result, allow_nan=False)) == result
    assert result["options"]["benchmark_profile_id"] == profile_id
    assert result["summary"]["benchmark_profile_id"] == profile_id
    assert result["bank"]["stats"]["active_totals"] == expected["active_totals"]
    assert result["bank"]["stats"]["by_kind"] == expected["by_kind"]
    assert result["bank"]["profile"]["profile"] == expected["bank_profile"]
    assert [document["document_id"] for document in result["tiers"]["target"]["documents"]] == expected[
        "target_documents"
    ]
    assert {tier: result["tiers"][tier]["record_count"] for tier in ("baseline", "target", "stress")} == expected[
        "record_counts"
    ]
    assert set(result["stages"]) == {
        "input_parse",
        "canonicalize",
        "validation",
        "document_tier_resolution",
        "compile_cache",
        "compile_construction",
        "document_prepare",
        "scan_project_sort",
    }
    assert result["stages"]["compile_cache"]["cache_hit_verified"] is True
    assert result["stages"]["compile_cache"]["exclusive"] is False
    assert set(result["stages"]["document_prepare"]["seconds_by_tier"]) == {"baseline", "target", "stress"}
    assert set(result["stages"]["scan_project_sort"]["seconds_by_tier"]) == {"baseline", "target", "stress"}
    assert all(tier["record_count_stable"] is True for tier in result["tiers"].values())


def test_benchmark_bank_profiles_mixed_literal_regex_workload(minimal_bank):
    patterns = minimal_bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]
    patterns["invoice"] = _regex_pattern(r"\bINV-\d+\b", benchmark_text="INV-123")

    result = benchmark_bank(minimal_bank, options={"benchmark_iterations": 1, "stress_multiplier": 2})

    assert result["bank"]["profile"]["profile"] == "mixed"
    assert result["tiers"]["target"]["documents"][1]["document_id"] == "target_regex"
    assert result["tiers"]["target"]["documents"][1]["record_count"] == 1
    assert any(diagnostic["code"] == "benchmark.regex_probes" for diagnostic in result["diagnostics"])


def test_synthetic_scale_bank_helper_is_deterministic_and_reports_rust_engine_profile():
    bank = make_synthetic_bank(name_count=6, patterns_per_name=4, entity_count=3, literal_ratio=0.75)

    result = benchmark_bank(bank, options={"benchmark_iterations": 1, "stress_multiplier": 2})
    engine_profiles = {profile["name"]: profile for profile in result["engine"]["matchers"]}

    assert result["bank"]["stats"]["active_totals"] == {"entities": 3, "names": 6, "patterns": 24}
    assert result["bank"]["stats"]["by_kind"] == {"literal": 18, "regex": 6}
    assert engine_profiles["nerb_engine"]["entity_count"] == 3
    assert engine_profiles["nerb_engine"]["pattern_count"] == 24
    assert engine_profiles["nerb_engine"]["match_mode"] == "entity_independent"
    assert make_synthetic_bank(name_count=6, patterns_per_name=4, entity_count=3, literal_ratio=0.75) == bank


def test_regress_bank_reports_diff_eval_benchmark_deltas_and_quality_gate(tmp_path, minimal_bank):
    old_bank = copy.deepcopy(minimal_bank)
    eval_ref = _write_jsonl(
        tmp_path / "acme.jsonl",
        [
            {
                "type": "positive",
                "text": "Acme Corp",
                "matches": [{"string": "Acme Corp", "start": 0, "end": 9}],
                "metadata": {},
            }
        ],
    )
    old_bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]["eval_refs"] = [eval_ref]
    new_bank = copy.deepcopy(old_bank)
    new_bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]["value"] = "Globex"

    result = regress_bank(
        old_bank,
        new_bank,
        base_path=tmp_path,
        options={"benchmark_iterations": 1, "stress_multiplier": 2},
    )

    assert result["diff"]["summary"]["patterns_changed"] == 1
    assert result["evaluations"]["old"]["summary"]["passed"] is True
    assert result["evaluations"]["new"]["summary"]["passed"] is False
    assert result["deltas"]["quality"]["positive_failed_delta"] == 1
    assert result["deltas"]["quality"]["regressed"] is True
    assert result["deltas"]["performance"]["target_bytes_per_second_ratio"] is not None
    assert result["deltas"]["performance"]["warm_cached_compile_seconds_ratio"] is not None
    assert result["gates"]["passed"] is False
    assert result["gates"]["quality"]["passed"] is False
    assert result["benchmarks"]["old"]["summary"]["cache_hit_verified"] is True
    assert result["benchmarks"]["new"]["summary"]["cache_hit_verified"] is True
    assert any(
        diagnostic["code"] == EVAL_POSITIVE_FAILED and diagnostic["metadata"]["bank"] == "new_bank"
        for diagnostic in result["diagnostics"]
    )


def test_regress_bank_quality_gate_rejects_equal_empty_evaluations(minimal_bank):
    result = regress_bank(
        minimal_bank,
        minimal_bank,
        options={"benchmark_iterations": 1, "stress_multiplier": 2},
    )

    assert result["deltas"]["quality"]["evaluated"] == {"old": False, "new": False}
    assert result["gates"]["quality"]["passed"] is False
    checks = {check["name"]: check for check in result["gates"]["quality"]["checks"]}
    assert checks["old_eval_evaluated"]["passed"] is False
    assert checks["new_eval_evaluated"]["passed"] is False
    assert result["gates"]["passed"] is False


def test_regress_bank_quality_gate_rejects_equal_failing_evaluations(tmp_path, minimal_bank):
    eval_ref = _write_jsonl(
        tmp_path / "miss.jsonl",
        [
            {
                "type": "positive",
                "text": "No expected match",
                "matches": [{"string": "expected", "start": 3, "end": 11}],
                "metadata": {},
            }
        ],
    )
    minimal_bank["eval_refs"] = [eval_ref]

    result = regress_bank(
        minimal_bank,
        minimal_bank,
        base_path=tmp_path,
        options={"benchmark_iterations": 1, "stress_multiplier": 2},
    )

    assert result["evaluations"]["old"]["summary"]["evaluated"] is True
    assert result["evaluations"]["new"]["summary"]["passed"] is False
    checks = {check["name"]: check for check in result["gates"]["quality"]["checks"]}
    assert checks["new_eval_passed"]["passed"] is False
    assert result["gates"]["quality"]["passed"] is False


def test_regress_bank_quality_gate_rejects_same_size_eval_suite_replacement(tmp_path, minimal_bank):
    old_ref = _write_jsonl(
        tmp_path / "old.jsonl",
        [
            {
                "type": "positive",
                "text": "Acme Corp",
                "matches": [{"string": "Acme Corp", "start": 0, "end": 9}],
                "metadata": {},
            }
        ],
    )
    new_ref = _write_jsonl(
        tmp_path / "new.jsonl",
        [
            {
                "type": "positive",
                "text": "For Acme Corp",
                "matches": [{"string": "Acme Corp", "start": 4, "end": 13}],
                "metadata": {},
            }
        ],
    )
    old_bank = copy.deepcopy(minimal_bank)
    new_bank = copy.deepcopy(minimal_bank)
    old_bank["eval_refs"] = [old_ref]
    new_bank["eval_refs"] = [new_ref]

    result = regress_bank(
        old_bank,
        new_bank,
        base_path=tmp_path,
        options={"benchmark_iterations": 1, "stress_multiplier": 2},
    )

    assert result["evaluations"]["old"]["summary"]["passed"] is True
    assert result["evaluations"]["new"]["summary"]["passed"] is True
    assert result["deltas"]["quality"]["positive_total_delta"] == 0
    checks = {check["name"]: check for check in result["gates"]["quality"]["checks"]}
    assert checks["eval_suite_sha256_match"]["passed"] is False
    assert result["gates"]["quality"]["passed"] is False


@pytest.mark.parametrize(
    "options",
    [
        {"max_cold_compile_seconds_ratio": float("nan")},
        {"max_warm_cached_compile_seconds_ratio": float("inf")},
        {"min_target_bytes_per_second_ratio": float("-inf")},
    ],
)
def test_regress_bank_rejects_non_finite_gate_thresholds(minimal_bank, options):
    with pytest.raises(ExtractionError, match="positive number"):
        regress_bank(
            minimal_bank,
            minimal_bank,
            options={"benchmark_iterations": 1, "stress_multiplier": 2, **options},
        )


def test_regress_bank_preserves_raw_diff_diagnostics(minimal_bank):
    old_bank = copy.deepcopy(minimal_bank)
    old_bank["default_regex_flags"] = ["IGNORECASE", "IGNORECASE"]

    result = regress_bank(
        old_bank,
        minimal_bank,
        options={"benchmark_iterations": 1, "stress_multiplier": 2},
    )

    assert result["diff"]["diagnostics"] == [
        {
            "severity": "warning",
            "code": "flags.duplicate",
            "path": "/default_regex_flags",
            "message": "Duplicate regex flags will be removed during canonicalization: 'IGNORECASE'.",
            "metadata": {"bank": "old_bank"},
        }
    ]
    assert any(
        diagnostic["code"] == "flags.duplicate" and diagnostic["metadata"]["bank"] == "old_bank"
        for diagnostic in result["diagnostics"]
    )

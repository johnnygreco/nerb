from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from nerb import benchmark_bank, regress_bank
from nerb.benchmarks import make_synthetic_bank
from nerb.diagnostics import EVAL_POSITIVE_FAILED


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
    assert first["summary"]["cache_hit_verified"] is True
    assert set(first["tiers"]) == {"baseline", "target", "stress"}
    assert all(tier["record_count_stable"] is True for tier in first["tiers"].values())
    assert first["bank"]["profile"]["profile"] == "mostly_literal"
    assert _benchmark_projection(first) == _benchmark_projection(second)


def test_benchmark_bank_profiles_mixed_literal_regex_workload(minimal_bank):
    patterns = minimal_bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]
    patterns["invoice"] = _regex_pattern(r"\bINV-\d+\b", benchmark_text="INV-123")

    result = benchmark_bank(minimal_bank, options={"benchmark_iterations": 1, "stress_multiplier": 2})

    assert result["bank"]["profile"]["profile"] == "mixed"
    assert result["tiers"]["target"]["documents"][1]["document_id"] == "target_regex"
    assert result["tiers"]["target"]["documents"][1]["record_count"] == 1
    assert any(diagnostic["code"] == "benchmark.regex_probes" for diagnostic in result["diagnostics"])


def test_synthetic_scale_bank_helper_is_deterministic_and_reports_matcher_shards():
    bank = make_synthetic_bank(name_count=6, patterns_per_name=4, entity_count=3, literal_ratio=0.75)

    result = benchmark_bank(bank, options={"benchmark_iterations": 1, "stress_multiplier": 2})
    matcher_profiles = {profile["name"]: profile for profile in result["engine"]["matchers"]}

    assert result["bank"]["stats"]["active_totals"] == {"entities": 3, "names": 6, "patterns": 24}
    assert result["bank"]["stats"]["by_kind"] == {"literal": 18, "regex": 6}
    assert matcher_profiles["literal"]["entity_shard_count"] == 3
    assert matcher_profiles["literal"]["exact_literal_patterns"] == 18
    assert matcher_profiles["literal"]["regex_fallback_literal_patterns"] == 0
    assert matcher_profiles["python_re"]["entity_shard_count"] == 3
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
    assert result["gates"]["passed"] is False
    assert result["gates"]["quality"]["passed"] is False
    assert result["benchmarks"]["old"]["summary"]["cache_hit_verified"] is True
    assert result["benchmarks"]["new"]["summary"]["cache_hit_verified"] is True
    assert any(
        diagnostic["code"] == EVAL_POSITIVE_FAILED and diagnostic["metadata"]["bank"] == "new_bank"
        for diagnostic in result["diagnostics"]
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

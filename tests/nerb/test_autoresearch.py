from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from nerb.autoresearch import append_result_jsonl, run_autoresearch, score_candidate


def _benchmark_payload(
    *,
    cold_compile_seconds: float,
    gate_passed: bool = True,
    canonical_json_bytes: int = 100,
    extractable_json_bytes: int = 80,
) -> dict[str, object]:
    return {
        "schema_version": "nerb.enron_benchmark.v1",
        "elapsed_seconds": 1.0,
        "bank": {
            "hash": "sha256:bank",
            "stats": {"active_totals": {"entities": 2, "names": 5, "patterns": 7}},
        },
        "manifest": {
            "artifact_hashes": {
                "train": "sha256:train",
                "test": "sha256:test",
                "bank": "sha256:bank-artifact",
            }
        },
        "quality": {"test": {"record_count": 5, "entity_counts": {"email_address": 3, "email_domain": 2}}},
        "benchmark": {
            "summary": {
                "cold_compile_seconds": cold_compile_seconds,
                "warm_cached_compile_seconds": 0.05,
                "target_bytes_per_second": 1000.0,
            },
            "bank": {
                "size": {
                    "canonical_json_bytes": canonical_json_bytes,
                    "extractable_json_bytes": extractable_json_bytes,
                    "native_source_bytes": extractable_json_bytes,
                }
            },
        },
        "gate": {
            "configured": True,
            "passed": gate_passed,
            "evaluator": {"passed": gate_passed, "checks": []},
            "quality": {"passed": gate_passed, "checks": []},
            "performance": {"configured": True, "passed": gate_passed, "checks": []},
        },
    }


def _write_json(path: Path, payload: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    return path


def _init_repo(path: Path) -> None:
    subprocess.run(["git", "init"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=path, check=True)
    (path / ".gitignore").write_text(".nerb/\n", encoding="utf-8")
    (path / "src/nerb").mkdir(parents=True)
    (path / "src/nerb/engine.py").write_text("BEST = 1\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=path, check=True)
    subprocess.run(["git", "commit", "-m", "baseline"], cwd=path, check=True, capture_output=True)


def _jsonl_rows(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_score_candidate_keeps_clear_improvement() -> None:
    score, decision = score_candidate(
        _benchmark_payload(cold_compile_seconds=10.0),
        _benchmark_payload(cold_compile_seconds=8.0),
        min_improvement_ratio=0.05,
    )

    assert decision == {"value": "keep", "reason": "candidate improved the primary construction score"}
    assert score["primary"]["ratio"] == 0.8
    assert score["gate"]["passed"] is True
    assert score["size"]["passed"] is True


def test_score_candidate_discards_gate_failure_and_small_improvement() -> None:
    _score, gate_decision = score_candidate(
        _benchmark_payload(cold_compile_seconds=10.0),
        _benchmark_payload(cold_compile_seconds=8.0, gate_passed=False),
        min_improvement_ratio=0.05,
    )
    _score, slow_decision = score_candidate(
        _benchmark_payload(cold_compile_seconds=10.0),
        _benchmark_payload(cold_compile_seconds=9.7),
        min_improvement_ratio=0.05,
    )

    assert gate_decision["value"] == "discard"
    assert gate_decision["reason"] == "evaluator, quality, or configured performance gate failed"
    assert slow_decision["value"] == "discard"
    assert slow_decision["reason"] == "candidate did not improve the primary construction score enough"


def test_append_result_jsonl_writes_one_compact_json_object_per_line(tmp_path: Path) -> None:
    log_path = tmp_path / "results.jsonl"

    append_result_jsonl(log_path, {"schema_version": "test", "decision": {"value": "keep"}})
    append_result_jsonl(log_path, {"schema_version": "test", "decision": {"value": "discard"}})

    rows = _jsonl_rows(log_path)
    assert [row["decision"]["value"] for row in rows] == ["keep", "discard"]


def test_run_autoresearch_keeps_improvement_in_dry_run_fixture_repo(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    (tmp_path / "src/nerb/engine.py").write_text("BEST = 2\n", encoding="utf-8")
    baseline_path = _write_json(tmp_path / ".nerb/baseline/benchmark.json", _benchmark_payload(cold_compile_seconds=10))
    candidate_path = _write_json(
        tmp_path / ".nerb/candidate/benchmark.json", _benchmark_payload(cold_compile_seconds=8)
    )
    results_path = tmp_path / ".nerb/autoresearch/results.jsonl"

    result = run_autoresearch(
        baseline_benchmark_json=baseline_path,
        candidate_benchmark_json=candidate_path,
        results_jsonl=results_path,
        description="fixture fast path",
        repo_root=tmp_path,
        checkpoint_ref="HEAD",
        editable_paths=("src/nerb/engine.py",),
        frozen_paths=("src/nerb/enron_benchmark.py",),
        min_improvement_ratio=0.05,
    )

    assert result["decision"]["value"] == "keep"
    assert result["git"] == {"apply_requested": False, "applied": False, "action": "none"}
    assert result["repo"]["changed_paths"] == ["src/nerb/engine.py"]
    assert (tmp_path / "src/nerb/engine.py").read_text(encoding="utf-8") == "BEST = 2\n"
    assert _jsonl_rows(results_path)[0]["decision"]["value"] == "keep"


def test_run_autoresearch_discards_when_frozen_file_changes(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    (tmp_path / "src/nerb/enron_benchmark.py").write_text("changed evaluator\n", encoding="utf-8")
    baseline_path = _write_json(tmp_path / ".nerb/baseline/benchmark.json", _benchmark_payload(cold_compile_seconds=10))
    candidate_path = _write_json(
        tmp_path / ".nerb/candidate/benchmark.json", _benchmark_payload(cold_compile_seconds=8)
    )

    result = run_autoresearch(
        baseline_benchmark_json=baseline_path,
        candidate_benchmark_json=candidate_path,
        results_jsonl=tmp_path / ".nerb/autoresearch/results.jsonl",
        description="bad evaluator edit",
        repo_root=tmp_path,
        checkpoint_ref="HEAD",
        editable_paths=("src/nerb/engine.py",),
        frozen_paths=("src/nerb/enron_benchmark.py",),
        min_improvement_ratio=0.05,
    )

    assert result["decision"]["value"] == "discard"
    assert result["repo"]["path_gate"]["frozen_touched"] == ["src/nerb/enron_benchmark.py"]


def test_run_autoresearch_apply_git_decision_resets_failed_candidate(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    engine_path = tmp_path / "src/nerb/engine.py"
    scratch_path = tmp_path / "src/nerb/scratch.py"
    engine_path.write_text("BEST = 3\n", encoding="utf-8")
    scratch_path.write_text("temporary experiment file\n", encoding="utf-8")
    baseline_path = _write_json(tmp_path / ".nerb/baseline/benchmark.json", _benchmark_payload(cold_compile_seconds=10))
    candidate_path = _write_json(
        tmp_path / ".nerb/candidate/benchmark.json", _benchmark_payload(cold_compile_seconds=9.8)
    )

    result = run_autoresearch(
        baseline_benchmark_json=baseline_path,
        candidate_benchmark_json=candidate_path,
        results_jsonl=tmp_path / ".nerb/autoresearch/results.jsonl",
        description="not enough improvement",
        repo_root=tmp_path,
        checkpoint_ref="HEAD",
        editable_paths=("src/nerb/engine.py", "src/nerb/scratch.py"),
        frozen_paths=(),
        min_improvement_ratio=0.05,
        apply_git_decision=True,
    )

    assert result["decision"]["value"] == "discard"
    assert result["git"]["action"] == "reset-hard-clean"
    assert engine_path.read_text(encoding="utf-8") == "BEST = 1\n"
    assert not scratch_path.exists()


def test_run_autoresearch_classifies_candidate_command_crash(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    baseline_path = _write_json(tmp_path / ".nerb/baseline/benchmark.json", _benchmark_payload(cold_compile_seconds=10))
    candidate_path = tmp_path / ".nerb/candidate/benchmark.json"
    result = run_autoresearch(
        baseline_benchmark_json=baseline_path,
        candidate_benchmark_json=candidate_path,
        results_jsonl=tmp_path / ".nerb/autoresearch/results.jsonl",
        description="crashing command",
        repo_root=tmp_path,
        checkpoint_ref="HEAD",
        editable_paths=("src/nerb/engine.py",),
        frozen_paths=(),
        candidate_command=[
            sys.executable,
            "-c",
            "import sys; sys.stderr.write('candidate failed'); sys.exit(7)",
        ],
    )

    assert result["decision"] == {"value": "discard", "reason": "crash"}
    assert result["process"]["exit_code"] == 7
    assert result["process"]["stderr_tail"] == "candidate failed"

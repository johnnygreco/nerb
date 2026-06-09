from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, cast

import pytest

from nerb.autoresearch import PROCESS_OUTPUT_TAIL_CHARS, append_result_jsonl, run_autoresearch, score_candidate


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


def test_score_candidate_discards_inconsistent_top_level_gate() -> None:
    inconsistent = _benchmark_payload(cold_compile_seconds=8.0)
    gate = cast(dict[str, Any], inconsistent["gate"])
    evaluator = cast(dict[str, Any], gate["evaluator"])
    evaluator["passed"] = False

    score, decision = score_candidate(
        _benchmark_payload(cold_compile_seconds=10.0),
        inconsistent,
        min_improvement_ratio=0.05,
    )

    assert score["gate"]["passed"] is False
    assert score["gate"]["evaluator_passed"] is False
    assert decision["value"] == "discard"


def test_score_candidate_discards_unconfigured_performance_gate() -> None:
    unconfigured = _benchmark_payload(cold_compile_seconds=8.0)
    gate = cast(dict[str, Any], unconfigured["gate"])
    performance = cast(dict[str, Any], gate["performance"])
    performance["configured"] = False
    performance["checks"] = []

    score, decision = score_candidate(
        _benchmark_payload(cold_compile_seconds=10.0),
        unconfigured,
        min_improvement_ratio=0.05,
    )

    assert score["gate"]["passed"] is False
    assert score["gate"]["performance_configured"] is False
    assert score["gate"]["performance_passed"] is True
    assert decision["value"] == "discard"


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
    marker_path = tmp_path / "ran.txt"
    frozen_path = tmp_path / "src/nerb/enron_benchmark.py"
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
        apply_git_decision=True,
        candidate_command=[
            sys.executable,
            "-c",
            "from pathlib import Path; Path('ran.txt').write_text('yes')",
        ],
    )

    assert result["decision"]["value"] == "discard"
    assert result["process"]["skipped"] is True
    assert result["git"]["action"] == "blocked"
    assert result["repo"]["path_gate"]["frozen_touched"] == ["src/nerb/enron_benchmark.py"]
    assert not marker_path.exists()
    assert frozen_path.exists()


def test_run_autoresearch_resolves_relative_paths_against_repo_root(tmp_path: Path, monkeypatch: Any) -> None:
    _init_repo(tmp_path)
    (tmp_path / "src/nerb/engine.py").write_text("BEST = 2\n", encoding="utf-8")
    _write_json(tmp_path / ".nerb/baseline/benchmark.json", _benchmark_payload(cold_compile_seconds=10))
    _write_json(tmp_path / ".nerb/candidate/benchmark.json", _benchmark_payload(cold_compile_seconds=8))
    outside_cwd = tmp_path.parent
    monkeypatch.chdir(outside_cwd)

    result = run_autoresearch(
        baseline_benchmark_json=Path(".nerb/baseline/benchmark.json"),
        candidate_benchmark_json=Path(".nerb/candidate/benchmark.json"),
        results_jsonl=Path(".nerb/autoresearch/results.jsonl"),
        description="relative paths",
        repo_root=tmp_path,
        checkpoint_ref="HEAD",
        editable_paths=("src/nerb/engine.py",),
        frozen_paths=(),
        min_improvement_ratio=0.05,
    )

    assert result["decision"]["value"] == "keep"
    assert (tmp_path / ".nerb/autoresearch/results.jsonl").exists()
    assert not (outside_cwd / ".nerb/autoresearch/results.jsonl").exists()


def test_run_autoresearch_scores_parseable_gate_failure_from_nonzero_command(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    baseline_path = _write_json(tmp_path / ".nerb/baseline/benchmark.json", _benchmark_payload(cold_compile_seconds=10))
    candidate_path = tmp_path / ".nerb/candidate/benchmark.json"
    writer_path = tmp_path / ".nerb/write_failed_gate.py"
    writer_path.parent.mkdir(parents=True, exist_ok=True)
    writer_path.write_text(
        "import json\n"
        "import sys\n"
        "from pathlib import Path\n"
        f"payload = {json.dumps(_benchmark_payload(cold_compile_seconds=8, gate_passed=False))!r}\n"
        "Path('.nerb/candidate').mkdir(parents=True, exist_ok=True)\n"
        "Path('.nerb/candidate/benchmark.json').write_text(payload, encoding='utf-8')\n"
        "sys.exit(1)\n",
        encoding="utf-8",
    )

    result = run_autoresearch(
        baseline_benchmark_json=baseline_path,
        candidate_benchmark_json=candidate_path,
        results_jsonl=tmp_path / ".nerb/autoresearch/results.jsonl",
        description="gate failure",
        repo_root=tmp_path,
        checkpoint_ref="HEAD",
        editable_paths=("src/nerb/engine.py",),
        frozen_paths=(),
        candidate_command=[sys.executable, ".nerb/write_failed_gate.py"],
    )

    assert result["process"]["exit_code"] == 1
    assert result["decision"]["reason"] == "evaluator, quality, or configured performance gate failed"
    assert result["score"]["gate"]["passed"] is False


def test_run_autoresearch_discards_stale_candidate_json_after_nonzero_command(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    baseline_path = _write_json(tmp_path / ".nerb/baseline/benchmark.json", _benchmark_payload(cold_compile_seconds=10))
    candidate_path = _write_json(
        tmp_path / ".nerb/candidate/benchmark.json",
        _benchmark_payload(cold_compile_seconds=8, gate_passed=False),
    )

    result = run_autoresearch(
        baseline_benchmark_json=baseline_path,
        candidate_benchmark_json=candidate_path,
        results_jsonl=tmp_path / ".nerb/autoresearch/results.jsonl",
        description="stale failed gate",
        repo_root=tmp_path,
        checkpoint_ref="HEAD",
        editable_paths=("src/nerb/engine.py",),
        frozen_paths=(),
        candidate_command=[sys.executable, "-c", "import sys; sys.exit(1)"],
    )

    assert result["decision"] == {"value": "discard", "reason": "candidate benchmark JSON was not freshly written"}
    assert result["score"] == {}


def test_run_autoresearch_discards_when_baseline_changes_during_candidate_run(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    baseline_path = _write_json(tmp_path / ".nerb/baseline/benchmark.json", _benchmark_payload(cold_compile_seconds=10))
    candidate_path = tmp_path / ".nerb/candidate/benchmark.json"
    writer_path = tmp_path / ".nerb/write_candidate_and_mutate_baseline.py"
    writer_path.parent.mkdir(parents=True, exist_ok=True)
    writer_path.write_text(
        "import json\n"
        "from pathlib import Path\n"
        f"candidate = {json.dumps(_benchmark_payload(cold_compile_seconds=8))!r}\n"
        f"baseline = {json.dumps(_benchmark_payload(cold_compile_seconds=100))!r}\n"
        "Path('.nerb/candidate').mkdir(parents=True, exist_ok=True)\n"
        "Path('.nerb/candidate/benchmark.json').write_text(candidate, encoding='utf-8')\n"
        "Path('.nerb/baseline/benchmark.json').write_text(baseline, encoding='utf-8')\n",
        encoding="utf-8",
    )

    result = run_autoresearch(
        baseline_benchmark_json=baseline_path,
        candidate_benchmark_json=candidate_path,
        results_jsonl=tmp_path / ".nerb/autoresearch/results.jsonl",
        description="mutated baseline",
        repo_root=tmp_path,
        checkpoint_ref="HEAD",
        editable_paths=("src/nerb/engine.py",),
        frozen_paths=(),
        candidate_command=[sys.executable, ".nerb/write_candidate_and_mutate_baseline.py"],
    )

    assert result["decision"] == {"value": "discard", "reason": "baseline benchmark JSON changed during candidate run"}
    assert result["error"]["type"] == "BaselineBenchmarkChanged"
    assert result["repo"]["baseline_gate"]["passed"] is False


def test_run_autoresearch_uses_immutable_checkpoint_ref_when_command_moves_head(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    frozen_path = tmp_path / "src/nerb/enron_benchmark.py"
    frozen_path.write_text("clean evaluator\n", encoding="utf-8")
    subprocess.run(["git", "add", "src/nerb/enron_benchmark.py"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-m", "add evaluator"], cwd=tmp_path, check=True, capture_output=True)
    checkpoint_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    baseline_path = _write_json(tmp_path / ".nerb/baseline/benchmark.json", _benchmark_payload(cold_compile_seconds=10))
    candidate_path = tmp_path / ".nerb/candidate/benchmark.json"
    writer_path = tmp_path / ".nerb/write_candidate_commit_frozen.py"
    writer_path.parent.mkdir(parents=True, exist_ok=True)
    writer_path.write_text(
        "import json\n"
        "import subprocess\n"
        "from pathlib import Path\n"
        f"payload = {json.dumps(_benchmark_payload(cold_compile_seconds=8))!r}\n"
        "Path('.nerb/candidate').mkdir(parents=True, exist_ok=True)\n"
        "Path('.nerb/candidate/benchmark.json').write_text(payload, encoding='utf-8')\n"
        "Path('src/nerb/enron_benchmark.py').write_text('changed evaluator\\n', encoding='utf-8')\n"
        "subprocess.run(['git', 'add', 'src/nerb/enron_benchmark.py'], check=True)\n"
        "subprocess.run(['git', 'commit', '-m', 'move head'], check=True, capture_output=True)\n",
        encoding="utf-8",
    )

    result = run_autoresearch(
        baseline_benchmark_json=baseline_path,
        candidate_benchmark_json=candidate_path,
        results_jsonl=tmp_path / ".nerb/autoresearch/results.jsonl",
        description="head moves",
        repo_root=tmp_path,
        checkpoint_ref="HEAD",
        editable_paths=("src/nerb/engine.py",),
        frozen_paths=("src/nerb/enron_benchmark.py",),
        candidate_command=[sys.executable, ".nerb/write_candidate_commit_frozen.py"],
    )

    assert result["decision"] == {
        "value": "discard",
        "reason": "changed files outside the editable experiment surface",
    }
    assert result["repo"]["checkpoint_ref"] == checkpoint_sha
    assert result["repo"]["path_gate"]["frozen_touched"] == ["src/nerb/enron_benchmark.py"]


def test_run_autoresearch_discards_stale_candidate_json_after_successful_command(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    baseline_path = _write_json(tmp_path / ".nerb/baseline/benchmark.json", _benchmark_payload(cold_compile_seconds=10))
    candidate_path = _write_json(
        tmp_path / ".nerb/candidate/benchmark.json", _benchmark_payload(cold_compile_seconds=8)
    )

    result = run_autoresearch(
        baseline_benchmark_json=baseline_path,
        candidate_benchmark_json=candidate_path,
        results_jsonl=tmp_path / ".nerb/autoresearch/results.jsonl",
        description="stale candidate",
        repo_root=tmp_path,
        checkpoint_ref="HEAD",
        editable_paths=("src/nerb/engine.py",),
        frozen_paths=(),
        candidate_command=[sys.executable, "-c", "pass"],
    )

    assert result["decision"] == {"value": "discard", "reason": "candidate benchmark JSON was not freshly written"}
    assert result["error"]["type"] == "StaleCandidateBenchmark"
    assert result["repo"]["candidate_output_gate"]["passed"] is False


def test_run_autoresearch_logs_and_resets_malformed_candidate_json(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    engine_path = tmp_path / "src/nerb/engine.py"
    engine_path.write_text("BEST = 9\n", encoding="utf-8")
    baseline_path = _write_json(tmp_path / ".nerb/baseline/benchmark.json", _benchmark_payload(cold_compile_seconds=10))
    candidate_path = tmp_path / ".nerb/candidate/benchmark.json"
    candidate_path.parent.mkdir(parents=True)
    candidate_path.write_text("{not-json", encoding="utf-8")
    results_path = tmp_path / ".nerb/autoresearch/results.jsonl"

    result = run_autoresearch(
        baseline_benchmark_json=baseline_path,
        candidate_benchmark_json=candidate_path,
        results_jsonl=results_path,
        description="malformed candidate",
        repo_root=tmp_path,
        checkpoint_ref="HEAD",
        editable_paths=("src/nerb/engine.py",),
        frozen_paths=(),
        apply_git_decision=True,
    )

    row = _jsonl_rows(results_path)[0]
    assert result["decision"] == {"value": "discard", "reason": "benchmark result could not be scored"}
    assert result["error"]["type"] == "JSONDecodeError"
    assert row["decision"]["reason"] == "benchmark result could not be scored"
    assert engine_path.read_text(encoding="utf-8") == "BEST = 1\n"


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
    assert result["error"]


def test_run_autoresearch_logs_missing_candidate_executable_and_applies_cleanup(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    engine_path = tmp_path / "src/nerb/engine.py"
    engine_path.write_text("BEST = 4\n", encoding="utf-8")
    baseline_path = _write_json(tmp_path / ".nerb/baseline/benchmark.json", _benchmark_payload(cold_compile_seconds=10))
    results_path = tmp_path / ".nerb/autoresearch/results.jsonl"

    result = run_autoresearch(
        baseline_benchmark_json=baseline_path,
        candidate_benchmark_json=tmp_path / ".nerb/candidate/benchmark.json",
        results_jsonl=results_path,
        description="missing executable",
        repo_root=tmp_path,
        checkpoint_ref="HEAD",
        editable_paths=("src/nerb/engine.py",),
        frozen_paths=(),
        candidate_command=["definitely-not-a-real-nerb-command"],
        apply_git_decision=True,
    )

    row = _jsonl_rows(results_path)[0]
    assert result["decision"]["value"] == "discard"
    assert result["decision"]["reason"] == "crash"
    assert result["process"]["exit_code"] == 127
    assert "definitely-not-a-real-nerb-command" in result["process"]["stderr_tail"]
    assert row["decision"]["reason"] == "crash"
    assert engine_path.read_text(encoding="utf-8") == "BEST = 1\n"


def test_run_autoresearch_logs_timeout_row(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    baseline_path = _write_json(tmp_path / ".nerb/baseline/benchmark.json", _benchmark_payload(cold_compile_seconds=10))
    results_path = tmp_path / ".nerb/autoresearch/results.jsonl"

    result = run_autoresearch(
        baseline_benchmark_json=baseline_path,
        candidate_benchmark_json=tmp_path / ".nerb/candidate/benchmark.json",
        results_jsonl=results_path,
        description="timeout",
        repo_root=tmp_path,
        checkpoint_ref="HEAD",
        editable_paths=("src/nerb/engine.py",),
        frozen_paths=(),
        timeout_seconds=0.1,
        candidate_command=[
            sys.executable,
            "-c",
            "import sys, time; sys.stdout.write('started'); sys.stdout.flush(); time.sleep(10)",
        ],
    )

    row = _jsonl_rows(results_path)[0]
    assert result["decision"] == {"value": "discard", "reason": "timeout"}
    assert result["process"]["timed_out"] is True
    assert result["process"]["stdout_tail"] == "started"
    assert row["decision"]["reason"] == "timeout"
    assert row["process"]["timed_out"] is True


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group cleanup regression")
def test_run_autoresearch_timeout_kills_candidate_process_group(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    engine_path = tmp_path / "src/nerb/engine.py"
    baseline_path = _write_json(tmp_path / ".nerb/baseline/benchmark.json", _benchmark_payload(cold_compile_seconds=10))
    writer_path = tmp_path / ".nerb/spawn_late_writer.py"
    writer_path.parent.mkdir(parents=True, exist_ok=True)
    writer_path.write_text(
        "import subprocess\n"
        "import sys\n"
        "import time\n"
        "subprocess.Popen([\n"
        "    sys.executable,\n"
        "    '-c',\n"
        '    "import time; from pathlib import Path; time.sleep(0.4); "\n'
        "    \"Path('src/nerb/engine.py').write_text('LATE = 1\\\\n', encoding='utf-8')\",\n"
        "], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
        "time.sleep(10)\n",
        encoding="utf-8",
    )

    result = run_autoresearch(
        baseline_benchmark_json=baseline_path,
        candidate_benchmark_json=tmp_path / ".nerb/candidate/benchmark.json",
        results_jsonl=tmp_path / ".nerb/autoresearch/results.jsonl",
        description="process tree timeout",
        repo_root=tmp_path,
        checkpoint_ref="HEAD",
        editable_paths=("src/nerb/engine.py",),
        frozen_paths=(),
        timeout_seconds=0.1,
        candidate_command=[sys.executable, ".nerb/spawn_late_writer.py"],
    )
    time.sleep(0.7)

    assert result["decision"] == {"value": "discard", "reason": "timeout"}
    assert engine_path.read_text(encoding="utf-8") == "BEST = 1\n"


def test_run_autoresearch_caps_candidate_output_tails(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    baseline_path = _write_json(tmp_path / ".nerb/baseline/benchmark.json", _benchmark_payload(cold_compile_seconds=10))
    candidate_path = tmp_path / ".nerb/candidate/benchmark.json"
    writer_path = tmp_path / ".nerb/noisy_candidate.py"
    writer_path.parent.mkdir(parents=True, exist_ok=True)
    writer_path.write_text(
        "import json\n"
        "import sys\n"
        "from pathlib import Path\n"
        f"payload = {json.dumps(_benchmark_payload(cold_compile_seconds=8))!r}\n"
        "sys.stdout.write('a' * 6000)\n"
        "sys.stderr.write('b' * 6000)\n"
        "Path('.nerb/candidate').mkdir(parents=True, exist_ok=True)\n"
        "Path('.nerb/candidate/benchmark.json').write_text(payload, encoding='utf-8')\n",
        encoding="utf-8",
    )

    result = run_autoresearch(
        baseline_benchmark_json=baseline_path,
        candidate_benchmark_json=candidate_path,
        results_jsonl=tmp_path / ".nerb/autoresearch/results.jsonl",
        description="noisy candidate",
        repo_root=tmp_path,
        checkpoint_ref="HEAD",
        editable_paths=("src/nerb/engine.py",),
        frozen_paths=(),
        candidate_command=[sys.executable, ".nerb/noisy_candidate.py"],
    )

    assert result["decision"]["value"] == "keep"
    assert result["process"]["stdout_tail"] == "a" * PROCESS_OUTPUT_TAIL_CHARS
    assert result["process"]["stderr_tail"] == "b" * PROCESS_OUTPUT_TAIL_CHARS


def test_script_runs_candidate_command_and_logs_result(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    (tmp_path / "src/nerb/engine.py").write_text("BEST = 2\n", encoding="utf-8")
    _write_json(tmp_path / ".nerb/baseline/benchmark.json", _benchmark_payload(cold_compile_seconds=10))
    writer_path = tmp_path / ".nerb/write_candidate.py"
    writer_path.parent.mkdir(parents=True, exist_ok=True)
    writer_path.write_text(
        "import json\n"
        "from pathlib import Path\n"
        f"payload = {json.dumps(_benchmark_payload(cold_compile_seconds=8))!r}\n"
        "Path('.nerb/candidate').mkdir(parents=True, exist_ok=True)\n"
        "Path('.nerb/candidate/benchmark.json').write_text(payload, encoding='utf-8')\n",
        encoding="utf-8",
    )
    repo_root = Path(__file__).resolve().parents[2]
    env = dict(os.environ)
    src_path = str(repo_root / "src")
    env["PYTHONPATH"] = src_path + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")

    completed = subprocess.run(
        [
            sys.executable,
            str(repo_root / "scripts/nerb_autoresearch.py"),
            "--baseline-benchmark-json",
            ".nerb/baseline/benchmark.json",
            "--candidate-benchmark-json",
            ".nerb/candidate/benchmark.json",
            "--results-jsonl",
            ".nerb/autoresearch/results.jsonl",
            "--description",
            "script smoke",
            "--repo-root",
            str(tmp_path),
            "--checkpoint-ref",
            "HEAD",
            "--editable-path",
            "src/nerb/engine.py",
            "--frozen-path",
            "src/nerb/enron_benchmark.py",
            "--min-improvement-ratio",
            "0.05",
            "--candidate-command",
            sys.executable,
            ".nerb/write_candidate.py",
        ],
        cwd=repo_root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    output = json.loads(completed.stdout)
    assert output["decision"]["value"] == "keep"
    assert output["score"]["primary"]["ratio"] == 0.8
    assert _jsonl_rows(tmp_path / ".nerb/autoresearch/results.jsonl")[0]["decision"]["value"] == "keep"

from __future__ import annotations

import argparse
import json
import math
import platform
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

AUTORESEARCH_RESULT_SCHEMA_VERSION = "nerb.autoresearch_result.v1"
DEFAULT_RESULTS_JSONL = Path(".nerb/autoresearch/results.jsonl")
DEFAULT_TIMEOUT_SECONDS = 30 * 60
DEFAULT_MIN_IMPROVEMENT_RATIO = 0.01
DEFAULT_MAX_CANONICAL_JSON_BYTES_RATIO = 1.05
DEFAULT_MAX_EXTRACTABLE_JSON_BYTES_RATIO = 1.05
PRIMARY_SCORE_FIELD = "benchmark.summary.cold_compile_seconds"

DEFAULT_EDITABLE_PATHS = (
    "src/nerb/bank.py",
    "src/nerb/engine.py",
    "src/nerb/engines.py",
    "src/nerb/records.py",
    "rust/Cargo.lock",
    "rust/Cargo.toml",
    "rust/src/bank.rs",
    "rust/src/engine.rs",
    "rust/src/flags.rs",
    "rust/src/formats.rs",
    "rust/src/ids.rs",
    "rust/src/lib.rs",
    "rust/src/match_buffer.rs",
)
DEFAULT_FROZEN_PATHS = (
    "scripts/enron_bank_build_benchmark.py",
    "src/nerb/benchmarks.py",
    "src/nerb/enron_benchmark.py",
    "tests/nerb/test_enron_benchmark.py",
    "tests/data/enron_sample.jsonl",
    "docs/enron-benchmark.md",
    ".agents/skills/nerb-large-source-bank-building",
)


@dataclass(frozen=True)
class ProcessResult:
    command: tuple[str, ...]
    exit_code: int | None
    timed_out: bool
    elapsed_seconds: float
    stdout_tail: str
    stderr_tail: str
    skipped: bool = False
    skip_reason: str | None = None


def main(argv: Sequence[str] | None = None) -> None:
    args = _parse_args(argv)
    result = run_autoresearch(
        baseline_benchmark_json=args.baseline_benchmark_json,
        candidate_benchmark_json=args.candidate_benchmark_json,
        results_jsonl=args.results_jsonl,
        description=args.description,
        candidate_command=args.candidate_command,
        timeout_seconds=args.timeout_seconds,
        min_improvement_ratio=args.min_improvement_ratio,
        max_canonical_json_bytes_ratio=args.max_canonical_json_bytes_ratio,
        max_extractable_json_bytes_ratio=args.max_extractable_json_bytes_ratio,
        repo_root=args.repo_root,
        checkpoint_ref=args.checkpoint_ref,
        editable_paths=args.editable_paths or DEFAULT_EDITABLE_PATHS,
        frozen_paths=args.frozen_paths or DEFAULT_FROZEN_PATHS,
        apply_git_decision=args.apply_git_decision,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False))
    if result["decision"]["value"] != "keep":
        raise SystemExit(1)


def run_autoresearch(
    *,
    baseline_benchmark_json: Path,
    candidate_benchmark_json: Path,
    results_jsonl: Path,
    description: str,
    candidate_command: Sequence[str] | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    min_improvement_ratio: float = DEFAULT_MIN_IMPROVEMENT_RATIO,
    max_canonical_json_bytes_ratio: float | None = DEFAULT_MAX_CANONICAL_JSON_BYTES_RATIO,
    max_extractable_json_bytes_ratio: float | None = DEFAULT_MAX_EXTRACTABLE_JSON_BYTES_RATIO,
    repo_root: Path = Path("."),
    checkpoint_ref: str = "HEAD",
    editable_paths: Sequence[str] = DEFAULT_EDITABLE_PATHS,
    frozen_paths: Sequence[str] = DEFAULT_FROZEN_PATHS,
    apply_git_decision: bool = False,
) -> dict[str, Any]:
    repo = repo_root.expanduser().resolve()
    baseline_path = _resolve_repo_path(repo, baseline_benchmark_json)
    candidate_path = _resolve_repo_path(repo, candidate_benchmark_json)
    results_path = _resolve_repo_path(repo, results_jsonl)
    _validate_positive_number(timeout_seconds, "timeout_seconds")
    _validate_nonnegative_ratio(min_improvement_ratio, "min_improvement_ratio")
    if max_canonical_json_bytes_ratio is not None:
        _validate_positive_number(max_canonical_json_bytes_ratio, "max_canonical_json_bytes_ratio")
    if max_extractable_json_bytes_ratio is not None:
        _validate_positive_number(max_extractable_json_bytes_ratio, "max_extractable_json_bytes_ratio")

    started = time.perf_counter()
    pre_changed_paths = _git_changed_paths(repo, checkpoint_ref)
    pre_path_gate = _path_gate(pre_changed_paths, editable_paths=editable_paths, frozen_paths=frozen_paths)
    if pre_path_gate["passed"]:
        process = (
            _run_candidate_command(candidate_command, timeout_seconds=timeout_seconds, cwd=repo)
            if candidate_command is not None
            else ProcessResult((), 0, False, 0.0, "", "")
        )
        changed_paths = _git_changed_paths(repo, checkpoint_ref)
        post_path_gate = _path_gate(changed_paths, editable_paths=editable_paths, frozen_paths=frozen_paths)
    else:
        process = ProcessResult(
            tuple(candidate_command or ()),
            None,
            False,
            0.0,
            "",
            "",
            skipped=True,
            skip_reason="pre-command path gate failed",
        )
        changed_paths = pre_changed_paths
        post_path_gate = pre_path_gate
    path_gate = _combined_path_gate(pre_path_gate, post_path_gate)

    score_payload: dict[str, Any] | None = None
    decision = {"value": "discard", "reason": "candidate evaluator did not complete successfully"}
    baseline: Mapping[str, Any] | None = None
    candidate: Mapping[str, Any] | None = None
    error: dict[str, str] | None = None
    if not pre_path_gate["passed"]:
        decision = {"value": "discard", "reason": "pre-command path gate failed"}
    elif process.timed_out:
        decision = {"value": "discard", "reason": "timeout"}
    elif not path_gate["passed"]:
        decision = {"value": "discard", "reason": "changed files outside the editable experiment surface"}
    else:
        baseline, candidate, score_payload, decision, error = _load_score_and_decide(
            baseline_path,
            candidate_path,
            process,
            min_improvement_ratio=min_improvement_ratio,
            max_canonical_json_bytes_ratio=max_canonical_json_bytes_ratio,
            max_extractable_json_bytes_ratio=max_extractable_json_bytes_ratio,
        )

    result = _result_payload(
        description=description,
        baseline_benchmark_json=baseline_path,
        candidate_benchmark_json=candidate_path,
        results_jsonl=results_path,
        repo_root=repo,
        checkpoint_ref=checkpoint_ref,
        editable_paths=editable_paths,
        frozen_paths=frozen_paths,
        changed_paths=changed_paths,
        path_gate=path_gate,
        process=process,
        score_payload=score_payload,
        baseline=baseline,
        candidate=candidate,
        decision=decision,
        error=error,
        elapsed_seconds=time.perf_counter() - started,
        apply_git_decision=apply_git_decision,
    )
    result["git"] = _apply_git_decision(
        repo,
        checkpoint_ref,
        result["decision"],
        changed_paths=changed_paths,
        apply=apply_git_decision,
    )
    append_result_jsonl(results_path, result)
    return result


def _load_score_and_decide(
    baseline_path: Path,
    candidate_path: Path,
    process: ProcessResult,
    *,
    min_improvement_ratio: float,
    max_canonical_json_bytes_ratio: float | None,
    max_extractable_json_bytes_ratio: float | None,
) -> tuple[
    Mapping[str, Any] | None, Mapping[str, Any] | None, dict[str, Any] | None, dict[str, str], dict[str, str] | None
]:
    try:
        baseline = _load_json_object(baseline_path)
        candidate = _load_json_object(candidate_path)
        score_payload, decision = score_candidate(
            baseline,
            candidate,
            min_improvement_ratio=min_improvement_ratio,
            max_canonical_json_bytes_ratio=max_canonical_json_bytes_ratio,
            max_extractable_json_bytes_ratio=max_extractable_json_bytes_ratio,
        )
    except (OSError, TypeError, ValueError) as exc:
        reason = "crash" if process.exit_code not in (None, 0) else "benchmark result could not be scored"
        return None, None, None, {"value": "discard", "reason": reason}, _error_payload(exc)

    if process.exit_code not in (None, 0):
        gate = _gate_payload(candidate)
        if gate.get("configured") is True and gate.get("passed") is False:
            return baseline, candidate, score_payload, decision, None
        return (
            baseline,
            candidate,
            score_payload,
            {"value": "discard", "reason": "candidate command exited nonzero after writing benchmark JSON"},
            None,
        )
    return baseline, candidate, score_payload, decision, None


def score_candidate(
    baseline: Mapping[str, Any],
    candidate: Mapping[str, Any],
    *,
    min_improvement_ratio: float = DEFAULT_MIN_IMPROVEMENT_RATIO,
    max_canonical_json_bytes_ratio: float | None = DEFAULT_MAX_CANONICAL_JSON_BYTES_RATIO,
    max_extractable_json_bytes_ratio: float | None = DEFAULT_MAX_EXTRACTABLE_JSON_BYTES_RATIO,
) -> tuple[dict[str, Any], dict[str, str]]:
    _validate_nonnegative_ratio(min_improvement_ratio, "min_improvement_ratio")
    baseline_score = _required_positive_number(baseline, ("benchmark", "summary", "cold_compile_seconds"))
    candidate_score = _required_positive_number(candidate, ("benchmark", "summary", "cold_compile_seconds"))
    ratio = _ratio(candidate_score, baseline_score)
    improvement_ratio = round(1.0 - ratio, 6)
    required_score = round(baseline_score * (1.0 - min_improvement_ratio), 9)

    gate = _gate_payload(candidate)
    gate_passed = gate.get("configured") is True and gate.get("passed") is True
    evaluator_passed = _nested_bool(gate, ("evaluator", "passed"))
    quality_passed = _nested_bool(gate, ("quality", "passed"))
    size_checks = _size_checks(
        baseline,
        candidate,
        max_canonical_json_bytes_ratio=max_canonical_json_bytes_ratio,
        max_extractable_json_bytes_ratio=max_extractable_json_bytes_ratio,
    )
    size_passed = all(check["passed"] for check in size_checks)

    score = {
        "primary": {
            "field": PRIMARY_SCORE_FIELD,
            "lower_is_better": True,
            "baseline": baseline_score,
            "candidate": candidate_score,
            "ratio": ratio,
            "improvement_ratio": improvement_ratio,
            "min_improvement_ratio": min_improvement_ratio,
            "required_candidate_max": required_score,
        },
        "gate": {
            "configured": gate.get("configured") is True,
            "passed": gate_passed,
            "evaluator_passed": evaluator_passed,
            "quality_passed": quality_passed,
            "performance_passed": _nested_bool(gate, ("performance", "passed")),
        },
        "size": {"passed": size_passed, "checks": size_checks},
        "timings": _timing_summary(candidate),
        "memory_size": _size_summary(candidate),
    }
    if not gate_passed:
        return score, {"value": "discard", "reason": "evaluator, quality, or configured performance gate failed"}
    if not size_passed:
        return score, {"value": "discard", "reason": "memory or size ceiling failed"}
    if candidate_score <= required_score:
        return score, {"value": "keep", "reason": "candidate improved the primary construction score"}
    return score, {"value": "discard", "reason": "candidate did not improve the primary construction score enough"}


def append_result_jsonl(path: Path, payload: Mapping[str, Any]) -> None:
    destination = path.expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("a", encoding="utf-8") as file:
        file.write(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False))
        file.write("\n")


def _result_payload(
    *,
    description: str,
    baseline_benchmark_json: Path,
    candidate_benchmark_json: Path,
    results_jsonl: Path,
    repo_root: Path,
    checkpoint_ref: str,
    editable_paths: Sequence[str],
    frozen_paths: Sequence[str],
    changed_paths: Sequence[str],
    path_gate: Mapping[str, Any],
    process: ProcessResult,
    score_payload: Mapping[str, Any] | None,
    baseline: Mapping[str, Any] | None,
    candidate: Mapping[str, Any] | None,
    decision: Mapping[str, str],
    error: Mapping[str, str] | None,
    elapsed_seconds: float,
    apply_git_decision: bool,
) -> dict[str, Any]:
    return {
        "schema_version": AUTORESEARCH_RESULT_SCHEMA_VERSION,
        "created_at": _timestamp(),
        "description": description,
        "result_log": str(results_jsonl),
        "repo": {
            "root": str(repo_root),
            "commit": _git_commit(repo_root),
            "checkpoint_ref": checkpoint_ref,
            "changed_paths": list(changed_paths),
            "editable_paths": list(editable_paths),
            "frozen_paths": list(frozen_paths),
            "path_gate": dict(path_gate),
        },
        "evaluator": {
            "baseline_benchmark_json": str(baseline_benchmark_json),
            "candidate_benchmark_json": str(candidate_benchmark_json),
            "baseline_bank_hash": _path_get(baseline or {}, ("bank", "hash")),
            "candidate_bank_hash": _path_get(candidate or {}, ("bank", "hash")),
            "baseline_artifact_hashes": _path_get(baseline or {}, ("manifest", "artifact_hashes")),
            "candidate_artifact_hashes": _path_get(candidate or {}, ("manifest", "artifact_hashes")),
        },
        "process": {
            "command": list(process.command),
            "exit_code": process.exit_code,
            "timed_out": process.timed_out,
            "skipped": process.skipped,
            "skip_reason": process.skip_reason,
            "elapsed_seconds": _seconds(process.elapsed_seconds),
            "stdout_tail": process.stdout_tail,
            "stderr_tail": process.stderr_tail,
        },
        "score": dict(score_payload or {}),
        "decision": dict(decision),
        "error": dict(error or {}),
        "git": {"apply_requested": apply_git_decision, "applied": False, "action": "none"},
        "environment": {
            "python": platform.python_version(),
            "python_implementation": platform.python_implementation(),
            "platform": platform.platform(),
        },
        "elapsed_seconds": _seconds(elapsed_seconds),
    }


def _run_candidate_command(command: Sequence[str], *, timeout_seconds: float, cwd: Path) -> ProcessResult:
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            list(command),
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return ProcessResult(
            tuple(command),
            None,
            True,
            time.perf_counter() - started,
            _tail(exc.stdout or ""),
            _tail(exc.stderr or ""),
        )
    return ProcessResult(
        tuple(command),
        completed.returncode,
        False,
        time.perf_counter() - started,
        _tail(completed.stdout),
        _tail(completed.stderr),
    )


def _apply_git_decision(
    repo_root: Path,
    checkpoint_ref: str,
    decision: Mapping[str, str],
    *,
    changed_paths: Sequence[str],
    apply: bool,
) -> dict[str, Any]:
    if not apply:
        return {"apply_requested": False, "applied": False, "action": "none"}
    if decision.get("value") == "keep":
        return {"apply_requested": True, "applied": False, "action": "keep"}
    _git(["reset", "--hard", checkpoint_ref], repo_root)
    if changed_paths:
        _git(["clean", "-fd", "--", *changed_paths], repo_root)
    return {
        "apply_requested": True,
        "applied": True,
        "action": "reset-hard-clean",
        "target": checkpoint_ref,
        "cleaned_paths": list(changed_paths),
    }


def _git_changed_paths(repo_root: Path, checkpoint_ref: str) -> list[str]:
    tracked = _git(["diff", "--name-only", checkpoint_ref, "--"], repo_root)
    untracked = _git(["ls-files", "--others", "--exclude-standard"], repo_root)
    paths = {path for path in [*tracked.splitlines(), *untracked.splitlines()] if path}
    return sorted(paths)


def _git_commit(repo_root: Path) -> str | None:
    try:
        return _git(["rev-parse", "HEAD"], repo_root).strip()
    except RuntimeError:
        return None


def _git(args: Sequence[str], repo_root: Path) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo_root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip() or f"git {' '.join(args)} failed")
    return completed.stdout


def _path_gate(
    changed_paths: Sequence[str],
    *,
    editable_paths: Sequence[str],
    frozen_paths: Sequence[str],
) -> dict[str, Any]:
    normalized_editable = tuple(_normalize_repo_path(path) for path in editable_paths)
    normalized_frozen = tuple(_normalize_repo_path(path) for path in frozen_paths)
    normalized_changed = tuple(_normalize_repo_path(path) for path in changed_paths)
    frozen_touched = [path for path in normalized_changed if _path_matches_any(path, normalized_frozen)]
    outside_editable = [path for path in normalized_changed if not _path_matches_any(path, normalized_editable)]
    return {
        "passed": not frozen_touched and not outside_editable,
        "frozen_touched": frozen_touched,
        "outside_editable": outside_editable,
    }


def _combined_path_gate(pre_gate: Mapping[str, Any], post_gate: Mapping[str, Any]) -> dict[str, Any]:
    frozen_touched = sorted(
        set(_string_list(pre_gate.get("frozen_touched")) + _string_list(post_gate.get("frozen_touched")))
    )
    outside_editable = sorted(
        set(_string_list(pre_gate.get("outside_editable")) + _string_list(post_gate.get("outside_editable")))
    )
    return {
        "passed": pre_gate.get("passed") is True and post_gate.get("passed") is True,
        "frozen_touched": frozen_touched,
        "outside_editable": outside_editable,
        "pre": dict(pre_gate),
        "post": dict(post_gate),
    }


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return []
    return [item for item in value if isinstance(item, str)]


def _path_matches_any(path: str, roots: Sequence[str]) -> bool:
    return any(path == root or path.startswith(f"{root}/") for root in roots)


def _normalize_repo_path(path: str) -> str:
    return path.replace("\\", "/").strip("/")


def _load_json_object(path: Path) -> Mapping[str, Any]:
    try:
        with path.expanduser().open(encoding="utf-8") as file:
            value = json.load(file)
    except OSError as exc:
        raise ValueError(f"Could not read benchmark JSON at {path}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise ValueError(f"Benchmark JSON must be an object: {path}.")
    return value


def _resolve_repo_path(repo_root: Path, path: Path) -> Path:
    expanded = path.expanduser()
    if expanded.is_absolute():
        return expanded
    return repo_root / expanded


def _error_payload(exc: BaseException) -> dict[str, str]:
    return {"type": type(exc).__name__, "message": str(exc)}


def _gate_payload(candidate: Mapping[str, Any]) -> Mapping[str, Any]:
    gate = candidate.get("gate")
    if not isinstance(gate, Mapping):
        return {}
    return gate


def _size_checks(
    baseline: Mapping[str, Any],
    candidate: Mapping[str, Any],
    *,
    max_canonical_json_bytes_ratio: float | None,
    max_extractable_json_bytes_ratio: float | None,
) -> list[dict[str, Any]]:
    checks = []
    if max_canonical_json_bytes_ratio is not None:
        checks.append(
            _ratio_check(
                "canonical_json_bytes_ratio",
                _path_get(candidate, ("benchmark", "bank", "size", "canonical_json_bytes")),
                _path_get(baseline, ("benchmark", "bank", "size", "canonical_json_bytes")),
                "<=",
                max_canonical_json_bytes_ratio,
            )
        )
    if max_extractable_json_bytes_ratio is not None:
        checks.append(
            _ratio_check(
                "extractable_json_bytes_ratio",
                _path_get(candidate, ("benchmark", "bank", "size", "extractable_json_bytes")),
                _path_get(baseline, ("benchmark", "bank", "size", "extractable_json_bytes")),
                "<=",
                max_extractable_json_bytes_ratio,
            )
        )
    return checks


def _ratio_check(
    name: str, candidate_value: Any, baseline_value: Any, operator: str, threshold: float
) -> dict[str, Any]:
    ratio = _optional_ratio(candidate_value, baseline_value)
    passed = ratio is not None and ratio <= threshold
    return {"name": name, "actual": ratio, "operator": operator, "threshold": threshold, "passed": passed}


def _timing_summary(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "cold_compile_seconds": _path_get(payload, ("benchmark", "summary", "cold_compile_seconds")),
        "warm_cached_compile_seconds": _path_get(payload, ("benchmark", "summary", "warm_cached_compile_seconds")),
        "target_bytes_per_second": _path_get(payload, ("benchmark", "summary", "target_bytes_per_second")),
        "elapsed_seconds": payload.get("elapsed_seconds"),
    }


def _size_summary(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "canonical_json_bytes": _path_get(payload, ("benchmark", "bank", "size", "canonical_json_bytes")),
        "extractable_json_bytes": _path_get(payload, ("benchmark", "bank", "size", "extractable_json_bytes")),
        "native_source_bytes": _path_get(payload, ("benchmark", "bank", "size", "native_source_bytes")),
        "active_patterns": _path_get(payload, ("bank", "stats", "active_totals", "patterns")),
        "active_names": _path_get(payload, ("bank", "stats", "active_totals", "names")),
        "active_entities": _path_get(payload, ("bank", "stats", "active_totals", "entities")),
    }


def _required_positive_number(payload: Mapping[str, Any], path: Sequence[str]) -> float:
    value = _path_get(payload, path)
    number = _finite_number(value)
    if number is None or number <= 0:
        dotted = ".".join(path)
        raise ValueError(f"Benchmark field {dotted} must be a finite positive number.")
    return number


def _path_get(payload: Mapping[str, Any], path: Sequence[str]) -> Any:
    current: Any = payload
    for key in path:
        if not isinstance(current, Mapping) or key not in current:
            return None
        current = current[key]
    return current


def _nested_bool(payload: Mapping[str, Any], path: Sequence[str]) -> bool:
    return _path_get(payload, path) is True


def _optional_ratio(candidate_value: Any, baseline_value: Any) -> float | None:
    candidate_number = _finite_number(candidate_value)
    baseline_number = _finite_number(baseline_value)
    if candidate_number is None or baseline_number is None or candidate_number <= 0 or baseline_number <= 0:
        return None
    return _ratio(candidate_number, baseline_number)


def _ratio(candidate_number: float, baseline_number: float) -> float:
    return round(candidate_number / baseline_number, 6)


def _finite_number(value: Any) -> float | None:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None
    try:
        parsed = float(value)
    except OverflowError:
        return None
    if not math.isfinite(parsed):
        return None
    return parsed


def _validate_positive_number(value: float, name: str) -> None:
    if _finite_number(value) is None or value <= 0:
        raise ValueError(f"{name} must be a finite positive number.")


def _validate_nonnegative_ratio(value: float, name: str) -> None:
    if _finite_number(value) is None or value < 0 or value >= 1:
        raise ValueError(f"{name} must be finite, nonnegative, and less than 1.")


def _timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _seconds(value: float) -> float:
    return round(value, 9)


def _tail(value: str | bytes | None, *, max_chars: int = 4_000) -> str:
    if value is None:
        return ""
    text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value
    if len(text) <= max_chars:
        return text
    return text[-max_chars:]


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run and score one NERB autoresearch bank-construction experiment.",
    )
    parser.add_argument("--baseline-benchmark-json", type=Path, required=True)
    parser.add_argument("--candidate-benchmark-json", type=Path, required=True)
    parser.add_argument("--results-jsonl", type=Path, default=DEFAULT_RESULTS_JSONL)
    parser.add_argument("--description", required=True)
    parser.add_argument("--timeout-seconds", type=_positive_float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--min-improvement-ratio", type=_nonnegative_ratio, default=DEFAULT_MIN_IMPROVEMENT_RATIO)
    parser.add_argument(
        "--max-canonical-json-bytes-ratio",
        type=_positive_float,
        default=DEFAULT_MAX_CANONICAL_JSON_BYTES_RATIO,
    )
    parser.add_argument(
        "--max-extractable-json-bytes-ratio",
        type=_positive_float,
        default=DEFAULT_MAX_EXTRACTABLE_JSON_BYTES_RATIO,
    )
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--checkpoint-ref", default="HEAD")
    parser.add_argument("--editable-path", dest="editable_paths", action="append", default=[])
    parser.add_argument("--frozen-path", dest="frozen_paths", action="append", default=[])
    parser.add_argument("--apply-git-decision", action="store_true")
    parser.add_argument("--candidate-command", nargs=argparse.REMAINDER)
    parsed = parser.parse_args(argv)
    if not parsed.candidate_command:
        parser.error("--candidate-command is required and must include at least one command token")
    return parsed


def _positive_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("value must be a finite positive number")
    return parsed


def _nonnegative_ratio(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed < 0 or parsed >= 1:
        raise argparse.ArgumentTypeError("value must be finite, nonnegative, and less than 1")
    return parsed

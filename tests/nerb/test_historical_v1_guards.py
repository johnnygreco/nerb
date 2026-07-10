from __future__ import annotations

from pathlib import Path

import pytest

from nerb.autoresearch import HISTORICAL_V1_NOTICE, _parse_args, main, run_autoresearch, score_candidate


def _historical_args(tmp_path: Path) -> list[str]:
    return [
        "--baseline-benchmark-json",
        str(tmp_path / "baseline.json"),
        "--candidate-benchmark-json",
        str(tmp_path / "candidate.json"),
        "--description",
        "historical diagnostic",
        "--candidate-command",
        "true",
    ]


def _with_historical_option(args: list[str], option: str) -> list[str]:
    candidate_command_index = args.index("--candidate-command")
    return [*args[:candidate_command_index], option, *args[candidate_command_index:]]


def test_autoresearch_cli_rejects_retired_v1_without_explicit_historical_opt_in(tmp_path: Path) -> None:
    with pytest.raises(SystemExit, match="test split") as exc_info:
        main(_historical_args(tmp_path))

    assert str(exc_info.value) == HISTORICAL_V1_NOTICE


@pytest.mark.parametrize("unsafe_flag", ["--apply-git-decision", "--promote-kept-benchmark"])
def test_autoresearch_cli_never_applies_historical_v1_decisions(tmp_path: Path, unsafe_flag: str) -> None:
    args = _with_historical_option(_historical_args(tmp_path), "--allow-historical-v1")
    args = _with_historical_option(args, unsafe_flag)
    with pytest.raises(SystemExit, match="cannot apply git decisions or promote"):
        main(args)


def test_autoresearch_parser_records_explicit_historical_opt_in(tmp_path: Path) -> None:
    args = _parse_args(_with_historical_option(_historical_args(tmp_path), "--allow-historical-v1"))

    assert args.allow_historical_v1 is True


def test_core_autoresearch_helper_fails_closed_before_touching_historical_artifacts(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="test split"):
        run_autoresearch(
            baseline_benchmark_json=tmp_path / "missing-baseline.json",
            candidate_benchmark_json=tmp_path / "missing-candidate.json",
            results_jsonl=tmp_path / "must-not-exist.jsonl",
            description="blocked historical run",
        )

    assert not (tmp_path / "must-not-exist.jsonl").exists()


@pytest.mark.parametrize("unsafe_flag", ["apply", "promote"])
def test_core_autoresearch_helper_blocks_historical_mutations(
    tmp_path: Path,
    unsafe_flag: str,
) -> None:
    with pytest.raises(ValueError, match="cannot apply git decisions or promote"):
        run_autoresearch(
            baseline_benchmark_json=tmp_path / "missing-baseline.json",
            candidate_benchmark_json=tmp_path / "missing-candidate.json",
            results_jsonl=tmp_path / "must-not-exist.jsonl",
            description="blocked historical mutation",
            allow_historical_v1=True,
            apply_git_decision=unsafe_flag == "apply",
            promote_kept_benchmark=unsafe_flag == "promote",
        )


def test_historical_score_helper_also_requires_explicit_opt_in() -> None:
    with pytest.raises(ValueError, match="test split"):
        score_candidate({}, {})

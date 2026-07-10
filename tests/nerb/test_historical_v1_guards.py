from __future__ import annotations

import ast
import json
import sys
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import ModuleType

import pytest

from nerb.autoresearch import HISTORICAL_V1_NOTICE, _parse_args, main, run_autoresearch, score_candidate

REPO_ROOT = Path(__file__).resolve().parents[2]
HERO_GENERATOR_PATH = REPO_ROOT / "examples" / "generate_benchmark_hero_images.py"


def _load_hero_generator() -> ModuleType:
    spec = spec_from_file_location("nerb_historical_hero_generator_test", HERO_GENERATOR_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError(f"Could not load {HERO_GENERATOR_PATH}")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


def test_hero_generator_fails_closed_before_import_or_output_side_effects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_hero_generator()
    output_dir = tmp_path / "must-not-exist"

    def unexpected_import(_name: str) -> None:
        raise AssertionError("historical generator imported plotting dependencies before its opt-in guard")

    monkeypatch.setattr(module, "import_module", unexpected_import)
    monkeypatch.setattr(sys, "argv", [str(HERO_GENERATOR_PATH), "--output-dir", str(output_dir)])

    with pytest.raises(SystemExit, match="retired Enron v1 evaluator"):
        module.main()

    assert not output_dir.exists()


def test_historical_hero_panels_keep_their_watermark_calls() -> None:
    tree = ast.parse(HERO_GENERATOR_PATH.read_text(encoding="utf-8"))
    functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}

    for function_name in ("_render_enron_quality_performance", "_render_autoresearch_objective"):
        calls = [node for node in ast.walk(functions[function_name]) if isinstance(node, ast.Call)]
        assert any(isinstance(call.func, ast.Name) and call.func.id == "_historical_watermark" for call in calls)


def test_retained_historical_artifacts_are_marked_and_unmarked_plots_stay_absent() -> None:
    measurements_path = REPO_ROOT / "examples" / "artifacts" / "hero-images" / "hero_measurements.json"
    measurements = json.loads(measurements_path.read_text(encoding="utf-8"))
    assert measurements["claim_status"] == "historical_unsupported"

    results_path = REPO_ROOT / "examples" / "artifacts" / "autoresearch" / "results.jsonl"
    results = [json.loads(line) for line in results_path.read_text(encoding="utf-8").splitlines() if line]
    assert results
    assert all(result["claim_status"] == "historical_non_promotable" for result in results)

    retired_plots = (
        REPO_ROOT / "docs" / "assets" / "images" / "enron-quality-performance.png",
        REPO_ROOT / "examples" / "artifacts" / "hero-images" / "enron-quality-performance.png",
        REPO_ROOT / "examples" / "artifacts" / "hero-images" / "autoresearch-objective.png",
    )
    assert all(not path.exists() for path in retired_plots)

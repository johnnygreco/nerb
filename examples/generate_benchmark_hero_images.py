from __future__ import annotations

import argparse
import json
from collections.abc import Mapping, Sequence
from importlib import import_module
from pathlib import Path
from typing import Any

from nerb.benchmarks import benchmark_bank
from nerb.enron_benchmark import _load_benchmark_documents, _quality_summary

EXAMPLE_DIR = Path(__file__).resolve().parent
DEFAULT_OUTPUT_DIR = EXAMPLE_DIR / "artifacts" / "hero-images"
DEFAULT_ENRON_ARTIFACT_DIR = Path(".nerb/enron-benchmark/issue-89-candidate")
DEFAULT_AUTORESEARCH_RESULTS_JSONL = Path(".nerb/autoresearch/f1-results.jsonl")
CREATED_AT = "2026-06-09T00:00:00Z"
SCALE_ENTITY_COUNTS = (1_000, 10_000, 50_000, 100_000)


def main() -> None:
    args = _parse_args()
    try:
        matplotlib = import_module("matplotlib")
        matplotlib.use("Agg")
        plt = import_module("matplotlib.pyplot")
    except ModuleNotFoundError as exc:  # pragma: no cover - command usage.
        raise SystemExit(
            "matplotlib is required. Run: "
            "uv run --with matplotlib==3.10.9 python examples/generate_benchmark_hero_images.py"
        ) from exc

    output_dir = args.output_dir.expanduser()
    output_dir.mkdir(parents=True, exist_ok=True)
    _configure_matplotlib(plt)

    enron = _load_enron_measurement(args.enron_artifact_dir, quality_documents=args.quality_documents)
    scale = _measure_scale(args.scale_entities)
    autoresearch = _autoresearch_objective_measurement(args.autoresearch_results_jsonl)
    measurements = {
        "schema_version": "nerb.hero_measurements.v1",
        "created_at": CREATED_AT,
        "enron": enron,
        "scale": scale,
        "autoresearch": autoresearch,
    }
    _write_json(output_dir / "hero_measurements.json", measurements)
    _render_enron_quality_performance(plt, enron, output_dir / "enron-quality-performance.png")
    _render_scale_100k(plt, scale, output_dir / "scale-100k-entities.png")
    _render_autoresearch_objective(plt, autoresearch, output_dir / "autoresearch-objective.png")

    print(f"Wrote benchmark-grounded hero images to {output_dir}")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate benchmark-grounded NERB hero plot assets.")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument(
        "--enron-artifact-dir",
        type=Path,
        default=DEFAULT_ENRON_ARTIFACT_DIR,
        help="Private .nerb benchmark directory containing train.jsonl, test.jsonl, bank.json, and benchmark.json.",
    )
    parser.add_argument(
        "--quality-documents",
        type=_positive_int,
        default=1_000,
        help="Number of train and held-out test documents to rescore for exact-span NER metrics.",
    )
    parser.add_argument(
        "--scale-entities",
        type=_positive_int,
        nargs="*",
        default=list(SCALE_ENTITY_COUNTS),
        help="Entity counts for synthetic scale measurements.",
    )
    parser.add_argument(
        "--autoresearch-results-jsonl",
        type=Path,
        default=DEFAULT_AUTORESEARCH_RESULTS_JSONL,
        help="Autoresearch result log used for the objective plot.",
    )
    return parser.parse_args()


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be a positive integer")
    return parsed


def _load_enron_measurement(artifact_dir: Path, *, quality_documents: int) -> dict[str, Any]:
    artifact_dir = artifact_dir.expanduser()
    benchmark_path = artifact_dir / "benchmark.json"
    bank_path = artifact_dir / "bank.json"
    train_path = artifact_dir / "train.jsonl"
    test_path = artifact_dir / "test.jsonl"
    missing = [path for path in (benchmark_path, bank_path, train_path, test_path) if not path.exists()]
    if missing:
        raise SystemExit(
            "Missing Enron benchmark artifacts: "
            + ", ".join(str(path) for path in missing)
            + ". Run scripts/enron_bank_build_benchmark.py first, or pass --enron-artifact-dir."
        )

    benchmark = _read_json(benchmark_path)
    bank = _read_json(bank_path)
    train_documents = _load_benchmark_documents(train_path, quality_documents)
    test_documents = _load_benchmark_documents(test_path, quality_documents)
    options = {
        "max_batch_documents": max(100, len(train_documents), len(test_documents)),
        "max_batch_text_bytes": 64 * 1024 * 1024,
    }
    quality = {
        "train": _quality_summary(bank, train_documents, options),
        "test": _quality_summary(bank, test_documents, options),
    }
    return {
        "artifact_dir": str(artifact_dir),
        "dataset": benchmark["manifest"]["dataset"],
        "sampling": benchmark["manifest"]["sampling"],
        "prep_summary": benchmark["manifest"]["prep_summary"],
        "artifact_hashes": benchmark["manifest"]["artifact_hashes"],
        "quality_document_limit": quality_documents,
        "quality": quality,
        "bank": {
            "hash": benchmark["bank"]["hash"],
            "stats": benchmark["bank"]["stats"],
            "size": benchmark["benchmark"]["bank"]["size"],
        },
        "benchmark_summary": benchmark["benchmark"]["summary"],
        "compile": benchmark["benchmark"]["compile"],
        "target_tier": benchmark["benchmark"]["tiers"]["target"],
    }


def _measure_scale(entity_counts: Sequence[int]) -> dict[str, Any]:
    cases: list[dict[str, Any]] = []
    for entity_count in entity_counts:
        bank = _compact_entity_bank(entity_count)
        token_count = min(entity_count, 2_000)
        document = " ".join(f"v{index}" for index in range(token_count))
        benchmark = benchmark_bank(
            bank,
            documents={
                "baseline": [{"document_id": f"scale_{entity_count}_baseline", "text": document[:5000]}],
                "target": [{"document_id": f"scale_{entity_count}_target", "text": document}],
                "stress": [{"document_id": f"scale_{entity_count}_stress", "text": f"{document} {document}"}],
            },
            options={"benchmark_iterations": 1},
        )
        cases.append(
            {
                "entities": entity_count,
                "names": benchmark["bank"]["stats"]["active_totals"]["names"],
                "patterns": benchmark["bank"]["stats"]["active_totals"]["patterns"],
                "source_bytes": benchmark["benchmark"]["bank"]["size"]["native_source_bytes"]
                if "benchmark" in benchmark
                else benchmark["bank"]["size"]["native_source_bytes"],
                "canonical_json_bytes": benchmark["bank"]["size"]["canonical_json_bytes"],
                "cold_compile_seconds": benchmark["summary"]["cold_compile_seconds"],
                "warm_cached_compile_seconds": benchmark["summary"]["warm_cached_compile_seconds"],
                "target_bytes": benchmark["tiers"]["target"]["bytes"],
                "target_records": benchmark["tiers"]["target"]["record_count"],
                "target_bytes_per_second": benchmark["summary"]["target_bytes_per_second"],
            }
        )
    return {
        "description": "Measured deterministic compact JSON banks with one literal pattern per entity.",
        "cases": cases,
        "limits": {
            "max_source_bytes": 64 * 1024 * 1024,
            "max_entities": 100_000,
            "max_patterns": 100_000,
        },
    }


def _compact_entity_bank(entity_count: int) -> dict[str, Any]:
    entities: dict[str, Any] = {}
    for index in range(entity_count):
        entity_id = f"e{index}"
        value = f"v{index}"
        entities[entity_id] = {
            "description": "",
            "status": "active",
            "regex_flags": [],
            "names": {
                "n": {
                    "canonical": value,
                    "description": "",
                    "status": "active",
                    "patterns": {
                        "p": {
                            "kind": "literal",
                            "value": value,
                            "description": "",
                            "status": "active",
                            "priority": 0,
                            "case_sensitive": True,
                            "normalize_whitespace": False,
                            "left_boundary": "none",
                            "right_boundary": "none",
                            "metadata": {},
                        }
                    },
                    "metadata": {},
                }
            },
            "metadata": {},
        }
    return {
        "schema_version": "nerb.bank.v1",
        "id": f"compact_scale_{entity_count}",
        "name": f"Compact Scale {entity_count}",
        "description": "Deterministic compact one-pattern-per-entity scale bank.",
        "version": "2026.06.09",
        "status": "active",
        "created_at": CREATED_AT,
        "updated_at": CREATED_AT,
        "unicode_normalization": "none",
        "default_regex_flags": [],
        "entities": entities,
        "metadata": {"source": "examples.generate_benchmark_hero_images"},
    }


def _autoresearch_objective_measurement(results_jsonl: Path) -> dict[str, Any]:
    rows = [json.loads(line) for line in results_jsonl.expanduser().read_text(encoding="utf-8").splitlines() if line]
    if not rows:
        raise ValueError(f"Autoresearch result log is empty: {results_jsonl}.")
    row = rows[-1]
    baseline_path = Path(row["evaluator"]["baseline_benchmark_json"])
    candidate_path = Path(row["evaluator"]["candidate_benchmark_json"])
    baseline_benchmark = _read_json(baseline_path)
    candidate_benchmark = _read_json(candidate_path)
    baseline_quality = baseline_benchmark["quality"]["test"]
    candidate_quality = candidate_benchmark["quality"]["test"]
    timings = row["score"]["timings"]
    return {
        "result_log": str(results_jsonl),
        "primary_metric": row["score"]["primary"]["field"],
        "lower_is_better": row["score"]["primary"]["lower_is_better"],
        "baseline": {
            "precision": baseline_quality["precision"],
            "recall": baseline_quality["recall"],
            "f1": baseline_quality["f1"],
            "cold_compile_seconds": baseline_benchmark["benchmark"]["summary"]["cold_compile_seconds"],
            "target_bytes_per_second": baseline_benchmark["benchmark"]["summary"]["target_bytes_per_second"],
        },
        "candidate": {
            "precision": candidate_quality["precision"],
            "recall": candidate_quality["recall"],
            "f1": candidate_quality["f1"],
            "cold_compile_seconds": timings["cold_compile_seconds"],
            "target_bytes_per_second": timings["target_bytes_per_second"],
        },
        "decision": row["decision"],
        "gates": {
            "quality": row["score"]["gate"]["quality_passed"],
            "performance": row["score"]["gate"]["performance_passed"],
            "size": row["score"]["size"]["passed"],
            "path": row["repo"]["path_gate"]["passed"],
        },
    }


def _render_enron_quality_performance(plt: Any, measurement: Mapping[str, Any], path: Path) -> None:
    fig, axes = plt.subplots(2, 2, figsize=(15.8, 9.3))
    fig.patch.set_facecolor("#f8fafc")
    _figure_title(
        fig,
        "Enron Entity-Bank Benchmark",
        "Real prepared split, exact span-level NER metrics, and Rust-backed construction measurements.",
    )

    train = measurement["quality"]["train"]
    test = measurement["quality"]["test"]
    ax = axes[0][0]
    _panel(ax)
    x = [0, 1, 2]
    width = 0.35
    train_values = [train["precision"], train["recall"], train["f1"]]
    test_values = [test["precision"], test["recall"], test["f1"]]
    ax.bar([i - width / 2 for i in x], train_values, width=width, color="#0f766e", label="Train")
    ax.bar([i + width / 2 for i in x], test_values, width=width, color="#2563eb", label="Held-out test")
    ax.set_ylim(0, 1.08)
    ax.set_xticks(x)
    ax.set_xticklabels(["Precision", "Recall", "F1"])
    ax.set_ylabel("Exact-span score")
    ax.set_title("Standard NER metrics")
    ax.legend(frameon=False, loc="lower right")
    for index, value in enumerate(test_values):
        ax.text(index + width / 2, value + 0.025, f"{value:.3f}", ha="center", fontsize=8.5, color="#1e293b")

    ax = axes[0][1]
    _panel(ax)
    categories = ["TP", "FP", "FN"]
    train_counts = [train["true_positive"], train["false_positive"], train["false_negative"]]
    test_counts = [test["true_positive"], test["false_positive"], test["false_negative"]]
    ax.bar([i - width / 2 for i in x], train_counts, width=width, color="#14b8a6", label="Train")
    ax.bar([i + width / 2 for i in x], test_counts, width=width, color="#f97316", label="Held-out test")
    ax.set_xticks(x)
    ax.set_xticklabels(categories)
    ax.set_yscale("symlog", linthresh=1)
    ax.set_title("Confusion counts")
    ax.set_ylabel("Span count")
    ax.legend(frameon=False, loc="upper right")

    ax = axes[1][0]
    _panel(ax)
    prep = measurement["prep_summary"]
    bank_totals = measurement["bank"]["stats"]["active_totals"]
    labels = ["Train docs", "Test docs", "Entities", "Names", "Patterns"]
    values = [
        prep["train_records"],
        prep["test_records"],
        bank_totals["entities"],
        bank_totals["names"],
        bank_totals["patterns"],
    ]
    bars = ax.bar(labels, values, color=["#475569", "#64748b", "#7c3aed", "#0891b2", "#ea580c"])
    ax.set_yscale("log")
    ax.set_title("Prepared split and bank scale")
    ax.set_ylabel("Count, log scale")
    ax.tick_params(axis="x", rotation=20)
    _label_bars(ax, bars, values)

    ax = axes[1][1]
    _panel(ax)
    summary = measurement["benchmark_summary"]
    metrics = {
        "Cold compile\nseconds": summary["cold_compile_seconds"],
        "Warm cache\nseconds": summary["warm_cached_compile_seconds"],
        "Target\nMB/s": summary["target_bytes_per_second"] / 1_000_000,
    }
    bars = ax.bar(list(metrics), list(metrics.values()), color=["#0ea5e9", "#a855f7", "#16a34a"])
    ax.set_title("Construction and extraction")
    ax.set_ylabel("Seconds or MB/s")
    _label_bars(ax, bars, list(metrics.values()), precision=2)

    fig.tight_layout(rect=(0, 0, 1, 0.9), pad=2.1)
    fig.savefig(path, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)


def _render_scale_100k(plt: Any, measurement: Mapping[str, Any], path: Path) -> None:
    cases = list(measurement["cases"])
    entities = [case["entities"] for case in cases]
    fig, axes = plt.subplots(2, 2, figsize=(15.8, 9.3))
    fig.patch.set_facecolor("#f8fafc")
    _figure_title(
        fig,
        "Scale Measurements To 100,000 Entities",
        "Compact JSON banks with one literal pattern per entity; source and native limits raised to cover this scale.",
    )
    series = [
        ("Cold compile seconds", [case["cold_compile_seconds"] for case in cases], "#2563eb", "Seconds"),
        ("Warm cache path seconds", [case["warm_cached_compile_seconds"] for case in cases], "#7c3aed", "Seconds"),
        ("Native source MB", [case["source_bytes"] / 1_000_000 for case in cases], "#ea580c", "MB"),
        ("Target throughput MB/s", [case["target_bytes_per_second"] / 1_000_000 for case in cases], "#0f766e", "MB/s"),
    ]
    for ax, (title, values, color, ylabel) in zip(axes.ravel(), series, strict=True):
        _panel(ax)
        ax.plot(entities, values, marker="o", linewidth=2.6, color=color)
        ax.scatter(entities, values, s=72, color=color, edgecolor="white", linewidth=1.1, zorder=3)
        ax.set_xscale("log")
        ax.set_xticks(entities)
        ax.set_xticklabels([f"{value:,}" for value in entities])
        ax.set_title(title)
        ax.set_ylabel(ylabel)
        ax.set_xlabel("Entities / names / patterns")
        for x_value, y_value in zip(entities, values, strict=True):
            ax.text(x_value, y_value, f"{y_value:.2f}", fontsize=8.5, color="#1e293b", ha="left", va="bottom")
    fig.tight_layout(rect=(0, 0, 1, 0.9), pad=2.1)
    fig.savefig(path, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)


def _render_autoresearch_objective(plt: Any, measurement: Mapping[str, Any], path: Path) -> None:
    fig, axes = plt.subplots(1, 3, figsize=(15.8, 5.8))
    fig.patch.set_facecolor("#f8fafc")
    _figure_title(
        fig,
        "Autoresearch Optimizes Held-Out F1",
        "Candidate decisions prioritize exact-span NER quality; compile and size remain gates, not the primary reward.",
    )
    baseline = measurement["baseline"]
    candidate = measurement["candidate"]

    ax = axes[0]
    _panel(ax)
    labels = ["Precision", "Recall", "F1"]
    baseline_values = [baseline["precision"], baseline["recall"], baseline["f1"]]
    candidate_values = [candidate["precision"], candidate["recall"], candidate["f1"]]
    x = list(range(len(labels)))
    width = 0.34
    ax.bar([i - width / 2 for i in x], baseline_values, width=width, color="#64748b", label="Baseline")
    ax.bar([i + width / 2 for i in x], candidate_values, width=width, color="#0f766e", label="Candidate")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylim(0, 1)
    ax.set_title("Primary objective")
    ax.legend(frameon=False, loc="lower right")

    ax = axes[1]
    _panel(ax)
    values = [baseline["cold_compile_seconds"] * 1000, candidate["cold_compile_seconds"] * 1000]
    bars = ax.bar(["Baseline", "Candidate"], values, color=["#0ea5e9", "#a855f7"])
    ax.set_title("Performance gate context")
    ax.set_ylabel("Cold compile milliseconds")
    _label_bars(ax, bars, values, precision=2)

    ax = axes[2]
    _panel(ax)
    gates = list(measurement["gates"])
    gate_values = [1 if measurement["gates"][gate] else 0 for gate in gates]
    ax.bar(gates, gate_values, color=["#16a34a" if value else "#dc2626" for value in gate_values])
    ax.set_ylim(0, 1.2)
    ax.set_yticks([0, 1])
    ax.set_yticklabels(["fail", "pass"])
    ax.set_title("Keep/discard guards")
    ax.tick_params(axis="x", rotation=20)

    fig.tight_layout(rect=(0, 0, 1, 0.86), pad=2.1)
    fig.savefig(path, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)


def _configure_matplotlib(plt: Any) -> None:
    plt.rcParams.update(
        {
            "figure.dpi": 180,
            "savefig.dpi": 180,
            "font.family": "DejaVu Sans",
            "axes.edgecolor": "#cbd5e1",
            "axes.labelcolor": "#334155",
            "axes.titleweight": "bold",
            "axes.grid": True,
            "grid.color": "#e2e8f0",
            "grid.linewidth": 0.8,
            "xtick.color": "#475569",
            "ytick.color": "#475569",
        }
    )


def _figure_title(fig: Any, title: str, subtitle: str) -> None:
    fig.text(0.03, 0.965, title, fontsize=22, weight="bold", color="#0f172a", va="top")
    fig.text(0.03, 0.925, subtitle, fontsize=10.5, color="#475569", va="top")


def _panel(ax: Any) -> None:
    ax.set_facecolor("#ffffff")
    ax.spines[["top", "right"]].set_visible(False)


def _label_bars(ax: Any, bars: Any, values: Sequence[float], *, precision: int = 0) -> None:
    labels = [f"{value:,.{precision}f}" for value in values]
    ax.bar_label(bars, labels=labels, fontsize=8.5, padding=3, color="#334155")


def _read_json(path: Path) -> Mapping[str, Any]:
    with path.open(encoding="utf-8") as file:
        value = json.load(file)
    if not isinstance(value, Mapping):
        raise ValueError(f"{path} must contain a JSON object.")
    return value


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n")


if __name__ == "__main__":
    main()

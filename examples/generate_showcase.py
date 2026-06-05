from __future__ import annotations

import json
import re
from collections.abc import Mapping
from importlib import import_module
from pathlib import Path
from typing import Any

from nerb import benchmark_bank, extract_report, extract_text, load_bank, validate_bank
from nerb.benchmarks import make_synthetic_bank

EXAMPLE_DIR = Path(__file__).resolve().parent
BANK_DIR = EXAMPLE_DIR / "banks"
DOCUMENT_DIR = EXAMPLE_DIR / "documents"
ARTIFACT_DIR = EXAMPLE_DIR / "artifacts"
EXTRACTION_DIR = ARTIFACT_DIR / "extractions"
REPORT_DIR = ARTIFACT_DIR / "reports"
BENCHMARK_DIR = ARTIFACT_DIR / "benchmarks"
SCALE_DIR = ARTIFACT_DIR / "scale"
FIGURE_DIR = ARTIFACT_DIR / "figures"

DOMAINS: dict[str, dict[str, str]] = {
    "security_ops": {
        "title": "Security Ops",
        "bank": "security_ops.json",
        "document": "security_ops.txt",
        "accent": "#0f766e",
        "tagline": "Route incident facts into local response memory.",
    },
    "revenue_ops": {
        "title": "Revenue Ops",
        "bank": "revenue_ops.json",
        "document": "revenue_ops.txt",
        "accent": "#b45309",
        "tagline": "Resolve account notes into CRM and playbook actions.",
    },
    "compliance_ops": {
        "title": "Compliance Ops",
        "bank": "compliance_ops.json",
        "document": "compliance_ops.txt",
        "accent": "#6d28d9",
        "tagline": "Bind audit notes to evidence, systems, and controls.",
    },
}

ENTITY_COLORS = [
    "#14b8a6",
    "#f97316",
    "#6366f1",
    "#e11d48",
    "#84cc16",
    "#0ea5e9",
    "#a855f7",
    "#facc15",
    "#22c55e",
    "#f43f5e",
]

SCALE_CASES = [
    {
        "id": "team_cache_1k",
        "label": "Team cache",
        "names": 250,
        "patterns_per_name": 4,
        "entities": 16,
        "document_bytes": 50_000,
        "literal_ratio": 0.75,
    },
    {
        "id": "org_cache_4k",
        "label": "Org cache",
        "names": 1_000,
        "patterns_per_name": 4,
        "entities": 64,
        "document_bytes": 150_000,
        "literal_ratio": 0.75,
    },
    {
        "id": "fleet_cache_10k",
        "label": "Fleet cache",
        "names": 2_500,
        "patterns_per_name": 4,
        "entities": 128,
        "document_bytes": 300_000,
        "literal_ratio": 0.75,
    },
]


def main() -> None:
    try:
        matplotlib = import_module("matplotlib")
        matplotlib.use("Agg")
        plt = import_module("matplotlib.pyplot")
    except ModuleNotFoundError as exc:
        message = (
            "matplotlib is required for showcase figures. "
            "Run: uv run --with matplotlib python examples/generate_showcase.py"
        )
        raise SystemExit(message) from exc

    _configure_matplotlib(plt)
    _ensure_artifact_dirs()

    summaries: list[dict[str, Any]] = []
    benchmark_results: dict[str, dict[str, Any]] = {}

    for domain_id, spec in DOMAINS.items():
        bank_path = BANK_DIR / spec["bank"]
        document_path = DOCUMENT_DIR / spec["document"]
        bank = load_bank(bank_path)
        document = document_path.read_text(encoding="utf-8").strip()

        validation = validate_bank(bank, base_path=bank_path.parent)
        if not validation["valid"]:
            raise SystemExit(f"{bank_path} failed validation: {json.dumps(validation['diagnostics'], indent=2)}")

        extraction = extract_text(bank, document)
        report = extract_report(bank, document, options={"context_chars": 36, "include_metadata": True})
        benchmark = benchmark_bank(
            bank,
            documents=_benchmark_documents(domain_id, document),
            options={"benchmark_iterations": 3, "stress_multiplier": 4},
        )

        _write_json(EXTRACTION_DIR / f"{domain_id}.json", extraction)
        _write_json(REPORT_DIR / f"{domain_id}.json", report)
        _write_json(BENCHMARK_DIR / f"{domain_id}.json", benchmark)
        _render_detection_figure(plt, domain_id, spec, document, report)

        summaries.append(_domain_summary(domain_id, spec, bank, document_path, extraction, report, benchmark))
        benchmark_results[domain_id] = benchmark

    scale_demo = _run_scale_demo()
    _write_json(SCALE_DIR / "scale_measurements.json", scale_demo)
    _render_scale_throughput_figure(plt, scale_demo)
    _render_scale_compile_figure(plt, scale_demo)
    _render_benchmark_throughput_figure(plt, benchmark_results)
    _render_benchmark_cache_figure(plt, benchmark_results)
    _write_json(ARTIFACT_DIR / "summary.json", {"domains": summaries, "scale": scale_demo})

    print("Wrote NERB showcase artifacts:")
    for path in sorted(ARTIFACT_DIR.rglob("*")):
        if path.is_file():
            print(f"- {path.relative_to(EXAMPLE_DIR)}")


def _configure_matplotlib(plt: Any) -> None:
    plt.rcParams.update(
        {
            "figure.dpi": 160,
            "savefig.dpi": 160,
            "font.family": "DejaVu Sans",
            "axes.titleweight": "bold",
            "axes.labelcolor": "#334155",
            "axes.edgecolor": "#cbd5e1",
            "axes.grid": True,
            "grid.color": "#e2e8f0",
            "grid.linewidth": 0.8,
            "xtick.color": "#475569",
            "ytick.color": "#475569",
        }
    )


def _ensure_artifact_dirs() -> None:
    for directory in (EXTRACTION_DIR, REPORT_DIR, BENCHMARK_DIR, SCALE_DIR, FIGURE_DIR):
        directory.mkdir(parents=True, exist_ok=True)


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n")


def _benchmark_documents(domain_id: str, document: str) -> dict[str, list[dict[str, str]]]:
    first_sentence = document.split(".", 1)[0] + "."
    return {
        "baseline": [{"document_id": f"{domain_id}_baseline", "text": first_sentence}],
        "target": [
            {"document_id": f"{domain_id}_primary", "text": document},
            {"document_id": f"{domain_id}_repeated", "text": f"{document}\n{document}"},
        ],
        "stress": [{"document_id": f"{domain_id}_stress", "text": " ".join([document] * 8)}],
    }


def _run_scale_demo() -> dict[str, Any]:
    cases: list[dict[str, Any]] = []
    for raw_case in SCALE_CASES:
        bank = make_synthetic_bank(
            name_count=int(raw_case["names"]),
            patterns_per_name=int(raw_case["patterns_per_name"]),
            entity_count=int(raw_case["entities"]),
            literal_ratio=float(raw_case["literal_ratio"]),
            bank_id=str(raw_case["id"]),
        )
        document = _scale_document(bank, target_bytes=int(raw_case["document_bytes"]))
        documents = {
            "baseline": [{"document_id": f"{raw_case['id']}_baseline", "text": document[: min(5_000, len(document))]}],
            "target": [{"document_id": f"{raw_case['id']}_target", "text": document}],
            "stress": [{"document_id": f"{raw_case['id']}_stress", "text": f"{document} {document}"}],
        }
        benchmark = benchmark_bank(bank, documents=documents, options={"benchmark_iterations": 2})
        target = benchmark["tiers"]["target"]
        cases.append(
            {
                "id": raw_case["id"],
                "label": raw_case["label"],
                "names": raw_case["names"],
                "entities": raw_case["entities"],
                "patterns": benchmark["bank"]["stats"]["active_totals"]["patterns"],
                "document_bytes": target["bytes"],
                "record_count": target["record_count"],
                "records_per_kb": round(target["record_count"] / max(target["bytes"] / 1024, 1), 3),
                "throughput": target["throughput"],
                "compile": benchmark["compile"],
                "engine": benchmark["engine"],
                "profile": benchmark["bank"]["profile"],
            }
        )

    return {
        "description": "Generated scale demonstration using deterministic synthetic JSON banks and documents.",
        "method": {
            "iterations": 2,
            "document_strategy": "repeat exact active pattern examples until the target byte size is reached",
            "measurement": "warm extraction scan/project/sort throughput plus cold compile and warm cache lookup",
        },
        "cases": cases,
    }


def _scale_document(bank: Mapping[str, Any], *, target_bytes: int) -> str:
    examples = _active_pattern_examples(bank)
    if not examples:
        raise ValueError("Scale demo requires at least one active pattern example.")

    chunks: list[str] = []
    size = 0
    index = 0
    while size < target_bytes:
        token = examples[index % len(examples)]
        separator = " " if chunks else ""
        next_size = size + len(separator.encode("utf-8")) + len(token.encode("utf-8"))
        if chunks and next_size > target_bytes:
            break
        chunks.append(token)
        size = next_size
        index += 1

    return " ".join(chunks)


def _active_pattern_examples(bank: Mapping[str, Any]) -> list[str]:
    examples: list[str] = []
    entities = bank.get("entities", {})
    if not isinstance(entities, Mapping):
        return examples

    for entity in entities.values():
        if not isinstance(entity, Mapping):
            continue
        names = entity.get("names", {})
        if not isinstance(names, Mapping):
            continue
        for name in names.values():
            if not isinstance(name, Mapping):
                continue
            patterns = name.get("patterns", {})
            if not isinstance(patterns, Mapping):
                continue
            for pattern in patterns.values():
                if not isinstance(pattern, Mapping):
                    continue
                metadata = pattern.get("metadata", {})
                if isinstance(metadata, Mapping) and isinstance(metadata.get("benchmark_text"), str):
                    examples.append(metadata["benchmark_text"])
                elif isinstance(pattern.get("value"), str):
                    examples.append(pattern["value"])

    return examples


def _domain_summary(
    domain_id: str,
    spec: Mapping[str, str],
    bank: Mapping[str, Any],
    document_path: Path,
    extraction: Mapping[str, Any],
    report: Mapping[str, Any],
    benchmark: Mapping[str, Any],
) -> dict[str, Any]:
    records = list(extraction["records"])
    return {
        "id": domain_id,
        "title": spec["title"],
        "bank_id": bank["id"],
        "document": str(document_path.relative_to(EXAMPLE_DIR)),
        "record_count": len(records),
        "resolved_record_count": report["summary"]["resolved_record_count"],
        "entity_counts": report["summary"]["entity_counts"],
        "bank_hash": extraction["bank"]["hash"],
        "engine": extraction["engine"],
        "target_bytes_per_second": benchmark["tiers"]["target"]["throughput"]["bytes_per_second"],
        "target_records_per_second": benchmark["tiers"]["target"]["throughput"]["records_per_second"],
    }


def _render_detection_figure(
    plt: Any,
    domain_id: str,
    spec: Mapping[str, str],
    document: str,
    report: Mapping[str, Any],
) -> None:
    records = [item["record"] for item in report["resolved_records"]]
    color_by_entity = _entity_palette(records)
    fig, ax = plt.subplots(figsize=(13.5, 8.8))
    fig.patch.set_facecolor("#f8fafc")
    ax.set_facecolor("#f8fafc")
    ax.set_axis_off()
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)

    accent = spec["accent"]
    _rounded_box(ax, 0.035, 0.89, 0.93, 0.085, facecolor="#ffffff", edgecolor="#dbeafe", linewidth=1.1)
    ax.text(0.055, 0.943, f"{spec['title']} detection map", fontsize=19, weight="bold", color="#0f172a", va="top")
    ax.text(0.055, 0.907, spec["tagline"], fontsize=10.5, color="#475569", va="top")
    ax.text(
        0.845,
        0.936,
        f"{len(records)} resolved spans",
        fontsize=10.5,
        color=accent,
        weight="bold",
        ha="center",
        va="center",
    )

    _rounded_box(ax, 0.035, 0.065, 0.66, 0.795, facecolor="#ffffff", edgecolor="#e2e8f0", linewidth=1.0)
    ax.text(0.055, 0.832, "Document with detected words", fontsize=12, weight="bold", color="#0f172a", va="top")
    _draw_segmented_document(ax, document, records, color_by_entity)

    _rounded_box(ax, 0.72, 0.065, 0.245, 0.795, facecolor="#ffffff", edgecolor="#e2e8f0", linewidth=1.0)
    ax.text(0.74, 0.832, "Agent metadata ledger", fontsize=12, weight="bold", color="#0f172a", va="top")
    _draw_metadata_ledger(ax, report["resolved_records"], color_by_entity)

    fig.savefig(FIGURE_DIR / f"ner_detection_{domain_id}.png", bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)


def _rounded_box(
    ax: Any,
    x: float,
    y: float,
    width: float,
    height: float,
    *,
    facecolor: str,
    edgecolor: str,
    linewidth: float = 1.0,
    radius: float = 0.018,
    alpha: float = 1.0,
) -> None:
    fancy_box_patch = getattr(import_module("matplotlib.patches"), "FancyBboxPatch")
    box = fancy_box_patch(
        (x, y),
        width,
        height,
        boxstyle=f"round,pad=0.008,rounding_size={radius}",
        linewidth=linewidth,
        facecolor=facecolor,
        edgecolor=edgecolor,
        alpha=alpha,
    )
    ax.add_patch(box)


def _entity_palette(records: list[Mapping[str, Any]]) -> dict[str, str]:
    entities = sorted({str(record["entity_id"]) for record in records})
    return {entity: ENTITY_COLORS[index % len(ENTITY_COLORS)] for index, entity in enumerate(entities)}


def _draw_segmented_document(
    ax: Any,
    document: str,
    records: list[Mapping[str, Any]],
    color_by_entity: Mapping[str, str],
) -> None:
    segments = _document_segments(document, records)
    lines = _flow_segments(segments, max_chars=64)
    start_y = 0.775
    line_height = 0.06
    char_width = 0.0085

    for line_index, line in enumerate(lines):
        y = start_y - line_index * line_height
        x = 0.055
        for text, record in line:
            if not text:
                continue
            if record is None:
                ax.text(x, y, text, fontsize=10.8, color="#334155", family="DejaVu Sans Mono", va="top")
            else:
                color = color_by_entity[str(record["entity_id"])]
                ax.text(
                    x,
                    y,
                    text,
                    fontsize=10.8,
                    color="#0f172a",
                    family="DejaVu Sans Mono",
                    weight="bold",
                    va="top",
                    bbox={
                        "boxstyle": "round,pad=0.25",
                        "facecolor": color,
                        "edgecolor": "none",
                        "alpha": 0.22,
                    },
                )
            x += len(text) * char_width
            if record is not None:
                x += 0.005

    legend_y = 0.115
    x = 0.055
    for entity_id, color in color_by_entity.items():
        _rounded_box(ax, x, legend_y, 0.13, 0.035, facecolor="#f8fafc", edgecolor="#e2e8f0", radius=0.01)
        ax.scatter([x + 0.015], [legend_y + 0.017], s=70, color=color, alpha=0.8)
        ax.text(x + 0.03, legend_y + 0.019, entity_id, fontsize=8.7, color="#334155", va="center")
        x += 0.145
        if x > 0.59:
            x = 0.055
            legend_y -= 0.042


def _document_segments(
    document: str,
    records: list[Mapping[str, Any]],
) -> list[tuple[str, Mapping[str, Any] | None]]:
    byte_to_char = _byte_to_char_offsets(document)
    ordered = sorted(records, key=lambda record: (int(record["start"]), int(record["end"])))
    segments: list[tuple[str, Mapping[str, Any] | None]] = []
    cursor = 0

    for record in ordered:
        start = byte_to_char[int(record["start"])]
        end = byte_to_char[int(record["end"])]
        if start > cursor:
            segments.append((document[cursor:start], None))
        segments.append((document[start:end], record))
        cursor = end

    if cursor < len(document):
        segments.append((document[cursor:], None))
    return segments


def _byte_to_char_offsets(text: str) -> dict[int, int]:
    offsets: dict[int, int] = {}
    byte_offset = 0
    for char_index, char in enumerate(text):
        offsets[byte_offset] = char_index
        byte_offset += len(char.encode("utf-8"))
    offsets[byte_offset] = len(text)
    return offsets


def _flow_segments(
    segments: list[tuple[str, Mapping[str, Any] | None]],
    *,
    max_chars: int,
) -> list[list[tuple[str, Mapping[str, Any] | None]]]:
    lines: list[list[tuple[str, Mapping[str, Any] | None]]] = [[]]
    line_len = 0

    for text, record in segments:
        tokens = [text] if record is not None else re.findall(r"\S+|\s+", text)
        for token in tokens:
            if token.isspace():
                if line_len == 0:
                    continue
                normalized = " "
                lines[-1].append((normalized, None))
                line_len += 1
                continue

            token_len = len(token)
            if line_len and line_len + token_len > max_chars:
                while lines[-1] and lines[-1][-1][0].isspace():
                    lines[-1].pop()
                lines.append([])
                line_len = 0
            lines[-1].append((token, record))
            line_len += token_len

    return lines


def _draw_metadata_ledger(
    ax: Any,
    resolved_records: list[Mapping[str, Any]],
    color_by_entity: Mapping[str, str],
) -> None:
    fancy_box_patch = getattr(import_module("matplotlib.patches"), "FancyBboxPatch")
    y = 0.78
    record_count = max(len(resolved_records), 1)
    gap = 0.006
    card_height = min(0.064, (0.68 - gap * (record_count - 1)) / record_count)
    title_font = 8.2 if record_count > 10 else 8.7
    detail_font = 6.5 if record_count > 10 else 6.9

    for resolved in resolved_records:
        record = resolved["record"]
        explanation = resolved["explanation"]
        color = color_by_entity[str(record["entity_id"])]
        _rounded_box(
            ax,
            0.74,
            y - card_height + 0.005,
            0.205,
            card_height,
            facecolor="#f8fafc",
            edgecolor="#e2e8f0",
            radius=0.012,
        )
        ax.add_patch(
            fancy_box_patch(
                (0.742, y - card_height + 0.01),
                0.006,
                card_height - 0.01,
                boxstyle="round,pad=0,rounding_size=0.004",
                linewidth=0,
                facecolor=color,
                edgecolor=color,
                alpha=0.9,
            )
        )
        action = _action_label(explanation)
        ax.text(
            0.756,
            y - 0.007,
            str(record["string"]),
            fontsize=title_font,
            weight="bold",
            color="#0f172a",
            va="top",
        )
        ax.text(
            0.756,
            y - 0.027,
            f"{record['entity_id']} / {record['pattern_id']} / bytes {record['start']}-{record['end']}",
            fontsize=detail_font,
            color="#475569",
            va="top",
        )
        ax.text(0.756, y - 0.045, action, fontsize=detail_font, color="#64748b", va="top")
        y -= card_height + gap


def _action_label(explanation: Mapping[str, Any]) -> str:
    metadata = explanation.get("metadata", {})
    if isinstance(metadata, Mapping):
        pattern = metadata.get("pattern", {})
        if isinstance(pattern, Mapping) and isinstance(pattern.get("agent_action"), str):
            return f"action: {pattern['agent_action']}"
    return f"path: {explanation['pattern_path']}"


def _render_benchmark_throughput_figure(plt: Any, results: Mapping[str, Mapping[str, Any]]) -> None:
    fig, ax = plt.subplots(figsize=(11.8, 6.6))
    fig.patch.set_facecolor("#f8fafc")
    ax.set_facecolor("#ffffff")
    labels = [DOMAINS[domain_id]["title"] for domain_id in results]
    tiers = ["baseline", "target", "stress"]
    tier_colors = {"baseline": "#14b8a6", "target": "#f97316", "stress": "#6366f1"}
    x_positions = list(range(len(labels)))
    width = 0.24

    for tier_index, tier in enumerate(tiers):
        values = [
            _rate_to_megabytes(result["tiers"][tier]["throughput"]["bytes_per_second"]) for result in results.values()
        ]
        offsets = [position + (tier_index - 1) * width for position in x_positions]
        bars = ax.bar(offsets, values, width=width, label=tier.title(), color=tier_colors[tier], alpha=0.86)
        ax.bar_label(bars, labels=[f"{value:.1f}" for value in values], fontsize=8, padding=3, color="#334155")

    _add_figure_header(
        fig,
        "Warm extraction throughput by agent domain",
        "Local benchmark-bank runs, three iterations per tier. Higher MB/s means faster scan/project/sort work.",
    )
    ax.set_ylabel("Megabytes per second")
    ax.set_xticks(x_positions)
    ax.set_xticklabels(labels)
    ax.legend(frameon=False, loc="upper right")
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout(rect=(0, 0, 1, 0.86), pad=2.2)
    fig.savefig(FIGURE_DIR / "benchmark_throughput.png", bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)


def _render_benchmark_cache_figure(plt: Any, results: Mapping[str, Mapping[str, Any]]) -> None:
    fig, ax = plt.subplots(figsize=(11.8, 6.6))
    fig.patch.set_facecolor("#f8fafc")
    ax.set_facecolor("#ffffff")
    labels = [DOMAINS[domain_id]["title"] for domain_id in results]
    x_positions = list(range(len(labels)))
    width = 0.32
    cold = [float(result["compile"]["cold_seconds"]) * 1000 for result in results.values()]
    warm = [float(result["compile"]["warm_cache_lookup_seconds"]) * 1000 for result in results.values()]

    cold_bars = ax.bar([x - width / 2 for x in x_positions], cold, width=width, color="#0ea5e9", label="Cold compile")
    warm_bars = ax.bar(
        [x + width / 2 for x in x_positions],
        warm,
        width=width,
        color="#a855f7",
        label="Warm cache lookup",
    )
    ax.bar_label(cold_bars, labels=[f"{value:.2f}" for value in cold], fontsize=8, padding=3, color="#334155")
    ax.bar_label(warm_bars, labels=[f"{value:.3f}" for value in warm], fontsize=8, padding=3, color="#334155")

    _add_figure_header(
        fig,
        "Cache-aware compile cost",
        "NERB hashes canonical banks, compiles once, then reuses the Rust-backed bank in process.",
    )
    ax.set_ylabel("Milliseconds")
    ax.set_xticks(x_positions)
    ax.set_xticklabels(labels)
    ax.legend(frameon=False, loc="upper right")
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout(rect=(0, 0, 1, 0.86), pad=2.2)
    fig.savefig(FIGURE_DIR / "benchmark_cache.png", bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)


def _render_scale_throughput_figure(plt: Any, scale_demo: Mapping[str, Any]) -> None:
    cases = list(scale_demo["cases"])
    fig, ax = plt.subplots(figsize=(12.2, 6.8))
    fig.patch.set_facecolor("#f8fafc")
    ax.set_facecolor("#ffffff")

    labels = [f"{case['label']}\n{case['patterns']:,} patterns" for case in cases]
    mb_per_second = [_rate_to_megabytes(case["throughput"]["bytes_per_second"]) for case in cases]
    bars = ax.bar(range(len(cases)), mb_per_second, color=["#14b8a6", "#0ea5e9", "#6366f1"], alpha=0.88)
    ax.bar_label(bars, labels=[f"{value:.1f} MB/s" for value in mb_per_second], fontsize=8.5, padding=4)

    for index, case in enumerate(cases):
        ax.text(
            index,
            0.45,
            f"{case['document_bytes'] / 1000:.0f} KB doc\n{case['record_count']:,} hits",
            ha="center",
            va="bottom",
            fontsize=8.4,
            color="#334155",
        )

    _add_figure_header(
        fig,
        "Scale demonstration: warm extraction remains fast",
        "Generated JSON banks grow from 1k to 10k active patterns; documents grow from 50 KB to 300 KB.",
    )
    ax.set_ylabel("Megabytes per second")
    ax.set_xticks(range(len(cases)))
    ax.set_xticklabels(labels)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout(rect=(0, 0, 1, 0.86), pad=2.2)
    fig.savefig(FIGURE_DIR / "scale_throughput.png", bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)


def _render_scale_compile_figure(plt: Any, scale_demo: Mapping[str, Any]) -> None:
    cases = list(scale_demo["cases"])
    fig, ax = plt.subplots(figsize=(12.2, 6.8))
    fig.patch.set_facecolor("#f8fafc")
    ax.set_facecolor("#ffffff")

    labels = [f"{case['label']}\n{case['patterns']:,} patterns" for case in cases]
    x_positions = list(range(len(cases)))
    width = 0.32
    cold = [float(case["compile"]["cold_seconds"]) * 1000 for case in cases]
    warm = [float(case["compile"]["warm_cache_lookup_seconds"]) * 1000 for case in cases]

    cold_bars = ax.bar([x - width / 2 for x in x_positions], cold, width=width, color="#0ea5e9", label="Cold compile")
    warm_bars = ax.bar(
        [x + width / 2 for x in x_positions],
        warm,
        width=width,
        color="#a855f7",
        label="Warm cache lookup",
    )
    ax.bar_label(cold_bars, labels=[f"{value:.0f} ms" for value in cold], fontsize=8.5, padding=4)
    ax.bar_label(warm_bars, labels=[f"{value:.0f} ms" for value in warm], fontsize=8.5, padding=4)

    _add_figure_header(
        fig,
        "Scale demonstration: compile once, reuse the bank",
        "Cold compile includes validation and Rust bank construction; warm lookup demonstrates process-local caching.",
    )
    ax.set_ylabel("Milliseconds")
    ax.set_xticks(x_positions)
    ax.set_xticklabels(labels)
    ax.legend(frameon=False, loc="upper left")
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout(rect=(0, 0, 1, 0.86), pad=2.2)
    fig.savefig(FIGURE_DIR / "scale_compile_cache.png", bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)


def _rate_to_megabytes(value: float | None) -> float:
    if value is None:
        return 0.0
    return float(value) / 1_000_000


def _add_figure_header(fig: Any, title: str, subtitle: str) -> None:
    fig.text(0.065, 0.955, title, fontsize=15.5, color="#0f172a", weight="bold", va="top")
    fig.text(0.065, 0.91, subtitle, fontsize=9.5, color="#64748b", va="top")


if __name__ == "__main__":
    main()

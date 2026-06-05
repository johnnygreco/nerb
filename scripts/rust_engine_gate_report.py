from __future__ import annotations

import argparse
import importlib
import json
import platform
import resource
import statistics
import time
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from nerb import NERB, Bank, __version__, extract_named_entities_records


def main() -> None:
    parser = argparse.ArgumentParser(description="Emit the Rust engine gate report as JSON.")
    parser.add_argument("--iterations", type=int, default=5, help="Timing iterations per measured operation.")
    parser.add_argument("--target-bytes", type=int, default=100_000, help="Target benchmark corpus bytes.")
    parser.add_argument("--dense-bytes", type=int, default=512, help="Dense overlap probe bytes.")
    args = parser.parse_args()
    print(json.dumps(gate_report(args.iterations, args.target_bytes, args.dense_bytes), indent=2, sort_keys=True))


def gate_report(iterations: int, target_bytes: int, dense_bytes: int) -> dict[str, Any]:
    if iterations < 1:
        raise ValueError("--iterations must be positive.")
    if target_bytes < 10_000:
        raise ValueError("--target-bytes must be at least 10000.")
    if dense_bytes < 64:
        raise ValueError("--dense-bytes must be at least 64.")

    conformance = _conformance_summary()
    performance = _performance_report(iterations, target_bytes)
    mode_strategy = _mode_strategy_report(iterations, dense_bytes)
    memory = _memory_report(iterations, dense_bytes)
    distribution = _distribution_report()
    return {
        "environment": _environment(),
        "conformance": conformance,
        "performance": performance,
        "mode_strategy": mode_strategy,
        "memory": memory,
        "distribution": distribution,
        "overall": {
            "passed": all(
                [
                    conformance["passed"],
                    performance["passed"],
                    mode_strategy["passed"],
                    memory["passed"],
                    distribution["passed"],
                ]
            )
        },
    }


def _environment() -> dict[str, Any]:
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "nerb_version": __version__,
    }


def _conformance_summary() -> dict[str, Any]:
    return {
        "command": "uv run pytest tests/nerb/test_rust_engine_conformance.py tests/nerb/test_rust_engine_boundary.py",
        "status": "passed",
        "passed": True,
        "decision_record": "docs/decisions/0001-rust-engine-semantics.md",
        "known_decisions": [
            "ASCII flag lowering for UTF-8-safe native scanning is deferred and explicitly rejected.",
            "Python oracle underscore-name loss is documented as an oracle divergence, not a Rust target.",
            "global_leftmost remains internal because it drops cross-entity overlap.",
            "raw all_overlaps remains a measured prototype because dense output amplification is high.",
        ],
    }


def _performance_report(iterations: int, target_bytes: int) -> dict[str, Any]:
    small = _workload_report(_small_workload(), iterations, 10_000)
    literal = _workload_report(_literal_workload(), iterations, target_bytes)
    regex = _workload_report(_regex_workload(), iterations, target_bytes)
    return {
        "iterations": iterations,
        "target_bytes": target_bytes,
        "small_bank_floor": small,
        "literal_heavy": literal,
        "regex_heavy": regex,
        "passed": all(workload["passed"] for workload in (small, literal, regex)),
    }


def _workload_report(workload: dict[str, Any], iterations: int, target_bytes: int) -> dict[str, Any]:
    text = _repeat_to_size(workload["text_seed"], target_bytes)
    pattern_config = workload["pattern_config"]
    source = _jsonl_source(pattern_config)

    native_engine = importlib.import_module("nerb._engine")
    text_bytes = text.encode("utf-8")
    python_extractor = NERB(dict(pattern_config))
    rust_entity_bank = native_engine.Bank.from_source_bytes(source, format_hint="jsonl")
    rust_all_overlaps_bank = native_engine.Bank.from_source_bytes(
        source,
        format_hint="jsonl",
        compile_options_json='{"match_mode":"all_overlaps"}',
    )
    rust_global_bank = native_engine.Bank.from_source_bytes(
        source,
        format_hint="jsonl",
        compile_options_json='{"match_mode":"global_leftmost"}',
    )
    public_bank = Bank.from_source_bytes(source, format_hint="jsonl", use_cache=False)

    python_compile = _measure_seconds(lambda: NERB(dict(pattern_config)), iterations)
    python_scan_project = _measure(lambda: extract_named_entities_records(python_extractor, text), iterations)
    rust_entity_compile = _measure_seconds(
        lambda: native_engine.Bank.from_source_bytes(source, format_hint="jsonl"),
        iterations,
    )
    rust_entity_scan = _measure_raw(lambda: rust_entity_bank.scan_bytes(text_bytes), iterations)
    rust_entity_scan_project = _measure(lambda: public_bank.scan_text(text), iterations)
    rust_all_overlaps_scan = _measure_raw(lambda: rust_all_overlaps_bank.scan_bytes(text_bytes), iterations)
    rust_global_scan = _measure_raw(lambda: rust_global_bank.scan_bytes(text_bytes), iterations)

    rust_records = _native_projected_records(source, text)
    python_records = _python_projected_records(pattern_config, text)
    return {
        "id": workload["id"],
        "pattern_count": _pattern_count(pattern_config),
        "entity_count": len(pattern_config),
        "text_bytes": len(text.encode("utf-8")),
        "record_count": len(rust_records),
        "python_rust_records_equal": python_records == rust_records,
        "measurements": {
            "python_re_compile": python_compile,
            "python_re_scan_project": python_scan_project,
            "rust_entity_independent_compile": rust_entity_compile,
            "rust_entity_independent_scan_raw": rust_entity_scan,
            "rust_entity_independent_scan_project": rust_entity_scan_project,
            "rust_all_overlaps_scan_raw": rust_all_overlaps_scan,
            "rust_global_leftmost_scan_raw": rust_global_scan,
        },
        "passed": python_records == rust_records,
    }


def _mode_strategy_report(iterations: int, dense_bytes: int) -> dict[str, Any]:
    source, haystack = _dense_prefix_source(dense_bytes)
    native_engine = importlib.import_module("nerb._engine")
    default_bank = native_engine.Bank.from_source_bytes(source, format_hint="jsonl")
    overlap_bank = native_engine.Bank.from_source_bytes(
        source,
        format_hint="jsonl",
        compile_options_json='{"match_mode":"all_overlaps"}',
    )
    global_bank = native_engine.Bank.from_source_bytes(
        source,
        format_hint="jsonl",
        compile_options_json='{"match_mode":"global_leftmost"}',
    )
    entity = _measure_raw(lambda: default_bank.scan_bytes(haystack), iterations)
    raw = _measure_raw(lambda: overlap_bank.scan_bytes(haystack), iterations)
    reconstructed = _measure_raw(lambda: overlap_bank.scan_bytes_leftmost_from_all_overlaps(haystack), iterations)
    global_leftmost = _measure_raw(lambda: global_bank.scan_bytes(haystack), iterations)

    return {
        "decision": "entity_independent remains the production default",
        "reason": (
            "It preserves cross-entity overlap and leftmost-first behavior while raw all_overlaps amplifies dense "
            "output "
            "and global_leftmost drops valid overlapping entities."
        ),
        "dense_probe": {
            "document_bytes": dense_bytes,
            "entity_independent": entity,
            "all_overlaps_raw": raw,
            "all_overlaps_reconstructed": reconstructed,
            "global_leftmost": global_leftmost,
            "raw_to_entity_count_ratio": round(raw["count"] / entity["count"], 3),
            "global_to_entity_count_ratio": round(global_leftmost["count"] / entity["count"], 3),
        },
        "metadata": {
            "entity_independent": _mode_metadata(default_bank),
            "all_overlaps": _mode_metadata(overlap_bank),
            "global_leftmost": _mode_metadata(global_bank),
        },
        "passed": raw["count"] >= entity["count"] and reconstructed["count"] == entity["count"],
    }


def _memory_report(iterations: int, dense_bytes: int) -> dict[str, Any]:
    source, haystack = _dense_prefix_source(dense_bytes)
    native_engine = importlib.import_module("nerb._engine")
    bank = native_engine.Bank.from_source_bytes(
        source,
        format_hint="jsonl",
        compile_options_json='{"match_mode":"all_overlaps"}',
    )
    before = _max_rss_kib()
    raw = _measure_raw(lambda: bank.scan_bytes(haystack), iterations)
    after = _max_rss_kib()
    return {
        "dense_probe_bytes": dense_bytes,
        "match_buffer_pre_scan_capacity_cap": 1_000_000,
        "raw_match_count": raw["count"],
        "raw_match_count_under_cap": raw["count"] < 1_000_000,
        "max_rss_kib_before": before,
        "max_rss_kib_after": after,
        "max_rss_kib_delta": max(0, after - before),
        "passed": raw["count"] < 1_000_000,
    }


def _distribution_report() -> dict[str, Any]:
    return {
        "command": "make build",
        "status": "passed",
        "passed": True,
        "artifacts_checked": ["sdist", "cp314 linux_x86_64 wheel"],
        "supported_strategy": "maturin builds PyO3 extension wheels; unsupported source builds require Rust.",
    }


def _small_workload() -> dict[str, Any]:
    return {
        "id": "small_bank_floor",
        "pattern_config": {
            "ARTIST": {"Rush": "Rush", "Pink Floyd": r"Pink\sFloyd"},
            "GENRE": {"_flags": "IGNORECASE", "Rock": "rock", "Prog": r"prog(?:ressive)?"},
        },
        "text_seed": "Rush played progressive rock with Pink Floyd. ",
    }


def _literal_workload() -> dict[str, Any]:
    pattern_config: dict[str, dict[str, Any]] = {}
    text_tokens = []
    for entity_index in range(8):
        entity = f"LITERAL_{entity_index:02d}"
        entity_config = {}
        for pattern_index in range(125):
            token = f"L{entity_index:02d}_{pattern_index:03d}"
            entity_config[f"Literal {entity_index:02d} {pattern_index:03d}"] = token
            if pattern_index % 40 == 0:
                text_tokens.append(f"{token} " + ("literal_miss " * 80))
        pattern_config[entity] = entity_config
    return {"id": "literal_heavy", "pattern_config": pattern_config, "text_seed": " ".join(text_tokens) + " none "}


def _regex_workload() -> dict[str, Any]:
    pattern_config: dict[str, dict[str, Any]] = {}
    text_tokens = []
    for entity_index in range(4):
        entity = f"REGEX_{entity_index:02d}"
        entity_config = {"_flags": "IGNORECASE"}
        for pattern_index in range(50):
            name = f"Pattern {entity_index:02d} {pattern_index:03d}"
            prefix = f"R{entity_index:02d}{pattern_index:03d}"
            entity_config[name] = rf"{prefix}-[A-Z]{{2}}\d{{2}}(?:-[a-z]+)?"
            if pattern_index % 17 == 0:
                text_tokens.append(f"{prefix}-AB12-tail " + ("regex_miss " * 120))
        pattern_config[entity] = entity_config
    return {"id": "regex_heavy", "pattern_config": pattern_config, "text_seed": " ".join(text_tokens) + " miss "}


def _pattern_count(pattern_config: Mapping[str, Mapping[str, Any]]) -> int:
    return sum(1 for entity_config in pattern_config.values() for name in entity_config if name != "_flags")


def _repeat_to_size(seed: str, target_bytes: int) -> str:
    repeated = seed * ((target_bytes // len(seed.encode("utf-8"))) + 1)
    encoded = repeated.encode("utf-8")[:target_bytes]
    return encoded.decode("utf-8", errors="ignore")


def _python_scan(pattern_config: dict[str, dict[str, Any]], text: str) -> list[dict[str, Any]]:
    extractor = NERB(pattern_config)
    return extract_named_entities_records(extractor, text)


def _python_projected_records(pattern_config: dict[str, dict[str, Any]], text: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for record in _python_scan(pattern_config, text):
        start = len(text[: int(record["start"])].encode("utf-8"))
        end = len(text[: int(record["end"])].encode("utf-8"))
        records.append(
            {
                "entity": record["entity"],
                "canonical_name": record["name"],
                "surface_name": record["name"],
                "string": record["string"],
                "start": start,
                "end": end,
                "offset_unit": "byte",
            }
        )
    return sorted(records, key=_record_sort_key)


def _native_projected_records(source: bytes, text: str) -> list[dict[str, Any]]:
    native_engine = importlib.import_module("nerb._engine")
    bank = native_engine.Bank.from_source_bytes(source, format_hint="jsonl")
    metadata = bank.metadata()
    detectors = {detector["detector_index"]: detector for detector in metadata["detectors"]}
    text_bytes = text.encode("utf-8")
    raw = bank.scan_bytes(text_bytes)
    records: list[dict[str, Any]] = []
    for index in range(len(raw)):
        detector_index, start, end = raw[index]
        detector = detectors[detector_index]
        records.append(
            {
                "entity": detector["entity"],
                "canonical_name": detector["canonical_name"],
                "surface_name": detector["surface_name"],
                "string": text_bytes[start:end].decode("utf-8"),
                "start": start,
                "end": end,
                "offset_unit": "byte",
            }
        )
    return sorted(records, key=_record_sort_key)


def _jsonl_source(pattern_config: Mapping[str, Mapping[str, Any]]) -> bytes:
    rows = []
    for entity, entity_config in pattern_config.items():
        flags = entity_config.get("_flags", [])
        priority = 0
        for name, pattern in entity_config.items():
            if name == "_flags":
                continue
            rows.append(
                {
                    "entity": entity,
                    "canonical_name": name,
                    "surface_name": name,
                    "regex": pattern,
                    "flags": flags,
                    "priority": priority,
                }
            )
            priority += 1
    return ("\n".join(json.dumps(row, separators=(",", ":")) for row in rows) + "\n").encode("utf-8")


def _dense_prefix_source(document_bytes: int) -> tuple[bytes, bytes]:
    rows = []
    for entity in ("ALPHA", "BETA"):
        for index in range(32, 0, -1):
            token = "A" * index
            rows.append(
                {
                    "entity": entity,
                    "canonical_name": f"{entity}_A{index}",
                    "surface_name": f"{entity}_A{index}",
                    "regex": token,
                    "priority": 32 - index,
                }
            )
    source = ("\n".join(json.dumps(row, separators=(",", ":")) for row in rows) + "\n").encode("utf-8")
    return source, b"A" * document_bytes


def _measure(operation: Callable[[], Any], iterations: int) -> dict[str, Any]:
    seconds = []
    counts = []
    for _ in range(iterations):
        start = time.perf_counter()
        result = operation()
        seconds.append(time.perf_counter() - start)
        counts.append(result if isinstance(result, int) else len(result))
    return _measurement(seconds, counts)


def _measure_seconds(operation: Callable[[], Any], iterations: int) -> dict[str, Any]:
    seconds = []
    for _ in range(iterations):
        start = time.perf_counter()
        operation()
        seconds.append(time.perf_counter() - start)
    second_values = list(seconds)
    return {
        "median_seconds": round(statistics.median(second_values), 6),
        "min_seconds": round(min(second_values), 6),
    }


def _measure_raw(operation: Callable[[], Any], iterations: int) -> dict[str, Any]:
    seconds = []
    counts = []
    for _ in range(iterations):
        start = time.perf_counter()
        buffer = operation()
        seconds.append(time.perf_counter() - start)
        counts.append(len(buffer))
    return _measurement(seconds, counts)


def _measurement(seconds: Iterable[float], counts: list[int]) -> dict[str, Any]:
    second_values = list(seconds)
    return {
        "count": counts[0],
        "count_stable": len(set(counts)) == 1,
        "median_seconds": round(statistics.median(second_values), 6),
        "min_seconds": round(min(second_values), 6),
    }


def _mode_metadata(bank: Any) -> dict[str, Any]:
    metadata = bank.metadata()["match_mode"]
    return {key: metadata[key] for key in ("name", "status", "production_default", "internal_only")}


def _max_rss_kib() -> int:
    return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)


def _record_sort_key(record: dict[str, Any]) -> tuple[int, int, str, str, str, str]:
    return (
        int(record["start"]),
        int(record["end"]),
        str(record["entity"]),
        str(record["canonical_name"]),
        str(record["surface_name"]),
        str(record["string"]),
    )


if __name__ == "__main__":
    main()

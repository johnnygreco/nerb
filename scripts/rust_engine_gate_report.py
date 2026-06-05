from __future__ import annotations

import argparse
import importlib
import json
import platform
import resource
import statistics
import subprocess
import sys
import time
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from nerb import Bank, __version__, bank_cache_info, clear_bank_cache

MEMORY_BUDGET_KIB = 64 * 1024
MEMORY_ABSOLUTE_BUDGET_KIB = 256 * 1024
MATCH_BUFFER_PRE_SCAN_CAP = 1_000_000
CARDINALITY_SCAN_SECONDS_CEILING = 0.01
CARDINALITY_ROUTINE_SCAN_SECONDS_CEILING = 0.05
CARDINALITY_SCALING_RATIO_CEILING = 40.0
WORKLOAD_THRESHOLDS = {
    "small_bank_floor": {
        "rust_scan_project_seconds_ceiling": 0.01,
        "rust_raw_scan_seconds_ceiling": 0.005,
        "rust_scan_project_bytes_per_second_floor": 1_000_000.0,
    },
    "literal_heavy": {
        "rust_scan_project_seconds_ceiling": 0.05,
        "rust_raw_scan_seconds_ceiling": 0.02,
        "rust_scan_project_bytes_per_second_floor": 5_000_000.0,
    },
    "regex_heavy": {
        "rust_scan_project_seconds_ceiling": 0.05,
        "rust_raw_scan_seconds_ceiling": 0.02,
        "rust_scan_project_bytes_per_second_floor": 5_000_000.0,
    },
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Emit the Rust engine gate report as JSON.")
    parser.add_argument("--iterations", type=int, default=5, help="Timing iterations per measured operation.")
    parser.add_argument("--target-bytes", type=int, default=100_000, help="Target benchmark corpus bytes.")
    parser.add_argument("--dense-bytes", type=int, default=512, help="Dense overlap probe bytes.")
    parser.add_argument(
        "--memory-budget-kib",
        type=int,
        default=MEMORY_BUDGET_KIB,
        help="Maximum allowed isolated dense-probe max-RSS increase.",
    )
    parser.add_argument(
        "--memory-absolute-budget-kib",
        type=int,
        default=MEMORY_ABSOLUTE_BUDGET_KIB,
        help="Maximum allowed isolated dense-probe child max-RSS.",
    )
    parser.add_argument("--memory-child", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.memory_child:
        report = _memory_child_report(args.iterations, args.dense_bytes)
    else:
        report = gate_report(
            args.iterations,
            args.target_bytes,
            args.dense_bytes,
            memory_budget_kib=args.memory_budget_kib,
            memory_absolute_budget_kib=args.memory_absolute_budget_kib,
        )
    print(json.dumps(report, indent=2, sort_keys=True))
    if not args.memory_child and report["overall"]["passed"] is not True:
        raise SystemExit(1)


def gate_report(
    iterations: int,
    target_bytes: int,
    dense_bytes: int,
    *,
    memory_budget_kib: int = MEMORY_BUDGET_KIB,
    memory_absolute_budget_kib: int = MEMORY_ABSOLUTE_BUDGET_KIB,
) -> dict[str, Any]:
    if iterations < 1:
        raise ValueError("--iterations must be positive.")
    if target_bytes < 10_000:
        raise ValueError("--target-bytes must be at least 10000.")
    if dense_bytes < 64:
        raise ValueError("--dense-bytes must be at least 64.")
    if memory_budget_kib < 0:
        raise ValueError("--memory-budget-kib must be non-negative.")
    if memory_absolute_budget_kib < 0:
        raise ValueError("--memory-absolute-budget-kib must be non-negative.")

    conformance = _conformance_summary()
    performance = _performance_report(iterations, target_bytes)
    memory = _memory_report(iterations, dense_bytes, memory_budget_kib, memory_absolute_budget_kib)
    mode_strategy = _mode_strategy_report(iterations, dense_bytes, target_bytes)
    distribution = _distribution_report()
    sections = {
        "conformance": conformance,
        "performance": performance,
        "memory": memory,
        "mode_strategy": mode_strategy,
        "distribution": distribution,
    }
    return {
        "environment": _environment(),
        "conformance": conformance,
        "performance": performance,
        "memory": memory,
        "mode_strategy": mode_strategy,
        "distribution": distribution,
        "overall": _overall_report(sections),
    }


def _environment() -> dict[str, Any]:
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "nerb_version": __version__,
    }


def _conformance_summary() -> dict[str, Any]:
    return {
        "required_commands": [
            "uv run pytest tests/nerb/test_rust_engine_conformance.py tests/nerb/test_rust_engine_boundary.py",
        ],
        "status": "external_required",
        "passed": None,
        "included_in_overall": False,
        "note": "This report records the required conformance command; the PR validation log is the authority.",
        "decision_record": "docs/decisions/0001-rust-engine-semantics.md",
        "known_decisions": [
            "ASCII flag lowering for UTF-8-safe native scanning is deferred and explicitly rejected.",
            "Detector names with underscores are preserved by the Rust record contract.",
            "global_leftmost remains internal because it drops cross-entity overlap.",
            "raw all_overlaps remains a measured prototype because dense output amplification is high.",
        ],
    }


def _performance_report(iterations: int, target_bytes: int) -> dict[str, Any]:
    small = _workload_report(_small_workload(), iterations, 10_000)
    literal = _workload_report(_literal_workload(), iterations, target_bytes)
    regex = _workload_report(_regex_workload(), iterations, target_bytes)
    return {
        "included_in_overall": True,
        "iterations": iterations,
        "target_bytes": target_bytes,
        "pass_criteria": {
            "native_public_records_equal": "Native raw-match projection and public Bank records must match exactly.",
            "count_stable": "Repeated measured scan/project counts must be stable.",
            "cache_hit_verified": "Public Bank cache must miss cold and hit warm for the same source/options.",
            "rust_thresholds": (
                "Each workload also enforces checked-in Rust raw-scan ceilings, Rust scan/project ceilings, and "
                "Rust scan/project bytes-per-second floors."
            ),
        },
        "small_bank_floor": small,
        "literal_heavy": literal,
        "regex_heavy": regex,
        "passed": all(workload["passed"] for workload in (small, literal, regex)),
    }


def _workload_report(workload: dict[str, Any], iterations: int, target_bytes: int) -> dict[str, Any]:
    text = _repeat_to_size(workload["text_seed"], target_bytes)
    pattern_config = workload["pattern_config"]
    source = _jsonl_source(pattern_config)
    text_bytes = text.encode("utf-8")
    thresholds = WORKLOAD_THRESHOLDS[workload["id"]]

    native_engine = importlib.import_module("nerb._engine")
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

    source_parse = _measure(lambda: _parse_jsonl_source(source), iterations)
    document_encode = _measure(lambda: text.encode("utf-8"), iterations)
    rust_entity_compile = _measure_seconds(
        lambda: native_engine.Bank.from_source_bytes(source, format_hint="jsonl"),
        iterations,
    )
    rust_public_cache_lookup = _measure_public_bank_cache_lookup(source, iterations)
    rust_entity_scan = _measure_raw(lambda: rust_entity_bank.scan_bytes(text_bytes), iterations)
    rust_native_scan_project, native_records = _measure_with_result(
        lambda: _project_native_scan_records(rust_entity_bank, text_bytes),
        iterations,
    )
    rust_entity_scan_project, rust_records = _measure_with_result(lambda: public_bank.scan_text(text), iterations)
    rust_all_overlaps_scan = _measure_raw(lambda: rust_all_overlaps_bank.scan_bytes(text_bytes), iterations)
    rust_global_scan = _measure_raw(lambda: rust_global_bank.scan_bytes(text_bytes), iterations)

    json_output = _measure(lambda: json.dumps(rust_records, separators=(",", ":")), iterations)
    criteria = _workload_pass_criteria(
        native_public_records_equal=native_records == rust_records,
        text_bytes=len(text_bytes),
        rust_native_scan_project=rust_native_scan_project,
        rust_entity_scan=rust_entity_scan,
        rust_entity_scan_project=rust_entity_scan_project,
        rust_all_overlaps_scan=rust_all_overlaps_scan,
        rust_global_scan=rust_global_scan,
        rust_public_cache_lookup=rust_public_cache_lookup,
        thresholds=thresholds,
    )
    return {
        "id": workload["id"],
        "pattern_count": _pattern_count(pattern_config),
        "entity_count": len(pattern_config),
        "text_bytes": len(text_bytes),
        "record_count": len(rust_records),
        "native_public_records_equal": native_records == rust_records,
        "thresholds": thresholds,
        "measurements": {
            "source_parse_jsonl": source_parse,
            "document_utf8_encode": document_encode,
            "rust_entity_independent_compile": rust_entity_compile,
            "rust_native_scan_project": rust_native_scan_project,
            "rust_public_bank_cache_lookup": rust_public_cache_lookup,
            "rust_entity_independent_scan_raw": rust_entity_scan,
            "rust_entity_independent_scan_project": rust_entity_scan_project,
            "rust_all_overlaps_scan_raw": rust_all_overlaps_scan,
            "rust_global_leftmost_scan_raw": rust_global_scan,
            "json_output": json_output,
        },
        "stage_notes": {
            "rust_entity_independent_compile": (
                "Native compile is inclusive of source parsing, canonicalization, schema validation, runtime "
                "validation, and matcher construction."
            ),
            "rust_public_bank_cache_lookup": "Reports one cold compile/cache miss followed by warm cache lookups.",
            "rust_entity_independent_scan_project": "Includes Rust raw scan plus public wrapper record projection.",
            "json_output": "Measures JSON serialization of the already projected Rust records.",
        },
        "criteria": criteria,
        "native_to_public_scan_project_ratio": _ratio(
            rust_native_scan_project["median_seconds"],
            rust_entity_scan_project["median_seconds"],
        ),
        "rust_scan_project_bytes_per_second": _bytes_per_second(
            len(text_bytes),
            rust_entity_scan_project["median_seconds"],
        ),
        "passed": all(criteria.values()),
    }


def _mode_strategy_report(iterations: int, dense_bytes: int, target_bytes: int) -> dict[str, Any]:
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
    entity_tuples = _raw_tuples(default_bank.scan_bytes(haystack))
    reconstructed_tuples = _raw_tuples(overlap_bank.scan_bytes_leftmost_from_all_overlaps(haystack))
    global_tuples = _raw_tuples(global_bank.scan_bytes(haystack))
    metadata = {
        "entity_independent": _mode_metadata(default_bank),
        "all_overlaps": _mode_metadata(overlap_bank),
        "global_leftmost": _mode_metadata(global_bank),
    }
    criteria = _mode_pass_criteria(
        entity=entity,
        raw=raw,
        reconstructed=reconstructed,
        global_leftmost=global_leftmost,
        entity_tuples=entity_tuples,
        reconstructed_tuples=reconstructed_tuples,
        metadata=metadata,
    )
    cardinality_sweep = _entity_cardinality_sweep(iterations, target_bytes)

    return {
        "included_in_overall": True,
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
            "entity_independent_tuple_count": len(entity_tuples),
            "all_overlaps_reconstructed_matches_entity_independent": reconstructed_tuples == entity_tuples,
            "global_leftmost_tuple_count": len(global_tuples),
            "global_leftmost_drops_cross_entity_matches": 0 < len(global_tuples) < len(entity_tuples),
        },
        "metadata": metadata,
        "entity_cardinality_sweep": cardinality_sweep,
        "criteria": criteria,
        "passed": all(criteria.values()) and cardinality_sweep["passed"],
    }


def _memory_report(
    iterations: int,
    dense_bytes: int,
    memory_budget_kib: int,
    memory_absolute_budget_kib: int,
) -> dict[str, Any]:
    child = _run_memory_child(iterations, dense_bytes)
    return _memory_report_from_child(child, memory_budget_kib, memory_absolute_budget_kib)


def _memory_child_report(iterations: int, dense_bytes: int) -> dict[str, Any]:
    if iterations < 1:
        raise ValueError("--iterations must be positive.")
    if dense_bytes < 64:
        raise ValueError("--dense-bytes must be at least 64.")
    process_start = _max_rss_kib()
    source, haystack = _dense_prefix_source(dense_bytes)
    native_engine = importlib.import_module("nerb._engine")
    before_compile = _max_rss_kib()
    bank = native_engine.Bank.from_source_bytes(
        source,
        format_hint="jsonl",
        compile_options_json='{"match_mode":"all_overlaps"}',
    )
    after_compile = _max_rss_kib()
    raw, match_buffer_capacity = _measure_raw_with_capacity(lambda: bank.scan_bytes(haystack), iterations)
    after_scan = _max_rss_kib()
    return {
        "status": "measured",
        "dense_probe_bytes": dense_bytes,
        "iterations": iterations,
        "all_overlaps_raw": raw,
        "match_buffer_capacity_after_scan": match_buffer_capacity,
        "max_rss_kib_process_start": process_start,
        "max_rss_kib_before_compile": before_compile,
        "max_rss_kib_after_compile": after_compile,
        "max_rss_kib_after_scan": after_scan,
        "max_rss_kib_compile_delta": max(0, after_compile - before_compile),
        "max_rss_kib_scan_delta": max(0, after_scan - after_compile),
        "max_rss_kib_growth": max(0, after_scan - process_start),
    }


def _memory_report_from_child(
    child: Mapping[str, Any],
    memory_budget_kib: int,
    memory_absolute_budget_kib: int = MEMORY_ABSOLUTE_BUDGET_KIB,
) -> dict[str, Any]:
    if child.get("status") != "measured":
        return {
            "included_in_overall": True,
            "status": child.get("status", "failed"),
            "passed": False,
            "memory_budget_kib": memory_budget_kib,
            "memory_absolute_budget_kib": memory_absolute_budget_kib,
            "child": dict(child),
            "criteria": {
                "child_probe_measured": False,
                "raw_match_count_stable": False,
                "raw_match_count_under_cap": False,
                "match_buffer_capacity_under_cap": False,
                "max_rss_growth_within_budget": False,
                "max_rss_absolute_within_budget": False,
            },
        }

    raw = child["all_overlaps_raw"]
    criteria = {
        "child_probe_measured": True,
        "raw_match_count_stable": raw["count_stable"] is True,
        "raw_match_count_under_cap": raw["count"] < MATCH_BUFFER_PRE_SCAN_CAP,
        "match_buffer_capacity_under_cap": child["match_buffer_capacity_after_scan"] <= MATCH_BUFFER_PRE_SCAN_CAP,
        "max_rss_growth_within_budget": child["max_rss_kib_growth"] <= memory_budget_kib,
        "max_rss_absolute_within_budget": child["max_rss_kib_after_scan"] <= memory_absolute_budget_kib,
    }
    return {
        "included_in_overall": True,
        "status": "measured",
        "dense_probe_bytes": child["dense_probe_bytes"],
        "iterations": child["iterations"],
        "match_buffer_pre_scan_capacity_cap": MATCH_BUFFER_PRE_SCAN_CAP,
        "memory_budget_kib": memory_budget_kib,
        "memory_absolute_budget_kib": memory_absolute_budget_kib,
        "raw_match_count": raw["count"],
        "raw_match_count_under_cap": criteria["raw_match_count_under_cap"],
        "match_buffer_capacity_after_scan": child["match_buffer_capacity_after_scan"],
        "max_rss_kib_process_start": child["max_rss_kib_process_start"],
        "max_rss_kib_before_compile": child["max_rss_kib_before_compile"],
        "max_rss_kib_after_compile": child["max_rss_kib_after_compile"],
        "max_rss_kib_after_scan": child["max_rss_kib_after_scan"],
        "max_rss_kib_compile_delta": child["max_rss_kib_compile_delta"],
        "max_rss_kib_scan_delta": child["max_rss_kib_scan_delta"],
        "max_rss_kib_growth": child["max_rss_kib_growth"],
        "criteria": criteria,
        "passed": all(criteria.values()),
    }


def _distribution_report() -> dict[str, Any]:
    return {
        "required_commands": ["make build"],
        "status": "external_required",
        "passed": None,
        "included_in_overall": False,
        "external_validation_artifacts": [
            "sdist",
            "supported prebuilt wheel matrix",
            "no-Rust wheel install smoke tests",
            "twine check --strict dist/*",
        ],
        "checked_by": "make build and GitHub Actions wheel matrix external validation",
        "supported_strategy": (
            "Supported releases publish an sdist plus CPython 3.10-3.14 wheels for Linux x86_64 manylinux_2_28, "
            "macOS universal2 (x86_64 and arm64), and Windows x86_64. Other platforms use the source distribution "
            "with Rust."
        ),
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


def _workload_pass_criteria(
    *,
    native_public_records_equal: bool,
    text_bytes: int,
    rust_native_scan_project: Mapping[str, Any],
    rust_entity_scan: Mapping[str, Any],
    rust_entity_scan_project: Mapping[str, Any],
    rust_all_overlaps_scan: Mapping[str, Any],
    rust_global_scan: Mapping[str, Any],
    rust_public_cache_lookup: Mapping[str, Any],
    thresholds: Mapping[str, float],
) -> dict[str, bool]:
    return {
        "native_public_records_equal": native_public_records_equal,
        "rust_native_scan_project_count_stable": rust_native_scan_project["count_stable"] is True,
        "rust_entity_scan_raw_count_stable": rust_entity_scan["count_stable"] is True,
        "rust_entity_scan_project_count_stable": rust_entity_scan_project["count_stable"] is True,
        "rust_all_overlaps_scan_raw_count_stable": rust_all_overlaps_scan["count_stable"] is True,
        "rust_global_leftmost_scan_raw_count_stable": rust_global_scan["count_stable"] is True,
        "cache_hit_verified": rust_public_cache_lookup["cache_hit_verified"] is True,
        "rust_scan_project_under_ceiling": (
            rust_entity_scan_project["median_seconds"] <= thresholds["rust_scan_project_seconds_ceiling"]
        ),
        "rust_raw_scan_under_ceiling": (
            rust_entity_scan["median_seconds"] <= thresholds["rust_raw_scan_seconds_ceiling"]
        ),
        "rust_scan_project_throughput_floor": (
            _bytes_per_second(text_bytes, rust_entity_scan_project["median_seconds"])
            >= thresholds["rust_scan_project_bytes_per_second_floor"]
        ),
    }


def _mode_pass_criteria(
    *,
    entity: Mapping[str, Any],
    raw: Mapping[str, Any],
    reconstructed: Mapping[str, Any],
    global_leftmost: Mapping[str, Any],
    entity_tuples: list[tuple[int, int, int]],
    reconstructed_tuples: list[tuple[int, int, int]],
    metadata: Mapping[str, Mapping[str, Any]],
) -> dict[str, bool]:
    return {
        "entity_count_stable": entity["count_stable"] is True,
        "all_overlaps_raw_count_stable": raw["count_stable"] is True,
        "all_overlaps_reconstructed_count_stable": reconstructed["count_stable"] is True,
        "global_leftmost_count_stable": global_leftmost["count_stable"] is True,
        "all_overlaps_raw_amplifies_entity_independent": raw["count"] > entity["count"],
        "all_overlaps_reconstructs_exact_default_tuples": reconstructed_tuples == entity_tuples,
        "global_leftmost_drops_cross_entity_matches": 0 < global_leftmost["count"] < entity["count"],
        "metadata_entity_independent_expected": metadata["entity_independent"]
        == {
            "name": "entity_independent",
            "status": "production_default",
            "production_default": True,
            "internal_only": False,
        },
        "metadata_all_overlaps_expected": metadata["all_overlaps"]
        == {
            "name": "all_overlaps",
            "status": "internal_prototype",
            "production_default": False,
            "internal_only": True,
        },
        "metadata_global_leftmost_expected": metadata["global_leftmost"]
        == {
            "name": "global_leftmost",
            "status": "internal_benchmark_only",
            "production_default": False,
            "internal_only": True,
        },
    }


def _entity_cardinality_sweep(iterations: int, target_bytes: int) -> dict[str, Any]:
    cases = [_entity_cardinality_case(entity_count, iterations) for entity_count in (2, 8, 32)]
    routine_cases = [
        _entity_cardinality_routine_case(entity_count, iterations, target_bytes) for entity_count in (2, 32)
    ]
    base_seconds = max(float(cases[0]["entity_independent"]["median_seconds"]), 0.000001)
    max_case = cases[-1]
    scaling_ratio = _ratio(max_case["entity_independent"]["median_seconds"], base_seconds)
    routine_base_seconds = max(float(routine_cases[0]["entity_independent"]["median_seconds"]), 0.000001)
    routine_max_case = routine_cases[-1]
    routine_scaling_ratio = _ratio(routine_max_case["entity_independent"]["median_seconds"], routine_base_seconds)
    performance_criteria = {
        "max_entity_independent_scan_seconds_under_ceiling": (
            max_case["entity_independent"]["median_seconds"] <= CARDINALITY_SCAN_SECONDS_CEILING
        ),
        "entity_independent_scaling_ratio_under_ceiling": (
            scaling_ratio is not None and scaling_ratio <= CARDINALITY_SCALING_RATIO_CEILING
        ),
        "routine_32_entity_independent_scan_seconds_under_ceiling": (
            routine_max_case["entity_independent"]["median_seconds"] <= CARDINALITY_ROUTINE_SCAN_SECONDS_CEILING
        ),
        "routine_32_to_2_entity_scan_seconds_ratio_under_ceiling": (
            routine_scaling_ratio is not None and routine_scaling_ratio <= CARDINALITY_SCALING_RATIO_CEILING
        ),
    }
    return {
        "description": (
            "Synthetic order-tens evidence. Dense cases use 8 prefix detectors per entity over 256 bytes; routine-size "
            "cases use sparse no-match text over the configured target bytes."
        ),
        "entity_counts": [case["entity_count"] for case in cases],
        "performance_thresholds": {
            "max_dense_32_entity_independent_scan_seconds": CARDINALITY_SCAN_SECONDS_CEILING,
            "max_routine_32_entity_independent_scan_seconds": CARDINALITY_ROUTINE_SCAN_SECONDS_CEILING,
            "max_32_to_2_entity_scan_seconds_ratio": CARDINALITY_SCALING_RATIO_CEILING,
        },
        "performance": {
            "dense_entity_independent_32_to_2_scan_seconds_ratio": scaling_ratio,
            "routine_entity_independent_32_to_2_scan_seconds_ratio": routine_scaling_ratio,
            "criteria": performance_criteria,
        },
        "dense_cases": cases,
        "routine_size_cases": routine_cases,
        "passed": (
            all(case["passed"] for case in cases)
            and all(case["passed"] for case in routine_cases)
            and all(performance_criteria.values())
        ),
    }


def _entity_cardinality_case(entity_count: int, iterations: int) -> dict[str, Any]:
    source, haystack = _dense_prefix_source(256, entity_count=entity_count, pattern_count=8)
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
    entity_tuples = _raw_tuples(default_bank.scan_bytes(haystack))
    reconstructed_tuples = _raw_tuples(overlap_bank.scan_bytes_leftmost_from_all_overlaps(haystack))
    metadata = {
        "entity_independent": _mode_metadata(default_bank),
        "all_overlaps": _mode_metadata(overlap_bank),
        "global_leftmost": _mode_metadata(global_bank),
    }
    criteria = _mode_pass_criteria(
        entity=entity,
        raw=raw,
        reconstructed=reconstructed,
        global_leftmost=global_leftmost,
        entity_tuples=entity_tuples,
        reconstructed_tuples=reconstructed_tuples,
        metadata=metadata,
    )
    return {
        "entity_count": entity_count,
        "workload": "dense_prefix",
        "pattern_count": entity_count * 8,
        "document_bytes": len(haystack),
        "entity_independent": entity,
        "all_overlaps_raw": raw,
        "all_overlaps_reconstructed": reconstructed,
        "global_leftmost": global_leftmost,
        "raw_to_entity_count_ratio": _ratio(raw["count"], entity["count"]),
        "global_to_entity_count_ratio": _ratio(global_leftmost["count"], entity["count"]),
        "criteria": criteria,
        "passed": all(criteria.values()),
    }


def _entity_cardinality_routine_case(entity_count: int, iterations: int, target_bytes: int) -> dict[str, Any]:
    source, haystack = _sparse_cardinality_source(target_bytes, entity_count=entity_count, pattern_count=8)
    native_engine = importlib.import_module("nerb._engine")
    default_bank = native_engine.Bank.from_source_bytes(source, format_hint="jsonl")
    entity = _measure_raw(lambda: default_bank.scan_bytes(haystack), iterations)
    return {
        "entity_count": entity_count,
        "workload": "routine_size_sparse_no_match",
        "pattern_count": entity_count * 8,
        "document_bytes": len(haystack),
        "entity_independent": entity,
        "criteria": {
            "entity_count_stable": entity["count_stable"] is True,
        },
        "passed": entity["count_stable"] is True,
    }


def _measure_public_bank_cache_lookup(source: bytes, iterations: int) -> dict[str, Any]:
    clear_bank_cache()
    cold_start = time.perf_counter()
    cold_bank = Bank.from_source_bytes(source, format_hint="jsonl", use_cache=True)
    cold_seconds = time.perf_counter() - cold_start
    cold_cache = cold_bank.cache_metadata()
    warm = _measure_seconds(lambda: Bank.from_source_bytes(source, format_hint="jsonl", use_cache=True), iterations)
    info = bank_cache_info()
    return {
        "cold_seconds": round(cold_seconds, 6),
        "warm_cache_lookup": warm,
        "cache_info": info,
        "cache_hit_verified": cold_cache["hit"] is False and info["misses"] == 1 and info["hits"] >= iterations,
    }


def _parse_jsonl_source(source: bytes) -> list[dict[str, Any]]:
    return [json.loads(line) for line in source.decode("utf-8").splitlines() if line]


def _run_memory_child(iterations: int, dense_bytes: int) -> dict[str, Any]:
    command = [
        sys.executable,
        __file__,
        "--memory-child",
        "--iterations",
        str(iterations),
        "--dense-bytes",
        str(dense_bytes),
    ]
    completed = subprocess.run(command, capture_output=True, check=False, text=True)
    if completed.returncode != 0:
        return {
            "status": "failed",
            "command": " ".join(command),
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
    try:
        parsed = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        return {
            "status": "failed",
            "command": " ".join(command),
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "error": str(error),
        }
    if not isinstance(parsed, dict):
        return {
            "status": "failed",
            "command": " ".join(command),
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "error": "memory child did not emit a JSON object",
        }
    parsed["command"] = " ".join(command)
    return parsed


def _overall_report(sections: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    included = {
        name: section["passed"]
        for name, section in sections.items()
        if section.get("included_in_overall", True) is True
    }
    external_required = [
        name for name, section in sections.items() if section.get("included_in_overall", True) is False
    ]
    return {
        "passed": all(passed is True for passed in included.values()),
        "included_sections": included,
        "external_required_sections": external_required,
    }


def _ratio(numerator: float, denominator: float) -> float | None:
    if denominator == 0:
        return None
    return round(numerator / denominator, 3)


def _bytes_per_second(byte_count: int, seconds: float) -> float:
    if seconds <= 0:
        return float("inf")
    return round(byte_count / seconds, 3)


def _repeat_to_size(seed: str, target_bytes: int) -> str:
    repeated = seed * ((target_bytes // len(seed.encode("utf-8"))) + 1)
    encoded = repeated.encode("utf-8")[:target_bytes]
    return encoded.decode("utf-8", errors="ignore")


def _project_native_scan_records(bank: Any, text_bytes: bytes) -> list[dict[str, Any]]:
    metadata = bank.metadata()
    detectors = {detector["detector_index"]: detector for detector in metadata["detectors"]}
    raw = bank.scan_bytes(text_bytes)
    projected: list[dict[str, Any]] = []
    for index in range(len(raw)):
        detector_index, start, end = raw[index]
        detector = detectors[detector_index]
        projected.append(
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
    return sorted(projected, key=_record_sort_key)


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


def _dense_prefix_source(document_bytes: int, *, entity_count: int = 2, pattern_count: int = 32) -> tuple[bytes, bytes]:
    rows = []
    for entity_number in range(entity_count):
        entity = ("ALPHA", "BETA")[entity_number] if entity_count == 2 else f"DENSE_{entity_number:03d}"
        for index in range(pattern_count, 0, -1):
            token = "A" * index
            rows.append(
                {
                    "entity": entity,
                    "canonical_name": f"{entity}_A{index}",
                    "surface_name": f"{entity}_A{index}",
                    "regex": token,
                    "priority": pattern_count - index,
                }
            )
    source = ("\n".join(json.dumps(row, separators=(",", ":")) for row in rows) + "\n").encode("utf-8")
    return source, b"A" * document_bytes


def _sparse_cardinality_source(document_bytes: int, *, entity_count: int, pattern_count: int) -> tuple[bytes, bytes]:
    rows = []
    for entity_number in range(entity_count):
        entity = f"SPARSE_{entity_number:03d}"
        for index in range(pattern_count):
            token = f"TOKEN_{entity_number:03d}_{index:03d}"
            rows.append(
                {
                    "entity": entity,
                    "canonical_name": token,
                    "surface_name": token,
                    "regex": token,
                    "priority": index,
                }
            )
    source = ("\n".join(json.dumps(row, separators=(",", ":")) for row in rows) + "\n").encode("utf-8")
    return source, b"z" * document_bytes


def _measure(operation: Callable[[], Any], iterations: int) -> dict[str, Any]:
    seconds = []
    counts = []
    for _ in range(iterations):
        start = time.perf_counter()
        result = operation()
        seconds.append(time.perf_counter() - start)
        counts.append(result if isinstance(result, int) else len(result))
    return _measurement(seconds, counts)


def _measure_with_result(operation: Callable[[], Any], iterations: int) -> tuple[dict[str, Any], Any]:
    seconds = []
    counts = []
    last_result = None
    for _ in range(iterations):
        start = time.perf_counter()
        last_result = operation()
        seconds.append(time.perf_counter() - start)
        counts.append(last_result if isinstance(last_result, int) else len(last_result))
    return _measurement(seconds, counts), last_result


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


def _measure_raw_with_capacity(operation: Callable[[], Any], iterations: int) -> tuple[dict[str, Any], int]:
    seconds = []
    counts = []
    last_capacity = 0
    for _ in range(iterations):
        start = time.perf_counter()
        buffer = operation()
        seconds.append(time.perf_counter() - start)
        counts.append(len(buffer))
        last_capacity = int(buffer.capacity())
    return _measurement(seconds, counts), last_capacity


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


def _raw_tuples(buffer: Any) -> list[tuple[int, int, int]]:
    tuples = []
    for index in range(len(buffer)):
        detector_index, start, end = buffer[index]
        tuples.append((int(detector_index), int(start), int(end)))
    return tuples


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

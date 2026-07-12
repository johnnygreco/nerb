from __future__ import annotations

import argparse
import importlib
import json
import math
import platform
import resource
import statistics
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from nerb import Bank, __version__, bank_cache_info, clear_bank_cache

MEMORY_BUDGET_KIB = 64 * 1024
MEMORY_ABSOLUTE_BUDGET_KIB = 256 * 1024
MATCH_BUFFER_PRE_SCAN_CAP = 1_000_000
MIN_TIMING_SAMPLES = 5
UNTIMED_WARMUP_ITERATIONS = 1
MEMORY_CHILD_TIMEOUT_SECONDS = 60
MAX_GATE_ITERATIONS = 1_000
MAX_MEMORY_CHILD_OUTPUT_BYTES = 1024 * 1024
MAX_PROTOCOL_INTEGER = 2**63 - 1
CARDINALITY_SCAN_SECONDS_CEILING = 0.01
CARDINALITY_ROUTINE_SCAN_SECONDS_CEILING = 0.05
DENSE_CARDINALITY_ENTITY_COUNT = 64
MEDIUM_BANK_ENTITY_COUNT = 1_000
MEDIUM_BANK_DOCUMENT_BYTES_FLOOR = 100_000
MEDIUM_BANK_PATTERNS_PER_ENTITY = 8
VALIDATED_ENTITY_COUNT = MEDIUM_BANK_ENTITY_COUNT
CARDINALITY_SCALING_RATIO_CEILING = 80.0
MEDIUM_BANK_TO_ROUTINE_MAX_RATIO_CEILING = 40.0
MEDIUM_BANK_THRESHOLDS = {
    "compile_seconds_ceiling": 5.0,
    "rust_raw_scan_seconds_ceiling": 0.2,
    "rust_scan_project_seconds_ceiling": 0.2,
    "rust_scan_project_bytes_per_second_floor": 500_000.0,
}
CORPUS_SIZE_THRESHOLDS = {
    "rust_scan_project_bytes_per_second_floor": 5_000_000.0,
}
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
    "mixed": {
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
    parser.add_argument(
        "--bank-owner-entity-count",
        type=int,
        default=None,
        help="Bank-owner current or target entity count for final cardinality signoff.",
    )
    parser.add_argument(
        "--bank-owner-growth-entity-count",
        type=int,
        default=None,
        help="Bank-owner expected growth entity count for final cardinality signoff.",
    )
    parser.add_argument(
        "--bank-owner-note",
        default=None,
        help="Optional note describing the bank-owner cardinality source.",
    )
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
            bank_owner_entity_count=args.bank_owner_entity_count,
            bank_owner_growth_entity_count=args.bank_owner_growth_entity_count,
            bank_owner_note=args.bank_owner_note,
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
    bank_owner_entity_count: int | None = None,
    bank_owner_growth_entity_count: int | None = None,
    bank_owner_note: str | None = None,
) -> dict[str, Any]:
    if type(iterations) is not int or not 1 <= iterations <= MAX_GATE_ITERATIONS:
        raise ValueError(f"--iterations must be between 1 and {MAX_GATE_ITERATIONS}.")
    if target_bytes < 10_000:
        raise ValueError("--target-bytes must be at least 10000.")
    if dense_bytes < 64:
        raise ValueError("--dense-bytes must be at least 64.")
    if memory_budget_kib < 0:
        raise ValueError("--memory-budget-kib must be non-negative.")
    if memory_absolute_budget_kib < 0:
        raise ValueError("--memory-absolute-budget-kib must be non-negative.")
    if bank_owner_entity_count is not None and bank_owner_entity_count < 1:
        raise ValueError("--bank-owner-entity-count must be positive when provided.")
    if bank_owner_growth_entity_count is not None and bank_owner_growth_entity_count < 1:
        raise ValueError("--bank-owner-growth-entity-count must be positive when provided.")

    conformance = _conformance_summary()
    performance = _performance_report(iterations, target_bytes)
    memory = _memory_report(iterations, dense_bytes, memory_budget_kib, memory_absolute_budget_kib)
    mode_strategy = _mode_strategy_report(iterations, dense_bytes, target_bytes)
    distribution = _distribution_report()
    bank_owner_cardinality = _bank_owner_cardinality_report(
        bank_owner_entity_count,
        bank_owner_growth_entity_count,
        bank_owner_note,
    )
    sections = {
        "conformance": conformance,
        "performance": performance,
        "memory": memory,
        "mode_strategy": mode_strategy,
        "distribution": distribution,
        "bank_owner_cardinality": bank_owner_cardinality,
    }
    return {
        "environment": _environment(),
        "conformance": conformance,
        "performance": performance,
        "memory": memory,
        "mode_strategy": mode_strategy,
        "distribution": distribution,
        "bank_owner_cardinality": bank_owner_cardinality,
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
            "ASCII flag lowering rewrites ASCII-sensitive escapes and boundaries while keeping Unicode-safe scanning.",
            "Detector names with underscores are preserved by the Rust record contract.",
            "global_leftmost remains internal because it drops cross-entity overlap.",
            "raw all_overlaps remains a measured prototype because dense output amplification is high.",
        ],
    }


def _performance_report(iterations: int, target_bytes: int) -> dict[str, Any]:
    small = _workload_report(_small_workload(), iterations, 10_000)
    literal = _workload_report(_literal_workload(), iterations, target_bytes)
    regex = _workload_report(_regex_workload(), iterations, target_bytes)
    mixed = _workload_report(_mixed_workload(), iterations, target_bytes)
    corpus_size = _corpus_size_report(_mixed_workload(), iterations, target_bytes)
    workloads = (small, literal, regex, mixed)
    gate = _gate_summary(
        {
            **{workload["id"]: workload["correctness_passed"] for workload in workloads},
            "corpus_size": corpus_size["correctness_passed"],
        },
        {
            **{workload["id"]: workload["timing_observed_passed"] for workload in workloads},
            "corpus_size": corpus_size["timing_observed_passed"],
        },
        iterations,
    )
    return {
        "included_in_overall": True,
        "baseline_id": "rust-engine-final-gates-v1",
        "iterations": iterations,
        "target_bytes": target_bytes,
        "checked_in_thresholds": {
            "workloads": WORKLOAD_THRESHOLDS,
            "corpus_size": CORPUS_SIZE_THRESHOLDS,
        },
        "pass_criteria": {
            "native_public_records_equal": "Native raw-match projection and public Bank records must match exactly.",
            "count_stable": "Untimed cold and repeated measured scan/project results and counts must be stable.",
            "cache_hit_verified": "Public Bank cache must miss cold and hit warm for the same source/options.",
            "rust_thresholds": (
                "Each workload also enforces checked-in Rust raw-scan ceilings, Rust scan/project ceilings, and "
                "Rust scan/project bytes-per-second floors."
            ),
        },
        "small_bank_floor": small,
        "literal_heavy": literal,
        "regex_heavy": regex,
        "mixed": mixed,
        "corpus_size": corpus_size,
        **gate,
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
    gate = _gate_summary(
        {
            name: passed
            for name, passed in criteria.items()
            if name
            not in {
                "rust_scan_project_under_ceiling",
                "rust_raw_scan_under_ceiling",
                "rust_scan_project_throughput_floor",
            }
        },
        {
            name: criteria[name]
            for name in (
                "rust_scan_project_under_ceiling",
                "rust_raw_scan_under_ceiling",
                "rust_scan_project_throughput_floor",
            )
        },
        iterations,
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
        **gate,
    }


def _corpus_size_report(workload: dict[str, Any], iterations: int, target_bytes: int) -> dict[str, Any]:
    source = _jsonl_source(workload["pattern_config"])
    native_engine = importlib.import_module("nerb._engine")
    native_bank = native_engine.Bank.from_source_bytes(source, format_hint="jsonl")
    public_bank = Bank.from_source_bytes(source, format_hint="jsonl", use_cache=False)
    sizes = [10_000]
    if target_bytes != 10_000:
        sizes.append(target_bytes)
    cases = [
        _corpus_size_case(
            workload,
            public_bank=public_bank,
            native_bank=native_bank,
            iterations=iterations,
            target_bytes=size,
        )
        for size in sizes
    ]
    gate = _gate_summary(
        {str(case["text_bytes"]): case["correctness_passed"] for case in cases},
        {str(case["text_bytes"]): case["timing_observed_passed"] for case in cases},
        iterations,
    )
    return {
        "description": "Mixed-bank corpus-size scaling over the routine target document sizes.",
        "workload_id": workload["id"],
        "text_bytes": [case["text_bytes"] for case in cases],
        "thresholds": CORPUS_SIZE_THRESHOLDS,
        "cases": cases,
        **gate,
    }


def _corpus_size_case(
    workload: dict[str, Any],
    *,
    public_bank: Bank,
    native_bank: Any,
    iterations: int,
    target_bytes: int,
) -> dict[str, Any]:
    text = _repeat_to_size(workload["text_seed"], target_bytes)
    text_bytes = text.encode("utf-8")
    raw_scan = _measure_raw(lambda: native_bank.scan_bytes(text_bytes), iterations)
    scan_project = _measure(lambda: public_bank.scan_text(text), iterations)
    bytes_per_second = _bytes_per_second(len(text_bytes), scan_project["median_seconds"])
    criteria = {
        "rust_raw_scan_count_stable": raw_scan["count_stable"] is True,
        "rust_raw_scan_warmup_matches_measured": raw_scan["warmup_matches_measured"] is True,
        "rust_scan_project_count_stable": scan_project["count_stable"] is True,
        "rust_scan_project_warmup_matches_measured": scan_project["warmup_matches_measured"] is True,
        "rust_scan_project_throughput_floor": (
            bytes_per_second >= CORPUS_SIZE_THRESHOLDS["rust_scan_project_bytes_per_second_floor"]
        ),
    }
    gate = _gate_summary(
        {
            "rust_raw_scan_count_stable": criteria["rust_raw_scan_count_stable"],
            "rust_raw_scan_warmup_matches_measured": criteria["rust_raw_scan_warmup_matches_measured"],
            "rust_scan_project_count_stable": criteria["rust_scan_project_count_stable"],
            "rust_scan_project_warmup_matches_measured": criteria["rust_scan_project_warmup_matches_measured"],
        },
        {"rust_scan_project_throughput_floor": criteria["rust_scan_project_throughput_floor"]},
        iterations,
    )
    return {
        "text_bytes": len(text_bytes),
        "rust_entity_independent_scan_raw": raw_scan,
        "rust_entity_independent_scan_project": scan_project,
        "rust_scan_project_bytes_per_second": bytes_per_second,
        "criteria": criteria,
        **gate,
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
    gate = _gate_summary(
        {
            **criteria,
            "entity_cardinality_sweep": cardinality_sweep["correctness_passed"],
        },
        {"entity_cardinality_sweep": cardinality_sweep["timing_observed_passed"]},
        iterations,
    )

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
        **gate,
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
    if type(iterations) is not int or not 1 <= iterations <= MAX_GATE_ITERATIONS:
        raise ValueError(f"--iterations must be between 1 and {MAX_GATE_ITERATIONS}.")
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
    validation_error = None
    if child.get("status") == "measured":
        child_iterations = child.get("iterations")
        child_dense_bytes = child.get("dense_probe_bytes")
        if (
            type(child_iterations) is not int
            or not 0 <= child_iterations <= MAX_PROTOCOL_INTEGER
            or type(child_dense_bytes) is not int
            or not 0 <= child_dense_bytes <= MAX_PROTOCOL_INTEGER
        ):
            validation_error = "memory child payload contains invalid request metadata"
        else:
            validation_error = _memory_child_payload_error(
                child,
                iterations=child_iterations,
                dense_bytes=child_dense_bytes,
            )
    if child.get("status") != "measured" or validation_error is not None:
        return {
            "included_in_overall": True,
            "status": "failed",
            "error": validation_error or "memory child did not return a measured payload",
            "correctness_passed": False,
            "passed": False,
            "memory_budget_kib": memory_budget_kib,
            "memory_absolute_budget_kib": memory_absolute_budget_kib,
            "diagnostic_output_included": False,
            "criteria": {
                "child_probe_measured": False,
                "raw_match_count_stable": False,
                "raw_warmup_matches_measured": False,
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
        "raw_warmup_matches_measured": raw["warmup_matches_measured"] is True,
        "raw_match_count_under_cap": raw["count"] < MATCH_BUFFER_PRE_SCAN_CAP,
        "match_buffer_capacity_under_cap": child["match_buffer_capacity_after_scan"] <= MATCH_BUFFER_PRE_SCAN_CAP,
        "max_rss_growth_within_budget": child["max_rss_kib_growth"] <= memory_budget_kib,
        "max_rss_absolute_within_budget": child["max_rss_kib_after_scan"] <= memory_absolute_budget_kib,
    }
    correctness_passed = all(criteria.values())
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
        "correctness_passed": correctness_passed,
        "passed": correctness_passed,
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


def _bank_owner_cardinality_report(
    entity_count: int | None,
    growth_entity_count: int | None,
    note: str | None,
) -> dict[str, Any]:
    if entity_count is None or growth_entity_count is None:
        return {
            "status": "external_required",
            "passed": None,
            "included_in_overall": False,
            "required_input": [
                "--bank-owner-entity-count",
                "--bank-owner-growth-entity-count",
            ],
            "validated_entity_count_ceiling": VALIDATED_ENTITY_COUNT,
            "decision": (
                "Record the bank-owner current or target entity count and expected growth before final goal "
                "completion. Counts above the validated ceiling require a new mode-strategy issue before changing "
                "the default."
            ),
        }

    max_claimed = max(entity_count, growth_entity_count)
    criteria = {
        "entity_count_recorded": entity_count > 0,
        "growth_entity_count_recorded": growth_entity_count > 0,
        "current_entity_count_within_validated_range": entity_count <= VALIDATED_ENTITY_COUNT,
        "growth_entity_count_within_validated_range": growth_entity_count <= VALIDATED_ENTITY_COUNT,
    }
    return {
        "status": "recorded",
        "passed": all(criteria.values()),
        "included_in_overall": True,
        "entity_count": entity_count,
        "growth_entity_count": growth_entity_count,
        "max_claimed_entity_count": max_claimed,
        "validated_entity_count_ceiling": VALIDATED_ENTITY_COUNT,
        "note": note,
        "decision": (
            "entity_independent remains the production default when current and expected-growth entity counts stay "
            "within the synthetic medium-bank range validated by this report."
        ),
        "criteria": criteria,
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


def _mixed_workload() -> dict[str, Any]:
    pattern_config: dict[str, dict[str, Any]] = {}
    text_tokens = []
    for entity_index in range(6):
        entity = f"MIXED_{entity_index:02d}"
        entity_config: dict[str, Any] = {"_flags": "IGNORECASE" if entity_index % 2 == 0 else []}
        for pattern_index in range(40):
            literal_token = f"M{entity_index:02d}_L{pattern_index:03d}"
            entity_config[f"Literal {entity_index:02d} {pattern_index:03d}"] = literal_token
            if pattern_index % 20 == 0:
                text_tokens.append(f"{literal_token} " + ("mixed_literal_miss " * 30))
        for pattern_index in range(20):
            regex_prefix = f"M{entity_index:02d}R{pattern_index:03d}"
            entity_config[f"Regex {entity_index:02d} {pattern_index:03d}"] = (
                rf"{regex_prefix}-(?:alpha|beta|gamma)-\d{{2}}"
            )
            if pattern_index % 10 == 0:
                text_tokens.append(f"{regex_prefix}-alpha-42 " + ("mixed_regex_miss " * 30))
        pattern_config[entity] = entity_config
    return {"id": "mixed", "pattern_config": pattern_config, "text_seed": " ".join(text_tokens) + " none "}


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
        "rust_native_scan_project_warmup_matches_measured": (
            rust_native_scan_project["warmup_matches_measured"] is True
        ),
        "rust_entity_scan_raw_count_stable": rust_entity_scan["count_stable"] is True,
        "rust_entity_scan_raw_warmup_matches_measured": rust_entity_scan["warmup_matches_measured"] is True,
        "rust_entity_scan_project_count_stable": rust_entity_scan_project["count_stable"] is True,
        "rust_entity_scan_project_warmup_matches_measured": (
            rust_entity_scan_project["warmup_matches_measured"] is True
        ),
        "rust_all_overlaps_scan_raw_count_stable": rust_all_overlaps_scan["count_stable"] is True,
        "rust_all_overlaps_scan_raw_warmup_matches_measured": (
            rust_all_overlaps_scan["warmup_matches_measured"] is True
        ),
        "rust_global_leftmost_scan_raw_count_stable": rust_global_scan["count_stable"] is True,
        "rust_global_leftmost_scan_raw_warmup_matches_measured": (rust_global_scan["warmup_matches_measured"] is True),
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
        "entity_warmup_matches_measured": entity["warmup_matches_measured"] is True,
        "all_overlaps_raw_count_stable": raw["count_stable"] is True,
        "all_overlaps_raw_warmup_matches_measured": raw["warmup_matches_measured"] is True,
        "all_overlaps_reconstructed_count_stable": reconstructed["count_stable"] is True,
        "all_overlaps_reconstructed_warmup_matches_measured": reconstructed["warmup_matches_measured"] is True,
        "global_leftmost_count_stable": global_leftmost["count_stable"] is True,
        "global_leftmost_warmup_matches_measured": global_leftmost["warmup_matches_measured"] is True,
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
    entity_counts = (2, 8, 32, DENSE_CARDINALITY_ENTITY_COUNT)
    cases = [_entity_cardinality_case(entity_count, iterations) for entity_count in entity_counts]
    routine_cases = [
        _entity_cardinality_routine_case(entity_count, iterations, target_bytes)
        for entity_count in (2, DENSE_CARDINALITY_ENTITY_COUNT)
    ]
    medium_bank_target_bytes = max(target_bytes, MEDIUM_BANK_DOCUMENT_BYTES_FLOOR)
    medium_bank_baseline_case = _entity_cardinality_routine_case(
        DENSE_CARDINALITY_ENTITY_COUNT,
        iterations,
        medium_bank_target_bytes,
    )
    medium_bank_case = _medium_bank_cardinality_case(MEDIUM_BANK_ENTITY_COUNT, iterations, medium_bank_target_bytes)
    base_seconds = max(float(cases[0]["entity_independent"]["median_seconds"]), 0.000001)
    max_case = cases[-1]
    scaling_ratio = _ratio(max_case["entity_independent"]["median_seconds"], base_seconds)
    routine_base_seconds = max(float(routine_cases[0]["entity_independent"]["median_seconds"]), 0.000001)
    routine_max_case = routine_cases[-1]
    routine_scaling_ratio = _ratio(routine_max_case["entity_independent"]["median_seconds"], routine_base_seconds)
    medium_to_routine_max_seconds_ratio = _ratio(
        medium_bank_case["entity_independent"]["median_seconds"],
        max(float(medium_bank_baseline_case["entity_independent"]["median_seconds"]), 0.000001),
    )
    performance_criteria = {
        "max_dense_entity_independent_scan_seconds_under_ceiling": (
            max_case["entity_independent"]["median_seconds"] <= CARDINALITY_SCAN_SECONDS_CEILING
        ),
        "dense_entity_independent_scaling_ratio_under_ceiling": (
            scaling_ratio is not None and scaling_ratio <= CARDINALITY_SCALING_RATIO_CEILING
        ),
        "routine_max_entity_independent_scan_seconds_under_ceiling": (
            routine_max_case["entity_independent"]["median_seconds"] <= CARDINALITY_ROUTINE_SCAN_SECONDS_CEILING
        ),
        "routine_max_to_2_entity_scan_seconds_ratio_under_ceiling": (
            routine_scaling_ratio is not None and routine_scaling_ratio <= CARDINALITY_SCALING_RATIO_CEILING
        ),
        "medium_bank_compile_seconds_under_ceiling": (
            medium_bank_case["criteria"]["compile_seconds_under_ceiling"] is True
        ),
        "medium_bank_raw_scan_seconds_under_ceiling": (
            medium_bank_case["criteria"]["rust_raw_scan_seconds_under_ceiling"] is True
        ),
        "medium_bank_scan_project_seconds_under_ceiling": (
            medium_bank_case["criteria"]["rust_scan_project_seconds_under_ceiling"] is True
        ),
        "medium_bank_scan_project_throughput_floor": (
            medium_bank_case["criteria"]["rust_scan_project_throughput_floor"] is True
        ),
        "medium_bank_to_routine_max_entity_scan_seconds_ratio_under_ceiling": (
            medium_to_routine_max_seconds_ratio is not None
            and medium_to_routine_max_seconds_ratio <= MEDIUM_BANK_TO_ROUTINE_MAX_RATIO_CEILING
        ),
    }
    correctness_criteria = {
        "dense_cases": all(case["correctness_passed"] for case in cases),
        "routine_size_cases": all(case["correctness_passed"] for case in routine_cases),
        "medium_bank_baseline_case": medium_bank_baseline_case["correctness_passed"],
        "medium_bank_case": medium_bank_case["correctness_passed"],
    }
    gate = _gate_summary(correctness_criteria, performance_criteria, iterations)
    return {
        "description": (
            "Synthetic cardinality evidence. Dense cases use 8 prefix detectors per entity over 256 bytes through the "
            "dense all-overlaps stress ceiling; the medium-bank case uses sparse no-match text over the configured "
            "target bytes with 1,000 top-level entities."
        ),
        "validated_entity_count_ceiling": VALIDATED_ENTITY_COUNT,
        "dense_entity_count_ceiling": DENSE_CARDINALITY_ENTITY_COUNT,
        "medium_bank_entity_count": MEDIUM_BANK_ENTITY_COUNT,
        "medium_bank_document_bytes_floor": MEDIUM_BANK_DOCUMENT_BYTES_FLOOR,
        "entity_counts": [case["entity_count"] for case in cases] + [medium_bank_case["entity_count"]],
        "dense_entity_counts": [case["entity_count"] for case in cases],
        "routine_entity_counts": [case["entity_count"] for case in routine_cases] + [medium_bank_case["entity_count"]],
        "performance_thresholds": {
            "max_dense_entity_independent_scan_seconds": CARDINALITY_SCAN_SECONDS_CEILING,
            "max_routine_entity_independent_scan_seconds": CARDINALITY_ROUTINE_SCAN_SECONDS_CEILING,
            "max_to_2_entity_scan_seconds_ratio": CARDINALITY_SCALING_RATIO_CEILING,
            "medium_bank": MEDIUM_BANK_THRESHOLDS,
            "medium_bank_to_routine_max_entity_scan_seconds_ratio": MEDIUM_BANK_TO_ROUTINE_MAX_RATIO_CEILING,
        },
        "performance": {
            "dense_entity_independent_max_to_2_scan_seconds_ratio": scaling_ratio,
            "routine_entity_independent_max_to_2_scan_seconds_ratio": routine_scaling_ratio,
            "medium_bank_to_routine_max_entity_scan_seconds_ratio": medium_to_routine_max_seconds_ratio,
            "criteria": performance_criteria,
        },
        "dense_cases": cases,
        "routine_size_cases": routine_cases,
        "medium_bank_baseline_case": medium_bank_baseline_case,
        "medium_bank_case": medium_bank_case,
        **gate,
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
    correctness_passed = all(criteria.values())
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
        "correctness_passed": correctness_passed,
        "passed": correctness_passed,
    }


def _entity_cardinality_routine_case(entity_count: int, iterations: int, target_bytes: int) -> dict[str, Any]:
    source, haystack = _sparse_cardinality_source(target_bytes, entity_count=entity_count, pattern_count=8)
    native_engine = importlib.import_module("nerb._engine")
    default_bank = native_engine.Bank.from_source_bytes(source, format_hint="jsonl")
    entity = _measure_raw(lambda: default_bank.scan_bytes(haystack), iterations)
    correctness_passed = entity["count_stable"] is True and entity["warmup_matches_measured"] is True
    return {
        "entity_count": entity_count,
        "workload": "routine_size_sparse_no_match",
        "pattern_count": entity_count * 8,
        "document_bytes": len(haystack),
        "entity_independent": entity,
        "criteria": {
            "entity_count_stable": correctness_passed,
        },
        "correctness_passed": correctness_passed,
        "passed": correctness_passed,
    }


def _medium_bank_cardinality_case(entity_count: int, iterations: int, target_bytes: int) -> dict[str, Any]:
    source, haystack = _sparse_cardinality_source(
        target_bytes,
        entity_count=entity_count,
        pattern_count=MEDIUM_BANK_PATTERNS_PER_ENTITY,
    )
    text = haystack.decode("utf-8")
    native_engine = importlib.import_module("nerb._engine")
    compile_seconds = _measure_seconds(
        lambda: native_engine.Bank.from_source_bytes(source, format_hint="jsonl"),
        iterations,
    )
    default_bank = native_engine.Bank.from_source_bytes(source, format_hint="jsonl")
    public_bank = Bank.from_source_bytes(source, format_hint="jsonl", use_cache=False)
    entity = _measure_raw(lambda: default_bank.scan_bytes(haystack), iterations)
    scan_project = _measure(lambda: public_bank.scan_text(text), iterations)
    bytes_per_second = _bytes_per_second(len(haystack), scan_project["median_seconds"])
    criteria = {
        "entity_count_stable": entity["count_stable"] is True,
        "entity_warmup_matches_measured": entity["warmup_matches_measured"] is True,
        "scan_project_count_stable": scan_project["count_stable"] is True,
        "scan_project_warmup_matches_measured": scan_project["warmup_matches_measured"] is True,
        "compile_seconds_under_ceiling": compile_seconds["median_seconds"]
        <= MEDIUM_BANK_THRESHOLDS["compile_seconds_ceiling"],
        "rust_raw_scan_seconds_under_ceiling": entity["median_seconds"]
        <= MEDIUM_BANK_THRESHOLDS["rust_raw_scan_seconds_ceiling"],
        "rust_scan_project_seconds_under_ceiling": scan_project["median_seconds"]
        <= MEDIUM_BANK_THRESHOLDS["rust_scan_project_seconds_ceiling"],
        "rust_scan_project_throughput_floor": (
            bytes_per_second >= MEDIUM_BANK_THRESHOLDS["rust_scan_project_bytes_per_second_floor"]
        ),
    }
    gate = _gate_summary(
        {
            "entity_count_stable": criteria["entity_count_stable"],
            "entity_warmup_matches_measured": criteria["entity_warmup_matches_measured"],
            "scan_project_count_stable": criteria["scan_project_count_stable"],
            "scan_project_warmup_matches_measured": criteria["scan_project_warmup_matches_measured"],
        },
        {
            name: criteria[name]
            for name in (
                "compile_seconds_under_ceiling",
                "rust_raw_scan_seconds_under_ceiling",
                "rust_scan_project_seconds_under_ceiling",
                "rust_scan_project_throughput_floor",
            )
        },
        iterations,
    )
    return {
        "entity_count": entity_count,
        "workload": "medium_bank_sparse_no_match",
        "pattern_count": entity_count * MEDIUM_BANK_PATTERNS_PER_ENTITY,
        "patterns_per_entity": MEDIUM_BANK_PATTERNS_PER_ENTITY,
        "source_bytes": len(source),
        "document_bytes": len(haystack),
        "rust_entity_independent_compile": compile_seconds,
        "entity_independent": entity,
        "entity_independent_scan_project": scan_project,
        "rust_scan_project_bytes_per_second": bytes_per_second,
        "thresholds": MEDIUM_BANK_THRESHOLDS,
        "criteria": criteria,
        **gate,
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
        "cold_seconds": cold_seconds,
        "warm_cache_lookup": warm,
        "cache_info": info,
        "cache_hit_verified": (
            cold_cache["hit"] is False
            and info["misses"] == 1
            and info["hits"] >= iterations + UNTIMED_WARMUP_ITERATIONS
        ),
    }


def _parse_jsonl_source(source: bytes) -> list[dict[str, Any]]:
    return [json.loads(line) for line in source.decode("utf-8").splitlines() if line]


def _run_memory_child(iterations: int, dense_bytes: int) -> dict[str, Any]:
    if type(iterations) is not int or not 1 <= iterations <= MAX_GATE_ITERATIONS:
        return _memory_child_failure(
            returncode=None,
            error="memory child request exceeds the iteration bound",
            stdout_bytes=0,
            stderr_bytes=0,
        )
    command = [
        sys.executable,
        __file__,
        "--memory-child",
        "--iterations",
        str(iterations),
        "--dense-bytes",
        str(dense_bytes),
    ]
    try:
        with tempfile.TemporaryFile(mode="w+b") as stdout_file, tempfile.TemporaryFile(mode="w+b") as stderr_file:
            completed = subprocess.run(
                command,
                stdout=stdout_file,
                stderr=stderr_file,
                check=False,
                timeout=MEMORY_CHILD_TIMEOUT_SECONDS,
            )
            stdout_bytes = stdout_file.tell()
            stderr_bytes = stderr_file.tell()
            if stdout_bytes + stderr_bytes > MAX_MEMORY_CHILD_OUTPUT_BYTES:
                return _memory_child_failure(
                    returncode=completed.returncode,
                    error="memory child output exceeded the byte bound",
                    stdout_bytes=stdout_bytes,
                    stderr_bytes=stderr_bytes,
                )
            stdout_file.seek(0)
            stdout_payload = stdout_file.read()
    except subprocess.TimeoutExpired:
        return {
            "status": "failed",
            "error": "memory child timed out",
            "timeout_seconds": MEMORY_CHILD_TIMEOUT_SECONDS,
            "diagnostic_output_included": False,
        }
    if completed.returncode != 0:
        return _memory_child_failure(
            returncode=completed.returncode,
            error="memory child exited nonzero",
            stdout_bytes=stdout_bytes,
            stderr_bytes=stderr_bytes,
        )
    try:
        parsed = json.loads(stdout_payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return _memory_child_failure(
            returncode=completed.returncode,
            error="memory child emitted invalid JSON",
            stdout_bytes=stdout_bytes,
            stderr_bytes=stderr_bytes,
        )
    validation_error = _memory_child_payload_error(parsed, iterations=iterations, dense_bytes=dense_bytes)
    if validation_error is not None:
        return _memory_child_failure(
            returncode=completed.returncode,
            error=validation_error,
            stdout_bytes=stdout_bytes,
            stderr_bytes=stderr_bytes,
        )
    return parsed


def _memory_child_failure(
    *,
    returncode: int | None,
    error: str,
    stdout_bytes: int,
    stderr_bytes: int,
) -> dict[str, Any]:
    return {
        "status": "failed",
        "returncode": returncode,
        "error": error,
        "stdout_bytes": stdout_bytes,
        "stderr_bytes": stderr_bytes,
        "diagnostic_output_included": False,
    }


def _memory_child_payload_error(value: Any, *, iterations: int, dense_bytes: int) -> str | None:
    expected_fields = {
        "status",
        "dense_probe_bytes",
        "iterations",
        "all_overlaps_raw",
        "match_buffer_capacity_after_scan",
        "max_rss_kib_process_start",
        "max_rss_kib_before_compile",
        "max_rss_kib_after_compile",
        "max_rss_kib_after_scan",
        "max_rss_kib_compile_delta",
        "max_rss_kib_scan_delta",
        "max_rss_kib_growth",
    }
    if type(value) is not dict or set(value) != expected_fields:
        return "memory child payload has an invalid object shape"
    if value["status"] != "measured" or value["iterations"] != iterations or value["dense_probe_bytes"] != dense_bytes:
        return "memory child payload does not match its bounded request"
    if not all(
        _is_bounded_protocol_integer(value[field])
        for field in expected_fields
        - {
            "status",
            "all_overlaps_raw",
        }
    ):
        return "memory child payload contains an invalid bounded integer"

    measurement = value["all_overlaps_raw"]
    expected_measurement_fields = {
        "count",
        "counts",
        "count_stable",
        "warmup_counts",
        "warmup_matches_measured",
        "samples_seconds",
        "sample_count",
        "warmup_iterations",
        "median_seconds",
        "min_seconds",
    }
    if type(measurement) is not dict or set(measurement) != expected_measurement_fields:
        return "memory child measurement has an invalid object shape"
    counts = measurement["counts"]
    warmup_counts = measurement["warmup_counts"]
    samples = measurement["samples_seconds"]
    if (
        type(counts) is not list
        or len(counts) != iterations
        or not all(_is_bounded_protocol_integer(item) for item in counts)
        or type(warmup_counts) is not list
        or len(warmup_counts) != UNTIMED_WARMUP_ITERATIONS
        or not all(_is_bounded_protocol_integer(item) for item in warmup_counts)
        or type(samples) is not list
        or len(samples) != iterations
        or not all(_is_bounded_protocol_seconds(item) for item in samples)
    ):
        return "memory child measurement contains invalid bounded samples"
    if (
        measurement["count"] != counts[0]
        or type(measurement["count_stable"]) is not bool
        or measurement["count_stable"] != (len(set([*warmup_counts, *counts])) == 1)
        or type(measurement["warmup_matches_measured"]) is not bool
        or measurement["sample_count"] != iterations
        or measurement["warmup_iterations"] != UNTIMED_WARMUP_ITERATIONS
        or not _same_protocol_float(measurement["median_seconds"], statistics.median(samples))
        or not _same_protocol_float(measurement["min_seconds"], min(samples))
    ):
        return "memory child measurement statistics are inconsistent"

    process_start = value["max_rss_kib_process_start"]
    before_compile = value["max_rss_kib_before_compile"]
    after_compile = value["max_rss_kib_after_compile"]
    after_scan = value["max_rss_kib_after_scan"]
    if not process_start <= before_compile <= after_compile <= after_scan:
        return "memory child RSS samples are not monotonic"
    if (
        value["max_rss_kib_compile_delta"] != after_compile - before_compile
        or value["max_rss_kib_scan_delta"] != after_scan - after_compile
        or value["max_rss_kib_growth"] != after_scan - process_start
    ):
        return "memory child RSS deltas are inconsistent"
    return None


def _is_bounded_protocol_integer(value: Any) -> bool:
    return type(value) is int and 0 <= value <= MAX_PROTOCOL_INTEGER


def _is_bounded_protocol_seconds(value: Any) -> bool:
    return type(value) in (int, float) and math.isfinite(value) and 0 <= value <= MEMORY_CHILD_TIMEOUT_SECONDS


def _same_protocol_float(actual: Any, expected: float) -> bool:
    return _is_bounded_protocol_seconds(actual) and math.isclose(float(actual), expected, rel_tol=1e-12, abs_tol=1e-15)


def _overall_report(sections: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    included_sections = {
        name: section for name, section in sections.items() if section.get("included_in_overall", True) is True
    }
    included = {name: section["passed"] for name, section in included_sections.items()}
    external_required = [
        name for name, section in sections.items() if section.get("included_in_overall", True) is False
    ]
    timing_sections = {name: section for name, section in included_sections.items() if "timing_eligible" in section}
    correctness_passed = all(
        section.get("correctness_passed", section["passed"]) is True for section in included_sections.values()
    )
    if not timing_sections:
        timing_eligible = False
        timing_status = "not_applicable"
        timing_passed = None
        timing_observed_passed = None
    elif all(section["timing_eligible"] is True for section in timing_sections.values()):
        timing_eligible = True
        timing_passed = all(section["timing_passed"] is True for section in timing_sections.values())
        timing_observed_passed = timing_passed
        timing_status = "passed" if timing_passed else "failed"
    else:
        timing_eligible = False
        timing_passed = None
        timing_observed_passed = all(section["timing_observed_passed"] is True for section in timing_sections.values())
        timing_status = "informational_insufficient_samples"
    return {
        "passed": all(passed is True for passed in included.values()),
        "correctness_passed": correctness_passed,
        "timing_eligible": timing_eligible,
        "timing_status": timing_status,
        "timing_passed": timing_passed,
        "timing_observed_passed": timing_observed_passed,
        "included_sections": included,
        "external_required_sections": external_required,
    }


def _gate_summary(
    correctness_criteria: Mapping[str, bool],
    timing_criteria: Mapping[str, bool],
    sample_count: int,
) -> dict[str, Any]:
    correctness_passed = all(passed is True for passed in correctness_criteria.values())
    timing_observed_passed = all(passed is True for passed in timing_criteria.values())
    timing_eligible = sample_count >= MIN_TIMING_SAMPLES
    timing_passed = timing_observed_passed if timing_eligible else None
    if timing_eligible:
        timing_status = "passed" if timing_observed_passed else "failed"
    else:
        timing_status = "informational_insufficient_samples"
    return {
        "correctness_criteria": dict(correctness_criteria),
        "timing_criteria": dict(timing_criteria),
        "correctness_passed": correctness_passed,
        "timing_sample_count": sample_count,
        "minimum_timing_samples": MIN_TIMING_SAMPLES,
        "timing_eligible": timing_eligible,
        "timing_status": timing_status,
        "timing_passed": timing_passed,
        "timing_observed_passed": timing_observed_passed,
        "passed": correctness_passed and (timing_observed_passed if timing_eligible else True),
    }


def _ratio(numerator: float, denominator: float) -> float | None:
    if denominator == 0:
        return None
    return numerator / denominator


def _bytes_per_second(byte_count: int, seconds: float) -> float:
    if seconds <= 0:
        return float("inf")
    return byte_count / seconds


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
    warmup_results = _warm_up(operation)
    warmup_counts = [_result_count(result) for result in warmup_results]
    reference_result = warmup_results[-1]
    seconds = []
    counts = []
    warmup_matches_measured = True
    for _ in range(iterations):
        start = time.perf_counter()
        result = operation()
        seconds.append(time.perf_counter() - start)
        counts.append(_result_count(result))
        warmup_matches_measured = warmup_matches_measured and result == reference_result
    return _measurement(
        seconds,
        counts,
        warmup_counts=warmup_counts,
        warmup_matches_measured=warmup_matches_measured,
        warmup_iterations=UNTIMED_WARMUP_ITERATIONS,
    )


def _measure_with_result(operation: Callable[[], Any], iterations: int) -> tuple[dict[str, Any], Any]:
    warmup_results = _warm_up(operation)
    warmup_counts = [_result_count(result) for result in warmup_results]
    reference_result = warmup_results[-1]
    seconds = []
    counts = []
    last_result = None
    warmup_matches_measured = True
    for _ in range(iterations):
        start = time.perf_counter()
        last_result = operation()
        seconds.append(time.perf_counter() - start)
        counts.append(_result_count(last_result))
        warmup_matches_measured = warmup_matches_measured and last_result == reference_result
    return (
        _measurement(
            seconds,
            counts,
            warmup_counts=warmup_counts,
            warmup_matches_measured=warmup_matches_measured,
            warmup_iterations=UNTIMED_WARMUP_ITERATIONS,
        ),
        last_result,
    )


def _measure_seconds(operation: Callable[[], Any], iterations: int) -> dict[str, Any]:
    _warm_up(operation)
    seconds = []
    for _ in range(iterations):
        start = time.perf_counter()
        operation()
        seconds.append(time.perf_counter() - start)
    second_values = list(seconds)
    return {
        "samples_seconds": second_values,
        "sample_count": len(second_values),
        "warmup_iterations": UNTIMED_WARMUP_ITERATIONS,
        "median_seconds": statistics.median(second_values),
        "min_seconds": min(second_values),
    }


def _measure_raw(operation: Callable[[], Any], iterations: int) -> dict[str, Any]:
    warmup_buffers = _warm_up(operation)
    warmup_counts = [len(buffer) for buffer in warmup_buffers]
    reference_tuples = _raw_tuples(warmup_buffers[-1])
    seconds = []
    counts = []
    warmup_matches_measured = True
    for _ in range(iterations):
        start = time.perf_counter()
        buffer = operation()
        seconds.append(time.perf_counter() - start)
        counts.append(len(buffer))
        warmup_matches_measured = warmup_matches_measured and _raw_tuples(buffer) == reference_tuples
    return _measurement(
        seconds,
        counts,
        warmup_counts=warmup_counts,
        warmup_matches_measured=warmup_matches_measured,
        warmup_iterations=UNTIMED_WARMUP_ITERATIONS,
    )


def _measure_raw_with_capacity(operation: Callable[[], Any], iterations: int) -> tuple[dict[str, Any], int]:
    warmup_buffers = _warm_up(operation)
    warmup_counts = [len(buffer) for buffer in warmup_buffers]
    reference_tuples = _raw_tuples(warmup_buffers[-1])
    seconds = []
    counts = []
    max_capacity = max(int(buffer.capacity()) for buffer in warmup_buffers)
    warmup_matches_measured = True
    for _ in range(iterations):
        start = time.perf_counter()
        buffer = operation()
        seconds.append(time.perf_counter() - start)
        counts.append(len(buffer))
        max_capacity = max(max_capacity, int(buffer.capacity()))
        warmup_matches_measured = warmup_matches_measured and _raw_tuples(buffer) == reference_tuples
    return (
        _measurement(
            seconds,
            counts,
            warmup_counts=warmup_counts,
            warmup_matches_measured=warmup_matches_measured,
            warmup_iterations=UNTIMED_WARMUP_ITERATIONS,
        ),
        max_capacity,
    )


def _warm_up(operation: Callable[[], Any]) -> list[Any]:
    return [operation() for _ in range(UNTIMED_WARMUP_ITERATIONS)]


def _result_count(result: Any) -> int:
    return result if isinstance(result, int) else len(result)


def _measurement(
    seconds: Iterable[float],
    counts: list[int],
    *,
    warmup_counts: Iterable[int] = (),
    warmup_matches_measured: bool = True,
    warmup_iterations: int = 0,
) -> dict[str, Any]:
    second_values = list(seconds)
    warmup_count_values = list(warmup_counts)
    correctness_counts = [*warmup_count_values, *counts]
    return {
        "count": counts[0],
        "counts": list(counts),
        "count_stable": len(set(correctness_counts)) == 1,
        "warmup_counts": warmup_count_values,
        "warmup_matches_measured": warmup_matches_measured,
        "samples_seconds": second_values,
        "sample_count": len(second_values),
        "warmup_iterations": warmup_iterations,
        "median_seconds": statistics.median(second_values),
        "min_seconds": min(second_values),
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
    max_rss = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    if platform.system() == "Darwin":
        return (max_rss + 1023) // 1024
    return max_rss


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

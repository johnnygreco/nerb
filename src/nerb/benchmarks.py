from __future__ import annotations

import re
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from .bank import bank_stats, canonicalize_bank, hash_bank
from .diagnostics import REGEX_EXPENSIVE_PROBE, REGEX_EXPENSIVE_STATIC, Diagnostic
from .diff import diff_banks
from .engines import (
    CompiledBank,
    ExtractionError,
    clear_compiled_bank_cache,
    compile_bank,
    compiled_bank_cache_info,
)
from .evals import eval_bank
from .extraction import _prepare_batch_documents
from .records import record_sort_key
from .validation import VALIDATION_LEVELS, validate_bank

__all__ = ["benchmark_bank", "regress_bank"]

DEFAULT_BENCHMARK_ITERATIONS = 3
DEFAULT_STRESS_MULTIPLIER = 8
DEFAULT_MAX_PATTERN_EXAMPLES = 12
BENCHMARK_TIERS = ("baseline", "target", "stress")


@dataclass(frozen=True)
class BenchmarkOptions:
    iterations: int
    stress_multiplier: int
    max_pattern_examples: int
    validation_level: str


def benchmark_bank(
    bank: Mapping[str, Any],
    *,
    documents: Sequence[Mapping[str, Any]] | Mapping[str, Any] | None = None,
    options: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Measure cold compile cost and warm extraction throughput for a JSON bank."""
    if not isinstance(bank, Mapping):
        raise TypeError("benchmark_bank requires a mapping bank object.")

    raw_options = options or {}
    benchmark_options = _resolve_benchmark_options(raw_options)
    canonical_bank = canonicalize_bank(bank)
    validation = validate_bank(canonical_bank, level=benchmark_options.validation_level)
    if not validation["valid"]:
        raise ExtractionError("Bank failed validation and cannot be benchmarked.", validation["diagnostics"])

    document_tiers = _resolve_document_tiers([canonical_bank], documents, benchmark_options)
    compile_report, compiled = _measure_compile(canonical_bank, raw_options)
    tiers = {
        tier: _measure_tier(compiled, document_tiers[tier], raw_options, benchmark_options) for tier in BENCHMARK_TIERS
    }
    profile = _bank_profile(canonical_bank)

    return {
        "bank": {
            "id": canonical_bank["id"],
            "version": canonical_bank["version"],
            "schema_version": canonical_bank["schema_version"],
            "hash": hash_bank(canonical_bank),
            "stats": bank_stats(canonical_bank),
            "profile": profile,
        },
        "engine": {
            "name": compiled.engine_name,
            "version": compiled.engine_version,
            "normalization": compiled.normalization,
            "include_statuses": list(compiled.include_statuses),
        },
        "options": {
            "iterations": benchmark_options.iterations,
            "stress_multiplier": benchmark_options.stress_multiplier,
            "max_pattern_examples": benchmark_options.max_pattern_examples,
            "validation_level": benchmark_options.validation_level,
        },
        "compile": compile_report,
        "tiers": tiers,
        "summary": _benchmark_summary(tiers, compile_report, profile, benchmark_options),
        "diagnostics": _benchmark_diagnostics(validation),
    }


def regress_bank(
    old_bank: Mapping[str, Any],
    new_bank: Mapping[str, Any],
    *,
    base_path: str | Path | None = None,
    options: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Run diff, eval, and benchmark comparisons for two JSON banks."""
    if not isinstance(old_bank, Mapping) or not isinstance(new_bank, Mapping):
        raise TypeError("regress_bank requires mapping bank objects.")

    raw_options = options or {}
    benchmark_options = _resolve_benchmark_options(raw_options)
    diff = diff_banks(old_bank, new_bank)
    old_canonical = canonicalize_bank(old_bank)
    new_canonical = canonicalize_bank(new_bank)
    benchmark_documents = _regression_benchmark_documents(old_canonical, new_canonical, raw_options, benchmark_options)

    old_eval = eval_bank(
        old_canonical,
        base_path=_regression_eval_base_path(base_path, raw_options, "old"),
        options=raw_options,
    )
    new_eval = eval_bank(
        new_canonical,
        base_path=_regression_eval_base_path(base_path, raw_options, "new"),
        options=raw_options,
    )
    old_benchmark = benchmark_bank(old_canonical, documents=benchmark_documents, options=raw_options)
    new_benchmark = benchmark_bank(new_canonical, documents=benchmark_documents, options=raw_options)
    deltas = {
        "quality": _quality_delta(old_eval, new_eval),
        "performance": _performance_delta(old_benchmark, new_benchmark),
    }
    gates = _regression_gates(deltas, raw_options)

    return {
        "diff": diff,
        "evaluations": {"old": old_eval, "new": new_eval},
        "benchmarks": {"old": old_benchmark, "new": new_benchmark},
        "deltas": deltas,
        "gates": gates,
        "diagnostics": _regression_diagnostics(diff, old_eval, new_eval, old_benchmark, new_benchmark),
    }


def _resolve_benchmark_options(options: Mapping[str, Any]) -> BenchmarkOptions:
    validation_level = str(options.get("benchmark_validation_level", options.get("validation_level", "standard")))
    if validation_level not in VALIDATION_LEVELS:
        raise ExtractionError(f"Benchmark validation_level must be one of {', '.join(VALIDATION_LEVELS)}.")
    return BenchmarkOptions(
        iterations=_positive_int_option(
            options,
            "benchmark_iterations",
            cast(int, options.get("iterations", DEFAULT_BENCHMARK_ITERATIONS)),
        ),
        stress_multiplier=_positive_int_option(options, "stress_multiplier", DEFAULT_STRESS_MULTIPLIER),
        max_pattern_examples=_positive_int_option(options, "max_pattern_examples", DEFAULT_MAX_PATTERN_EXAMPLES),
        validation_level=validation_level,
    )


def _positive_int_option(options: Mapping[str, Any], key: str, default: int) -> int:
    value = options.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ExtractionError(f"Benchmark option {key} must be a positive integer.")
    return value


def _optional_float_option(options: Mapping[str, Any], key: str) -> float | None:
    value = options.get(key)
    if value is None:
        return None
    if not isinstance(value, (int, float)) or isinstance(value, bool) or value <= 0:
        raise ExtractionError(f"Regression gate option {key} must be a positive number.")
    return float(value)


def _resolve_document_tiers(
    banks: Sequence[Mapping[str, Any]],
    documents: Sequence[Mapping[str, Any]] | Mapping[str, Any] | None,
    options: BenchmarkOptions,
) -> dict[str, list[Mapping[str, Any]]]:
    synthetic = _synthetic_document_tiers(banks, options)
    if documents is None:
        return synthetic

    if isinstance(documents, Mapping) and ("text" in documents or "file_path" in documents):
        synthetic["target"] = [cast(Mapping[str, Any], documents)]
        return synthetic

    if isinstance(documents, Mapping):
        document_tiers = cast(Mapping[str, Any], documents)
        tiers = dict(synthetic)
        for tier in BENCHMARK_TIERS:
            tier_documents = document_tiers.get(tier)
            if tier_documents is not None:
                tiers[tier] = _document_list(tier_documents, tier)
        return tiers

    synthetic["target"] = _document_list(documents, "target")
    return synthetic


def _document_list(value: Any, tier: str) -> list[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        if "text" in value or "file_path" in value:
            return [value]
        raise TypeError(f"Benchmark documents for tier {tier!r} must be a document or sequence of documents.")
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise TypeError(f"Benchmark documents for tier {tier!r} must be a sequence of documents.")
    documents = list(value)
    if not all(isinstance(document, Mapping) for document in documents):
        raise TypeError(f"Benchmark documents for tier {tier!r} must be document objects.")
    return cast(list[Mapping[str, Any]], documents)


def _synthetic_document_tiers(
    banks: Sequence[Mapping[str, Any]],
    options: BenchmarkOptions,
) -> dict[str, list[Mapping[str, Any]]]:
    examples = _pattern_examples(banks, options.max_pattern_examples)
    literal_examples = [example["text"] for example in examples if example["kind"] == "literal"]
    regex_examples = [example["text"] for example in examples if example["kind"] == "regex"]
    all_examples = [example["text"] for example in examples]

    literal_text = _joined_examples(literal_examples, "NERB literal control document.")
    regex_text = _joined_examples(regex_examples, "NERB regex control document.")
    mixed_text = _joined_examples(all_examples, "NERB mixed control document.")
    baseline_text = _joined_examples(all_examples[:1], "NERB baseline control document.")
    stress_text = " ".join([mixed_text] * options.stress_multiplier)

    return {
        "baseline": [{"document_id": "baseline_0", "text": baseline_text}],
        "target": [
            {"document_id": "target_literal", "text": literal_text},
            {"document_id": "target_regex", "text": regex_text},
            {"document_id": "target_mixed", "text": mixed_text},
        ],
        "stress": [{"document_id": "stress_mixed", "text": stress_text}],
    }


def _joined_examples(examples: Sequence[str], fallback: str) -> str:
    values = [value for value in examples if value]
    return " ".join(values) if values else fallback


def _pattern_examples(banks: Sequence[Mapping[str, Any]], limit: int) -> list[dict[str, str]]:
    examples: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for bank_index, bank in enumerate(banks):
        for key, kind, text in _iter_active_pattern_examples(bank):
            if not text:
                continue
            seen_key = (kind, text)
            if seen_key in seen:
                continue
            seen.add(seen_key)
            examples.append({"key": f"bank_{bank_index}/{key}", "kind": kind, "text": text})
            if len(examples) >= limit:
                return examples
    return examples


def _iter_active_pattern_examples(bank: Mapping[str, Any]) -> list[tuple[str, str, str]]:
    if bank.get("status") != "active":
        return []

    examples: list[tuple[str, str, str]] = []
    entities = bank.get("entities", {})
    if not isinstance(entities, Mapping):
        return examples

    for entity_id, entity in sorted(entities.items()):
        if not isinstance(entity_id, str) or not isinstance(entity, Mapping):
            continue
        entity_map = cast(Mapping[str, Any], entity)
        if entity_map.get("status") != "active":
            continue
        names = entity_map.get("names", {})
        if not isinstance(names, Mapping):
            continue
        for name_id, name in sorted(names.items()):
            if not isinstance(name_id, str) or not isinstance(name, Mapping):
                continue
            name_map = cast(Mapping[str, Any], name)
            if name_map.get("status") != "active":
                continue
            patterns = name_map.get("patterns", {})
            if not isinstance(patterns, Mapping):
                continue
            for pattern_id, pattern in sorted(patterns.items()):
                if not isinstance(pattern_id, str) or not isinstance(pattern, Mapping):
                    continue
                pattern_map = cast(Mapping[str, Any], pattern)
                if pattern_map.get("status") != "active":
                    continue
                kind = pattern_map.get("kind")
                if kind not in {"literal", "regex"}:
                    continue
                text = _pattern_example_text(pattern_map, name_map, pattern_id)
                examples.append((f"{entity_id}/{name_id}/{pattern_id}", kind, text))
    return examples


def _pattern_example_text(pattern: Mapping[str, Any], name: Mapping[str, Any], pattern_id: str) -> str:
    metadata = pattern.get("metadata", {})
    if isinstance(metadata, Mapping):
        for key in ("benchmark_text", "example_text"):
            value = metadata.get(key)
            if isinstance(value, str) and value:
                return value

    value = pattern.get("value")
    if not isinstance(value, str):
        return str(name.get("canonical", pattern_id.replace("_", " ")))
    if pattern.get("kind") == "literal":
        return value
    return _regex_candidate(value) or str(name.get("canonical", pattern_id.replace("_", " ")))


def _regex_candidate(value: str) -> str:
    candidate = value.strip()
    candidate = candidate.removeprefix("^").removesuffix("$")
    replacements = (
        (r"\b", ""),
        (r"\s+", " "),
        (r"\s*", " "),
        (r"\s", " "),
        (r"\d+", "123"),
        (r"\d*", "123"),
        (r"\d", "1"),
        (r"\w+", "word"),
        (r"\w*", "word"),
        (r"\w", "w"),
        (r"\-", "-"),
        (r"\.", "."),
        (r"\+", "+"),
        (r"\(", "("),
        (r"\)", ")"),
    )
    for old, new in replacements:
        candidate = candidate.replace(old, new)
    candidate = re.sub(r"\[[A-Z]-[A-Z]\]\+", "ABC", candidate)
    candidate = re.sub(r"\[[a-z]-[a-z]\]\+", "abc", candidate)
    candidate = re.sub(r"\[[0-9]-[0-9]\]\+", "123", candidate)
    candidate = re.sub(r"\[[^\]]+\][+*]?", "A", candidate)
    if "|" in candidate:
        candidate = candidate.split("|", 1)[0]
    candidate = candidate.replace("(?:", "(")
    candidate = re.sub(r"\(([^()?]+)\)[+*?]?", r"\1", candidate)
    candidate = re.sub(r"[+*?{}]", "", candidate)
    candidate = candidate.replace("\\", "")
    return " ".join(candidate.split())


def _measure_compile(
    bank: Mapping[str, Any],
    options: Mapping[str, Any],
) -> tuple[dict[str, Any], CompiledBank]:
    before_reset = compiled_bank_cache_info()
    clear_compiled_bank_cache()
    after_reset = compiled_bank_cache_info()

    cold_start = time.perf_counter()
    cold_compiled, cold_cache_hit = compile_bank(bank, options=options)
    cold_seconds = time.perf_counter() - cold_start
    after_cold = compiled_bank_cache_info()

    warm_start = time.perf_counter()
    warm_compiled, warm_cache_hit = compile_bank(bank, options=options)
    warm_seconds = time.perf_counter() - warm_start
    after_warm = compiled_bank_cache_info()

    return (
        {
            "cold_seconds": _seconds(cold_seconds),
            "warm_cache_lookup_seconds": _seconds(warm_seconds),
            "cache": {
                "before_reset": before_reset,
                "after_reset": after_reset,
                "after_cold": after_cold,
                "after_warm": after_warm,
                "cold_hit": cold_cache_hit,
                "warm_hit": warm_cache_hit,
            },
        },
        warm_compiled if warm_cache_hit else cold_compiled,
    )


def _measure_tier(
    compiled: CompiledBank,
    documents: Sequence[Mapping[str, Any]],
    extraction_options: Mapping[str, Any],
    benchmark_options: BenchmarkOptions,
) -> dict[str, Any]:
    prepared_documents, combined_bytes = _prepare_batch_documents(documents, options=extraction_options)
    document_summaries: list[dict[str, Any]] = []
    run_record_counts: list[int] = []

    start = time.perf_counter()
    for iteration in range(benchmark_options.iterations):
        run_record_count = 0
        for document_id, source, text in prepared_documents:
            records = compiled.finditer(text)
            records.sort(key=record_sort_key)
            run_record_count += len(records)
            if iteration == 0:
                document_summaries.append(
                    {
                        "document_id": document_id,
                        "source": source,
                        "record_count": len(records),
                    }
                )
        run_record_counts.append(run_record_count)
    elapsed_seconds = time.perf_counter() - start

    record_count = run_record_counts[0] if run_record_counts else 0
    document_bytes = [int(document["source"]["bytes"]) for document in document_summaries]
    total_documents = len(prepared_documents) * benchmark_options.iterations
    total_bytes = combined_bytes * benchmark_options.iterations
    total_records = sum(run_record_counts)

    return {
        "document_count": len(prepared_documents),
        "bytes": combined_bytes,
        "size": {
            "min_bytes": min(document_bytes, default=0),
            "max_bytes": max(document_bytes, default=0),
            "average_bytes": round(sum(document_bytes) / len(document_bytes), 3) if document_bytes else 0.0,
        },
        "iterations": benchmark_options.iterations,
        "record_count": record_count,
        "documents_with_records": sum(1 for document in document_summaries if document["record_count"] > 0),
        "record_counts_by_run": run_record_counts,
        "record_count_stable": len(set(run_record_counts)) <= 1,
        "documents": document_summaries,
        "warm_extraction_seconds": _seconds(elapsed_seconds),
        "throughput": {
            "documents_per_second": _rate(total_documents, elapsed_seconds),
            "bytes_per_second": _rate(total_bytes, elapsed_seconds),
            "records_per_second": _rate(total_records, elapsed_seconds),
        },
    }


def _seconds(value: float) -> float:
    return round(value, 9)


def _rate(amount: int, elapsed_seconds: float) -> float | None:
    if elapsed_seconds <= 0:
        return None
    return round(amount / elapsed_seconds, 3)


def _bank_profile(bank: Mapping[str, Any]) -> dict[str, Any]:
    stats = bank_stats(bank)
    literal_count = int(stats["by_kind"]["literal"])
    regex_count = int(stats["by_kind"]["regex"])
    active_patterns = int(stats["active_totals"]["patterns"])
    if active_patterns == 0:
        profile = "empty"
    elif literal_count >= regex_count * 3:
        profile = "mostly_literal"
    elif regex_count >= literal_count * 3:
        profile = "mostly_regex"
    else:
        profile = "mixed"
    return {
        "profile": profile,
        "literal_patterns": literal_count,
        "regex_patterns": regex_count,
        "active_patterns": active_patterns,
    }


def _benchmark_summary(
    tiers: Mapping[str, Mapping[str, Any]],
    compile_report: Mapping[str, Any],
    profile: Mapping[str, Any],
    options: BenchmarkOptions,
) -> dict[str, Any]:
    target = tiers["target"]
    target_throughput = target["throughput"]
    return {
        "tier_count": len(tiers),
        "document_count": sum(int(tier["document_count"]) for tier in tiers.values()),
        "record_count": sum(int(tier["record_count"]) for tier in tiers.values()),
        "extraction_iterations": options.iterations,
        "cache_hit_verified": compile_report["cache"]["cold_hit"] is False
        and compile_report["cache"]["warm_hit"] is True,
        "profile": profile["profile"],
        "cold_compile_seconds": compile_report["cold_seconds"],
        "target_documents_per_second": target_throughput["documents_per_second"],
        "target_bytes_per_second": target_throughput["bytes_per_second"],
        "target_records_per_second": target_throughput["records_per_second"],
    }


def _benchmark_diagnostics(validation: Mapping[str, Any]) -> list[Diagnostic]:
    regex_codes = {REGEX_EXPENSIVE_PROBE, REGEX_EXPENSIVE_STATIC}
    diagnostics = [dict(item) for item in validation["diagnostics"] if item.get("code") in regex_codes]
    engine_compatibility = validation.get("engine_compatibility", {})
    runtime_probes = engine_compatibility.get("runtime_probes", {})
    if runtime_probes:
        diagnostics.append(
            {
                "severity": "info",
                "code": "benchmark.regex_probes",
                "path": "",
                "message": "Benchmark used bounded regex probe diagnostics from validation.",
                "metadata": runtime_probes,
            }
        )
    diagnostics.sort(key=lambda item: (item.get("path", ""), item.get("severity", ""), item.get("code", "")))
    return diagnostics


def _regression_benchmark_documents(
    old_bank: Mapping[str, Any],
    new_bank: Mapping[str, Any],
    options: Mapping[str, Any],
    benchmark_options: BenchmarkOptions,
) -> dict[str, list[Mapping[str, Any]]]:
    documents = options.get("benchmark_documents", options.get("documents"))
    return _resolve_document_tiers([old_bank, new_bank], documents, benchmark_options)


def _regression_eval_base_path(
    default_base_path: str | Path | None,
    options: Mapping[str, Any],
    bank_label: str,
) -> str | Path | None:
    explicit_base_path = options.get(f"{bank_label}_base_path")
    if explicit_base_path is not None:
        return cast(str | Path, explicit_base_path)

    bank_path = options.get(f"{bank_label}_bank_path")
    if bank_path is not None:
        return Path(cast(str | Path, bank_path)).expanduser().parent

    return default_base_path


def _quality_delta(old_eval: Mapping[str, Any], new_eval: Mapping[str, Any]) -> dict[str, Any]:
    old_summary = old_eval["summary"]
    new_summary = new_eval["summary"]
    positive_failed_delta = int(new_summary["positive_failed"]) - int(old_summary["positive_failed"])
    negative_failed_delta = int(new_summary["negative_failed"]) - int(old_summary["negative_failed"])
    failure_count_delta = len(new_eval["failures"]) - len(old_eval["failures"])
    return {
        "passed": {"old": bool(old_summary["passed"]), "new": bool(new_summary["passed"])},
        "positive_total_delta": int(new_summary["positive_total"]) - int(old_summary["positive_total"]),
        "positive_failed_delta": positive_failed_delta,
        "negative_total_delta": int(new_summary["negative_total"]) - int(old_summary["negative_total"]),
        "negative_failed_delta": negative_failed_delta,
        "failure_count_delta": failure_count_delta,
        "regressed": positive_failed_delta > 0
        or negative_failed_delta > 0
        or failure_count_delta > 0
        or (bool(old_summary["passed"]) and not bool(new_summary["passed"])),
        "improved": positive_failed_delta < 0 or negative_failed_delta < 0 or failure_count_delta < 0,
    }


def _performance_delta(old_benchmark: Mapping[str, Any], new_benchmark: Mapping[str, Any]) -> dict[str, Any]:
    old_compile = old_benchmark["compile"]
    new_compile = new_benchmark["compile"]
    tiers = {
        tier: _tier_performance_delta(old_benchmark["tiers"][tier], new_benchmark["tiers"][tier])
        for tier in BENCHMARK_TIERS
    }
    return {
        "cold_compile_seconds_delta": _difference(new_compile["cold_seconds"], old_compile["cold_seconds"]),
        "cold_compile_seconds_ratio": _ratio(new_compile["cold_seconds"], old_compile["cold_seconds"]),
        "warm_cache_lookup_seconds_delta": _difference(
            new_compile["warm_cache_lookup_seconds"],
            old_compile["warm_cache_lookup_seconds"],
        ),
        "target_bytes_per_second_delta": tiers["target"]["bytes_per_second_delta"],
        "target_bytes_per_second_ratio": tiers["target"]["bytes_per_second_ratio"],
        "target_records_per_second_delta": tiers["target"]["records_per_second_delta"],
        "target_records_per_second_ratio": tiers["target"]["records_per_second_ratio"],
        "tiers": tiers,
    }


def _tier_performance_delta(old_tier: Mapping[str, Any], new_tier: Mapping[str, Any]) -> dict[str, Any]:
    old_throughput = old_tier["throughput"]
    new_throughput = new_tier["throughput"]
    return {
        "record_count_delta": int(new_tier["record_count"]) - int(old_tier["record_count"]),
        "documents_with_records_delta": int(new_tier["documents_with_records"])
        - int(old_tier["documents_with_records"]),
        "warm_extraction_seconds_delta": _difference(
            new_tier["warm_extraction_seconds"],
            old_tier["warm_extraction_seconds"],
        ),
        "documents_per_second_delta": _difference(
            new_throughput["documents_per_second"],
            old_throughput["documents_per_second"],
        ),
        "documents_per_second_ratio": _ratio(
            new_throughput["documents_per_second"],
            old_throughput["documents_per_second"],
        ),
        "bytes_per_second_delta": _difference(
            new_throughput["bytes_per_second"],
            old_throughput["bytes_per_second"],
        ),
        "bytes_per_second_ratio": _ratio(
            new_throughput["bytes_per_second"],
            old_throughput["bytes_per_second"],
        ),
        "records_per_second_delta": _difference(
            new_throughput["records_per_second"],
            old_throughput["records_per_second"],
        ),
        "records_per_second_ratio": _ratio(
            new_throughput["records_per_second"],
            old_throughput["records_per_second"],
        ),
    }


def _difference(new_value: Any, old_value: Any) -> float | None:
    if new_value is None or old_value is None:
        return None
    return round(float(new_value) - float(old_value), 9)


def _ratio(new_value: Any, old_value: Any) -> float | None:
    if new_value is None or old_value in {None, 0}:
        return None
    return round(float(new_value) / float(old_value), 6)


def _regression_gates(deltas: Mapping[str, Any], options: Mapping[str, Any]) -> dict[str, Any]:
    quality_delta = deltas["quality"]
    quality_checks = [
        _gate_check(
            "positive_failed_delta",
            quality_delta["positive_failed_delta"],
            "<=",
            int(options.get("max_positive_failed_delta", 0)),
        ),
        _gate_check(
            "negative_failed_delta",
            quality_delta["negative_failed_delta"],
            "<=",
            int(options.get("max_negative_failed_delta", 0)),
        ),
        _gate_check(
            "failure_count_delta",
            quality_delta["failure_count_delta"],
            "<=",
            int(options.get("max_eval_failure_delta", 0)),
        ),
    ]

    performance_delta = deltas["performance"]
    performance_checks: list[dict[str, Any]] = []
    max_cold_compile_ratio = _optional_float_option(options, "max_cold_compile_seconds_ratio")
    if max_cold_compile_ratio is not None:
        performance_checks.append(
            _gate_check(
                "cold_compile_seconds_ratio",
                performance_delta["cold_compile_seconds_ratio"],
                "<=",
                max_cold_compile_ratio,
            )
        )
    min_target_bytes_ratio = _optional_float_option(options, "min_target_bytes_per_second_ratio")
    if min_target_bytes_ratio is not None:
        performance_checks.append(
            _gate_check(
                "target_bytes_per_second_ratio",
                performance_delta["target_bytes_per_second_ratio"],
                ">=",
                min_target_bytes_ratio,
            )
        )

    quality_passed = all(check["passed"] for check in quality_checks)
    performance_passed = all(check["passed"] for check in performance_checks)
    return {
        "passed": quality_passed and performance_passed,
        "quality": {"passed": quality_passed, "checks": quality_checks},
        "performance": {
            "passed": performance_passed,
            "checks": performance_checks,
            "configured": bool(performance_checks),
        },
    }


def _gate_check(name: str, actual: Any, operator: str, threshold: float | int) -> dict[str, Any]:
    if actual is None:
        passed = False
    elif operator == "<=":
        passed = actual <= threshold
    elif operator == ">=":
        passed = actual >= threshold
    else:
        raise ValueError(f"Unsupported gate operator: {operator}.")
    return {"name": name, "actual": actual, "operator": operator, "threshold": threshold, "passed": passed}


def _regression_diagnostics(
    diff: Mapping[str, Any],
    old_eval: Mapping[str, Any],
    new_eval: Mapping[str, Any],
    old_benchmark: Mapping[str, Any],
    new_benchmark: Mapping[str, Any],
) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    diagnostics.extend(cast(list[Diagnostic], diff["diagnostics"]))
    diagnostics.extend(_eval_diagnostics(old_eval, "old_bank"))
    diagnostics.extend(_eval_diagnostics(new_eval, "new_bank"))
    diagnostics.extend(_bank_labeled_diagnostics(old_benchmark["diagnostics"], "old_bank"))
    diagnostics.extend(_bank_labeled_diagnostics(new_benchmark["diagnostics"], "new_bank"))
    diagnostics.sort(
        key=lambda item: (
            item.get("metadata", {}).get("bank", ""),
            item.get("path", ""),
            item.get("severity", ""),
            item.get("code", ""),
            item.get("message", ""),
        )
    )
    return diagnostics


def _eval_diagnostics(eval_result: Mapping[str, Any], bank_label: str) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    for failure in eval_result["failures"]:
        for item in failure.get("diagnostics", []):
            enriched = dict(item)
            metadata = dict(enriched.get("metadata", {}))
            metadata.update(
                {
                    "bank": bank_label,
                    "eval_ref": failure.get("eval_ref"),
                    "record": failure.get("record"),
                    "failure_type": failure.get("type"),
                }
            )
            enriched["metadata"] = metadata
            diagnostics.append(enriched)
    return diagnostics


def _bank_labeled_diagnostics(diagnostics: Sequence[Mapping[str, Any]], bank_label: str) -> list[Diagnostic]:
    labeled: list[Diagnostic] = []
    for item in diagnostics:
        enriched = dict(item)
        metadata = dict(enriched.get("metadata", {}))
        metadata["bank"] = bank_label
        enriched["metadata"] = metadata
        labeled.append(enriched)
    return labeled

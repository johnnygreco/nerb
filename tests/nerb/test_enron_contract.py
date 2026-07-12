from __future__ import annotations

import copy
import json
import math
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import pytest
from jsonschema import Draft202012Validator

import nerb.enron_contract as enron_contract
from nerb.enron_contract import (
    ENRON_EVIDENCE_SCHEMA,
    ENRON_EVIDENCE_SCHEMA_VERSION,
    ENRON_MANIFEST_SCHEMA,
    ENRON_MANIFEST_SCHEMA_VERSION,
    ENRON_PERFORMANCE_OUTPUT_SCHEMA,
    calculate_enron_breakeven,
    calculate_enron_performance_comparison,
    calculate_enron_performance_statistics,
    hash_enron_breakeven_plan,
    hash_enron_environment,
    hash_enron_manifest,
    hash_enron_performance_bank,
    hash_enron_performance_baseline,
    hash_enron_performance_comparison_plan,
    hash_enron_performance_harness,
    hash_enron_performance_input,
    hash_enron_performance_inventory,
    hash_enron_performance_manifest,
    hash_enron_samples,
    hash_enron_test_lineage_entry,
    hash_enron_thresholds,
    hash_enron_workload,
    load_enron_evidence,
    load_enron_manifest,
    summarize_enron_performance_inventory,
    validate_enron_conformance_output,
    validate_enron_evidence,
    validate_enron_manifest,
    validate_enron_performance_output,
    validate_enron_quality_output,
)

JsonObject = dict[str, Any]
JsonPath = tuple[str | int, ...]
_PROMOTABLE_FIXTURE_CACHE: dict[
    str,
    tuple[JsonObject, JsonObject, dict[str, list[JsonObject]]],
] = {}


class _ExplodingMapping(Mapping[str, Any]):
    def __getitem__(self, key: str) -> Any:
        raise RuntimeError(f"unexpected resolver access: {key}")

    def __iter__(self) -> Iterator[str]:
        raise RuntimeError("unexpected resolver iteration")

    def __len__(self) -> int:
        raise RuntimeError("unexpected resolver length access")


@pytest.fixture
def manifest(test_data_path: Path) -> JsonObject:
    return json.loads((test_data_path / "enron_manifest_v2.json").read_text(encoding="utf-8"))


@pytest.fixture
def evidence(test_data_path: Path) -> JsonObject:
    return json.loads((test_data_path / "enron_evidence_v2.json").read_text(encoding="utf-8"))


def _codes(result: JsonObject) -> set[str]:
    return {str(item["code"]) for item in result["diagnostics"]}


def _assert_code(result: JsonObject, code: str) -> None:
    assert result["valid"] is False
    assert code in _codes(result), result["diagnostics"]


def test_standalone_quality_and_conformance_outputs_reuse_contract_semantics(evidence: JsonObject) -> None:
    quality = copy.deepcopy(evidence["quality"])
    conformance = copy.deepcopy(evidence["catalog_conformance"])

    assert validate_enron_quality_output(quality) == {"valid": True, "diagnostics": []}
    assert validate_enron_conformance_output(conformance, active_patterns=5) == {
        "valid": True,
        "diagnostics": [],
    }

    quality["slices"][0]["metrics"]["open_world_recall"] = 0.5
    _assert_code(validate_enron_quality_output(quality), "contract.metric_arithmetic")
    _assert_code(
        validate_enron_conformance_output(conformance, active_patterns=4),
        "contract.conformance_bank_mismatch",
    )


def _at(value: Any, path: JsonPath) -> Any:
    current = value
    for part in path:
        current = current[part]
    return current


def _set(value: Any, path: JsonPath, replacement: Any) -> None:
    current = value
    for part in path[:-1]:
        current = current[part]
    current[path[-1]] = replacement


def _resolve_pointer(value: Any, pointer: str) -> Any:
    current = value
    for raw_part in pointer.removeprefix("/").split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        current = current[int(part)] if isinstance(current, list) else current[part]
    return current


def _refresh_check_actuals(evidence: JsonObject, *, target_prefix: str) -> None:
    for check in evidence["promotion"]["checks"]:
        if not check["target"].startswith(target_prefix):
            continue
        actual = _resolve_pointer(evidence, check["target"])
        refreshed = _gate(
            check["id"],
            check["category"],
            check["target"],
            check["operator"],
            check["threshold"],
            actual,
        )
        check["actual"] = refreshed["actual"]
        check["passed"] = refreshed["passed"]


def _inventory_summary(inventory: Sequence[Mapping[str, int]]) -> JsonObject:
    return summarize_enron_performance_inventory(inventory)


def _inventory_payload_bytes(inventory: Sequence[Mapping[str, int]]) -> int:
    payload = json.dumps(inventory, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return len(payload.encode("utf-8"))


def _sample_stats(
    samples: Sequence[float],
    input_descriptor: Mapping[str, Any] | None,
    phase: str,
    sample_unit: str,
    work_per_sample: int,
) -> JsonObject:
    return calculate_enron_performance_statistics(
        samples,
        input_descriptor,
        phase=phase,
        sample_unit=sample_unit,
        work_per_sample=work_per_sample,
    )


def _sample_payload_bytes(samples: Sequence[float]) -> int:
    payload = json.dumps(
        [float(value) for value in samples],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return len(payload.encode("utf-8"))


def _refresh_bank_descriptor(bank: JsonObject) -> None:
    bank["descriptor_sha256"] = hash_enron_performance_bank(bank)


def _refresh_input_descriptor(input_descriptor: JsonObject) -> None:
    input_descriptor["descriptor_sha256"] = hash_enron_performance_input(input_descriptor)


def _refresh_workload(evidence: JsonObject, workload: JsonObject, samples: Sequence[float] | None = None) -> None:
    resolved = list(workload["samples_seconds"] if samples is None else samples)
    input_descriptor = next(
        (item for item in evidence["performance"]["inputs"] if item["id"] == workload["input_id"]),
        None,
    )
    workload["input_sha256"] = None if input_descriptor is None else input_descriptor["descriptor_sha256"]
    workload["records_per_sample"] = (
        input_descriptor["records"] * workload["work_per_sample"]
        if input_descriptor is not None and workload["sample_unit"] == "whole_input"
        else None
    )
    workload["stats"] = _sample_stats(
        resolved,
        input_descriptor,
        workload["phase"],
        workload["sample_unit"],
        workload["work_per_sample"],
    )
    peak_rss_bytes = workload["peak_rss_bytes"]
    workload["rss_samples_bytes"] = [] if peak_rss_bytes is None else [peak_rss_bytes] * len(resolved)
    workload["workload_sha256"] = hash_enron_workload(workload)


def _refresh_same_path_comparison(evidence: JsonObject, comparison: JsonObject) -> None:
    workloads = {item["id"]: item for item in evidence["performance"]["workloads"]}
    candidate = workloads[comparison["candidate_workload_id"]]
    baseline = workloads[comparison["baseline_workload_id"]]
    outputs = calculate_enron_performance_comparison(
        candidate["stats"],
        baseline["stats"],
        metric=comparison["metric"],
        noise_method="exact_block_swap",
        candidate_samples=candidate["samples_seconds"],
        baseline_samples=baseline["samples_seconds"],
        block_count=comparison["block_count"],
        samples_per_block=comparison["samples_per_block"],
        block_assignment=comparison["block_assignment"],
        significance_level=comparison["significance_level"],
        stability_tolerance=comparison["stability_tolerance"],
    )
    comparison.update(outputs)


def _refresh_cross_path_comparison(evidence: JsonObject, comparison: JsonObject) -> None:
    workloads = {item["id"]: item for item in evidence["performance"]["workloads"]}
    candidate = workloads[comparison["candidate_workload_id"]]
    baseline = workloads[comparison["baseline_workload_id"]]
    outputs = calculate_enron_performance_comparison(
        candidate["stats"],
        baseline["stats"],
        metric=comparison["metric"],
        noise_method=comparison["noise_method"],
        candidate_samples=candidate["samples_seconds"],
        baseline_samples=baseline["samples_seconds"],
        noise_multiplier=comparison["noise_multiplier"],
        regression_tolerance=comparison["regression_tolerance"],
    )
    comparison.update(outputs)


def _rehash_lineage(evidence: JsonObject) -> None:
    lineage = evidence["test_access"]["lineage"]
    for entry in lineage:
        entry["entry_sha256"] = hash_enron_test_lineage_entry(entry)
    evidence["test_access"]["lineage_head_sha256"] = lineage[-1]["entry_sha256"] if lineage else None


def _normalize_lineage(evidence: JsonObject) -> None:
    lineage = evidence["test_access"]["lineage"]
    previous: JsonObject | None = None
    for index, entry in enumerate(lineage):
        entry["sequence"] = index + 1
        if previous is None:
            entry["predecessor_benchmark_version"] = None
            entry["changes_informed_by_predecessor"] = []
            entry["previous_entry_sha256"] = None
        else:
            entry["predecessor_benchmark_version"] = previous["benchmark_version"]
            entry["changes_informed_by_predecessor"] = entry["changes_informed_by_predecessor"] or [
                "aggregate outcome reviewed"
            ]
            entry["previous_entry_sha256"] = previous["entry_sha256"]
        entry["entry_sha256"] = hash_enron_test_lineage_entry(entry)
        previous = entry
    evidence["test_access"]["lineage_head_sha256"] = previous["entry_sha256"] if previous else None


def _refresh_frozen_contract(evidence: JsonObject) -> None:
    evidence["performance_manifest_sha256"] = hash_enron_performance_manifest(evidence["performance"])
    evidence["thresholds_sha256"] = hash_enron_thresholds(evidence["promotion"]["checks"])
    access = evidence["test_access"]
    frozen = access["frozen_target"]
    frozen.update(
        {
            "manifest_sha256": evidence["manifest_sha256"],
            "bank_hash": evidence["bank"]["canonical_hash"],
            "evaluator_source_sha256": evidence["evaluator"]["source_sha256"],
            "split_manifest_sha256": evidence["splits"]["manifest_sha256"],
            "test_artifact_sha256": evidence["splits"]["roles"]["test"]["artifact"]["sha256"],
            "thresholds_sha256": evidence["thresholds_sha256"],
            "performance_manifest_sha256": evidence["performance_manifest_sha256"],
            "git_commit": evidence["software"]["git_commit"],
        }
    )
    for entry in access["lineage"]:
        if entry["benchmark_version"] == access["benchmark_version"]:
            entry["frozen_target"] = copy.deepcopy(frozen)
    _normalize_lineage(evidence)


def _sync_bound_manifest(manifest: JsonObject, evidence: JsonObject) -> None:
    manifest["thresholds_sha256"] = evidence["thresholds_sha256"]
    manifest["performance_manifest_sha256"] = evidence["performance_manifest_sha256"]
    evidence["manifest_sha256"] = hash_enron_manifest(manifest)
    _refresh_frozen_contract(evidence)


def _gate(
    identifier: str,
    category: str,
    target: str,
    operator: str,
    threshold: Any,
    actual: Any,
) -> JsonObject:
    if operator == "eq":
        passed = type(actual) is type(threshold) and actual == threshold
    elif operator == "gte":
        passed = float(actual) >= float(threshold)
    else:
        passed = float(actual) <= float(threshold)
    return {
        "id": identifier,
        "category": category,
        "target": target,
        "operator": operator,
        "threshold": threshold,
        "actual": actual,
        "passed": passed,
    }


def _claim_provenance(evidence: Mapping[str, Any]) -> JsonObject:
    return {
        "benchmark_version": evidence["test_access"]["benchmark_version"],
        "source_revision": evidence["source"]["revision"],
        "bank_hash": evidence["bank"]["canonical_hash"],
        "evaluator_source_sha256": evidence["evaluator"]["source_sha256"],
        "environment_sha256": hash_enron_environment(evidence["environment"]),
    }


def _catalog_claim(evidence: Mapping[str, Any]) -> JsonObject:
    return {
        "id": "catalog_conformance_recall",
        "kind": "catalog_conformance",
        "metric": "catalog_conformance_recall",
        "value": evidence["catalog_conformance"]["recall"],
        "label_strength": "synthetic_conformance",
        "annotation_completeness": "exhaustive_within_scope",
        "quality_slice_id": None,
        "performance_workload_id": None,
        "scope": {"entity_class": None, "cohort": None, "split_role": None, "text_view": None},
        **_claim_provenance(evidence),
    }


def _quality_claim(evidence: Mapping[str, Any], metric: str, *, slice_index: int = 0) -> JsonObject:
    item = evidence["quality"]["slices"][slice_index]
    return {
        "id": metric,
        "kind": "open_world_quality",
        "metric": metric,
        "value": item["metrics"][metric],
        "label_strength": item["label_strength"],
        "annotation_completeness": item["annotation_completeness"],
        "quality_slice_id": item["id"],
        "performance_workload_id": None,
        "scope": {
            "entity_class": item["entity_class"],
            "cohort": item["cohort"],
            "split_role": item["split_role"],
            "text_view": item["text_view"],
        },
        **_claim_provenance(evidence),
    }


def _performance_claim(
    evidence: Mapping[str, Any], metric: str, stat_field: str, *, workload_index: int = 0
) -> JsonObject:
    workload = evidence["performance"]["workloads"][workload_index]
    return {
        "id": metric,
        "kind": "performance",
        "metric": metric,
        "value": workload["stats"][stat_field],
        "label_strength": "unlabeled",
        "annotation_completeness": "not_applicable",
        "quality_slice_id": None,
        "performance_workload_id": workload["id"],
        "scope": {"entity_class": None, "cohort": None, "split_role": None, "text_view": None},
        **_claim_provenance(evidence),
    }


def _sha256_number(value: int) -> str:
    return "sha256:" + f"{value:064x}"


def _make_inventory(hit_density: str, *, documents: int = 100, bytes_per_document: int = 10240) -> list[JsonObject]:
    record_counts = {
        "negative": [0] * documents,
        "sparse": [1] + [0] * (documents - 1),
        "normal": [1] * documents,
        "dense": [3] * documents,
    }[hit_density]
    return [{"bytes": bytes_per_document, "records": count} for count in record_counts]


def _make_performance_input(
    bank: Mapping[str, Any],
    *,
    identifier: str,
    artifact_number: int,
    kind: str,
    hit_density: str,
    bytes_per_document: int = 10240,
) -> tuple[JsonObject, list[JsonObject]]:
    inventory = _make_inventory(hit_density, bytes_per_document=bytes_per_document)
    summary = _inventory_summary(inventory)
    generator = None
    if kind == "synthetic_input":
        generator = {
            "id": f"{identifier}_generator",
            "version": "1.0.0",
            "source_sha256": _sha256_number(artifact_number + 1),
            "spec_sha256": _sha256_number(artifact_number + 2),
            "seed": f"{identifier}-seed",
        }
    descriptor: JsonObject = {
        "id": identifier,
        "kind": kind,
        "bank_id": bank["id"],
        "bank_hash": bank["bank_hash"],
        "artifact": {
            "id": f"{identifier}_documents",
            "sha256": _sha256_number(artifact_number),
            "bytes": summary["bytes"],
        },
        "inventory_ref": {
            "id": f"{identifier}_inventory",
            "sha256": hash_enron_performance_inventory(inventory),
            "bytes": _inventory_payload_bytes(inventory),
        },
        "generator": generator,
        **summary,
        "descriptor_sha256": _sha256_number(0),
    }
    _refresh_input_descriptor(descriptor)
    return descriptor, inventory


def _make_scale_bank(active_patterns: int, *, number: int) -> JsonObject:
    active_entities = active_patterns * 3 // 5
    active_names = active_patterns * 4 // 5
    active_aliases = active_patterns // 5
    regex_patterns = active_patterns // 5
    descriptor: JsonObject = {
        "id": f"scale_{active_patterns}",
        "kind": "synthetic_scale",
        "bank_hash": _sha256_number(number),
        "artifact": {
            "id": f"scale_{active_patterns}_bank_artifact",
            "sha256": _sha256_number(number + 1),
            "bytes": active_patterns * 64,
        },
        "generator": {
            "id": "fixture_scale_bank_generator",
            "version": "1.0.0",
            "source_sha256": _sha256_number(900),
            "spec_sha256": _sha256_number(901),
            "seed": f"scale-{active_patterns}-pattern-seed",
        },
        "composition": {
            "taxonomy": [
                {
                    "entity_class": "synthetic_person",
                    "entities": active_entities,
                    "canonical_names": active_names - active_aliases,
                    "aliases": active_aliases,
                    "literal_patterns": active_patterns - regex_patterns,
                    "regex_patterns": regex_patterns,
                },
            ]
        },
        "descriptor_sha256": _sha256_number(0),
        "active_entities": active_entities,
        "active_names": active_names,
        "active_aliases": active_aliases,
        "active_patterns": active_patterns,
        "canonical_json_bytes": active_patterns * 64,
        "native_source_bytes": active_patterns * 32,
    }
    _refresh_bank_descriptor(descriptor)
    return descriptor


def _make_performance_harnesses(evidence: Mapping[str, Any]) -> list[JsonObject]:
    harnesses: list[JsonObject] = []
    for number, phase in enumerate(enron_contract.PERFORMANCE_PHASES, start=1):
        descriptor: JsonObject = {
            "id": f"{phase}_harness",
            "phase": phase,
            "command_id": "fixture_build",
            "source_sha256": _sha256_number(680 + number),
            "operation_spec_sha256": _sha256_number(700 + number),
            "source_artifact": (
                copy.deepcopy(evidence["splits"]["roles"]["train"]["artifact"])
                if phase in {"source_profile", "source_build"}
                else None
            ),
            "descriptor_sha256": _sha256_number(0),
        }
        descriptor["descriptor_sha256"] = hash_enron_performance_harness(descriptor)
        harnesses.append(descriptor)
    return sorted(harnesses, key=lambda item: item["id"])


def _refresh_harness_dependents(evidence: JsonObject, harness: JsonObject) -> None:
    harness["descriptor_sha256"] = hash_enron_performance_harness(harness)
    for workload in evidence["performance"]["workloads"]:
        if workload["harness_id"] != harness["id"]:
            continue
        workload["harness_sha256"] = harness["descriptor_sha256"]
        workload["workload_sha256"] = hash_enron_workload(workload)


def _make_decision_workload(
    evidence: JsonObject,
    template: JsonObject,
    *,
    identifier: str,
    bank: Mapping[str, Any],
    input_descriptor: Mapping[str, Any],
    phase: str,
    sample_unit: str,
    promotion_gate: bool = False,
    concurrency: int = 1,
    decision_grade: bool = True,
    sample_count: int | None = None,
) -> JsonObject:
    process_model = {
        "source_profile": "fresh_process_per_sample",
        "source_build": "fresh_process_per_sample",
        "cold_compile": "fresh_process_per_sample",
        "helper_cache_miss": "fresh_process_per_sample",
        "helper_cache_hit": "reused_process",
        "direct_bank_scan": "reused_process",
        "end_to_end": "fresh_process_per_sample",
    }[phase]
    setup_phase = phase in {"source_profile", "source_build", "cold_compile"}
    if setup_phase:
        sample_unit = "operation"
    resolved_sample_count = (
        sample_count
        if sample_count is not None
        else 20
        if setup_phase
        else 1_000
        if phase == "direct_bank_scan" and decision_grade
        else 100
    )
    sample_base = (
        0.0001
        if sample_unit == "document"
        else 0.015
        if phase == "helper_cache_miss"
        else 0.02
        if phase == "end_to_end"
        else 0.01
    )
    sample_step = 0.00000001 if sample_unit == "document" else 0.000001
    harness = next(item for item in evidence["performance"]["harnesses"] if item["phase"] == phase)
    workload = copy.deepcopy(template)
    workload.update(
        {
            "id": identifier,
            "phase": phase,
            "promotion_gate": promotion_gate,
            "decision_grade": decision_grade,
            "harness_id": harness["id"],
            "harness_sha256": harness["descriptor_sha256"],
            "bank_id": bank["id"],
            "bank_hash": bank["bank_hash"],
            "input_id": None if setup_phase else input_descriptor["id"],
            "input_sha256": None if setup_phase else input_descriptor["descriptor_sha256"],
            "baseline_id": None,
            "warmups": 3 if process_model == "reused_process" else 0,
            "sample_unit": sample_unit,
            "work_per_sample": 1,
            "concurrency": concurrency,
            "process_model": process_model,
            "samples_seconds": [sample_base + index * sample_step for index in range(resolved_sample_count)],
            "samples_ref": None,
            "peak_rss_bytes": 1024 * 1024,
        }
    )
    _refresh_workload(evidence, workload)
    return workload


def _add_baseline_comparisons_and_breakeven(
    evidence: JsonObject, candidate_workloads: Sequence[JsonObject]
) -> list[JsonObject]:
    performance = evidence["performance"]
    baseline: JsonObject = {
        "id": "exact_fixture_baseline",
        "name": "fixture-exact-reference",
        "version": "1.0.0",
        "source_sha256": _sha256_number(960),
        "capabilities": {
            "literal_patterns": True,
            "regex_patterns": True,
            "aliases": True,
            "canonical_mapping": True,
            "unicode": True,
        },
        "semantic_equivalence": "exact",
        "descriptor_sha256": _sha256_number(0),
    }
    baseline["descriptor_sha256"] = hash_enron_performance_baseline(baseline)
    performance["baselines"] = [baseline]
    baseline_workloads: list[JsonObject] = []
    comparisons: list[JsonObject] = []
    for candidate in candidate_workloads:
        reference = copy.deepcopy(candidate)
        reference.update(
            {
                "id": f"baseline_{candidate['id']}",
                "promotion_gate": False,
                "decision_grade": False,
                "baseline_id": baseline["id"],
                "samples_seconds": [float(value) * 1.01 for value in candidate["samples_seconds"]],
            }
        )
        _refresh_workload(evidence, reference)
        baseline_workloads.append(reference)
        metrics = [
            "p99_seconds"
            if candidate["phase"] == "direct_bank_scan" and candidate["stats"]["sample_count"] >= 1_000
            else "median_seconds"
        ]
        for metric in metrics:
            block_count = 10
            samples_per_block = len(candidate["samples_seconds"]) // block_count
            outputs = calculate_enron_performance_comparison(
                candidate["stats"],
                reference["stats"],
                metric=metric,
                noise_method="exact_block_swap",
                candidate_samples=candidate["samples_seconds"],
                baseline_samples=reference["samples_seconds"],
                block_count=block_count,
                samples_per_block=samples_per_block,
                block_assignment=["candidate_first", "control_first"] * 5,
                significance_level=0.05,
                stability_tolerance=0.05,
            )
            comparison: JsonObject = {
                "id": f"compare_{candidate['id']}_{metric}",
                "candidate_workload_id": candidate["id"],
                "baseline_workload_id": reference["id"],
                "comparison_kind": "same_path_stability",
                "metric": metric,
                "noise_method": "exact_block_swap",
                "block_assignment": ["candidate_first", "control_first"] * 5,
                "significance_level": 0.05,
                "stability_tolerance": 0.05,
                **outputs,
                "comparison_plan_sha256": _sha256_number(0),
            }
            comparison["comparison_plan_sha256"] = hash_enron_performance_comparison_plan(comparison)
            comparisons.append(comparison)
    performance["comparisons"] = sorted(comparisons, key=lambda item: item["id"])

    candidate_profile = next(item for item in candidate_workloads if item["phase"] == "source_profile")
    candidate_setup = next(item for item in candidate_workloads if item["phase"] == "source_build")
    candidate_compile = next(item for item in candidate_workloads if item["phase"] == "cold_compile")
    candidate_marginal = next(item for item in candidate_workloads if item["id"] == "direct_bank_throughput")
    candidate_proxy = next(item for item in candidate_workloads if item["id"] == "direct_bank_cache_value_proxy")
    baseline_marginal = next(item for item in candidate_workloads if item["id"] == "helper_cache_miss_fixture")
    cross_outputs = calculate_enron_performance_comparison(
        candidate_proxy["stats"],
        baseline_marginal["stats"],
        metric="p99_seconds",
        noise_multiplier=2.0,
        regression_tolerance=0.05,
        noise_method="paired_block_ratio_mad",
        candidate_samples=candidate_proxy["samples_seconds"],
        baseline_samples=baseline_marginal["samples_seconds"],
    )
    cross_comparison: JsonObject = {
        "id": "compare_direct_bank_cache_value_proxy_vs_helper_cache_miss_fixture_p99_seconds",
        "candidate_workload_id": candidate_proxy["id"],
        "baseline_workload_id": baseline_marginal["id"],
        "comparison_kind": "cross_path_value",
        "metric": "p99_seconds",
        "noise_multiplier": 2.0,
        "noise_method": "paired_block_ratio_mad",
        "regression_tolerance": 0.05,
        **cross_outputs,
        "comparison_plan_sha256": _sha256_number(0),
    }
    cross_comparison["comparison_plan_sha256"] = hash_enron_performance_comparison_plan(cross_comparison)
    comparisons.append(cross_comparison)
    performance["comparisons"] = sorted(comparisons, key=lambda item: item["id"])
    components = [
        {
            "id": "baseline_fixed_build",
            "side": "baseline",
            "application": "fixed",
            "category": "bank_build",
            "source": "workload_median_seconds",
            "description": "Shared candidate source-build time.",
            "workload_id": candidate_setup["id"],
            "assumption_sha256": None,
            "value": candidate_setup["stats"]["median_seconds"],
        },
        {
            "id": "baseline_fixed_source_curation",
            "side": "baseline",
            "application": "fixed",
            "category": "source_curation",
            "source": "declared_assumption",
            "description": "Shared frozen source-curation effort assumption.",
            "workload_id": None,
            "assumption_sha256": _sha256_number(970),
            "value": 0.001,
        },
        {
            "id": "baseline_fixed_source_profiling",
            "side": "baseline",
            "application": "fixed",
            "category": "source_profiling",
            "source": "workload_median_seconds",
            "description": "Shared measured source-profiling time.",
            "workload_id": candidate_profile["id"],
            "assumption_sha256": None,
            "value": candidate_profile["stats"]["median_seconds"],
        },
        {
            "id": "baseline_per_request_scan",
            "side": "baseline",
            "application": "per_unit",
            "category": "scan",
            "source": "workload_seconds_per_request",
            "description": "Exact NERB helper-cache-miss time per frozen whole-input request.",
            "workload_id": baseline_marginal["id"],
            "assumption_sha256": None,
            "value": baseline_marginal["stats"]["median_seconds"],
        },
        {
            "id": "candidate_fixed_build",
            "side": "candidate",
            "application": "fixed",
            "category": "bank_build",
            "source": "workload_median_seconds",
            "description": "Candidate source-build time.",
            "workload_id": candidate_setup["id"],
            "assumption_sha256": None,
            "value": candidate_setup["stats"]["median_seconds"],
        },
        {
            "id": "candidate_fixed_cold_compile",
            "side": "candidate",
            "application": "fixed",
            "category": "cold_compile",
            "source": "workload_median_seconds",
            "description": "Candidate cold native compilation time.",
            "workload_id": candidate_compile["id"],
            "assumption_sha256": None,
            "value": candidate_compile["stats"]["median_seconds"],
        },
        {
            "id": "candidate_fixed_source_curation",
            "side": "candidate",
            "application": "fixed",
            "category": "source_curation",
            "source": "declared_assumption",
            "description": "Frozen source-curation effort assumption.",
            "workload_id": None,
            "assumption_sha256": _sha256_number(970),
            "value": 0.001,
        },
        {
            "id": "candidate_fixed_source_profiling",
            "side": "candidate",
            "application": "fixed",
            "category": "source_profiling",
            "source": "workload_median_seconds",
            "description": "Measured candidate source-profiling time.",
            "workload_id": candidate_profile["id"],
            "assumption_sha256": None,
            "value": candidate_profile["stats"]["median_seconds"],
        },
        {
            "id": "candidate_per_request_scan",
            "side": "candidate",
            "application": "per_unit",
            "category": "scan",
            "source": "workload_seconds_per_request",
            "description": "Candidate scan time per frozen whole-input request.",
            "workload_id": candidate_marginal["id"],
            "assumption_sha256": None,
            "value": candidate_marginal["stats"]["median_seconds"],
        },
    ]
    candidate_fixed_value = sum(
        (
            candidate_profile["stats"]["median_seconds"],
            candidate_setup["stats"]["median_seconds"],
            candidate_compile["stats"]["median_seconds"],
            0.001,
        )
    )
    baseline_fixed_value = sum(
        (
            candidate_profile["stats"]["median_seconds"],
            candidate_setup["stats"]["median_seconds"],
            0.001,
        )
    )
    candidate_value_per_unit = candidate_marginal["stats"]["median_seconds"]
    baseline_value_per_unit = baseline_marginal["stats"]["median_seconds"]
    breakeven = calculate_enron_breakeven(
        candidate_fixed_value,
        baseline_fixed_value,
        candidate_value_per_unit,
        baseline_value_per_unit,
        minimum_units=1,
        maximum_units=1_000_000,
    )
    model: JsonObject = {
        "id": "fixture_build_scan_breakeven",
        "parameter_name": "whole_input_scan_requests",
        "parameter_unit": "request",
        "value_unit": "seconds",
        "minimum_units": 1,
        "maximum_units": 1_000_000,
        "components": components,
        "candidate_fixed_value": candidate_fixed_value,
        "baseline_fixed_value": baseline_fixed_value,
        "candidate_value_per_unit": candidate_value_per_unit,
        "baseline_value_per_unit": baseline_value_per_unit,
        **breakeven,
        "model_plan_sha256": _sha256_number(0),
    }
    model["model_plan_sha256"] = hash_enron_breakeven_plan(model)
    performance["breakeven_models"] = [model]
    return baseline_workloads


def _refresh_breakeven_outputs(model: JsonObject) -> None:
    totals = {
        (side, application): sum(
            float(item["value"])
            for item in model["components"]
            if item["side"] == side and item["application"] == application
        )
        for side in ("candidate", "baseline")
        for application in ("fixed", "per_unit")
    }
    result = calculate_enron_breakeven(
        totals[("candidate", "fixed")],
        totals[("baseline", "fixed")],
        totals[("candidate", "per_unit")],
        totals[("baseline", "per_unit")],
        minimum_units=model["minimum_units"],
        maximum_units=model["maximum_units"],
    )
    model.update(
        {
            "candidate_fixed_value": totals[("candidate", "fixed")],
            "baseline_fixed_value": totals[("baseline", "fixed")],
            "candidate_value_per_unit": totals[("candidate", "per_unit")],
            "baseline_value_per_unit": totals[("baseline", "per_unit")],
            **result,
        }
    )
    model["model_plan_sha256"] = hash_enron_breakeven_plan(model)


def _add_required_performance_matrix(evidence: JsonObject) -> dict[str, list[JsonObject]]:
    performance = evidence["performance"]
    inventories: dict[str, list[JsonObject]] = {}
    evaluated_bank = performance["banks"][0]
    performance["harnesses"] = _make_performance_harnesses(evidence)
    real_input, inventory = _make_performance_input(
        evaluated_bank,
        identifier="real_scan_input",
        artifact_number=700,
        kind="real_input",
        hit_density="normal",
    )
    performance["inputs"] = [real_input]
    inventories[real_input["inventory_ref"]["id"]] = inventory
    template = performance["workloads"][0]
    workloads = [
        _make_decision_workload(
            evidence,
            template,
            identifier="direct_bank_latency",
            bank=evaluated_bank,
            input_descriptor=real_input,
            phase="direct_bank_scan",
            sample_unit="document",
            promotion_gate=True,
        ),
        _make_decision_workload(
            evidence,
            template,
            identifier="direct_bank_throughput",
            bank=evaluated_bank,
            input_descriptor=real_input,
            phase="direct_bank_scan",
            sample_unit="whole_input",
            promotion_gate=True,
        ),
        _make_decision_workload(
            evidence,
            template,
            identifier="direct_bank_cache_value_proxy",
            bank=evaluated_bank,
            input_descriptor=real_input,
            phase="direct_bank_scan",
            sample_unit="whole_input",
            decision_grade=False,
            sample_count=100,
        ),
    ]
    for phase in (
        "source_profile",
        "source_build",
        "cold_compile",
        "helper_cache_miss",
        "helper_cache_hit",
        "end_to_end",
    ):
        workloads.append(
            _make_decision_workload(
                evidence,
                template,
                identifier=f"{phase}_fixture",
                bank=evaluated_bank,
                input_descriptor=real_input,
                phase=phase,
                sample_unit="whole_input",
                concurrency=4 if phase == "helper_cache_hit" else 1,
            )
        )

    scale_banks: dict[int, JsonObject] = {}
    for index, active_patterns in enumerate(enron_contract.PERFORMANCE_SCALE_PATTERNS, start=1):
        bank = _make_scale_bank(active_patterns, number=800 + index * 10)
        scale_banks[active_patterns] = bank
        performance["banks"].append(bank)

    scale_anchor, scale_inventory = _make_performance_input(
        scale_banks[1_000],
        identifier="scale_1000_input",
        artifact_number=850,
        kind="synthetic_input",
        hit_density="negative",
        bytes_per_document=10_240,
    )
    scale_anchor["generator"].update(
        {
            "id": "controlled_sweep_input_generator",
            "version": "1.0.0",
            "source_sha256": _sha256_number(1020),
        }
    )
    _refresh_input_descriptor(scale_anchor)
    scale_inputs = {1_000: scale_anchor}
    inventories[scale_anchor["inventory_ref"]["id"]] = scale_inventory
    for active_patterns in (10_000, 25_000, 100_000):
        input_descriptor = copy.deepcopy(scale_anchor)
        input_descriptor.update(
            {
                "id": f"scale_{active_patterns}_input",
                "bank_id": scale_banks[active_patterns]["id"],
                "bank_hash": scale_banks[active_patterns]["bank_hash"],
            }
        )
        _refresh_input_descriptor(input_descriptor)
        scale_inputs[active_patterns] = input_descriptor
    for active_patterns, input_descriptor in scale_inputs.items():
        performance["inputs"].append(input_descriptor)
        workloads.append(
            _make_decision_workload(
                evidence,
                template,
                identifier=f"scale_{active_patterns}_scan",
                bank=scale_banks[active_patterns],
                input_descriptor=input_descriptor,
                phase="direct_bank_scan",
                sample_unit="whole_input",
            )
        )

    for index, hit_density in enumerate(("sparse", "normal", "dense"), start=1):
        input_descriptor, density_inventory = _make_performance_input(
            scale_banks[1_000],
            identifier=f"density_{hit_density}_input",
            artifact_number=1000 + index,
            kind="synthetic_input",
            hit_density=hit_density,
            bytes_per_document=10_240,
        )
        input_descriptor["generator"].update(
            {
                "id": "controlled_sweep_input_generator",
                "version": "1.0.0",
                "source_sha256": _sha256_number(1020),
            }
        )
        _refresh_input_descriptor(input_descriptor)
        performance["inputs"].append(input_descriptor)
        inventories[input_descriptor["inventory_ref"]["id"]] = density_inventory
        workloads.append(
            _make_decision_workload(
                evidence,
                template,
                identifier=f"density_{hit_density}_scan",
                bank=scale_banks[1_000],
                input_descriptor=input_descriptor,
                phase="direct_bank_scan",
                sample_unit="whole_input",
            )
        )

    for index, (size_cohort, bytes_per_document) in enumerate(
        (("small", 512), ("large", 65_536), ("huge", 300_000)),
        start=1,
    ):
        input_descriptor, size_inventory = _make_performance_input(
            scale_banks[1_000],
            identifier=f"size_{size_cohort}_input",
            artifact_number=1010 + index,
            kind="synthetic_input",
            hit_density="negative",
            bytes_per_document=bytes_per_document,
        )
        input_descriptor["generator"].update(
            {
                "id": "controlled_sweep_input_generator",
                "version": "1.0.0",
                "source_sha256": _sha256_number(1020),
            }
        )
        _refresh_input_descriptor(input_descriptor)
        performance["inputs"].append(input_descriptor)
        inventories[input_descriptor["inventory_ref"]["id"]] = size_inventory
        workloads.append(
            _make_decision_workload(
                evidence,
                template,
                identifier=f"size_{size_cohort}_scan",
                bank=scale_banks[1_000],
                input_descriptor=input_descriptor,
                phase="direct_bank_scan",
                sample_unit="whole_input",
            )
        )

    workloads.append(
        _make_decision_workload(
            evidence,
            template,
            identifier="concurrency_4_scan",
            bank=scale_banks[1_000],
            input_descriptor=scale_anchor,
            phase="direct_bank_scan",
            sample_unit="whole_input",
            concurrency=4,
        )
    )
    baseline_workloads = _add_baseline_comparisons_and_breakeven(evidence, workloads)
    workloads.extend(baseline_workloads)
    performance["banks"].sort(key=lambda item: item["id"])
    performance["inputs"].sort(key=lambda item: item["id"])
    performance["harnesses"].sort(key=lambda item: item["id"])
    performance["workloads"] = sorted(workloads, key=lambda item: item["id"])
    return inventories


def _promotable(
    manifest: JsonObject, evidence: JsonObject
) -> tuple[JsonObject, JsonObject, dict[str, list[JsonObject]]]:
    cache_key = json.dumps(
        [manifest, evidence],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    cached = _PROMOTABLE_FIXTURE_CACHE.get(cache_key)
    if cached is not None:
        return copy.deepcopy(cached)
    bound_manifest = copy.deepcopy(manifest)
    value = copy.deepcopy(evidence)
    bound_manifest["artifact_kind"] = "real_benchmark"
    value["artifact_kind"] = "real_benchmark"
    release_commit = "f" * 40
    bound_manifest["software"]["git_commit"] = release_commit
    value["software"]["git_commit"] = release_commit
    bound_manifest["commands"] = copy.deepcopy(value["commands"])

    bound_manifest["source"]["input_records"] = 145
    bound_manifest["preparation"]["output_records"] = 145
    bound_manifest["splits"]["roles"]["test"].update({"records": 120, "groups": 120})
    natural_label = bound_manifest["labels"][0]
    natural_label["role_populations"][0].update({"documents": 120, "spans": 200})
    natural_label["span_count"] = 200
    natural_label["annotation_scope"]["document_regions"] = copy.deepcopy(
        bound_manifest["preparation"]["text_views"][0]["document_regions"]
    )
    natural_label["annotation_scope"]["exclusions"] = []
    value["source"] = copy.deepcopy(bound_manifest["source"])
    value["preparation"] = copy.deepcopy(bound_manifest["preparation"])
    value["splits"] = copy.deepcopy(bound_manifest["splits"])
    quality = value["quality"]["slices"][0]
    quality["annotation_scope"] = copy.deepcopy(natural_label["annotation_scope"])
    quality.update(
        {
            "promotion_gate": True,
            "documents": 120,
            "documents_with_sensitive_gold": 100,
            "documents_with_any_miss": 5,
            "documents_with_cataloged_gold": 80,
            "documents_with_any_cataloged_miss": 0,
            "documents_with_any_leaked_character": 5,
            "gold_spans": 200,
            "predicted_spans": 200,
            "true_positive": 190,
            "false_positive": 10,
            "false_negative": 10,
            "cataloged_gold_spans": 160,
            "cataloged_true_positive": 160,
            "cataloged_false_negative": 0,
            "cataloged_wrong_canonical": 0,
            "sensitive_gold_characters": 1000,
            "covered_sensitive_characters": 980,
            "leaked_sensitive_characters": 20,
            "predicted_characters": 1110,
            "over_redacted_characters": 130,
            "evaluated_characters": 10_000,
            "negative_documents": 20,
            "negative_documents_with_predictions": 10,
            "metrics": {
                "precision": 0.95,
                "open_world_recall": 0.95,
                "f1": 0.95,
                "catalog_coverage": 0.8,
                "cataloged_recall": 1.0,
                "document_leak_rate": 0.05,
                "cataloged_document_leak_rate": 0.0,
                "sensitive_character_recall": 0.98,
                "sensitive_character_leak_rate": 0.02,
                "negative_document_false_alarm_rate": 0.5,
                "over_redaction_rate": 0.013,
            },
        }
    )
    bound_manifest["quality_plan"][0].update(
        {
            "promotion_gate": True,
            "documents": quality["documents"],
            "documents_with_sensitive_gold": quality["documents_with_sensitive_gold"],
            "negative_documents": quality["negative_documents"],
            "gold_spans": quality["gold_spans"],
            "cataloged_gold_spans": quality["cataloged_gold_spans"],
            "documents_with_cataloged_gold": quality["documents_with_cataloged_gold"],
            "sensitive_gold_characters": quality["sensitive_gold_characters"],
            "evaluated_characters": quality["evaluated_characters"],
        }
    )
    inventories = _add_required_performance_matrix(value)

    quality_index = 0
    checks = [
        _gate(
            "catalog_conformance",
            "catalog_conformance",
            "/catalog_conformance/passed",
            "eq",
            True,
            value["catalog_conformance"]["passed"],
        ),
        _gate("privacy_scan", "privacy", "/privacy/status", "eq", "passed", value["privacy"]["status"]),
        _gate("clean_git", "provenance", "/software/git_dirty", "eq", False, value["software"]["git_dirty"]),
        _gate(
            "cataloged_false_negative",
            "quality",
            f"/quality/slices/{quality_index}/cataloged_false_negative",
            "eq",
            0,
            quality["cataloged_false_negative"],
        ),
        _gate(
            "cataloged_wrong_canonical",
            "quality",
            f"/quality/slices/{quality_index}/cataloged_wrong_canonical",
            "eq",
            0,
            quality["cataloged_wrong_canonical"],
        ),
        _gate(
            "cataloged_document_miss",
            "quality",
            f"/quality/slices/{quality_index}/documents_with_any_cataloged_miss",
            "eq",
            0,
            quality["documents_with_any_cataloged_miss"],
        ),
    ]
    quality_thresholds = {
        "open_world_recall": ("gte", 0.95),
        "catalog_coverage": ("gte", 0.8),
        "cataloged_recall": ("gte", 1.0),
        "document_leak_rate": ("lte", 0.05),
        "sensitive_character_recall": ("gte", 0.98),
        "sensitive_character_leak_rate": ("lte", 0.02),
        "negative_document_false_alarm_rate": ("lte", 0.5),
        "over_redaction_rate": ("lte", 0.05),
    }
    for metric, (operator, threshold) in quality_thresholds.items():
        checks.append(
            _gate(
                f"quality_{metric}",
                "quality",
                f"/quality/slices/{quality_index}/metrics/{metric}",
                operator,
                threshold,
                quality["metrics"][metric],
            )
        )
    performance_input_by_id = {item["id"]: item for item in value["performance"]["inputs"]}
    for workload_index, workload in enumerate(value["performance"]["workloads"]):
        if not workload["decision_grade"]:
            continue
        fields = {
            "median_seconds": ("lte", 1.0),
            "p95_seconds": ("lte", 1.0),
            "peak_rss_bytes": ("lte", 2 * 1024 * 1024),
        }
        if workload["phase"] in enron_contract.PERFORMANCE_SETUP_PHASES:
            fields["mad_seconds"] = ("lte", 1.0)
        else:
            fields["p99_seconds"] = ("lte", 1.0)
        if workload["sample_unit"] == "document":
            fields["seconds_per_document"] = ("lte", 1.0)
            if workload["phase"] == "direct_bank_scan":
                fields["p99_seconds"] = ("lte", 0.05)
        elif workload["sample_unit"] == "whole_input":
            fields.update(
                {
                    "documents_per_second": ("gte", 1.0),
                    "mib_per_second": ("gte", 0.001),
                }
            )
            if workload["promotion_gate"]:
                fields["documents_per_second"] = ("gte", 100.0)
                fields["mib_per_second"] = ("gte", 1.0)
            if workload["phase"] == "direct_bank_scan":
                input_descriptor = performance_input_by_id[workload["input_id"]]
                fields["documents_per_second"] = ("gte", 100.0)
                fields["mib_per_second"] = ("gte", 1.0)
                fields["p99_seconds"] = (
                    "lte",
                    min(
                        input_descriptor["documents"] / 100.0,
                        (input_descriptor["bytes"] / (1024 * 1024)) / 1.0,
                    ),
                )
        for field, (operator, threshold) in fields.items():
            target = f"/performance/workloads/{workload_index}/"
            target += f"stats/{field}" if field != "peak_rss_bytes" else field
            actual = workload[field] if field == "peak_rss_bytes" else workload["stats"][field]
            checks.append(
                _gate(
                    f"performance_{workload['id']}_{field}",
                    "performance",
                    target,
                    operator,
                    threshold,
                    actual,
                )
            )
    value["promotion"]["checks"] = checks
    latency_index = next(
        index
        for index, workload in enumerate(value["performance"]["workloads"])
        if workload["id"] == "direct_bank_latency"
    )
    throughput_index = next(
        index
        for index, workload in enumerate(value["performance"]["workloads"])
        if workload["id"] == "direct_bank_throughput"
    )
    quality_claim_metrics = (
        "precision",
        "open_world_recall",
        "f1",
        "catalog_coverage",
        "cataloged_recall",
        "document_leak_rate",
        "cataloged_document_leak_rate",
        "sensitive_character_recall",
        "sensitive_character_leak_rate",
        "negative_document_false_alarm_rate",
        "over_redaction_rate",
    )
    value["promotion"]["claims"] = [
        _catalog_claim(value),
        *(_quality_claim(value, metric) for metric in quality_claim_metrics),
        _performance_claim(
            value,
            "direct_bank_scan_p99_seconds",
            "p99_seconds",
            workload_index=latency_index,
        ),
        _performance_claim(
            value,
            "direct_bank_scan_mib_per_second",
            "mib_per_second",
            workload_index=throughput_index,
        ),
    ]
    value["promotion"]["passed"] = True
    value["verifier"]["passed"] = True
    _refresh_frozen_contract(value)
    _sync_bound_manifest(bound_manifest, value)
    result = (bound_manifest, value, inventories)
    _PROMOTABLE_FIXTURE_CACHE[cache_key] = copy.deepcopy(result)
    return result


def _validate_promoted(
    evidence: JsonObject,
    manifest: JsonObject,
    inventories: Mapping[str, Sequence[Mapping[str, int]]],
    *,
    trusted_lineage_prefix: Sequence[Mapping[str, Any]] = (),
    referenced_samples: Mapping[str, Sequence[float]] | None = None,
) -> JsonObject:
    return validate_enron_evidence(
        evidence,
        manifest=manifest,
        trusted_lineage_prefix=trusted_lineage_prefix,
        referenced_samples=referenced_samples,
        referenced_input_inventories=inventories,
    )


def _real_nonpromoted(
    manifest: JsonObject, evidence: JsonObject
) -> tuple[JsonObject, JsonObject, dict[str, list[JsonObject]]]:
    bound_manifest, value, inventories = _promotable(manifest, evidence)
    value["promotion"]["passed"] = False
    value["verifier"]["passed"] = False
    return bound_manifest, value, inventories


def _with_predecessor(evidence: JsonObject) -> list[JsonObject]:
    access = evidence["test_access"]
    current = copy.deepcopy(access["lineage"][-1])
    predecessor = copy.deepcopy(current)
    predecessor["benchmark_version"] = "fixture-v1"
    predecessor["accessed_at"] = "2026-07-09T00:02:00Z"
    predecessor["outcome"] = "failed"
    predecessor["aggregate_artifact"] = {
        "id": "prior_aggregate",
        "sha256": "sha256:" + "9" * 64,
        "bytes": 256,
    }
    predecessor["frozen_target"]["frozen_at"] = "2026-07-09T00:01:00Z"
    predecessor["frozen_target"]["test_artifact_sha256"] = "sha256:" + "8" * 64
    access["lineage"] = [predecessor, current]
    _normalize_lineage(evidence)
    return copy.deepcopy(access["lineage"][:-1])


def _unevaluated(evidence: JsonObject) -> JsonObject:
    value = copy.deepcopy(evidence)
    value["quality"] = {
        "evaluated": False,
        "matching_semantics": value["quality"]["matching_semantics"],
        "character_position_semantics": value["quality"]["character_position_semantics"],
        "slices": [],
    }
    value["catalog_conformance"] = {
        "evaluated": False,
        "label_artifact_id": None,
        "active_patterns": 0,
        "patterns_with_positive_cases": 0,
        "approved_positive_cases": 0,
        "correctly_mapped": 0,
        "missed": 0,
        "wrong_canonical": 0,
        "negative_cases": 0,
        "unexpected_negative_matches": 0,
        "positive_cases_artifact": None,
        "negative_cases_artifact": None,
        "policy_sha256": None,
        "recall": None,
        "passed": False,
    }
    value["performance"] = {
        "evaluated": False,
        "banks": [],
        "inputs": [],
        "harnesses": [],
        "workloads": [],
        "baselines": [],
        "comparisons": [],
        "breakeven_models": [],
    }
    value["test_access"]["current_version_access_count"] = 0
    value["test_access"]["current_version_accessed_at"] = None
    value["test_access"]["lineage"] = []
    value["test_access"]["lineage_head_sha256"] = None
    value["promotion"] = {
        "passed": False,
        "checks": [_gate("privacy_scan", "privacy", "/privacy/status", "eq", "passed", value["privacy"]["status"])],
        "claims": [],
    }
    value["verifier"]["passed"] = False
    _refresh_frozen_contract(value)
    return value


def _drop_performance_assertions(evidence: JsonObject) -> None:
    evidence["promotion"]["checks"] = [
        check for check in evidence["promotion"]["checks"] if check["category"] != "performance"
    ]
    evidence["promotion"]["claims"] = [
        claim for claim in evidence["promotion"]["claims"] if claim["kind"] != "performance"
    ]
    _refresh_frozen_contract(evidence)


def test_schema_ids_meta_validation_and_json_serialization() -> None:
    assert ENRON_MANIFEST_SCHEMA["$id"] == "https://nerb.dev/schemas/enron-manifest.v2.schema.json"
    assert ENRON_EVIDENCE_SCHEMA["$id"] == "https://nerb.dev/schemas/enron-evidence.v2.schema.json"
    assert ENRON_PERFORMANCE_OUTPUT_SCHEMA["$id"] == "https://nerb.dev/schemas/enron-performance-output.v2.schema.json"
    Draft202012Validator.check_schema(ENRON_MANIFEST_SCHEMA)
    Draft202012Validator.check_schema(ENRON_EVIDENCE_SCHEMA)
    Draft202012Validator.check_schema(ENRON_PERFORMANCE_OUTPUT_SCHEMA)
    json.dumps(ENRON_MANIFEST_SCHEMA, allow_nan=False)
    json.dumps(ENRON_EVIDENCE_SCHEMA, allow_nan=False)
    json.dumps(ENRON_PERFORMANCE_OUTPUT_SCHEMA, allow_nan=False)


def test_schemas_close_root_and_nested_objects(manifest: JsonObject, evidence: JsonObject) -> None:
    manifest["unexpected"] = True
    manifest["privacy"]["unexpected"] = True
    evidence["quality"]["slices"][0]["unexpected"] = True

    assert "contract.schema.additionalProperties" in _codes(validate_enron_manifest(manifest))
    assert "contract.schema.additionalProperties" in _codes(validate_enron_evidence(evidence))


def test_standalone_performance_output_schema_is_closed_and_schema_only(evidence: JsonObject) -> None:
    performance = copy.deepcopy(evidence["performance"])
    assert validate_enron_performance_output(performance) == {"valid": True, "diagnostics": []}

    performance["unexpected"] = True
    _assert_code(validate_enron_performance_output(performance), "contract.schema.additionalProperties")
    del performance["unexpected"]
    del performance["workloads"][0]["phase"]
    _assert_code(validate_enron_performance_output(performance), "contract.schema.required")


@pytest.mark.parametrize(
    ("path", "replacement", "code"),
    [
        (("quality", "slices", 0, "gold_spans"), True, "contract.schema.type"),
        (("quality", "slices", 0, "metrics", "open_world_recall"), float("nan"), "contract.resource_limits"),
        (("performance", "workloads", 0, "samples_seconds", 0), float("inf"), "contract.resource_limits"),
        (("performance", "workloads", 0, "samples_seconds", 0), 0.0, "contract.schema.minimum"),
        (("source", "input_records"), 2**63, "contract.schema.maximum"),
        (("commands", 0, "elapsed_seconds"), 1e301, "contract.resource_limits"),
    ],
)
def test_contract_rejects_non_json_or_out_of_range_numeric_values(
    evidence: JsonObject, path: JsonPath, replacement: Any, code: str
) -> None:
    _set(evidence, path, replacement)

    _assert_code(validate_enron_evidence(evidence), code)


@pytest.mark.parametrize(
    "field",
    [
        "artifact_kind",
        "evaluator",
        "source",
        "preparation",
        "splits",
        "bank",
        "software",
        "commands",
        "environment",
        "privacy",
        "verifier",
    ],
)
def test_evidence_requires_each_provenance_family(evidence: JsonObject, field: str) -> None:
    del evidence[field]

    _assert_code(validate_enron_evidence(evidence), "contract.schema.required")


def test_synthetic_fixtures_are_valid_exactly_bound_and_nonclaimable(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    assert manifest["schema_version"] == ENRON_MANIFEST_SCHEMA_VERSION
    assert evidence["schema_version"] == ENRON_EVIDENCE_SCHEMA_VERSION
    assert manifest["artifact_kind"] == evidence["artifact_kind"] == "synthetic_fixture"
    assert evidence["manifest_sha256"] == hash_enron_manifest(manifest)
    assert evidence["promotion"]["passed"] is False
    assert evidence["verifier"]["passed"] is False
    assert validate_enron_manifest(manifest) == {"valid": True, "diagnostics": []}
    assert validate_enron_evidence(evidence, manifest=manifest) == {"valid": True, "diagnostics": []}


def test_synthetic_fixture_cannot_self_promote_or_claim_verifier_success(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    evidence["promotion"]["passed"] = True
    evidence["verifier"]["passed"] = True

    result = validate_enron_evidence(evidence, manifest=manifest, trusted_lineage_prefix=[])

    _assert_code(result, "contract.synthetic_fixture_claim")


def test_synthetic_fixture_cannot_publish_structured_claims(evidence: JsonObject) -> None:
    evidence["promotion"]["claims"] = [_catalog_claim(evidence)]

    _assert_code(validate_enron_evidence(evidence), "contract.synthetic_fixture_claim")


def test_unverified_real_evidence_cannot_publish_structured_claims(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, value, inventories = _promotable(manifest, evidence)
    value["promotion"]["passed"] = False
    value["verifier"]["passed"] = False

    _assert_code(
        _validate_promoted(value, bound_manifest, inventories),
        "contract.unverified_claims",
    )


def test_manifest_annotation_states_are_consistent(manifest: JsonObject) -> None:
    label = manifest["labels"][0]
    label["label_strength"] = "unlabeled"
    label["annotation_completeness"] = "partial"

    _assert_code(validate_enron_manifest(manifest), "contract.unlabeled_annotation_state")


def test_natural_label_population_cannot_merge_multiple_entity_classes(manifest: JsonObject) -> None:
    manifest["labels"][0]["annotation_scope"]["entity_classes"].append("email_address")

    _assert_code(validate_enron_manifest(manifest), "contract.natural_label_entity_population")


@pytest.mark.parametrize(
    "path",
    [
        ("preparation", "prepared_artifact", "bytes"),
        ("splits", "roles", "test", "artifact", "bytes"),
        ("labels", 0, "artifact", "bytes"),
    ],
)
def test_content_addressed_artifacts_must_be_nonempty(manifest: JsonObject, path: JsonPath) -> None:
    _set(manifest, path, 0)

    _assert_code(validate_enron_manifest(manifest), "contract.schema.minimum")


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        ("leakage", "contract.split_leakage"),
        ("unsealed", "contract.test_not_sealed"),
        ("group_bounds", "contract.split_group_bounds"),
        ("role_total", "contract.split_record_total"),
        ("preparation_bounds", "contract.preparation_record_bounds"),
    ],
)
def test_manifest_split_and_preparation_invariants(manifest: JsonObject, mutation: str, code: str) -> None:
    if mutation == "leakage":
        manifest["splits"]["leakage_groups_crossing"] = 1
    elif mutation == "unsealed":
        manifest["splits"]["test_sealed"] = False
    elif mutation == "group_bounds":
        manifest["splits"]["roles"]["validation"]["groups"] = 6
    elif mutation == "role_total":
        manifest["splits"]["roles"]["validation"]["records"] = 6
    else:
        manifest["preparation"]["output_records"] = 31

    _assert_code(validate_enron_manifest(manifest), code)


def test_split_roles_cannot_reuse_identical_content_addressed_artifacts(manifest: JsonObject) -> None:
    train_artifact = copy.deepcopy(manifest["splits"]["roles"]["train"]["artifact"])
    manifest["splits"]["roles"]["validation"]["artifact"] = copy.deepcopy(train_artifact)
    manifest["splits"]["roles"]["test"]["artifact"] = copy.deepcopy(train_artifact)

    _assert_code(validate_enron_manifest(manifest), "contract.split_artifact_overlap")


def test_manifest_timestamps_and_ids_are_deterministic(manifest: JsonObject) -> None:
    manifest["created_at"] = "not-a-time"
    manifest["commands"].append(copy.deepcopy(manifest["commands"][0]))
    manifest["labels"].append(copy.deepcopy(manifest["labels"][0]))

    result = validate_enron_manifest(manifest)

    assert {"contract.invalid_timestamp", "contract.duplicate_id"} <= _codes(result)


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        ("documents", "contract.label_population_bounds"),
        ("span_total", "contract.label_population_spans"),
        ("missing_role", "contract.label_population_roles"),
        ("duplicate_role", "contract.duplicate_label_population_role"),
        ("natural_conformance_role", "contract.natural_label_role"),
        ("synthetic_test_role", "contract.conformance_label_role"),
    ],
)
def test_manifest_label_populations_are_role_bound_and_bounded(manifest: JsonObject, mutation: str, code: str) -> None:
    natural = manifest["labels"][0]
    conformance = manifest["labels"][1]
    if mutation == "documents":
        natural["role_populations"][0]["documents"] = manifest["splits"]["roles"]["test"]["records"] + 1
    elif mutation == "span_total":
        natural["role_populations"][0]["spans"] += 1
    elif mutation == "missing_role":
        natural["roles"] = ["test", "validation"]
    elif mutation == "duplicate_role":
        natural["role_populations"].append(copy.deepcopy(natural["role_populations"][0]))
    elif mutation == "natural_conformance_role":
        natural["roles"] = ["conformance"]
        natural["role_populations"][0]["role"] = "conformance"
    else:
        conformance["roles"] = ["test"]
        conformance["role_populations"][0]["role"] = "test"

    _assert_code(validate_enron_manifest(manifest), code)


@pytest.mark.parametrize("mutation", ["same_producer", "missing_adjudication"])
def test_independent_labels_require_distinct_review_and_adjudication_provenance(
    manifest: JsonObject, mutation: str
) -> None:
    provenance = manifest["labels"][0]["annotation_provenance"]
    if mutation == "same_producer":
        provenance["reviewer_id"] = provenance["producer_id"]
    else:
        provenance["adjudication_artifact"] = None

    result = validate_enron_manifest(manifest)

    assert {"contract.annotation_review_provenance", "contract.annotation_independence"} <= _codes(result)


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        ("unknown_label", "contract.unknown_quality_plan_label"),
        ("unknown_view", "contract.unknown_quality_text_view"),
        ("wrong_role", "contract.quality_plan_label_role"),
        ("wrong_class", "contract.quality_plan_entity_class"),
        ("duplicate_descriptor", "contract.duplicate_quality_plan_descriptor"),
    ],
)
def test_manifest_quality_plan_is_closed_over_labels_views_and_unique_descriptors(
    manifest: JsonObject, mutation: str, code: str
) -> None:
    plan = manifest["quality_plan"][0]
    if mutation == "unknown_label":
        plan["label_artifact_id"] = "missing_labels"
    elif mutation == "unknown_view":
        plan["text_view"] = "missing_view"
    elif mutation == "wrong_role":
        plan["split_role"] = "validation"
    elif mutation == "wrong_class":
        plan["entity_class"] = "email_address"
    else:
        duplicate = copy.deepcopy(plan)
        duplicate["id"] = "duplicate_descriptor"
        manifest["quality_plan"].append(duplicate)

    _assert_code(validate_enron_manifest(manifest), code)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("documents", 99),
        ("gold_spans", 99),
        ("negative_documents", 19),
        ("sensitive_gold_characters", 499),
    ],
)
def test_decision_grade_quality_plan_rejects_tiny_privacy_support(
    manifest: JsonObject, evidence: JsonObject, field: str, value: int
) -> None:
    bound_manifest, _, _ = _promotable(manifest, evidence)
    plan = bound_manifest["quality_plan"][0]
    plan[field] = value
    label = bound_manifest["labels"][0]
    if field == "documents":
        bound_manifest["source"]["input_records"] = 124
        bound_manifest["preparation"]["output_records"] = 124
        bound_manifest["splits"]["roles"]["test"].update({"records": value, "groups": value})
        label["role_populations"][0]["documents"] = value
        plan["documents_with_sensitive_gold"] = 79
        plan["negative_documents"] = 20
    elif field == "gold_spans":
        label["role_populations"][0]["spans"] = value
        label["span_count"] = value
        plan["cataloged_gold_spans"] = value
    elif field == "negative_documents":
        plan["documents_with_sensitive_gold"] = plan["documents"] - value

    _assert_code(validate_enron_manifest(bound_manifest), "contract.quality_gate_minimum_support")


def test_quality_gate_must_label_the_entire_frozen_final_test_population(manifest: JsonObject) -> None:
    label = manifest["labels"][0]
    label["role_populations"][0]["documents"] = 4
    plan = manifest["quality_plan"][0]
    plan.update(
        {
            "promotion_gate": True,
            "documents": 4,
            "documents_with_sensitive_gold": 4,
            "negative_documents": 0,
        }
    )

    _assert_code(validate_enron_manifest(manifest), "contract.quality_gate_test_population")


def test_promoted_quality_gate_rejects_annotation_region_subset(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    primary_view = bound_manifest["preparation"]["text_views"][0]
    primary_view["document_regions"].append("natural_subject")
    bound_manifest["labels"][0]["annotation_scope"]["document_regions"].append("natural_subject")
    promoted["preparation"] = copy.deepcopy(bound_manifest["preparation"])
    promoted["quality"]["slices"][0]["annotation_scope"]["document_regions"].append("natural_subject")
    _sync_bound_manifest(bound_manifest, promoted)
    promoted["quality"]["slices"][0]["annotation_scope"]["document_regions"] = ["natural_body"]

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.quality_gate_annotation_scope",
    )


def test_promoted_quality_gate_rejects_annotation_exclusions(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    promoted["quality"]["slices"][0]["annotation_scope"]["exclusions"] = ["natural_subject"]

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.quality_gate_annotation_scope",
    )


def test_answer_bearing_nonprimary_view_cannot_replace_promoted_natural_view(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    injected_view = copy.deepcopy(bound_manifest["preparation"]["text_views"][0])
    injected_view.update(
        {
            "id": "answer_inventory_view",
            "artifact_sha256": _sha256_number(950),
            "primary_for_quality": False,
            "answer_bearing_fields_included": True,
        }
    )
    bound_manifest["preparation"]["text_views"].append(injected_view)
    promoted["preparation"] = copy.deepcopy(bound_manifest["preparation"])
    promoted["quality"]["slices"][0]["text_view"] = injected_view["id"]
    claim = next(item for item in promoted["promotion"]["claims"] if item["kind"] == "open_world_quality")
    claim["scope"]["text_view"] = injected_view["id"]
    _sync_bound_manifest(bound_manifest, promoted)

    result = _validate_promoted(promoted, bound_manifest, inventories)

    assert {"contract.quality_plan_binding", "contract.quality_gate_primary_view"} <= _codes(result)


def test_answer_bearing_view_cannot_be_promoted_by_relabeling_it_primary(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    natural_view = bound_manifest["preparation"]["text_views"][0]
    natural_view["primary_for_quality"] = False
    injected_view = copy.deepcopy(natural_view)
    injected_view.update(
        {
            "id": "answer_inventory_view",
            "artifact_sha256": _sha256_number(951),
            "primary_for_quality": True,
            "answer_bearing_fields_included": True,
        }
    )
    bound_manifest["preparation"]["text_views"].append(injected_view)
    bound_manifest["quality_plan"][0]["text_view"] = injected_view["id"]
    promoted["preparation"] = copy.deepcopy(bound_manifest["preparation"])
    promoted["quality"]["slices"][0]["text_view"] = injected_view["id"]
    for claim in promoted["promotion"]["claims"]:
        if claim["kind"] == "open_world_quality":
            claim["scope"]["text_view"] = injected_view["id"]
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.answer_bearing_quality_view",
    )


@pytest.mark.parametrize(
    ("field", "replacement", "code"),
    [
        ("label_artifact_id", "missing_labels", "contract.unknown_label_artifact"),
        ("label_strength", "structured_weak", "contract.label_binding_mismatch"),
        ("annotation_completeness", "partial", "contract.label_binding_mismatch"),
        ("split_role", "validation", "contract.label_role_mismatch"),
    ],
)
def test_quality_slice_annotation_provenance_binds_to_manifest(
    manifest: JsonObject, evidence: JsonObject, field: str, replacement: Any, code: str
) -> None:
    evidence["quality"]["slices"][0][field] = replacement

    _assert_code(validate_enron_evidence(evidence, manifest=manifest), code)


def test_quality_entity_class_must_be_inside_annotation_scope(evidence: JsonObject) -> None:
    evidence["quality"]["slices"][0]["entity_class"] = "email_address"

    _assert_code(validate_enron_evidence(evidence), "contract.annotation_scope_mismatch")


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("matching_semantics", "substring"),
        ("character_position_semantics", "scalar_index_without_document"),
    ],
)
def test_quality_semantics_lock_exact_spans_and_document_disjoint_positions(
    evidence: JsonObject, field: str, replacement: str
) -> None:
    evidence["quality"][field] = replacement

    _assert_code(validate_enron_evidence(evidence), "contract.schema.const")


def test_partial_independent_slice_is_diagnostic_only(manifest: JsonObject, evidence: JsonObject) -> None:
    manifest["labels"][0]["annotation_completeness"] = "partial"
    manifest["quality_plan"][0]["negative_documents"] = 0
    manifest["quality_plan"][0]["sensitive_gold_characters"] = 0
    manifest["quality_plan"][0]["evaluated_characters"] = 0
    item = evidence["quality"]["slices"][0]
    item["annotation_completeness"] = "partial"
    item["promotion_gate"] = False
    item["false_positive"] = 0
    item["predicted_spans"] = item["true_positive"]
    for field in (
        "sensitive_gold_characters",
        "covered_sensitive_characters",
        "leaked_sensitive_characters",
        "predicted_characters",
        "over_redacted_characters",
        "evaluated_characters",
        "negative_documents",
        "negative_documents_with_predictions",
        "documents_with_any_leaked_character",
    ):
        item[field] = 0
    for metric in (
        "precision",
        "open_world_recall",
        "f1",
        "document_leak_rate",
        "cataloged_document_leak_rate",
        "sensitive_character_recall",
        "sensitive_character_leak_rate",
        "negative_document_false_alarm_rate",
        "over_redaction_rate",
    ):
        item["metrics"][metric] = None
    evidence["promotion"]["claims"] = [
        claim for claim in evidence["promotion"]["claims"] if claim["kind"] != "open_world_quality"
    ]
    evidence["promotion"]["checks"] = [
        check for check in evidence["promotion"]["checks"] if check["category"] != "quality"
    ]
    _refresh_frozen_contract(evidence)
    _sync_bound_manifest(manifest, evidence)

    assert validate_enron_manifest(manifest) == {"valid": True, "diagnostics": []}
    assert validate_enron_evidence(evidence, manifest=manifest) == {"valid": True, "diagnostics": []}


def test_partial_independent_claim_is_rejected_even_when_nonpromoted(evidence: JsonObject) -> None:
    evidence["promotion"]["claims"] = [_quality_claim(evidence, "open_world_recall")]
    evidence["quality"]["slices"][0]["annotation_completeness"] = "partial"

    _assert_code(validate_enron_evidence(evidence), "contract.unsupported_claim")


@pytest.mark.parametrize(
    "field",
    [
        "gold_spans",
        "predicted_spans",
        "cataloged_gold_spans",
        "sensitive_gold_characters",
        "predicted_characters",
    ],
)
def test_quality_count_identities_are_recomputed(evidence: JsonObject, field: str) -> None:
    evidence["quality"]["slices"][0][field] += 1

    _assert_code(validate_enron_evidence(evidence), "contract.count_arithmetic")


@pytest.mark.parametrize(
    "metric",
    [
        "precision",
        "open_world_recall",
        "f1",
        "catalog_coverage",
        "cataloged_recall",
        "document_leak_rate",
        "cataloged_document_leak_rate",
        "sensitive_character_recall",
        "sensitive_character_leak_rate",
        "negative_document_false_alarm_rate",
        "over_redaction_rate",
    ],
)
def test_every_quality_metric_is_recomputed(evidence: JsonObject, metric: str) -> None:
    metrics = evidence["quality"]["slices"][0]["metrics"]
    metrics[metric] = 0.123456 if metrics[metric] != 0.123456 else 0.654321

    _assert_code(validate_enron_evidence(evidence), "contract.metric_arithmetic")


@pytest.mark.parametrize(
    ("numerator", "denominator"),
    [
        ("documents_with_sensitive_gold", "documents"),
        ("documents_with_any_miss", "documents_with_sensitive_gold"),
        ("documents_with_cataloged_gold", "documents_with_sensitive_gold"),
        ("documents_with_any_cataloged_miss", "documents_with_cataloged_gold"),
        ("documents_with_any_leaked_character", "documents_with_sensitive_gold"),
        ("cataloged_gold_spans", "gold_spans"),
        ("cataloged_true_positive", "true_positive"),
        ("cataloged_false_negative", "false_negative"),
        ("cataloged_wrong_canonical", "true_positive"),
        ("covered_sensitive_characters", "sensitive_gold_characters"),
        ("sensitive_gold_characters", "evaluated_characters"),
        ("predicted_characters", "evaluated_characters"),
        ("negative_documents_with_predictions", "negative_documents"),
        ("negative_documents", "documents"),
    ],
)
def test_quality_count_bounds_are_enforced(evidence: JsonObject, numerator: str, denominator: str) -> None:
    item = evidence["quality"]["slices"][0]
    item[numerator] = item[denominator] + 1

    _assert_code(validate_enron_evidence(evidence), "contract.count_bounds")


def test_exhaustive_quality_partitions_positive_and_negative_documents(evidence: JsonObject) -> None:
    evidence["quality"]["slices"][0]["negative_documents"] = 3

    _assert_code(validate_enron_evidence(evidence), "contract.document_partition")


@pytest.mark.parametrize(
    ("event_field", "document_field"),
    [
        ("false_negative", "documents_with_any_miss"),
        ("leaked_sensitive_characters", "documents_with_any_leaked_character"),
    ],
)
def test_quality_event_and_document_presence_are_consistent(
    evidence: JsonObject, event_field: str, document_field: str
) -> None:
    item = evidence["quality"]["slices"][0]
    assert item[event_field] > 0
    item[document_field] = 0
    if document_field == "documents_with_any_miss":
        item["metrics"]["document_leak_rate"] = 0.0

    _assert_code(validate_enron_evidence(evidence), "contract.document_event_consistency")


def test_cataloged_miss_documents_include_wrong_mappings(evidence: JsonObject) -> None:
    item = evidence["quality"]["slices"][0]
    item["cataloged_true_positive"] = 15
    item["cataloged_wrong_canonical"] = 1
    item["metrics"]["cataloged_recall"] = 15 / 16

    _assert_code(validate_enron_evidence(evidence), "contract.document_event_consistency")


def test_document_event_count_cannot_exceed_corresponding_events(evidence: JsonObject) -> None:
    item = evidence["quality"]["slices"][0]
    item["documents_with_any_miss"] = 3
    item["metrics"]["document_leak_rate"] = 3 / 8

    _assert_code(validate_enron_evidence(evidence), "contract.document_event_bounds")


def test_document_disjoint_character_universe_is_bounded(evidence: JsonObject) -> None:
    item = evidence["quality"]["slices"][0]
    item["evaluated_characters"] = 110
    item["metrics"]["over_redaction_rate"] = 13 / 110

    _assert_code(validate_enron_evidence(evidence), "contract.character_universe_bounds")


def test_public_quality_slices_have_a_privacy_minimum_size(evidence: JsonObject) -> None:
    evidence["quality"]["slices"][0]["documents"] = 4

    _assert_code(validate_enron_evidence(evidence), "contract.privacy_small_slice")


@pytest.mark.parametrize("field", ["documents", "gold_spans"])
def test_quality_all_cohort_exactly_matches_bound_label_population(
    manifest: JsonObject, evidence: JsonObject, field: str
) -> None:
    evidence["quality"]["slices"][0][field] -= 1

    _assert_code(validate_enron_evidence(evidence, manifest=manifest), "contract.quality_population_exactness")


@pytest.mark.parametrize(
    "field",
    [
        "documents",
        "documents_with_sensitive_gold",
        "negative_documents",
        "gold_spans",
        "cataloged_gold_spans",
        "documents_with_cataloged_gold",
        "sensitive_gold_characters",
        "evaluated_characters",
    ],
)
def test_quality_evidence_cannot_drift_from_frozen_plan_denominators(
    manifest: JsonObject, evidence: JsonObject, field: str
) -> None:
    evidence["quality"]["slices"][0][field] += 1

    _assert_code(validate_enron_evidence(evidence, manifest=manifest), "contract.quality_plan_binding")


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        ("empty_predictions_with_characters", "contract.empty_prediction_character_set"),
        ("empty_gold_with_characters", "contract.empty_sensitive_character_set"),
        ("catalog_partition", "contract.cataloged_true_positive_partition"),
        ("perfect_span_recall_with_leaked_characters", "contract.exact_recall_character_consistency"),
    ],
)
def test_quality_count_and_position_set_invariants(evidence: JsonObject, mutation: str, code: str) -> None:
    item = evidence["quality"]["slices"][0]
    if mutation == "empty_predictions_with_characters":
        item["predicted_spans"] = 0
    elif mutation == "empty_gold_with_characters":
        item["sensitive_gold_characters"] = 0
    elif mutation == "catalog_partition":
        item["cataloged_true_positive"] = item["true_positive"]
        item["cataloged_wrong_canonical"] = 1
    else:
        item["true_positive"] = item["gold_spans"]
        item["false_negative"] = 0
        item["documents_with_any_miss"] = 0
        item["metrics"]["open_world_recall"] = 1.0
        item["metrics"]["f1"] = 2 * item["true_positive"] / (2 * item["true_positive"] + item["false_positive"])
        item["metrics"]["document_leak_rate"] = 0.0

    _assert_code(validate_enron_evidence(evidence), code)


@pytest.mark.parametrize(
    ("field", "replacement", "code"),
    [
        ("label_artifact_id", None, "contract.missing_conformance_label"),
        ("active_patterns", 4, "contract.conformance_bank_mismatch"),
        ("patterns_with_positive_cases", 4, "contract.incomplete_pattern_support"),
        ("approved_positive_cases", 4, "contract.pattern_case_support"),
        ("negative_cases", 0, "contract.empty_conformance"),
        ("positive_cases_artifact", None, "contract.missing_conformance_artifact"),
        ("approved_positive_cases", 11, "contract.conformance_arithmetic"),
        ("unexpected_negative_matches", 11, "contract.conformance_negative_bounds"),
        ("passed", False, "contract.conformance_gate"),
    ],
)
def test_conformance_binds_bank_pattern_support_and_negative_cases(
    evidence: JsonObject, field: str, replacement: Any, code: str
) -> None:
    evidence["catalog_conformance"][field] = replacement

    _assert_code(validate_enron_evidence(evidence), code)


def test_conformance_binds_exhaustive_synthetic_label_artifact(manifest: JsonObject, evidence: JsonObject) -> None:
    evidence["catalog_conformance"]["label_artifact_id"] = "independent_person_labels"

    _assert_code(
        validate_enron_evidence(evidence, manifest=manifest),
        "contract.conformance_label_binding",
    )


@pytest.mark.parametrize("mutation", ["negative_artifact", "negative_count", "policy"])
def test_conformance_evidence_cannot_drift_from_frozen_negative_cases_or_policy(
    manifest: JsonObject, evidence: JsonObject, mutation: str
) -> None:
    conformance = evidence["catalog_conformance"]
    if mutation == "negative_artifact":
        conformance["negative_cases_artifact"]["sha256"] = _sha256_number(998)
    elif mutation == "negative_count":
        conformance["negative_cases"] += 1
    else:
        conformance["policy_sha256"] = _sha256_number(997)

    _assert_code(validate_enron_evidence(evidence, manifest=manifest), "contract.conformance_plan_binding")


def test_manifest_conformance_plan_cannot_overlap_positive_and_negative_artifacts(manifest: JsonObject) -> None:
    manifest["conformance_plan"]["negative_cases_artifact"] = copy.deepcopy(
        manifest["conformance_plan"]["positive_cases_artifact"]
    )

    _assert_code(validate_enron_manifest(manifest), "contract.conformance_plan_artifact_overlap")


def test_unevaluated_evidence_is_valid_but_cannot_be_promoted(evidence: JsonObject) -> None:
    value = _unevaluated(evidence)
    assert validate_enron_evidence(value) == {"valid": True, "diagnostics": []}

    value["promotion"]["passed"] = True
    _assert_code(validate_enron_evidence(value), "contract.promotion_prerequisite")


def test_real_unevaluated_evidence_cannot_forge_promotion_and_verifier_success(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    bound_manifest = copy.deepcopy(manifest)
    value = _unevaluated(evidence)
    bound_manifest["artifact_kind"] = "real_benchmark"
    value["artifact_kind"] = "real_benchmark"
    bound_manifest["software"]["git_commit"] = "f" * 40
    value["software"]["git_commit"] = "f" * 40
    value["promotion"]["passed"] = True
    value["verifier"]["passed"] = True
    _refresh_frozen_contract(value)
    _sync_bound_manifest(bound_manifest, value)

    result = validate_enron_evidence(value, manifest=bound_manifest, trusted_lineage_prefix=[])

    assert {
        "contract.decision_grade_prerequisite",
        "contract.forged_promotion",
        "contract.forged_verifier",
    } <= _codes(result)


@pytest.mark.parametrize(
    ("path", "replacement", "code"),
    [
        (("value",), 0.1, "contract.unsupported_claim"),
        (("label_strength",), "structured_weak", "contract.unsupported_claim"),
        (("annotation_completeness",), "partial", "contract.unsupported_claim"),
        (("quality_slice_id",), "missing", "contract.unsupported_claim"),
        (("scope", "cohort"), "head", "contract.unsupported_claim"),
        (("source_revision",), "other", "contract.claim_provenance"),
        (("bank_hash",), "sha256:" + "0" * 64, "contract.unsupported_claim"),
        (("environment_sha256",), "sha256:" + "0" * 64, "contract.claim_provenance"),
    ],
)
def test_structured_quality_claims_are_verified_even_when_nonpromoted(
    manifest: JsonObject, evidence: JsonObject, path: JsonPath, replacement: Any, code: str
) -> None:
    bound_manifest, value, inventories = _real_nonpromoted(manifest, evidence)
    claim = next(item for item in value["promotion"]["claims"] if item["metric"] == "open_world_recall")
    _set(claim, path, replacement)

    _assert_code(_validate_promoted(value, bound_manifest, inventories), code)


def test_structured_performance_claim_must_reference_exact_workload(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, value, inventories = _real_nonpromoted(manifest, evidence)
    claim = next(item for item in value["promotion"]["claims"] if item["kind"] == "performance")
    claim["performance_workload_id"] = "missing"

    _assert_code(
        _validate_promoted(value, bound_manifest, inventories),
        "contract.unsupported_claim",
    )


def test_promoted_quality_claim_cannot_cherry_pick_a_non_gate_validation_slice(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    validation = copy.deepcopy(promoted["quality"]["slices"][0])
    validation.update({"id": "validation_cherry_pick", "split_role": "validation", "promotion_gate": False})
    promoted["quality"]["slices"].append(validation)
    claim_index = next(
        index for index, item in enumerate(promoted["promotion"]["claims"]) if item["metric"] == "open_world_recall"
    )
    promoted["promotion"]["claims"][claim_index] = _quality_claim(
        promoted,
        "open_world_recall",
        slice_index=len(promoted["quality"]["slices"]) - 1,
    )

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.unsupported_claim",
    )


def test_promoted_performance_claim_cannot_cherry_pick_a_synthetic_scale_workload(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    scale_index = next(
        index for index, item in enumerate(promoted["performance"]["workloads"]) if item["id"].startswith("scale_")
    )
    claim_index = next(
        index
        for index, item in enumerate(promoted["promotion"]["claims"])
        if item["metric"] == "direct_bank_scan_mib_per_second"
    )
    promoted["promotion"]["claims"][claim_index] = _performance_claim(
        promoted,
        "direct_bank_scan_mib_per_second",
        "mib_per_second",
        workload_index=scale_index,
    )

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.unsupported_claim",
    )


def test_duplicate_claim_ids_are_rejected(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, value, inventories = _real_nonpromoted(manifest, evidence)
    value["promotion"]["claims"].append(copy.deepcopy(value["promotion"]["claims"][0]))

    _assert_code(_validate_promoted(value, bound_manifest, inventories), "contract.duplicate_id")


@pytest.mark.parametrize(
    "metric",
    [
        "catalog_conformance_recall",
        "precision",
        "open_world_recall",
        "f1",
        "catalog_coverage",
        "cataloged_recall",
        "document_leak_rate",
        "cataloged_document_leak_rate",
        "sensitive_character_recall",
        "sensitive_character_leak_rate",
        "negative_document_false_alarm_rate",
        "over_redaction_rate",
        "direct_bank_scan_p99_seconds",
        "direct_bank_scan_mib_per_second",
    ],
)
def test_promotion_requires_the_complete_privacy_utility_and_speed_claim_scorecard(
    manifest: JsonObject, evidence: JsonObject, metric: str
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    promoted["promotion"]["claims"] = [item for item in promoted["promotion"]["claims"] if item["metric"] != metric]

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.missing_required_claim",
    )


def test_complete_quality_claim_suite_is_required_for_each_promoted_gate(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    second_label = copy.deepcopy(bound_manifest["labels"][0])
    second_label["id"] = "independent_person_labels_second"
    second_label["artifact"] = {
        "id": "independent_labels_second",
        "sha256": _sha256_number(952),
        "bytes": 1024,
    }
    second_label["annotation_provenance"]["adjudication_artifact"] = {
        "id": "independent_adjudication_second",
        "sha256": _sha256_number(953),
        "bytes": 512,
    }
    bound_manifest["labels"].append(second_label)

    second_plan = copy.deepcopy(bound_manifest["quality_plan"][0])
    second_plan.update(
        {
            "id": "independent_all_test_second",
            "label_artifact_id": second_label["id"],
        }
    )
    bound_manifest["quality_plan"].append(second_plan)

    second_slice = copy.deepcopy(promoted["quality"]["slices"][0])
    second_slice.update(
        {
            "id": second_plan["id"],
            "label_artifact_id": second_label["id"],
        }
    )
    promoted["quality"]["slices"].append(second_slice)
    first_quality_checks = [
        item for item in promoted["promotion"]["checks"] if item["target"].startswith("/quality/slices/0/")
    ]
    for check in first_quality_checks:
        duplicate = copy.deepcopy(check)
        duplicate["id"] = f"second_{check['id']}"
        duplicate["target"] = duplicate["target"].replace("/quality/slices/0/", "/quality/slices/1/")
        promoted["promotion"]["checks"].append(duplicate)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.missing_required_claim",
    )


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        ("actual", "contract.gate_actual"),
        ("passed", "contract.gate_result"),
        ("target", "contract.gate_target"),
        ("category", "contract.gate_category_target"),
    ],
)
def test_typed_gates_recompute_target_actual_and_result(evidence: JsonObject, mutation: str, code: str) -> None:
    check = evidence["promotion"]["checks"][3]
    if mutation == "actual":
        check["actual"] = 0.1
    elif mutation == "passed":
        check["passed"] = not check["passed"]
    elif mutation == "target":
        check["target"] = "/quality/missing"
    else:
        check["category"] = "privacy"

    _assert_code(validate_enron_evidence(evidence), code)


def test_gate_actual_must_be_an_exact_copy_of_its_target(evidence: JsonObject) -> None:
    check = evidence["promotion"]["checks"][3]
    check["actual"] = math.nextafter(check["actual"], math.inf)

    _assert_code(validate_enron_evidence(evidence), "contract.gate_actual")


@pytest.mark.parametrize(
    ("actual", "operator", "threshold"),
    [
        (2**53 + 1, "eq", 2**53),
        (2**53, "gte", 2**53 + 1),
        (2**53 + 1, "lte", 2**53),
    ],
)
def test_gate_comparisons_preserve_large_integer_precision(actual: int, operator: str, threshold: int) -> None:
    assert enron_contract._compare_gate(actual, operator, threshold) is False


@pytest.mark.parametrize(
    "target",
    [
        "/performance/comparisons/0/candidate_value",
        "/performance/breakeven_models/0/candidate_fixed_value",
        "/performance/inputs/0/document_length_distribution/mean_bytes",
    ],
)
def test_performance_gates_cannot_target_tolerance_accepted_display_fields(
    manifest: JsonObject, evidence: JsonObject, target: str
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    actual = _resolve_pointer(promoted, target)
    promoted["promotion"]["checks"].append(
        _gate(
            "unsupported_performance_display_gate",
            "performance",
            target,
            "gte",
            actual,
            actual,
        )
    )
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.gate_target",
    )


def test_claim_cannot_round_quality_in_the_favorable_direction(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, value, inventories = _real_nonpromoted(manifest, evidence)
    claim = next(item for item in value["promotion"]["claims"] if item["metric"] == "open_world_recall")
    claim["value"] = math.nextafter(claim["value"], math.inf)

    _assert_code(
        _validate_promoted(value, bound_manifest, inventories),
        "contract.unsupported_claim",
    )


def test_quality_gate_uses_exact_count_ratio_at_gte_threshold(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    quality = promoted["quality"]["slices"][0]
    quality.update(
        {
            "gold_spans": 2_000_000_001,
            "true_positive": 1_900_000_000,
            "false_negative": 100_000_001,
            "false_positive": 10,
            "predicted_spans": 1_900_000_010,
            "cataloged_gold_spans": 1_600_000_001,
            "cataloged_true_positive": 1_600_000_001,
        }
    )
    quality["metrics"].update(
        {
            "precision": quality["true_positive"] / quality["predicted_spans"],
            "open_world_recall": 0.95,
            "f1": 2
            * quality["true_positive"]
            / (2 * quality["true_positive"] + quality["false_positive"] + quality["false_negative"]),
            "catalog_coverage": quality["cataloged_gold_spans"] / quality["gold_spans"],
            "cataloged_recall": 1.0,
        }
    )
    label = bound_manifest["labels"][0]
    next(item for item in label["role_populations"] if item["role"] == "test")["spans"] = quality["gold_spans"]
    label["span_count"] = quality["gold_spans"]
    plan = bound_manifest["quality_plan"][0]
    plan["gold_spans"] = quality["gold_spans"]
    plan["cataloged_gold_spans"] = quality["cataloged_gold_spans"]
    for claim in promoted["promotion"]["claims"]:
        if claim["kind"] == "open_world_quality":
            claim["value"] = quality["metrics"][claim["metric"]]
    _refresh_check_actuals(promoted, target_prefix="/quality/")
    _sync_bound_manifest(bound_manifest, promoted)

    exact_recall = quality["true_positive"] / quality["gold_spans"]
    assert exact_recall < 0.95
    result = _validate_promoted(promoted, bound_manifest, inventories)

    assert "contract.metric_arithmetic" not in _codes(result)
    assert "contract.unsupported_claim" in _codes(result)
    _assert_code(result, "contract.gate_result")


@pytest.mark.parametrize("referenced", [False, True])
def test_performance_gate_uses_raw_samples_at_lte_threshold(
    manifest: JsonObject, evidence: JsonObject, referenced: bool
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    workloads = {item["id"]: item for item in promoted["performance"]["workloads"]}
    candidate = workloads["direct_bank_latency"]
    baseline = workloads["baseline_direct_bank_latency"]
    candidate["samples_seconds"] = sorted(candidate["samples_seconds"])
    candidate["samples_seconds"][-11:] = [0.05000000002 + index / 1_000_000_000_000 for index in range(11)]
    baseline["samples_seconds"] = sorted(baseline["samples_seconds"])
    baseline["samples_seconds"][-11:] = [0.06000000002 + index / 1_000_000_000_000 for index in range(11)]
    _refresh_workload(promoted, candidate)
    raw_p99 = candidate["stats"]["p99_seconds"]
    _refresh_workload(promoted, baseline)
    candidate["stats"]["p99_seconds"] = 0.05

    candidate_index = promoted["performance"]["workloads"].index(candidate)
    _refresh_check_actuals(promoted, target_prefix=f"/performance/workloads/{candidate_index}/")
    for claim in promoted["promotion"]["claims"]:
        if claim["kind"] == "performance" and claim["performance_workload_id"] == candidate["id"]:
            claim["value"] = candidate["stats"]["p99_seconds"]

    referenced_samples = None
    if referenced:
        samples = list(candidate["samples_seconds"])
        candidate["samples_seconds"] = []
        candidate["samples_ref"] = {
            "id": "boundary_samples",
            "sha256": hash_enron_samples(samples),
            "bytes": _sample_payload_bytes(samples),
        }
        referenced_samples = {"boundary_samples": samples}
    _sync_bound_manifest(bound_manifest, promoted)

    assert raw_p99 > 0.05
    result = _validate_promoted(
        promoted,
        bound_manifest,
        inventories,
        referenced_samples=referenced_samples,
    )

    assert "contract.performance_arithmetic" not in _codes(result)
    assert "contract.unsupported_claim" in _codes(result)
    _assert_code(result, "contract.gate_result")


def test_threshold_hash_binds_typed_gate_configuration(evidence: JsonObject) -> None:
    evidence["promotion"]["checks"][3]["threshold"] = 0.99

    _assert_code(validate_enron_evidence(evidence), "contract.threshold_hash_mismatch")


def test_threshold_hash_is_reorder_stable_but_prevents_cross_gate_threshold_swaps(evidence: JsonObject) -> None:
    reordered = copy.deepcopy(evidence)
    reordered["promotion"]["checks"].reverse()
    assert validate_enron_evidence(reordered) == {"valid": True, "diagnostics": []}

    recall = next(item for item in reordered["promotion"]["checks"] if item["id"] == "open_world_recall")
    latency = next(item for item in reordered["promotion"]["checks"] if item["id"] == "direct_scan_median")
    recall["threshold"], latency["threshold"] = latency["threshold"], recall["threshold"]

    _assert_code(validate_enron_evidence(reordered), "contract.threshold_hash_mismatch")


@pytest.mark.parametrize(
    ("gate_kind", "threshold", "code"),
    [
        ("quality_gte", -1.0, "contract.vacuous_quality_threshold"),
        ("quality_lte", 100.0, "contract.vacuous_quality_threshold"),
        ("performance_gte", -1.0, "contract.vacuous_performance_threshold"),
        ("performance_lte", 0.0, "contract.vacuous_performance_threshold"),
    ],
)
def test_decision_grade_thresholds_reject_vacuous_minus_one_and_hundred_bypasses(
    manifest: JsonObject, evidence: JsonObject, gate_kind: str, threshold: float, code: str
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    if gate_kind == "quality_gte":
        check = next(item for item in promoted["promotion"]["checks"] if item["id"] == "quality_open_world_recall")
    elif gate_kind == "quality_lte":
        check = next(item for item in promoted["promotion"]["checks"] if item["id"] == "quality_document_leak_rate")
    elif gate_kind == "performance_gte":
        check = next(
            item
            for item in promoted["promotion"]["checks"]
            if item["operator"] == "gte" and item["target"].endswith("/stats/mib_per_second")
        )
    else:
        check = next(
            item
            for item in promoted["promotion"]["checks"]
            if item["operator"] == "lte" and item["target"].endswith("/stats/median_seconds")
        )
    check["threshold"] = threshold
    refreshed = _gate(
        check["id"],
        check["category"],
        check["target"],
        check["operator"],
        threshold,
        check["actual"],
    )
    check["passed"] = refreshed["passed"]
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(_validate_promoted(promoted, bound_manifest, inventories), code)


def test_decision_grade_recall_threshold_cannot_weaken_privacy_policy_floor(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    check = next(item for item in promoted["promotion"]["checks"] if item["id"] == "quality_open_world_recall")
    check["threshold"] = 0.94
    check["passed"] = True
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.quality_threshold_policy",
    )


@pytest.mark.parametrize(
    ("check_id", "threshold"),
    [
        ("performance_direct_bank_latency_p99_seconds", 0.051),
        ("performance_direct_bank_throughput_documents_per_second", 99.0),
        ("performance_direct_bank_throughput_mib_per_second", 0.99),
        ("performance_direct_bank_latency_peak_rss_bytes", 8 * 1024**3 + 1),
    ],
)
def test_same_machine_baseline_cannot_authorize_impractical_headline_thresholds(
    manifest: JsonObject, evidence: JsonObject, check_id: str, threshold: float
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    check = next(item for item in promoted["promotion"]["checks"] if item["id"] == check_id)
    check.update(
        _gate(
            check["id"],
            check["category"],
            check["target"],
            check["operator"],
            threshold,
            check["actual"],
        )
    )
    assert check["passed"] is True
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.performance_threshold_policy",
    )


def test_slower_exact_baseline_cannot_authorize_impractical_scale_performance(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    workloads = {item["id"]: item for item in promoted["performance"]["workloads"]}
    candidate = workloads["scale_100000_scan"]
    baseline = workloads["baseline_scale_100000_scan"]
    candidate["samples_seconds"] = [80_000.0 + index / 1_000_000 for index in range(1_000)]
    baseline["samples_seconds"] = [85_000.0 + index / 1_000_000 for index in range(1_000)]
    _refresh_workload(promoted, candidate)
    _refresh_workload(promoted, baseline)

    candidate_index = promoted["performance"]["workloads"].index(candidate)
    target_prefix = f"/performance/workloads/{candidate_index}/"
    for check in promoted["promotion"]["checks"]:
        if not check["target"].startswith(target_prefix):
            continue
        actual = _resolve_pointer(promoted, check["target"])
        threshold = check["threshold"]
        if check["target"].endswith("_seconds"):
            threshold = 90_000.0
        elif check["operator"] == "gte":
            threshold = 1e-9
        check.update(_gate(check["id"], check["category"], check["target"], check["operator"], threshold, actual))
        assert check["passed"] is True

    for comparison in promoted["performance"]["comparisons"]:
        if comparison["candidate_workload_id"] != candidate["id"]:
            continue
        _refresh_same_path_comparison(promoted, comparison)

    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.performance_threshold_policy",
    )


def test_gate_rejects_incompatible_typed_comparison(evidence: JsonObject) -> None:
    check = evidence["promotion"]["checks"][1]
    check["operator"] = "gte"
    _refresh_frozen_contract(evidence)

    _assert_code(validate_enron_evidence(evidence), "contract.gate_comparison")


def test_duplicate_gate_ids_are_rejected(evidence: JsonObject) -> None:
    evidence["promotion"]["checks"].append(copy.deepcopy(evidence["promotion"]["checks"][0]))

    _assert_code(validate_enron_evidence(evidence), "contract.duplicate_id")


def test_duplicate_gate_targets_are_rejected(evidence: JsonObject) -> None:
    duplicate = copy.deepcopy(evidence["promotion"]["checks"][0])
    duplicate["id"] = "same_target_different_id"
    evidence["promotion"]["checks"].append(duplicate)

    _assert_code(validate_enron_evidence(evidence), "contract.duplicate_gate_target")


def test_real_promotable_evidence_requires_and_accepts_manifest_and_trusted_lineage(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)

    assert validate_enron_manifest(bound_manifest) == {"valid": True, "diagnostics": []}
    assert _validate_promoted(promoted, bound_manifest, inventories) == {
        "valid": True,
        "diagnostics": [],
    }
    candidate_workloads = [item for item in promoted["performance"]["workloads"] if item["baseline_id"] is None]
    baseline_workloads = [item for item in promoted["performance"]["workloads"] if item["baseline_id"] is not None]
    assert len(promoted["performance"]["harnesses"]) == 7
    assert len(candidate_workloads) == len(baseline_workloads) == 20

    _assert_code(
        validate_enron_evidence(promoted, trusted_lineage_prefix=[]),
        "contract.manifest_required",
    )
    _assert_code(
        validate_enron_evidence(promoted, manifest=bound_manifest),
        "contract.trusted_lineage_required",
    )


def test_real_artifacts_reject_synthetic_placeholder_commit(manifest: JsonObject, evidence: JsonObject) -> None:
    manifest["artifact_kind"] = "real_benchmark"
    evidence["artifact_kind"] = "real_benchmark"

    _assert_code(validate_enron_manifest(manifest), "contract.placeholder_release_identity")
    _assert_code(validate_enron_evidence(evidence), "contract.placeholder_release_identity")


def test_zero_gold_cannot_be_a_promotion_quality_gate(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    promoted["quality"]["slices"][0]["gold_spans"] = 0

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.natural_catalog_gate",
    )


def test_promotion_requires_every_predeclared_quality_and_performance_gate(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    promoted["promotion"]["checks"] = [
        item for item in promoted["promotion"]["checks"] if item["id"] != "quality_over_redaction_rate"
    ]
    _refresh_frozen_contract(promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.missing_required_gate",
    )


def test_promotion_requires_mandated_gate_operator_semantics(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    check = next(
        item
        for item in promoted["promotion"]["checks"]
        if item["target"] == "/quality/slices/0/metrics/catalog_coverage"
    )
    check["operator"] = "lte"
    check["passed"] = False
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.required_gate_semantics",
    )


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        ("phase", "contract.missing_performance_phase"),
        ("scale", "contract.missing_scale_shape"),
        ("unused_bank", "contract.unused_performance_bank"),
    ],
)
def test_promotion_requires_full_phase_scale_density_and_concurrency_matrix(
    manifest: JsonObject, evidence: JsonObject, mutation: str, code: str
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    performance = promoted["performance"]
    if mutation == "phase":
        performance["workloads"] = [item for item in performance["workloads"] if item["phase"] != "end_to_end"]
    elif mutation == "scale":
        removed_hash = next(item["bank_hash"] for item in performance["banks"] if item["active_patterns"] == 1_000)
        performance["banks"] = [item for item in performance["banks"] if item["bank_hash"] != removed_hash]
        performance["workloads"] = [item for item in performance["workloads"] if item["bank_hash"] != removed_hash]
    else:
        unused_hash = next(item["bank_hash"] for item in performance["banks"] if item["active_patterns"] == 100_000)
        performance["workloads"] = [item for item in performance["workloads"] if item["bank_hash"] != unused_hash]
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        code,
    )


@pytest.mark.parametrize(
    ("axis", "code"),
    [
        ("scale", "contract.uncontrolled_scale_sweep"),
        ("density", "contract.uncontrolled_density_sweep"),
        ("size", "contract.uncontrolled_size_sweep"),
        ("concurrency", "contract.uncontrolled_concurrency_sweep"),
    ],
)
def test_global_axis_coverage_cannot_hide_confounded_performance_sweeps(
    manifest: JsonObject, evidence: JsonObject, axis: str, code: str
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    performance = promoted["performance"]
    workloads = {item["id"]: item for item in performance["workloads"]}
    if axis == "concurrency":
        anchor = next(item for item in performance["inputs"] if item["id"] == "scale_1000_input")
        concurrent_only = copy.deepcopy(anchor)
        concurrent_only["id"] = "concurrency_only_input"
        _refresh_input_descriptor(concurrent_only)
        performance["inputs"].append(concurrent_only)
        performance["inputs"].sort(key=lambda item: item["id"])
        for workload_id in ("concurrency_4_scan", "baseline_concurrency_4_scan"):
            workload = workloads[workload_id]
            workload["input_id"] = concurrent_only["id"]
            _refresh_workload(promoted, workload)
    else:
        candidate_id = {
            "scale": "scale_100000_scan",
            "density": "density_dense_scan",
            "size": "size_huge_scan",
        }[axis]
        for workload_id in (candidate_id, f"baseline_{candidate_id}"):
            workload = workloads[workload_id]
            workload["concurrency"] = 2
            workload["workload_sha256"] = hash_enron_workload(workload)

    direct_cells = [
        item
        for item in performance["workloads"]
        if item["decision_grade"] and item["baseline_id"] is None and item["phase"] == "direct_bank_scan"
    ]
    input_by_id = {item["id"]: item for item in performance["inputs"]}
    bank_by_id = {item["id"]: item for item in performance["banks"]}
    assert {bank_by_id[item["bank_id"]]["active_patterns"] for item in direct_cells} >= {
        1_000,
        10_000,
        25_000,
        100_000,
    }
    assert {input_by_id[item["input_id"]]["hit_density"] for item in direct_cells} >= {
        "negative",
        "sparse",
        "normal",
        "dense",
    }
    assert {input_by_id[item["input_id"]]["size_cohort"] for item in direct_cells} >= {
        "small",
        "medium",
        "large",
        "huge",
    }
    concurrencies = {item["concurrency"] for item in direct_cells}
    assert 1 in concurrencies and any(value > 1 for value in concurrencies)
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(_validate_promoted(promoted, bound_manifest, inventories), code)


def test_unrelated_generator_family_cannot_masquerade_as_controlled_density_sweep(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    performance = promoted["performance"]
    input_descriptor = next(item for item in performance["inputs"] if item["id"] == "density_dense_input")
    input_descriptor["generator"].update(
        {
            "id": "unrelated_generator_family",
            "version": "9.0.0",
            "source_sha256": _sha256_number(1110),
        }
    )
    _refresh_input_descriptor(input_descriptor)
    for workload in performance["workloads"]:
        if workload["input_id"] == input_descriptor["id"]:
            _refresh_workload(promoted, workload)
    assert {item["hit_density"] for item in performance["inputs"]} >= {
        "negative",
        "sparse",
        "normal",
        "dense",
    }
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.uncontrolled_density_sweep",
    )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("id", "unrelated_scale_bank_generator"),
        ("version", "9.0.0"),
        ("source_sha256", _sha256_number(1111)),
        ("spec_sha256", _sha256_number(1112)),
    ],
)
def test_required_scale_banks_share_one_generator_family(
    manifest: JsonObject, evidence: JsonObject, field: str, replacement: str
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    scale_bank = next(
        item
        for item in promoted["performance"]["banks"]
        if item["kind"] == "synthetic_scale" and item["active_patterns"] == 100_000
    )
    scale_bank["generator"][field] = replacement
    _refresh_bank_descriptor(scale_bank)
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.uncontrolled_scale_generator_family",
    )


@pytest.mark.parametrize(
    ("axis", "input_ids", "code"),
    [
        (
            "density",
            ("scale_1000_input", "density_sparse_input", "density_normal_input", "density_dense_input"),
            "contract.uncontrolled_density_sweep",
        ),
        (
            "size",
            ("scale_1000_input", "size_small_input", "size_large_input", "size_huge_input"),
            "contract.uncontrolled_size_sweep",
        ),
    ],
)
def test_unrelated_real_inputs_cannot_masquerade_as_a_controlled_generated_sweep(
    manifest: JsonObject,
    evidence: JsonObject,
    axis: str,
    input_ids: tuple[str, ...],
    code: str,
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    inputs = {item["id"]: item for item in promoted["performance"]["inputs"]}
    for input_id in input_ids:
        inputs[input_id]["kind"] = "real_input"
        inputs[input_id]["generator"] = None
        _refresh_input_descriptor(inputs[input_id])
    for workload in promoted["performance"]["workloads"]:
        if workload["input_id"] in input_ids:
            _refresh_workload(promoted, workload)
    assert axis in {"density", "size"}
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(_validate_promoted(promoted, bound_manifest, inventories), code)


def test_required_scale_axis_is_exact_active_pattern_count_not_alias_count(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    bank = next(item for item in promoted["performance"]["banks"] if item["active_patterns"] == 1_000)
    taxon = bank["composition"]["taxonomy"][0]
    taxon.update(
        {
            "entities": 3_000,
            "canonical_names": 3_000,
            "aliases": 1_000,
            "literal_patterns": 4_000,
            "regex_patterns": 1_000,
        }
    )
    bank.update(
        {
            "active_entities": 3_000,
            "active_names": 4_000,
            "active_aliases": 1_000,
            "active_patterns": 5_000,
        }
    )
    _refresh_bank_descriptor(bank)
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.missing_scale_shape",
    )


def test_promoted_performance_banks_require_unique_content_hashes(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    scale_banks = [item for item in promoted["performance"]["banks"] if item["kind"] == "synthetic_scale"]
    scale_banks[1]["bank_hash"] = scale_banks[0]["bank_hash"]
    _refresh_bank_descriptor(scale_banks[1])
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.duplicate_performance_bank_hash",
    )


@pytest.mark.parametrize("mutation", ["taxonomy", "aliases", "regex", "name_ratio"])
def test_synthetic_scale_banks_require_realistic_mixed_composition(
    manifest: JsonObject, evidence: JsonObject, mutation: str
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    bank = next(
        item
        for item in promoted["performance"]["banks"]
        if item["kind"] == "synthetic_scale" and item["active_patterns"] == 1_000
    )
    taxonomy = bank["composition"]["taxonomy"]
    if mutation == "taxonomy":
        taxonomy[0]["entity_class"] = "unrelated_scale_taxonomy"
    elif mutation == "aliases":
        taxonomy[0]["canonical_names"] += bank["active_names"]
        bank["active_names"] += bank["active_names"]
    elif mutation == "regex":
        taxonomy[0]["literal_patterns"] += taxonomy[0]["regex_patterns"]
        taxonomy[0]["regex_patterns"] = 0
    else:
        taxonomy[0]["canonical_names"] += bank["active_patterns"] - bank["active_names"]
        bank["active_names"] = bank["active_patterns"]
    _refresh_bank_descriptor(bank)
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.unrealistic_scale_bank",
    )


def test_scale_descriptor_without_a_decision_workload_cannot_promote(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    promoted["performance"]["workloads"] = [
        item for item in promoted["performance"]["workloads"] if item["id"] != "scale_100000_scan"
    ]
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.missing_scale_decision_cell",
    )


def test_every_decision_cell_requires_full_exact_twin_stability_coverage(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    promoted["performance"]["comparisons"] = [
        item
        for item in promoted["performance"]["comparisons"]
        if not (item["candidate_workload_id"] == "scale_1000_scan" and item["metric"] == "p99_seconds")
    ]
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.performance_stability_coverage",
    )


@pytest.mark.parametrize("mutation", ["warmups", "sample_count"])
def test_exact_baseline_comparison_requires_identical_sampling_protocol(
    manifest: JsonObject, evidence: JsonObject, mutation: str
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    candidate = next(item for item in promoted["performance"]["workloads"] if item["id"] == "scale_100000_scan")
    baseline = next(item for item in promoted["performance"]["workloads"] if item["id"] == "baseline_scale_100000_scan")
    if mutation == "warmups":
        baseline["warmups"] = candidate["warmups"] + 1
        baseline["workload_sha256"] = hash_enron_workload(baseline)
    else:
        baseline["samples_seconds"].append(0.0152)
        _refresh_workload(promoted, baseline)
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.incomparable_performance_baseline",
    )


def test_exact_setup_baseline_requires_same_source_artifact(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    performance = promoted["performance"]
    candidate_harness = next(item for item in performance["harnesses"] if item["phase"] == "source_build")
    baseline_harness = copy.deepcopy(candidate_harness)
    baseline_harness.update(
        {
            "id": "baseline_source_build_harness",
            "source_artifact": {
                "id": "different_profiled_source",
                "sha256": _sha256_number(1111),
                "bytes": 8192,
            },
        }
    )
    baseline_harness["descriptor_sha256"] = hash_enron_performance_harness(baseline_harness)
    performance["harnesses"].append(baseline_harness)
    performance["harnesses"].sort(key=lambda item: item["id"])
    baseline = next(item for item in performance["workloads"] if item["id"] == "baseline_source_build_fixture")
    baseline["harness_id"] = baseline_harness["id"]
    baseline["harness_sha256"] = baseline_harness["descriptor_sha256"]
    baseline["workload_sha256"] = hash_enron_workload(baseline)
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.incomparable_performance_baseline",
    )


def test_out_of_tolerance_exact_twin_comparison_cannot_promote(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    candidate = next(item for item in promoted["performance"]["workloads"] if item["id"] == "scale_1000_scan")
    candidate["samples_seconds"] = [0.02 + sample / 1_000_000 for sample in range(1_000)]
    _refresh_workload(promoted, candidate)
    index = promoted["performance"]["workloads"].index(candidate)
    _refresh_check_actuals(promoted, target_prefix=f"/performance/workloads/{index}/")
    for comparison in promoted["performance"]["comparisons"]:
        if comparison["candidate_workload_id"] != candidate["id"]:
            continue
        _refresh_same_path_comparison(promoted, comparison)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.performance_stability_coverage",
    )


def test_promotion_requires_a_finite_additive_breakeven_value_model(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    promoted["performance"]["breakeven_models"] = []
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.missing_breakeven_value_model",
    )


def test_cross_path_proxy_cannot_replace_promoted_direct_breakeven_marginal(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    model = promoted["performance"]["breakeven_models"][0]
    proxy = next(item for item in promoted["performance"]["workloads"] if item["id"] == "direct_bank_cache_value_proxy")
    component = next(item for item in model["components"] if item["id"] == "candidate_per_request_scan")
    component["workload_id"] = proxy["id"]
    component["value"] = proxy["stats"]["median_seconds"]
    _refresh_breakeven_outputs(model)
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.missing_breakeven_value_model",
    )


def test_cross_path_proxy_requires_its_own_within_tolerance_median_control(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    promoted["performance"]["comparisons"] = [
        item
        for item in promoted["performance"]["comparisons"]
        if not (
            item["candidate_workload_id"] == "direct_bank_cache_value_proxy"
            and item["comparison_kind"] == "same_path_stability"
            and item["metric"] == "median_seconds"
        )
    ]
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.missing_breakeven_value_model",
    )


def test_promoted_breakeven_shared_acquisition_costs_cancel(manifest: JsonObject, evidence: JsonObject) -> None:
    _bound_manifest, promoted, _inventories = _promotable(manifest, evidence)
    model = promoted["performance"]["breakeven_models"][0]
    cold_compile = next(item for item in model["components"] if item["id"] == "candidate_fixed_cold_compile")

    assert model["candidate_fixed_value"] - model["baseline_fixed_value"] == pytest.approx(cold_compile["value"])


def test_promoted_breakeven_rejects_fractionalized_whole_input_helper_cost(
    manifest: JsonObject,
    evidence: JsonObject,
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    model = promoted["performance"]["breakeven_models"][0]
    workloads = {item["id"]: item for item in promoted["performance"]["workloads"]}
    model["parameter_name"] = "scanned_documents"
    model["parameter_unit"] = "document"
    for component in model["components"]:
        if component["category"] != "scan":
            continue
        component["source"] = "workload_seconds_per_document"
        component["value"] = workloads[component["workload_id"]]["stats"]["seconds_per_document"]
    _refresh_breakeven_outputs(model)
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.missing_breakeven_value_model",
    )


def test_request_breakeven_component_requires_a_whole_input_workload(
    manifest: JsonObject,
    evidence: JsonObject,
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    model = promoted["performance"]["breakeven_models"][0]
    component = next(item for item in model["components"] if item["id"] == "candidate_per_request_scan")
    latency = next(item for item in promoted["performance"]["workloads"] if item["id"] == "direct_bank_latency")
    component["workload_id"] = latency["id"]
    component["value"] = latency["stats"]["median_seconds"]
    _refresh_breakeven_outputs(model)
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.invalid_breakeven_component",
    )


def test_promoted_value_model_requires_measured_source_profiling(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    model = promoted["performance"]["breakeven_models"][0]
    model["components"] = [item for item in model["components"] if item["id"] != "candidate_fixed_source_profiling"]
    _refresh_breakeven_outputs(model)
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.missing_breakeven_value_model",
    )


def test_synthetic_scale_scan_pair_cannot_stand_in_for_evaluated_bank_value_model(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    model = promoted["performance"]["breakeven_models"][0]
    workloads = {item["id"]: item for item in promoted["performance"]["workloads"]}
    for component_id, workload_id in (
        ("candidate_per_request_scan", "scale_1000_scan"),
        ("baseline_per_request_scan", "baseline_scale_1000_scan"),
    ):
        component = next(item for item in model["components"] if item["id"] == component_id)
        workload = workloads[workload_id]
        component["workload_id"] = workload_id
        component["value"] = workload["stats"]["median_seconds"]
    _refresh_breakeven_outputs(model)
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    result = _validate_promoted(promoted, bound_manifest, inventories)

    assert {"contract.invalid_breakeven_model", "contract.missing_breakeven_value_model"} <= _codes(result)


def test_slow_decision_cell_fails_its_frozen_performance_thresholds(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    index = next(
        index for index, item in enumerate(promoted["performance"]["workloads"]) if item["id"] == "scale_1000_scan"
    )
    workload = promoted["performance"]["workloads"][index]
    workload["samples_seconds"] = [2.0 + sample / 1_000_000 for sample in range(1_000)]
    _refresh_workload(promoted, workload)
    _refresh_check_actuals(promoted, target_prefix=f"/performance/workloads/{index}/")

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.decision_grade_prerequisite",
    )


def test_scale_decision_cell_cannot_disguise_itself_as_the_wrong_phase(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    workload = next(item for item in promoted["performance"]["workloads"] if item["id"] == "scale_100000_scan")
    workload["phase"] = "helper_cache_hit"
    workload["workload_sha256"] = hash_enron_workload(workload)
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.missing_scale_decision_cell",
    )


def test_reused_decision_cell_requires_nonzero_warmups(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    workload = next(item for item in promoted["performance"]["workloads"] if item["id"] == "direct_bank_latency")
    workload["warmups"] = 0
    workload["workload_sha256"] = hash_enron_workload(workload)
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    result = _validate_promoted(promoted, bound_manifest, inventories)

    assert {"contract.performance_warmups", "contract.invalid_decision_grade_workload"} <= _codes(result)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("artifact_kind", "real_benchmark"),
        ("evaluator", {"version": "9.9.9"}),
        ("source", {"revision": "other"}),
        ("preparation", {"output_records": 29}),
        ("splits", {"seed": "other-seed"}),
        ("bank", {"id": "other-bank"}),
        ("software", {"engine_version": "9.9.9"}),
        ("environment", {"cpu_model": "other-cpu"}),
        ("privacy", {"scanner": "other-scanner"}),
    ],
)
def test_bound_evidence_detects_every_provenance_family_drift(
    manifest: JsonObject, evidence: JsonObject, field: str, replacement: JsonObject | str
) -> None:
    if isinstance(replacement, dict):
        evidence[field].update(replacement)
    else:
        evidence[field] = replacement

    _assert_code(validate_enron_evidence(evidence, manifest=manifest), "contract.provenance_mismatch")


def test_bound_evidence_detects_manifest_and_verifier_identity_drift(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    evidence["manifest_sha256"] = "sha256:" + "0" * 64
    _assert_code(validate_enron_evidence(evidence, manifest=manifest), "contract.manifest_hash_mismatch")

    evidence["manifest_sha256"] = hash_enron_manifest(manifest)
    evidence["verifier"]["source_sha256"] = "sha256:" + "0" * 64
    _assert_code(validate_enron_evidence(evidence, manifest=manifest), "contract.provenance_mismatch")


def test_evidence_commands_must_equal_the_frozen_sanitized_manifest_plan(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    evidence["commands"][0]["elapsed_seconds"] += 0.5

    _assert_code(validate_enron_evidence(evidence, manifest=manifest), "contract.provenance_mismatch")


def test_manifest_hash_is_deterministic_and_content_sensitive(manifest: JsonObject) -> None:
    first = hash_enron_manifest(manifest)
    assert hash_enron_manifest(dict(reversed(list(manifest.items())))) == first

    manifest["source"]["revision"] = "changed"
    assert hash_enron_manifest(manifest) != first


@pytest.mark.parametrize(
    "field",
    [
        "bank_hash",
        "evaluator_source_sha256",
        "split_manifest_sha256",
        "test_artifact_sha256",
        "thresholds_sha256",
        "performance_manifest_sha256",
        "git_commit",
    ],
)
def test_final_test_freeze_binds_every_frozen_target(evidence: JsonObject, field: str) -> None:
    evidence["test_access"]["frozen_target"][field] = "f" * 40 if field == "git_commit" else "sha256:" + "0" * 64

    _assert_code(validate_enron_evidence(evidence), "contract.freeze_mismatch")


def test_final_test_cannot_be_an_optimization_role(evidence: JsonObject) -> None:
    evidence["test_access"]["optimization_roles"].append("test")

    _assert_code(validate_enron_evidence(evidence), "contract.test_optimized")


def test_unrecorded_current_test_access_fails_closed(evidence: JsonObject) -> None:
    evidence["test_access"]["lineage"] = []
    evidence["test_access"]["lineage_head_sha256"] = None

    _assert_code(validate_enron_evidence(evidence), "contract.test_access_count")


def test_test_quality_aggregate_cannot_hide_behind_zero_access_and_empty_lineage(evidence: JsonObject) -> None:
    evidence["test_access"]["current_version_access_count"] = 0
    evidence["test_access"]["current_version_accessed_at"] = None
    evidence["test_access"]["lineage"] = []
    evidence["test_access"]["lineage_head_sha256"] = None

    _assert_code(validate_enron_evidence(evidence), "contract.test_aggregate_without_access")


def test_lineage_entry_hash_and_head_are_verified(evidence: JsonObject) -> None:
    evidence["test_access"]["lineage"][0]["aggregate_artifact"]["bytes"] += 1

    _assert_code(validate_enron_evidence(evidence), "contract.lineage_hash_mismatch")

    evidence["test_access"]["lineage"][0]["aggregate_artifact"]["bytes"] -= 1
    evidence["test_access"]["lineage_head_sha256"] = "sha256:" + "0" * 64
    _assert_code(validate_enron_evidence(evidence), "contract.lineage_head_mismatch")


def test_lineage_sequence_and_access_timestamp_are_verified(evidence: JsonObject) -> None:
    entry = evidence["test_access"]["lineage"][0]
    entry["sequence"] = 2
    entry["accessed_at"] = "not-a-timestamp"
    evidence["test_access"]["current_version_accessed_at"] = entry["accessed_at"]
    _rehash_lineage(evidence)

    result = validate_enron_evidence(evidence)

    assert {"contract.lineage_sequence", "contract.invalid_timestamp"} <= _codes(result)


def test_final_test_access_cannot_precede_freeze(evidence: JsonObject) -> None:
    entry = evidence["test_access"]["lineage"][0]
    entry["accessed_at"] = "2026-07-10T00:00:30Z"
    evidence["test_access"]["current_version_accessed_at"] = entry["accessed_at"]
    _rehash_lineage(evidence)

    _assert_code(validate_enron_evidence(evidence), "contract.test_before_freeze")


def test_frozen_target_cannot_predate_manifest(manifest: JsonObject, evidence: JsonObject) -> None:
    evidence["test_access"]["frozen_target"]["frozen_at"] = "2026-07-09T23:59:00Z"
    evidence["test_access"]["lineage"][0]["frozen_target"] = copy.deepcopy(evidence["test_access"]["frozen_target"])
    _rehash_lineage(evidence)

    _assert_code(
        validate_enron_evidence(evidence, manifest=manifest),
        "contract.freeze_timestamp_order",
    )


def test_current_benchmark_version_must_match_manifest(manifest: JsonObject, evidence: JsonObject) -> None:
    evidence["test_access"]["benchmark_version"] = "other-version"

    _assert_code(
        validate_enron_evidence(evidence, manifest=manifest),
        "contract.benchmark_version_mismatch",
    )


def test_first_lineage_entry_cannot_claim_a_predecessor(evidence: JsonObject) -> None:
    entry = evidence["test_access"]["lineage"][0]
    entry["predecessor_benchmark_version"] = "hidden-prior-version"
    entry["changes_informed_by_predecessor"] = ["selection informed by hidden result"]
    entry["previous_entry_sha256"] = "sha256:" + "9" * 64
    _rehash_lineage(evidence)

    _assert_code(validate_enron_evidence(evidence), "contract.lineage_origin")


def test_failed_or_aborted_current_outcome_cannot_promote(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    promoted["test_access"]["lineage"][-1]["outcome"] = "aborted"
    _rehash_lineage(promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.failed_test_promotion",
    )


@pytest.mark.parametrize("outcome", ["failed", "aborted"])
def test_failed_current_outcome_can_publish_full_nonpromoted_aggregate(
    manifest: JsonObject, evidence: JsonObject, outcome: str
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    promoted["promotion"].update({"passed": False, "claims": []})
    promoted["verifier"]["passed"] = False
    promoted["test_access"]["lineage"][-1]["outcome"] = outcome
    _rehash_lineage(promoted)

    assert _validate_promoted(promoted, bound_manifest, inventories) == {
        "valid": True,
        "diagnostics": [],
    }


def test_successor_lineage_accepts_exact_trusted_append(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    trusted_prefix = _with_predecessor(promoted)

    assert _validate_promoted(
        promoted,
        bound_manifest,
        inventories,
        trusted_lineage_prefix=trusted_prefix,
    ) == {"valid": True, "diagnostics": []}


def test_successor_lineage_rejects_reused_final_test_artifact(
    manifest: JsonObject,
    evidence: JsonObject,
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    _with_predecessor(promoted)
    lineage = promoted["test_access"]["lineage"]
    lineage[0]["frozen_target"]["test_artifact_sha256"] = lineage[1]["frozen_target"]["test_artifact_sha256"]
    _normalize_lineage(promoted)

    _assert_code(
        _validate_promoted(
            promoted,
            bound_manifest,
            inventories,
            trusted_lineage_prefix=copy.deepcopy(lineage[:-1]),
        ),
        "contract.test_population_reused",
    )


def test_successor_lineage_rejects_non_append_only_prefix(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    _with_predecessor(promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.lineage_not_append_only",
    )


def test_trusted_lineage_prefix_rejects_scalar_shape_without_type_error(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)

    result = validate_enron_evidence(
        promoted,
        manifest=bound_manifest,
        trusted_lineage_prefix=cast(Any, 42),
        referenced_input_inventories=inventories,
    )

    _assert_code(result, "contract.trusted_lineage_shape")


def test_trusted_lineage_prefix_rejects_container_subclasses_without_invoking_overrides(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    class ExplodingList(list[Any]):
        def __len__(self) -> int:
            raise RuntimeError("unexpected lineage-prefix length access")

    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    result = validate_enron_evidence(
        promoted,
        manifest=bound_manifest,
        trusted_lineage_prefix=cast(Any, ExplodingList()),
        referenced_input_inventories=inventories,
    )

    _assert_code(result, "contract.trusted_lineage_shape")


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        ("hash", "contract.lineage_predecessor_hash"),
        ("version", "contract.lineage_predecessor_version"),
        ("disclosure", "contract.lineage_missing_disclosure"),
        ("timestamp", "contract.lineage_timestamp_order"),
    ],
)
def test_successor_lineage_links_and_discloses_prior_outcome(
    manifest: JsonObject, evidence: JsonObject, mutation: str, code: str
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    trusted_prefix = _with_predecessor(promoted)
    current = promoted["test_access"]["lineage"][-1]
    if mutation == "hash":
        current["previous_entry_sha256"] = "sha256:" + "0" * 64
    elif mutation == "version":
        current["predecessor_benchmark_version"] = "other-version"
    elif mutation == "disclosure":
        current["changes_informed_by_predecessor"] = []
    else:
        current["accessed_at"] = trusted_prefix[-1]["accessed_at"]
        promoted["test_access"]["current_version_accessed_at"] = current["accessed_at"]
    _rehash_lineage(promoted)

    _assert_code(
        _validate_promoted(
            promoted,
            bound_manifest,
            inventories,
            trusted_lineage_prefix=trusted_prefix,
        ),
        code,
    )


def test_repeated_benchmark_version_in_lineage_is_rejected(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    trusted_prefix = _with_predecessor(promoted)
    promoted["test_access"]["lineage"][0]["benchmark_version"] = promoted["test_access"]["benchmark_version"]
    promoted["test_access"]["lineage"][1]["predecessor_benchmark_version"] = promoted["test_access"][
        "benchmark_version"
    ]
    promoted["test_access"]["lineage"][1]["previous_entry_sha256"] = hash_enron_test_lineage_entry(
        promoted["test_access"]["lineage"][0]
    )
    _rehash_lineage(promoted)
    trusted_prefix = copy.deepcopy(promoted["test_access"]["lineage"][:-1])

    _assert_code(
        _validate_promoted(
            promoted,
            bound_manifest,
            inventories,
            trusted_lineage_prefix=trusted_prefix,
        ),
        "contract.test_reused",
    )


def test_workload_descriptor_and_performance_manifest_hashes_are_bound(evidence: JsonObject) -> None:
    evidence["performance"]["workloads"][0]["warmups"] += 1
    _assert_code(validate_enron_evidence(evidence), "contract.workload_hash_mismatch")

    evidence["performance"]["workloads"][0]["workload_sha256"] = hash_enron_workload(
        evidence["performance"]["workloads"][0]
    )
    _assert_code(validate_enron_evidence(evidence), "contract.performance_manifest_hash")


def test_harness_descriptor_and_performance_manifest_hashes_are_bound(evidence: JsonObject) -> None:
    harness = evidence["performance"]["harnesses"][0]
    harness["source_sha256"] = _sha256_number(1100)
    _assert_code(validate_enron_evidence(evidence), "contract.performance_harness_hash")

    _refresh_harness_dependents(evidence, harness)
    _assert_code(validate_enron_evidence(evidence), "contract.performance_manifest_hash")


@pytest.mark.parametrize("mutation", ["identifier", "hash", "phase"])
def test_workload_must_bind_exact_phase_harness(evidence: JsonObject, mutation: str) -> None:
    workload = evidence["performance"]["workloads"][0]
    if mutation == "identifier":
        workload["harness_id"] = "missing_harness"
    elif mutation == "hash":
        workload["harness_sha256"] = _sha256_number(1101)
    else:
        workload["phase"] = "helper_cache_hit"
    workload["workload_sha256"] = hash_enron_workload(workload)
    _refresh_frozen_contract(evidence)

    _assert_code(validate_enron_evidence(evidence), "contract.unknown_performance_harness")


def test_performance_harness_command_must_be_declared(evidence: JsonObject) -> None:
    harness = evidence["performance"]["harnesses"][0]
    harness["command_id"] = "missing_command"
    _refresh_harness_dependents(evidence, harness)
    _refresh_frozen_contract(evidence)

    _assert_code(validate_enron_evidence(evidence), "contract.performance_harness_command")


@pytest.mark.parametrize("phase", ["source_profile", "source_build", "direct_bank_scan"])
def test_harness_source_artifact_presence_is_phase_bound(
    manifest: JsonObject, evidence: JsonObject, phase: str
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    harness = next(item for item in promoted["performance"]["harnesses"] if item["phase"] == phase)
    harness["source_artifact"] = (
        {"id": "unexpected_source", "sha256": _sha256_number(1102), "bytes": 64}
        if phase == "direct_bank_scan"
        else None
    )
    _refresh_harness_dependents(promoted, harness)
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.performance_harness_source_artifact",
    )


@pytest.mark.parametrize("phase", ["source_profile", "source_build"])
def test_setup_harness_source_artifact_must_match_its_frozen_role(
    manifest: JsonObject, evidence: JsonObject, phase: str
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    harness = next(item for item in promoted["performance"]["harnesses"] if item["phase"] == phase)
    harness["source_artifact"]["sha256"] = _sha256_number(1105)
    _refresh_harness_dependents(promoted, harness)
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.performance_harness_source_binding",
    )


def test_performance_harness_ids_are_unique(evidence: JsonObject) -> None:
    evidence["performance"]["harnesses"].append(copy.deepcopy(evidence["performance"]["harnesses"][0]))

    _assert_code(validate_enron_evidence(evidence), "contract.duplicate_id")


def test_performance_harnesses_require_canonical_order(manifest: JsonObject, evidence: JsonObject) -> None:
    _, promoted, _ = _promotable(manifest, evidence)
    promoted["performance"]["harnesses"].reverse()

    _assert_code(validate_enron_evidence(promoted), "contract.performance_descriptor_order")


def test_unused_performance_harness_cannot_be_frozen(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    harness = copy.deepcopy(promoted["performance"]["harnesses"][0])
    harness.update(
        {
            "id": "unused_direct_harness",
            "source_sha256": _sha256_number(1103),
            "operation_spec_sha256": _sha256_number(1104),
        }
    )
    harness["descriptor_sha256"] = hash_enron_performance_harness(harness)
    promoted["performance"]["harnesses"].append(harness)
    promoted["performance"]["harnesses"].sort(key=lambda item: item["id"])
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.unused_performance_harness",
    )


@pytest.mark.parametrize(
    ("collection", "field"),
    [
        ("banks", "composition"),
        ("banks", "active_aliases"),
        ("inputs", "inventory_ref"),
        ("harnesses", "command_id"),
        ("harnesses", "operation_spec_sha256"),
        ("workloads", "harness_id"),
        ("workloads", "harness_sha256"),
        ("workloads", "sample_unit"),
        ("workloads", "rss_samples_bytes"),
    ],
)
def test_performance_descriptor_schema_requires_issue_152_identity_and_work_fields(
    evidence: JsonObject, collection: str, field: str
) -> None:
    del evidence["performance"][collection][0][field]

    _assert_code(validate_enron_evidence(evidence), "contract.schema.required")


@pytest.mark.parametrize("collection", ["baselines", "comparisons", "breakeven_models"])
def test_performance_result_schema_requires_complete_baseline_and_breakeven_shapes(
    evidence: JsonObject, collection: str
) -> None:
    evidence["performance"][collection].append({})

    expected_code = "contract.schema.oneOf" if collection == "comparisons" else "contract.schema.required"
    _assert_code(validate_enron_evidence(evidence), expected_code)


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        ("bank_hash", "contract.performance_bank_descriptor_hash"),
        ("bank_composition", "contract.performance_bank_composition"),
        ("input_hash", "contract.performance_input_descriptor_hash"),
        ("input_distribution", "contract.performance_input_distribution"),
        ("input_size", "contract.performance_size_cohort"),
    ],
)
def test_performance_bank_and_input_descriptors_are_recomputed(evidence: JsonObject, mutation: str, code: str) -> None:
    bank = evidence["performance"]["banks"][0]
    input_descriptor = evidence["performance"]["inputs"][0]
    if mutation == "bank_hash":
        bank["active_patterns"] += 1
    elif mutation == "bank_composition":
        bank["composition"]["taxonomy"][0]["literal_patterns"] += 1
        _refresh_bank_descriptor(bank)
    elif mutation == "input_hash":
        input_descriptor["records"] += 1
    elif mutation == "input_distribution":
        input_descriptor["hit_distribution"]["mean_records"] += 1
        _refresh_input_descriptor(input_descriptor)
    else:
        input_descriptor["size_cohort"] = "small"
        _refresh_input_descriptor(input_descriptor)

    _assert_code(validate_enron_evidence(evidence), code)


def test_bank_provenance_distinguishes_physical_artifact_bytes_from_canonical_bytes(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    assert manifest["bank"]["artifact_bytes"] == evidence["bank"]["artifact_bytes"] == 3072
    assert evidence["bank"]["canonical_json_bytes"] == 2048
    assert evidence["performance"]["banks"][0]["artifact"]["bytes"] == 3072
    assert validate_enron_manifest(manifest) == {"valid": True, "diagnostics": []}
    assert validate_enron_evidence(evidence) == {"valid": True, "diagnostics": []}


def test_evaluated_performance_bank_binds_physical_artifact_size(evidence: JsonObject) -> None:
    descriptor = evidence["performance"]["banks"][0]
    descriptor["artifact"]["bytes"] = evidence["bank"]["canonical_json_bytes"]
    _refresh_bank_descriptor(descriptor)
    _refresh_frozen_contract(evidence)

    _assert_code(validate_enron_evidence(evidence), "contract.performance_bank_mismatch")


def test_bank_provenance_requires_physical_artifact_size(evidence: JsonObject) -> None:
    del evidence["bank"]["artifact_bytes"]

    _assert_code(validate_enron_evidence(evidence), "contract.schema.required")


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        ("comparison_plan", "contract.performance_comparison_hash"),
        ("comparison_output", "contract.performance_comparison_arithmetic"),
        ("component_output", "contract.breakeven_component_arithmetic"),
        ("model_output", "contract.performance_breakeven_arithmetic"),
    ],
)
def test_baseline_comparison_and_breakeven_plans_are_frozen_but_outputs_are_recomputed(
    manifest: JsonObject, evidence: JsonObject, mutation: str, code: str
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    comparison = promoted["performance"]["comparisons"][0]
    model = promoted["performance"]["breakeven_models"][0]
    if mutation == "comparison_plan":
        comparison["samples_per_block"] += 1
    elif mutation == "comparison_output":
        comparison["candidate_value"] += 1
    elif mutation == "component_output":
        model["components"][0]["value"] += 1
    else:
        model["candidate_fixed_value"] += 1

    _assert_code(_validate_promoted(promoted, bound_manifest, inventories), code)


@pytest.mark.parametrize(
    ("field", "value"),
    [("noise_multiplier", 6.0), ("regression_tolerance", 0.11)],
)
def test_comparison_noise_policy_has_bounded_schema_parameters(
    manifest: JsonObject, evidence: JsonObject, field: str, value: float
) -> None:
    _, promoted, _ = _promotable(manifest, evidence)
    comparison = next(
        item for item in promoted["performance"]["comparisons"] if item["comparison_kind"] == "cross_path_value"
    )
    comparison[field] = value

    _assert_code(validate_enron_evidence(promoted), "contract.schema.oneOf")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("block_count", 9),
        ("block_assignment", ["candidate_first"] * 10),
        ("significance_level", 0.04),
        ("stability_tolerance", 0.04),
    ],
)
def test_exact_block_swap_policy_is_frozen_by_schema(
    manifest: JsonObject, evidence: JsonObject, field: str, value: Any
) -> None:
    _, promoted, _ = _promotable(manifest, evidence)
    comparison = next(
        item for item in promoted["performance"]["comparisons"] if item["comparison_kind"] == "same_path_stability"
    )
    comparison[field] = value

    _assert_code(validate_enron_evidence(promoted), "contract.schema.oneOf")


def test_incomplete_exact_block_swap_samples_cannot_validate(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    candidate = next(item for item in promoted["performance"]["workloads"] if item["id"] == "scale_1000_scan")
    candidate["samples_seconds"] = candidate["samples_seconds"][:-1]
    _refresh_workload(promoted, candidate)
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.incomparable_performance_baseline",
    )


def test_breakeven_components_require_public_descriptions(manifest: JsonObject, evidence: JsonObject) -> None:
    _, promoted, _ = _promotable(manifest, evidence)
    del promoted["performance"]["breakeven_models"][0]["components"][0]["description"]

    _assert_code(validate_enron_evidence(promoted), "contract.schema.required")


def test_exact_baseline_identity_requires_full_nerb_capabilities(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    baseline = promoted["performance"]["baselines"][0]
    baseline["capabilities"]["canonical_mapping"] = False
    baseline["descriptor_sha256"] = hash_enron_performance_baseline(baseline)
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.performance_baseline_capability",
    )


def test_breakeven_component_category_must_match_its_workload_phase(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    model = promoted["performance"]["breakeven_models"][0]
    component = next(item for item in model["components"] if item["id"] == "candidate_fixed_build")
    component["category"] = "cold_compile"
    model["model_plan_sha256"] = hash_enron_breakeven_plan(model)
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.invalid_breakeven_component",
    )


def test_breakeven_alternative_must_use_the_exact_same_frozen_input(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    model = promoted["performance"]["breakeven_models"][0]
    baseline_component = next(item for item in model["components"] if item["id"] == "baseline_per_request_scan")
    baseline_workload = next(
        item for item in promoted["performance"]["workloads"] if item["id"] == baseline_component["workload_id"]
    )
    other_input = next(item for item in promoted["performance"]["inputs"] if item["id"] == "scale_1000_input")
    baseline_workload["input_id"] = other_input["id"]
    baseline_workload["input_sha256"] = other_input["descriptor_sha256"]
    baseline_workload["workload_sha256"] = hash_enron_workload(baseline_workload)
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.missing_breakeven_value_model",
    )


def test_direct_same_path_control_cannot_replace_uncached_breakeven_alternative(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    model = promoted["performance"]["breakeven_models"][0]
    component = next(item for item in model["components"] if item["id"] == "baseline_per_request_scan")
    direct_control = next(
        item for item in promoted["performance"]["workloads"] if item["id"] == "baseline_direct_bank_latency"
    )
    component["workload_id"] = direct_control["id"]
    component["value"] = direct_control["stats"]["median_seconds"]
    _refresh_breakeven_outputs(model)
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    result = _validate_promoted(promoted, bound_manifest, inventories)
    assert {"contract.invalid_breakeven_component", "contract.missing_breakeven_value_model"} <= _codes(result)


def test_non_equivalent_baseline_cannot_satisfy_uncached_breakeven_alternative(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    baseline = promoted["performance"]["baselines"][0]
    baseline["semantic_equivalence"] = "subset"
    baseline["descriptor_sha256"] = hash_enron_performance_baseline(baseline)
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    result = _validate_promoted(promoted, bound_manifest, inventories)
    assert {"contract.incomparable_performance_baseline", "contract.missing_breakeven_value_model"} <= _codes(result)


def test_breakeven_paths_retain_independent_same_path_controls(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    model = promoted["performance"]["breakeven_models"][0]
    component = next(item for item in model["components"] if item["id"] == "baseline_per_request_scan")
    promoted["performance"]["comparisons"] = [
        item
        for item in promoted["performance"]["comparisons"]
        if not (
            item["candidate_workload_id"] == component["workload_id"]
            and item["comparison_kind"] == "same_path_stability"
            and item["metric"] == "median_seconds"
        )
    ]
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    result = _validate_promoted(promoted, bound_manifest, inventories)
    assert {"contract.performance_stability_coverage", "contract.missing_breakeven_value_model"} <= _codes(result)


def test_zero_vacuous_breakeven_assumptions_cannot_satisfy_promotion(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    model = promoted["performance"]["breakeven_models"][0]
    for component in model["components"]:
        if component["category"] == "source_curation":
            component["value"] = 0.0
    _refresh_breakeven_outputs(model)
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.missing_breakeven_value_model",
    )


def test_promoted_breakeven_rejects_extra_asymmetric_cost_components(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    model = promoted["performance"]["breakeven_models"][0]
    model["components"].append(
        {
            "id": "baseline_per_document_external_call",
            "side": "baseline",
            "application": "per_unit",
            "category": "external_call",
            "source": "declared_assumption",
            "description": "Adversarial external-call assumption.",
            "workload_id": None,
            "assumption_sha256": _sha256_number(975),
            "value": 0.5,
        }
    )
    model["components"].sort(key=lambda item: item["id"])
    _refresh_breakeven_outputs(model)
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.missing_breakeven_value_model",
    )


@pytest.mark.parametrize("mismatch", ["declared_value", "measured_workload"])
def test_promoted_breakeven_requires_identical_shared_acquisition_components(
    mismatch: str,
    manifest: JsonObject,
    evidence: JsonObject,
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    model = promoted["performance"]["breakeven_models"][0]
    if mismatch == "declared_value":
        component = next(item for item in model["components"] if item["id"] == "baseline_fixed_source_curation")
        component["value"] += 0.001
    else:
        component = next(item for item in model["components"] if item["id"] == "baseline_fixed_source_profiling")
        component["workload_id"] = "baseline_source_profile_fixture"
    _refresh_breakeven_outputs(model)
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.missing_breakeven_value_model",
    )


def test_breakeven_component_totals_reject_numeric_overflow(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    model = promoted["performance"]["breakeven_models"][0]
    for index in range(2):
        model["components"].append(
            {
                "id": f"candidate_fixed_overflow_{index}",
                "side": "candidate",
                "application": "fixed",
                "category": "labor",
                "source": "declared_assumption",
                "description": "Overflow-boundary labor assumption.",
                "workload_id": None,
                "assumption_sha256": _sha256_number(985 + index),
                "value": 1e300,
            }
        )
    model["components"].sort(key=lambda item: item["id"])
    model["model_plan_sha256"] = hash_enron_breakeven_plan(model)
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.breakeven_numeric_bounds",
    )


def test_throughput_denominators_cannot_be_inflated_without_matching_inventory(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    input_descriptor = next(item for item in promoted["performance"]["inputs"] if item["id"] == "real_scan_input")
    multiplier = 1_000_000
    input_descriptor["bytes"] *= multiplier
    input_descriptor["artifact"]["bytes"] *= multiplier
    lengths = input_descriptor["document_length_distribution"]
    for field in ("minimum_bytes", "p50_bytes", "p95_bytes", "p99_bytes", "maximum_bytes", "mean_bytes"):
        lengths[field] *= multiplier
    input_descriptor["size_cohort"] = "huge"
    _refresh_input_descriptor(input_descriptor)
    for workload in promoted["performance"]["workloads"]:
        if workload["input_id"] != input_descriptor["id"]:
            continue
        _refresh_workload(promoted, workload)
    for index, workload in enumerate(promoted["performance"]["workloads"]):
        if workload["input_id"] == input_descriptor["id"] and workload["decision_grade"]:
            _refresh_check_actuals(promoted, target_prefix=f"/performance/workloads/{index}/")
    throughput_claim = next(
        item for item in promoted["promotion"]["claims"] if item["metric"] == "direct_bank_scan_mib_per_second"
    )
    throughput_workload = next(
        item
        for item in promoted["performance"]["workloads"]
        if item["id"] == throughput_claim["performance_workload_id"]
    )
    throughput_claim["value"] = throughput_workload["stats"]["mib_per_second"]
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.performance_inventory_arithmetic",
    )


@pytest.mark.parametrize("commitment", ["artifact", "inventory"])
def test_post_freeze_input_commitment_changes_break_manifest_and_frozen_binding(
    manifest: JsonObject, evidence: JsonObject, commitment: str
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    input_descriptor = next(item for item in promoted["performance"]["inputs"] if item["id"] == "real_scan_input")
    target = input_descriptor["artifact" if commitment == "artifact" else "inventory_ref"]
    target["sha256"] = _sha256_number(993 if commitment == "artifact" else 992)
    _refresh_input_descriptor(input_descriptor)
    for workload in promoted["performance"]["workloads"]:
        if workload["input_id"] == input_descriptor["id"]:
            workload["input_sha256"] = input_descriptor["descriptor_sha256"]
            workload["workload_sha256"] = hash_enron_workload(workload)
    promoted["performance_manifest_sha256"] = hash_enron_performance_manifest(promoted["performance"])

    result = _validate_promoted(promoted, bound_manifest, inventories)

    assert {"contract.freeze_mismatch", "contract.provenance_mismatch"} <= _codes(result)


def test_referenced_input_inventory_hash_mismatch_is_rejected(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    changed = copy.deepcopy(inventories)
    inventory_id = next(iter(changed))
    changed[inventory_id][0]["records"] += 1

    _assert_code(
        _validate_promoted(promoted, bound_manifest, changed),
        "contract.performance_inventory_hash",
    )


@pytest.mark.parametrize("payload", [None, 42, {}, [{"bytes": 1}]])
def test_malformed_inventory_resolver_entries_fail_closed_for_promotion(
    manifest: JsonObject, evidence: JsonObject, payload: Any
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    changed = cast(dict[str, Any], copy.deepcopy(inventories))
    inventory_id = next(iter(changed))
    changed[inventory_id] = payload

    result = _validate_promoted(promoted, bound_manifest, cast(Any, changed))

    assert {"contract.performance_inventory_shape", "contract.performance_inventory_unavailable"} <= _codes(result)


def test_document_sample_unit_cannot_report_aggregate_throughput(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    workload = next(item for item in promoted["performance"]["workloads"] if item["id"] == "direct_bank_latency")
    assert workload["stats"]["mib_per_second"] is None
    workload["stats"]["mib_per_second"] = 1_000_000.0

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.performance_arithmetic",
    )


def test_non_scan_phase_cannot_use_ambiguous_document_sample_units(evidence: JsonObject) -> None:
    workload = evidence["performance"]["workloads"][0]
    workload["phase"] = "source_build"
    workload["sample_unit"] = "document"
    workload["process_model"] = "fresh_process_per_sample"
    _refresh_workload(evidence, workload)
    _refresh_frozen_contract(evidence)

    _assert_code(validate_enron_evidence(evidence), "contract.performance_phase_sample_unit")


@pytest.mark.parametrize("workload_id", ["source_profile_fixture", "source_build_fixture", "cold_compile_fixture"])
def test_setup_operation_cells_cannot_borrow_scan_denominators(
    manifest: JsonObject, evidence: JsonObject, workload_id: str
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    workload = next(item for item in promoted["performance"]["workloads"] if item["id"] == workload_id)
    assert workload["sample_unit"] == "operation"
    assert workload["input_id"] is workload["input_sha256"] is None
    assert all(
        workload["stats"][field] is None
        for field in ("documents_per_second", "mib_per_second", "records_per_second", "seconds_per_document")
    )
    input_descriptor = next(item for item in promoted["performance"]["inputs"] if item["id"] == "real_scan_input")
    workload["input_id"] = input_descriptor["id"]
    workload["input_sha256"] = input_descriptor["descriptor_sha256"]
    workload["workload_sha256"] = hash_enron_workload(workload)
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.setup_phase_input",
    )


@pytest.mark.parametrize(
    "field",
    [
        "sample_count",
        "median_seconds",
        "p95_seconds",
        "p99_seconds",
        "mad_seconds",
        "documents_per_second",
        "mib_per_second",
        "records_per_second",
        "seconds_per_document",
    ],
)
def test_every_performance_statistic_is_recomputed_with_tail_samples(
    manifest: JsonObject, evidence: JsonObject, field: str
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    stats = promoted["performance"]["workloads"][0]["stats"]
    stats[field] = stats[field] + 1 if stats[field] is not None else 1.0

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.performance_arithmetic",
    )


@pytest.mark.parametrize(
    ("sample_count", "has_p95", "has_p99"),
    [(5, False, False), (19, False, False), (20, True, False), (99, True, False), (100, True, True)],
)
def test_p95_and_p99_require_meaningful_sample_support(
    evidence: JsonObject, sample_count: int, has_p95: bool, has_p99: bool
) -> None:
    value = copy.deepcopy(evidence)
    workload = value["performance"]["workloads"][0]
    workload["samples_seconds"] = [0.01 + index / 1_000_000 for index in range(sample_count)]
    _refresh_workload(value, workload)
    _drop_performance_assertions(value)

    assert (workload["stats"]["p95_seconds"] is not None) is has_p95
    assert (workload["stats"]["p99_seconds"] is not None) is has_p99
    assert validate_enron_evidence(value) == {"valid": True, "diagnostics": []}


def test_public_performance_arithmetic_helpers_share_verifier_semantics(evidence: JsonObject) -> None:
    input_descriptor = evidence["performance"]["inputs"][0]
    inventory = [{"bytes": 1024, "records": 0}, {"bytes": 2048, "records": 1}]
    assert summarize_enron_performance_inventory(inventory)["documents"] == 2

    setup = calculate_enron_performance_statistics(
        [0.01 + index / 1_000_000 for index in range(100)],
        None,
        phase="source_build",
        sample_unit="operation",
        work_per_sample=1,
    )
    candidate = calculate_enron_performance_statistics(
        [0.01] * 100,
        input_descriptor,
        phase="direct_bank_scan",
        sample_unit="whole_input",
        work_per_sample=1,
    )
    baseline = calculate_enron_performance_statistics(
        [0.02] * 100,
        input_descriptor,
        phase="direct_bank_scan",
        sample_unit="whole_input",
        work_per_sample=1,
    )
    assert setup["p95_seconds"] is not None and setup["p99_seconds"] is None
    comparison = calculate_enron_performance_comparison(
        candidate,
        baseline,
        metric="p99_seconds",
        noise_method="paired_block_ratio_mad",
        candidate_samples=[0.01] * 100,
        baseline_samples=[0.02] * 100,
        noise_multiplier=2.0,
        regression_tolerance=0.05,
    )
    assert comparison["direction"] == "lower_is_better"
    assert comparison["result"] == "improved"
    assert calculate_enron_breakeven(
        10.0,
        0.0,
        0.001,
        0.002,
        minimum_units=1,
        maximum_units=20_000,
    ) == {"result": "finite_breakeven", "breakeven_units": 10_000}


def _exact_block_swap_comparison(
    evidence: JsonObject,
    candidate_samples: Sequence[float],
    baseline_samples: Sequence[float],
) -> JsonObject:
    input_descriptor = evidence["performance"]["inputs"][0]
    candidate = calculate_enron_performance_statistics(
        candidate_samples,
        input_descriptor,
        phase="direct_bank_scan",
        sample_unit="whole_input",
        work_per_sample=1,
    )
    baseline = calculate_enron_performance_statistics(
        baseline_samples,
        input_descriptor,
        phase="direct_bank_scan",
        sample_unit="whole_input",
        work_per_sample=1,
    )
    return calculate_enron_performance_comparison(
        candidate,
        baseline,
        metric="p99_seconds",
        noise_method="exact_block_swap",
        candidate_samples=candidate_samples,
        baseline_samples=baseline_samples,
        block_count=10,
        samples_per_block=len(candidate_samples) // 10,
        block_assignment=["candidate_first", "control_first"] * 5,
        significance_level=0.05,
        stability_tolerance=0.05,
    )


def test_exact_block_swap_is_label_invariant_and_marks_one_block_tail_inconclusive(evidence: JsonObject) -> None:
    candidate_samples = [*([0.012] * 11), *([0.01] * 989)]
    baseline_samples = [0.01] * 1_000

    forward = _exact_block_swap_comparison(evidence, candidate_samples, baseline_samples)
    reversed_labels = _exact_block_swap_comparison(evidence, baseline_samples, candidate_samples)

    assert forward["candidate_value"] == reversed_labels["baseline_value"]
    assert forward["baseline_value"] == reversed_labels["candidate_value"]
    for field in (
        "direction",
        "block_count",
        "samples_per_block",
        "block_assignment",
        "absolute_log_ratio",
        "absolute_relative_gap",
        "permutation_p_value",
        "result",
    ):
        assert forward[field] == reversed_labels[field]
    assert forward["permutation_p_value"] == 1.0
    assert forward["result"] == "inconclusive"


def test_exact_block_swap_p99_is_robust_to_a_few_isolated_tail_points(evidence: JsonObject) -> None:
    candidate_samples = [0.02, 0.02, 0.02, *([0.01] * 997)]

    comparison = _exact_block_swap_comparison(evidence, candidate_samples, [0.01] * 1_000)

    assert comparison["candidate_value"] == comparison["baseline_value"] == 0.01
    assert comparison["absolute_relative_gap"] == 0.0
    assert comparison["result"] == "within_tolerance"


@pytest.mark.parametrize(
    ("candidate_seconds", "expected_result"),
    [
        (0.01049, "within_tolerance"),
        (0.0105, "within_tolerance"),
        (math.nextafter(0.0105, math.inf), "unstable"),
    ],
)
def test_exact_block_swap_uses_a_boundary_safe_frozen_tolerance(
    evidence: JsonObject, candidate_seconds: float, expected_result: str
) -> None:
    comparison = _exact_block_swap_comparison(evidence, [candidate_seconds] * 1_000, [0.01] * 1_000)

    assert comparison["permutation_p_value"] == 2 / 1024
    assert comparison["result"] == expected_result


def test_exact_block_swap_plan_hash_binds_every_stability_policy_field() -> None:
    comparison: JsonObject = {
        "id": "same_path_fixture",
        "candidate_workload_id": "candidate",
        "baseline_workload_id": "control",
        "comparison_kind": "same_path_stability",
        "metric": "p99_seconds",
        "direction": "symmetric",
        "noise_method": "exact_block_swap",
        "block_count": 10,
        "samples_per_block": 10,
        "block_assignment": ["candidate_first", "control_first"] * 5,
        "significance_level": 0.05,
        "stability_tolerance": 0.05,
    }
    original = hash_enron_performance_comparison_plan(comparison)

    for field, value in (
        ("direction", "lower_is_better"),
        ("noise_method", "different"),
        ("block_count", 9),
        ("samples_per_block", 11),
        ("block_assignment", ["candidate_first"] * 10),
        ("significance_level", 0.04),
        ("stability_tolerance", 0.04),
    ):
        mutated = {**comparison, field: value}
        assert hash_enron_performance_comparison_plan(mutated) != original


def test_paired_block_ratio_mad_removes_common_drift_for_latency_and_throughput(evidence: JsonObject) -> None:
    input_descriptor = evidence["performance"]["inputs"][0]
    candidate_samples = [0.01, 0.02, 0.03, 0.04, 0.05]
    baseline_samples = [0.02, 0.04, 0.06, 0.08, 0.10]
    candidate = calculate_enron_performance_statistics(
        candidate_samples,
        input_descriptor,
        phase="direct_bank_scan",
        sample_unit="whole_input",
        work_per_sample=1,
    )
    baseline = calculate_enron_performance_statistics(
        baseline_samples,
        input_descriptor,
        phase="helper_cache_miss",
        sample_unit="whole_input",
        work_per_sample=1,
    )

    for metric in ("median_seconds", "mib_per_second"):
        comparison = calculate_enron_performance_comparison(
            candidate,
            baseline,
            metric=metric,
            noise_multiplier=2.0,
            regression_tolerance=0.05,
            noise_method="paired_block_ratio_mad",
            candidate_samples=candidate_samples,
            baseline_samples=baseline_samples,
        )
        assert comparison["noise_floor"] == 0.0
        assert comparison["result"] == "improved"


def _set_promoted_proxy_cross_path_ratios(evidence: JsonObject, ratios: Sequence[float]) -> JsonObject:
    workloads = {item["id"]: item for item in evidence["performance"]["workloads"]}
    comparison = next(
        item for item in evidence["performance"]["comparisons"] if item["comparison_kind"] == "cross_path_value"
    )
    proxy = workloads[comparison["candidate_workload_id"]]
    baseline = workloads[comparison["baseline_workload_id"]]
    assert len(ratios) == len(proxy["samples_seconds"]) == len(baseline["samples_seconds"])
    proxy["samples_seconds"] = [
        baseline_sample * ratio for baseline_sample, ratio in zip(baseline["samples_seconds"], ratios, strict=True)
    ]
    _refresh_workload(evidence, proxy)

    same_path = next(
        item
        for item in evidence["performance"]["comparisons"]
        if item["candidate_workload_id"] == proxy["id"] and item["comparison_kind"] == "same_path_stability"
    )
    exact_twin = workloads[same_path["baseline_workload_id"]]
    exact_twin["samples_seconds"] = [sample * 1.01 for sample in proxy["samples_seconds"]]
    _refresh_workload(evidence, exact_twin)
    _refresh_same_path_comparison(evidence, same_path)
    _refresh_cross_path_comparison(evidence, comparison)
    return comparison


def test_cross_path_noise_floor_accepts_the_exact_directional_ceiling(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    comparison = _set_promoted_proxy_cross_path_ratios(promoted, [7 / 16] * 50 + [9 / 16] * 50)
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    assert comparison["noise_floor"] == 0.25
    assert comparison["result"] == "improved"
    assert _validate_promoted(promoted, bound_manifest, inventories) == {"valid": True, "diagnostics": []}


def test_cross_path_noise_floor_rejects_the_next_float_even_when_direction_improves(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    next_upper_ratio = math.nextafter(9 / 16, math.inf)
    comparison = _set_promoted_proxy_cross_path_ratios(promoted, [7 / 16] * 50 + [next_upper_ratio] * 50)
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    assert comparison["noise_floor"] == math.nextafter(0.25, math.inf)
    assert comparison["result"] == "improved"
    comparison_path = f"/performance/comparisons/{promoted['performance']['comparisons'].index(comparison)}"
    result = _validate_promoted(promoted, bound_manifest, inventories)
    assert [(item["code"], item["path"]) for item in result["diagnostics"]] == [
        ("contract.unstable_performance_comparison", comparison_path),
        ("contract.forged_promotion", "/promotion/passed"),
        ("contract.forged_verifier", "/verifier/passed"),
    ]


def test_regressed_directional_cross_path_result_prevents_promotion(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    comparison = _set_promoted_proxy_cross_path_ratios(promoted, [2.0] * 100)
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    assert comparison["noise_floor"] == 0.0
    assert comparison["result"] == "regressed"
    result = _validate_promoted(promoted, bound_manifest, inventories)
    assert [(item["code"], item["path"]) for item in result["diagnostics"]] == [
        ("contract.missing_breakeven_value_model", "/performance/breakeven_models"),
        ("contract.forged_promotion", "/promotion/passed"),
        ("contract.forged_verifier", "/verifier/passed"),
    ]


def test_public_performance_arithmetic_helpers_reject_invalid_inputs(evidence: JsonObject) -> None:
    with pytest.raises(ValueError, match="at least five"):
        calculate_enron_performance_statistics(
            [0.01, float("nan"), 0.02, 0.03, 0.04],
            evidence["performance"]["inputs"][0],
            phase="direct_bank_scan",
            sample_unit="whole_input",
            work_per_sample=1,
        )
    with pytest.raises(ValueError, match="Unsupported"):
        calculate_enron_performance_comparison(
            evidence["performance"]["workloads"][0]["stats"],
            evidence["performance"]["workloads"][0]["stats"],
            metric="sample_count",
            noise_method="paired_block_ratio_mad",
            noise_multiplier=2.0,
            regression_tolerance=0.05,
        )
    with pytest.raises(ValueError, match="finite"):
        calculate_enron_breakeven(
            True,
            0.0,
            0.001,
            0.002,
            minimum_units=1,
            maximum_units=20_000,
        )
    with pytest.raises(ValueError, match="finite"):
        calculate_enron_breakeven(
            10**300,
            0,
            10**300,
            10**300,
            minimum_units=2**63 - 1,
            maximum_units=2**63 - 1,
        )
    with pytest.raises(ValueError, match="ordered"):
        calculate_enron_breakeven(
            1.0,
            0.0,
            0.001,
            0.002,
            minimum_units=1,
            maximum_units=2**63,
        )


def test_decision_grade_direct_performance_requires_one_thousand_samples(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    workload = next(item for item in promoted["performance"]["workloads"] if item["id"] == "direct_bank_latency")
    workload["samples_seconds"] = workload["samples_seconds"][:999]
    _refresh_workload(promoted, workload)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.invalid_decision_grade_workload",
    )


def test_promotable_performance_separates_direct_p99_evidence_from_cross_path_proxy(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    _bound_manifest, promoted, _inventories = _promotable(manifest, evidence)
    workloads = {item["id"]: item for item in promoted["performance"]["workloads"]}
    comparisons = promoted["performance"]["comparisons"]
    throughput = workloads["direct_bank_throughput"]
    proxy = workloads["direct_bank_cache_value_proxy"]
    model = promoted["performance"]["breakeven_models"][0]
    candidate_marginal = next(item for item in model["components"] if item["id"] == "candidate_per_request_scan")

    assert throughput["decision_grade"] is True
    assert throughput["promotion_gate"] is True
    assert throughput["stats"]["sample_count"] == 1_000
    assert proxy["decision_grade"] is False
    assert proxy["promotion_gate"] is False
    assert proxy["stats"]["sample_count"] == 100
    assert candidate_marginal["workload_id"] == throughput["id"]
    assert any(
        item["candidate_workload_id"] == throughput["id"]
        and item["comparison_kind"] == "same_path_stability"
        and item["metric"] == "p99_seconds"
        and item["result"] == "within_tolerance"
        for item in comparisons
    )
    assert any(
        item["candidate_workload_id"] == proxy["id"]
        and item["comparison_kind"] == "same_path_stability"
        and item["metric"] == "median_seconds"
        and item["result"] == "within_tolerance"
        for item in comparisons
    )
    assert any(
        item["candidate_workload_id"] == proxy["id"]
        and item["comparison_kind"] == "cross_path_value"
        and item["metric"] == "p99_seconds"
        for item in comparisons
    )


def test_setup_decision_cells_use_twenty_samples_with_descriptive_p95_and_median_stability(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    _, promoted, _ = _promotable(manifest, evidence)
    setup_ids = {"source_profile_fixture", "source_build_fixture", "cold_compile_fixture"}
    setup_cells = [item for item in promoted["performance"]["workloads"] if item["id"] in setup_ids]

    assert len(setup_cells) == 3
    assert all(item["stats"]["sample_count"] == 20 for item in setup_cells)
    assert all(
        item["stats"]["p95_seconds"] is not None and item["stats"]["p99_seconds"] is None for item in setup_cells
    )
    comparisons = promoted["performance"]["comparisons"]
    assert all(
        {item["metric"] for item in comparisons if item["candidate_workload_id"] == workload["id"]}
        == {"median_seconds"}
        for workload in setup_cells
    )


def test_setup_decision_cells_require_twenty_samples(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    workload = next(item for item in promoted["performance"]["workloads"] if item["id"] == "source_build_fixture")
    workload["samples_seconds"] = workload["samples_seconds"][:19]
    _refresh_workload(promoted, workload)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.invalid_decision_grade_workload",
    )


def test_setup_decision_cells_require_mad_gate_and_median_stability_comparison(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    workload = next(item for item in promoted["performance"]["workloads"] if item["id"] == "source_profile_fixture")
    promoted["performance"]["comparisons"] = [
        item
        for item in promoted["performance"]["comparisons"]
        if not (item["candidate_workload_id"] == workload["id"] and item["metric"] == "median_seconds")
    ]
    promoted["promotion"]["checks"] = [
        item
        for item in promoted["promotion"]["checks"]
        if item["target"]
        != f"/performance/workloads/{promoted['performance']['workloads'].index(workload)}/stats/mad_seconds"
    ]
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    result = _validate_promoted(promoted, bound_manifest, inventories)
    assert {"contract.performance_stability_coverage", "contract.missing_required_gate"} <= _codes(result)


def test_referenced_samples_are_hash_verified_and_recomputed(evidence: JsonObject) -> None:
    value = copy.deepcopy(evidence)
    workload = value["performance"]["workloads"][0]
    samples = list(workload["samples_seconds"])
    workload["samples_seconds"] = []
    workload["samples_ref"] = {
        "id": "fixture_samples",
        "sha256": hash_enron_samples(samples),
        "bytes": _sample_payload_bytes(samples),
    }

    assert validate_enron_evidence(value, referenced_samples={"fixture_samples": samples}) == {
        "valid": True,
        "diagnostics": [],
    }
    _assert_code(validate_enron_evidence(value), "contract.performance_samples_unavailable")

    workload["samples_ref"]["sha256"] = "sha256:" + "0" * 64
    _assert_code(
        validate_enron_evidence(value, referenced_samples={"fixture_samples": samples}),
        "contract.performance_sample_hash",
    )


def test_referenced_sample_byte_count_is_verified(evidence: JsonObject) -> None:
    workload = evidence["performance"]["workloads"][0]
    samples = list(workload["samples_seconds"])
    workload["samples_seconds"] = []
    workload["samples_ref"] = {
        "id": "fixture_samples",
        "sha256": hash_enron_samples(samples),
        "bytes": _sample_payload_bytes(samples) + 1,
    }

    _assert_code(
        validate_enron_evidence(evidence, referenced_samples={"fixture_samples": samples}),
        "contract.performance_sample_hash",
    )


@pytest.mark.parametrize(
    ("resolver", "code"),
    [
        ("samples", "contract.performance_sample_resolver_shape"),
        ("inventories", "contract.performance_inventory_resolver_shape"),
    ],
)
def test_external_resolver_top_level_shape_is_validated(evidence: JsonObject, resolver: str, code: str) -> None:
    kwargs: dict[str, Any] = (
        {"referenced_samples": 42} if resolver == "samples" else {"referenced_input_inventories": [1, 2, 3]}
    )

    _assert_code(validate_enron_evidence(evidence, **kwargs), code)


@pytest.mark.parametrize(
    ("resolver", "code"),
    [
        ("samples", "contract.performance_sample_resolver_shape"),
        ("inventories", "contract.performance_inventory_resolver_shape"),
    ],
)
def test_custom_mapping_resolvers_fail_closed_without_invoking_hostile_methods(
    evidence: JsonObject, resolver: str, code: str
) -> None:
    hostile = _ExplodingMapping()
    kwargs: dict[str, Any] = (
        {"referenced_samples": hostile} if resolver == "samples" else {"referenced_input_inventories": hostile}
    )

    _assert_code(validate_enron_evidence(evidence, **kwargs), code)


def test_custom_mapping_inventory_rows_fail_closed_without_invoking_hostile_methods(evidence: JsonObject) -> None:
    inventory_id = evidence["performance"]["inputs"][0]["inventory_ref"]["id"]

    _assert_code(
        validate_enron_evidence(
            evidence,
            referenced_input_inventories={inventory_id: [_ExplodingMapping()]},
        ),
        "contract.performance_inventory_shape",
    )


def test_numeric_subclasses_in_external_resolvers_fail_closed_without_invoking_overrides(evidence: JsonObject) -> None:
    class EvilFloat(float):
        def __float__(self) -> float:
            raise RuntimeError("unexpected float conversion")

    class EvilInt(int):
        def __ge__(self, other: object) -> bool:
            raise RuntimeError(f"unexpected integer comparison: {other}")

    samples_evidence = copy.deepcopy(evidence)
    workload = samples_evidence["performance"]["workloads"][0]
    workload["samples_seconds"] = []
    workload["samples_ref"] = {"id": "hostile_samples", "sha256": _sha256_number(995), "bytes": 1}
    _assert_code(
        validate_enron_evidence(samples_evidence, referenced_samples={"hostile_samples": [EvilFloat(0.01)]}),
        "contract.performance_sample_support",
    )

    inventory_id = evidence["performance"]["inputs"][0]["inventory_ref"]["id"]
    _assert_code(
        validate_enron_evidence(
            evidence,
            referenced_input_inventories={inventory_id: [{"bytes": EvilInt(1), "records": 0}]},
        ),
        "contract.performance_inventory_shape",
    )


def test_scalar_referenced_sample_fails_closed_without_type_error(evidence: JsonObject) -> None:
    workload = evidence["performance"]["workloads"][0]
    workload["samples_seconds"] = []
    workload["samples_ref"] = {"id": "scalar_samples", "sha256": _sha256_number(994), "bytes": 1}

    _assert_code(
        validate_enron_evidence(evidence, referenced_samples=cast(Any, {"scalar_samples": 0.01})),
        "contract.performance_sample_support",
    )


def test_referenced_samples_can_support_promotion(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    workload = next(item for item in promoted["performance"]["workloads"] if item["id"] == "direct_bank_latency")
    samples = list(workload["samples_seconds"])
    workload["samples_seconds"] = []
    workload["samples_ref"] = {
        "id": "decision_samples",
        "sha256": hash_enron_samples(samples),
        "bytes": _sample_payload_bytes(samples),
    }

    assert _validate_promoted(
        promoted,
        bound_manifest,
        inventories,
        referenced_samples={"decision_samples": samples},
    ) == {"valid": True, "diagnostics": []}


def test_shared_referenced_performance_artifacts_are_prepared_once(
    evidence: JsonObject, monkeypatch: pytest.MonkeyPatch
) -> None:
    workload = evidence["performance"]["workloads"][0]
    samples = list(workload["samples_seconds"])
    workload["samples_seconds"] = []
    workload["samples_ref"] = {
        "id": "shared_samples",
        "sha256": hash_enron_samples(samples),
        "bytes": _sample_payload_bytes(samples),
    }
    duplicate_workload = copy.deepcopy(workload)
    duplicate_workload["id"] = "shared_samples_second_workload"
    duplicate_workload["workload_sha256"] = hash_enron_workload(duplicate_workload)
    evidence["performance"]["workloads"].append(duplicate_workload)

    input_descriptor = evidence["performance"]["inputs"][0]
    duplicate_input = copy.deepcopy(input_descriptor)
    duplicate_input["id"] = "shared_inventory_second_input"
    _refresh_input_descriptor(duplicate_input)
    evidence["performance"]["inputs"].append(duplicate_input)
    inventory_id = input_descriptor["inventory_ref"]["id"]
    inventory = [{"bytes": 1, "records": 0}]

    sample_calls = 0
    inventory_calls = 0
    prepare_samples = enron_contract._prepare_performance_samples
    prepare_inventory = enron_contract._prepare_performance_inventory

    def counted_samples(values: Sequence[Any]) -> Any:
        nonlocal sample_calls
        sample_calls += 1
        return prepare_samples(values)

    def counted_inventory(values: Sequence[Mapping[str, int]]) -> Any:
        nonlocal inventory_calls
        inventory_calls += 1
        return prepare_inventory(values)

    monkeypatch.setattr(enron_contract, "_prepare_performance_samples", counted_samples)
    monkeypatch.setattr(enron_contract, "_prepare_performance_inventory", counted_inventory)

    validate_enron_evidence(
        evidence,
        referenced_samples={"shared_samples": samples},
        referenced_input_inventories={inventory_id: inventory},
    )

    assert sample_calls == inventory_calls == 1


def test_referenced_performance_artifacts_share_an_aggregate_item_budget(
    evidence: JsonObject, monkeypatch: pytest.MonkeyPatch
) -> None:
    workload = evidence["performance"]["workloads"][0]
    samples = list(workload["samples_seconds"])
    workload["samples_seconds"] = []
    workload["samples_ref"] = {
        "id": "budget_samples",
        "sha256": hash_enron_samples(samples),
        "bytes": _sample_payload_bytes(samples),
    }
    monkeypatch.setattr(enron_contract, "MAX_REFERENCED_ITEMS", len(samples) - 1)

    _assert_code(
        validate_enron_evidence(evidence, referenced_samples={"budget_samples": samples}),
        "contract.performance_reference_budget",
    )


@pytest.mark.parametrize(
    ("phase", "process_model", "code"),
    [
        ("direct_bank_scan", "fresh_process_per_sample", "contract.performance_phase_process_model"),
        ("source_profile", "reused_process", "contract.performance_phase_process_model"),
        ("cold_compile", "reused_process", "contract.performance_phase_process_model"),
    ],
)
def test_performance_phase_requires_correct_process_model(
    evidence: JsonObject, phase: str, process_model: str, code: str
) -> None:
    workload = evidence["performance"]["workloads"][0]
    workload["phase"] = phase
    workload["process_model"] = process_model
    workload["workload_sha256"] = hash_enron_workload(workload)
    _refresh_frozen_contract(evidence)

    _assert_code(validate_enron_evidence(evidence), code)


def test_performance_ids_are_unique(evidence: JsonObject) -> None:
    evidence["performance"]["banks"].append(copy.deepcopy(evidence["performance"]["banks"][0]))
    evidence["performance"]["workloads"].append(copy.deepcopy(evidence["performance"]["workloads"][0]))

    _assert_code(validate_enron_evidence(evidence), "contract.duplicate_id")


def test_performance_workload_must_reference_declared_bank(evidence: JsonObject) -> None:
    workload = evidence["performance"]["workloads"][0]
    workload["bank_hash"] = "sha256:" + "0" * 64
    workload["workload_sha256"] = hash_enron_workload(workload)
    _refresh_frozen_contract(evidence)

    _assert_code(validate_enron_evidence(evidence), "contract.unknown_performance_bank")


def test_unknown_decision_input_fails_with_diagnostic_instead_of_key_error(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    workload = next(item for item in promoted["performance"]["workloads"] if item["id"] == "scale_1000_scan")
    workload["input_id"] = "missing_decision_input"
    workload["input_sha256"] = _sha256_number(995)
    workload["workload_sha256"] = hash_enron_workload(workload)
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.unknown_performance_input",
    )


def test_peak_rss_measurements_must_be_strictly_positive(evidence: JsonObject) -> None:
    evidence["performance"]["workloads"][0]["peak_rss_bytes"] = 0

    _assert_code(validate_enron_evidence(evidence), "contract.schema.anyOf")


@pytest.mark.parametrize("mutation", ["length", "maximum"])
def test_peak_rss_is_bound_to_one_memory_sample_per_timing_sample(evidence: JsonObject, mutation: str) -> None:
    workload = evidence["performance"]["workloads"][0]
    if mutation == "length":
        workload["rss_samples_bytes"].pop()
    else:
        workload["rss_samples_bytes"][0] = workload["peak_rss_bytes"] + 1

    _assert_code(validate_enron_evidence(evidence), "contract.performance_rss_samples")


def test_decision_grade_concurrency_cannot_exceed_recorded_machine_capacity(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    workload = next(item for item in promoted["performance"]["workloads"] if item["id"] == "scale_100000_scan")
    workload["concurrency"] = promoted["environment"]["cpu_count"] + 1
    workload["workload_sha256"] = hash_enron_workload(workload)
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.performance_concurrency_bounds",
    )


def test_lifecycle_concurrency_cannot_exceed_recorded_machine_capacity(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    for workload_id in ("helper_cache_hit_fixture", "baseline_helper_cache_hit_fixture"):
        workload = next(item for item in promoted["performance"]["workloads"] if item["id"] == workload_id)
        workload["concurrency"] = promoted["environment"]["cpu_count"] + 1
        workload["workload_sha256"] = hash_enron_workload(workload)
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.performance_concurrency_bounds",
    )


def test_decision_grade_rss_cannot_exceed_recorded_machine_memory(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    bound_manifest["environment"]["memory_bytes"] = 1
    promoted["environment"]["memory_bytes"] = 1
    environment_sha256 = hash_enron_environment(promoted["environment"])
    for claim in promoted["promotion"]["claims"]:
        claim["environment_sha256"] = environment_sha256
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.performance_memory_bounds",
    )


def test_failed_decision_grade_harness_command_cannot_support_promotion(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    bound_manifest["commands"][0]["exit_status"] = 1
    promoted["commands"][0]["exit_status"] = 1
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.performance_command_failure",
    )


def test_failed_exact_baseline_harness_command_cannot_support_promotion(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    failed_command = copy.deepcopy(promoted["commands"][0])
    failed_command.update({"id": "failed_baseline_command", "exit_status": 1})
    promoted["commands"].append(copy.deepcopy(failed_command))
    bound_manifest["commands"].append(copy.deepcopy(failed_command))

    baseline = next(
        item for item in promoted["performance"]["workloads"] if item["id"] == "baseline_direct_bank_latency"
    )
    original_harness = next(
        item for item in promoted["performance"]["harnesses"] if item["id"] == baseline["harness_id"]
    )
    failed_harness = copy.deepcopy(original_harness)
    failed_harness.update({"id": "failed_baseline_harness", "command_id": failed_command["id"]})
    failed_harness["descriptor_sha256"] = hash_enron_performance_harness(failed_harness)
    promoted["performance"]["harnesses"].append(failed_harness)
    promoted["performance"]["harnesses"].sort(key=lambda item: item["id"])
    baseline["harness_id"] = failed_harness["id"]
    baseline["harness_sha256"] = failed_harness["descriptor_sha256"]
    baseline["workload_sha256"] = hash_enron_workload(baseline)
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        _validate_promoted(promoted, bound_manifest, inventories),
        "contract.performance_command_failure",
    )


@pytest.mark.parametrize("target", ["manifest", "evidence"])
def test_real_artifacts_reject_placeholder_all_zero_content_hashes(
    manifest: JsonObject, evidence: JsonObject, target: str
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    if target == "manifest":
        bound_manifest["source"]["content_sha256"] = "sha256:" + "0" * 64
        result = validate_enron_manifest(bound_manifest)
    else:
        promoted["evaluator"]["source_sha256"] = "sha256:" + "0" * 64
        result = _validate_promoted(promoted, bound_manifest, inventories)

    _assert_code(result, "contract.placeholder_content_hash")


@pytest.mark.parametrize(
    "unsafe",
    [
        "/private/source.jsonl",
        "--source=/private/source.jsonl",
        r"C:\Users\fixture\source.jsonl",
        r"D:\corpus\source.jsonl",
        r"E:relative\source.jsonl",
        r"\rooted\source.jsonl",
        r"\\server\share\source.jsonl",
        "--source=Z:/corpus/source.jsonl",
        "/tmp/source.jsonl",
        "FOO=/tmp/source.jsonl",
        "sh -c python /tmp/source.jsonl",
        "--config:/tmp/private.json",
        "--output,/workspace/data.json",
        "artifact(/tmp/private.json)",
        "-I/Volumes/ClientAcme/secret/include",
        "-L/srv/customer-alpha/private-lib",
        "--sysroot/tmp/build",
        r"-IC:\Users\fixture\private\include",
        "-I//server/private/include",
        "--root//server/private",
        "-I~/private/include",
        "-I../private/include",
        "file:///private/source.jsonl",
        "~/source.jsonl",
        "../source.jsonl",
    ],
)
def test_commands_reject_private_or_traversing_paths(manifest: JsonObject, unsafe: str) -> None:
    manifest["commands"][0]["argv"].append(unsafe)

    _assert_code(validate_enron_manifest(manifest), "contract.private_absolute_path")


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("owner", "fixture@example.test", "contract.public_direct_identifier"),
        ("owner", "person@internal", "contract.public_direct_identifier"),
        ("owner", '"δοκιμή@παράδειγμα.test"', "contract.public_direct_identifier"),
        ("owner", "alice＠example.test", "contract.public_direct_identifier"),
        ("owner", "alice%2540example.test", "contract.public_direct_identifier"),
        ("owner", "alice&#64;example.test", "contract.public_direct_identifier"),
        ("owner", "alice&commat;example.test", "contract.public_direct_identifier"),
        ("owner", "alice&amp;#64;example.test", "contract.public_direct_identifier"),
        ("owner", "alice%25252540example.test", "contract.public_direct_identifier"),
        (
            "owner",
            "https://example.test/run?contact=alice%25252525252540example.test",
            "contract.public_direct_identifier",
        ),
        ("owner", "123-45-6789", "contract.public_structured_identifier"),
        ("owner", "123‐45‐6789", "contract.public_structured_identifier"),
        ("owner", "１２３-４５-６７８９", "contract.public_structured_identifier"),
        ("owner", "+1 (713) 555-0199", "contract.public_structured_identifier"),
        ("owner", "+1(713)555-0199", "contract.public_structured_identifier"),
        ("owner", "(713)5550199", "contract.public_structured_identifier"),
        ("owner", "＋１（７１３）５５５－０１９９", "contract.public_structured_identifier"),
        ("owner", "+17135550199", "contract.public_structured_identifier"),
        ("owner", "+447911123456", "contract.public_structured_identifier"),
        ("owner", "+44 7911 123456", "contract.public_structured_identifier"),
        ("owner", "713+555+0199", "contract.public_structured_identifier"),
        ("owner", "+33 1 42 68 53 00", "contract.public_structured_identifier"),
        ("owner", "+91 98765 43210", "contract.public_structured_identifier"),
        ("owner", "+١٧١٣٥٥٥٠١٩٩", "contract.public_structured_identifier"),
        ("owner", "١٢٣-٤٥-٦٧٨٩", "contract.public_structured_identifier"),
        (
            "owner",
            "%2525252B1%25252520%25252528713%25252529%25252520555-0199",
            "contract.public_structured_identifier",
        ),
        ("access", "/Users/fixture/private/source", "contract.public_private_path"),
        ("access", "FOO=/tmp/source.jsonl", "contract.public_private_path"),
        ("access", "python /tmp/source.jsonl --safe", "contract.public_private_path"),
        ("access", "--config:/tmp/private.json", "contract.public_private_path"),
        ("access", "--output,/workspace/data.json", "contract.public_private_path"),
        ("access", "artifact(/tmp/private.json)", "contract.public_private_path"),
        ("access", "artifact%2528%252Ftmp%252Fprivate.json%2529", "contract.public_private_path"),
        ("access", "／Users／alice／secret.json", "contract.public_private_path"),
        ("access", "file：／／／Users／alice／secret.json", "contract.public_private_path"),
        ("access", "..／secret.json", "contract.public_private_path"),
        ("access", "&#47;Users&#47;alice&#47;private.json", "contract.public_private_path"),
        ("access", "%2525252FUsers%2525252Falice%2525252Fprivate.json", "contract.public_private_path"),
        (
            "access",
            "file%2525253A%2525252F%2525252F%2525252FUsers%2525252Falice%2525252Fprivate.json",
            "contract.public_private_path",
        ),
    ],
)
def test_entire_public_serialization_is_scanned_for_identifiers_and_paths(
    manifest: JsonObject, field: str, value: str, code: str
) -> None:
    manifest["source"][field] = value

    _assert_code(validate_enron_manifest(manifest), code)


@pytest.mark.parametrize(
    "unsafe",
    [
        r"D:\corpus\source.jsonl",
        r"E:relative\source.jsonl",
        r"\rooted\source.jsonl",
        r"\\server\share\source.jsonl",
    ],
)
def test_public_serialization_rejects_windows_local_path_variants(manifest: JsonObject, unsafe: str) -> None:
    manifest["source"]["access"] = unsafe

    _assert_code(validate_enron_manifest(manifest), "contract.public_private_path")


@pytest.mark.parametrize(
    "unsafe",
    [
        "https://example.test/run?source=/Users/alice/private.json",
        "https://example.test/run#file=/home/alice/corpus.jsonl",
        "https://example.test/redirect?next=file:///private/source.jsonl",
        "https://example.test/run?source=%252FUsers%252Falice%252Fprivate.json",
    ],
)
def test_http_url_exemption_does_not_hide_private_query_or_fragment_values(manifest: JsonObject, unsafe: str) -> None:
    manifest["source"]["access"] = unsafe

    _assert_code(validate_enron_manifest(manifest), "contract.public_private_path")


@pytest.mark.parametrize(
    ("unsafe", "code"),
    [
        ("https://example.test/run?contact=alice%40example.test", "contract.public_direct_identifier"),
        ("https://example.test/alice%2540example.test", "contract.public_direct_identifier"),
        ("https://example.test/run?phone=%2B1%28713%29555-0199", "contract.public_structured_identifier"),
        ("https://example.test/run?phone=%2B1+713+555+0199", "contract.public_structured_identifier"),
        ("https://example.test/run?phone=%2B44+7911+123456", "contract.public_structured_identifier"),
        ("https://example.test/run#ssn=123%2D45%2D6789", "contract.public_structured_identifier"),
    ],
)
def test_http_url_exemption_does_not_hide_encoded_identifiers(manifest: JsonObject, unsafe: str, code: str) -> None:
    manifest["source"]["access"] = unsafe

    _assert_code(validate_enron_manifest(manifest), code)


@pytest.mark.parametrize(
    ("value", "code"),
    [
        ("doc_" + "a" * 64, "contract.public_direct_identifier"),
        ("ｄｏｃ＿" + "ａ" * 64, "contract.public_direct_identifier"),
        ("do\u200bc_" + "a" * 64, "contract.public_direct_identifier"),
        ("doc%255F" + "a" * 64, "contract.public_direct_identifier"),
        (
            "https://example.test/archive/doc%255F" + "a" * 64,
            "contract.public_direct_identifier",
        ),
        ("7135550199", "contract.public_structured_identifier"),
        ("17135550199", "contract.public_structured_identifier"),
        ("７１３５５５０１９９", "contract.public_structured_identifier"),
        ("71355\u200b50199", "contract.public_structured_identifier"),
        (
            "https://example.test/run?callback=7135550199",
            "contract.public_structured_identifier",
        ),
    ],
)
def test_canonical_public_scanner_rejects_obfuscated_document_ids_and_compact_phones(
    value: str,
    code: str,
) -> None:
    diagnostics = enron_contract._public_serialization_diagnostics({"safe": value})

    assert code in {item["code"] for item in diagnostics}


@pytest.mark.parametrize("location", ["key", "value"])
@pytest.mark.parametrize(
    "unsafe",
    [
        "do\u00adc_" + "a" * 64,
        "do\U000e0001c_" + "b" * 64,
        "71355\u180e50199",
        "alice%4\u20620example.test",
        "artifact(.\ufe0f./private.json)",
    ],
)
def test_canonical_public_scanner_removes_default_ignorables_in_keys_and_values(
    location: str,
    unsafe: str,
) -> None:
    payload = {unsafe: "aggregate"} if location == "key" else {"safe": unsafe}

    diagnostics = enron_contract._public_serialization_diagnostics(payload)

    assert diagnostics
    assert unsafe not in json.dumps(diagnostics, ensure_ascii=False, sort_keys=True)


@pytest.mark.parametrize(
    "unsafe_key",
    [
        "doc_" + "b" * 64,
        "do\u200bc_" + "b" * 64,
        "7135550199",
        "７１３５５５０１９９",
    ],
)
def test_canonical_public_scanner_inspects_mapping_keys(unsafe_key: str) -> None:
    diagnostics = enron_contract._public_serialization_diagnostics({unsafe_key: "aggregate"})

    assert diagnostics
    assert unsafe_key not in json.dumps(diagnostics, ensure_ascii=False, sort_keys=True)


@pytest.mark.parametrize(
    "safe",
    [
        "sha256:" + "1" * 64,
        "1" * 64,
        "a7135550199b",
        "17135550199suffix",
        "prefix7135550199",
    ],
)
def test_compact_phone_scanner_uses_alphanumeric_boundaries_without_matching_hashes(safe: str) -> None:
    diagnostics = enron_contract._public_serialization_diagnostics({"safe": safe})

    assert "contract.public_structured_identifier" not in {item["code"] for item in diagnostics}


@pytest.mark.parametrize(
    "safe_url",
    [
        "https://example.test/a(b)/c?view=public#summary",
        "https://[2001:db8::1]:8443/a(b)/c?view=public#summary",
        "https://example.test/redirect?next=https://other.test/docs",
        "https://example.test/redirect?next=https%3A%2F%2Fother.test%2Fdocs",
    ],
)
def test_http_urls_and_gate_json_pointers_are_public_path_exemptions(
    manifest: JsonObject, evidence: JsonObject, safe_url: str
) -> None:
    manifest["source"]["access"] = safe_url

    assert validate_enron_manifest(manifest) == {"valid": True, "diagnostics": []}
    assert validate_enron_evidence(evidence) == {"valid": True, "diagnostics": []}
    assert all(item["target"].startswith("/") for item in evidence["promotion"]["checks"])


def test_safe_html_entity_text_remains_public(manifest: JsonObject) -> None:
    manifest["source"]["owner"] = "Research &amp; Development"

    assert validate_enron_manifest(manifest) == {"valid": True, "diagnostics": []}


def test_public_normalization_budget_fails_closed_with_bounded_work(
    manifest: JsonObject, monkeypatch: pytest.MonkeyPatch
) -> None:
    encoded = "%40"
    for _ in range(enron_contract.MAX_PUBLIC_DECODE_ROUNDS + 1):
        encoded = encoded.replace("%", "%25")
    calls = 0
    transform = enron_contract._public_text_transform

    def counted(value: str) -> str:
        nonlocal calls
        calls += 1
        return transform(value)

    monkeypatch.setattr(enron_contract, "_public_text_transform", counted)
    _, converged = enron_contract._normalize_public_text(f"alice{encoded}example.test")
    assert converged is False
    assert calls <= enron_contract.MAX_PUBLIC_DECODE_ROUNDS + 1
    monkeypatch.setattr(enron_contract, "_public_text_transform", transform)
    manifest["source"]["owner"] = f"alice{encoded}example.test"

    _assert_code(validate_enron_manifest(manifest), "contract.public_ambiguous_encoding")


def test_diagnostics_do_not_echo_direct_identifiers_or_offending_values(manifest: JsonObject) -> None:
    secret = "sensitive.person@private.example"
    manifest["source"]["owner"] = secret

    result = validate_enron_manifest(manifest)

    _assert_code(result, "contract.public_direct_identifier")
    assert secret not in json.dumps(result, sort_keys=True)


def test_schema_diagnostics_do_not_echo_invalid_secret_values(manifest: JsonObject) -> None:
    secret = "sensitive.person@internal"
    manifest["source"]["input_records"] = secret

    result = validate_enron_manifest(manifest)

    _assert_code(result, "contract.schema.type")
    assert secret not in json.dumps(result, sort_keys=True)


def test_privacy_pass_cannot_hide_raw_text_identifiers_or_violations(manifest: JsonObject) -> None:
    manifest["privacy"]["raw_text_included"] = True
    manifest["privacy"]["direct_identifiers_included"] = True
    manifest["privacy"]["violation_count"] = 2

    _assert_code(validate_enron_manifest(manifest), "contract.forged_privacy_pass")


def test_diagnostics_are_deterministically_capped(manifest: JsonObject) -> None:
    manifest["commands"] = [copy.deepcopy(manifest["commands"][0]) for _ in range(150)]

    result = validate_enron_manifest(manifest)

    assert len(result["diagnostics"]) == enron_contract.MAX_DIAGNOSTICS + 1
    assert result["diagnostics"][-1]["code"] == "contract.diagnostics_truncated"
    assert result == validate_enron_manifest(manifest)


def test_expensive_diagnostic_collectors_stop_early_and_never_echo_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_diagnostics = enron_contract._command_diagnostics(
        [{"cwd": "/tmp/private", "argv": []} for _ in range(enron_contract.MAX_COLLECTION_ITEMS)],
        "/commands",
    )
    assert len(command_diagnostics) == enron_contract.MAX_DIAGNOSTICS + 1

    placeholder_diagnostics = enron_contract._placeholder_hash_diagnostics(
        {f"key_{index:04d}": enron_contract.ZERO_SHA256 for index in range(1000)}
    )
    assert len(placeholder_diagnostics) == enron_contract.MAX_DIAGNOSTICS + 1
    assert [item["path"] for item in placeholder_diagnostics[:2]] == ["/key_0000", "/key_0001"]

    consumed: list[int] = []
    secret = "private-value@internal"

    def strings(_value: Any) -> Any:
        for index in range(enron_contract.MAX_COLLECTION_ITEMS):
            consumed.append(index)
            yield f"/value_{index:04d}", secret

    monkeypatch.setattr(enron_contract, "_iter_strings", strings)
    public_diagnostics = enron_contract._public_serialization_diagnostics({})

    assert len(consumed) == len(public_diagnostics) == enron_contract.MAX_DIAGNOSTICS + 1
    assert secret not in json.dumps(public_diagnostics, sort_keys=True)


@pytest.mark.parametrize("shape", ["depth", "cycle", "collection"])
def test_validator_rejects_deep_cyclic_and_oversized_in_memory_structures(shape: str) -> None:
    if shape == "depth":
        value: Any = {}
        current = value
        for _ in range(enron_contract.MAX_CONTRACT_DEPTH + 2):
            current["next"] = {}
            current = current["next"]
    elif shape == "cycle":
        value = {}
        value["self"] = value
    else:
        value = [None] * (enron_contract.MAX_COLLECTION_ITEMS + 1)

    _assert_code(validate_enron_evidence(value), "contract.resource_limits")


def test_embedded_and_referenced_sample_collection_limits_fail_closed(evidence: JsonObject) -> None:
    embedded = copy.deepcopy(evidence)
    embedded["performance"]["workloads"][0]["samples_seconds"] = [0.01] * (enron_contract.MAX_COLLECTION_ITEMS + 1)
    _assert_code(validate_enron_evidence(embedded), "contract.resource_limits")

    referenced = copy.deepcopy(evidence)
    workload = referenced["performance"]["workloads"][0]
    workload["samples_seconds"] = []
    workload["samples_ref"] = {"id": "too_many_samples", "sha256": _sha256_number(990), "bytes": 1}
    _assert_code(
        validate_enron_evidence(
            referenced,
            referenced_samples={"too_many_samples": [0.01] * (enron_contract.MAX_COLLECTION_ITEMS + 1)},
        ),
        "contract.performance_sample_support",
    )


def test_referenced_input_inventory_collection_limit_fails_closed(evidence: JsonObject) -> None:
    inventory_id = evidence["performance"]["inputs"][0]["inventory_ref"]["id"]
    oversized = [{"bytes": 1, "records": 0}] * (enron_contract.MAX_COLLECTION_ITEMS + 1)

    _assert_code(
        validate_enron_evidence(evidence, referenced_input_inventories={inventory_id: oversized}),
        "contract.performance_inventory_shape",
    )


def test_contract_loaders_accept_bound_sanitized_fixtures(test_data_path: Path) -> None:
    manifest = load_enron_manifest(test_data_path / "enron_manifest_v2.json")
    evidence = load_enron_evidence(test_data_path / "enron_evidence_v2.json", manifest=manifest)

    assert manifest["artifact_kind"] == "synthetic_fixture"
    assert evidence["manifest_sha256"] == hash_enron_manifest(manifest)


def test_contract_loaders_reject_symlinks(tmp_path: Path, test_data_path: Path) -> None:
    link = tmp_path / "manifest-link.json"
    link.symlink_to(test_data_path / "enron_manifest_v2.json")

    with pytest.raises(ValueError, match="regular non-symlink"):
        load_enron_manifest(link)


def test_contract_loader_uses_nofollow_and_rejects_lstat_fstat_identity_change(
    test_data_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_open = enron_contract.os.open
    real_fstat = enron_contract.os.fstat
    opened_flags: list[int] = []

    def recording_open(path: Any, flags: int) -> int:
        opened_flags.append(flags)
        return real_open(path, flags)

    def changed_fstat(descriptor: int) -> Any:
        fields = list(real_fstat(descriptor))
        fields[2] += 1
        return enron_contract.os.stat_result(fields)

    monkeypatch.setattr(enron_contract.os, "open", recording_open)
    monkeypatch.setattr(enron_contract.os, "fstat", changed_fstat)

    with pytest.raises(ValueError):
        load_enron_manifest(test_data_path / "enron_manifest_v2.json")

    assert opened_flags
    nofollow = getattr(enron_contract.os, "O_NOFOLLOW", 0)
    if nofollow:
        assert opened_flags[0] & nofollow


def test_contract_loaders_reject_directories(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="regular non-symlink"):
        load_enron_manifest(tmp_path)


def test_contract_loaders_reject_oversized_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(enron_contract, "MAX_CONTRACT_BYTES", 64)
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"{" + b" " * 64 + b"}")

    with pytest.raises(ValueError, match="exceeds"):
        load_enron_manifest(oversized)


@pytest.mark.parametrize(
    ("limit", "payload", "message"),
    [
        ("nodes", '{"items":[' + ",".join("{}" for _ in range(20)) + "]}", "node-count"),
        ("collection", '{"items":[0,1,2,3,4]}', "collection-size"),
        ("depth", '{"a":{"b":{"c":0}}}', "depth"),
    ],
)
def test_contract_loader_enforces_structural_limits_before_json_materialization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, limit: str, payload: str, message: str
) -> None:
    source = tmp_path / f"{limit}-amplification.json"
    source.write_text(payload, encoding="utf-8")
    monkeypatch.setattr(
        enron_contract,
        {
            "nodes": "MAX_CONTRACT_NODES",
            "collection": "MAX_COLLECTION_ITEMS",
            "depth": "MAX_CONTRACT_DEPTH",
        }[limit],
        {"nodes": 8, "collection": 4, "depth": 2}[limit],
    )

    def unexpected_parse(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("json.loads must not run after preflight exhaustion")

    monkeypatch.setattr(enron_contract.json, "loads", unexpected_parse)

    with pytest.raises(ValueError, match=message):
        enron_contract._load_contract_json(source)


@pytest.mark.parametrize("payload", ["[]", "null", '"text"', "1"])
def test_contract_loaders_reject_non_object_json(tmp_path: Path, payload: str) -> None:
    source = tmp_path / "non-object.json"
    source.write_text(payload, encoding="utf-8")

    with pytest.raises(ValueError, match="JSON object"):
        load_enron_manifest(source)


def test_contract_loaders_reject_duplicate_keys_and_non_finite_json(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"outer":{"value":1,"value":2}}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate key"):
        load_enron_manifest(duplicate)

    for index, constant in enumerate(("NaN", "Infinity", "-Infinity")):
        non_finite = tmp_path / f"non-finite-{index}.json"
        non_finite.write_text(f'{{"value":{constant}}}', encoding="utf-8")
        with pytest.raises(ValueError, match="non-finite"):
            load_enron_evidence(non_finite)


def test_contract_loaders_reject_structurally_invalid_contracts(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid Enron v2 manifest"):
        load_enron_manifest(invalid)
    with pytest.raises(ValueError, match="Invalid Enron v2 evidence"):
        load_enron_evidence(invalid)


def test_all_successful_results_and_contracts_serialize_without_non_finite_values(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    bound_manifest, promoted, inventories = _promotable(manifest, evidence)
    successful_values = [
        ENRON_MANIFEST_SCHEMA,
        ENRON_EVIDENCE_SCHEMA,
        manifest,
        evidence,
        bound_manifest,
        promoted,
        validate_enron_manifest(manifest),
        validate_enron_evidence(evidence, manifest=manifest),
        validate_enron_manifest(bound_manifest),
        _validate_promoted(promoted, bound_manifest, inventories),
    ]

    for value in successful_values:
        json.dumps(value, allow_nan=False)

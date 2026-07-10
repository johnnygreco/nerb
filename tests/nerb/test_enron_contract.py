from __future__ import annotations

import copy
import json
import math
from collections.abc import Mapping, Sequence
from pathlib import Path
from statistics import median
from typing import Any

import pytest
from jsonschema import Draft202012Validator

import nerb.enron_contract as enron_contract
from nerb.enron_contract import (
    ENRON_EVIDENCE_SCHEMA,
    ENRON_EVIDENCE_SCHEMA_VERSION,
    ENRON_MANIFEST_SCHEMA,
    ENRON_MANIFEST_SCHEMA_VERSION,
    hash_enron_environment,
    hash_enron_manifest,
    hash_enron_performance_manifest,
    hash_enron_samples,
    hash_enron_test_lineage_entry,
    hash_enron_thresholds,
    hash_enron_workload,
    load_enron_evidence,
    load_enron_manifest,
    validate_enron_evidence,
    validate_enron_manifest,
)

JsonObject = dict[str, Any]
JsonPath = tuple[str | int, ...]


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


def _nearest_rank(values: Sequence[float], probability: float) -> float:
    return sorted(values)[max(0, math.ceil(probability * len(values)) - 1)]


def _sample_stats(samples: Sequence[float], documents: int, byte_count: int) -> JsonObject:
    ordered = sorted(float(value) for value in samples)
    median_seconds = float(median(ordered))
    deviations = [abs(value - median_seconds) for value in ordered]
    return {
        "sample_count": len(ordered),
        "median_seconds": median_seconds,
        "p95_seconds": _nearest_rank(ordered, 0.95) if len(ordered) >= 20 else None,
        "p99_seconds": _nearest_rank(ordered, 0.99) if len(ordered) >= 100 else None,
        "mad_seconds": float(median(deviations)),
        "documents_per_second": documents / median_seconds,
        "mib_per_second": byte_count / (1024 * 1024) / median_seconds,
    }


def _sample_payload_bytes(samples: Sequence[float]) -> int:
    payload = json.dumps(
        [float(value) for value in samples],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return len(payload.encode("utf-8"))


def _refresh_workload(workload: JsonObject, samples: Sequence[float] | None = None) -> None:
    resolved = list(workload["samples_seconds"] if samples is None else samples)
    workload["stats"] = _sample_stats(resolved, workload["documents"], workload["bytes"])
    workload["workload_sha256"] = hash_enron_workload(workload)


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
            "bank_hash": evidence["bank"]["canonical_hash"],
            "evaluator_source_sha256": evidence["evaluator"]["source_sha256"],
            "split_manifest_sha256": evidence["splits"]["manifest_sha256"],
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


def _quality_claim(evidence: Mapping[str, Any], metric: str) -> JsonObject:
    item = evidence["quality"]["slices"][0]
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


def _performance_claim(evidence: Mapping[str, Any], metric: str, stat_field: str) -> JsonObject:
    workload = evidence["performance"]["workloads"][0]
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


def _add_required_performance_matrix(evidence: JsonObject) -> None:
    performance = evidence["performance"]
    evaluated_hash = evidence["bank"]["canonical_hash"]
    base = performance["workloads"][0]
    phase_specs = (
        ("source_build", "negative", 1, "reused_process"),
        ("cold_compile", "sparse", 1, "fresh_process_per_sample"),
        ("helper_cache_miss", "dense", 1, "reused_process"),
        ("helper_cache_hit", "normal", 4, "reused_process"),
        ("end_to_end", "normal", 1, "reused_process"),
    )
    for phase, hit_density, concurrency, process_model in phase_specs:
        workload = copy.deepcopy(base)
        workload.update(
            {
                "id": f"{phase}_fixture",
                "phase": phase,
                "promotion_gate": False,
                "bank_hash": evaluated_hash,
                "hit_density": hit_density,
                "concurrency": concurrency,
                "process_model": process_model,
                "samples_seconds": [0.02 + index / 100_000 for index in range(5)],
                "samples_ref": None,
            }
        )
        _refresh_workload(workload)
        performance["workloads"].append(workload)

    for index, active_patterns in enumerate((1_000, 10_000, 25_000, 100_000), start=1):
        bank_hash = "sha256:" + f"{active_patterns:064x}"
        performance["banks"].append(
            {
                "id": f"scale_{active_patterns}",
                "kind": "synthetic_scale",
                "bank_hash": bank_hash,
                "active_entities": max(1, active_patterns // 10),
                "active_names": active_patterns,
                "active_patterns": active_patterns,
                "canonical_json_bytes": active_patterns * 64,
                "native_source_bytes": active_patterns * 32,
            }
        )
        workload = copy.deepcopy(base)
        workload.update(
            {
                "id": f"scale_{active_patterns}_scan",
                "promotion_gate": False,
                "bank_hash": bank_hash,
                "concurrency": 1 if index < 4 else 4,
                "hit_density": ("negative", "sparse", "normal", "dense")[index - 1],
                "samples_seconds": [0.03 + sample / 100_000 for sample in range(5)],
                "samples_ref": None,
            }
        )
        _refresh_workload(workload)
        performance["workloads"].append(workload)


def _promotable(manifest: JsonObject, evidence: JsonObject) -> tuple[JsonObject, JsonObject]:
    bound_manifest = copy.deepcopy(manifest)
    value = copy.deepcopy(evidence)
    bound_manifest["artifact_kind"] = "real_benchmark"
    value["artifact_kind"] = "real_benchmark"
    release_commit = "f" * 40
    bound_manifest["software"]["git_commit"] = release_commit
    value["software"]["git_commit"] = release_commit

    quality = value["quality"]["slices"][0]
    quality["promotion_gate"] = True
    workload = value["performance"]["workloads"][0]
    workload["promotion_gate"] = True
    workload["samples_seconds"] = [0.01 + index / 1_000_000 for index in range(100)]
    workload["samples_ref"] = None
    _refresh_workload(workload)
    _add_required_performance_matrix(value)

    quality_index = 0
    workload_index = 0
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
        "open_world_recall": ("gte", 0.85),
        "catalog_coverage": ("gte", 0.75),
        "cataloged_recall": ("gte", 1.0),
        "document_leak_rate": ("lte", 0.2),
        "sensitive_character_recall": ("gte", 0.9),
        "sensitive_character_leak_rate": ("lte", 0.1),
        "negative_document_false_alarm_rate": ("lte", 0.6),
        "over_redaction_rate": ("lte", 0.02),
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
    performance_thresholds = {
        "median_seconds": ("lte", 0.02),
        "p95_seconds": ("lte", 0.02),
        "p99_seconds": ("lte", 0.02),
        "mib_per_second": ("gte", 50.0),
        "peak_rss_bytes": ("lte", 2 * 1024 * 1024),
    }
    for field, (operator, threshold) in performance_thresholds.items():
        target = f"/performance/workloads/{workload_index}/"
        target += f"stats/{field}" if field != "peak_rss_bytes" else field
        checks.append(
            _gate(
                f"performance_{field}",
                "performance",
                target,
                operator,
                threshold,
                workload[field] if field == "peak_rss_bytes" else workload["stats"][field],
            )
        )
    value["promotion"]["checks"] = checks
    value["promotion"]["claims"] = [
        _catalog_claim(value),
        _quality_claim(value, "open_world_recall"),
        _performance_claim(value, "direct_bank_scan_p99_seconds", "p99_seconds"),
        _performance_claim(value, "direct_bank_scan_mib_per_second", "mib_per_second"),
    ]
    value["promotion"]["passed"] = True
    value["verifier"]["passed"] = True
    _refresh_frozen_contract(value)
    _sync_bound_manifest(bound_manifest, value)
    return bound_manifest, value


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
        "recall": None,
        "passed": False,
    }
    value["performance"] = {"evaluated": False, "banks": [], "workloads": []}
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
    Draft202012Validator.check_schema(ENRON_MANIFEST_SCHEMA)
    Draft202012Validator.check_schema(ENRON_EVIDENCE_SCHEMA)
    json.dumps(ENRON_MANIFEST_SCHEMA, allow_nan=False)
    json.dumps(ENRON_EVIDENCE_SCHEMA, allow_nan=False)


def test_schemas_close_root_and_nested_objects(manifest: JsonObject, evidence: JsonObject) -> None:
    manifest["unexpected"] = True
    manifest["privacy"]["unexpected"] = True
    evidence["quality"]["slices"][0]["unexpected"] = True

    assert "contract.schema.additionalProperties" in _codes(validate_enron_manifest(manifest))
    assert "contract.schema.additionalProperties" in _codes(validate_enron_evidence(evidence))


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("quality", "slices", 0, "gold_spans"), True),
        (("quality", "slices", 0, "metrics", "open_world_recall"), float("nan")),
        (("performance", "workloads", 0, "samples_seconds", 0), float("inf")),
        (("performance", "workloads", 0, "samples_seconds", 0), 0.0),
        (("source", "input_records"), 2**63),
        (("commands", 0, "elapsed_seconds"), 1e301),
    ],
)
def test_contract_rejects_non_json_or_out_of_range_numeric_values(
    evidence: JsonObject, path: JsonPath, replacement: Any
) -> None:
    _set(evidence, path, replacement)

    result = validate_enron_evidence(evidence)

    assert result["valid"] is False
    assert any(code.startswith("contract.schema.") for code in _codes(result))


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


def test_manifest_annotation_states_are_consistent(manifest: JsonObject) -> None:
    label = manifest["labels"][0]
    label["label_strength"] = "unlabeled"
    label["annotation_completeness"] = "partial"

    _assert_code(validate_enron_manifest(manifest), "contract.unlabeled_annotation_state")


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


def test_manifest_timestamps_and_ids_are_deterministic(manifest: JsonObject) -> None:
    manifest["created_at"] = "not-a-time"
    manifest["commands"].append(copy.deepcopy(manifest["commands"][0]))
    manifest["labels"].append(copy.deepcopy(manifest["labels"][0]))

    result = validate_enron_manifest(manifest)

    assert {"contract.invalid_timestamp", "contract.duplicate_id"} <= _codes(result)


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
    manifest["thresholds_sha256"] = evidence["thresholds_sha256"]
    manifest["performance_manifest_sha256"] = evidence["performance_manifest_sha256"]
    evidence["manifest_sha256"] = hash_enron_manifest(manifest)

    assert validate_enron_manifest(manifest) == {"valid": True, "diagnostics": []}
    assert validate_enron_evidence(evidence, manifest=manifest) == {"valid": True, "diagnostics": []}


def test_partial_independent_claim_is_rejected_even_when_nonpromoted(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    manifest["labels"][0]["annotation_completeness"] = "partial"
    evidence["quality"]["slices"][0]["annotation_completeness"] = "partial"
    evidence["manifest_sha256"] = hash_enron_manifest(manifest)

    _assert_code(validate_enron_evidence(evidence, manifest=manifest), "contract.unsupported_claim")


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


def test_unevaluated_evidence_is_valid_but_cannot_be_promoted(evidence: JsonObject) -> None:
    value = _unevaluated(evidence)
    assert validate_enron_evidence(value) == {"valid": True, "diagnostics": []}

    value["promotion"]["passed"] = True
    _assert_code(validate_enron_evidence(value), "contract.promotion_prerequisite")


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
    evidence: JsonObject, path: JsonPath, replacement: Any, code: str
) -> None:
    claim = evidence["promotion"]["claims"][1]
    _set(claim, path, replacement)

    _assert_code(validate_enron_evidence(evidence), code)


def test_structured_performance_claim_must_reference_exact_workload(evidence: JsonObject) -> None:
    claim = next(item for item in evidence["promotion"]["claims"] if item["kind"] == "performance")
    claim["performance_workload_id"] = "missing"

    _assert_code(validate_enron_evidence(evidence), "contract.unsupported_claim")


def test_duplicate_claim_ids_are_rejected(evidence: JsonObject) -> None:
    evidence["promotion"]["claims"].append(copy.deepcopy(evidence["promotion"]["claims"][0]))

    _assert_code(validate_enron_evidence(evidence), "contract.duplicate_id")


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


def test_threshold_hash_binds_typed_gate_configuration(evidence: JsonObject) -> None:
    evidence["promotion"]["checks"][3]["threshold"] = 0.99

    _assert_code(validate_enron_evidence(evidence), "contract.threshold_hash_mismatch")


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
    bound_manifest, promoted = _promotable(manifest, evidence)

    assert validate_enron_manifest(bound_manifest) == {"valid": True, "diagnostics": []}
    assert validate_enron_evidence(promoted, manifest=bound_manifest, trusted_lineage_prefix=[]) == {
        "valid": True,
        "diagnostics": [],
    }

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
    bound_manifest, promoted = _promotable(manifest, evidence)
    promoted["quality"]["slices"][0]["gold_spans"] = 0

    _assert_code(
        validate_enron_evidence(promoted, manifest=bound_manifest, trusted_lineage_prefix=[]),
        "contract.natural_catalog_gate",
    )


def test_promotion_requires_every_predeclared_quality_and_performance_gate(
    manifest: JsonObject, evidence: JsonObject
) -> None:
    bound_manifest, promoted = _promotable(manifest, evidence)
    promoted["promotion"]["checks"] = [
        item for item in promoted["promotion"]["checks"] if item["id"] != "quality_over_redaction_rate"
    ]
    _refresh_frozen_contract(promoted)

    _assert_code(
        validate_enron_evidence(promoted, manifest=bound_manifest, trusted_lineage_prefix=[]),
        "contract.missing_required_gate",
    )


def test_promotion_requires_mandated_gate_operator_semantics(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, promoted = _promotable(manifest, evidence)
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
        validate_enron_evidence(promoted, manifest=bound_manifest, trusted_lineage_prefix=[]),
        "contract.required_gate_semantics",
    )


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        ("phase", "contract.missing_performance_phase"),
        ("scale", "contract.missing_scale_shape"),
        ("density", "contract.missing_hit_density"),
        ("concurrency", "contract.missing_concurrency_shape"),
        ("unused_bank", "contract.unused_performance_bank"),
    ],
)
def test_promotion_requires_full_phase_scale_density_and_concurrency_matrix(
    manifest: JsonObject, evidence: JsonObject, mutation: str, code: str
) -> None:
    bound_manifest, promoted = _promotable(manifest, evidence)
    performance = promoted["performance"]
    if mutation == "phase":
        performance["workloads"] = [item for item in performance["workloads"] if item["phase"] != "end_to_end"]
    elif mutation == "scale":
        removed_hash = next(item["bank_hash"] for item in performance["banks"] if item["active_patterns"] == 1_000)
        performance["banks"] = [item for item in performance["banks"] if item["bank_hash"] != removed_hash]
        performance["workloads"] = [item for item in performance["workloads"] if item["bank_hash"] != removed_hash]
    elif mutation == "density":
        for workload in performance["workloads"]:
            workload["hit_density"] = "normal"
            workload["workload_sha256"] = hash_enron_workload(workload)
    elif mutation == "concurrency":
        for workload in performance["workloads"]:
            workload["concurrency"] = 1
            workload["workload_sha256"] = hash_enron_workload(workload)
    else:
        unused_hash = next(item["bank_hash"] for item in performance["banks"] if item["active_patterns"] == 100_000)
        performance["workloads"] = [item for item in performance["workloads"] if item["bank_hash"] != unused_hash]
    _refresh_frozen_contract(promoted)
    _sync_bound_manifest(bound_manifest, promoted)

    _assert_code(
        validate_enron_evidence(promoted, manifest=bound_manifest, trusted_lineage_prefix=[]),
        code,
    )


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
    bound_manifest, promoted = _promotable(manifest, evidence)
    promoted["test_access"]["lineage"][-1]["outcome"] = "aborted"
    _rehash_lineage(promoted)

    _assert_code(
        validate_enron_evidence(promoted, manifest=bound_manifest, trusted_lineage_prefix=[]),
        "contract.failed_test_promotion",
    )


def test_successor_lineage_accepts_exact_trusted_append(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, promoted = _promotable(manifest, evidence)
    trusted_prefix = _with_predecessor(promoted)

    assert validate_enron_evidence(
        promoted,
        manifest=bound_manifest,
        trusted_lineage_prefix=trusted_prefix,
    ) == {"valid": True, "diagnostics": []}


def test_successor_lineage_rejects_non_append_only_prefix(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, promoted = _promotable(manifest, evidence)
    _with_predecessor(promoted)

    _assert_code(
        validate_enron_evidence(promoted, manifest=bound_manifest, trusted_lineage_prefix=[]),
        "contract.lineage_not_append_only",
    )


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
    bound_manifest, promoted = _promotable(manifest, evidence)
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
        validate_enron_evidence(
            promoted,
            manifest=bound_manifest,
            trusted_lineage_prefix=trusted_prefix,
        ),
        code,
    )


def test_repeated_benchmark_version_in_lineage_is_rejected(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, promoted = _promotable(manifest, evidence)
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
        validate_enron_evidence(
            promoted,
            manifest=bound_manifest,
            trusted_lineage_prefix=trusted_prefix,
        ),
        "contract.test_reused",
    )


def test_workload_descriptor_and_performance_manifest_hashes_are_bound(evidence: JsonObject) -> None:
    evidence["performance"]["workloads"][0]["documents"] += 1
    _assert_code(validate_enron_evidence(evidence), "contract.workload_hash_mismatch")

    evidence["performance"]["workloads"][0]["workload_sha256"] = hash_enron_workload(
        evidence["performance"]["workloads"][0]
    )
    _assert_code(validate_enron_evidence(evidence), "contract.performance_manifest_hash")


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
    ],
)
def test_every_performance_statistic_is_recomputed_with_tail_samples(
    manifest: JsonObject, evidence: JsonObject, field: str
) -> None:
    bound_manifest, promoted = _promotable(manifest, evidence)
    stats = promoted["performance"]["workloads"][0]["stats"]
    stats[field] = stats[field] + 1 if stats[field] is not None else 1.0

    _assert_code(
        validate_enron_evidence(promoted, manifest=bound_manifest, trusted_lineage_prefix=[]),
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
    _refresh_workload(workload)
    _drop_performance_assertions(value)

    assert (workload["stats"]["p95_seconds"] is not None) is has_p95
    assert (workload["stats"]["p99_seconds"] is not None) is has_p99
    assert validate_enron_evidence(value) == {"valid": True, "diagnostics": []}


def test_promoted_performance_requires_at_least_one_hundred_samples(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, promoted = _promotable(manifest, evidence)
    workload = promoted["performance"]["workloads"][0]
    workload["samples_seconds"] = workload["samples_seconds"][:99]

    _assert_code(
        validate_enron_evidence(promoted, manifest=bound_manifest, trusted_lineage_prefix=[]),
        "contract.invalid_performance_gate",
    )


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


def test_referenced_samples_can_support_promotion(manifest: JsonObject, evidence: JsonObject) -> None:
    bound_manifest, promoted = _promotable(manifest, evidence)
    workload = promoted["performance"]["workloads"][0]
    samples = list(workload["samples_seconds"])
    workload["samples_seconds"] = []
    workload["samples_ref"] = {
        "id": "decision_samples",
        "sha256": hash_enron_samples(samples),
        "bytes": _sample_payload_bytes(samples),
    }

    assert validate_enron_evidence(
        promoted,
        manifest=bound_manifest,
        trusted_lineage_prefix=[],
        referenced_samples={"decision_samples": samples},
    ) == {"valid": True, "diagnostics": []}


@pytest.mark.parametrize(
    ("phase", "process_model", "code"),
    [
        ("direct_bank_scan", "fresh_process_per_sample", "contract.direct_scan_process_model"),
        ("cold_compile", "reused_process", "contract.cold_compile_process_model"),
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


@pytest.mark.parametrize(
    "unsafe",
    [
        "/private/source.jsonl",
        "--source=/private/source.jsonl",
        r"C:\Users\fixture\source.jsonl",
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
        ("access", "/Users/fixture/private/source", "contract.public_private_path"),
    ],
)
def test_entire_public_serialization_is_scanned_for_identifiers_and_paths(
    manifest: JsonObject, field: str, value: str, code: str
) -> None:
    manifest["source"][field] = value

    _assert_code(validate_enron_manifest(manifest), code)


def test_privacy_pass_cannot_hide_raw_text_identifiers_or_violations(manifest: JsonObject) -> None:
    manifest["privacy"]["raw_text_included"] = True
    manifest["privacy"]["direct_identifiers_included"] = True
    manifest["privacy"]["violation_count"] = 2

    _assert_code(validate_enron_manifest(manifest), "contract.forged_privacy_pass")


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


def test_contract_loaders_reject_directories(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="regular non-symlink"):
        load_enron_manifest(tmp_path)


def test_contract_loaders_reject_oversized_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(enron_contract, "MAX_CONTRACT_BYTES", 64)
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"{" + b" " * 64 + b"}")

    with pytest.raises(ValueError, match="exceeds"):
        load_enron_manifest(oversized)


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
    bound_manifest, promoted = _promotable(manifest, evidence)
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
        validate_enron_evidence(promoted, manifest=bound_manifest, trusted_lineage_prefix=[]),
    ]

    for value in successful_values:
        json.dumps(value, allow_nan=False)

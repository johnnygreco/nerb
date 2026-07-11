from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import nerb.enron_performance as performance_module
from nerb.bank import bank_stats, canonicalize_bank, hash_bank
from nerb.enron_contract import (
    PERFORMANCE_PHASE_PROCESS_MODELS,
    PERFORMANCE_SCALE_PATTERNS,
    hash_enron_performance_bank,
    hash_enron_performance_input,
    hash_enron_performance_manifest,
    hash_enron_workload,
    summarize_enron_performance_inventory,
)
from nerb.enron_performance import (
    EnronPerformanceError,
    EnronPerformancePrepareOptions,
    EnronPerformanceRunOptions,
    prepare_enron_performance_manifest,
    run_enron_performance,
    verify_enron_performance_run,
)
from nerb.enron_performance_fixtures import (
    EnronPerformanceBankFixture,
    EnronPerformanceInputFixture,
    EnronPerformanceInventoryRow,
)

_HASH_1 = "sha256:" + "1" * 64
_HASH_2 = "sha256:" + "2" * 64
_GENERATOR = {
    "id": "safe_test_generator",
    "version": "1.0.0",
    "source_sha256": _HASH_1,
    "spec_sha256": _HASH_2,
    "seed": "safe-test-seed",
}


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _artifact(identifier: str, payload: bytes) -> dict[str, Any]:
    return {"id": identifier, "sha256": _sha256(payload), "bytes": len(payload)}


def _evaluated_descriptor() -> dict[str, Any]:
    payload = b'{"safe":"evaluated-bank"}'
    descriptor: dict[str, Any] = {
        "id": "evaluated_bank",
        "kind": "evaluated_bank",
        "bank_hash": _sha256(b"evaluated-bank-hash"),
        "artifact": _artifact("evaluated_bank_artifact", payload),
        "generator": None,
        "composition": {
            "taxonomy": [
                {
                    "entity_class": "contact",
                    "entities": 1,
                    "canonical_names": 501,
                    "aliases": 0,
                    "literal_patterns": 500,
                    "regex_patterns": 1,
                },
                {
                    "entity_class": "person",
                    "entities": 1,
                    "canonical_names": 0,
                    "aliases": 127,
                    "literal_patterns": 127,
                    "regex_patterns": 0,
                },
            ]
        },
        "descriptor_sha256": "",
        "active_entities": 2,
        "active_names": 628,
        "active_aliases": 127,
        "active_patterns": 628,
        "canonical_json_bytes": len(payload),
        "native_source_bytes": len(payload),
    }
    descriptor["descriptor_sha256"] = hash_enron_performance_bank(descriptor)
    return descriptor


def _fake_bank_fixtures() -> tuple[EnronPerformanceBankFixture, ...]:
    fixtures: list[EnronPerformanceBankFixture] = []
    for active_patterns in PERFORMANCE_SCALE_PATTERNS:
        identifier = f"scale_{active_patterns}"
        source = _canonical({"SAFE": {identifier: f"TOKEN_{active_patterns}"}})
        canonical = _canonical({"schema": 1, "safe_id": identifier})
        aliases = active_patterns // 5
        contact_patterns = active_patterns - aliases
        descriptor: dict[str, Any] = {
            "id": identifier,
            "kind": "synthetic_scale",
            "bank_hash": _sha256(f"bank:{identifier}".encode()),
            "artifact": _artifact(f"{identifier}_canonical_bank", canonical),
            "generator": dict(_GENERATOR),
            "composition": {
                "taxonomy": [
                    {
                        "entity_class": "contact",
                        "entities": 1,
                        "canonical_names": contact_patterns,
                        "aliases": 0,
                        "literal_patterns": contact_patterns,
                        "regex_patterns": 0,
                    },
                    {
                        "entity_class": "person",
                        "entities": 1,
                        "canonical_names": 0,
                        "aliases": aliases,
                        "literal_patterns": aliases,
                        "regex_patterns": 0,
                    },
                ]
            },
            "descriptor_sha256": "",
            "active_entities": 2,
            "active_names": active_patterns,
            "active_aliases": aliases,
            "active_patterns": active_patterns,
            "canonical_json_bytes": len(canonical),
            "native_source_bytes": len(source),
        }
        descriptor["descriptor_sha256"] = hash_enron_performance_bank(descriptor)
        fixtures.append(
            EnronPerformanceBankFixture(
                id=identifier,
                source_artifact_id=f"{identifier}_native_source",
                source_filename=f"banks/{identifier}.native.jsonl",
                canonical_artifact_id=f"{identifier}_canonical_bank",
                canonical_filename=f"banks/{identifier}.canonical.json",
                source_bytes=source,
                canonical_bytes=canonical,
                source_sha256=_sha256(source),
                bank_hash=descriptor["bank_hash"],
                canonical_sha256=_sha256(canonical),
                descriptor_bytes=_canonical(descriptor),
                preflight_record_count=0,
                _hit_tokens=(),
            )
        )
    return tuple(fixtures)


def _input_descriptor(
    identifier: str,
    *,
    bank: Mapping[str, Any],
    kind: str = "synthetic_input",
    documents: Sequence[bytes] = (b"safe",) * 100,
    records: Sequence[int] | None = None,
) -> tuple[dict[str, Any], bytes, bytes, tuple[EnronPerformanceInventoryRow, ...]]:
    record_counts = tuple(0 for _ in documents) if records is None else tuple(records)
    assert len(documents) == len(record_counts)
    inventory = [
        {"bytes": len(document), "records": record_count}
        for document, record_count in zip(documents, record_counts, strict=True)
    ]
    raw = b"".join(documents)
    inventory_bytes = _canonical(inventory)
    descriptor: dict[str, Any] = {
        "id": identifier,
        "kind": kind,
        "bank_id": bank["id"],
        "bank_hash": bank["bank_hash"],
        "artifact": _artifact(f"{identifier}_documents", raw),
        "inventory_ref": _artifact(f"{identifier}_inventory", inventory_bytes),
        "generator": None if kind == "real_input" else dict(_GENERATOR),
        **summarize_enron_performance_inventory(inventory),
        "descriptor_sha256": "",
    }
    descriptor["descriptor_sha256"] = hash_enron_performance_input(descriptor)
    rows = tuple(
        EnronPerformanceInventoryRow(byte_count=len(document), record_count=record_count)
        for document, record_count in zip(documents, record_counts, strict=True)
    )
    return descriptor, raw, inventory_bytes, rows


def _fake_input_fixtures(
    bank_fixtures: Sequence[EnronPerformanceBankFixture],
) -> tuple[EnronPerformanceInputFixture, ...]:
    bank_by_id = {fixture.id: fixture.descriptor for fixture in bank_fixtures}
    inputs: list[EnronPerformanceInputFixture] = []
    identifiers = [
        *(f"scale_{active_patterns}_input" for active_patterns in PERFORMANCE_SCALE_PATTERNS),
        *(f"density_{density}_input" for density in ("sparse", "normal", "dense")),
        *(f"size_{size}_input" for size in ("small", "large", "huge")),
    ]
    for identifier in identifiers:
        if identifier.startswith("scale_"):
            bank_id = identifier.removesuffix("_input")
        else:
            bank_id = "scale_1000"
        descriptor, raw, inventory_bytes, rows = _input_descriptor(
            identifier,
            bank=bank_by_id[bank_id],
        )
        inputs.append(
            EnronPerformanceInputFixture(
                id=identifier,
                artifact_id=descriptor["artifact"]["id"],
                artifact_filename=f"inputs/{identifier}.raw",
                inventory_id=descriptor["inventory_ref"]["id"],
                inventory_filename=f"inputs/{identifier}.inventory.json",
                artifact_bytes=raw,
                inventory_bytes=inventory_bytes,
                documents=(b"safe",) * 100,
                inventory_rows=rows,
                descriptor_bytes=_canonical(descriptor),
            )
        )
    return tuple(inputs)


def _make_plan(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    monkeypatch.setattr(performance_module, "_source_sha256", lambda _paths: _HASH_1)
    bank_fixtures = _fake_bank_fixtures()
    evaluated = _evaluated_descriptor()
    real_input, _raw, _inventory, _rows = _input_descriptor(
        "real_validation_input",
        bank=evaluated,
        kind="real_input",
    )
    return performance_module._performance_plan(
        benchmark_version="safe-benchmark-v2",
        source_profile_artifact=_artifact("development_train", b"safe-train"),
        source_build_artifact=_artifact("development_train", b"safe-train"),
        evaluated_bank=evaluated,
        bank_fixtures=bank_fixtures,
        real_input=real_input,
        input_fixtures=_fake_input_fixtures(bank_fixtures),
        concurrency=4,
        source_curation_seconds=60.0,
    )


@pytest.fixture
def performance_plan(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    return _make_plan(monkeypatch)


def test_plan_freezes_exact_matrix_controls_comparisons_and_hashes(
    performance_plan: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    repeated = _make_plan(monkeypatch)
    assert repeated == performance_plan
    assert performance_plan["scale_axis"] == "active_matcher_patterns"
    assert performance_plan["catalog_aliases_reported_separately"] is True
    assert performance_plan["plan_sha256"] == performance_module._canonical_hash(
        {key: value for key, value in performance_plan.items() if key != "plan_sha256"}
    )

    decision = performance_plan["profiles"]["decision"]
    performance = decision["performance"]
    workloads = {item["id"]: item for item in performance["workloads"]}
    candidates = [item for item in workloads.values() if item["decision_grade"]]
    controls = [item for item in workloads.values() if item["id"].startswith("control_")]
    exploratory = [item for item in workloads.values() if item["id"].startswith("explore_")]
    assert len(candidates) == 19
    assert len(controls) == 19
    assert len(exploratory) == 2
    assert len(performance["comparisons"]) == 46
    cross_path = [item for item in performance["comparisons"] if item["comparison_kind"] == "cross_path_value"]
    assert len(cross_path) == 12
    assert {item["noise_method"] for item in cross_path} == {"paired_block_ratio_mad"}
    assert len(performance["breakeven_models"]) == 1
    assert decision["performance_manifest_sha256"] == hash_enron_performance_manifest(performance)
    assert all(item["workload_sha256"] == hash_enron_workload(item) for item in workloads.values())

    baseline_by_id = {item["id"]: item for item in performance["baselines"]}
    assert baseline_by_id[performance_module.PERFORMANCE_EXACT_CONTROL_ID]["semantic_equivalence"] == "exact"
    assert baseline_by_id[performance_module.PERFORMANCE_UNCACHED_BASELINE_ID]["semantic_equivalence"] == "exact"
    for candidate in candidates:
        control = workloads[f"control_{candidate['id']}"]
        for field in (
            "phase",
            "harness_id",
            "harness_sha256",
            "bank_id",
            "bank_hash",
            "input_id",
            "input_sha256",
            "warmups",
            "sample_unit",
            "work_per_sample",
            "concurrency",
            "process_model",
        ):
            assert control[field] == candidate[field]
    tail_metrics = [
        item["metric"]
        for item in performance["comparisons"]
        if item["metric"].startswith("p") and item["comparison_kind"] == "same_path_stability"
    ]
    assert tail_metrics.count("p95_seconds") == 3
    assert tail_metrics.count("p99_seconds") == 16


def test_smoke_plan_is_explicitly_nonpromotable(performance_plan: dict[str, Any]) -> None:
    smoke = performance_plan["profiles"]["smoke"]
    performance = smoke["performance"]
    assert smoke["sample_policy"] == {
        "setup_samples": 5,
        "scan_samples": 5,
        "document_samples": None,
        "warmups": 3,
        "interleaving": "candidate_only",
        "promotable": False,
    }
    assert len(performance["workloads"]) == 9
    assert not any(item["decision_grade"] or item["promotion_gate"] for item in performance["workloads"])
    assert not any(item["id"].startswith("control_") for item in performance["workloads"])
    assert performance["comparisons"] == []
    assert performance["breakeven_models"] == []
    assert smoke["performance_manifest_sha256"] == hash_enron_performance_manifest(performance)


def test_plan_reports_aliases_separately_from_matcher_patterns(performance_plan: dict[str, Any]) -> None:
    banks = {item["id"]: item for item in performance_plan["profiles"]["decision"]["performance"]["banks"]}
    assert banks["evaluated_bank"]["active_aliases"] == 127
    assert banks["evaluated_bank"]["active_patterns"] == 628
    for active_patterns in PERFORMANCE_SCALE_PATTERNS:
        bank = banks[f"scale_{active_patterns}"]
        assert bank["active_patterns"] == active_patterns
        assert bank["active_aliases"] == active_patterns // 5
        assert bank["active_aliases"] != bank["active_patterns"]
        taxonomy = bank["composition"]["taxonomy"]
        assert sum(item["literal_patterns"] + item["regex_patterns"] for item in taxonomy) == active_patterns
        assert sum(item["aliases"] for item in taxonomy) == bank["active_aliases"]


@pytest.mark.parametrize(
    ("sample_count", "expected"),
    [
        (1, ("candidate", "control")),
        (2, ("candidate", "control", "control", "candidate")),
        (
            5,
            (
                "candidate",
                "control",
                "control",
                "candidate",
                "candidate",
                "control",
                "control",
                "candidate",
                "candidate",
                "control",
            ),
        ),
    ],
)
def test_exact_controls_use_balanced_abba_order(sample_count: int, expected: tuple[str, ...]) -> None:
    assert performance_module._interleaved_labels(sample_count) == expected


def test_exact_cache_value_schedule_balances_paths_inside_abba_rounds() -> None:
    paths = performance_module.PERFORMANCE_EXACT_VALUE_PATHS
    schedule = performance_module._exact_value_schedule(4)
    expected_rounds = (
        (paths[0], paths[1], paths[3], paths[2]),
        tuple(f"control_{paths[index]}" for index in (1, 2, 0, 3)),
        tuple(f"control_{paths[index]}" for index in (2, 3, 1, 0)),
        (paths[3], paths[0], paths[2], paths[1]),
        (paths[1], paths[2], paths[0], paths[3]),
        tuple(f"control_{paths[index]}" for index in (0, 1, 3, 2)),
        tuple(f"control_{paths[index]}" for index in (3, 0, 2, 1)),
        (paths[2], paths[3], paths[1], paths[0]),
    )

    assert tuple(tuple(schedule[index : index + 4]) for index in range(0, len(schedule), 4)) == expected_rounds
    assert len(schedule) == 32
    assert all(schedule.count(identifier) == 4 for round_ids in expected_rounds for identifier in round_ids)


def test_materialization_recomputes_statistics_comparisons_and_breakeven(
    performance_plan: dict[str, Any],
) -> None:
    performance = performance_plan["profiles"]["decision"]["performance"]
    workload_by_id = {item["id"]: item for item in performance["workloads"]}
    input_by_id = {item["id"]: item for item in performance["inputs"]}
    candidate_plan = workload_by_id["real_direct_throughput"]
    control_plan = workload_by_id["control_real_direct_throughput"]
    candidate_observations = [
        {"elapsed_ns": 1_000_000 + index, "record_count": 0, "peak_rss_bytes": 64 * 1024 * 1024} for index in range(100)
    ]
    control_observations = [
        {"elapsed_ns": 2_000_000 + index, "record_count": 0, "peak_rss_bytes": 65 * 1024 * 1024} for index in range(100)
    ]
    candidate = performance_module._materialize_workload(
        candidate_plan,
        candidate_observations,
        input_by_id,
        require_rss=True,
    )
    control = performance_module._materialize_workload(
        control_plan,
        control_observations,
        input_by_id,
        require_rss=True,
    )
    comparison_plan = performance_module._comparison_plan(candidate_plan, control_plan, "mib_per_second")
    comparison = performance_module._materialize_comparison(
        comparison_plan,
        {candidate["id"]: candidate, control["id"]: control},
    )

    assert candidate["stats"]["sample_count"] == 100
    assert candidate["stats"]["p99_seconds"] == candidate["samples_seconds"][98]
    assert candidate["peak_rss_bytes"] == 64 * 1024 * 1024
    assert comparison["direction"] == "higher_is_better"
    assert comparison["result"] == "improved"

    candidates = {
        identifier: {"id": identifier}
        for identifier in (
            "real_source_profile",
            "real_source_build",
            "real_cold_compile",
            "real_helper_cache_miss",
            "real_direct_throughput",
        )
    }
    breakeven_plan = performance_module._breakeven_plan(
        candidates,
        source_curation_seconds=6.0,
    )
    measured = {
        "real_helper_cache_miss": {"stats": {"seconds_per_document": 1.0}},
        "real_source_build": {"stats": {"median_seconds": 2.0}},
        "real_cold_compile": {"stats": {"median_seconds": 1.0}},
        "real_source_profile": {"stats": {"median_seconds": 1.0}},
        "real_direct_throughput": {"stats": {"seconds_per_document": 0.5}},
    }
    breakeven = performance_module._materialize_breakeven(breakeven_plan, measured)
    assert breakeven["candidate_fixed_value"] == 10.0
    assert breakeven["baseline_fixed_value"] == 9.0
    assert breakeven["candidate_value_per_unit"] == 0.5
    assert breakeven["baseline_value_per_unit"] == 1.0
    assert breakeven["result"] == "finite_breakeven"
    assert breakeven["breakeven_units"] == 2


def _valid_worker_result(request: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": performance_module.RESULT_SCHEMA_VERSION,
        "nonce": request["nonce"],
        "workload_sha256": request["workload_sha256"],
        "pid": 7,
        "status": "ok",
        "error_code": None,
        "elapsed_ns": 123,
        "peak_rss_bytes": 4_096,
        "peak_rss_status": "supported",
        "record_count": 0,
        "correctness_sha256": _HASH_2,
    }


@pytest.mark.parametrize(
    "mutation",
    [
        {"extra_private_text": "SAFE_PRIVATE_FIXTURE_TOKEN"},
        {"nonce": "wrong-nonce"},
        {"status": "error", "error_code": "operation_failed"},
        {"elapsed_ns": 0},
        {"correctness_sha256": "invalid"},
        {"peak_rss_bytes": 0},
        {"peak_rss_status": "unknown"},
    ],
)
def test_worker_result_protocol_rejects_shape_and_binding_changes_without_echoing_payload(
    mutation: dict[str, Any],
) -> None:
    request = {"nonce": "safe-nonce", "workload_sha256": _HASH_1}
    result = {**_valid_worker_result(request), **mutation}
    with pytest.raises(EnronPerformanceError) as error:
        performance_module._decode_worker_result(_canonical(result), request)
    assert "SAFE_PRIVATE_FIXTURE_TOKEN" not in str(error.value)


@pytest.mark.parametrize(
    "payload_mutation",
    [
        lambda payload: payload.replace(
            b'"nonce":"safe-nonce"',
            b'"nonce":"duplicate-safe-value","nonce":"safe-nonce"',
            1,
        ),
        lambda payload: payload.replace(b'"elapsed_ns":123', b'"elapsed_ns":NaN', 1),
    ],
)
def test_worker_result_protocol_rejects_duplicate_keys_and_nonfinite_json(
    payload_mutation: Any,
) -> None:
    request = {"nonce": "safe-nonce", "workload_sha256": _HASH_1}
    payload = payload_mutation(_canonical(_valid_worker_result(request)))
    with pytest.raises(EnronPerformanceError, match="invalid aggregate JSON"):
        performance_module._decode_worker_result(payload, request)


@pytest.mark.parametrize(
    ("peak_rss_bytes", "peak_rss_status"),
    [(None, "supported"), (4_096, "unsupported_platform"), (4_096, "resource_unavailable")],
)
def test_worker_result_protocol_rejects_inconsistent_rss_support(
    peak_rss_bytes: int | None,
    peak_rss_status: str,
) -> None:
    request = {"nonce": "safe-nonce", "workload_sha256": _HASH_1}
    result = {
        **_valid_worker_result(request),
        "peak_rss_bytes": peak_rss_bytes,
        "peak_rss_status": peak_rss_status,
    }
    with pytest.raises(EnronPerformanceError, match="RSS"):
        performance_module._decode_worker_result(_canonical(result), request)


def test_unsupported_rss_is_nonpromotable_but_valid_for_smoke(performance_plan: dict[str, Any]) -> None:
    performance = performance_plan["profiles"]["smoke"]["performance"]
    workload = next(item for item in performance["workloads"] if item["id"] == "real_direct_throughput")
    inputs = {item["id"]: item for item in performance["inputs"]}
    observations = [{"elapsed_ns": 1_000_000, "record_count": 0, "peak_rss_bytes": None} for _ in range(5)]

    materialized = performance_module._materialize_workload(workload, observations, inputs, require_rss=False)
    assert materialized["rss_samples_bytes"] == []
    assert materialized["peak_rss_bytes"] is None
    with pytest.raises(EnronPerformanceError, match="RSS"):
        performance_module._materialize_workload(workload, observations, inputs, require_rss=True)


def test_source_build_worker_never_echoes_exception_text_or_invalid_correlation_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        performance_module,
        "build_enron_intelligence_bank",
        lambda _options: (_ for _ in ()).throw(RuntimeError("SAFE_PRIVATE_FIXTURE_TOKEN")),
    )
    monkeypatch.setattr(performance_module, "_source_build_peak_rss", lambda: (None, "resource_unavailable"))
    monkeypatch.setattr(performance_module.tempfile, "gettempdir", lambda: str(tmp_path))
    temporary_root = tmp_path / "nerb-performance-build-test"
    temporary_root.mkdir()
    request = {
        "schema_version": "nerb.enron_performance_source_build_request.v1",
        "nonce": "safe-nonce",
        "workload_sha256": _HASH_1,
        "development_run": str(tmp_path.resolve()),
        "annotation_run": None,
        "cmu_catalog_bindings": None,
        "benchmark_version": "safe-v2",
        "created_at": "2026-07-11T00:00:00Z",
        "expected_projection_sha256": _HASH_2,
        "output_dir": str((temporary_root / "build").resolve()),
    }
    failed = performance_module._source_build_worker_result(_canonical(request))
    serialized = _canonical(failed).decode("ascii")
    assert failed["error_code"] == "operation_failed"
    assert "SAFE_PRIVATE_FIXTURE_TOKEN" not in serialized
    assert str(tmp_path) not in serialized

    request["nonce"] = "synthetic.person@example.invalid"
    rejected = performance_module._source_build_worker_result(_canonical(request))
    assert rejected["status"] == "error"
    assert rejected["error_code"] == "request_shape"
    assert rejected["nonce"] is None
    assert "@" not in _canonical(rejected).decode("ascii")


def test_source_build_parent_removes_private_temp_tree_after_forced_child_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(performance_module.tempfile, "tempdir", str(tmp_path))
    temporary_roots: list[Path] = []

    def fail_after_private_write(
        _command: Sequence[str],
        request: Mapping[str, Any],
        **_kwargs: Any,
    ) -> tuple[bytes, int]:
        output_dir = Path(str(request["output_dir"]))
        output_dir.mkdir(parents=True)
        (output_dir / "private-artifact.json").write_text("private fixture", encoding="utf-8")
        temporary_roots.append(output_dir.parent)
        raise EnronPerformanceError("Source-build performance worker exceeded its fixed boundary.")

    monkeypatch.setattr(performance_module, "_run_bounded_fresh_process", fail_after_private_write)
    with pytest.raises(EnronPerformanceError, match="fixed boundary"):
        performance_module._run_source_build_once(
            {"nonce": "safe-nonce", "workload_sha256": _HASH_1},
            timeout_seconds=0.1,
        )

    assert len(temporary_roots) == 1
    assert not temporary_roots[0].exists()


def test_evaluated_descriptor_keeps_real_catalog_aliases_truthful(test_data_path: Path) -> None:
    bank = json.loads((test_data_path / "enron_bank_v2_fake.json").read_text(encoding="utf-8"))
    payload = _canonical(bank)
    artifact = performance_module._artifact_from_bytes("evaluated_bank_artifact", "banks/evaluated.json", payload)
    descriptor = performance_module._evaluated_bank_descriptor(bank, artifact, native_source_bytes=321)
    taxonomy = {item["entity_class"]: item for item in descriptor["composition"]["taxonomy"]}

    assert descriptor["active_patterns"] == 3
    assert descriptor["active_aliases"] == 1
    assert descriptor["active_aliases"] != descriptor["active_patterns"]
    assert taxonomy["contact"]["canonical_names"] == 2
    assert taxonomy["contact"]["aliases"] == 0
    assert taxonomy["person"]["canonical_names"] == 0
    assert taxonomy["person"]["aliases"] == 1
    assert descriptor["descriptor_sha256"] == hash_enron_performance_bank(descriptor)


def _prepare_run(
    tmp_path: Path,
    test_data_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    name: str,
    real_fixtures: bool = False,
    snapshot_bank_payload: bytes | None = None,
) -> Path:
    bank_run = tmp_path / f"{name}-bank-build"
    bank_run.mkdir()
    bank = json.loads((test_data_path / "enron_bank_v2_fake.json").read_text(encoding="utf-8"))
    bank_payload = _canonical(bank)
    development_run = tmp_path / f"{name}-development"
    development_run.mkdir()
    train_payload = b'{"safe":"train"}\n'
    (development_run / "train.jsonl").write_bytes(train_payload)
    stats = bank_stats(bank)
    card = {
        "benchmark_version": "safe-benchmark-v2",
        "fixture_mode": False,
        "promotable": False,
        "run_sha256": _HASH_1,
        "source": {
            "development_manifest_sha256": _HASH_2,
            "train_artifact_sha256": _sha256(train_payload),
            "train_records": 1,
            "sealed_test_accessed": False,
        },
        "builder": {
            "candidate_source_sha256": _HASH_1,
            "candidate_ledger_sha256": _HASH_2,
            "source_sha256": performance_module._builder_implementation_sha256(),
            "policy_sha256": performance_module.EnronBankPolicy().sha256,
        },
        "bank": {
            "artifact_sha256": _sha256(bank_payload),
            "artifact_bytes": len(bank_payload),
            "canonical_sha256": hash_bank(bank),
            "canonical_json_bytes": len(_canonical(canonicalize_bank(bank))),
            "stats": stats,
        },
        "iterations": [
            {
                "id": "selected-safe",
                "selected": True,
                "active_patterns": stats["active_totals"]["patterns"],
            }
        ],
        "catalog_conformance": {
            "active_patterns": stats["active_totals"]["patterns"],
            "approved_positive_cases": 3,
            "correctly_mapped": 3,
            "missed": 0,
            "wrong_canonical": 0,
            "negative_cases": 1,
            "unexpected_negative_matches": 0,
            "passed": True,
        },
        "privacy": {"status": "passed"},
    }
    development = SimpleNamespace(
        manifest={
            "development_roles": {
                "train": {
                    "records": 1,
                    "artifact": {
                        "id": "development_train",
                        "sha256": _sha256(train_payload),
                        "bytes": len(train_payload),
                    },
                }
            }
        },
        manifest_sha256=_HASH_2,
    )

    class _SafeNativeBank:
        def scan_bytes(self, _document: bytes) -> list[Any]:
            return []

    verification = {
        "valid": True,
        "benchmark_version": card["benchmark_version"],
        "fixture_mode": card["fixture_mode"],
        "promotable": card["promotable"],
        "bank_sha256": card["bank"]["canonical_sha256"],
        "bank_card_run_sha256": card.get("run_sha256"),
        "sealed_test_accessed": card["source"]["sealed_test_accessed"],
        "privacy": card["privacy"],
    }
    bank_snapshot = SimpleNamespace(
        summary=verification,
        card=card,
        bank=bank,
        bank_payload=bank_payload if snapshot_bank_payload is None else snapshot_bank_payload,
        validation_documents=tuple(
            {"document_id": f"doc_{index:03d}", "text": f"safe validation text {index}"} for index in range(100)
        ),
        build_created_at="2026-07-11T00:00:00Z",
    )
    monkeypatch.setattr(
        performance_module,
        "_verify_enron_bank_build_snapshot",
        lambda *_args, **_kwargs: bank_snapshot,
    )
    monkeypatch.setattr(performance_module, "load_enron_development_split", lambda _path: development)
    monkeypatch.setattr(
        performance_module,
        "compile_bank_with_report",
        lambda _bank: (
            SimpleNamespace(native_bank=_SafeNativeBank()),
            False,
            {"source": {"extractable_json_bytes": 321}},
        ),
    )
    if not real_fixtures:
        bank_fixtures = _fake_bank_fixtures()
        monkeypatch.setattr(
            performance_module,
            "make_enron_performance_bank_fixtures",
            lambda *, evaluated_bank: bank_fixtures,
        )
        monkeypatch.setattr(
            performance_module,
            "make_enron_performance_input_fixtures",
            lambda fixtures: _fake_input_fixtures(fixtures),
        )
    monkeypatch.setattr(performance_module, "_source_sha256", lambda _paths: _HASH_1)
    output = tmp_path / f"{name}-prepared-output"
    summary = prepare_enron_performance_manifest(
        EnronPerformancePrepareOptions(
            bank_build_run=bank_run,
            development_run=development_run,
            output_dir=output,
            concurrency=2,
            allow_unignored_output=True,
        )
    )
    assert summary["committed"] is True
    assert summary["banks"] == 5
    assert summary["inputs"] == 11
    assert summary["decision_workloads"] == 40
    assert summary["sealed_test_accessed"] is False
    return output


def test_prepare_rejects_snapshot_bank_bytes_that_do_not_match_verified_card(
    tmp_path: Path,
    test_data_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(EnronPerformanceError, match="differs from its verified bank card"):
        _prepare_run(
            tmp_path,
            test_data_path,
            monkeypatch,
            name="mismatched-snapshot-bank",
            snapshot_bank_payload=b"{}",
        )

    assert not (tmp_path / "mismatched-snapshot-bank-prepared-output").exists()


def _aggregate_observations(
    workload: Mapping[str, Any],
    sample_count: int,
    *,
    control: bool = False,
    sequences: Sequence[int] | None = None,
) -> list[dict[str, Any]]:
    base_identifier = str(workload["id"]).removeprefix("control_")
    digest_group = (
        "exact-real-cache-value"
        if base_identifier
        in {"real_direct_throughput", "real_helper_cache_hit", "real_helper_cache_miss", "real_end_to_end"}
        else base_identifier
    )
    digest = _sha256(f"correctness:{digest_group}".encode())
    base_ns = 2_200_000 if control else 2_000_000
    resolved_sequences = list(range(sample_count)) if sequences is None else list(sequences)
    reused_pid = 10_000 + int.from_bytes(hashlib.sha256(str(workload["id"]).encode()).digest()[:4], "big")
    return [
        {
            "sequence": sequence,
            "pid": reused_pid if workload["process_model"] == "reused_process" else 10_000 + sequence,
            "record_count": 0,
            "correctness_sha256": digest,
            "elapsed_ns": base_ns + index,
            "peak_rss_bytes": 64 * 1024 * 1024,
        }
        for index, sequence in enumerate(resolved_sequences)
    ]


def _patch_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    def execute_workload(
        workload: Mapping[str, Any],
        _performance: Mapping[str, Any],
        _prepared: Any,
        *,
        sample_count: int,
        worker_timeout_seconds: float,
        source_build_timeout_seconds: float,
        sequence_start: int,
    ) -> tuple[list[dict[str, Any]], int]:
        assert worker_timeout_seconds > 0
        assert source_build_timeout_seconds > 0
        sequences = list(range(sequence_start, sequence_start + sample_count))
        return _aggregate_observations(workload, sample_count, sequences=sequences), sequence_start + sample_count

    def execute_pair(
        candidate: Mapping[str, Any],
        control: Mapping[str, Any],
        _performance: Mapping[str, Any],
        _prepared: Any,
        *,
        sample_count: int,
        worker_timeout_seconds: float,
        source_build_timeout_seconds: float,
        sequence_start: int,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
        assert worker_timeout_seconds > 0
        assert source_build_timeout_seconds > 0
        labels = performance_module._interleaved_labels(sample_count)
        candidate_sequences = [sequence_start + index for index, label in enumerate(labels) if label == "candidate"]
        control_sequences = [sequence_start + index for index, label in enumerate(labels) if label == "control"]
        return (
            _aggregate_observations(candidate, sample_count, sequences=candidate_sequences),
            _aggregate_observations(control, sample_count, control=True, sequences=control_sequences),
            sequence_start + sample_count * 2,
        )

    def execute_exact_value_block(
        workloads: Mapping[str, Mapping[str, Any]],
        _performance: Mapping[str, Any],
        _prepared: Any,
        *,
        sample_count: int,
        worker_timeout_seconds: float,
        source_build_timeout_seconds: float,
        sequence_start: int,
    ) -> tuple[dict[str, list[dict[str, Any]]], int]:
        assert worker_timeout_seconds > 0
        assert source_build_timeout_seconds > 0
        schedule = performance_module._exact_value_schedule(sample_count)
        results = {identifier: [] for identifier in set(schedule)}
        for offset, identifier in enumerate(schedule):
            observation = _aggregate_observations(
                workloads[identifier],
                1,
                control=identifier.startswith("control_"),
                sequences=[sequence_start + offset],
            )[0]
            results[identifier].append(observation)
        return results, sequence_start + len(schedule)

    monkeypatch.setattr(performance_module, "_execute_workload", execute_workload)
    monkeypatch.setattr(performance_module, "_execute_pair", execute_pair)
    monkeypatch.setattr(performance_module, "_execute_exact_value_block", execute_exact_value_block)
    monkeypatch.setattr(
        performance_module,
        "_environment",
        lambda: {
            "os": "SyntheticOS",
            "architecture": "safe-arch",
            "python": "3.13.0",
            "cpu_count": 4,
            "cpu_model": "Safe Test CPU",
            "memory_bytes": 16 * 1024**3,
        },
    )
    monkeypatch.setattr(
        performance_module,
        "_software",
        lambda: {
            "package_version": "0.0.0-safe",
            "engine_version": "safe-engine",
            "git_commit": "0" * 40,
            "git_dirty": False,
        },
    )


def test_prepared_and_smoke_runs_commit_verify_and_detect_artifact_tampering(
    tmp_path: Path, test_data_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name="smoke")
    loaded = performance_module._load_prepared_performance_run(prepared)
    assert loaded.plan["plan_sha256"] == loaded.manifest["plan_sha256"]
    assert str(tmp_path) not in json.dumps(loaded.plan, sort_keys=True)
    _patch_execution(monkeypatch)
    output = tmp_path / "smoke-run"
    report = run_enron_performance(
        EnronPerformanceRunOptions(
            prepared_run=prepared,
            output_dir=output,
            profile="smoke",
            allow_unignored_output=True,
        )
    )

    assert report["decision_grade"] == {"passed": False, "failure_codes": ["smoke_profile_nonpromotable"]}
    assert report["privacy"] == {
        "status": "passed",
        "raw_text_included": False,
        "direct_identifiers_included": False,
        "private_paths_included": False,
        "violation_count": 0,
    }
    verified = verify_enron_performance_run(output)
    assert verified["valid"] is True
    assert verified["profile"] == "smoke"
    assert verified["sealed_test_accessed"] is False

    report_path = output / "report.json"
    report_path.write_bytes(report_path.read_bytes() + b" ")
    with pytest.raises(EnronPerformanceError, match="artifact"):
        verify_enron_performance_run(output)


def test_privacy_safe_smoke_routes_real_requests_through_worker_subprocesses(
    tmp_path: Path, test_data_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepare_run(
        tmp_path,
        test_data_path,
        monkeypatch,
        name="real-worker-smoke",
        real_fixtures=True,
    )
    output = tmp_path / "real-worker-smoke-run"
    report = run_enron_performance(
        EnronPerformanceRunOptions(
            prepared_run=prepared,
            output_dir=output,
            profile="smoke",
            allow_unignored_output=True,
        )
    )

    assert report["decision_grade"] == {"passed": False, "failure_codes": ["smoke_profile_nonpromotable"]}
    assert verify_enron_performance_run(output)["valid"] is True


def _rewrite_aggregate_report(output: Path, report: dict[str, Any]) -> None:
    report["run_sha256"] = performance_module._canonical_hash(
        {key: value for key, value in report.items() if key != "run_sha256"}
    )
    payload = performance_module._pretty_json_bytes(report)
    (output / "report.json").write_bytes(payload)
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    artifact = next(item for item in manifest["artifacts"] if item["id"] == "performance_report")
    artifact["sha256"] = _sha256(payload)
    artifact["bytes"] = len(payload)
    manifest["run_sha256"] = report["run_sha256"]
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def test_run_verifier_rejects_rehashed_free_text_and_forged_smoke_decision(
    tmp_path: Path, test_data_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name="closed-report")
    _patch_execution(monkeypatch)

    extra_output = tmp_path / "extra-report-field"
    extra_report = run_enron_performance(
        EnronPerformanceRunOptions(
            prepared_run=prepared,
            output_dir=extra_output,
            profile="smoke",
            allow_unignored_output=True,
        )
    )
    extra_report["unexpected_unstructured_text"] = "private free-form content"
    _rewrite_aggregate_report(extra_output, extra_report)
    with pytest.raises(EnronPerformanceError, match="closed envelope"):
        verify_enron_performance_run(extra_output)

    decision_output = tmp_path / "forged-smoke-decision"
    decision_report = run_enron_performance(
        EnronPerformanceRunOptions(
            prepared_run=prepared,
            output_dir=decision_output,
            profile="smoke",
            allow_unignored_output=True,
        )
    )
    decision_report["decision_grade"] = {"passed": True, "failure_codes": []}
    _rewrite_aggregate_report(decision_output, decision_report)
    with pytest.raises(EnronPerformanceError, match="decision-grade"):
        verify_enron_performance_run(decision_output)


def test_run_rejects_workload_concurrency_above_execution_host_before_measurement(
    tmp_path: Path, test_data_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name="undersized-host")
    _patch_execution(monkeypatch)
    monkeypatch.setattr(
        performance_module,
        "_environment",
        lambda: {
            "os": "SyntheticOS",
            "architecture": "safe-arch",
            "python": "3.13.0",
            "cpu_count": 1,
            "cpu_model": "Safe Test CPU",
            "memory_bytes": 16 * 1024**3,
        },
    )
    monkeypatch.setattr(
        performance_module,
        "_execute_workload",
        lambda *_args, **_kwargs: pytest.fail("measurement started before the execution-host capacity check"),
    )

    with pytest.raises(EnronPerformanceError, match="current CPU count"):
        run_enron_performance(
            EnronPerformanceRunOptions(
                prepared_run=prepared,
                output_dir=tmp_path / "undersized-host-run",
                profile="smoke",
                allow_unignored_output=True,
            )
        )


def test_run_rejects_stale_harness_source_before_measurement(
    tmp_path: Path, test_data_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name="stale-harness")
    _patch_execution(monkeypatch)
    monkeypatch.setattr(performance_module, "_performance_harness_source_sha256", lambda: _HASH_2)
    monkeypatch.setattr(
        performance_module,
        "_execute_workload",
        lambda *_args, **_kwargs: pytest.fail("measurement started with a stale harness fingerprint"),
    )

    with pytest.raises(EnronPerformanceError, match="harness source differs"):
        run_enron_performance(
            EnronPerformanceRunOptions(
                prepared_run=prepared,
                output_dir=tmp_path / "stale-harness-run",
                profile="smoke",
                allow_unignored_output=True,
            )
        )


def test_run_rejects_execution_source_change_during_measurement(
    tmp_path: Path, test_data_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name="changing-harness")
    frozen = performance_module._load_prepared_performance_run(prepared)
    frozen_source = frozen.plan["profiles"]["smoke"]["performance"]["harnesses"][0]["source_sha256"]
    _patch_execution(monkeypatch)
    fingerprints = iter((frozen_source, _HASH_2))
    monkeypatch.setattr(performance_module, "_performance_harness_source_sha256", lambda: next(fingerprints))

    with pytest.raises(EnronPerformanceError, match="changed during"):
        run_enron_performance(
            EnronPerformanceRunOptions(
                prepared_run=prepared,
                output_dir=tmp_path / "changing-harness-run",
                profile="smoke",
                allow_unignored_output=True,
            )
        )


@pytest.mark.parametrize(
    ("target", "message"),
    [
        ("evaluated", "evaluated status"),
        ("harness", "harness descriptor"),
        ("baseline", "baseline descriptor"),
    ],
)
def test_run_verifier_rejects_rehashed_unbound_descriptor_commitments(
    target: str,
    message: str,
    tmp_path: Path,
    test_data_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name=f"descriptor-{target}")
    _patch_execution(monkeypatch)
    output = tmp_path / f"descriptor-{target}-run"
    report = run_enron_performance(
        EnronPerformanceRunOptions(
            prepared_run=prepared,
            output_dir=output,
            profile="smoke",
            allow_unignored_output=True,
        )
    )
    if target == "evaluated":
        report["performance"]["evaluated"] = False
    elif target == "harness":
        report["performance"]["harnesses"][0]["descriptor_sha256"] = _HASH_1
    else:
        report["performance"]["baselines"][0]["descriptor_sha256"] = _HASH_1
    _rewrite_aggregate_report(output, report)

    with pytest.raises(EnronPerformanceError, match=message):
        verify_enron_performance_run(output)


def test_run_verifier_rejects_rehashed_peak_rss_that_disagrees_with_raw_samples(
    tmp_path: Path, test_data_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name="rss-aggregate")
    _patch_execution(monkeypatch)
    output = tmp_path / "rss-aggregate-run"
    report = run_enron_performance(
        EnronPerformanceRunOptions(
            prepared_run=prepared,
            output_dir=output,
            profile="decision",
            allow_unignored_output=True,
        )
    )
    decision_workload = next(item for item in report["performance"]["workloads"] if item["decision_grade"])
    decision_workload["peak_rss_bytes"] = max(decision_workload["rss_samples_bytes"]) - 1
    _rewrite_aggregate_report(output, report)

    with pytest.raises(EnronPerformanceError, match="RSS aggregation"):
        verify_enron_performance_run(output)


def test_run_verifier_rejects_rehashed_exact_record_denominator(
    tmp_path: Path, test_data_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name="record-denominator")
    _patch_execution(monkeypatch)
    output = tmp_path / "record-denominator-run"
    report = run_enron_performance(
        EnronPerformanceRunOptions(
            prepared_run=prepared,
            output_dir=output,
            profile="smoke",
            allow_unignored_output=True,
        )
    )
    performance = report["performance"]
    workload = next(item for item in performance["workloads"] if item["id"] == "real_direct_throughput")
    input_descriptor = next(item for item in performance["inputs"] if item["id"] == workload["input_id"])
    workload["records_per_sample"] = 1
    workload["stats"] = performance_module.calculate_enron_performance_statistics(
        workload["samples_seconds"],
        input_descriptor,
        phase=workload["phase"],
        sample_unit=workload["sample_unit"],
        work_per_sample=workload["work_per_sample"],
        records_per_sample=1,
    )
    _rewrite_aggregate_report(output, report)

    audit_path = output / "audit" / "results.jsonl"
    rows = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    audit = next(item for item in rows if item["workload_id"] == workload["id"])
    for sample in audit["samples"]:
        sample["record_count"] = 1
    audit_payload = b"".join(_canonical(item) + b"\n" for item in rows)
    audit_path.write_bytes(audit_payload)
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    audit_artifact = next(item for item in manifest["artifacts"] if item["id"] == "performance_audit")
    audit_artifact["sha256"] = _sha256(audit_payload)
    audit_artifact["bytes"] = len(audit_payload)
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(EnronPerformanceError, match="record denominator"):
        verify_enron_performance_run(output)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("cpu_count", 1, "recorded CPU count"),
        ("memory_bytes", 1, "recorded machine memory"),
    ],
)
def test_run_verifier_rejects_rehashed_execution_host_capacity(
    field: str,
    value: int,
    message: str,
    tmp_path: Path,
    test_data_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name=f"host-{field}")
    _patch_execution(monkeypatch)
    output = tmp_path / f"host-{field}-run"
    report = run_enron_performance(
        EnronPerformanceRunOptions(
            prepared_run=prepared,
            output_dir=output,
            profile="smoke",
            allow_unignored_output=True,
        )
    )
    report["environment"][field] = value
    _rewrite_aggregate_report(output, report)

    with pytest.raises(EnronPerformanceError, match=message):
        verify_enron_performance_run(output)


@pytest.mark.parametrize("field", ["suite", "benchmark_version"])
def test_prepared_manifest_identity_is_bound_to_frozen_plan(
    field: str,
    tmp_path: Path,
    test_data_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name=f"prepared-{field}")
    manifest_path = prepared / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest[field] = f"tampered-{field}"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(EnronPerformanceError, match="manifest"):
        performance_module._load_prepared_performance_run(prepared)


@pytest.mark.parametrize(
    ("artifact_id", "kind"),
    [
        ("performance_plan", "private_locations"),
        ("private_locations", "public_plan"),
        ("real_validation_inventory", "aggregate_report"),
    ],
)
def test_prepared_manifest_rejects_artifact_privacy_reclassification(
    artifact_id: str,
    kind: str,
    tmp_path: Path,
    test_data_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name=f"prepared-kind-{artifact_id}")
    manifest_path = prepared / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    artifact = next(item for item in manifest["artifacts"] if item["id"] == artifact_id)
    artifact["kind"] = kind
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(EnronPerformanceError, match="privacy classification"):
        performance_module._load_prepared_performance_run(prepared)


@pytest.mark.parametrize("field", ["suite", "benchmark_version"])
def test_run_manifest_identity_is_bound_to_frozen_report_and_plan(
    field: str,
    tmp_path: Path,
    test_data_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name=f"run-{field}")
    _patch_execution(monkeypatch)
    output = tmp_path / f"run-identity-{field}"
    run_enron_performance(
        EnronPerformanceRunOptions(
            prepared_run=prepared,
            output_dir=output,
            profile="smoke",
            allow_unignored_output=True,
        )
    )
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest[field] = f"tampered-{field}"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(EnronPerformanceError, match="manifest"):
        verify_enron_performance_run(output)


def test_run_manifest_rejects_private_audit_reclassification(
    tmp_path: Path, test_data_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name="run-kind")
    _patch_execution(monkeypatch)
    output = tmp_path / "run-kind-output"
    run_enron_performance(
        EnronPerformanceRunOptions(
            prepared_run=prepared,
            output_dir=output,
            profile="smoke",
            allow_unignored_output=True,
        )
    )
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    audit = next(item for item in manifest["artifacts"] if item["id"] == "performance_audit")
    audit["kind"] = "aggregate_report"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(EnronPerformanceError, match="privacy classification"):
        verify_enron_performance_run(output)


def test_run_verifier_fails_closed_on_content_addressed_malformed_report(
    tmp_path: Path, test_data_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name="malformed-report")
    _patch_execution(monkeypatch)
    output = tmp_path / "malformed-report-run"
    run_enron_performance(
        EnronPerformanceRunOptions(
            prepared_run=prepared,
            output_dir=output,
            profile="smoke",
            allow_unignored_output=True,
        )
    )
    report_path = output / "report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report.pop("performance")
    report_payload = json.dumps(report, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    report_path.write_bytes(report_payload)
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    report_artifact = next(item for item in manifest["artifacts"] if item["id"] == "performance_report")
    report_artifact["sha256"] = _sha256(report_payload)
    report_artifact["bytes"] = len(report_payload)
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(EnronPerformanceError, match="report"):
        verify_enron_performance_run(output)


def test_run_verifier_fails_closed_on_consistently_rebound_malformed_plan(
    tmp_path: Path, test_data_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name="malformed-plan")
    _patch_execution(monkeypatch)
    output = tmp_path / "malformed-plan-run"
    run_enron_performance(
        EnronPerformanceRunOptions(
            prepared_run=prepared,
            output_dir=output,
            profile="smoke",
            allow_unignored_output=True,
        )
    )
    plan_path = output / "plan.json"
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan.pop("profiles")
    plan["plan_sha256"] = performance_module._canonical_hash(
        {key: value for key, value in plan.items() if key != "plan_sha256"}
    )
    plan_payload = json.dumps(plan, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    plan_path.write_bytes(plan_payload)

    report_path = output / "report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["plan_sha256"] = plan["plan_sha256"]
    report["run_sha256"] = performance_module._canonical_hash(
        {key: value for key, value in report.items() if key != "run_sha256"}
    )
    report_payload = json.dumps(report, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    report_path.write_bytes(report_payload)

    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["plan_sha256"] = plan["plan_sha256"]
    manifest["run_sha256"] = report["run_sha256"]
    plan_artifact = next(item for item in manifest["artifacts"] if item["id"] == "performance_plan")
    plan_artifact["sha256"] = _sha256(plan_payload)
    plan_artifact["bytes"] = len(plan_payload)
    report_artifact = next(item for item in manifest["artifacts"] if item["id"] == "performance_report")
    report_artifact["sha256"] = _sha256(report_payload)
    report_artifact["bytes"] = len(report_payload)
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(EnronPerformanceError, match="plan"):
        verify_enron_performance_run(output)


def test_prepared_manifest_rejects_duplicate_json_keys(
    tmp_path: Path, test_data_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name="duplicate-manifest")
    manifest_path = prepared / "manifest.json"
    payload = manifest_path.read_bytes().replace(
        b'"suite":',
        b'"suite":"duplicate-safe-value","suite":',
        1,
    )
    manifest_path.write_bytes(payload)
    with pytest.raises(EnronPerformanceError, match="strict finite JSON"):
        performance_module._load_prepared_performance_run(prepared)


def test_decision_run_verifier_rejects_exact_control_audit_mismatch(
    tmp_path: Path, test_data_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name="decision")
    _patch_execution(monkeypatch)
    output = tmp_path / "decision-run"
    report = run_enron_performance(
        EnronPerformanceRunOptions(
            prepared_run=prepared,
            output_dir=output,
            profile="decision",
            allow_unignored_output=True,
        )
    )
    assert report["profile"] == "decision"
    assert len([item for item in report["performance"]["workloads"] if item["decision_grade"]]) == 19
    assert verify_enron_performance_run(output)["valid"] is True

    audit_path = output / "audit" / "results.jsonl"
    rows = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    control = next(item for item in rows if item["workload_id"].startswith("control_"))
    for sample in control["samples"]:
        sample["correctness_sha256"] = _HASH_1
    audit_payload = b"".join(_canonical(item) + b"\n" for item in rows)
    audit_path.write_bytes(audit_payload)
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    audit_artifact = next(item for item in manifest["artifacts"] if item["id"] == "performance_audit")
    audit_artifact["sha256"] = _sha256(audit_payload)
    audit_artifact["bytes"] = len(audit_payload)
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(EnronPerformanceError, match="exact control correctness sequence"):
        verify_enron_performance_run(output)


def test_decision_run_verifier_rejects_rehashed_cross_path_order_swap(
    tmp_path: Path, test_data_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name="decision-order")
    _patch_execution(monkeypatch)
    output = tmp_path / "decision-order-run"
    run_enron_performance(
        EnronPerformanceRunOptions(
            prepared_run=prepared,
            output_dir=output,
            profile="decision",
            allow_unignored_output=True,
        )
    )
    audit_path = output / "audit" / "results.jsonl"
    rows = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    by_id = {item["workload_id"]: item for item in rows}
    direct = by_id["real_direct_throughput"]["samples"][0]
    helper_hit = by_id["real_helper_cache_hit"]["samples"][0]
    direct["sequence"], helper_hit["sequence"] = helper_hit["sequence"], direct["sequence"]
    audit_payload = b"".join(_canonical(item) + b"\n" for item in rows)
    audit_path.write_bytes(audit_payload)
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    audit_artifact = next(item for item in manifest["artifacts"] if item["id"] == "performance_audit")
    audit_artifact["sha256"] = _sha256(audit_payload)
    audit_artifact["bytes"] = len(audit_payload)
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(EnronPerformanceError, match="cache-value block ordering"):
        verify_enron_performance_run(output)


def test_decision_run_verifier_rejects_nonchronological_workload_samples(
    tmp_path: Path, test_data_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name="decision-sample-order")
    _patch_execution(monkeypatch)
    output = tmp_path / "decision-sample-order-run"
    run_enron_performance(
        EnronPerformanceRunOptions(
            prepared_run=prepared,
            output_dir=output,
            profile="decision",
            allow_unignored_output=True,
        )
    )
    audit_path = output / "audit" / "results.jsonl"
    rows = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    direct = next(item for item in rows if item["workload_id"] == "real_direct_throughput")
    direct["samples"].reverse()
    audit_payload = b"".join(_canonical(item) + b"\n" for item in rows)
    audit_path.write_bytes(audit_payload)
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    audit_artifact = next(item for item in manifest["artifacts"] if item["id"] == "performance_audit")
    audit_artifact["sha256"] = _sha256(audit_payload)
    audit_artifact["bytes"] = len(audit_payload)
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(EnronPerformanceError, match="not chronological"):
        verify_enron_performance_run(output)


def test_decision_run_verifier_rejects_reused_candidate_control_pid_aliasing(
    tmp_path: Path, test_data_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepare_run(tmp_path, test_data_path, monkeypatch, name="decision-pid-alias")
    _patch_execution(monkeypatch)
    output = tmp_path / "decision-pid-alias-run"
    run_enron_performance(
        EnronPerformanceRunOptions(
            prepared_run=prepared,
            output_dir=output,
            profile="decision",
            allow_unignored_output=True,
        )
    )
    audit_path = output / "audit" / "results.jsonl"
    rows = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    by_id = {item["workload_id"]: item for item in rows}
    candidate_pid = by_id["real_direct_throughput"]["samples"][0]["pid"]
    for sample in by_id["control_real_direct_throughput"]["samples"]:
        sample["pid"] = candidate_pid
    audit_payload = b"".join(_canonical(item) + b"\n" for item in rows)
    audit_path.write_bytes(audit_payload)
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    audit_artifact = next(item for item in manifest["artifacts"] if item["id"] == "performance_audit")
    audit_artifact["sha256"] = _sha256(audit_payload)
    audit_artifact["bytes"] = len(audit_payload)
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(EnronPerformanceError, match="reused exact-control process isolation"):
        verify_enron_performance_run(output)


def test_execute_pair_rejects_correctness_mismatch_before_materialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = {
        "id": "candidate",
        "process_model": "fresh_process_per_sample",
        "sample_unit": "whole_input",
    }
    control = {
        "id": "control_candidate",
        "process_model": "fresh_process_per_sample",
        "sample_unit": "whole_input",
    }
    results = iter(
        (
            {"record_count": 1, "correctness_sha256": _HASH_1},
            {"record_count": 2, "correctness_sha256": _HASH_2},
        )
    )
    monkeypatch.setattr(performance_module, "_run_one_observation", lambda *_args, **_kwargs: next(results))
    monkeypatch.setattr(performance_module, "_interleaved_labels", lambda _count: ("candidate", "control"))
    with pytest.raises(EnronPerformanceError, match="differs from its candidate"):
        performance_module._execute_pair(
            candidate,
            control,
            {},
            cast(Any, None),
            sample_count=1,
            worker_timeout_seconds=1.0,
            source_build_timeout_seconds=1.0,
            sequence_start=0,
        )


def test_exact_value_block_preserves_reused_and_fresh_process_models(monkeypatch: pytest.MonkeyPatch) -> None:
    reused_paths = {"real_direct_throughput", "real_helper_cache_hit"}
    workloads: dict[str, dict[str, Any]] = {
        identifier: {
            "id": identifier,
            "process_model": (
                "reused_process" if identifier.removeprefix("control_") in reused_paths else "fresh_process_per_sample"
            ),
        }
        for path in performance_module.PERFORMANCE_EXACT_VALUE_PATHS
        for identifier in (path, f"control_{path}")
    }
    sessions: list[Any] = []
    calls: list[tuple[str, bool]] = []

    class _Session:
        def __init__(self, *, timeout_seconds: float) -> None:
            assert timeout_seconds == 1.0
            self.closed = False
            sessions.append(self)

        def close(self) -> None:
            self.closed = True

    def observe(workload: Mapping[str, Any], *_args: Any, session: Any = None, **_kwargs: Any) -> dict[str, Any]:
        expected_reused = workload["process_model"] == "reused_process"
        calls.append((str(workload["id"]), session is not None))
        assert (session is not None) is expected_reused
        return {"record_count": 1, "correctness_sha256": _HASH_1}

    monkeypatch.setattr(performance_module, "_WorkerSession", _Session)
    monkeypatch.setattr(performance_module, "_run_one_observation", observe)
    results, next_sequence = performance_module._execute_exact_value_block(
        workloads,
        {},
        cast(Any, None),
        sample_count=4,
        worker_timeout_seconds=1.0,
        source_build_timeout_seconds=1.0,
        sequence_start=7,
    )

    assert [identifier for identifier, _reused in calls] == list(performance_module._exact_value_schedule(4))
    assert set(results) == set(workloads)
    assert all(len(items) == 4 for items in results.values())
    assert next_sequence == 39
    assert len(sessions) == 4
    assert all(session.closed for session in sessions)


def test_public_privacy_scanner_accepts_plan_and_rejects_private_paths_and_identifiers(
    performance_plan: dict[str, Any], tmp_path: Path
) -> None:
    assert performance_module._public_serialization_diagnostics(performance_plan) == []
    diagnostics = performance_module._public_serialization_diagnostics(
        {
            "private_path": str((tmp_path / "private-corpus.jsonl").resolve()),
            "identifier": "synthetic.person@example.invalid",
        }
    )
    codes = {item["code"] for item in diagnostics}
    assert "contract.public_private_path" in codes
    assert "contract.public_direct_identifier" in codes


@pytest.mark.parametrize(
    "options",
    [
        EnronPerformancePrepareOptions(Path("bank"), Path("dev"), Path("prep"), Path("out"), real_input_documents=99),
        EnronPerformancePrepareOptions(Path("bank"), Path("dev"), Path("prep"), Path("out"), concurrency=1),
        EnronPerformancePrepareOptions(
            Path("bank"),
            Path("dev"),
            Path("prep"),
            Path("out"),
            source_curation_seconds=float("nan"),
        ),
    ],
)
def test_prepare_rejects_invalid_options_before_loading_private_runs(options: EnronPerformancePrepareOptions) -> None:
    with pytest.raises(EnronPerformanceError):
        prepare_enron_performance_manifest(options)


@pytest.mark.parametrize(
    "options",
    [
        EnronPerformanceRunOptions(Path("prepared"), Path("out"), profile=cast(Any, "unknown")),
        EnronPerformanceRunOptions(Path("prepared"), Path("out"), smoke_samples=4),
        EnronPerformanceRunOptions(Path("prepared"), Path("out"), worker_timeout_seconds=0),
        EnronPerformanceRunOptions(Path("prepared"), Path("out"), source_build_timeout_seconds=float("inf")),
    ],
)
def test_run_rejects_invalid_options_before_loading_prepared_run(options: EnronPerformanceRunOptions) -> None:
    with pytest.raises(EnronPerformanceError):
        run_enron_performance(options)


def test_orchestrators_reject_non_option_objects() -> None:
    with pytest.raises(EnronPerformanceError, match="preparation options"):
        prepare_enron_performance_manifest(cast(Any, object()))
    with pytest.raises(EnronPerformanceError, match="run options"):
        run_enron_performance(cast(Any, object()))


def test_phase_process_models_are_reflected_in_warmup_policy(performance_plan: dict[str, Any]) -> None:
    workloads = performance_plan["profiles"]["decision"]["performance"]["workloads"]
    candidates = [item for item in workloads if item["decision_grade"]]
    for workload in candidates:
        expected_model = PERFORMANCE_PHASE_PROCESS_MODELS[workload["phase"]]
        assert workload["process_model"] == expected_model
        assert workload["warmups"] == (3 if expected_model == "reused_process" else 0)

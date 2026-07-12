from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from pathlib import Path
from typing import Any

import pytest

import nerb.enron_bank_workflow as bank_workflow
from nerb.engines import compile_bank
from nerb.enron_bank_builder import (
    ITERATION_POLICIES,
    CuratedIteration,
    EnronBankBuildError,
    EnronBankPolicy,
    _canonical_hash,
    _validate_policy,
    curate_enron_iteration,
    mine_enron_candidates,
)
from nerb.enron_bank_workflow import (
    EnronBankBuildOptions,
    _decide_iterations,
    _paired_role,
    _policy_from_descriptor,
    _source_binding,
    _validate_public_card,
    _validation_projection,
    build_enron_intelligence_bank,
    verify_enron_bank_build,
)
from nerb.enron_preparation import EnronPreparationOptions, prepare_enron_source
from nerb.enron_quality import DEFAULT_MAX_QUALITY_PREDICTIONS_TOTAL
from nerb.enron_splitting import (
    EnronSplitError,
    EnronSplitOptions,
    load_enron_development_split,
    split_enron_preparation,
)


def _source_row(index: int) -> dict[str, Any]:
    sender = "Alice Alpha <alice.alpha@example.invalid>" if index % 2 == 0 else "Bob Beta <bob.beta@example.invalid>"
    recipient = "Bob Beta <bob.beta@example.invalid>" if index % 2 == 0 else "Alice Alpha <alice.alpha@example.invalid>"
    return {
        "message_id": f"<fixture-{index:03d}@messages.invalid>",
        "subject": f"Unique fixture subject {index:03d}",
        "from": sender,
        "to": [recipient, "Service Desk <service.desk@example.invalid>"],
        "cc": [],
        "bcc": [],
        "date": f"2001-01-{index + 1:02d}T12:00:00Z",
        "body": f"Synthetic fixture body marker {index:03d}.",
        "file_name": f"maildir/owner-{index % 4}/inbox/{index}",
    }


def _development_bundle(tmp_path: Path, *, rows: int = 20) -> tuple[Path, Path]:
    source = tmp_path / "source.jsonl"
    source.write_text(
        "".join(json.dumps(_source_row(index), separators=(",", ":")) + "\n" for index in range(rows)),
        encoding="utf-8",
    )
    preparation = tmp_path / "preparation"
    prepare_enron_source(
        EnronPreparationOptions(
            output_dir=preparation,
            input_jsonl=source,
            dataset_id="synthetic/enron-bank-builder",
            dataset_revision="fixture-v2",
        )
    )
    development = tmp_path / "development"
    sealed = tmp_path / "sealed"
    split_enron_preparation(
        EnronSplitOptions(
            preparation_run=preparation,
            development_output_dir=development,
            sealed_output_dir=sealed,
            fixture_mode=True,
            sample_per_role=100,
        )
    )
    return development, sealed


def _mine(tmp_path: Path, development_path: Path):
    development = load_enron_development_split(development_path)
    source_binding = _source_binding(development, "enron-v2")
    spool = tmp_path / "spool.sqlite3"
    spool.touch()
    pool = mine_enron_candidates(
        _paired_role(
            development.iter_train_records(),
            development.iter_train_memberships(),
            role="train",
        ),
        sqlite_path=spool,
        train_artifact_sha256=source_binding["train_artifact_sha256"],
        policy=EnronBankPolicy(),
    )
    return pool, source_binding


def test_verified_snapshot_stays_private_and_public_wrapper_returns_only_summary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    marker = "sensitive-marker@example.invalid"
    summary = {"schema_version": "nerb.enron_bank_build_verification.v2", "valid": True}
    snapshot = bank_workflow._VerifiedEnronBankBuildSnapshot(
        summary=summary,
        card={"private": marker},
        bank={"private": marker},
        bank_payload=marker.encode(),
        validation_documents=({"text": marker},),
        build_created_at="2026-07-10T00:00:00Z",
    )
    monkeypatch.setattr(bank_workflow, "_verify_enron_bank_build_snapshot", lambda *_args, **_kwargs: snapshot)

    assert marker not in repr(snapshot)
    assert verify_enron_bank_build(tmp_path) == summary


def test_source_binding_rejects_same_byte_manifest_aba_replacement(tmp_path: Path) -> None:
    development_path, _sealed = _development_bundle(tmp_path)
    development = load_enron_development_split(development_path)
    manifest_path = development_path / "manifest.json"
    parked_original = tmp_path / "manifest.original.json"
    replacement = tmp_path / "manifest.replacement.json"
    replacement.write_bytes(manifest_path.read_bytes())
    replacement.chmod(0o600)
    manifest_path.replace(parked_original)
    replacement.replace(manifest_path)
    try:
        with pytest.raises(EnronSplitError, match=r"(?i)(changed|verified)"):
            _source_binding(development, "enron-v2")
    finally:
        manifest_path.replace(replacement)
        parked_original.replace(manifest_path)


def _rewrite_private_artifact(
    output: Path,
    *,
    artifact_id: str,
    relative_path: str,
    value: Any,
    jsonl: bool = False,
) -> None:
    path = output / relative_path
    if jsonl:
        payload = b"".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
            for row in value
        )
    else:
        payload = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    path.write_bytes(payload)
    path.chmod(0o600)
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    descriptor = manifest["artifacts"][artifact_id]
    descriptor["bytes"] = len(payload)
    descriptor["sha256"] = "sha256:" + hashlib.sha256(payload).hexdigest()
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    manifest_path.chmod(0o600)


def _synthetic_cmu_quality() -> dict[str, Any]:
    return {
        "evaluated": True,
        "contract_validation": {"valid": True},
        "protocol_sha256": "sha256:" + "1" * 64,
        "run_sha256": "sha256:" + "2" * 64,
        "quality": {
            "slices": [
                {
                    "id": "cmu_person_all_train",
                    "label_strength": "independent",
                    "annotation_completeness": "exhaustive_within_scope",
                    "documents": 2,
                    "documents_with_sensitive_gold": 1,
                    "documents_with_any_miss": 1,
                    "documents_with_cataloged_gold": 1,
                    "documents_with_any_cataloged_miss": 0,
                    "documents_with_any_leaked_character": 1,
                    "gold_spans": 2,
                    "predicted_spans": 1,
                    "true_positive": 1,
                    "false_negative": 1,
                    "false_positive": 0,
                    "cataloged_gold_spans": 1,
                    "cataloged_true_positive": 1,
                    "cataloged_false_negative": 0,
                    "cataloged_wrong_canonical": 0,
                    "sensitive_gold_characters": 10,
                    "covered_sensitive_characters": 5,
                    "leaked_sensitive_characters": 5,
                    "predicted_characters": 5,
                    "over_redacted_characters": 0,
                    "evaluated_characters": 20,
                    "negative_documents": 1,
                    "negative_documents_with_predictions": 0,
                    "metrics": {
                        "precision": 1.0,
                        "open_world_recall": 0.5,
                        "f1": 2 / 3,
                        "catalog_coverage": 0.5,
                        "cataloged_recall": 1.0,
                        "document_leak_rate": 1.0,
                        "cataloged_document_leak_rate": 0.0,
                        "sensitive_character_recall": 0.5,
                        "sensitive_character_leak_rate": 0.5,
                        "negative_document_false_alarm_rate": 0.0,
                        "over_redaction_rate": 0.0,
                    },
                }
            ]
        },
    }


@pytest.mark.parametrize(
    "malformation",
    [
        "missing_quality",
        "slices_not_sequence",
        "slice_not_mapping",
        "duplicate_target_slice",
        "metrics_not_mapping",
        "missing_projected_field",
        "missing_run_hash",
    ],
)
def test_independent_auxiliary_summary_normalizes_malformed_private_quality(malformation: str) -> None:
    quality = json.loads(json.dumps(_synthetic_cmu_quality()))
    target = quality["quality"]["slices"][0]
    if malformation == "missing_quality":
        del quality["quality"]
    elif malformation == "slices_not_sequence":
        quality["quality"]["slices"] = 1
    elif malformation == "slice_not_mapping":
        quality["quality"]["slices"] = [1]
    elif malformation == "duplicate_target_slice":
        quality["quality"]["slices"].append(dict(target))
    elif malformation == "metrics_not_mapping":
        target["metrics"] = []
    elif malformation == "missing_projected_field":
        del target["label_strength"]
    else:
        del quality["run_sha256"]

    with pytest.raises(EnronBankBuildError, match="Auxiliary CMU quality evidence is invalid"):
        bank_workflow._independent_auxiliary_summary(quality)


def test_private_builder_runs_three_iterations_and_verifies_without_sealed_access(tmp_path: Path) -> None:
    development, sealed = _development_bundle(tmp_path)
    output = tmp_path / "build"

    card = build_enron_intelligence_bank(EnronBankBuildOptions(development_run=development, output_dir=output))

    serialized = json.dumps(card, sort_keys=True)
    assert "@" not in serialized
    assert str(tmp_path) not in serialized
    assert card["builder"]["selected_iteration_id"] == "iteration_02_email_recall"
    assert [item["decision"] for item in card["iterations"]] == ["discard", "keep", "discard"]
    assert card["validation"]["contact"]["labeled_span_recall"] == 1.0
    assert card["validation"]["open_world_metrics_supported"] is False
    assert card["validation"]["contact"]["precision"] is None
    assert card["catalog_conformance"]["passed"] is True
    assert card["promotable"] is False
    assert not (sealed / "ACCESS_CLAIMED.json").exists()
    assert not (sealed / "ACCESS_OUTCOME.json").exists()

    snapshot = bank_workflow._verify_enron_bank_build_snapshot(output)
    verification = snapshot.summary
    assert set(verification) == {
        "schema_version",
        "valid",
        "benchmark_version",
        "fixture_mode",
        "promotable",
        "bank_sha256",
        "bank_card_run_sha256",
        "candidate_count",
        "iteration_count",
        "selected_iteration_id",
        "catalog_conformance_passed",
        "validation_reverified",
        "cmu_reverified",
        "sealed_test_accessed",
        "privacy",
    }
    assert verification["valid"] is True
    assert verification["validation_reverified"] is True
    assert verification["sealed_test_accessed"] is False
    assert snapshot.card == card
    assert snapshot.bank_payload == (output / "bank.json").read_bytes()
    assert snapshot.bank["metadata"]["sealed_test_accessed"] is False
    assert len(snapshot.validation_documents) == card["source"]["validation_records"]
    assert snapshot.build_created_at == "2026-07-10T00:00:00Z"


@pytest.mark.parametrize("supply_annotation", [False, True])
def test_private_builder_requires_paired_cmu_evidence_inputs(tmp_path: Path, supply_annotation: bool) -> None:
    options = EnronBankBuildOptions(
        development_run=tmp_path / "development",
        output_dir=tmp_path / "build",
        annotation_run=tmp_path / "annotations" if supply_annotation else None,
        cmu_catalog_bindings_path=None if supply_annotation else tmp_path / "reviewed-bindings.jsonl",
    )

    with pytest.raises(EnronBankBuildError, match="must be supplied together"):
        build_enron_intelligence_bank(options)

    assert not options.output_dir.exists()


def test_cmu_auxiliary_evaluates_an_exact_private_copy_of_reviewed_bindings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    reviewed = tmp_path / "reviewed-bindings.jsonl"
    binding = {
        "document_id": "reviewed_document",
        "start": 4,
        "end": 9,
        "catalog_identity": None,
    }
    reviewed.write_text(json.dumps(binding, separators=(", ", ": ")) + "\n", encoding="utf-8")
    annotation_run = tmp_path / "annotations"
    observed: dict[str, Any] = {}

    def fake_evaluate(bank, *, annotation_run_dir, catalog_bindings_path):
        observed["bank"] = bank
        observed["annotation_run"] = annotation_run_dir
        observed["bindings_path"] = catalog_bindings_path
        observed["bindings"] = [json.loads(line) for line in catalog_bindings_path.read_text().splitlines()]
        return {"evaluated": True, "contract_validation": {"valid": True}}

    monkeypatch.setattr(bank_workflow, "evaluate_cmu_enron_training_quality_files", fake_evaluate)
    bank = {"id": "selected_bank"}
    with bank_workflow.PrivateRun(tmp_path / "private-build", allow_unignored_output=True) as run:
        bindings, quality = bank_workflow._stage_and_evaluate_cmu_auxiliary(
            run,
            bank,
            annotation_run,
            reviewed,
        )

        copied_path = run.stage_dir / "auxiliary/cmu-train-catalog-bindings.jsonl"
        assert copied_path == observed["bindings_path"]
        assert copied_path != reviewed
        assert observed["bindings"] == [binding]
        assert copied_path.read_bytes() == bank_workflow._canonical_json_bytes(binding) + b"\n"

    assert bindings == (binding,)
    assert quality == {"evaluated": True, "contract_validation": {"valid": True}}
    assert observed["bank"] is bank
    assert observed["annotation_run"] == annotation_run


def test_verifier_rejects_coherently_tampered_public_cmu_aggregate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    development, _sealed = _development_bundle(tmp_path)
    reviewed = tmp_path / "reviewed-bindings.jsonl"
    reviewed.write_text(
        json.dumps({"document_id": "reviewed_document", "start": 0, "end": 1, "catalog_identity": None}) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        bank_workflow,
        "evaluate_cmu_enron_training_quality_files",
        lambda *_args, **_kwargs: _synthetic_cmu_quality(),
    )
    output = tmp_path / "build"
    build_enron_intelligence_bank(
        EnronBankBuildOptions(
            development_run=development,
            output_dir=output,
            annotation_run=tmp_path / "annotations",
            cmu_catalog_bindings_path=reviewed,
        )
    )

    card = json.loads((output / "bank-card.json").read_text(encoding="utf-8"))
    auxiliary = card["independent_auxiliary"]
    auxiliary["documents_with_any_miss"] = 0
    auxiliary["metrics"]["document_leak_rate"] = 0.0
    card["run_sha256"] = _canonical_hash({key: value for key, value in card.items() if key != "run_sha256"})
    _validate_public_card(card)
    _rewrite_private_artifact(
        output,
        artifact_id="bank_card",
        relative_path="bank-card.json",
        value=card,
    )
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["bank_card_run_sha256"] = card["run_sha256"]
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    manifest_path.chmod(0o600)

    with pytest.raises(EnronBankBuildError, match="Public auxiliary summary differs"):
        verify_enron_bank_build(output)


def test_verifier_normalizes_malformed_private_cmu_evidence(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    development, _sealed = _development_bundle(tmp_path)
    reviewed = tmp_path / "reviewed-bindings.jsonl"
    reviewed.write_text(
        json.dumps({"document_id": "reviewed_document", "start": 0, "end": 1, "catalog_identity": None}) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        bank_workflow,
        "evaluate_cmu_enron_training_quality_files",
        lambda *_args, **_kwargs: _synthetic_cmu_quality(),
    )
    output = tmp_path / "build"
    build_enron_intelligence_bank(
        EnronBankBuildOptions(
            development_run=development,
            output_dir=output,
            annotation_run=tmp_path / "annotations",
            cmu_catalog_bindings_path=reviewed,
        )
    )
    _rewrite_private_artifact(
        output,
        artifact_id="cmu_quality",
        relative_path="auxiliary/cmu-train-quality.json",
        value={"quality": {"slices": 1}},
    )

    with pytest.raises(EnronBankBuildError, match="Auxiliary CMU quality evidence is invalid"):
        verify_enron_bank_build(output)


def test_private_builder_is_deterministic_for_same_frozen_development_bundle(tmp_path: Path) -> None:
    development, _sealed = _development_bundle(tmp_path)
    first = tmp_path / "first"
    second = tmp_path / "second"

    first_card = build_enron_intelligence_bank(EnronBankBuildOptions(development_run=development, output_dir=first))
    second_card = build_enron_intelligence_bank(EnronBankBuildOptions(development_run=development, output_dir=second))

    assert first_card == second_card
    for relative in ("bank.json", "candidates.jsonl", "candidate-funnel.json", "iterations.jsonl"):
        assert (first / relative).read_bytes() == (second / relative).read_bytes()


def test_private_builder_retains_only_the_selected_candidate_ledger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    development, _sealed = _development_bundle(tmp_path)
    retention: list[bool] = []
    original_curate = bank_workflow.curate_enron_iteration

    def record_retention(*args: Any, **kwargs: Any) -> Any:
        retention.append(kwargs["retain_candidate_ledger"])
        return original_curate(*args, **kwargs)

    monkeypatch.setattr(bank_workflow, "curate_enron_iteration", record_retention)

    output = tmp_path / "build"
    build_enron_intelligence_bank(EnronBankBuildOptions(development_run=development, output_dir=output))

    assert retention == [False, True, False]
    retention.clear()

    verify_enron_bank_build(output)

    assert retention == [False, True, False]


def test_distinct_leakage_groups_not_duplicate_documents_control_contact_activation(tmp_path: Path) -> None:
    record = {
        "document_id": "doc_" + "1" * 64,
        "date": {"utc": "2001-01-01T00:00:00Z"},
        "headers": {
            "from": [{"name": "Alice Alpha", "address": "alice.alpha@example.invalid"}],
            "to": [],
            "cc": [],
            "bcc": [],
        },
    }
    duplicate = {**record, "document_id": "doc_" + "2" * 64}
    membership = {"document_id": record["document_id"], "group_id": "sha256:" + "a" * 64, "role": "train"}
    duplicate_membership = {
        "document_id": duplicate["document_id"],
        "group_id": membership["group_id"],
        "role": "train",
    }
    spool = tmp_path / "duplicates.sqlite3"
    spool.touch()
    pool = mine_enron_candidates(
        [(record, membership), (duplicate, duplicate_membership)],
        sqlite_path=spool,
        train_artifact_sha256="sha256:" + "b" * 64,
        policy=EnronBankPolicy(),
    )
    assert pool.contacts[0].document_count == 2
    assert pool.contacts[0].leakage_group_count == 1
    curated = curate_enron_iteration(
        pool,
        policy=EnronBankPolicy(),
        iteration=ITERATION_POLICIES[1],
        source_binding={"fixture_mode": True},
    )
    exact = next(item for item in curated.candidates if item["candidate_type"] == "contact")
    assert exact["decision"] == "draft"
    assert exact["primary_reason_code"] == "insufficient_distinct_group_support"


def test_ambiguous_full_name_shared_by_two_addresses_is_rejected(tmp_path: Path) -> None:
    rows = []
    for index, address in enumerate(("sam.person@one.invalid", "sam.person@two.invalid"), start=1):
        record = {
            "document_id": f"doc_{index:064x}",
            "date": {"utc": f"2001-01-0{index}T00:00:00Z"},
            "headers": {
                "from": [{"name": "Sam Person", "address": address}],
                "to": [],
                "cc": [],
                "bcc": [],
            },
        }
        membership = {
            "document_id": record["document_id"],
            "group_id": f"sha256:{index:064x}",
            "role": "train",
        }
        rows.append((record, membership))
    spool = tmp_path / "ambiguous.sqlite3"
    spool.touch()
    pool = mine_enron_candidates(
        rows,
        sqlite_path=spool,
        train_artifact_sha256="sha256:" + "c" * 64,
        policy=EnronBankPolicy(minimum_contact_groups=1, minimum_person_alias_groups=1),
    )
    curated = curate_enron_iteration(
        pool,
        policy=EnronBankPolicy(minimum_contact_groups=1, minimum_person_alias_groups=1),
        iteration=ITERATION_POLICIES[1],
        source_binding={"fixture_mode": True},
    )
    person = next(item for item in curated.candidates if item["candidate_type"] == "person_alias")
    assert person["decision"] == "rejected"
    assert person["primary_reason_code"] == "ambiguous_address_ownership"


def test_exact_known_contact_outranks_generic_contact_fallback(tmp_path: Path) -> None:
    development, _sealed = _development_bundle(tmp_path)
    pool, source_binding = _mine(tmp_path, development)
    curated = curate_enron_iteration(
        pool,
        policy=EnronBankPolicy(),
        iteration=ITERATION_POLICIES[1],
        source_binding=source_binding,
    )
    known = next(
        item for item in curated.candidates if item["candidate_type"] == "contact" and item["decision"] == "active"
    )
    value = known["normalized_value"]
    compiled, _cache_hit = compile_bank(curated.bank, options={"include_statuses": ["active"]})

    contact_records = [item for item in compiled.finditer(value) if item["entity_id"] == "contact"]

    assert len(contact_records) == 1
    assert contact_records[0]["name_id"] != "unknown_email_contact"


def test_public_card_scan_rejects_direct_identifiers(tmp_path: Path) -> None:
    development, _sealed = _development_bundle(tmp_path)
    card = build_enron_intelligence_bank(
        EnronBankBuildOptions(development_run=development, output_dir=tmp_path / "build")
    )
    changed = json.loads(json.dumps(card))
    changed["source"]["dataset_id"] = "private.person@example.invalid"
    changed["run_sha256"] = _canonical_hash({key: value for key, value in changed.items() if key != "run_sha256"})

    with pytest.raises(EnronBankBuildError, match="privacy scanner rejected"):
        _validate_public_card(changed)


def test_public_card_scan_rejects_recommitted_stale_scanner_provenance(tmp_path: Path) -> None:
    development, _sealed = _development_bundle(tmp_path)
    card = build_enron_intelligence_bank(
        EnronBankBuildOptions(development_run=development, output_dir=tmp_path / "build")
    )
    changed = json.loads(json.dumps(card))
    privacy = changed["privacy"]
    privacy["scanner_source_sha256"] = "sha256:" + "5" * 64
    privacy["report_sha256"] = _canonical_hash({key: value for key, value in privacy.items() if key != "report_sha256"})
    changed["run_sha256"] = _canonical_hash({key: value for key, value in changed.items() if key != "run_sha256"})

    with pytest.raises(EnronBankBuildError, match="scanner implementation commitment"):
        _validate_public_card(changed)


@pytest.mark.parametrize(
    ("location", "unsafe"),
    [
        ("value", "private.person%2540example.invalid"),
        ("key", "private.person%2540example.invalid"),
        ("value", "１２３‐４５‐６７８９"),
        ("key", "+442079460958"),
        ("value", "artifact%2528%252FUsers%252Falice%252Fprivate.json%2529"),
        ("key", "..%252Fprivate.json"),
    ],
)
def test_public_card_scan_rejects_encoded_unicode_key_and_value_identifiers(
    tmp_path: Path,
    location: str,
    unsafe: str,
) -> None:
    development, _sealed = _development_bundle(tmp_path)
    card = build_enron_intelligence_bank(
        EnronBankBuildOptions(development_run=development, output_dir=tmp_path / "build")
    )
    changed = json.loads(json.dumps(card))
    if location == "value":
        changed["source"]["dataset_revision"] = unsafe
    else:
        reasons = changed["candidate_funnel"]["by_primary_reason"]
        original = next(iter(reasons))
        reasons[unsafe] = reasons.pop(original)
    changed["run_sha256"] = _canonical_hash({key: value for key, value in changed.items() if key != "run_sha256"})

    with pytest.raises(EnronBankBuildError, match="privacy scanner rejected"):
        _validate_public_card(changed)


def test_verifier_rejects_tampered_private_bank(tmp_path: Path) -> None:
    development, _sealed = _development_bundle(tmp_path)
    output = tmp_path / "build"
    build_enron_intelligence_bank(EnronBankBuildOptions(development_run=development, output_dir=output))
    bank_path = output / "bank.json"
    bank_path.write_bytes(bank_path.read_bytes() + b" ")

    with pytest.raises(EnronBankBuildError, match="descriptor"):
        verify_enron_bank_build(output)


@pytest.mark.parametrize(
    "payload",
    [
        b'{"overflow":1e999}\n',
        b'{"oversized_integer":' + b"9" * 257 + b"}\n",
        b"[" * 10_000 + b"0" + b"]" * 10_000,
    ],
)
def test_private_json_reader_normalizes_nonfinite_and_recursive_input(tmp_path: Path, payload: bytes) -> None:
    path = tmp_path / "private.json"
    path.write_bytes(payload)
    path.chmod(0o600)

    with pytest.raises(EnronBankBuildError, match="invalid"):
        bank_workflow._read_private_json(path)


def test_private_jsonl_reader_rejects_oversized_integer(tmp_path: Path) -> None:
    path = tmp_path / "private.jsonl"
    path.write_bytes(b'{"oversized_integer":' + b"9" * 257 + b"}\n")
    path.chmod(0o600)

    with pytest.raises(EnronBankBuildError, match="invalid"):
        bank_workflow._read_private_jsonl(path)


def test_private_sqlite_projection_reader_rejects_oversized_integer(tmp_path: Path) -> None:
    development, _sealed = _development_bundle(tmp_path)
    _pool, source_binding = _mine(tmp_path, development)
    spool = tmp_path / "spool.sqlite3"
    with sqlite3.connect(spool) as connection:
        document_id, payload = connection.execute(
            "SELECT document_id, payload FROM source_projections ORDER BY document_id LIMIT 1"
        ).fetchone()
        assert isinstance(payload, bytes)
        changed = re.sub(
            rb'("structured_entries":)[0-9]+',
            lambda match: match.group(1) + b"9" * 257,
            payload,
            count=1,
        )
        assert changed != payload
        connection.execute(
            "UPDATE source_projections SET payload = ? WHERE document_id = ?",
            (changed, document_id),
        )

    with pytest.raises(EnronBankBuildError, match="source projection payload is invalid"):
        bank_workflow._replay_candidate_pool_snapshot(
            spool,
            train_artifact_sha256=source_binding["train_artifact_sha256"],
            policy=EnronBankPolicy(),
        )


def test_verifier_rejects_oversized_descriptor_before_hashing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    development, _sealed = _development_bundle(tmp_path)
    output = tmp_path / "build"
    build_enron_intelligence_bank(EnronBankBuildOptions(development_run=development, output_dir=output))
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"]["selected_bank"]["bytes"] = bank_workflow._MAX_PRIVATE_JSON_BYTES + 1
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    manifest_path.chmod(0o600)

    original_fingerprint = bank_workflow._fingerprint_private_artifact

    def unexpected_hash(path: Path, **kwargs: Any):
        if path == output / "bank.json":
            raise AssertionError("oversized artifact must be rejected before hashing")
        return original_fingerprint(path, **kwargs)

    monkeypatch.setattr(bank_workflow, "_fingerprint_private_artifact", unexpected_hash)
    with pytest.raises(EnronBankBuildError, match="resource limit"):
        verify_enron_bank_build(output)


def test_verifier_recomputes_candidate_funnel_from_ledger(tmp_path: Path) -> None:
    development, _sealed = _development_bundle(tmp_path)
    output = tmp_path / "build"
    build_enron_intelligence_bank(EnronBankBuildOptions(development_run=development, output_dir=output))
    candidates_path = output / "candidates.jsonl"
    lines = candidates_path.read_text(encoding="utf-8").splitlines()
    candidate = json.loads(lines[0])
    candidate["primary_reason_code"] = "semantic_tamper"
    lines[0] = json.dumps(candidate, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    candidates_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    candidates_path.chmod(0o600)

    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    descriptor = manifest["artifacts"]["candidates"]
    payload = candidates_path.read_bytes()
    descriptor["bytes"] = len(payload)
    descriptor["sha256"] = "sha256:" + hashlib.sha256(payload).hexdigest()
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    manifest_path.chmod(0o600)

    with pytest.raises(EnronBankBuildError, match="candidate rationale"):
        verify_enron_bank_build(output)


def test_verifier_replays_rejected_candidate_evidence_from_mining_spool(tmp_path: Path) -> None:
    development, _sealed = _development_bundle(tmp_path)
    output = tmp_path / "build"
    policy = EnronBankPolicy(
        max_active_contacts=1,
        max_active_people=1,
        max_active_person_aliases=1,
        max_draft_per_class=1,
    )
    build_enron_intelligence_bank(EnronBankBuildOptions(development_run=development, output_dir=output, policy=policy))
    rows = [json.loads(line) for line in (output / "candidates.jsonl").read_text(encoding="utf-8").splitlines()]
    rejected = next(row for row in rows if row["decision"] == "rejected")
    rejected["evidence"]["observation_count"] += 1
    _rewrite_private_artifact(
        output,
        artifact_id="candidates",
        relative_path="candidates.jsonl",
        value=rows,
        jsonl=True,
    )

    with pytest.raises(EnronBankBuildError, match="candidate ledger differs from replayed"):
        verify_enron_bank_build(output)


@pytest.mark.parametrize("oversized_cell", ["projection_payload", "observation_surface"])
def test_mining_replay_rejects_sparse_oversized_cells_before_private_cell_fetch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    oversized_cell: str,
) -> None:
    _pool, source_binding = _mine(tmp_path, _development_bundle(tmp_path)[0])
    spool = tmp_path / "spool.sqlite3"
    connection = sqlite3.connect(spool)
    try:
        if oversized_cell == "projection_payload":
            monkeypatch.setattr(bank_workflow, "_MAX_PRIVATE_SQLITE_PROJECTION_BYTES", 64)
            connection.execute(
                "UPDATE source_projections SET payload = zeroblob(?) WHERE document_id = "
                "(SELECT document_id FROM source_projections ORDER BY document_id LIMIT 1)",
                (65,),
            )
        else:
            connection.execute(
                "UPDATE observations SET surface = CAST(zeroblob(?) AS TEXT) WHERE "
                "(kind, normalized_value, surface, related, source_type, document_id) = "
                "(SELECT kind, normalized_value, surface, related, source_type, document_id "
                "FROM observations ORDER BY kind, normalized_value LIMIT 1)",
                (EnronBankPolicy().max_candidate_value_bytes + 1,),
            )
        connection.commit()
    finally:
        connection.close()

    def unexpected_private_fetch(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("SQL cell preflight must reject before private cell materialization")

    monkeypatch.setattr(bank_workflow, "_iter_mining_source_projections", unexpected_private_fetch)
    monkeypatch.setattr(bank_workflow, "_read_candidate_evidence", unexpected_private_fetch)

    with pytest.raises(EnronBankBuildError, match="cell exceeds"):
        bank_workflow._replay_candidate_pool_snapshot(
            spool,
            train_artifact_sha256=source_binding["train_artifact_sha256"],
            policy=EnronBankPolicy(),
        )


def test_mining_sqlite_length_limit_handles_missing_setlimit_api() -> None:
    connection_without_setlimit: Any = object()

    assert bank_workflow._set_mining_sqlite_length_limit(connection_without_setlimit) is False


def test_mining_replay_preflights_schema_text_without_connection_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pool, source_binding = _mine(tmp_path, _development_bundle(tmp_path)[0])
    spool = tmp_path / "spool.sqlite3"
    with sqlite3.connect(spool) as connection:
        schema_sql = connection.execute("SELECT sql FROM sqlite_schema WHERE name = 'source_projections'").fetchone()[0]
        assert isinstance(schema_sql, str)
        connection.execute("PRAGMA writable_schema=ON")
        connection.execute(
            "UPDATE sqlite_schema SET sql = ? WHERE name = 'source_projections'",
            (schema_sql + " " * (bank_workflow._MAX_MINING_SQLITE_SCHEMA_CELL_BYTES + 1),),
        )

    monkeypatch.setattr(bank_workflow, "_set_mining_sqlite_length_limit", lambda _connection: False)

    def unexpected_schema_fetch(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("schema preflight must reject before private schema text materialization")

    monkeypatch.setattr(bank_workflow, "_iter_mining_sqlite_schema_rows", unexpected_schema_fetch)

    with pytest.raises(EnronBankBuildError, match="schema cell exceeds"):
        bank_workflow._replay_candidate_pool_snapshot(
            spool,
            train_artifact_sha256=source_binding["train_artifact_sha256"],
            policy=EnronBankPolicy(),
        )


@pytest.mark.parametrize("iteration_index", [0, 2])
def test_verifier_rejects_internally_consistent_nonselected_iteration_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    iteration_index: int,
) -> None:
    development, _sealed = _development_bundle(tmp_path)
    output = tmp_path / "build"
    target = ITERATION_POLICIES[iteration_index]
    original_bind = bank_workflow._bind_curated_iteration

    def replace_iteration(curated: CuratedIteration, **kwargs: Any) -> CuratedIteration:
        bound = original_bind(curated, **kwargs)
        if bound.iteration != target:
            return bound
        bank = dict(bound.bank)
        bank["description"] = f"{bank['description']} Internally consistent replacement."
        return CuratedIteration(
            iteration=bound.iteration,
            bank=bank,
            candidates=bound.candidates,
            funnel=bound.funnel,
            collisions=bound.collisions,
        )

    monkeypatch.setattr(bank_workflow, "_bind_curated_iteration", replace_iteration)
    card = build_enron_intelligence_bank(EnronBankBuildOptions(development_run=development, output_dir=output))
    monkeypatch.setattr(bank_workflow, "_bind_curated_iteration", original_bind)

    stored_bank = json.loads((output / f"banks/{target.id}.json").read_text(encoding="utf-8"))
    stored_hash = bank_workflow.hash_bank(stored_bank)
    stored_structural = json.loads(
        (output / f"validation/structural-iteration-{iteration_index + 1:02d}.json").read_text(encoding="utf-8")
    )
    stored_quality = json.loads(
        (output / f"validation/quality-iteration-{iteration_index + 1:02d}.json").read_text(encoding="utf-8")
    )
    assert card["iterations"][iteration_index]["bank_sha256"] == stored_hash
    assert stored_structural["hash"] == stored_hash
    assert stored_quality["bank"]["canonical_sha256"] == stored_hash

    with pytest.raises(EnronBankBuildError, match="iteration bank differs from replayed"):
        verify_enron_bank_build(output)


def test_verifier_replays_collision_report_from_curation(tmp_path: Path) -> None:
    development, _sealed = _development_bundle(tmp_path)
    output = tmp_path / "build"
    build_enron_intelligence_bank(EnronBankBuildOptions(development_run=development, output_dir=output))
    collision_path = output / "collision-report.json"
    collisions = json.loads(collision_path.read_text(encoding="utf-8"))
    collisions["allowed_fallback_shadowing"] += 1
    _rewrite_private_artifact(
        output,
        artifact_id="collision_report",
        relative_path="collision-report.json",
        value=collisions,
    )

    with pytest.raises(EnronBankBuildError, match="collision report differs from replayed"):
        verify_enron_bank_build(output)


@pytest.mark.parametrize(
    "field",
    ["source_sha256", "candidate_source_sha256", "candidate_ledger_sha256"],
)
def test_verifier_cross_binds_manifest_builder_commitments(tmp_path: Path, field: str) -> None:
    development, _sealed = _development_bundle(tmp_path)
    output = tmp_path / "build"
    build_enron_intelligence_bank(EnronBankBuildOptions(development_run=development, output_dir=output))
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["builder"][field] = "sha256:" + "0" * 64
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    manifest_path.chmod(0o600)

    with pytest.raises(EnronBankBuildError, match="commitment"):
        verify_enron_bank_build(output)


@pytest.mark.parametrize("section", ["source", "privacy"])
def test_verifier_rejects_false_sealed_test_declarations(tmp_path: Path, section: str) -> None:
    development, _sealed = _development_bundle(tmp_path)
    output = tmp_path / "build"
    build_enron_intelligence_bank(EnronBankBuildOptions(development_run=development, output_dir=output))
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest[section]["sealed_test_accessed"] = True
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    manifest_path.chmod(0o600)

    with pytest.raises(EnronBankBuildError, match="manifest"):
        verify_enron_bank_build(output)


def test_verifier_reconstructs_iteration_promotion_decision(tmp_path: Path) -> None:
    development, _sealed = _development_bundle(tmp_path)
    output = tmp_path / "build"
    build_enron_intelligence_bank(EnronBankBuildOptions(development_run=development, output_dir=output))
    iterations_path = output / "iterations.jsonl"
    rows = [json.loads(line) for line in iterations_path.read_text(encoding="utf-8").splitlines()]
    rows[0]["decision_reason_code"] = "semantic_tamper"
    payload = b"".join(
        json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
        for row in rows
    )
    iterations_path.write_bytes(payload)
    iterations_path.chmod(0o600)

    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    descriptor = manifest["artifacts"]["iterations"]
    descriptor["bytes"] = len(payload)
    descriptor["sha256"] = "sha256:" + hashlib.sha256(payload).hexdigest()
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    manifest_path.chmod(0o600)

    with pytest.raises(EnronBankBuildError, match="promotion ledger"):
        verify_enron_bank_build(output)


def test_verifier_rejects_manifest_artifact_traversal(tmp_path: Path) -> None:
    development, _sealed = _development_bundle(tmp_path)
    output = tmp_path / "build"
    build_enron_intelligence_bank(EnronBankBuildOptions(development_run=development, output_dir=output))
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"]["selected_bank"]["name"] = "../bank.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(EnronBankBuildError, match="artifact name"):
        verify_enron_bank_build(output)


def test_verifier_rejects_unexpected_symlinked_directory(tmp_path: Path) -> None:
    development, _sealed = _development_bundle(tmp_path)
    output = tmp_path / "build"
    build_enron_intelligence_bank(EnronBankBuildOptions(development_run=development, output_dir=output))
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    (output / "unexpected").symlink_to(outside, target_is_directory=True)

    with pytest.raises(EnronBankBuildError, match="symlink"):
        verify_enron_bank_build(output)


def test_verifier_rejects_non_private_artifact_directory(tmp_path: Path) -> None:
    development, _sealed = _development_bundle(tmp_path)
    output = tmp_path / "build"
    build_enron_intelligence_bank(EnronBankBuildOptions(development_run=development, output_dir=output))
    (output / "validation").chmod(0o750)

    with pytest.raises(EnronBankBuildError, match="non-private"):
        verify_enron_bank_build(output)


def test_verifier_detects_identical_file_replacement_during_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    development, _sealed = _development_bundle(tmp_path)
    output = tmp_path / "build"
    build_enron_intelligence_bank(EnronBankBuildOptions(development_run=development, output_dir=output))
    target = output / "collision-report.json"
    original_read = bank_workflow._read_private_json
    replaced = False

    def replace_after_initial_inventory(path: Path, **kwargs: Any) -> Any:
        nonlocal replaced
        value = original_read(path, **kwargs)
        if path.name == "bank-card.json" and not replaced:
            replacement = output / "replacement.json"
            replacement.write_bytes(target.read_bytes())
            replacement.chmod(0o600)
            replacement.replace(target)
            replaced = True
        return value

    monkeypatch.setattr(bank_workflow, "_read_private_json", replace_after_initial_inventory)

    with pytest.raises(EnronBankBuildError, match="changed during verification"):
        verify_enron_bank_build(output)


@pytest.mark.parametrize("relative_path", ["collision-report.json", "mining.sqlite3"])
def test_verifier_rejects_identical_artifact_aba_during_semantic_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative_path: str,
) -> None:
    development, _sealed = _development_bundle(tmp_path)
    output = tmp_path / "build"
    build_enron_intelligence_bank(EnronBankBuildOptions(development_run=development, output_dir=output))
    target = output / relative_path
    original_identity = target.stat()
    parked = tmp_path / f"parked-{target.name}"
    replacement = tmp_path / f"replacement-{target.name}"
    replacement.write_bytes(target.read_bytes())
    replacement.chmod(0o600)
    original_open = bank_workflow.open_private_binary_input
    target_opens = 0

    def aba_open(path: Path, **kwargs: Any):
        nonlocal target_opens
        if path != target:
            return original_open(path, **kwargs)
        target_opens += 1
        if target_opens != 2:
            return original_open(path, **kwargs)
        target.replace(parked)
        replacement.replace(target)
        try:
            opened = original_open(path, **kwargs)
        finally:
            target.replace(replacement)
            parked.replace(target)
        return opened

    monkeypatch.setattr(bank_workflow, "open_private_binary_input", aba_open)

    with pytest.raises(EnronBankBuildError, match="changed during verification"):
        verify_enron_bank_build(output)

    restored_identity = target.stat()
    assert (restored_identity.st_dev, restored_identity.st_ino) == (
        original_identity.st_dev,
        original_identity.st_ino,
    )


def test_builder_rejects_jsonl_lines_its_verifier_cannot_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    development, _sealed = _development_bundle(tmp_path)
    output = tmp_path / "build"
    monkeypatch.setattr(bank_workflow, "_MAX_PRIVATE_JSONL_LINE_BYTES", 64)

    with pytest.raises(EnronBankBuildError, match="line exceeds"):
        build_enron_intelligence_bank(EnronBankBuildOptions(development_run=development, output_dir=output))

    assert not output.exists()


def test_builder_normalizes_late_development_tamper_and_rolls_back_private_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    development, _sealed = _development_bundle(tmp_path)
    output = tmp_path / "build"
    original_load = bank_workflow.load_enron_development_split

    def load_then_tamper(path: Path, **kwargs: Any):
        loaded = original_load(path, **kwargs)
        train_path = path / "train.jsonl"
        rows = [json.loads(line) for line in train_path.read_text(encoding="utf-8").splitlines()]
        current_body = str(rows[0]["views"]["current_body"])
        rows[0]["views"]["current_body"] = ("X" if not current_body.startswith("X") else "Y") + current_body[1:]
        train_path.write_text(
            "".join(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
            encoding="utf-8",
        )
        train_path.chmod(0o600)
        return loaded

    monkeypatch.setattr(bank_workflow, "load_enron_development_split", load_then_tamper)

    with pytest.raises(EnronBankBuildError, match=r"(?i)(changed|unsafe)"):
        build_enron_intelligence_bank(EnronBankBuildOptions(development_run=development, output_dir=output))

    assert not output.exists()
    assert not tuple(output.parent.glob(f".{output.name}.stage-*"))


def test_mining_capacity_fails_closed_before_unbounded_growth(tmp_path: Path) -> None:
    rows = []
    for index in range(3):
        record = {
            "document_id": f"doc_{index + 1:064x}",
            "date": {"utc": None},
            "headers": {
                "from": [{"name": "Person Fixture", "address": f"person{index}@example.invalid"}],
                "to": [],
                "cc": [],
                "bcc": [],
            },
        }
        rows.append(
            (
                record,
                {
                    "document_id": record["document_id"],
                    "group_id": f"sha256:{index + 1:064x}",
                    "role": "train",
                },
            )
        )
    spool = tmp_path / "bounded.sqlite3"
    spool.touch()
    with pytest.raises(EnronBankBuildError, match="Unique candidates"):
        mine_enron_candidates(
            rows,
            sqlite_path=spool,
            train_artifact_sha256="sha256:" + "d" * 64,
            policy=EnronBankPolicy(max_unique_candidates=2),
        )


def test_default_policy_commits_to_the_frozen_quality_prediction_capacity() -> None:
    policy = EnronBankPolicy()

    assert policy.max_train_artifact_bytes == 512 * 1024 * 1024
    assert policy.max_validation_records == 10_000
    assert policy.max_validation_artifact_bytes == 96 * 1024 * 1024
    assert policy.max_validation_entries == 250_000
    assert policy.max_validation_spans == 150_000
    assert policy.max_quality_predictions == DEFAULT_MAX_QUALITY_PREDICTIONS_TOTAL
    assert policy.max_development_memberships_bytes == 48 * 1024 * 1024
    assert policy.max_development_samples_bytes == 24 * 1024 * 1024
    assert policy.max_observations == 2_000_000
    assert policy.max_unique_candidates == 50_000
    assert policy.descriptor()["capacity"]["max_quality_predictions"] == DEFAULT_MAX_QUALITY_PREDICTIONS_TOTAL
    _validate_policy(policy)


def test_declared_validation_capacity_fails_before_private_run_and_mining(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    development, _sealed = _development_bundle(tmp_path)
    output = tmp_path / "build"

    def unexpected_mining(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("capacity preflight must run before candidate mining")

    monkeypatch.setattr(bank_workflow, "mine_enron_candidates", unexpected_mining)

    with pytest.raises(EnronBankBuildError, match="admission limits"):
        build_enron_intelligence_bank(
            EnronBankBuildOptions(
                development_run=development,
                output_dir=output,
                policy=EnronBankPolicy(max_validation_records=1),
            )
        )

    assert not output.exists()
    assert not tuple(output.parent.glob(f".{output.name}.stage-*"))


@pytest.mark.parametrize(
    ("policy", "message"),
    [
        (EnronBankPolicy(max_quality_predictions=DEFAULT_MAX_QUALITY_PREDICTIONS_TOTAL - 1), "evaluator limit"),
        (
            EnronBankPolicy(max_validation_spans=DEFAULT_MAX_QUALITY_PREDICTIONS_TOTAL + 1),
            "prediction capacity",
        ),
    ],
)
def test_policy_rejects_quality_capacity_drift(policy: EnronBankPolicy, message: str) -> None:
    with pytest.raises(EnronBankBuildError, match=message):
        _validate_policy(policy)


def test_private_policy_parser_rejects_committed_quality_capacity_drift() -> None:
    descriptor = EnronBankPolicy().descriptor()
    descriptor["capacity"]["max_quality_predictions"] -= 1

    with pytest.raises(EnronBankBuildError, match="descriptor is invalid"):
        _policy_from_descriptor(descriptor)


@pytest.mark.parametrize(
    ("policy", "message"),
    [
        (EnronBankPolicy(max_validation_entries=1), "header entries"),
        (EnronBankPolicy(max_validation_spans=1), "structured spans"),
        (EnronBankPolicy(max_validation_text_utf8_bytes=8), "structured text"),
    ],
)
def test_validation_projection_total_capacity_limits_fail_closed(
    policy: EnronBankPolicy,
    message: str,
) -> None:
    document_id = "doc_" + "9" * 64
    record = {
        "document_id": document_id,
        "headers": {
            "from": [{"name": "Alice Alpha", "address": "alice.alpha@example.invalid"}],
            "to": [{"name": "Bob Beta", "address": "bob.beta@example.invalid"}],
            "cc": [],
            "bcc": [],
        },
    }
    membership = {"document_id": document_id, "group_id": "sha256:" + "9" * 64, "role": "validation"}

    with pytest.raises(EnronBankBuildError, match=message):
        _validation_projection(
            [(record, membership)],
            source_binding={"validation_artifact_sha256": "sha256:" + "8" * 64},
            policy=policy,
        )


def test_iteration_selection_rejects_a_cataloged_person_miss() -> None:
    contact = {
        "id": "validation_contact_structured_weak",
        "false_negative": 0,
        "cataloged_false_negative": 0,
        "cataloged_wrong_canonical": 0,
    }
    person = {
        "id": "validation_person_structured_weak",
        "cataloged_false_negative": 1,
        "cataloged_wrong_canonical": 0,
    }
    evaluated = tuple(
        {
            "quality": {
                "protocol_sha256": "sha256:" + "9" * 64,
                "quality": {"slices": [contact, person]},
            }
        }
        for _iteration in ITERATION_POLICIES
    )

    with pytest.raises(EnronBankBuildError, match="cataloged person miss"):
        _decide_iterations(evaluated)

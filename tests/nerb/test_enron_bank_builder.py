from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

import nerb.enron_bank_workflow as bank_workflow
from nerb.engines import compile_bank
from nerb.enron_bank_builder import (
    ITERATION_POLICIES,
    EnronBankBuildError,
    EnronBankPolicy,
    curate_enron_iteration,
    mine_enron_candidates,
)
from nerb.enron_bank_workflow import (
    EnronBankBuildOptions,
    _paired_role,
    _source_binding,
    _validate_public_card,
    _validation_projection,
    build_enron_intelligence_bank,
    verify_enron_bank_build,
)
from nerb.enron_preparation import EnronPreparationOptions, prepare_enron_source
from nerb.enron_splitting import EnronSplitOptions, load_enron_development_split, split_enron_preparation


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
    source_binding = _source_binding(development, development_path, "enron-v2")
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

    verification = verify_enron_bank_build(output)
    assert verification["valid"] is True
    assert verification["validation_reverified"] is True
    assert verification["sealed_test_accessed"] is False


def test_private_builder_is_deterministic_for_same_frozen_development_bundle(tmp_path: Path) -> None:
    development, _sealed = _development_bundle(tmp_path)
    first = tmp_path / "first"
    second = tmp_path / "second"

    first_card = build_enron_intelligence_bank(EnronBankBuildOptions(development_run=development, output_dir=first))
    second_card = build_enron_intelligence_bank(EnronBankBuildOptions(development_run=development, output_dir=second))

    assert first_card == second_card
    for relative in ("bank.json", "candidates.jsonl", "candidate-funnel.json", "iterations.jsonl"):
        assert (first / relative).read_bytes() == (second / relative).read_bytes()


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
    changed = dict(card)
    changed["charter"] = {"leaked": "private.person@example.invalid"}
    changed["run_sha256"] = "sha256:" + "0" * 64

    with pytest.raises(EnronBankBuildError, match="run commitment|direct identifier"):
        _validate_public_card(changed)


def test_verifier_rejects_tampered_private_bank(tmp_path: Path) -> None:
    development, _sealed = _development_bundle(tmp_path)
    output = tmp_path / "build"
    build_enron_intelligence_bank(EnronBankBuildOptions(development_run=development, output_dir=output))
    bank_path = output / "bank.json"
    bank_path.write_bytes(bank_path.read_bytes() + b" ")

    with pytest.raises(EnronBankBuildError, match="descriptor"):
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

    def replace_after_initial_inventory(path: Path) -> Any:
        nonlocal replaced
        value = original_read(path)
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

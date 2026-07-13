from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import stat
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import nerb.enron_bank_workflow as bank_workflow
import nerb.enron_quality as quality_module
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
    _validation_plan,
    build_enron_intelligence_bank,
)
from nerb.enron_bank_workflow import (
    verify_enron_bank_build as _verify_enron_bank_build_api,
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
    split_scratch = _private_scratch_root(tmp_path, "split-scratch")
    split_enron_preparation(
        EnronSplitOptions(
            preparation_run=preparation,
            development_output_dir=development,
            sealed_output_dir=sealed,
            scratch_dir=split_scratch,
            fixture_mode=True,
            sample_per_role=100,
        )
    )
    return development, sealed


def _private_scratch_root(parent: Path, name: str = "verify-scratch") -> Path:
    scratch = parent / name
    scratch.mkdir(mode=0o700, exist_ok=True)
    return scratch


def _assert_cleanup_tombstones(root: Path, *, count: int) -> None:
    entries = sorted(root.iterdir())
    assert len(entries) == count
    assert all(re.fullmatch(r"\.nerb-cleanup-[0-9a-f]{48}", entry.name) for entry in entries)
    tree = bank_workflow._snapshot_private_tree(root)
    assert all(identity.size == 0 for identity in tree.values() if identity.kind == "file")


def verify_enron_bank_build(
    run_dir: Path,
    *,
    development_run: Path,
    scratch_root: Path | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Keep existing verifier tests concise while always exercising an explicit private root."""

    owned_root = scratch_root or _private_scratch_root(run_dir.parent)
    return _verify_enron_bank_build_api(
        run_dir,
        development_run=development_run,
        scratch_root=owned_root,
        **kwargs,
    )


def _mine(tmp_path: Path, development_path: Path):
    development = load_enron_development_split(development_path)
    source_binding = _source_binding(development, "enron")
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
        validation_plan=bank_workflow._ValidationPlan(
            slices=(),
            unsupported=(),
            artifact_sha256="sha256:" + "0" * 64,
            records=1,
            entries=0,
            spans=0,
            text_utf8_bytes=0,
        ),
        policy=EnronBankPolicy(),
        build_created_at="2026-07-10T00:00:00Z",
    )
    monkeypatch.setattr(bank_workflow, "_verify_enron_bank_build_snapshot", lambda *_args, **_kwargs: snapshot)

    assert marker not in repr(snapshot)
    assert verify_enron_bank_build(tmp_path, development_run=tmp_path) == summary


def test_public_verifier_requires_explicit_scratch_root(tmp_path: Path) -> None:
    with pytest.raises(TypeError, match="scratch_root"):
        _verify_enron_bank_build_api(tmp_path, development_run=tmp_path)  # ty: ignore[missing-argument]


def test_deep_scratch_has_no_system_temp_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected_temporary(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("system temporary storage must not be consulted")

    monkeypatch.setattr(bank_workflow.tempfile, "TemporaryDirectory", unexpected_temporary)

    with pytest.raises(EnronBankBuildError, match="Scratch root is invalid"):
        with bank_workflow._deep_verify_scratch_root(None):  # ty: ignore[invalid-argument-type]
            raise AssertionError("invalid scratch root must fail before allocation")


def test_implicit_build_scratch_accepts_pinned_sticky_shared_temp_base(tmp_path: Path) -> None:
    shared = tmp_path / "shared-temp"
    shared.mkdir(mode=0o700)
    shared.chmod(0o1777)
    sensitive = b"synthetic private scratch payload"

    with bank_workflow._owned_private_scratch_directory(
        shared,
        prefix="nerb-linux-temp-test-",
        allow_sticky_shared_base=True,
    ) as scratch:
        info = scratch.stat()
        assert stat.S_IMODE(info.st_mode) == 0o700
        payload = scratch / "quality.sqlite3"
        payload.write_bytes(sensitive)
        payload.chmod(0o600)

    assert all(sensitive not in path.read_bytes() for path in shared.rglob("*") if path.is_file())


def test_implicit_build_scratch_rejects_shared_temp_base_without_sticky_bit(tmp_path: Path) -> None:
    shared = tmp_path / "unsafe-shared-temp"
    shared.mkdir(mode=0o700)
    shared.chmod(0o777)

    with pytest.raises(EnronBankBuildError, match="non-private entry"):
        with bank_workflow._owned_private_scratch_directory(
            shared,
            prefix="nerb-unsafe-temp-test-",
            allow_sticky_shared_base=True,
        ):
            raise AssertionError("unsafe shared base must fail before allocation")


def test_scratch_budget_accounts_main_file_and_sidecars_together(tmp_path: Path) -> None:
    scratch = _private_scratch_root(tmp_path, "accounted-scratch")
    main = scratch / "mining.sqlite3"
    journal = scratch / "mining.sqlite3-journal"
    main.write_bytes(b"m" * 40)
    journal.write_bytes(b"j" * 30)
    main.chmod(0o600)
    journal.chmod(0o600)

    budget = bank_workflow._ScratchDirectoryBudget(scratch, 64)
    with pytest.raises(EnronBankBuildError, match="declared byte budget"):
        budget.checkpoint()


def test_scratch_budget_rejects_under_budget_leftovers(tmp_path: Path) -> None:
    scratch = _private_scratch_root(tmp_path, "leftover-scratch")
    leftover = scratch / "quality-cmu.sqlite3"
    leftover.write_bytes(b"x")
    leftover.chmod(0o600)

    with pytest.raises(EnronBankBuildError, match="retained a non-tombstone payload"):
        bank_workflow._ScratchDirectoryBudget(scratch, 1024).require_empty()


def test_bank_iteration_scratch_accepts_only_payload_empty_private_tombstones(tmp_path: Path) -> None:
    scratch = _private_scratch_root(tmp_path, "iteration-scratch")
    tombstone = scratch / (".nerb-cleanup-" + "a" * 48)
    tombstone.write_bytes(b"")
    tombstone.chmod(0o600)
    budget = bank_workflow._ScratchDirectoryBudget(scratch, 1024)

    budget.require_empty()
    tombstone.write_bytes(b"retained private payload")

    with pytest.raises(EnronBankBuildError, match="non-tombstone payload"):
        budget.require_empty()


def test_bank_iteration_scratch_move_out_wipes_pinned_payload_and_preserves_substitute(tmp_path: Path) -> None:
    scratch_root = _private_scratch_root(tmp_path, "iteration-scratch-root")
    parked = tmp_path / "parked-iteration-scratch"
    substitute: Path | None = None

    with pytest.raises(EnronBankBuildError, match="Scratch directory failed safely"):
        with bank_workflow._owned_private_scratch_directory(
            scratch_root,
            prefix="nerb-enron-bank-iteration-test-",
        ) as scratch:
            private_payload = scratch / "quality.sqlite3"
            private_payload.write_bytes(b"private bank iteration payload")
            private_payload.chmod(0o600)
            scratch.replace(parked)
            scratch.mkdir(mode=0o700)
            substitute = scratch / "preserve.txt"
            substitute.write_bytes(b"unrelated replacement")
            substitute.chmod(0o600)

    assert (parked / "quality.sqlite3").read_bytes() == b""
    assert substitute is not None and substitute.read_bytes() == b"unrelated replacement"


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
            _source_binding(development, "enron")
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
    assert card["validation"]["evaluator_sha256"].startswith("sha256:")
    assert card["validation"]["open_world_metrics_supported"] is False
    assert card["validation"]["contact"]["precision"] is None
    assert card["catalog_conformance"]["passed"] is True
    assert card["promotable"] is False
    assert not (sealed / "ACCESS_CLAIMED.json").exists()
    assert not (sealed / "ACCESS_OUTCOME.json").exists()

    snapshot = bank_workflow._verify_enron_bank_build_snapshot(
        output,
        development_run=development,
        scratch_root=_private_scratch_root(tmp_path),
    )
    verification = snapshot.summary
    assert card["validation"]["evaluator_sha256"] == verification["selected_validation_evaluator_sha256"]
    assert set(verification) == {
        "schema_version",
        "valid",
        "benchmark_version",
        "fixture_mode",
        "promotable",
        "bank_sha256",
        "bank_card_run_sha256",
        "candidate_source_sha256",
        "candidate_ledger_sha256",
        "candidate_count",
        "iteration_count",
        "selected_iteration_id",
        "selected_validation_run_sha256",
        "selected_validation_evaluator_sha256",
        "builder_policy_sha256",
        "catalog_conformance_passed",
        "validation_reverified",
        "cmu_reverified",
        "sealed_test_accessed",
        "privacy",
    }
    assert verification["valid"] is True
    assert verification["candidate_source_sha256"] == card["builder"]["candidate_source_sha256"]
    assert verification["candidate_ledger_sha256"] == card["builder"]["candidate_ledger_sha256"]
    assert verification["validation_reverified"] is True
    assert verification["sealed_test_accessed"] is False
    assert snapshot.card == card
    assert snapshot.bank_payload == (output / "bank.json").read_bytes()
    assert snapshot.bank["metadata"]["sealed_test_accessed"] is False
    assert snapshot.validation_plan.records == card["source"]["validation_records"]
    assert snapshot.build_created_at == "2026-07-10T00:00:00Z"
    artifact_ids = set(json.loads((output / "manifest.json").read_text(encoding="utf-8"))["artifacts"])
    assert "validation_plan" in artifact_ids
    assert "validation_documents" not in artifact_ids
    assert not any(artifact_id.startswith("validation_gold_") for artifact_id in artifact_ids)
    assert not (output / "validation/documents.jsonl").exists()
    assert not tuple((output / "validation").glob("gold-iteration-*.jsonl"))


def test_streaming_validation_is_one_pass_differential_and_heartbeat_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    development, _sealed = _development_bundle(tmp_path)
    output = tmp_path / "build"
    card = build_enron_intelligence_bank(EnronBankBuildOptions(development_run=development, output_dir=output))
    deep = verify_enron_bank_build(output, development_run=development)
    stored_plan = json.loads((output / "validation/plan.json").read_text(encoding="utf-8"))
    validation_records = int(card["source"]["validation_records"])
    scratch = _private_scratch_root(tmp_path, "streaming-scratch")
    progress: list[int] = []
    activity_count = 0
    compile_calls = 0
    actual_compile = quality_module.compile_bank

    def heartbeat() -> None:
        nonlocal activity_count
        activity_count += 1

    def counted_compile(*args: Any, **kwargs: Any) -> Any:
        nonlocal compile_calls
        compile_calls += 1
        return actual_compile(*args, **kwargs)

    monkeypatch.setattr(quality_module, "compile_bank", counted_compile)
    monkeypatch.setattr(
        bank_workflow,
        "mine_enron_candidates",
        lambda *_args, **_kwargs: pytest.fail("streaming validation must not remine train"),
    )
    monkeypatch.setattr(
        bank_workflow,
        "curate_enron_iteration",
        lambda *_args, **_kwargs: pytest.fail("streaming validation must not recurate the bank"),
    )

    summary = bank_workflow._run_enron_streaming_validation(
        output,
        development_run=development,
        scratch_root=scratch,
        progress_callback=progress.append,
        activity_callback=heartbeat,
    )

    assert summary == {
        "validation_records": validation_records,
        "validation_text_utf8_bytes": stored_plan["text_utf8_bytes"],
        "bank_sha256": deep["bank_sha256"],
        "bank_card_run_sha256": deep["bank_card_run_sha256"],
        "evaluator_sha256": deep["selected_validation_evaluator_sha256"],
        "builder_policy_sha256": deep["builder_policy_sha256"],
        "validation_run_sha256": deep["selected_validation_run_sha256"],
        "development_manifest_sha256": card["source"]["development_manifest_sha256"],
        "sealed_test_accessed": False,
    }
    assert progress == [validation_records]
    assert activity_count > 0
    assert compile_calls == 1
    _assert_cleanup_tombstones(scratch, count=1)
    assert "_run_enron_streaming_validation" not in bank_workflow.__all__


def test_streaming_validation_rejects_tamper_and_path_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    development, _sealed = _development_bundle(tmp_path)
    output = tmp_path / "build"
    build_enron_intelligence_bank(EnronBankBuildOptions(development_run=development, output_dir=output))
    scratch = _private_scratch_root(tmp_path, "streaming-scratch")
    quality_path = output / "validation/quality-iteration-02.json"
    original_quality = quality_path.read_bytes()
    quality_path.write_bytes(original_quality + b" ")
    quality_path.chmod(0o600)
    with pytest.raises(EnronBankBuildError, match="artifact descriptor"):
        bank_workflow._run_enron_streaming_validation(
            output,
            development_run=development,
            scratch_root=scratch,
        )
    quality_path.write_bytes(original_quality)
    quality_path.chmod(0o600)

    target = output / "collision-report.json"
    original_read = bank_workflow._read_private_json
    replaced = False

    def replace_unconsumed_artifact(path: Path, **kwargs: Any) -> Any:
        nonlocal replaced
        value = original_read(path, **kwargs)
        if path.name == "bank-card.json" and not replaced:
            replacement = tmp_path / "replacement-collision.json"
            replacement.write_bytes(target.read_bytes())
            replacement.chmod(0o600)
            replacement.replace(target)
            replaced = True
        return value

    monkeypatch.setattr(bank_workflow, "_read_private_json", replace_unconsumed_artifact)
    with pytest.raises(EnronBankBuildError, match="tree changed during streaming validation"):
        bank_workflow._run_enron_streaming_validation(
            output,
            development_run=development,
            scratch_root=scratch,
        )
    assert replaced is True
    _assert_cleanup_tombstones(scratch, count=2)


def test_streaming_validation_activity_failure_cleans_caller_scratch(
    tmp_path: Path,
) -> None:
    development, _sealed = _development_bundle(tmp_path)
    output = tmp_path / "build"
    build_enron_intelligence_bank(EnronBankBuildOptions(development_run=development, output_dir=output))
    scratch = _private_scratch_root(tmp_path, "streaming-scratch")
    private_marker = str(tmp_path / "callback-private-marker")

    def fail_while_quality_spool_exists() -> None:
        if tuple(scratch.rglob("*.sqlite3")):
            raise RuntimeError(private_marker)

    with pytest.raises(EnronBankBuildError, match="streamed safely") as captured:
        bank_workflow._run_enron_streaming_validation(
            output,
            development_run=development,
            scratch_root=scratch,
            activity_callback=fail_while_quality_spool_exists,
        )
    assert private_marker not in str(captured.value)
    _assert_cleanup_tombstones(scratch, count=1)


def test_full_capacity_allocation_and_near_max_bank_conformance_fit_closed_limits() -> None:
    policy = EnronBankPolicy()
    assert policy.max_active_contacts == 12_000
    assert policy.max_active_people == 12_000
    assert policy.max_active_person_aliases == 12_999
    assert policy.max_active_domains == 0
    assert policy.max_active_contacts + policy.max_active_person_aliases + 1 == policy.max_active_patterns == 25_000
    assert policy.max_unique_candidates == 200_000

    value_padding = "x" * 1_050

    def literal_pattern(index: int, prefix: str, *, normalize_whitespace: bool) -> dict[str, Any]:
        return {
            "kind": "literal",
            "value": f"{prefix}{index:05d} {value_padding}",
            "description": "Synthetic capacity witness.",
            "status": "active",
            "priority": index,
            "case_sensitive": False,
            "normalize_whitespace": normalize_whitespace,
            "left_boundary": "word",
            "right_boundary": "word",
            "metadata": {},
        }

    contact_patterns = {
        f"contact_{index:05d}": literal_pattern(index, "contact", normalize_whitespace=False)
        for index in range(policy.max_active_contacts)
    }
    person_patterns = {
        f"person_{index:05d}": literal_pattern(12_000 + index, "person", normalize_whitespace=True)
        for index in range(policy.max_active_person_aliases)
    }
    contact_patterns["structured_email"] = {
        "kind": "regex",
        "value": r"(?i:[a-z]+@[a-z]+\.[a-z]+)",
        "description": "Synthetic fallback witness.",
        "status": "active",
        "priority": 24_999,
        "metadata": {},
    }
    bank = {
        "schema_version": "nerb.bank.v1",
        "id": "synthetic_capacity",
        "name": "Synthetic capacity bank",
        "description": "Near-maximum byte and exact-pattern capacity witness.",
        "version": "1",
        "status": "active",
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
        "unicode_normalization": "none",
        "default_regex_flags": [],
        "entities": {
            "contact": {
                "description": "Synthetic contacts.",
                "status": "active",
                "regex_flags": [],
                "names": {
                    "all_contacts": {
                        "canonical": "Synthetic contact",
                        "description": "Synthetic contacts.",
                        "status": "active",
                        "patterns": contact_patterns,
                        "metadata": {},
                    }
                },
                "metadata": {},
            },
            "person": {
                "description": "Synthetic people.",
                "status": "active",
                "regex_flags": [],
                "names": {
                    "all_people": {
                        "canonical": "Synthetic person",
                        "description": "Synthetic people.",
                        "status": "active",
                        "patterns": person_patterns,
                        "metadata": {},
                    }
                },
                "metadata": {},
            },
        },
        "metadata": {},
    }
    bank_bytes = len(bank_workflow._canonical_json_bytes(bank))
    positives, negatives = bank_workflow._conformance_cases(bank)
    artifact_bytes = tuple(
        sum(len(bank_workflow._canonical_json_bytes(item)) + 1 for item in values) for values in (positives, negatives)
    )

    assert 30 * 1024 * 1024 < bank_bytes <= policy.max_bank_json_bytes
    assert len(positives) + len(negatives) == 88_009
    assert len(positives) + len(negatives) <= bank_workflow._MAX_CONFORMANCE_TOTAL_RECORDS
    assert all(value <= bank_workflow._MAX_CONFORMANCE_ARTIFACT_BYTES for value in artifact_bytes)


def test_build_and_deep_replay_progress_is_exact_monotonic_and_output_equivalent(tmp_path: Path) -> None:
    development_path, _sealed = _development_bundle(tmp_path)
    development = load_enron_development_split(development_path)
    roles = development.manifest["development_roles"]
    train_records = roles["train"]["records"]
    validation_records = roles["validation"]["records"]
    build_events: list[int] = []
    callback_output = tmp_path / "callback-build"
    reference_output = tmp_path / "reference-build"

    callback_card = build_enron_intelligence_bank(
        EnronBankBuildOptions(
            development_run=development_path,
            output_dir=callback_output,
            progress_callback=build_events.append,
        )
    )
    reference_card = build_enron_intelligence_bank(
        EnronBankBuildOptions(development_run=development_path, output_dir=reference_output)
    )

    assert callback_card == reference_card
    assert build_events == [train_records]

    replay_events: list[int] = []
    replayed = verify_enron_bank_build(
        callback_output,
        development_run=development_path,
        progress_callback=replay_events.append,
    )
    reference = verify_enron_bank_build(reference_output, development_run=development_path)

    assert replayed == reference
    assert replay_events == [train_records + validation_records]
    assert replayed["selected_validation_run_sha256"].startswith("sha256:")
    assert replayed["selected_validation_evaluator_sha256"].startswith("sha256:")
    assert replayed["builder_policy_sha256"] == EnronBankPolicy().sha256


def test_progress_reporter_emits_closed_intervals_and_one_final_value() -> None:
    events: list[int] = []
    reporter = bank_workflow._ProgressReporter(events.append)

    for _index in range(20_001):
        reporter.consumed()
    reporter.finish()
    reporter.finish()

    assert events == [10_000, 20_000, 20_001]


def test_progress_callback_failures_clean_build_output_and_deep_scratch(tmp_path: Path) -> None:
    development, _sealed = _development_bundle(tmp_path)
    failed_output = tmp_path / "failed-build"

    def abort_build(_count: int) -> None:
        raise RuntimeError("stop build")

    with pytest.raises(RuntimeError, match="stop build"):
        build_enron_intelligence_bank(
            EnronBankBuildOptions(
                development_run=development,
                output_dir=failed_output,
                progress_callback=abort_build,
            )
        )
    assert not failed_output.exists()

    output = tmp_path / "build"
    build_enron_intelligence_bank(EnronBankBuildOptions(development_run=development, output_dir=output))
    scratch_root = tmp_path / "scratch"
    scratch_root.mkdir(mode=0o700)

    def abort_replay(_count: int) -> None:
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        verify_enron_bank_build(
            output,
            development_run=development,
            scratch_root=scratch_root,
            progress_callback=abort_replay,
        )
    _assert_cleanup_tombstones(scratch_root, count=1)


def test_deep_verifier_places_every_sqlite_spool_in_caller_scratch_and_cleans_it(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    development, _sealed = _development_bundle(tmp_path)
    output = tmp_path / "build"
    build_enron_intelligence_bank(EnronBankBuildOptions(development_run=development, output_dir=output))
    scratch_root = tmp_path / "scratch"
    scratch_root.mkdir(mode=0o700)
    observed: list[Path] = []
    original_copy = bank_workflow._copy_verified_private_artifact
    original_quality = bank_workflow.evaluate_enron_quality
    original_mine = bank_workflow.mine_enron_candidates

    def record_copy(source: Path, destination: Path, **kwargs: Any) -> None:
        observed.append(destination)
        original_copy(source, destination, **kwargs)

    def record_quality(*args: Any, **kwargs: Any) -> dict[str, Any]:
        observed.append(Path(kwargs["spool_path"]))
        return original_quality(*args, **kwargs)

    def record_mine(*args: Any, **kwargs: Any):
        observed.append(Path(kwargs["sqlite_path"]))
        return original_mine(*args, **kwargs)

    monkeypatch.setattr(bank_workflow, "_copy_verified_private_artifact", record_copy)
    monkeypatch.setattr(bank_workflow, "evaluate_enron_quality", record_quality)
    monkeypatch.setattr(bank_workflow, "mine_enron_candidates", record_mine)

    verify_enron_bank_build(output, development_run=development, scratch_root=scratch_root)

    assert len(observed) == 5
    assert all(path.is_relative_to(scratch_root) for path in observed)
    assert all(not path.exists() for path in observed)
    _assert_cleanup_tombstones(scratch_root, count=1)


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

    def fake_evaluate(
        bank,
        *,
        annotation_run_dir,
        catalog_bindings_path,
        spool_path,
        max_spool_bytes,
        activity_callback=None,
    ):
        observed["bank"] = bank
        observed["annotation_run"] = annotation_run_dir
        observed["bindings_path"] = catalog_bindings_path
        observed["bindings"] = [json.loads(line) for line in catalog_bindings_path.read_text().splitlines()]
        observed["spool_path"] = spool_path
        observed["max_spool_bytes"] = max_spool_bytes
        spool_path.write_bytes(b"transient metadata spool")
        spool_path.chmod(0o600)
        spool_path.unlink()
        return {"evaluated": True, "contract_validation": {"valid": True}}

    monkeypatch.setattr(bank_workflow, "evaluate_cmu_enron_training_quality_files", fake_evaluate)
    bank = {"id": "selected_bank"}
    with bank_workflow.PrivateRun(tmp_path / "private-build", allow_unignored_output=True) as run:
        scratch = run.ensure_directory("scratch")
        bindings, quality = bank_workflow._stage_and_evaluate_cmu_auxiliary(
            run,
            bank,
            annotation_run,
            reviewed,
            spool_path=scratch / "cmu.sqlite3",
            max_spool_bytes=1024 * 1024,
        )

        copied_path = run.stage_dir / "auxiliary/cmu-train-catalog-bindings.jsonl"
        assert copied_path == observed["bindings_path"]
        assert copied_path != reviewed
        assert observed["bindings"] == [binding]
        assert copied_path.read_bytes() == bank_workflow._canonical_json_bytes(binding) + b"\n"
        assert observed["spool_path"] == scratch / "cmu.sqlite3"
        assert observed["max_spool_bytes"] == 1024 * 1024
        assert not observed["spool_path"].exists()

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
        verify_enron_bank_build(output, development_run=development)


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
        verify_enron_bank_build(output, development_run=development)


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

    verify_enron_bank_build(output, development_run=development)

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
        verify_enron_bank_build(output, development_run=development)


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
        bank_workflow._read_private_jsonl(path, max_bytes=1024, max_records=1)


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
        verify_enron_bank_build(output, development_run=development)


def test_candidate_ledger_record_ceiling_is_artifact_specific_and_precedes_fingerprinting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    development, _sealed = _development_bundle(tmp_path)
    output = tmp_path / "build"
    policy = EnronBankPolicy()
    build_enron_intelligence_bank(EnronBankBuildOptions(development_run=development, output_dir=output, policy=policy))
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"]["candidates"]["records"] = (
        policy.max_unique_candidates + bank_workflow._MAX_CANDIDATE_LEDGER_EXTRA_RECORDS + 1
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    manifest_path.chmod(0o600)
    original_fingerprint = bank_workflow._fingerprint_private_artifact

    def reject_candidate_fingerprint(path: Path, **kwargs: Any):
        if path == output / "candidates.jsonl":
            raise AssertionError("candidate ceiling must be checked before fingerprinting")
        return original_fingerprint(path, **kwargs)

    monkeypatch.setattr(bank_workflow, "_fingerprint_private_artifact", reject_candidate_fingerprint)

    with pytest.raises(EnronBankBuildError, match="resource limit"):
        verify_enron_bank_build(output, development_run=development)


def test_candidate_ledger_verification_retains_only_one_parsed_row(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    development, _sealed = _development_bundle(tmp_path)
    output = tmp_path / "build"
    build_enron_intelligence_bank(EnronBankBuildOptions(development_run=development, output_dir=output))
    batch_sizes: list[int] = []
    materialized_paths: list[Path] = []
    original_validate = bank_workflow._verify_candidate_ledger
    original_jsonl = bank_workflow._read_private_jsonl

    def record_batch(candidates, bank, **kwargs: Any):
        batch_sizes.append(len(candidates))
        return original_validate(candidates, bank, **kwargs)

    def record_materialized(path: Path, **kwargs: Any):
        materialized_paths.append(path)
        return original_jsonl(path, **kwargs)

    monkeypatch.setattr(bank_workflow, "_verify_candidate_ledger", record_batch)
    monkeypatch.setattr(bank_workflow, "_read_private_jsonl", record_materialized)

    verify_enron_bank_build(output, development_run=development)

    expected_records = json.loads((output / "manifest.json").read_text(encoding="utf-8"))["artifacts"]["candidates"][
        "records"
    ]
    assert batch_sizes == [expected_records]
    assert output / "candidates.jsonl" not in materialized_paths


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("duplicate_id", "values are invalid"),
        ("duplicate_pattern_ref", "referenced by multiple candidates"),
    ],
)
def test_streamed_candidate_ledger_preserves_cross_row_invariants(
    tmp_path: Path,
    mutation: str,
    message: str,
) -> None:
    development, _sealed = _development_bundle(tmp_path)
    output = tmp_path / "build"
    build_enron_intelligence_bank(EnronBankBuildOptions(development_run=development, output_dir=output))
    bank = json.loads((output / "bank.json").read_text(encoding="utf-8"))
    stored = [json.loads(line) for line in (output / "candidates.jsonl").read_text(encoding="utf-8").splitlines()]
    retained = next(row for row in stored if row["bank_ref"] is not None)
    first = json.loads(json.dumps(retained))
    second = json.loads(json.dumps(retained))
    if mutation == "duplicate_pattern_ref":
        second["candidate_id"] = f"{second['candidate_id']}_copy"
    rows = (first, second)
    ledger = tmp_path / f"{mutation}.jsonl"
    ledger.write_bytes(b"".join(bank_workflow._canonical_json_bytes(row) + b"\n" for row in rows))
    ledger.chmod(0o600)
    fingerprint = bank_workflow._fingerprint_private_artifact(
        ledger,
        max_bytes=1024 * 1024,
        jsonl_record_limit=2,
    )

    with pytest.raises(EnronBankBuildError, match=message):
        bank_workflow._verify_streamed_candidate_ledger(
            ledger,
            expected_candidates=rows,
            bank=bank,
            expected_fingerprint=fingerprint,
            max_bytes=1024 * 1024,
            max_records=2,
        )


def test_mining_snapshot_copy_is_preflighted_against_exact_scratch_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir(mode=0o700)
    budget = bank_workflow.MIN_ENRON_BANK_VERIFY_SCRATCH_BYTES
    identity = bank_workflow._PrivateEntryIdentity(
        kind="file",
        device=1,
        inode=1,
        mode=0o600,
        link_count=1,
        size=budget + 1,
        modified_ns=1,
        changed_ns=1,
    )
    fingerprint = bank_workflow._PrivateFileFingerprint(identity=identity, sha256="sha256:" + "0" * 64)

    def unexpected_copy(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("over-budget mining snapshot must not be copied")

    monkeypatch.setattr(bank_workflow, "_copy_verified_private_artifact", unexpected_copy)

    with pytest.raises(EnronBankBuildError, match="scratch budget"):
        bank_workflow._replay_candidate_pool(
            tmp_path / "missing.sqlite3",
            train_artifact_sha256="sha256:" + "1" * 64,
            policy=EnronBankPolicy(),
            expected_fingerprint=fingerprint,
            scratch_dir=scratch,
            max_scratch_bytes=budget,
            resource_checkpoint=lambda: 0,
        )
    assert list(scratch.iterdir()) == []


def test_mining_snapshot_move_out_wipes_pinned_payload_and_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.sqlite3"
    source.write_bytes(b"private verified mining snapshot")
    source.chmod(0o600)
    fingerprint = bank_workflow._fingerprint_private_artifact(source, max_bytes=1024)
    scratch = _private_scratch_root(tmp_path, "snapshot-scratch")
    parked = tmp_path / "parked-mining-snapshot.sqlite3"
    real_copy = bank_workflow._copy_verified_private_artifact

    def copy_then_substitute(*args: Any, **kwargs: Any) -> None:
        real_copy(*args, **kwargs)
        destination = Path(args[1])
        destination.replace(parked)
        destination.write_bytes(b"replacement private mining snapshot")
        destination.chmod(0o600)

    monkeypatch.setattr(bank_workflow, "_copy_verified_private_artifact", copy_then_substitute)

    with pytest.raises(EnronBankBuildError, match="scratch file changed"):
        bank_workflow._replay_candidate_pool(
            source,
            train_artifact_sha256="sha256:" + "1" * 64,
            policy=EnronBankPolicy(),
            expected_fingerprint=fingerprint,
            scratch_dir=scratch,
            max_scratch_bytes=bank_workflow.MIN_ENRON_BANK_VERIFY_SCRATCH_BYTES,
            resource_checkpoint=lambda: 0,
        )

    assert parked.read_bytes() == b""
    _assert_cleanup_tombstones(scratch, count=1)


def test_fresh_mining_rebuild_move_out_wipes_pinned_payload_and_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratch = _private_scratch_root(tmp_path, "rebuild-scratch")
    parked = tmp_path / "parked-mining-rebuild.sqlite3"

    class EmptyDevelopment:
        def iter_train_records(self) -> tuple[()]:
            return ()

        def iter_train_memberships(self) -> tuple[()]:
            return ()

    def mine_then_substitute(*_args: Any, **kwargs: Any) -> object:
        path = Path(kwargs["sqlite_path"])
        path.write_bytes(b"private fresh mining rebuild")
        path.replace(parked)
        path.write_bytes(b"replacement private mining rebuild")
        path.chmod(0o600)
        return object()

    monkeypatch.setattr(bank_workflow, "mine_enron_candidates", mine_then_substitute)

    with pytest.raises(EnronBankBuildError, match="scratch file changed"):
        bank_workflow._rebuild_candidate_pool_from_development(
            EmptyDevelopment(),
            train_artifact_sha256="sha256:" + "1" * 64,
            policy=EnronBankPolicy(),
            scratch_dir=scratch,
            max_scratch_bytes=bank_workflow.MIN_ENRON_BANK_VERIFY_SCRATCH_BYTES,
            progress=bank_workflow._ProgressReporter(None),
            resource_checkpoint=lambda: 0,
        )

    assert parked.read_bytes() == b""
    _assert_cleanup_tombstones(scratch, count=1)


def test_deep_verifier_rejects_fresh_train_rebuild_identity_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    development, _sealed = _development_bundle(tmp_path)
    output = tmp_path / "build"
    build_enron_intelligence_bank(EnronBankBuildOptions(development_run=development, output_dir=output))
    original_rebuild = bank_workflow._rebuild_candidate_pool_from_development

    def changed_rebuild(*args: Any, **kwargs: Any):
        pool = original_rebuild(*args, **kwargs)
        return replace(pool, ledger_sha256="sha256:" + "0" * 64)

    monkeypatch.setattr(bank_workflow, "_rebuild_candidate_pool_from_development", changed_rebuild)

    with pytest.raises(EnronBankBuildError, match="fresh development-train rebuild"):
        verify_enron_bank_build(output, development_run=development)


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

    with pytest.raises(EnronBankBuildError, match="differs from replayed mining and curation"):
        verify_enron_bank_build(output, development_run=development)


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
        verify_enron_bank_build(output, development_run=development)


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
        verify_enron_bank_build(output, development_run=development)


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
        verify_enron_bank_build(output, development_run=development)


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
        verify_enron_bank_build(output, development_run=development)


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
        verify_enron_bank_build(output, development_run=development)


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
        verify_enron_bank_build(output, development_run=development)


def test_verifier_rejects_manifest_artifact_traversal(tmp_path: Path) -> None:
    development, _sealed = _development_bundle(tmp_path)
    output = tmp_path / "build"
    build_enron_intelligence_bank(EnronBankBuildOptions(development_run=development, output_dir=output))
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"]["selected_bank"]["name"] = "../bank.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(EnronBankBuildError, match="artifact name"):
        verify_enron_bank_build(output, development_run=development)


def test_verifier_rejects_unexpected_symlinked_directory(tmp_path: Path) -> None:
    development, _sealed = _development_bundle(tmp_path)
    output = tmp_path / "build"
    build_enron_intelligence_bank(EnronBankBuildOptions(development_run=development, output_dir=output))
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    (output / "unexpected").symlink_to(outside, target_is_directory=True)

    with pytest.raises(EnronBankBuildError, match="symlink"):
        verify_enron_bank_build(output, development_run=development)


def test_verifier_rejects_non_private_artifact_directory(tmp_path: Path) -> None:
    development, _sealed = _development_bundle(tmp_path)
    output = tmp_path / "build"
    build_enron_intelligence_bank(EnronBankBuildOptions(development_run=development, output_dir=output))
    (output / "validation").chmod(0o750)

    with pytest.raises(EnronBankBuildError, match="non-private"):
        verify_enron_bank_build(output, development_run=development)


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
        verify_enron_bank_build(output, development_run=development)


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
        verify_enron_bank_build(output, development_run=development)

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

    assert policy.max_train_artifact_bytes == 6 * 1024 * 1024 * 1024
    assert policy.max_validation_records == 75_000
    assert policy.max_validation_artifact_bytes == 1024 * 1024 * 1024
    assert policy.max_validation_entries == 1_000_000
    assert policy.max_validation_spans == 1_000_000
    assert policy.max_quality_predictions == DEFAULT_MAX_QUALITY_PREDICTIONS_TOTAL
    assert policy.max_development_memberships_bytes == 512 * 1024 * 1024
    assert policy.max_development_samples_bytes == 64 * 1024 * 1024
    assert policy.max_observations == 10_000_000
    assert policy.max_unique_candidates == 200_000
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
def test_validation_plan_total_capacity_limits_fail_closed(
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
        _validation_plan(
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

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

import nerb.enron_sealed_audit as sealed_audit
from nerb.enron_private_io import EnronPrivateIOError, PrivateRun
from nerb.enron_sealed_audit import (
    EnronSealedAuditError,
    capture_enron_sealed_audit_sample,
    hash_enron_sealed_audit_plan,
    make_enron_sealed_audit_plan,
    select_enron_sealed_audit_sample,
    validate_enron_sealed_audit_plan,
    verify_enron_sealed_audit_sample,
)

SHA_A = "sha256:" + "a" * 64
SHA_B = "sha256:" + "b" * 64
COMMIT = "c" * 40


def _plan(
    sample_size: int = 4,
    frame_documents: int = 7,
    frame_groups: int = 6,
    *,
    max_projection_bytes: int = 10 * 1024 * 1024,
) -> dict[str, Any]:
    return make_enron_sealed_audit_plan(
        sample_size=sample_size,
        frame_documents=frame_documents,
        frame_groups=frame_groups,
        test_artifact_sha256=SHA_A,
        membership_artifact_sha256="sha256:" + "1" * 64,
        split_manifest_sha256="sha256:" + "2" * 64,
        split_policy_sha256=SHA_B,
        frozen_git_commit=COMMIT,
        bank_sha256="sha256:" + "3" * 64,
        evaluator_source_sha256="sha256:" + "4" * 64,
        thresholds_sha256="sha256:" + "5" * 64,
        performance_manifest_sha256="sha256:" + "6" * 64,
        annotation_policy_sha256="sha256:" + "7" * 64,
        catalog_policy_sha256="sha256:" + "8" * 64,
        fixture_mode=True,
        max_input_bytes=32 * 1024 * 1024,
        max_projection_bytes=max_projection_bytes,
        max_retained_projection_bytes=16 * 1024 * 1024,
    )


def _target(plan: Mapping[str, Any]) -> dict[str, str]:
    return {
        "frozen_at": "2026-01-01T00:00:00Z",
        "audit_plan_sha256": hash_enron_sealed_audit_plan(plan),
        "test_artifact_sha256": str(plan["test_artifact_sha256"]),
        "split_manifest_sha256": str(plan["split_manifest_sha256"]),
        "git_commit": str(plan["frozen_git_commit"]),
        "bank_hash": str(plan["bank_sha256"]),
        "evaluator_source_sha256": str(plan["evaluator_source_sha256"]),
        "thresholds_sha256": str(plan["thresholds_sha256"]),
        "performance_manifest_sha256": str(plan["performance_manifest_sha256"]),
    }


def _capture_plan(pairs: list[tuple[dict[str, Any], dict[str, Any]]], sample_size: int = 3) -> dict[str, Any]:
    def artifact_sha256(index: int) -> str:
        digest = hashlib.sha256()
        for pair in pairs:
            digest.update(
                json.dumps(pair[index], ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            )
        return "sha256:" + digest.hexdigest()

    plan = _plan(sample_size, len(pairs), len({pair[1]["group_id"] for pair in pairs}))
    return validate_enron_sealed_audit_plan(
        {
            **plan,
            "test_artifact_sha256": artifact_sha256(0),
            "membership_artifact_sha256": artifact_sha256(1),
        }
    )


def _size_bucket(text: str) -> str:
    size = len(text.encode())
    for upper, label in ((0, "0"), (255, "1-255"), (1023, "256-1023"), (4095, "1024-4095"), (16383, "4096-16383")):
        if size <= upper:
            return label
    return "16384-65535"


def _pair(
    index: int,
    *,
    group: int | None = None,
    identity: str = "all_known",
    text: str | None = None,
    challenges: tuple[str, ...] = (),
) -> tuple[dict[str, Any], dict[str, Any]]:
    selected_text = text if text is not None else f"Exact projection {index}"
    document_id = f"doc_{index:064x}"
    record = {
        "document_id": document_id,
        "views": {"subject_current_body": selected_text, "current_body": "must not be projected"},
    }
    frequencies = {
        "all_known": ["head"],
        "mixed": ["novel", "tail"],
        "all_novel": ["novel"],
        "unavailable": [],
    }[identity]
    count = 0 if identity == "unavailable" else 2 if identity == "mixed" else 1
    membership = {
        "schema_version": "nerb.enron_split_membership.v2",
        "document_id": document_id,
        "group_id": "sha256:" + f"{index if group is None else group:064x}",
        "role": "test",
        "occurrence_count": 1,
        "temporal": {"eligible": True, "status": "valid", "anchor_utc": "2001-01-01T00:00:00Z"},
        "mailbox": "inbox",
        "mailbox_recurrence": "known",
        "size": _size_bucket(selected_text),
        "group_size": "1" if group is None else "2",
        "identities": {"recurrence": identity, "count": count, "contains_frequency": frequencies},
        "views": {"natural": bool(selected_text), "structured": True},
        "challenges": sorted(challenges),
    }
    return record, membership


def test_plan_is_closed_canonical_and_binds_every_frozen_input() -> None:
    plan = _plan()
    assert validate_enron_sealed_audit_plan(dict(reversed(tuple(plan.items())))) == plan
    assert hash_enron_sealed_audit_plan(plan) == hash_enron_sealed_audit_plan(dict(reversed(tuple(plan.items()))))
    assert plan["no_tuning"] is True
    assert plan["fixture_mode"] is True
    assert plan["audit_execution_policy_sha256"] == sealed_audit.AUDIT_EXECUTION_POLICY_SHA256
    assert sealed_audit.AUDIT_EXECUTION_POLICY["prediction_audit"]["selected_case_coverage"] == "exact"
    assert sealed_audit.AUDIT_EXECUTION_POLICY["prediction_audit"]["unresolved_cases_allowed"] == 0
    assert "distinct" in sealed_audit.AUDIT_EXECUTION_POLICY["prediction_audit"]["reviewer_separation"]
    assert sealed_audit.AUDIT_EXECUTION_POLICY["prediction_audit"]["gold_defect"] == "invalidate_without_rescore"
    assert plan["resource_limits"]["max_retained_projection_bytes"] == 16 * 1024 * 1024
    with pytest.raises(EnronSealedAuditError, match="fields"):
        validate_enron_sealed_audit_plan({**plan, "seed": "chosen-after-results"})
    with pytest.raises(EnronSealedAuditError, match="sample size"):
        validate_enron_sealed_audit_plan({**plan, "fixture_mode": False})
    production = {**plan, "fixture_mode": False, "sample_size": 100, "frame_documents": 100, "frame_groups": 100}
    assert validate_enron_sealed_audit_plan(production)["sample_size"] == 100
    changed_catalog = {**plan, "catalog_policy_sha256": "sha256:" + "9" * 64}
    assert hash_enron_sealed_audit_plan(changed_catalog) != hash_enron_sealed_audit_plan(plan)
    with pytest.raises(EnronSealedAuditError, match="identity or policy"):
        validate_enron_sealed_audit_plan({**plan, "audit_execution_policy_sha256": "sha256:" + "9" * 64})


def test_selection_is_order_independent_group_deduplicated_and_exact_projection() -> None:
    pairs = [_pair(index) for index in range(6)] + [_pair(20, group=0)]
    first_rows, first_receipt = select_enron_sealed_audit_sample(pairs, _plan())
    second_rows, second_receipt = select_enron_sealed_audit_sample(reversed(pairs), _plan())
    assert first_rows == second_rows
    assert first_receipt == second_receipt
    assert len(first_rows) == len({row["group_id"] for row in first_rows}) == 4
    assert first_receipt["population_groups"] == 6
    assert all(
        row["text_view"] == "subject_current_body" and "must not be projected" not in row["text"] for row in first_rows
    )
    assert all(
        row["unicode_scalars"] == len(row["text"]) and row["text_sha256"].startswith("sha256:") for row in first_rows
    )


def test_stratified_base_and_hamilton_allocation_are_exact() -> None:
    pairs = [
        *(_pair(index) for index in range(5)),
        *(
            _pair(100 + index, identity="all_novel", text="m" * 1024, challenges=("near_duplicate_group",))
            for index in range(3)
        ),
        *(_pair(200 + index, identity="unavailable", text="l" * 16384) for index in range(2)),
    ]
    rows, receipt = select_enron_sealed_audit_sample(pairs, _plan(7, 10, 10))
    quotas = {(row["identity"], row["size"], row["risk"]): row["quota"] for row in receipt["strata"]}
    assert len(rows) == 7
    assert quotas == {
        ("all_known", "short", "ordinary"): 3,
        ("all_novel", "medium", "risk"): 2,
        ("unavailable", "long", "ordinary"): 2,
    }


def test_selection_rejects_prediction_fields_malformed_membership_and_bounds() -> None:
    record, membership = _pair(1)
    with pytest.raises(EnronSealedAuditError, match="Prediction or label"):
        select_enron_sealed_audit_sample([({**record, "predictions": []}, membership)], _plan(1, 1, 1))
    with pytest.raises(EnronSealedAuditError, match="membership"):
        select_enron_sealed_audit_sample([(record, {**membership, "role": "validation"})], _plan(1, 1, 1))
    with pytest.raises(EnronSealedAuditError, match="row bound"):
        select_enron_sealed_audit_sample([_pair(1), _pair(2)], _plan(1, 1, 1))
    with pytest.raises(EnronSealedAuditError, match="projection exceeds"):
        select_enron_sealed_audit_sample([_pair(1, text="too long")], _plan(1, 1, 1, max_projection_bytes=2))
    with pytest.raises(EnronSealedAuditError, match="group population"):
        select_enron_sealed_audit_sample([_pair(1, group=1), _pair(2, group=1)], _plan(1, 2, 2))


class _FakeAccess:
    def __init__(self, pairs: list[tuple[dict[str, Any], dict[str, Any]]], *, fail_after: int | None = None) -> None:
        self.pairs = pairs
        self.fail_after = fail_after
        self.bound_sha256: str | None = None
        self.output_binding_sha256: str | None = None
        self.expected_committed_output: Path | None = None
        self.outcome: str | None = None

    def bind_audit_plan(self, audit_plan_sha256: str) -> None:
        self.bound_sha256 = audit_plan_sha256

    def __enter__(self) -> _FakeAccess:
        return self

    def iter_records_with_memberships(self) -> Any:
        for index, pair in enumerate(self.pairs):
            if self.fail_after == index:
                raise RuntimeError("synthetic partial stream failure")
            yield pair

    def bind_audit_output(self, audit_output_binding_sha256: str) -> dict[str, Any]:
        if self.expected_committed_output is not None:
            assert (self.expected_committed_output / "COMMITTED").is_file()
        self.output_binding_sha256 = audit_output_binding_sha256
        return {
            "status": "audit_output_bound",
            "audit_output_binding_sha256": audit_output_binding_sha256,
        }

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.outcome = "completed" if exc is None else "failed"


def test_capture_commits_before_completed_access_and_offline_verifier_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pairs = [_pair(index) for index in range(5)]
    plan = _capture_plan(pairs)
    access = _FakeAccess(pairs)
    access.expected_committed_output = tmp_path / "captured"
    monkeypatch.setattr(sealed_audit, "_begin_final_test_access", lambda *_args: access)
    result = capture_enron_sealed_audit_sample(
        tmp_path / "sealed",
        tmp_path / "captured",
        frozen_target=_target(plan),
        plan=plan,
        allow_unignored_output=True,
    )
    verified = verify_enron_sealed_audit_sample(tmp_path / "captured")
    assert access.bound_sha256 == hash_enron_sealed_audit_plan(plan)
    assert access.output_binding_sha256 == result["audit_output_binding_sha256"]
    assert access.outcome == "completed"
    assert result["captured"] is verified["valid"] is True
    assert result["promotable"] is verified["promotable"] is False
    assert result["sample_artifact"] == verified["sample_artifact"]
    assert result["access_completion"] == {
        "status": "completed",
        "audit_output_binding_sha256": result["audit_output_binding_sha256"],
    }
    assert verified["audit_output_binding_sha256"] == result["audit_output_binding_sha256"]
    assert verified["access_completion"] is None
    assert set(path.name for path in (tmp_path / "captured").iterdir()) == {
        "COMMITTED",
        "plan.json",
        "documents.jsonl",
        "receipt.json",
    }


def test_partial_capture_failure_consumes_access_and_leaves_no_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pairs = [_pair(index) for index in range(5)]
    plan = _capture_plan(pairs)
    access = _FakeAccess(pairs, fail_after=2)
    monkeypatch.setattr(sealed_audit, "_begin_final_test_access", lambda *_args: access)
    with pytest.raises(EnronSealedAuditError, match="capture failed"):
        capture_enron_sealed_audit_sample(
            tmp_path / "sealed",
            tmp_path / "partial",
            frozen_target=_target(plan),
            plan=plan,
            allow_unignored_output=True,
        )
    assert access.outcome == "failed"
    assert not (tmp_path / "partial").exists()


def test_commit_failure_consumes_access_and_is_atomic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pairs = [_pair(index) for index in range(5)]
    plan = _capture_plan(pairs)
    access = _FakeAccess(pairs)
    monkeypatch.setattr(sealed_audit, "_begin_final_test_access", lambda *_args: access)

    def fail_commit(self: PrivateRun) -> Path:
        raise EnronPrivateIOError("synthetic commit failure")

    monkeypatch.setattr(PrivateRun, "commit", fail_commit)
    with pytest.raises(EnronSealedAuditError, match="capture failed"):
        capture_enron_sealed_audit_sample(
            tmp_path / "sealed",
            tmp_path / "atomic",
            frozen_target=_target(plan),
            plan=plan,
            allow_unignored_output=True,
        )
    assert access.outcome == "failed"
    assert not (tmp_path / "atomic").exists()


def test_offline_verifier_rejects_corruption(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pairs = [_pair(index) for index in range(5)]
    plan = _capture_plan(pairs)
    monkeypatch.setattr(
        sealed_audit,
        "_begin_final_test_access",
        lambda *_args: _FakeAccess(pairs),
    )
    output = tmp_path / "captured"
    capture_enron_sealed_audit_sample(
        tmp_path / "sealed", output, frozen_target=_target(plan), plan=plan, allow_unignored_output=True
    )
    with (output / "documents.jsonl").open("ab") as handle:
        handle.write(b"{}\n")
    with pytest.raises(EnronSealedAuditError, match="sample"):
        verify_enron_sealed_audit_sample(output)


def test_trusted_binding_rejects_a_self_consistently_rewritten_sample(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pairs = [_pair(index) for index in range(5)]
    plan = _capture_plan(pairs)
    monkeypatch.setattr(sealed_audit, "_begin_final_test_access", lambda *_args: _FakeAccess(pairs))
    output = tmp_path / "captured-rewritten"
    captured = capture_enron_sealed_audit_sample(
        tmp_path / "sealed",
        output,
        frozen_target=_target(plan),
        plan=plan,
        allow_unignored_output=True,
    )
    trusted_binding = captured["audit_output_binding_sha256"]

    rows = [json.loads(line) for line in (output / "documents.jsonl").read_text(encoding="utf-8").splitlines()]
    rows[0]["text"] = "X" + rows[0]["text"][1:]
    rows[0]["text_sha256"] = "sha256:" + hashlib.sha256(rows[0]["text"].encode()).hexdigest()
    rows[0]["unicode_scalars"] = len(rows[0]["text"])
    sample_payload = b"".join(
        json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n" for row in rows
    )
    (output / "documents.jsonl").write_bytes(sample_payload)
    receipt = json.loads((output / "receipt.json").read_text(encoding="utf-8"))
    receipt["sample_artifact"] = {
        "sha256": "sha256:" + hashlib.sha256(sample_payload).hexdigest(),
        "bytes": len(sample_payload),
        "records": len(rows),
    }
    receipt_core = {key: value for key, value in receipt.items() if key != "audit_output_binding_sha256"}
    receipt["audit_output_binding_sha256"] = sealed_audit._audit_output_binding_sha256(receipt_core)  # noqa: SLF001
    (output / "receipt.json").write_text(
        json.dumps(receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    assert verify_enron_sealed_audit_sample(output)["valid"] is True
    with pytest.raises(EnronSealedAuditError, match=r"(?i)(trusted|binding|match)"):
        verify_enron_sealed_audit_sample(
            output,
            expected_audit_output_binding_sha256=trusted_binding,
        )


def test_production_sample_verification_requires_an_immutable_output_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pairs = [_pair(index) for index in range(100)]
    fixture_plan = _capture_plan(pairs, sample_size=100)
    plan = validate_enron_sealed_audit_plan({**fixture_plan, "fixture_mode": False})
    monkeypatch.setattr(sealed_audit, "_begin_final_test_access", lambda *_args: _FakeAccess(pairs))
    output = tmp_path / "production-captured"
    captured = capture_enron_sealed_audit_sample(
        tmp_path / "sealed",
        output,
        frozen_target=_target(plan),
        plan=plan,
        allow_unignored_output=True,
    )

    with pytest.raises(EnronSealedAuditError, match=r"(?i)(production|trusted|outcome)"):
        verify_enron_sealed_audit_sample(output)
    verified = verify_enron_sealed_audit_sample(
        output,
        expected_audit_output_binding_sha256=captured["audit_output_binding_sha256"],
    )
    assert verified["valid"] is True
    assert verified["promotable"] is True


def test_offline_verifier_recomputes_selection_rank(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pairs = [_pair(index) for index in range(5)]
    plan = _capture_plan(pairs)
    monkeypatch.setattr(sealed_audit, "_begin_final_test_access", lambda *_args: _FakeAccess(pairs))
    output = tmp_path / "captured-rank"
    capture_enron_sealed_audit_sample(
        tmp_path / "sealed", output, frozen_target=_target(plan), plan=plan, allow_unignored_output=True
    )

    rows = [json.loads(line) for line in (output / "documents.jsonl").read_text(encoding="utf-8").splitlines()]
    rows[0]["selection_rank_sha256"] = "sha256:" + "9" * 64
    sample_payload = b"".join(
        json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n" for row in rows
    )
    (output / "documents.jsonl").write_bytes(sample_payload)
    receipt = json.loads((output / "receipt.json").read_text(encoding="utf-8"))
    receipt["sample_artifact"] = {
        "sha256": "sha256:" + hashlib.sha256(sample_payload).hexdigest(),
        "bytes": len(sample_payload),
        "records": len(rows),
    }
    (output / "receipt.json").write_text(
        json.dumps(receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(EnronSealedAuditError, match="private sample row"):
        verify_enron_sealed_audit_sample(output)


def test_offline_verifier_recomputes_hamilton_allocation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pairs = [
        *(_pair(index) for index in range(5)),
        *(
            _pair(100 + index, identity="all_novel", text="m" * 1024, challenges=("near_duplicate_group",))
            for index in range(3)
        ),
        *(_pair(200 + index, identity="unavailable", text="l" * 16384) for index in range(2)),
    ]
    plan = _capture_plan(pairs, sample_size=7)
    monkeypatch.setattr(sealed_audit, "_begin_final_test_access", lambda *_args: _FakeAccess(pairs))
    output = tmp_path / "captured-allocation"
    capture_enron_sealed_audit_sample(
        tmp_path / "sealed", output, frozen_target=_target(plan), plan=plan, allow_unignored_output=True
    )

    receipt = json.loads((output / "receipt.json").read_text(encoding="utf-8"))
    populations = {
        ("all_known", "short", "ordinary"): 3,
        ("all_novel", "medium", "risk"): 5,
        ("unavailable", "long", "ordinary"): 2,
    }
    for row in receipt["strata"]:
        row["population_groups"] = populations[(row["identity"], row["size"], row["risk"])]
        row["base"] = min(2, row["population_groups"])
    (output / "receipt.json").write_text(
        json.dumps(receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(EnronSealedAuditError, match="Hamilton"):
        verify_enron_sealed_audit_sample(output)


def test_plan_target_binding_drift_fails_before_access_or_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pairs = [_pair(index) for index in range(5)]
    plan = _capture_plan(pairs)
    started = False

    def begin(*_args: Any) -> None:
        nonlocal started
        started = True

    monkeypatch.setattr(sealed_audit, "_begin_final_test_access", begin)
    target = _target(plan)
    target["bank_hash"] = "sha256:" + "9" * 64
    with pytest.raises(EnronSealedAuditError, match="differs"):
        capture_enron_sealed_audit_sample(
            tmp_path / "sealed",
            tmp_path / "drift",
            frozen_target=target,
            plan=plan,
            allow_unignored_output=True,
        )
    assert started is False
    assert not (tmp_path / "drift").exists()


def test_membership_artifact_drift_consumes_access_and_does_not_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pairs = [_pair(index) for index in range(5)]
    plan = validate_enron_sealed_audit_plan(
        {**_capture_plan(pairs), "membership_artifact_sha256": "sha256:" + "9" * 64}
    )
    access = _FakeAccess(pairs)
    monkeypatch.setattr(sealed_audit, "_begin_final_test_access", lambda *_args: access)
    with pytest.raises(EnronSealedAuditError, match="artifact commitments"):
        capture_enron_sealed_audit_sample(
            tmp_path / "sealed",
            tmp_path / "membership-drift",
            frozen_target=_target(plan),
            plan=plan,
            allow_unignored_output=True,
        )
    assert access.outcome == "failed"
    assert not (tmp_path / "membership-drift").exists()

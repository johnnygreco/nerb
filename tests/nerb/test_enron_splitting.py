from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

import nerb.enron_contract as enron_contract
import nerb.enron_splitting as enron_splitting
from nerb.enron_preparation import EnronPreparationOptions, prepare_enron_source
from nerb.enron_splitting import (
    EnronDevelopmentSplit,
    EnronSplitError,
    EnronSplitOptions,
    load_enron_development_split,
    split_enron_preparation,
    verify_enron_splits,
)

JsonObject = dict[str, Any]


@dataclass(frozen=True)
class SplitRun:
    preparation: Path
    development: Path
    sealed: Path
    seed: str
    summary: Mapping[str, Any]
    loaded: EnronDevelopmentSplit


def _write_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
            for row in rows
        ),
        encoding="utf-8",
    )
    return path


def _row(
    marker: str,
    *,
    date: str | None,
    subject: str | None = None,
    body: str | None = None,
    message_id: str | None = None,
    sender: str | None = None,
    recipients: Sequence[str] | None = None,
    file_name: str | None = None,
) -> JsonObject:
    return {
        "message_id": message_id if message_id is not None else f"<{marker}@fixture.invalid>",
        "subject": subject if subject is not None else f"Subject {marker}",
        "from": sender if sender is not None else f"sender-{marker}@fixture.invalid",
        "to": list(recipients) if recipients is not None else [f"recipient-{marker}@fixture.invalid"],
        "cc": [],
        "bcc": [],
        "date": date,
        "body": (
            body if body is not None else f"Natural private message body for {marker} with unique evidence {marker}."
        ),
        "file_name": file_name if file_name is not None else f"owner-{marker}/inbox/{marker}",
    }


def _dated_rows(count: int, *, prefix: str = "single", start: datetime | None = None) -> list[JsonObject]:
    first = start or datetime(2000, 1, 1, tzinfo=timezone.utc)
    return [
        _row(
            f"{prefix}-{index:03d}",
            date=(first + timedelta(days=index)).isoformat().replace("+00:00", "Z"),
        )
        for index in range(count)
    ]


def _prepare(tmp_path: Path, rows: Sequence[Mapping[str, Any]], *, name: str = "preparation") -> Path:
    source = _write_jsonl(tmp_path / f"{name}.jsonl", rows)
    output = tmp_path / name
    result = prepare_enron_source(
        EnronPreparationOptions(
            output_dir=output,
            input_jsonl=source,
            dataset_id="synthetic/enron-splitting",
            dataset_revision="fixture-v2",
            dataset_split="train",
            max_rows=None,
            max_jsonl_line_bytes=256 * 1024,
            max_body_chars=32 * 1024,
            max_body_bytes=128 * 1024,
            max_subject_chars=1024,
            max_subject_bytes=4 * 1024,
            max_recipients_per_field=64,
            allow_unignored_output=False,
        )
    )
    assert result["committed"] is True
    return output


def _split(
    tmp_path: Path,
    preparation: Path,
    *,
    name: str = "split",
    fixture_mode: bool = True,
    seed: str = "adversarial-split-seed",
    train_fraction: float = 0.8,
    validation_fraction: float = 0.1,
    sample_per_role: int = 4,
) -> SplitRun:
    development = tmp_path / f"{name}-development"
    sealed = tmp_path / f"{name}-sealed"
    summary = split_enron_preparation(
        EnronSplitOptions(
            preparation_run=preparation,
            development_output_dir=development,
            sealed_output_dir=sealed,
            benchmark_version="enron-v2-test",
            seed=seed,
            train_fraction=train_fraction,
            validation_fraction=validation_fraction,
            near_hamming=3,
            max_near_candidate_pairs=1_000_000,
            sample_per_role=sample_per_role,
            fixture_mode=fixture_mode,
            allow_unignored_output=False,
        )
    )
    assert summary["committed"] is True
    return SplitRun(
        preparation=preparation,
        development=development,
        sealed=sealed,
        seed=seed,
        summary=summary,
        loaded=load_enron_development_split(development),
    )


def _read_jsonl(path: Path) -> tuple[JsonObject, ...]:
    return tuple(json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip())


def _role_rows(run: SplitRun) -> dict[str, tuple[JsonObject, ...]]:
    return {
        "train": _read_jsonl(run.development / "train.jsonl"),
        "validation": _read_jsonl(run.development / "validation.jsonl"),
        "test": _read_jsonl(run.sealed / "test.jsonl"),
    }


def _document_roles(run: SplitRun) -> dict[str, str]:
    roles: dict[str, str] = {}
    for role, rows in _role_rows(run).items():
        for row in rows:
            document_id = row.get("document_id")
            assert isinstance(document_id, str)
            assert document_id not in roles
            roles[document_id] = role
    return roles


def _membership_rows(run: SplitRun) -> tuple[JsonObject, ...]:
    return (
        *_read_jsonl(run.development / "memberships.jsonl"),
        *_read_jsonl(run.sealed / "memberships.jsonl"),
    )


def _nested_value(value: Any, candidate_keys: set[str]) -> Any:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = str(key).casefold().replace("-", "_")
            if normalized in candidate_keys:
                return child
        for child in value.values():
            found = _nested_value(child, candidate_keys)
            if found is not None:
                return found
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for child in value:
            found = _nested_value(child, candidate_keys)
            if found is not None:
                return found
    return None


def _membership_by_document(run: SplitRun) -> dict[str, JsonObject]:
    result: dict[str, JsonObject] = {}
    for row in _membership_rows(run):
        document_id = _nested_value(row, {"document_id"})
        assert isinstance(document_id, str), row
        assert document_id not in result
        result[document_id] = row
    return result


def _group_id(row: Mapping[str, Any]) -> str:
    value = _nested_value(row, {"leakage_group_id", "group_id"})
    assert isinstance(value, str), row
    return value


def _prepared_rows(preparation: Path) -> tuple[JsonObject, ...]:
    candidates: list[tuple[JsonObject, ...]] = []
    for path in preparation.glob("*.jsonl"):
        rows = _read_jsonl(path)
        if rows and all(row.get("status") == "prepared" and isinstance(row.get("document_id"), str) for row in rows):
            candidates.append(rows)
    assert len(candidates) == 1
    return candidates[0]


def _documents_by_subject(preparation: Path) -> dict[str, str]:
    return {str(row["headers"]["subject"]): str(row["document_id"]) for row in _prepared_rows(preparation)}


def _file_sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _frozen_target(run: SplitRun) -> dict[str, str]:
    return {
        "frozen_at": "2026-01-01T00:00:00Z",
        "manifest_sha256": "sha256:" + "1" * 64,
        "bank_hash": "sha256:" + "2" * 64,
        "evaluator_source_sha256": "sha256:" + "3" * 64,
        "split_manifest_sha256": _file_sha256(run.sealed / "manifest.json"),
        "test_artifact_sha256": _file_sha256(run.sealed / "test.jsonl"),
        "thresholds_sha256": "sha256:" + "4" * 64,
        "performance_manifest_sha256": "sha256:" + "5" * 64,
        "git_commit": "6" * 40,
    }


def _tree_bytes(root: Path) -> dict[str, bytes]:
    return {path.relative_to(root).as_posix(): path.read_bytes() for path in sorted(root.rglob("*")) if path.is_file()}


def _serialized_aggregate(*values: Any) -> str:
    return json.dumps(values, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _transitive_leakage_rows() -> list[JsonObject]:
    near_base = " ".join(f"confidential-project-token-{index}" for index in range(120))
    exact_body = "References: <bridge-c@fixture.invalid>\n\nExact bridge payload shared by two mailbox copies."
    rows = [
        _row(
            "bridge-a",
            date="2001-01-01T00:00:00Z",
            subject="Exact bridge",
            body=exact_body,
            sender="exact-a@fixture.invalid",
            recipients=["exact-a-recipient@fixture.invalid"],
        ),
        _row(
            "bridge-b",
            date="2001-01-02T00:00:00Z",
            subject="Exact bridge",
            body=exact_body,
            sender="exact-b@fixture.invalid",
            recipients=["exact-b-recipient@fixture.invalid"],
        ),
        _row(
            "bridge-c",
            date="2001-01-03T00:00:00Z",
            subject="Confidential migration",
            body="The referenced source record joins the reply edge to this thread.",
            sender="thread-one@fixture.invalid",
            recipients=["thread-two@fixture.invalid"],
        ),
        _row(
            "bridge-d",
            date="2001-01-04T00:00:00Z",
            subject="Re: Confidential migration",
            body=near_base,
            sender="thread-two@fixture.invalid",
            recipients=["thread-one@fixture.invalid"],
        ),
        _row(
            "bridge-e",
            date="2001-01-05T00:00:00Z",
            subject="Unrelated subject with a copied body",
            body=near_base + " added",
            sender="near-copy@fixture.invalid",
            recipients=["near-recipient@fixture.invalid"],
        ),
        _row(
            "empty-one",
            date="2001-01-06T00:00:00Z",
            subject="",
            body="",
            sender="",
            recipients=[],
        ),
        _row(
            "empty-two",
            date="2001-01-07T00:00:00Z",
            subject="",
            body="",
            sender="",
            recipients=[],
        ),
    ]
    rows.extend(_dated_rows(16, prefix="island", start=datetime(2001, 2, 1, tzinfo=timezone.utc)))
    return rows


def _identity_cohort_rows() -> list[JsonObject]:
    start = datetime(2000, 1, 1, tzinfo=timezone.utc)
    rows = [
        _row(
            f"head-train-{index:02d}",
            date=(start + timedelta(days=index)).isoformat().replace("+00:00", "Z"),
            sender="head-identity@fixture.invalid",
            recipients=["head-peer@fixture.invalid"],
            file_name=f"owner-head/inbox/{index}",
        )
        for index in range(20)
    ]
    rows.extend(
        [
            _row(
                "tail-train",
                date=(start + timedelta(days=20)).isoformat().replace("+00:00", "Z"),
                sender="tail-identity@fixture.invalid",
                recipients=["tail-peer@fixture.invalid"],
                file_name="owner-tail/inbox/train",
            ),
            _row(
                "cohort-filler-sent",
                date=(start + timedelta(days=21)).isoformat().replace("+00:00", "Z"),
                file_name="owner-filler/sent/one",
            ),
            _row(
                "cohort-filler-draft",
                date=(start + timedelta(days=22)).isoformat().replace("+00:00", "Z"),
                file_name="owner-filler/drafts/two",
            ),
            _row(
                "cohort-filler-large",
                date=(start + timedelta(days=23)).isoformat().replace("+00:00", "Z"),
                body="large-cohort-token " * 80,
            ),
            _row(
                "known-head-late",
                date=(start + timedelta(days=24)).isoformat().replace("+00:00", "Z"),
                sender="head-identity@fixture.invalid",
                recipients=["head-peer@fixture.invalid"],
                file_name="owner-head/sent/late",
            ),
            _row(
                "known-tail-late",
                date=(start + timedelta(days=25)).isoformat().replace("+00:00", "Z"),
                sender="tail-identity@fixture.invalid",
                recipients=["tail-peer@fixture.invalid"],
                file_name="owner-tail/sent/late",
            ),
            _row(
                "novel-late",
                date=(start + timedelta(days=26)).isoformat().replace("+00:00", "Z"),
                sender="novel-identity@fixture.invalid",
                recipients=["novel-peer@fixture.invalid"],
                file_name="owner-novel/inbox/late",
            ),
            _row(
                "mixed-late",
                date=(start + timedelta(days=27)).isoformat().replace("+00:00", "Z"),
                sender="head-identity@fixture.invalid",
                recipients=["mixed-novel-peer@fixture.invalid"],
                file_name="owner-head/inbox/mixed",
            ),
            _row(
                "structured-only-late",
                date=(start + timedelta(days=28)).isoformat().replace("+00:00", "Z"),
                subject="",
                body="",
                sender="structured-only@fixture.invalid",
                recipients=["structured-peer@fixture.invalid"],
                file_name="owner-structured/inbox/late",
            ),
            _row(
                "natural-only-late",
                date=(start + timedelta(days=29)).isoformat().replace("+00:00", "Z"),
                sender="",
                recipients=[],
                file_name="",
            ),
        ]
    )
    assert len(rows) == 30
    return rows


def _membership_for_subject(run: SplitRun, subject: str) -> JsonObject:
    document_id = _documents_by_subject(run.preparation)[subject]
    return _membership_by_document(run)[document_id]


def _cohort_flags(membership: Mapping[str, Any]) -> set[str]:
    result: set[str] = set()

    def visit(value: Any) -> None:
        if isinstance(value, Mapping):
            for key, child in value.items():
                result.add(str(key).casefold())
                visit(child)
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            for child in value:
                visit(child)
        elif isinstance(value, str):
            result.add(value.casefold())

    visit(membership)
    return result


def test_split_artifacts_are_byte_deterministic_and_row_order_invariant(tmp_path: Path) -> None:
    rows = _dated_rows(24, prefix="reorder")
    preparation_a = _prepare(tmp_path / "a", rows)
    preparation_b = _prepare(tmp_path / "b", list(reversed(rows)))
    run_a = _split(tmp_path / "a", preparation_a, sample_per_role=3)
    run_b = _split(tmp_path / "b", preparation_b, sample_per_role=3)

    assert _tree_bytes(run_a.development) == _tree_bytes(run_b.development)
    assert _tree_bytes(run_a.sealed) == _tree_bytes(run_b.sealed)
    assert run_a.summary == run_b.summary
    assert verify_enron_splits(run_a.development, run_a.sealed, seed=run_a.seed) == verify_enron_splits(
        run_b.development, run_b.sealed, seed=run_b.seed
    )


def test_leakage_edges_form_one_transitive_component_without_grouping_empty_text(tmp_path: Path) -> None:
    preparation = _prepare(tmp_path, _transitive_leakage_rows())
    run = _split(tmp_path, preparation, train_fraction=0.7, validation_fraction=0.15)
    subjects = _documents_by_subject(preparation)
    memberships = _membership_by_document(run)
    roles = _document_roles(run)

    bridge_ids = {subjects[name] for name in ("Exact bridge", "Confidential migration", "Re: Confidential migration")}
    copied_near = subjects["Unrelated subject with a copied body"]
    bridge_ids.add(copied_near)
    # Two records share the exact-bridge subject, so recover both directly from the prepared artifact.
    bridge_ids.update(
        str(row["document_id"]) for row in _prepared_rows(preparation) if row["headers"]["subject"] == "Exact bridge"
    )
    assert len(bridge_ids) == 5
    assert len({_group_id(memberships[document_id]) for document_id in bridge_ids}) == 1
    assert len({roles[document_id] for document_id in bridge_ids}) == 1
    assert "thread_or_reply_group" in memberships[subjects["Confidential migration"]]["challenges"]
    assert "thread_or_reply_group" in memberships[subjects["Re: Confidential migration"]]["challenges"]

    empty_ids = [
        str(row["document_id"]) for row in _prepared_rows(preparation) if not row["views"]["subject_current_body"]
    ]
    assert len(empty_ids) == 2
    assert _group_id(memberships[empty_ids[0]]) != _group_id(memberships[empty_ids[1]])

    group_roles: defaultdict[str, set[str]] = defaultdict(set)
    for document_id, membership in memberships.items():
        group_roles[_group_id(membership)].add(roles[document_id])
    assert group_roles
    assert all(len(group_role_set) == 1 for group_role_set in group_roles.values())


def test_folded_visible_body_reference_joins_the_referenced_message(tmp_path: Path) -> None:
    rows = [
        _row(
            "folded-parent",
            date="2001-01-01T00:00:00Z",
            subject="Parent with transport identity",
            body="Parent content that is intentionally unrelated to the reply text.",
            sender="parent-only@fixture.invalid",
            recipients=["parent-recipient@fixture.invalid"],
        ),
        _row(
            "folded-reply",
            date="2001-01-02T00:00:00Z",
            subject="Different subject without thread overlap",
            body=(
                "In-Reply-To: <unrelated@fixture.invalid>\n"
                "\t<folded-parent@fixture.invalid>\n\n"
                "A separate reply body whose folded continuation carries the parent identifier."
            ),
            sender="reply-only@fixture.invalid",
            recipients=["reply-recipient@fixture.invalid"],
        ),
        *_dated_rows(16, prefix="folded-island", start=datetime(2001, 2, 1, tzinfo=timezone.utc)),
    ]
    preparation = _prepare(tmp_path, rows)
    run = _split(tmp_path, preparation)
    subjects = _documents_by_subject(preparation)
    memberships = _membership_by_document(run)
    parent = memberships[subjects["Parent with transport identity"]]
    reply = memberships[subjects["Different subject without thread overlap"]]

    assert _group_id(parent) == _group_id(reply)
    assert "thread_or_reply_group" in parent["challenges"]
    assert "thread_or_reply_group" in reply["challenges"]


def test_paired_band_index_is_complete_at_radius_three_and_excludes_four_changed_bands() -> None:
    base = "0000000000000000"
    radius_three = f"{(1 << 0) | (1 << 13) | (1 << 26):016x}"
    four_changed_bands = f"{(1 << 0) | (1 << 13) | (1 << 26) | (1 << 39):016x}"

    base_keys = set(enron_splitting._near_pair_keys(base))  # noqa: SLF001
    assert base_keys & set(enron_splitting._near_pair_keys(radius_three))  # noqa: SLF001
    assert not base_keys & set(enron_splitting._near_pair_keys(four_changed_bands))  # noqa: SLF001


def test_near_candidate_budget_aborts_before_materializing_an_oversized_bucket(tmp_path: Path) -> None:
    connection = enron_splitting._open_spool(tmp_path / "split.sqlite3")  # noqa: SLF001
    try:
        for node in range(3):
            connection.execute("INSERT INTO near_signatures VALUES (?, ?)", (node, "0000000000000000"))
            for pair_index, value in enron_splitting._near_pair_keys("0000000000000000"):  # noqa: SLF001
                connection.execute("INSERT INTO near_bands VALUES (?, ?, ?)", (pair_index, value, node))
        options = EnronSplitOptions(
            preparation_run=tmp_path / "unused-preparation",
            development_output_dir=tmp_path / "unused-development",
            sealed_output_dir=tmp_path / "unused-sealed",
            max_near_candidate_pairs=1,
            fixture_mode=True,
        )

        with pytest.raises(EnronSplitError, match=r"(?i)(candidate|budget|fail|closed)"):
            enron_splitting._build_leakage_graph(connection, 3, options)  # noqa: SLF001
    finally:
        connection.close()


def test_latest_group_member_controls_temporal_role_and_invalid_dates_are_auditable(tmp_path: Path) -> None:
    shared_subject = "Late member controls this exact group"
    shared_body = "The same bounded content occurs in both an early and a future mailbox copy."
    rows = _dated_rows(18, prefix="timeline", start=datetime(2000, 1, 1, tzinfo=timezone.utc))
    rows.extend(
        [
            _row("temporal-early", date="1999-01-01T00:00:00Z", subject=shared_subject, body=shared_body),
            _row("temporal-late", date="2005-01-01T00:00:00Z", subject=shared_subject, body=shared_body),
            _row("date-missing", date=None),
            _row("date-invalid", date="not-a-date"),
        ]
    )
    preparation = _prepare(tmp_path, rows)
    run = _split(tmp_path, preparation, train_fraction=0.7, validation_fraction=0.15)
    roles = _document_roles(run)
    prepared = _prepared_rows(preparation)
    temporal_ids = [str(row["document_id"]) for row in prepared if row["headers"]["subject"] == shared_subject]
    assert len(temporal_ids) == 2
    assert {roles[document_id] for document_id in temporal_ids} == {"test"}

    sealed_manifest = json.loads((run.sealed / "manifest.json").read_text(encoding="utf-8"))
    aggregate = _serialized_aggregate(run.summary, run.loaded.manifest, run.loaded.freeze_receipt, sealed_manifest)
    assert "invalid" in aggregate.casefold()
    assert "missing" in aggregate.casefold()
    assert "temporal" in aggregate.casefold()


def test_non_temporal_components_use_stable_seeded_assignment_independent_of_temporal_population(
    tmp_path: Path,
) -> None:
    non_temporal = [
        _row(f"undated-{index:02d}", date=None if index % 2 == 0 else "invalid-date") for index in range(40)
    ]
    preparation_only = _prepare(tmp_path / "only", non_temporal)
    preparation_mixed = _prepare(
        tmp_path / "mixed",
        [*reversed(non_temporal), *_dated_rows(20, prefix="dated", start=datetime(2002, 1, 1, tzinfo=timezone.utc))],
    )
    run_only = _split(tmp_path / "only", preparation_only, seed="non-temporal-seed")
    run_mixed = _split(tmp_path / "mixed", preparation_mixed, seed="non-temporal-seed")
    only_roles = _document_roles(run_only)
    mixed_roles = _document_roles(run_mixed)
    undated_ids = {str(row["document_id"]) for row in _prepared_rows(preparation_only)}

    assert {document_id: only_roles[document_id] for document_id in undated_ids} == {
        document_id: mixed_roles[document_id] for document_id in undated_ids
    }
    assert len({only_roles[document_id] for document_id in undated_ids}) >= 2
    for membership in _membership_by_document(run_only).values():
        temporal = membership.get("temporal")
        assert isinstance(temporal, Mapping)
        assert temporal.get("eligible") is False
        assert temporal.get("anchor_utc") is None


def test_identity_frequency_mailbox_and_view_cohorts_follow_train_inventory(tmp_path: Path) -> None:
    preparation = _prepare(tmp_path, _identity_cohort_rows())
    run = _split(tmp_path, preparation, sample_per_role=3)

    known_head = _membership_for_subject(run, "Subject known-head-late")
    known_tail = _membership_for_subject(run, "Subject known-tail-late")
    novel = _membership_for_subject(run, "Subject novel-late")
    mixed = _membership_for_subject(run, "Subject mixed-late")
    structured_only = _membership_for_subject(run, "")
    natural_only = _membership_for_subject(run, "Subject natural-only-late")

    assert known_head["identities"]["recurrence"] == "all_known"
    assert "head" in known_head["identities"]["contains_frequency"]
    assert known_tail["identities"]["recurrence"] == "all_known"
    assert "tail" in known_tail["identities"]["contains_frequency"]
    assert novel["identities"]["recurrence"] == "all_novel"
    assert "novel" in novel["identities"]["contains_frequency"]
    assert mixed["identities"]["recurrence"] == "mixed"
    assert known_head["mailbox"] == "sent"
    assert known_head["mailbox_recurrence"] == "known"
    assert novel["mailbox"] == "inbox"
    assert novel["mailbox_recurrence"] == "novel"
    assert structured_only["views"] == {"natural": False, "structured": True}
    assert natural_only["views"] == {"natural": True, "structured": False}

    aggregate_flags = _cohort_flags(run.loaded.manifest) | _cohort_flags(run.loaded.freeze_receipt)
    assert any("negative" in flag for flag in aggregate_flags)
    assert "unsupported_without_exhaustive_labels" in aggregate_flags


def test_representative_samples_are_deterministic_stratified_and_not_a_source_prefix(tmp_path: Path) -> None:
    preparation = _prepare(tmp_path, _identity_cohort_rows())
    run = _split(tmp_path, preparation, sample_per_role=3)
    roles = _role_rows(run)
    samples = {
        "train": [],
        "validation": [],
        "test": [],
    }
    for path in (run.development / "samples.jsonl", run.sealed / "samples.jsonl"):
        for row in _read_jsonl(path):
            role = row.get("role")
            document_id = row.get("document_id")
            assert role in samples
            assert isinstance(document_id, str)
            samples[str(role)].append(document_id)
            assert isinstance(row.get("stratum_sha256"), str)

    assert all(3 <= len(selected) <= len(roles[role]) for role, selected in samples.items())
    train_sample_rows = [row for row in _read_jsonl(run.development / "samples.jsonl") if row.get("role") == "train"]
    assert len({str(row["stratum_sha256"]) for row in train_sample_rows}) >= 2
    train_ids = sorted(str(row["document_id"]) for row in roles["train"])
    assert set(samples["train"]) != set(train_ids[: len(samples["train"])])
    assert max(train_ids.index(document_id) for document_id in samples["train"]) >= len(samples["train"])


def test_development_api_cannot_reach_test_and_aggregate_views_are_private(tmp_path: Path) -> None:
    rows = _dated_rows(24, prefix="privacy")
    rows[0] = _row(
        "privacy-marker",
        date="2000-01-01T00:00:00Z",
        sender="sensitive-alice@secret.example",
        recipients=["sensitive-bob@secret.example"],
        body="PRIVATE-SPLIT-MARKER must remain only in protected record artifacts.",
    )
    preparation = _prepare(tmp_path, rows)
    run = _split(tmp_path, preparation)

    assert tuple(run.loaded.iter_train_records()) == _role_rows(run)["train"]
    assert tuple(run.loaded.iter_validation_records()) == _role_rows(run)["validation"]
    public_callables = {
        name for name in dir(run.loaded) if not name.startswith("_") and callable(getattr(run.loaded, name))
    }
    assert not any("test" in name.casefold() for name in public_callables)
    assert not any("role" in name.casefold() for name in public_callables)

    test_hash = _file_sha256(run.sealed / "test.jsonl")
    aggregate = _serialized_aggregate(run.summary, run.loaded.manifest, run.loaded.freeze_receipt)
    assert "PRIVATE-SPLIT-MARKER" not in aggregate
    assert "sensitive-alice@secret.example" not in aggregate
    assert "sensitive-bob@secret.example" not in aggregate
    assert str(tmp_path) not in aggregate
    assert test_hash not in aggregate


def test_steward_projection_matches_the_closed_v2_split_contract(tmp_path: Path) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="contract"))
    run = _split(tmp_path, preparation)

    projection = enron_splitting.project_enron_contract_splits(
        run.development,
        run.sealed,
        seed=run.seed,
    )
    errors = list(enron_contract.EnronContractValidator(enron_contract._SPLITS).iter_errors(projection))  # noqa: SLF001
    assert errors == []
    assert set(projection) == {
        "manifest_sha256",
        "policy_sha256",
        "leakage_audit_sha256",
        "leakage_groups_crossing",
        "test_sealed",
        "seed",
        "roles",
    }
    assert all(set(value["artifact"]) == {"id", "sha256", "bytes"} for value in projection["roles"].values())


def test_final_test_access_claim_is_written_before_one_shot_record_access(tmp_path: Path) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="one-shot"))
    run = _split(tmp_path, preparation)
    target = _frozen_target(run)
    claim_path = run.sealed / "ACCESS_CLAIMED.json"
    outcome_path = run.sealed / "ACCESS_OUTCOME.json"
    assert (run.sealed / "PAIR_COMMITTED.json").is_file()
    assert not claim_path.exists()

    invalid_target = {**target, "split_manifest_sha256": "sha256:" + "0" * 64}
    with pytest.raises(EnronSplitError, match=r"(?i)(target|manifest|hash|frozen)"):
        with enron_splitting.begin_enron_final_test_access(run.sealed, frozen_target=invalid_target):
            pass
    assert not claim_path.exists()

    with enron_splitting.begin_enron_final_test_access(run.sealed, frozen_target=target) as access:
        assert claim_path.is_file()
        assert claim_path.stat().st_mode & 0o777 == 0o600
        accessed = tuple(access.iter_records())
    assert accessed == _role_rows(run)["test"]
    claim_aggregate = claim_path.read_text(encoding="utf-8")
    assert "@fixture.invalid" not in claim_aggregate
    assert str(tmp_path) not in claim_aggregate
    verified = verify_enron_splits(run.development, run.sealed, seed=run.seed)
    assert verified["access"]["status"] == "completed"
    assert verified["access"]["access_count"] == 1

    with pytest.raises(EnronSplitError, match=r"(?i)(access|claim|once|already)"):
        with enron_splitting.begin_enron_final_test_access(run.sealed, frozen_target=target):
            pass

    outcome = json.loads(outcome_path.read_text(encoding="utf-8"))
    outcome["claim_sha256"] = "sha256:" + "0" * 64
    outcome_path.write_text(
        json.dumps(outcome, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(EnronSplitError, match=r"(?i)(access|outcome|claim|bind|hash)"):
        verify_enron_splits(run.development, run.sealed, seed=run.seed)


def test_missing_pair_commit_receipt_blocks_sealed_access_without_creating_claim(tmp_path: Path) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="unpaired"))
    run = _split(tmp_path, preparation)
    (run.sealed / "PAIR_COMMITTED.json").unlink()

    with pytest.raises(EnronSplitError, match=r"(?i)(pair|commit|missing|inventory|file)"):
        with enron_splitting.begin_enron_final_test_access(run.sealed, frozen_target=_frozen_target(run)):
            pass
    assert not (run.sealed / "ACCESS_CLAIMED.json").exists()


def test_deep_verifier_rejects_deliberate_cross_role_contamination(tmp_path: Path) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="contamination"))
    run = _split(tmp_path, preparation)
    assert verify_enron_splits(run.development, run.sealed, seed=run.seed)["valid"] is True

    train_line = (run.development / "train.jsonl").read_text(encoding="utf-8").splitlines(keepends=True)[0]
    with (run.development / "validation.jsonl").open("a", encoding="utf-8") as file:
        file.write(train_line)
    with pytest.raises(EnronSplitError, match=r"(?i)(artifact|hash|leakage|cross|duplicate|role)"):
        verify_enron_splits(run.development, run.sealed, seed=run.seed)


def test_small_corpora_require_explicit_non_promotable_fixture_mode(tmp_path: Path) -> None:
    preparation = _prepare(tmp_path, _dated_rows(6, prefix="small"))
    with pytest.raises(EnronSplitError, match=r"(?i)(fixture|production|minimum|small|record|group)"):
        _split(tmp_path, preparation, name="production", fixture_mode=False, sample_per_role=1)

    fixture = _split(tmp_path, preparation, name="fixture", fixture_mode=True, sample_per_role=1)
    assert fixture.summary["fixture_mode"] is True
    assert fixture.summary["promotable"] is False
    assert all(_role_rows(fixture).values())


@pytest.mark.parametrize("nested_target", ["sealed_below_development", "development_below_preparation"])
def test_split_rejects_nested_private_roots_before_creating_output(
    tmp_path: Path,
    nested_target: str,
) -> None:
    preparation = _prepare(tmp_path, _dated_rows(6, prefix="nested"))
    development = tmp_path / "development"
    sealed = development / "sealed"
    if nested_target == "development_below_preparation":
        development = preparation / "development"
        sealed = tmp_path / "sealed"

    with pytest.raises(EnronSplitError, match=r"(?i)(nested|distinct|path)"):
        split_enron_preparation(
            EnronSplitOptions(
                preparation_run=preparation,
                development_output_dir=development,
                sealed_output_dir=sealed,
                benchmark_version="enron-v2-nested-fixture",
                seed="nested-seed",
                sample_per_role=1,
                fixture_mode=True,
            )
        )

    assert not development.exists()
    assert not sealed.exists()

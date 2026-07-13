from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

import nerb.enron_contract as enron_contract
import nerb.enron_splitting as enron_splitting
from nerb.enron_preparation import EnronPreparationOptions, prepare_enron_source
from nerb.enron_splitting import (
    EnronDevelopmentAdmissionError,
    EnronDevelopmentAdmissionLimits,
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
    progress_callback: Callable[[int], None] | None = None,
    activity_callback: Callable[[], None] | None = None,
    scratch_dir: Path | None = None,
) -> SplitRun:
    development = tmp_path / f"{name}-development"
    sealed = tmp_path / f"{name}-sealed"
    selected_scratch = scratch_dir or tmp_path / f"{name}-scratch"
    selected_scratch.mkdir(mode=0o700, exist_ok=True)
    summary = split_enron_preparation(
        EnronSplitOptions(
            preparation_run=preparation,
            development_output_dir=development,
            sealed_output_dir=sealed,
            seed=seed,
            train_fraction=train_fraction,
            validation_fraction=validation_fraction,
            near_hamming=3,
            max_near_candidate_pairs=1_000_000,
            sample_per_role=sample_per_role,
            fixture_mode=fixture_mode,
            allow_unignored_output=False,
            progress_callback=progress_callback,
            activity_callback=activity_callback,
            scratch_dir=selected_scratch,
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


def _exact_development_admission(manifest: Mapping[str, Any]) -> EnronDevelopmentAdmissionLimits:
    roles = manifest["development_roles"]
    artifacts = manifest["artifacts"]
    return EnronDevelopmentAdmissionLimits(
        max_train_records=roles["train"]["records"],
        max_train_artifact_bytes=artifacts["train"]["bytes"],
        max_validation_records=roles["validation"]["records"],
        max_validation_artifact_bytes=artifacts["validation"]["bytes"],
        max_development_memberships_bytes=artifacts["memberships"]["bytes"],
        max_development_samples_bytes=artifacts["samples"]["bytes"],
    )


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


def _bound_final_test_access(
    run: SplitRun,
    *,
    target: Mapping[str, str] | None = None,
) -> enron_splitting.EnronFinalTestAccess:
    access = enron_splitting.begin_enron_final_test_access(
        run.sealed,
        frozen_target=_frozen_target(run) if target is None else target,
    )
    access.bind_evidence("sha256:" + "7" * 64)
    return access


def _tree_bytes(root: Path) -> dict[str, bytes]:
    return {path.relative_to(root).as_posix(): path.read_bytes() for path in sorted(root.rglob("*")) if path.is_file()}


def _assert_payload_empty_private_tree(root: Path) -> None:
    for path in root.rglob("*"):
        info = path.lstat()
        assert not stat.S_ISLNK(info.st_mode)
        assert info.st_uid == os.geteuid()
        if stat.S_ISDIR(info.st_mode):
            assert stat.S_IMODE(info.st_mode) == 0o700
        else:
            assert stat.S_ISREG(info.st_mode)
            assert stat.S_IMODE(info.st_mode) == 0o600
            assert info.st_size == 0


def _assert_cleanup_tombstones(root: Path, *, count: int) -> None:
    entries = sorted(root.iterdir())
    assert len(entries) == count
    for entry in entries:
        assert re.fullmatch(r"\.nerb-cleanup-[0-9a-f]{48}", entry.name)
        assert entry.is_dir()
        assert stat.S_IMODE(entry.stat().st_mode) == 0o700
        _assert_payload_empty_private_tree(entry)


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


def test_initial_ingest_progress_uses_fixed_intervals_and_final_count(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def records() -> Iterable[tuple[int, bytes, Mapping[str, Any]]]:
        for index in range(20_001):
            row = {
                "document_id": "doc_" + f"{index:064x}",
                "source": {
                    "identical_occurrence_count": 1,
                    "mailbox_folder_role": "unavailable",
                    "mailbox_owner_sha256": None,
                },
                "date": {"temporal_eligible": False, "utc": None, "status": "missing"},
                "views": {
                    "full_visible_body": "",
                    "current_body": "",
                    "subject_current_body": "",
                    "current_body_core": "",
                    "structured_headers": {},
                },
                "grouping": {"normalized_thread_subject_sha256": None, "near_duplicate": {}},
                "headers": {"message_id": ""},
                "cleaning": {"body_truncated": False, "subject_truncated": False, "transform_counts": {}},
            }
            raw = enron_splitting._canonical_line(row)  # noqa: SLF001
            yield index + 1, raw, row

    monkeypatch.setattr(enron_splitting, "_iter_strict_jsonl", lambda *_args, **_kwargs: records())
    monkeypatch.setattr(enron_splitting, "_verify_prepared_record", lambda *_args, **_kwargs: None)
    connection = enron_splitting._open_spool(tmp_path / "progress.sqlite3")  # noqa: SLF001
    observed: list[int] = []
    try:
        assert connection.execute("PRAGMA temp_store").fetchone()[0] == 2
        count = enron_splitting._ingest_prepared(  # noqa: SLF001
            connection,
            tmp_path / "unused.jsonl",
            {},
            finalize=False,
            progress_callback=observed.append,
        )
    finally:
        connection.close()

    assert count == 20_001
    assert observed == [10_000, 20_000, 20_001]


def test_observational_split_options_do_not_change_artifacts_and_replay_scratch_is_owned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="observational-options"))
    baseline = _split(tmp_path, preparation, name="observational-baseline")
    scratch = tmp_path / "capacity-scratch"
    scratch.mkdir(mode=0o700)
    actual_loader = enron_splitting.load_enron_preparation_run
    actual_open_spool = enron_splitting._open_spool  # noqa: SLF001
    observed_loader_scratch: list[Path | None] = []
    observed_spools: list[Path] = []
    progress: list[int] = []
    activity = 0

    def heartbeat() -> None:
        nonlocal activity
        activity += 1

    def checked_loader(
        path: Path,
        *,
        scratch_dir: Path | None = None,
        activity_callback: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        observed_loader_scratch.append(scratch_dir)
        assert scratch_dir is not None
        return actual_loader(path, scratch_dir=scratch_dir, activity_callback=activity_callback)

    def checked_spool(path: Path, **kwargs: Any) -> Any:
        observed_spools.append(path)
        connection = actual_open_spool(path, **kwargs)
        assert connection.execute("PRAGMA temp_store").fetchone()[0] == 2
        return connection

    monkeypatch.setattr(enron_splitting, "load_enron_preparation_run", checked_loader)
    monkeypatch.setattr(enron_splitting, "_open_spool", checked_spool)
    observed = _split(
        tmp_path,
        preparation,
        name="observational-enabled",
        progress_callback=progress.append,
        activity_callback=heartbeat,
        scratch_dir=scratch,
    )

    replay_spools = [path for path in observed_spools if "preseal-replay" in path.parent.name]
    assert observed_loader_scratch == [scratch]
    assert progress == [24]
    assert activity > 0
    assert len(replay_spools) == 1
    assert replay_spools[0].is_relative_to(scratch)
    assert not replay_spools[0].parent.exists()
    assert not any(path.name == ".preseal-replay" for path in observed.development.rglob("*"))
    _assert_cleanup_tombstones(scratch, count=3)
    assert _tree_bytes(observed.development) == _tree_bytes(baseline.development)
    assert _tree_bytes(observed.sealed) == _tree_bytes(baseline.sealed)


def test_split_rejects_preparation_manifest_substitution_after_deep_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="manifest-substitution"))
    scratch = tmp_path / "manifest-substitution-scratch"
    scratch.mkdir(mode=0o700)
    manifest_path = preparation / "manifest.json"
    parked_manifest = tmp_path / "verified-manifest.json"
    actual_loader = enron_splitting.load_enron_preparation_run

    def substitute_after_verification(
        path: Path,
        *,
        scratch_dir: Path,
        activity_callback: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        verified = actual_loader(path, scratch_dir=scratch_dir, activity_callback=activity_callback)
        manifest_path.replace(parked_manifest)
        manifest_path.write_text("{}\n", encoding="utf-8")
        manifest_path.chmod(0o600)
        return verified

    monkeypatch.setattr(enron_splitting, "load_enron_preparation_run", substitute_after_verification)

    with pytest.raises(EnronSplitError, match=r"(?i)(verified|manifest|changed)"):
        _split(
            tmp_path,
            preparation,
            name="manifest-substitution",
            scratch_dir=scratch,
        )

    assert parked_manifest.is_file()
    assert not (tmp_path / "manifest-substitution-development").exists()
    assert not (tmp_path / "manifest-substitution-sealed").exists()
    _assert_cleanup_tombstones(scratch, count=1)


def test_private_split_spool_hardlink_substitution_wipes_every_link_before_failing(tmp_path: Path) -> None:
    scratch = tmp_path / "split-spool-scratch"
    scratch.mkdir(mode=0o700)
    linked_paths: list[tuple[Path, Path]] = []

    with pytest.raises(EnronSplitError, match=r"(?i)(spool|clean)"):
        with enron_splitting._private_split_spool(  # noqa: SLF001
            scratch,
            purpose="hardlink-adversary",
            allow_unignored_output=True,
        ) as connection:
            connection.execute("CREATE TABLE private_marker (value TEXT NOT NULL)")
            connection.execute("INSERT INTO private_marker VALUES (?)", ("private split marker",))
            connection.commit()
            spool_paths = list(scratch.rglob("split.sqlite3"))
            assert len(spool_paths) == 1
            original = spool_paths[0]
            linked = original.with_name("split-hardlink.sqlite3")
            os.link(original, linked)
            linked_paths.append((original, linked))

    assert len(linked_paths) == 1
    original, linked = linked_paths[0]
    assert original.read_bytes() == b""
    assert linked.read_bytes() == b""
    assert original.stat().st_ino == linked.stat().st_ino
    _assert_payload_empty_private_tree(scratch)


def test_private_split_spool_move_out_wipes_original_and_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratch = tmp_path / "split-spool-scratch"
    scratch.mkdir(mode=0o700)
    parked = tmp_path / "parked-split.sqlite3"
    actual_open = enron_splitting._open_spool  # noqa: SLF001

    def substitute_after_open(path: Path, **kwargs: Any) -> Any:
        connection = actual_open(path, **kwargs)
        path.replace(parked)
        path.write_bytes(b"replacement private split payload")
        path.chmod(0o600)
        return connection

    monkeypatch.setattr(enron_splitting, "_open_spool", substitute_after_open)

    with enron_splitting._private_split_spool(  # noqa: SLF001
        scratch,
        purpose="move-out-adversary",
        allow_unignored_output=True,
    ) as connection:
        connection.execute("CREATE TABLE private_marker (value TEXT NOT NULL)")
        connection.execute("INSERT INTO private_marker VALUES (?)", ("private split marker",))
        connection.commit()

    assert parked.read_bytes() == b""
    _assert_cleanup_tombstones(scratch, count=1)
    assert all(path.read_bytes() == b"" for path in scratch.rglob("split.sqlite3"))


def test_private_split_spool_close_failure_supersedes_body_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratch = tmp_path / "split-spool-scratch"
    scratch.mkdir(mode=0o700)

    class FailingCloseConnection:
        def close(self) -> None:
            raise enron_splitting.sqlite3.OperationalError("injected close failure")

    monkeypatch.setattr(enron_splitting, "_open_spool", lambda *_args, **_kwargs: FailingCloseConnection())

    with pytest.raises(EnronSplitError, match="could not be closed") as caught:
        with enron_splitting._private_split_spool(
            scratch,
            purpose="close-failure",
            allow_unignored_output=True,
        ):
            raise RuntimeError("injected split body failure")

    assert isinstance(caught.value.__cause__, RuntimeError)
    _assert_cleanup_tombstones(scratch, count=1)


def test_callback_and_replay_scratch_failures_roll_back_without_path_disclosure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="rollback-observers"))
    private_marker = str(tmp_path / "private-progress-path")

    def failed_progress(_records: int) -> None:
        raise OSError(private_marker)

    with pytest.raises(EnronSplitError, match="progress callback") as progress_error:
        _split(
            tmp_path,
            preparation,
            name="callback-rollback",
            progress_callback=failed_progress,
        )
    assert private_marker not in str(progress_error.value)
    assert not (tmp_path / "callback-rollback-development").exists()
    assert not (tmp_path / "callback-rollback-sealed").exists()

    def failed_activity() -> None:
        stages = tuple(tmp_path.glob(".activity-rollback-development.stage-*"))
        if stages and (stages[0] / "train.jsonl").exists():
            raise OSError(private_marker)

    with pytest.raises(EnronSplitError, match="activity callback failed") as activity_error:
        _split(
            tmp_path,
            preparation,
            name="activity-rollback",
            activity_callback=failed_activity,
        )
    assert private_marker not in str(activity_error.value)
    assert not (tmp_path / "activity-rollback-development").exists()
    assert not (tmp_path / "activity-rollback-sealed").exists()
    assert not tuple(tmp_path.glob(".activity-rollback-*.stage-*"))

    actual_open_spool = enron_splitting._open_spool  # noqa: SLF001

    def fail_replay_spool(path: Path, **kwargs: Any) -> Any:
        if "preseal-replay" in path.parent.name:
            raise OSError(private_marker)
        return actual_open_spool(path, **kwargs)

    monkeypatch.setattr(enron_splitting, "_open_spool", fail_replay_spool)
    with pytest.raises(EnronSplitError, match=r"(?i)(construction|failed|safely)") as replay_error:
        _split(tmp_path, preparation, name="replay-rollback")
    assert private_marker not in str(replay_error.value)
    assert not (tmp_path / "replay-rollback-development").exists()
    assert not (tmp_path / "replay-rollback-sealed").exists()
    assert not tuple(tmp_path.glob(".replay-rollback-*.stage-*"))


def test_verifier_sanitizes_path_bearing_underlying_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_marker = str(tmp_path / "private-verification-path")
    monkeypatch.setattr(
        enron_splitting,
        "_verify_enron_splits_metadata",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError(private_marker)),
    )

    with pytest.raises(EnronSplitError, match=r"(?i)(verification|failed|safely)") as error:
        verify_enron_splits(tmp_path / "development", tmp_path / "sealed")
    assert private_marker not in str(error.value)


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
            scratch_dir=tmp_path / "unused-scratch",
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


def test_fractional_second_timestamp_is_chronologically_later_than_whole_second(tmp_path: Path) -> None:
    shared_subject = "Fractional timestamp anchor"
    shared_body = "Two exact copies exercise chronological rather than lexical timestamp ordering."
    rows = [
        _row(
            "fractional-whole",
            date="2000-01-01T00:00:00Z",
            subject=shared_subject,
            body=shared_body,
        ),
        _row(
            "fractional-later",
            date="2000-01-01T00:00:00.500000Z",
            subject=shared_subject,
            body=shared_body,
        ),
        *_dated_rows(16, prefix="fractional-island", start=datetime(2000, 2, 1, tzinfo=timezone.utc)),
    ]
    preparation = _prepare(tmp_path, rows)
    run = _split(tmp_path, preparation)
    group_rows = _read_jsonl(run.sealed / "group-assignments.jsonl")
    prepared_ids = {
        str(row["document_id"]) for row in _prepared_rows(preparation) if row["headers"]["subject"] == shared_subject
    }
    group = next(row for row in group_rows if prepared_ids <= set(row["member_document_ids"]))

    assert group["records"] == 2
    assert group["anchor_utc"] == "2000-01-01T00:00:00.500000Z"


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


def test_representative_sampler_reserves_named_marginal_cohorts_before_hamilton_allocation(
    tmp_path: Path,
) -> None:
    def membership(
        index: int,
        *,
        date_status: str = "missing",
        frequency: str = "mid",
        natural: bool = True,
        challenge: str | None = None,
    ) -> enron_splitting._Membership:  # noqa: SLF001
        return enron_splitting._Membership(  # noqa: SLF001
            document_id=f"doc_{index:064x}",
            group_id="sha256:" + f"{index:064x}",
            role="validation",
            occurrence_count=1,
            temporal_eligible=False,
            date_status=date_status,
            anchor_utc=None,
            mailbox="inbox",
            mailbox_recurrence="known",
            size="medium",
            group_size="2",
            identity_recurrence="all_known",
            identity_count=1,
            identity_frequencies=(frequency,),
            natural=natural,
            structured=True,
            challenges=() if challenge is None else (challenge,),
        )

    memberships = [
        membership(0, date_status="invalid", frequency="head", challenge="near_duplicate_group"),
        membership(1, frequency="tail", challenge="thread_or_reply_group"),
        membership(
            2,
            date_status="out_of_range",
            natural=False,
            challenge="exact_duplicate_group",
        ),
        *(membership(index) for index in range(3, 20)),
    ]
    options = EnronSplitOptions(
        preparation_run=tmp_path / "unused-preparation",
        development_output_dir=tmp_path / "unused-development",
        sealed_output_dir=tmp_path / "unused-sealed",
        scratch_dir=tmp_path / "unused-scratch",
        seed="sample-gap",
        sample_per_role=4,
        fixture_mode=True,
    )
    selected, counts = enron_splitting._select_samples(memberships, options)  # noqa: SLF001
    selected_documents = {memberships[node].document_id for node in selected}

    assert {memberships[index].document_id for index in (0, 1, 2)} <= selected_documents
    assert counts["validation"] == 4
    reversed_selected, _ = enron_splitting._select_samples(tuple(reversed(memberships)), options)  # noqa: SLF001
    assert selected_documents == {tuple(reversed(memberships))[node].document_id for node in reversed_selected}

    production = EnronSplitOptions(
        preparation_run=tmp_path / "production-preparation",
        development_output_dir=tmp_path / "production-development",
        sealed_output_dir=tmp_path / "production-sealed",
        scratch_dir=tmp_path / "production-scratch",
        seed="sample-gap",
        sample_per_role=2,
        fixture_mode=False,
    )
    with pytest.raises(EnronSplitError, match=r"(?i)(sample|budget|cohort|stratum)"):
        enron_splitting._select_samples(memberships, production)  # noqa: SLF001


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
    assert {"iter_train_memberships", "iter_validation_memberships"} <= public_callables
    assert not any("test" in name.casefold() for name in public_callables)
    assert not any("role" in name.casefold() for name in public_callables)

    test_hash = _file_sha256(run.sealed / "test.jsonl")
    aggregate = _serialized_aggregate(run.summary, run.loaded.manifest, run.loaded.freeze_receipt)
    assert "PRIVATE-SPLIT-MARKER" not in aggregate
    assert "sensitive-alice@secret.example" not in aggregate
    assert "sensitive-bob@secret.example" not in aggregate
    assert str(tmp_path) not in aggregate
    assert test_hash not in aggregate


def test_development_membership_iterators_pair_exactly_with_fixed_role_records(tmp_path: Path) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="membership-pairing"))
    run = _split(tmp_path, preparation)

    pairs = (
        (
            "train",
            tuple(run.loaded.iter_train_records()),
            tuple(run.loaded.iter_train_memberships()),
        ),
        (
            "validation",
            tuple(run.loaded.iter_validation_records()),
            tuple(run.loaded.iter_validation_memberships()),
        ),
    )
    for role, records, memberships in pairs:
        expected = run.loaded.manifest["development_roles"][role]["records"]
        assert len(records) == len(memberships) == expected
        for record, membership in zip(records, memberships, strict=True):
            assert membership["role"] == role
            assert membership["document_id"] == record["document_id"]


def test_development_membership_iterators_reject_tampered_schema_and_role(tmp_path: Path) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="membership-tamper"))
    run = _split(tmp_path, preparation)
    membership_path = run.development / "memberships.jsonl"
    original = _read_jsonl(membership_path)

    wrong_schema = [dict(row) for row in original]
    wrong_schema[0]["schema_version"] = "nerb.enron_split_membership.invalid"
    _write_jsonl(membership_path, wrong_schema)
    with pytest.raises(EnronSplitError, match=r"(?i)(canonical|schema|frozen|descriptor)"):
        tuple(run.loaded.iter_train_memberships())

    forbidden_role = [dict(row) for row in original]
    forbidden_role[0]["role"] = "test"
    _write_jsonl(membership_path, forbidden_role)
    with pytest.raises(EnronSplitError, match=r"(?i)(schema|role|frozen|descriptor)"):
        tuple(run.loaded.iter_train_memberships())


@pytest.mark.parametrize("role", ["train", "validation"])
def test_development_role_iterators_recheck_frozen_descriptor_after_load(tmp_path: Path, role: str) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix=f"{role}-post-load-tamper"))
    run = _split(tmp_path, preparation)
    role_path = run.development / f"{role}.jsonl"
    changed = [dict(row) for row in _read_jsonl(role_path)]
    changed[0]["views"] = dict(changed[0]["views"])
    current_body = str(changed[0]["views"]["current_body"])
    changed[0]["views"]["current_body"] = ("X" if not current_body.startswith("X") else "Y") + current_body[1:]
    _write_jsonl(role_path, changed)

    iterator = getattr(run.loaded, f"iter_{role}_records")
    with pytest.raises(EnronSplitError, match=r"(?i)(frozen|descriptor|changed)"):
        tuple(iterator())


def test_development_membership_iterators_recheck_frozen_descriptor_after_load(tmp_path: Path) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="membership-post-load-tamper"))
    run = _split(tmp_path, preparation)
    membership_path = run.development / "memberships.jsonl"
    changed = [dict(row) for row in _read_jsonl(membership_path)]
    group_id = str(changed[0]["group_id"])
    changed[0]["group_id"] = group_id[:-1] + ("0" if group_id[-1] != "0" else "1")
    _write_jsonl(membership_path, changed)

    with pytest.raises(EnronSplitError, match=r"(?i)(frozen|descriptor|changed)"):
        tuple(run.loaded.iter_train_memberships())


@pytest.mark.parametrize(
    ("artifact_name", "iterator_name"),
    [
        ("train.jsonl", "iter_train_records"),
        ("validation.jsonl", "iter_validation_records"),
        ("memberships.jsonl", "iter_train_memberships"),
    ],
)
def test_development_iterators_reject_exact_file_replacement_during_stream(
    tmp_path: Path,
    artifact_name: str,
    iterator_name: str,
) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix=f"stream-replacement-{iterator_name}"))
    run = _split(tmp_path, preparation)
    artifact_path = run.development / artifact_name
    iterator = getattr(run.loaded, iterator_name)()
    next(iterator)

    replacement = run.development / f".{artifact_name}.replacement"
    shutil.copyfile(artifact_path, replacement)
    replacement.chmod(0o600)
    replacement.replace(artifact_path)

    with pytest.raises(EnronSplitError, match=r"(?i)(frozen|private|changed)"):
        tuple(iterator)


@pytest.mark.parametrize("metadata_name", ["manifest.json", "split-freeze-receipt.json"])
def test_development_iterators_reject_exact_metadata_replacement_after_load(
    tmp_path: Path,
    metadata_name: str,
) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix=f"metadata-replacement-{metadata_name}"))
    run = _split(tmp_path, preparation)
    metadata_path = run.development / metadata_name
    replacement = run.development / f".{metadata_name}.replacement"
    shutil.copyfile(metadata_path, replacement)
    replacement.chmod(0o600)
    replacement.replace(metadata_path)

    with pytest.raises(EnronSplitError, match=r"(?i)(private|changed|verified)"):
        tuple(run.loaded.iter_train_records())


@pytest.mark.parametrize(
    "raw",
    [
        b'{"value":NaN}',
        b'{"value":Infinity}',
        b'{"value":1e999}',
        b'{"value":1,"value":2}',
        b'{"value":' + b"[" * 2_000 + b"0" + b"]" * 2_000 + b"}",
    ],
)
def test_private_json_metadata_rejects_nonfinite_duplicate_recursive_and_overflow_values(
    tmp_path: Path,
    raw: bytes,
) -> None:
    path = tmp_path / "metadata.json"
    path.write_bytes(raw)
    path.chmod(0o600)

    with pytest.raises(EnronSplitError, match=r"(?i)(json|finite|duplicate|valid)"):
        enron_splitting._read_json_object(path)  # noqa: SLF001


def test_private_json_and_jsonl_use_an_explicit_integer_digit_limit(tmp_path: Path) -> None:
    digits = b"9" * (enron_splitting._MAX_PRIVATE_JSON_INTEGER_DIGITS + 1)  # noqa: SLF001
    raw = b'{"value":' + digits + b"}"
    path = tmp_path / "metadata.json"
    path.write_bytes(raw)
    path.chmod(0o600)

    with pytest.raises(EnronSplitError, match=r"(?i)(integer|digit|json)"):
        enron_splitting._read_json_object(path)  # noqa: SLF001
    with pytest.raises(EnronSplitError, match=r"(?i)(integer|digit|json)"):
        enron_splitting._parse_frozen_jsonl_object(path, 1, raw + b"\n")  # noqa: SLF001


def test_private_json_metadata_rejects_aba_path_replacement_during_parse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "metadata.json"
    parked_original = tmp_path / "metadata.original.json"
    path.write_bytes(b'{"version":"original"}')
    path.chmod(0o600)
    path.replace(parked_original)
    path.write_bytes(b'{"version":"replacement"}')
    path.chmod(0o600)
    real_loads = json.loads

    def restore_original(payload: str | bytes | bytearray, **kwargs: Any) -> Any:
        parked_original.replace(path)
        return real_loads(payload, **kwargs)

    monkeypatch.setattr(enron_splitting.json, "loads", restore_original)

    with pytest.raises(EnronSplitError, match=r"(?i)(changed|verified)"):
        enron_splitting._read_json_object(path)  # noqa: SLF001
    assert real_loads(path.read_bytes()) == {"version": "original"}


def test_descriptor_hash_and_size_are_bound_to_one_file_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "artifact.jsonl"
    replacement = tmp_path / "artifact.replacement.jsonl"
    payload = b'{"value":"same bytes"}\n'
    path.write_bytes(payload)
    replacement.write_bytes(payload)
    path.chmod(0o600)
    replacement.chmod(0o600)
    descriptor = {
        "id": "artifact",
        "name": path.name,
        "sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
        "records": 1,
    }
    real_identity = enron_splitting._private_regular_identity  # noqa: SLF001
    identity_calls = 0

    def replace_after_first_fstat(info: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
        nonlocal identity_calls
        identity = real_identity(info)
        identity_calls += 1
        if identity_calls == 1:
            replacement.replace(path)
        return identity

    monkeypatch.setattr(enron_splitting, "_private_regular_identity", replace_after_first_fstat)

    with pytest.raises(EnronSplitError, match=r"(?i)(changed|verified|private|single-link)"):
        enron_splitting._verify_descriptor(tmp_path, descriptor, path.name)  # noqa: SLF001


def test_development_admission_accepts_exact_frozen_manifest_capacities(tmp_path: Path) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="admission-exact"))
    run = _split(tmp_path, preparation)
    limits = _exact_development_admission(run.loaded.manifest)

    loaded = load_enron_development_split(run.development, admission_limits=limits)

    assert loaded.manifest == run.loaded.manifest
    assert tuple(loaded.iter_train_records()) == tuple(run.loaded.iter_train_records())
    assert tuple(loaded.iter_validation_records()) == tuple(run.loaded.iter_validation_records())


@pytest.mark.parametrize(
    "limited_field",
    [
        "max_train_records",
        "max_train_artifact_bytes",
        "max_validation_records",
        "max_validation_artifact_bytes",
        "max_development_memberships_bytes",
        "max_development_samples_bytes",
    ],
)
def test_development_admission_rejects_manifest_capacity_before_large_artifact_hashing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    limited_field: str,
) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix=f"admission-{limited_field}"))
    run = _split(tmp_path, preparation)
    exact = _exact_development_admission(run.loaded.manifest)
    limits = replace(exact, **{limited_field: getattr(exact, limited_field) - 1})
    snapshots: list[Path] = []

    def unexpected_snapshot(path: Path, expected_bytes: int) -> Any:
        snapshots.append(path)
        raise AssertionError(f"admission must precede hashing {path} ({expected_bytes})")

    monkeypatch.setattr(enron_splitting, "_snapshot_private_artifact", unexpected_snapshot)

    with pytest.raises(EnronDevelopmentAdmissionError, match="admission limit"):
        load_enron_development_split(run.development, admission_limits=limits)

    assert snapshots == []


def test_development_loader_validates_every_descriptor_before_hashing_large_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="admission-descriptor"))
    run = _split(tmp_path, preparation)
    manifest_path = run.development / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"]["samples"]["bytes"] = "invalid"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    manifest_path.chmod(0o600)
    snapshots: list[Path] = []

    def unexpected_snapshot(path: Path, expected_bytes: int) -> Any:
        snapshots.append(path)
        raise AssertionError(f"descriptor validation must precede hashing {path} ({expected_bytes})")

    monkeypatch.setattr(enron_splitting, "_snapshot_private_artifact", unexpected_snapshot)

    with pytest.raises(EnronSplitError, match="descriptor"):
        load_enron_development_split(run.development)

    assert snapshots == []


def test_steward_projection_matches_the_closed_split_contract(tmp_path: Path) -> None:
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


def test_final_test_state_starts_explicitly_sealed_unbound(tmp_path: Path) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="sealed-unbound"))
    run = _split(tmp_path, preparation)

    manifest = json.loads((run.sealed / "manifest.json").read_text(encoding="utf-8"))
    verified = verify_enron_splits(run.development, run.sealed, seed=run.seed)

    assert manifest["sealing"]["initial_access_state"] == "sealed_unbound"
    assert verified["preparation"] == manifest["preparation"]
    assert verified["access"] == {
        "status": "sealed_unbound",
        "access_count": 0,
        "accessed_at": None,
        "aggregate_sha256": None,
    }


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
        enron_splitting.begin_enron_final_test_access(
            run.sealed,
            frozen_target=invalid_target,
        ).bind_evidence("sha256:" + "7" * 64)
    assert not claim_path.exists()
    assert not (run.sealed / "EVIDENCE_BOUND.json").exists()

    with _bound_final_test_access(run, target=target) as access:
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


def test_evidence_binding_and_claim_precede_the_only_test_content_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="claim-first"))
    run = _split(tmp_path, preparation)
    access = _bound_final_test_access(run)
    actual_open = enron_splitting.open_private_binary_input_at
    opened = 0

    def checked_open(directory_fd: int, name: str, **kwargs: Any) -> Any:
        nonlocal opened
        if name != "test.jsonl":
            return actual_open(directory_fd, name, **kwargs)
        assert (run.sealed / "EVIDENCE_BOUND.json").is_file()
        assert (run.sealed / "ACCESS_CLAIMED.json").is_file()
        assert not (run.sealed / "ACCESS_OUTCOME.json").exists()
        opened += 1
        return actual_open(directory_fd, name, **kwargs)

    monkeypatch.setattr(enron_splitting, "open_private_binary_input_at", checked_open)
    with access as active:
        assert tuple(active.iter_records()) == _role_rows(run)["test"]

    assert opened == 1
    assert verify_enron_splits(run.development, run.sealed, seed=run.seed)["access"]["status"] == "completed"


def test_claim_rechecks_every_transition_receipt_identity_before_test_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="transition-recheck"))
    run = _split(tmp_path, preparation)
    target = _frozen_target(run)
    _bound_final_test_access(run, target=target)
    actual_snapshot = enron_splitting._read_json_object_snapshot_at  # noqa: SLF001
    actual_open = enron_splitting.open_private_binary_input_at

    for critical_name in (
        "manifest.json",
        "PRESEAL_VERIFIED.json",
        "PAIR_COMMITTED.json",
        "EVIDENCE_BOUND.json",
    ):
        replaced = False
        test_opened = False

        def replace_after_snapshot(directory_fd: int, name: str, **kwargs: Any) -> Any:
            nonlocal replaced
            snapshot = actual_snapshot(directory_fd, name, **kwargs)
            if name == critical_name and not replaced:
                path = run.sealed / name
                replacement = run.sealed / f".{name}.identity-replacement"
                replacement.write_bytes(path.read_bytes())
                replacement.chmod(0o600)
                replacement.replace(path)
                replaced = True
            return snapshot

        def reject_test_open(directory_fd: int, name: str, **kwargs: Any) -> Any:
            nonlocal test_opened
            if name == "test.jsonl":
                test_opened = True
                pytest.fail("transition identity failure opened test content")
            return actual_open(directory_fd, name, **kwargs)

        with monkeypatch.context() as context:
            context.setattr(enron_splitting, "_read_json_object_snapshot_at", replace_after_snapshot)
            context.setattr(enron_splitting, "open_private_binary_input_at", reject_test_open)
            with pytest.raises(EnronSplitError, match=r"(?i)(changed|identity|verified)"):
                with enron_splitting.begin_enron_final_test_access(run.sealed, frozen_target=target):
                    pass

        assert replaced is True
        assert test_opened is False
        assert not (run.sealed / "ACCESS_CLAIMED.json").exists()
        assert not (run.sealed / "ACCESS_OUTCOME.json").exists()


def test_transition_uses_the_directory_pinned_before_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="transition-root-pin"))
    run = _split(tmp_path, preparation)
    access = _bound_final_test_access(run)
    actual_snapshot = enron_splitting._read_json_object_snapshot_at  # noqa: SLF001
    renamed = run.sealed.with_name("transition-root-pin-renamed")
    renamed_once = False

    def rename_after_manifest(directory_fd: int, name: str, **kwargs: Any) -> Any:
        nonlocal renamed_once
        snapshot = actual_snapshot(directory_fd, name, **kwargs)
        if name == "manifest.json" and not renamed_once:
            run.sealed.rename(renamed)
            run.sealed.mkdir(mode=0o700)
            renamed_once = True
        return snapshot

    monkeypatch.setattr(enron_splitting, "_read_json_object_snapshot_at", rename_after_manifest)
    with access as active:
        assert tuple(active.iter_records())

    assert renamed_once is True
    assert not (run.sealed / "ACCESS_CLAIMED.json").exists()
    assert (renamed / "ACCESS_CLAIMED.json").is_file()
    assert (renamed / "ACCESS_OUTCOME.json").is_file()
    run.sealed.rmdir()
    assert verify_enron_splits(run.development, renamed, seed=run.seed)["access"]["status"] == "completed"


def test_final_access_requires_one_nonreplayable_evidence_binding(tmp_path: Path) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="binding-required"))
    run = _split(tmp_path, preparation)
    target = _frozen_target(run)
    unbound = enron_splitting.begin_enron_final_test_access(run.sealed, frozen_target=target)

    with pytest.raises(EnronSplitError, match=r"(?i)(evidence|bound)"):
        with unbound:
            pass
    assert not (run.sealed / "ACCESS_CLAIMED.json").exists()

    bound = enron_splitting.begin_enron_final_test_access(run.sealed, frozen_target=target)
    binding = bound.bind_evidence("sha256:" + "7" * 64)
    assert binding["status"] == "evidence_bound"
    assert verify_enron_splits(run.development, run.sealed, seed=run.seed)["access"] == {
        "status": "evidence_bound",
        "access_count": 0,
        "accessed_at": None,
        "aggregate_sha256": "sha256:" + "7" * 64,
    }
    with pytest.raises(EnronSplitError, match=r"(?i)(bound|replay)"):
        enron_splitting.begin_enron_final_test_access(
            run.sealed,
            frozen_target=target,
        ).bind_evidence("sha256:" + "7" * 64)


def test_failure_opening_test_after_claim_consumes_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="claimed-open-failure"))
    run = _split(tmp_path, preparation)
    access = _bound_final_test_access(run)
    actual_open = enron_splitting.open_private_binary_input_at

    def fail_test_open(directory_fd: int, name: str, **kwargs: Any) -> Any:
        if name == "test.jsonl":
            raise EnronSplitError("injected content-open failure")
        return actual_open(directory_fd, name, **kwargs)

    monkeypatch.setattr(
        enron_splitting,
        "open_private_binary_input_at",
        fail_test_open,
    )

    with pytest.raises(EnronSplitError, match="injected content-open failure"):
        with access:
            pass

    assert (run.sealed / "ACCESS_CLAIMED.json").is_file()
    assert json.loads((run.sealed / "ACCESS_OUTCOME.json").read_text(encoding="utf-8"))["status"] == "failed"
    assert verify_enron_splits(run.development, run.sealed, seed=run.seed)["access"]["status"] == "failed"
    with pytest.raises(EnronSplitError, match=r"(?i)(claimed|retry|already)"):
        with enron_splitting.begin_enron_final_test_access(run.sealed, frozen_target=_frozen_target(run)):
            pass


def test_reordered_binding_timestamp_fails_before_claim_or_test_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="binding-time-order"))
    run = _split(tmp_path, preparation)
    access = _bound_final_test_access(run)
    actual_open = enron_splitting.open_private_binary_input_at

    def reject_test_open(directory_fd: int, name: str, **kwargs: Any) -> Any:
        if name == "test.jsonl":
            pytest.fail("reordered binding opened test content")
        return actual_open(directory_fd, name, **kwargs)

    monkeypatch.setattr(enron_splitting, "_utc_now", lambda: "2026-01-02T00:00:00.000000Z")
    monkeypatch.setattr(enron_splitting, "open_private_binary_input_at", reject_test_open)

    with pytest.raises(EnronSplitError, match=r"(?i)(ordered|binding|transition|timestamp)"):
        with access:
            pass

    assert not (run.sealed / "ACCESS_CLAIMED.json").exists()
    assert not (run.sealed / "ACCESS_OUTCOME.json").exists()


def test_future_binding_timestamp_is_rejected_before_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="future-binding-time"))
    run = _split(tmp_path, preparation)
    access = enron_splitting.begin_enron_final_test_access(run.sealed, frozen_target=_frozen_target(run))
    monkeypatch.setattr(enron_splitting, "_utc_now", lambda: "2100-01-01T00:00:00.000000Z")

    with pytest.raises(EnronSplitError, match=r"(?i)(timestamp|wall clock|future)"):
        access.bind_evidence("sha256:" + "7" * 64)

    assert not (run.sealed / "EVIDENCE_BOUND.json").exists()
    assert not (run.sealed / "ACCESS_CLAIMED.json").exists()
    assert not (run.sealed / "ACCESS_OUTCOME.json").exists()


def test_future_access_timestamp_is_rejected_before_claim_or_test_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="future-access-time"))
    run = _split(tmp_path, preparation)
    access = _bound_final_test_access(run)
    actual_open = enron_splitting.open_private_binary_input_at

    def reject_test_open(directory_fd: int, name: str, **kwargs: Any) -> Any:
        if name == "test.jsonl":
            pytest.fail("future access timestamp opened test content")
        return actual_open(directory_fd, name, **kwargs)

    monkeypatch.setattr(enron_splitting, "_utc_now", lambda: "2100-01-01T00:00:00.000000Z")
    monkeypatch.setattr(enron_splitting, "open_private_binary_input_at", reject_test_open)

    with pytest.raises(EnronSplitError, match=r"(?i)(timestamp|wall clock|future)"):
        with access:
            pass

    assert (run.sealed / "EVIDENCE_BOUND.json").is_file()
    assert not (run.sealed / "ACCESS_CLAIMED.json").exists()
    assert not (run.sealed / "ACCESS_OUTCOME.json").exists()


def test_future_claim_timestamp_is_rejected_even_when_chain_is_rehashed(tmp_path: Path) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="future-claim-time"))
    run = _split(tmp_path, preparation)
    with _bound_final_test_access(run) as active:
        tuple(active.iter_records())
    claim_path = run.sealed / "ACCESS_CLAIMED.json"
    outcome_path = run.sealed / "ACCESS_OUTCOME.json"
    claim = json.loads(claim_path.read_text(encoding="utf-8"))
    outcome = json.loads(outcome_path.read_text(encoding="utf-8"))
    claim["accessed_at"] = "2100-01-01T00:00:00.000000Z"
    claim_core = {key: value for key, value in claim.items() if key != "claim_sha256"}
    claim["claim_sha256"] = enron_splitting._hash_bytes(  # noqa: SLF001
        enron_splitting._canonical_json(claim_core).encode("utf-8")  # noqa: SLF001
    )
    outcome["accessed_at"] = claim["accessed_at"]
    outcome["claim_sha256"] = claim["claim_sha256"]
    claim_path.write_bytes(enron_splitting._canonical_line(claim))  # noqa: SLF001
    outcome_path.write_bytes(enron_splitting._canonical_line(outcome))  # noqa: SLF001
    claim_path.chmod(0o600)
    outcome_path.chmod(0o600)

    with pytest.raises(EnronSplitError, match=r"(?i)(timestamp|order|access)"):
        verify_enron_splits(run.development, run.sealed, seed=run.seed)


def test_malformed_nested_manifest_is_sanitized_for_binding(tmp_path: Path) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="malformed-binding"))
    run = _split(tmp_path, preparation)
    access = enron_splitting.begin_enron_final_test_access(run.sealed, frozen_target=_frozen_target(run))
    manifest_path = run.sealed / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["roles"] = []
    manifest_path.write_bytes(enron_splitting._canonical_line(manifest))  # noqa: SLF001
    manifest_path.chmod(0o600)

    with pytest.raises(EnronSplitError, match=r"(?i)(role|structur|invalid)") as error:
        access.bind_evidence("sha256:" + "7" * 64)

    assert str(tmp_path) not in str(error.value)
    assert not (run.sealed / "EVIDENCE_BOUND.json").exists()
    assert not (run.sealed / "ACCESS_CLAIMED.json").exists()


def test_malformed_nested_manifest_is_sanitized_before_claim_or_test_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="malformed-claim"))
    run = _split(tmp_path, preparation)
    access = _bound_final_test_access(run)
    manifest_path = run.sealed / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["sealing"] = []
    manifest_path.write_bytes(enron_splitting._canonical_line(manifest))  # noqa: SLF001
    manifest_path.chmod(0o600)
    actual_open = enron_splitting.open_private_binary_input_at

    def reject_test_open(directory_fd: int, name: str, **kwargs: Any) -> Any:
        if name == "test.jsonl":
            pytest.fail("malformed manifest opened test content")
        return actual_open(directory_fd, name, **kwargs)

    monkeypatch.setattr(enron_splitting, "open_private_binary_input_at", reject_test_open)
    with pytest.raises(EnronSplitError, match=r"(?i)(sealing|structur|invalid)") as error:
        with access:
            pass

    assert str(tmp_path) not in str(error.value)
    assert not (run.sealed / "ACCESS_CLAIMED.json").exists()
    assert not (run.sealed / "ACCESS_OUTCOME.json").exists()


def test_malformed_nested_manifest_is_sanitized_for_crash_finalizer(tmp_path: Path) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="malformed-finalizer"))
    run = _split(tmp_path, preparation)
    with _bound_final_test_access(run) as active:
        tuple(active.iter_records())
    (run.sealed / "ACCESS_OUTCOME.json").unlink()
    manifest_path = run.sealed / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["leakage"] = []
    manifest_path.write_bytes(enron_splitting._canonical_line(manifest))  # noqa: SLF001
    manifest_path.chmod(0o600)

    with pytest.raises(EnronSplitError, match=r"(?i)(leakage|structur|invalid)") as error:
        enron_splitting.finalize_aborted_enron_final_test_access(run.sealed)

    assert str(tmp_path) not in str(error.value)
    assert not (run.sealed / "ACCESS_OUTCOME.json").exists()


def test_malformed_nested_manifest_is_sanitized_for_metadata_verification(tmp_path: Path) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="malformed-metadata"))
    run = _split(tmp_path, preparation)
    manifest_path = run.sealed / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["aggregates"] = []
    manifest_path.write_bytes(enron_splitting._canonical_line(manifest))  # noqa: SLF001
    manifest_path.chmod(0o600)

    with pytest.raises(EnronSplitError, match=r"(?i)(aggregate|verification|invalid)") as error:
        verify_enron_splits(run.development, run.sealed, seed=run.seed)

    assert str(tmp_path) not in str(error.value)


def test_partial_or_unused_claimed_stream_is_aborted(tmp_path: Path) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="claimed-abort"))
    run = _split(tmp_path, preparation)

    with _bound_final_test_access(run):
        pass

    outcome = json.loads((run.sealed / "ACCESS_OUTCOME.json").read_text(encoding="utf-8"))
    assert outcome["status"] == "aborted"
    assert verify_enron_splits(run.development, run.sealed, seed=run.seed)["access"]["status"] == "aborted"


@pytest.mark.parametrize("failure_kind", ["parse", "count", "hash", "identity"])
def test_caught_stream_integrity_failures_are_recorded_failed(tmp_path: Path, failure_kind: str) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix=f"caught-stream-{failure_kind}"))
    run = _split(tmp_path, preparation)
    access = _bound_final_test_access(run)
    if failure_kind == "parse":
        test_path = run.sealed / "test.jsonl"
        original = test_path.read_bytes()
        test_path.write_bytes(bytes([original[0] ^ 1]) + original[1:])
        test_path.chmod(0o600)

    with access as active:
        if failure_kind == "count":
            active._expected_records += 1  # noqa: SLF001
        elif failure_kind == "hash":
            active._expected_sha256 = "sha256:" + "0" * 64  # noqa: SLF001
        elif failure_kind == "identity":
            assert active._opened_identity is not None  # noqa: SLF001
            active._opened_identity = (*active._opened_identity[:-1], active._opened_identity[-1] + 1)  # noqa: SLF001
        with pytest.raises(EnronSplitError, match=r"(?i)(invalid|canonical|content|changed)"):
            tuple(active.iter_records())

    outcome = json.loads((run.sealed / "ACCESS_OUTCOME.json").read_text(encoding="utf-8"))
    assert outcome["status"] == "failed"
    assert verify_enron_splits(run.development, run.sealed, seed=run.seed)["access"]["status"] == "failed"


def test_live_access_owner_blocks_crash_finalization(tmp_path: Path) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="live-finalizer"))
    run = _split(tmp_path, preparation)

    with _bound_final_test_access(run) as active:
        with pytest.raises(EnronSplitError, match=r"(?i)(active|owner|transition)"):
            enron_splitting.finalize_aborted_enron_final_test_access(run.sealed)
        assert not (run.sealed / "ACCESS_OUTCOME.json").exists()
        tuple(active.iter_records())

    assert verify_enron_splits(run.development, run.sealed, seed=run.seed)["access"]["status"] == "completed"


def test_same_size_postseal_test_change_fails_only_after_claim(tmp_path: Path) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="postseal-change"))
    run = _split(tmp_path, preparation)
    target = _frozen_target(run)
    test_path = run.sealed / "test.jsonl"
    original = test_path.read_bytes()
    changed = bytes([original[0] ^ 1]) + original[1:]
    assert len(changed) == len(original)
    test_path.write_bytes(changed)
    test_path.chmod(0o600)
    access = _bound_final_test_access(run, target=target)

    with pytest.raises(EnronSplitError, match=r"(?i)(invalid|canonical|content)"):
        with access as active:
            tuple(active.iter_records())

    assert json.loads((run.sealed / "ACCESS_OUTCOME.json").read_text(encoding="utf-8"))["status"] == "failed"
    assert verify_enron_splits(run.development, run.sealed, seed=run.seed)["access"]["status"] == "failed"


def test_rehashed_evidence_binding_substitution_breaks_claim_chain(tmp_path: Path) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="binding-substitution"))
    run = _split(tmp_path, preparation)
    with _bound_final_test_access(run) as active:
        tuple(active.iter_records())
    binding_path = run.sealed / "EVIDENCE_BOUND.json"
    binding = json.loads(binding_path.read_text(encoding="utf-8"))
    binding["aggregate_sha256"] = "sha256:" + "8" * 64
    binding_core = {key: value for key, value in binding.items() if key != "binding_sha256"}
    binding["binding_sha256"] = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(binding_core, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
    )
    binding_path.write_text(
        json.dumps(binding, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    binding_path.chmod(0o600)

    with pytest.raises(EnronSplitError, match=r"(?i)(evidence|binding|claim)"):
        verify_enron_splits(run.development, run.sealed, seed=run.seed)


def test_rehashed_claim_cannot_change_the_evidence_bound_target(tmp_path: Path) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="claim-target-substitution"))
    run = _split(tmp_path, preparation)
    with _bound_final_test_access(run) as active:
        tuple(active.iter_records())
    claim_path = run.sealed / "ACCESS_CLAIMED.json"
    outcome_path = run.sealed / "ACCESS_OUTCOME.json"
    claim = json.loads(claim_path.read_text(encoding="utf-8"))
    outcome = json.loads(outcome_path.read_text(encoding="utf-8"))
    claim["frozen_target"]["bank_hash"] = "sha256:" + "9" * 64
    claim_core = {key: value for key, value in claim.items() if key != "claim_sha256"}
    claim["claim_sha256"] = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(claim_core, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
    )
    outcome["claim_sha256"] = claim["claim_sha256"]
    outcome["frozen_target_sha256"] = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(
                claim["frozen_target"],
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
    )
    claim_path.write_text(
        json.dumps(claim, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    outcome_path.write_text(
        json.dumps(outcome, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    claim_path.chmod(0o600)
    outcome_path.chmod(0o600)

    with pytest.raises(EnronSplitError, match=r"(?i)(claim target|evidence binding)"):
        verify_enron_splits(run.development, run.sealed, seed=run.seed)


def test_final_test_access_pins_directory_across_rename_and_cwd_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "original-parent"
    preparation = _prepare(parent, _dated_rows(24, prefix="pinned"))
    run = _split(parent, preparation)
    target = _frozen_target(run)
    expected = _role_rows(run)["test"]
    renamed = parent / "renamed-sealed"
    other = tmp_path / "other-parent"
    other.mkdir(mode=0o700)

    monkeypatch.chdir(parent)
    bound = _bound_final_test_access(run, target=target)
    relative_access = enron_splitting.begin_enron_final_test_access(Path(run.sealed.name), frozen_target=target)
    assert bound is not relative_access
    with relative_access as access:
        accessed = tuple(access.iter_records())
        run.sealed.rename(renamed)
        monkeypatch.chdir(other)

    assert accessed == expected
    assert (renamed / "ACCESS_CLAIMED.json").is_file()
    assert (renamed / "ACCESS_OUTCOME.json").is_file()
    assert verify_enron_splits(run.development, renamed, seed=run.seed)["access"]["status"] == "completed"


def test_hard_linked_sealed_clone_is_not_an_independent_access_capability(tmp_path: Path) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="hard-link"))
    run = _split(tmp_path, preparation)
    clone = tmp_path / "hard-linked-sealed"
    shutil.copytree(run.sealed, clone, copy_function=os.link)
    assert (clone / "test.jsonl").stat().st_nlink == 2

    with pytest.raises(EnronSplitError, match=r"(?i)(unsafe|link|private|file)"):
        enron_splitting.begin_enron_final_test_access(
            clone,
            frozen_target=_frozen_target(run),
        ).bind_evidence("sha256:" + "7" * 64)
    assert not (clone / "ACCESS_CLAIMED.json").exists()
    assert not (run.sealed / "ACCESS_CLAIMED.json").exists()


def test_private_receipt_publication_is_atomic_after_interrupted_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "private-receipts"
    root.mkdir(mode=0o700)
    real_write = os.write
    writes = 0

    def interrupted_write(file_descriptor: int, payload: bytes) -> int:
        nonlocal writes
        writes += 1
        if writes == 1:
            return real_write(file_descriptor, payload[:12])
        raise OSError("simulated interrupted receipt write")

    monkeypatch.setattr(os, "write", interrupted_write)
    with pytest.raises(EnronSplitError, match=r"(?i)(receipt|atomic|publish)"):
        enron_splitting._write_exclusive_private_json(  # noqa: SLF001
            root,
            "ACCESS_CLAIMED.json",
            {"schema_version": "test", "commitment": "sha256:" + "1" * 64},
        )

    retained = tuple(root.iterdir())
    assert len(retained) == 1
    assert re.fullmatch(r"\.nerb-cleanup-[0-9a-f]{48}", retained[0].name)
    assert retained[0].read_bytes() == b""
    assert stat.S_IMODE(retained[0].stat().st_mode) == 0o600
    assert not tuple(root.glob(".ACCESS_CLAIMED.json.stage-*"))


def test_private_receipt_publication_needs_no_parent_write_permission(tmp_path: Path) -> None:
    parent = tmp_path / "read-only-parent"
    root = parent / "private-receipts"
    root.mkdir(parents=True, mode=0o700)
    parent.chmod(0o500)
    try:
        enron_splitting._write_exclusive_private_json(  # noqa: SLF001
            root,
            "ACCESS_CLAIMED.json",
            {"schema_version": "test", "commitment": "sha256:" + "1" * 64},
        )
        receipt = root / "ACCESS_CLAIMED.json"
        assert receipt.is_file()
        assert receipt.stat().st_mode & 0o777 == 0o600
        assert receipt.stat().st_nlink == 1
    finally:
        parent.chmod(0o700)


@pytest.mark.parametrize("swap_point", ["before", "after"])
def test_private_receipt_publication_swaps_preserve_substitutes_and_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    swap_point: str,
) -> None:
    root = tmp_path / "private-receipts"
    root.mkdir(mode=0o700)
    moved_name = f"moved-authentic-{swap_point}"
    substitute = b"unrelated-receipt-substitute"
    real_rename = enron_splitting._rename_noreplace_at

    def swap_around_rename(
        source_directory_fd: int,
        source_name: str,
        destination_directory_fd: int,
        destination_name: str,
    ) -> None:
        if destination_name == "ACCESS_CLAIMED.json" and swap_point == "before":
            os.rename(source_name, moved_name, src_dir_fd=source_directory_fd, dst_dir_fd=source_directory_fd)
            substitute_fd = os.open(
                source_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=source_directory_fd,
            )
            try:
                os.write(substitute_fd, substitute)
            finally:
                os.close(substitute_fd)
        real_rename(source_directory_fd, source_name, destination_directory_fd, destination_name)
        if destination_name == "ACCESS_CLAIMED.json" and swap_point == "after":
            os.rename(
                destination_name,
                moved_name,
                src_dir_fd=destination_directory_fd,
                dst_dir_fd=destination_directory_fd,
            )
            substitute_fd = os.open(
                destination_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=destination_directory_fd,
            )
            try:
                os.write(substitute_fd, substitute)
            finally:
                os.close(substitute_fd)

    monkeypatch.setattr(enron_splitting, "_rename_noreplace_at", swap_around_rename)
    with pytest.raises(EnronSplitError, match=r"(?i)(receipt|identity|publish)"):
        enron_splitting._write_exclusive_private_json(
            root,
            "ACCESS_CLAIMED.json",
            {"schema_version": "test", "commitment": "sha256:" + "1" * 64},
        )

    assert not (root / "ACCESS_CLAIMED.json").exists()
    assert (root / moved_name).read_bytes() == b""
    stages = tuple(root.glob(".ACCESS_CLAIMED.json.stage-*"))
    assert len(stages) == 1
    assert stages[0].read_bytes() == substitute


def test_stale_internal_receipt_stage_is_recovered_before_inventory_validation(tmp_path: Path) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="stale-receipt"))
    run = _split(tmp_path, preparation)
    stage = run.sealed / (".ACCESS_CLAIMED.json.stage-" + "a" * 24)
    stage.write_bytes(b'{"partial":')
    stage.chmod(0o600)
    stale_time = time.time_ns() - 10_000_000_000
    os.utime(stage, ns=(stale_time, stale_time))

    root = enron_splitting._assert_committed_run(  # noqa: SLF001
        run.sealed,
        enron_splitting._SEALED_FILES,  # noqa: SLF001
        allow_access_files=True,
    )
    assert root == run.sealed.absolute()
    assert not stage.exists()
    retained = tuple(run.sealed.glob(".nerb-cleanup-*"))
    assert len(retained) == 1
    assert retained[0].read_bytes() == b""


def test_stale_receipt_stage_swap_is_preserved_and_blocks_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "private-receipts"
    root.mkdir(mode=0o700)
    stage = root / (".ACCESS_CLAIMED.json.stage-" + "c" * 24)
    stage.write_bytes(b"partial-private-receipt")
    stage.chmod(0o600)
    stale_time = time.time_ns() - 10_000_000_000
    os.utime(stage, ns=(stale_time, stale_time))
    moved = root / "moved-authentic-stage"
    substitute = b"unrelated-stale-receipt"
    real_cleanup = enron_splitting._wipe_and_quarantine_receipt_file_at

    def swap_before_cleanup(
        directory_fd: int,
        name: str,
        descriptor: int,
        expected_identity: tuple[int, int],
    ) -> str:
        os.rename(name, moved.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        substitute_fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=directory_fd,
        )
        try:
            os.write(substitute_fd, substitute)
        finally:
            os.close(substitute_fd)
        return real_cleanup(directory_fd, name, descriptor, expected_identity)

    monkeypatch.setattr(enron_splitting, "_wipe_and_quarantine_receipt_file_at", swap_before_cleanup)
    with pytest.raises(EnronSplitError, match=r"(?i)(receipt|staging|safe)"):
        enron_splitting._cleanup_stale_receipt_stages(root)

    assert stage.read_bytes() == substitute
    assert moved.read_bytes() == b""


def test_receipt_quarantine_rename_race_restores_the_substitute_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "private-receipts"
    root.mkdir(mode=0o700)
    source = root / (".ACCESS_CLAIMED.json.stage-" + "d" * 24)
    source.write_bytes(b"authentic-private-receipt")
    source.chmod(0o600)
    moved = root / "moved-authentic-receipt"
    substitute = b"preserve-receipt-substitute"
    directory_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    descriptor = os.open(source.name, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
    identity = enron_splitting._receipt_file_identity(os.fstat(descriptor))
    real_rename = enron_splitting._rename_noreplace_at
    swapped = False

    def swap_inside_quarantine_rename(
        source_directory_fd: int,
        source_name: str,
        destination_directory_fd: int,
        destination_name: str,
    ) -> None:
        nonlocal swapped
        if source_name == source.name and destination_name.startswith(".nerb-cleanup-") and not swapped:
            swapped = True
            os.rename(source_name, moved.name, src_dir_fd=source_directory_fd, dst_dir_fd=source_directory_fd)
            substitute_fd = os.open(
                source_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=source_directory_fd,
            )
            try:
                os.write(substitute_fd, substitute)
            finally:
                os.close(substitute_fd)
        real_rename(source_directory_fd, source_name, destination_directory_fd, destination_name)

    monkeypatch.setattr(enron_splitting, "_rename_noreplace_at", swap_inside_quarantine_rename)
    try:
        with pytest.raises(EnronSplitError):
            enron_splitting._wipe_and_quarantine_receipt_file_at(
                directory_fd,
                source.name,
                descriptor,
                identity,
            )
    finally:
        os.close(descriptor)
        os.close(directory_fd)

    assert source.read_bytes() == substitute
    assert moved.read_bytes() == b""
    assert not tuple(root.glob(".nerb-cleanup-*"))


def test_unsafe_internal_receipt_stage_uses_stable_split_error_boundary(tmp_path: Path) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="unsafe-receipt"))
    run = _split(tmp_path, preparation)
    stage = run.sealed / (".ACCESS_CLAIMED.json.stage-" + "b" * 24)
    stage.symlink_to(run.sealed / "manifest.json")

    with pytest.raises(EnronSplitError, match=r"(?i)(stale|receipt|unsafe|stage)"):
        enron_splitting._assert_committed_run(  # noqa: SLF001
            run.sealed,
            enron_splitting._SEALED_FILES,  # noqa: SLF001
            allow_access_files=True,
        )


def test_crash_stranded_claim_can_be_finalized_as_aborted_without_reopening_test(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="finalize-aborted"))
    run = _split(tmp_path, preparation)
    with _bound_final_test_access(run) as access:
        tuple(access.iter_records())
    (run.sealed / "ACCESS_OUTCOME.json").unlink()
    assert verify_enron_splits(run.development, run.sealed, seed=run.seed)["access"]["status"] == "claimed"
    actual_open_at = enron_splitting.open_private_binary_input_at
    monkeypatch.setattr(
        enron_splitting,
        "open_private_binary_input_at",
        lambda directory_fd, name, **kwargs: (
            pytest.fail("aborted finalization reopened sealed content")
            if name == "test.jsonl"
            else actual_open_at(directory_fd, name, **kwargs)
        ),
    )

    finalized = enron_splitting.finalize_aborted_enron_final_test_access(run.sealed)
    assert finalized["status"] == "aborted"
    assert finalized["access_count"] == 1
    assert verify_enron_splits(run.development, run.sealed, seed=run.seed)["access"]["status"] == "aborted"
    with pytest.raises(EnronSplitError, match=r"(?i)(claim|outcome|awaiting|access)"):
        enron_splitting.finalize_aborted_enron_final_test_access(run.sealed)


def test_process_exit_releases_claim_liveness_lock_for_aborted_finalization(tmp_path: Path) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="process-stranded-claim"))
    run = _split(tmp_path, preparation)
    target = _frozen_target(run)
    enron_splitting.begin_enron_final_test_access(run.sealed, frozen_target=target).bind_evidence("sha256:" + "7" * 64)
    script = """
import json
import os
import sys
from pathlib import Path
from nerb.enron_splitting import begin_enron_final_test_access

access = begin_enron_final_test_access(Path(sys.argv[1]), frozen_target=json.loads(sys.argv[2]))
access.__enter__()
os._exit(0)
"""

    subprocess.run(
        [sys.executable, "-c", script, str(run.sealed), json.dumps(target, sort_keys=True)],
        check=True,
    )

    assert (run.sealed / "ACCESS_CLAIMED.json").is_file()
    assert not (run.sealed / "ACCESS_OUTCOME.json").exists()
    finalized = enron_splitting.finalize_aborted_enron_final_test_access(run.sealed)
    assert finalized["status"] == "aborted"
    assert finalized["access_count"] == 1


def test_missing_pair_commit_receipt_blocks_sealed_access_without_creating_claim(tmp_path: Path) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="unpaired"))
    run = _split(tmp_path, preparation)
    (run.sealed / "PAIR_COMMITTED.json").unlink()

    with pytest.raises(EnronSplitError, match=r"(?i)(pair|commit|missing|inventory|file)"):
        enron_splitting.begin_enron_final_test_access(
            run.sealed,
            frozen_target=_frozen_target(run),
        ).bind_evidence("sha256:" + "7" * 64)
    assert not (run.sealed / "ACCESS_CLAIMED.json").exists()


def test_preseal_receipt_is_pair_bound_and_postseal_verification_never_opens_test(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="preseal-proof"))
    run = _split(tmp_path, preparation)
    receipt_path = run.sealed / "PRESEAL_VERIFIED.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    pair = json.loads((run.sealed / "PAIR_COMMITTED.json").read_text(encoding="utf-8"))
    assert receipt["test_content_verified_before_seal"] is True
    assert pair["preseal_verification_sha256"] == _file_sha256(receipt_path)
    actual_open = enron_splitting.open_private_binary_input
    actual_open_at = enron_splitting.open_private_binary_input_at

    def reject_test_open(path: Path, **kwargs: Any) -> Any:
        if Path(path).name == "test.jsonl":
            pytest.fail("post-seal verification opened test content")
        return actual_open(path, **kwargs)

    monkeypatch.setattr(enron_splitting, "open_private_binary_input", reject_test_open)
    monkeypatch.setattr(
        enron_splitting,
        "open_private_binary_input_at",
        lambda directory_fd, name, **kwargs: (
            pytest.fail("post-seal verification opened pinned test content")
            if name == "test.jsonl"
            else actual_open_at(directory_fd, name, **kwargs)
        ),
    )
    assert verify_enron_splits(run.development, run.sealed, seed=run.seed)["valid"] is True
    assert (
        enron_splitting.project_enron_contract_splits(run.development, run.sealed, seed=run.seed)["test_sealed"] is True
    )


def test_preseal_verification_failure_is_atomic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="preseal-atomic"))
    monkeypatch.setattr(
        enron_splitting,
        "_verify_prepared_conservation",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(EnronSplitError("injected preseal failure")),
    )

    with pytest.raises(EnronSplitError, match="injected preseal failure"):
        _split(tmp_path, preparation, name="preseal-failure")
    assert not (tmp_path / "preseal-failure-development").exists()
    assert not (tmp_path / "preseal-failure-sealed").exists()


def test_preseal_replay_rejects_a_coherently_wrong_build_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="preseal-independent-replay"))
    actual_build_state = enron_splitting._build_state

    def wrong_build_state(*args: Any, **kwargs: Any) -> Any:
        state = actual_build_state(*args, **kwargs)
        return replace(state, edge_counts={**state.edge_counts, "coherently_wrong": 1})

    monkeypatch.setattr(enron_splitting, "_build_state", wrong_build_state)

    with pytest.raises(EnronSplitError, match=r"(?i)(pre-seal|replay|aggregate)"):
        _split(tmp_path, preparation, name="preseal-independent-replay")
    assert not (tmp_path / "preseal-independent-replay-development").exists()
    assert not (tmp_path / "preseal-independent-replay-sealed").exists()


def test_changed_preseal_receipt_is_rejected_without_opening_test(tmp_path: Path) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="preseal-tamper"))
    run = _split(tmp_path, preparation)
    receipt_path = run.sealed / "PRESEAL_VERIFIED.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["prepared_records"] += 1
    receipt_path.write_text(
        json.dumps(receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    receipt_path.chmod(0o600)

    with pytest.raises(EnronSplitError, match=r"(?i)(pre-seal|receipt|hash|bind)"):
        verify_enron_splits(run.development, run.sealed, seed=run.seed)
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


def test_postseal_verifier_uses_preseal_receipt_without_reingesting_roles(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preparation = _prepare(tmp_path, _dated_rows(24, prefix="ingestion-aba"))
    run = _split(tmp_path, preparation)
    monkeypatch.setattr(
        enron_splitting,
        "_ingest_prepared",
        lambda *_args, **_kwargs: pytest.fail("post-seal verification must not reingest role content"),
    )

    assert verify_enron_splits(run.development, run.sealed, seed=run.seed)["valid"] is True


def test_small_corpora_require_explicit_non_promotable_fixture_mode(tmp_path: Path) -> None:
    preparation = _prepare(tmp_path, _dated_rows(6, prefix="small"))
    with pytest.raises(EnronSplitError, match=r"(?i)(fixture|production|minimum|small|record|group)"):
        _split(tmp_path, preparation, name="production", fixture_mode=False, sample_per_role=1)

    fixture = _split(tmp_path, preparation, name="fixture", fixture_mode=True, sample_per_role=1)
    assert fixture.summary["fixture_mode"] is True
    assert fixture.summary["promotable"] is False
    assert all(_role_rows(fixture).values())


def test_production_support_floors_enforce_each_frozen_boundary(tmp_path: Path) -> None:
    options = EnronSplitOptions(
        preparation_run=tmp_path / "unused-preparation",
        development_output_dir=tmp_path / "unused-development",
        sealed_output_dir=tmp_path / "unused-sealed",
        scratch_dir=tmp_path / "unused-scratch",
        fixture_mode=False,
    )

    def components(largest: int = 9_999) -> tuple[enron_splitting._Component, ...]:  # noqa: SLF001
        return tuple(
            enron_splitting._Component(  # noqa: SLF001
                group_id="sha256:" + f"{index:064x}",
                nodes=(),
                records=largest if index == 0 else 1,
                occurrences=largest if index == 0 else 1,
                temporal=False,
                anchor_utc=None,
            )
            for index in range(3)
        )

    role_records = {"train": 160_000, "validation": 20_000, "test": 20_000}
    role_groups = {"train": 1_000, "validation": 1_000, "test": 1_000}
    enron_splitting._enforce_support(  # noqa: SLF001
        components(), 200_000, role_records, role_groups, 0, options
    )

    with pytest.raises(EnronSplitError, match=r"(?i)(truncation|grouping|production)"):
        enron_splitting._enforce_support(  # noqa: SLF001
            components(), 200_000, role_records, role_groups, 1, options
        )
    with pytest.raises(EnronSplitError, match=r"(?i)(five percent|10000|record)"):
        enron_splitting._enforce_support(  # noqa: SLF001
            components(),
            200_000,
            {**role_records, "test": 9_999},
            role_groups,
            0,
            options,
        )
    with pytest.raises(EnronSplitError, match=r"(?i)(five percent|10000|record)"):
        enron_splitting._enforce_support(  # noqa: SLF001
            components(),
            300_000,
            {"train": 270_001, "validation": 15_000, "test": 14_999},
            role_groups,
            0,
            options,
        )
    with pytest.raises(EnronSplitError, match=r"(?i)(1000|group)"):
        enron_splitting._enforce_support(  # noqa: SLF001
            components(),
            200_000,
            role_records,
            {**role_groups, "validation": 999},
            0,
            options,
        )
    with pytest.raises(EnronSplitError, match=r"(?i)(five percent|component)"):
        enron_splitting._enforce_support(  # noqa: SLF001
            components(10_000), 200_000, role_records, role_groups, 0, options
        )


def test_production_cohort_support_accepts_exact_floor_and_rejects_one_below(tmp_path: Path) -> None:
    options = EnronSplitOptions(
        preparation_run=tmp_path / "unused-preparation",
        development_output_dir=tmp_path / "unused-development",
        sealed_output_dir=tmp_path / "unused-sealed",
        scratch_dir=tmp_path / "unused-scratch",
        fixture_mode=False,
    )
    required = {
        "identity:all_known": 100,
        "identity:all_novel": 100,
        "frequency:head": 100,
        "frequency:tail": 100,
        "natural:present": 100,
        "structured:present": 100,
    }
    counts = {"train": {}, "validation": dict(required), "test": dict(required)}
    enron_splitting._enforce_cohort_support(counts, options)  # noqa: SLF001

    counts["test"]["frequency:tail"] = 99
    with pytest.raises(EnronSplitError, match=r"(?i)(cohort|head|tail|100)"):
        enron_splitting._enforce_cohort_support(counts, options)  # noqa: SLF001


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
                scratch_dir=tmp_path / "unused-scratch",
                seed="nested-seed",
                sample_per_role=1,
                fixture_mode=True,
            )
        )

    assert not development.exists()
    assert not sealed.exists()

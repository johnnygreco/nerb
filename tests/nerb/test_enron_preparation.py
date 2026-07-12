from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

import nerb.enron_preparation as enron_preparation
from nerb.enron_preparation import (
    PREPARED_RECORD_SCHEMA_VERSION,
    PROFILE_SCHEMA_VERSION,
    EnronPreparationOptions,
    load_enron_preparation_run,
    prepare_enron_source,
)

JsonObject = dict[str, Any]
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
DOCUMENT_ID_RE = re.compile(r"^[a-z0-9_.:-]*[0-9a-f]{64}$")


@dataclass(frozen=True)
class RunArtifacts:
    root: Path
    records_path: Path
    profile_path: Path
    manifest_path: Path
    records: tuple[JsonObject, ...]
    profile: JsonObject
    manifest: JsonObject


def _options(input_jsonl: Path | None, output_dir: Path, **overrides: Any) -> EnronPreparationOptions:
    values: dict[str, Any] = {
        "output_dir": output_dir,
        "input_jsonl": input_jsonl,
        "dataset_id": "synthetic/enron-preparation",
        "dataset_revision": "fixture-v2",
        "dataset_split": "train",
        "max_rows": None,
        "max_jsonl_line_bytes": 64 * 1024,
        "max_body_chars": 8 * 1024,
        "max_body_bytes": 32 * 1024,
        "max_subject_chars": 512,
        "max_subject_bytes": 2 * 1024,
        "max_recipients_per_field": 64,
        "allow_unignored_output": False,
    }
    values.update(overrides)
    return EnronPreparationOptions(**values)


def _prepare(input_jsonl: Path, output_dir: Path, **overrides: Any) -> tuple[Mapping[str, Any], RunArtifacts]:
    result = prepare_enron_source(_options(input_jsonl, output_dir, **overrides))
    assert isinstance(result, Mapping)
    return result, _discover_run(output_dir)


def _discover_run(output_dir: Path) -> RunArtifacts:
    assert output_dir.is_dir()
    jsonl_candidates: list[tuple[Path, tuple[JsonObject, ...]]] = []
    json_candidates: list[tuple[Path, JsonObject]] = []
    for path in sorted(candidate for candidate in output_dir.rglob("*") if candidate.is_file()):
        if path.suffix == ".jsonl":
            rows = tuple(json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
            if rows and all(row.get("schema_version") == PREPARED_RECORD_SCHEMA_VERSION for row in rows):
                jsonl_candidates.append((path, rows))
        elif path.suffix == ".json":
            value = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(value, dict):
                json_candidates.append((path, value))

    assert len(jsonl_candidates) == 1, jsonl_candidates
    profile_candidates = [
        (path, value) for path, value in json_candidates if value.get("schema_version") == PROFILE_SCHEMA_VERSION
    ]
    assert len(profile_candidates) == 1, profile_candidates
    manifest_candidates = [
        (path, value)
        for path, value in json_candidates
        if path != profile_candidates[0][0]
        and (
            "manifest" in str(value.get("schema_version", ""))
            or ("artifacts" in value and "source" in value)
            or ("prepared_artifact" in value and "profile_artifact" in value)
        )
    ]
    assert len(manifest_candidates) == 1, manifest_candidates

    records_path, records = jsonl_candidates[0]
    profile_path, profile = profile_candidates[0]
    manifest_path, manifest = manifest_candidates[0]
    return RunArtifacts(
        root=manifest_path.parent,
        records_path=records_path,
        profile_path=profile_path,
        manifest_path=manifest_path,
        records=records,
        profile=profile,
        manifest=manifest,
    )


def _write_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> Path:
    payload = "".join(
        json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
        for row in rows
    )
    path.write_text(payload, encoding="utf-8")
    return path


def _normalized_path(parts: Sequence[str]) -> str:
    return re.sub(r"[^a-z0-9]+", "", "/".join(parts).lower())


def _walk(value: Any, path: tuple[str, ...] = ()) -> Iterable[tuple[tuple[str, ...], Any]]:
    yield path, value
    if isinstance(value, Mapping):
        for key, child in value.items():
            yield from _walk(child, (*path, str(key)))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            yield from _walk(child, (*path, str(index)))


def _matching_values(value: Any, alternatives: Sequence[Sequence[str]], expected_type: type[Any]) -> list[Any]:
    matches: list[Any] = []
    for path, child in _walk(value):
        if type(child) is not expected_type:
            continue
        normalized = _normalized_path(path)
        if any(
            all(re.sub(r"[^a-z0-9]+", "", token.lower()) in normalized for token in terms) for terms in alternatives
        ):
            matches.append(child)
    return matches


def _assert_counter(value: Any, *alternatives: Sequence[str], minimum: int = 1) -> None:
    matches = _matching_values(value, alternatives, int)
    assert any(item >= minimum for item in matches), (alternatives, matches, value)


def _first_hash(value: Any, *alternatives: Sequence[str]) -> str:
    matches = _matching_values(value, alternatives, str)
    hashes = [item for item in matches if SHA256_RE.fullmatch(item)]
    assert hashes, (alternatives, matches, value)
    return hashes[0]


def _first_integer(value: Any, *alternatives: Sequence[str]) -> int:
    matches = _matching_values(value, alternatives, int)
    assert matches, (alternatives, value)
    return int(matches[0])


def _strings(value: Any) -> Iterable[str]:
    for _, child in _walk(value):
        if isinstance(child, str):
            yield child


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, separators=(",", ": "), allow_nan=False) + "\n",
        encoding="utf-8",
    )


def _rebind_run(run: RunArtifacts, profile: JsonObject, manifest: JsonObject) -> None:
    for artifact_id, path in (("prepared_records", run.records_path), ("rejections", run.root / "rejections.jsonl")):
        descriptor = manifest["artifacts"][artifact_id]
        descriptor["sha256"] = _sha256_file(path)
        descriptor["bytes"] = path.stat().st_size
        profile["artifacts"][artifact_id] = dict(descriptor)
    manifest["source"] = dict(profile["source"])
    manifest["privacy"] = dict(profile["privacy"])
    manifest["preparation"] = {
        "cleaning_policy_sha256": profile["policies"]["cleaning_policy_sha256"],
        "date_policy_sha256": profile["policies"]["date_policy_sha256"],
        "grouping_policy_sha256": profile["policies"]["grouping_policy_sha256"],
        "output_records": profile["records"]["unique_prepared_records"],
        "output_occurrences": profile["records"]["prepared_occurrences"],
        "text_views": profile["text_views"],
    }
    _write_json(run.profile_path, profile)
    manifest["artifacts"]["profile"]["sha256"] = _sha256_file(run.profile_path)
    manifest["artifacts"]["profile"]["bytes"] = run.profile_path.stat().st_size
    _write_json(run.manifest_path, manifest)


def _strip_transport_provenance(value: Any) -> Any:
    """Remove the explicitly order-sensitive raw-container receipt, if one is emitted."""
    if isinstance(value, Mapping):
        identifier = str(value.get("id", "")).lower()
        if "transport" in identifier or "raw_input" in identifier or "raw-input" in identifier:
            return None
        cleaned: dict[str, Any] = {}
        for key, child in value.items():
            normalized = re.sub(r"[^a-z0-9]+", "", str(key).lower())
            if "transport" in normalized or "rawinput" in normalized:
                continue
            if "inputfile" in normalized and ("sha256" in normalized or "hash" in normalized):
                continue
            stripped = _strip_transport_provenance(child)
            if stripped is not None:
                cleaned[str(key)] = stripped
        return cleaned
    if isinstance(value, list):
        return [stripped for item in value if (stripped := _strip_transport_provenance(item)) is not None]
    return value


def _assert_aggregate_private(profile: Mapping[str, Any], manifest: Mapping[str, Any], tmp_path: Path) -> None:
    serialized = json.dumps(
        {"profile": profile, "manifest": manifest},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    forbidden = (
        "@",
        "fixture.invalid",
        "alice.alpha",
        "ZEPHYR-GALAXY-SECRET",
        "PRIVATE-SCRIPT-MARKER",
        "GAMMA-UNICODE-MARKER",
        "maildir/alice",
        str(tmp_path),
    )
    assert all(token not in serialized for token in forbidden)


def test_reordered_source_produces_identical_prepared_profile_and_manifest(
    tmp_path: Path, test_data_path: Path
) -> None:
    source = test_data_path / "enron_preparation.jsonl"
    reversed_source = tmp_path / "reversed.jsonl"
    lines = source.read_text(encoding="utf-8").splitlines()
    reversed_source.write_text("\n".join(reversed(lines)) + "\n", encoding="utf-8")

    _, first = _prepare(source, tmp_path / "first")
    _, second = _prepare(reversed_source, tmp_path / "second")

    assert first.records_path.read_bytes() == second.records_path.read_bytes()
    assert first.profile_path.read_bytes() == second.profile_path.read_bytes()
    assert _strip_transport_provenance(first.manifest) == _strip_transport_provenance(second.manifest)
    assert [record["document_id"] for record in first.records] == sorted(
        record["document_id"] for record in first.records
    )
    assert all(DOCUMENT_ID_RE.fullmatch(str(record["document_id"])) for record in first.records)
    assert "source_index" not in json.dumps(first.records, sort_keys=True)
    first_receipt = json.loads((first.root / "transport-receipt.json").read_text(encoding="utf-8"))
    assert first_receipt["transport_complete"] is True
    assert first_receipt["transport_sha256"] == _sha256_file(source)
    assert first_receipt["transport_prefix_sha256"] is None


def test_row_limited_local_receipt_labels_prefix_hash_as_incomplete(tmp_path: Path, test_data_path: Path) -> None:
    source = test_data_path / "enron_preparation.jsonl"
    _, run = _prepare(source, tmp_path / "limited", max_rows=1)
    receipt = json.loads((run.root / "transport-receipt.json").read_text(encoding="utf-8"))

    assert receipt["transport_complete"] is False
    assert receipt["transport_sha256"] is None
    assert SHA256_RE.fullmatch(receipt["transport_prefix_sha256"])
    assert receipt["transport_bytes"] < source.stat().st_size


def test_exact_duplicate_rows_collapse_but_distinct_mailbox_copies_remain_grouped(
    tmp_path: Path, test_data_path: Path
) -> None:
    _, run = _prepare(test_data_path / "enron_preparation.jsonl", tmp_path / "run")

    document_ids = [str(record["document_id"]) for record in run.records]
    assert len(document_ids) == len(set(document_ids))
    occurrence_counts = [
        _first_integer(
            record,
            ("source", "occurrence", "count"),
            ("identical", "row", "count"),
            ("duplicate", "occurrence", "count"),
        )
        for record in run.records
    ]
    assert occurrence_counts.count(2) == 1

    message_groups: defaultdict[str, list[JsonObject]] = defaultdict(list)
    content_groups: defaultdict[str, list[JsonObject]] = defaultdict(list)
    for record in run.records:
        message_groups[_first_hash(record, ("grouping", "message", "id"), ("provenance", "message", "id"))].append(
            record
        )
        content_groups[_first_hash(record, ("grouping", "exact", "content"), ("grouping", "exact", "body"))].append(
            record
        )

    mailbox_copies = [group for group in message_groups.values() if len(group) >= 2]
    assert mailbox_copies
    assert any(len({str(record["document_id"]) for record in group}) >= 2 for group in mailbox_copies)
    assert any(len(group) >= 2 for group in content_groups.values())
    _assert_counter(run.profile, ("duplicate", "source", "row"), ("identical", "input", "row"))
    _assert_counter(run.profile, ("duplicate", "message", "id"), ("mailbox", "copy"))


def test_mailbox_owner_hash_groups_files_without_exposing_mailbox_paths(tmp_path: Path, test_data_path: Path) -> None:
    _, run = _prepare(test_data_path / "enron_preparation.jsonl", tmp_path / "run")
    alpha = [record for record in run.records if record["headers"]["message_id"] == "<alpha-001@fixture.invalid>"]
    beta = next(record for record in run.records if record["headers"]["message_id"] == "<beta-002@fixture.invalid>")

    alpha_owners = {record["source"]["mailbox_owner_sha256"] for record in alpha}
    assert len(alpha_owners) == 2
    assert beta["source"]["mailbox_owner_sha256"] in alpha_owners
    assert beta["source"]["mailbox_folder_role"] == "inbox"
    assert run.profile["grouping_features"]["mailbox_owner_available"] == 8
    assert run.profile["cleaning"]["mailbox_locator_parsed"] == 8
    _assert_aggregate_private(run.profile, run.manifest, tmp_path)


def test_mailbox_folder_roles_use_frozen_tokens_not_substrings() -> None:
    assert enron_preparation._mailbox_folder_role(["sent_mail"]) == "sent"
    assert enron_preparation._mailbox_folder_role(["presentations"]) == "other"


def test_cleaning_dates_and_natural_views_are_auditable_without_answer_injection(
    tmp_path: Path, test_data_path: Path
) -> None:
    _, run = _prepare(
        test_data_path / "enron_preparation.jsonl",
        tmp_path / "run",
        max_recipients_per_field=2,
    )

    natural_texts: list[str] = []
    for record in run.records:
        views = record.get("views")
        assert isinstance(views, Mapping)
        assert isinstance(views.get("current_body"), str)
        assert isinstance(views.get("subject_current_body"), str)
        assert isinstance(views.get("structured_headers"), Mapping)
        natural_texts.extend((str(views["current_body"]), str(views["subject_current_body"])))

    joined = "\n".join(natural_texts)
    assert "Addresses:" not in joined
    assert "PRIVATE-SCRIPT-MARKER" not in joined
    assert "<script" not in joined.lower()
    assert "=?UTF-8?" not in joined
    assert "\x07" not in joined
    assert "\u200b" not in joined
    assert "EPSILON MIME MARKER" in joined
    reply = next(text for text in natural_texts if "Acknowledged." in text)
    assert "Original Message" not in reply
    assert "ZEPHYR-GALAXY-SECRET" not in reply

    all_record_strings = set(_strings(run.records))
    assert "2001-01-02T09:04:05Z" in all_record_strings
    assert any("invalid" in value.lower() for value in all_record_strings)
    assert any("missing" in value.lower() for value in all_record_strings)

    _assert_counter(run.profile, ("date", "invalid"))
    _assert_counter(run.profile, ("date", "missing"))
    _assert_counter(run.profile, ("html", "removed"), ("html", "decoded"))
    _assert_counter(run.profile, ("mime", "decoded"), ("quoted", "printable", "decoded"))
    _assert_counter(run.profile, ("control", "removed"), ("control", "replaced"))
    _assert_counter(run.profile, ("reply", "removed"), ("quoted", "reply"))
    _assert_counter(run.profile, ("recipient", "truncated"), ("recipient", "limit"))
    _assert_counter(run.profile, ("header", "encoded", "decoded"))
    _assert_aggregate_private(run.profile, run.manifest, tmp_path)


def test_malformed_nonfinite_duplicate_key_invalid_utf8_and_huge_rows_are_bounded_and_counted(tmp_path: Path) -> None:
    valid_one = json.dumps(
        {
            "message_id": "<valid-one@fixture.invalid>",
            "subject": "Valid one",
            "from": "one@fixture.invalid",
            "to": [],
            "cc": [],
            "bcc": [],
            "date": "2001-01-01T00:00:00Z",
            "body": "FIRST-VALID-MARKER",
            "file_name": "fixture/valid-one",
        },
        separators=(",", ":"),
    ).encode()
    valid_two = (
        valid_one.replace(b"valid-one", b"valid-two")
        .replace(b"Valid one", b"Valid two")
        .replace(b"FIRST-VALID-MARKER", b"SECOND-VALID-MARKER")
    )
    huge = b'{"message_id":"<huge@fixture.invalid>","body":"' + b"X" * (1024 * 1024) + b'"}'
    source = tmp_path / "adversarial.jsonl"
    source.write_bytes(
        b"\n".join(
            (
                valid_one,
                b'{"message_id":"unterminated"',
                b'{"message_id":"duplicate","message_id":"duplicate-again","body":"x"}',
                b'{"message_id":"nonfinite","value":NaN,"body":"x"}',
                b'{"message_id":"invalid-utf8","body":"\xff"}',
                huge,
                valid_two,
            )
        )
        + b"\n"
    )

    _, run = _prepare(source, tmp_path / "run", max_jsonl_line_bytes=512)

    assert len(run.records) == 2
    assert any("FIRST-VALID-MARKER" in value for value in _strings(run.records))
    assert any("SECOND-VALID-MARKER" in value for value in _strings(run.records))
    _assert_counter(run.profile, ("malformed", "json"), ("invalid", "json"))
    _assert_counter(run.profile, ("duplicate", "json", "key"), ("duplicate", "key"))
    _assert_counter(run.profile, ("nonfinite", "json"), ("nonfinite", "number"))
    _assert_counter(run.profile, ("invalid", "utf8"), ("encoding", "invalid"))
    _assert_counter(run.profile, ("oversized", "line"), ("line", "too", "large"), ("jsonl", "line", "limit"))
    _assert_aggregate_private(run.profile, run.manifest, tmp_path)
    rejection_rows = [
        json.loads(line) for line in (run.root / "rejections.jsonl").read_text(encoding="utf-8").splitlines() if line
    ]
    assert sum(row["occurrence_count"] for row in rejection_rows) == 5
    assert all(SHA256_RE.fullmatch(row["source_digest_sha256"]) for row in rejection_rows)
    assert all("@" not in json.dumps(row, sort_keys=True) for row in rejection_rows)


def test_character_byte_and_recipient_limits_do_not_split_unicode(tmp_path: Path) -> None:
    row = {
        "message_id": "<limits@fixture.invalid>",
        "subject": "SUBJECT-LIMIT-" + "é" * 80,
        "from": "sender@fixture.invalid",
        "to": [f"recipient-{index}@fixture.invalid" for index in range(6)],
        "cc": [f"copy-{index}@fixture.invalid" for index in range(4)],
        "bcc": [],
        "date": "2001-01-01T00:00:00Z",
        "body": "BODY-LIMIT-" + "🙂" * 100,
        "file_name": "fixture/limits",
    }
    source = _write_jsonl(tmp_path / "limits.jsonl", [row])

    _, run = _prepare(
        source,
        tmp_path / "run",
        max_body_chars=40,
        max_body_bytes=48,
        max_subject_chars=20,
        max_subject_bytes=24,
        max_recipients_per_field=2,
    )

    assert len(run.records) == 1
    views = run.records[0]["views"]
    body = str(views["current_body"])
    assert len(body) <= 40
    assert len(body.encode("utf-8")) <= 48
    assert "SUBJECT-LIMIT-" + "é" * 80 not in str(views["subject_current_body"])
    structured_headers = views["structured_headers"]
    assert isinstance(structured_headers, Mapping)
    for field in ("to", "cc", "bcc"):
        recipients = structured_headers.get(field, [])
        assert isinstance(recipients, Sequence) and not isinstance(recipients, (str, bytes, bytearray))
        assert len(recipients) <= 2
    _assert_counter(run.profile, ("body", "truncated"), ("body", "limit"))
    _assert_counter(run.profile, ("subject", "truncated"), ("subject", "limit"))
    _assert_counter(run.profile, ("recipient", "truncated"), ("recipient", "limit"))
    assert run.records[0]["view_metadata"]["subject_current_body"]["truncated"] is True


def test_message_id_and_embedded_reference_features_use_the_same_join_key(tmp_path: Path) -> None:
    rows = [
        {
            "message_id": "<original@fixture.invalid>",
            "subject": "Thread",
            "from": "first@fixture.invalid",
            "to": ["second@fixture.invalid"],
            "cc": [],
            "bcc": [],
            "date": "2001-01-01T00:00:00Z",
            "body": "Original body.",
            "file_name": "fixture/original",
        },
        {
            "message_id": "<reply@fixture.invalid>",
            "subject": "Re: Thread",
            "from": "second@fixture.invalid",
            "to": ["first@fixture.invalid"],
            "cc": [],
            "bcc": [],
            "date": "2001-01-02T00:00:00Z",
            "body": "Reply body.\n\nReferences: <original@fixture.invalid>",
            "file_name": "fixture/reply",
        },
    ]
    _, run = _prepare(_write_jsonl(tmp_path / "thread.jsonl", rows), tmp_path / "run")

    original = next(record for record in run.records if record["headers"]["message_id"].startswith("<original"))
    reply = next(record for record in run.records if record["headers"]["message_id"].startswith("<reply"))
    original_key = original["grouping"]["normalized_message_id_sha256"]
    assert original_key in reply["grouping"]["embedded_message_id_sha256s"]


def test_embedded_message_id_scan_covers_full_bounded_body_and_reports_cap() -> None:
    late_id = "<late-reference@fixture.invalid>"
    hashes, truncated = enron_preparation._embedded_message_id_features(  # noqa: SLF001
        "X" * 1_000_001 + f"\nReferences: {late_id}"
    )
    assert hashes == [enron_preparation._private_feature_hash("message-id", late_id.strip("<>").casefold())]  # noqa: SLF001
    assert truncated is False

    many_ids = "References: " + " ".join(f"<reference-{index}@fixture.invalid>" for index in range(65))
    hashes, truncated = enron_preparation._embedded_message_id_features(many_ids)  # noqa: SLF001
    assert len(hashes) == 64
    assert truncated is True


def test_recipient_cap_counts_multiple_addresses_parsed_from_one_header_value(tmp_path: Path) -> None:
    row = {
        "message_id": "<headers@fixture.invalid>",
        "subject": "Header parsing",
        "from": "sender@fixture.invalid",
        "to": ["one@fixture.invalid, two@fixture.invalid, three@fixture.invalid"],
        "cc": [],
        "bcc": [],
        "date": "2001-01-01T00:00:00Z",
        "body": "Natural body.",
        "file_name": "fixture/headers",
    }
    _, run = _prepare(
        _write_jsonl(tmp_path / "headers.jsonl", [row]),
        tmp_path / "run",
        max_recipients_per_field=2,
    )

    assert len(run.records[0]["views"]["structured_headers"]["to"]) == 2
    _assert_counter(run.profile, ("recipient", "truncated"), minimum=1)


def test_oversized_and_empty_structured_header_values_are_explicitly_audited(tmp_path: Path) -> None:
    base = {
        "message_id": "<headers@fixture.invalid>",
        "subject": "Header audit",
        "from": "sender@fixture.invalid",
        "to": [","],
        "cc": [],
        "bcc": [],
        "date": "2001-01-01T00:00:00Z",
        "body": "Natural body.",
        "file_name": "fixture/headers",
    }
    oversized = {**base, "message_id": "<oversized@fixture.invalid>", "to": ["x" * 16_385]}
    _, run = _prepare(_write_jsonl(tmp_path / "header-audit.jsonl", [base, oversized]), tmp_path / "run")

    assert len(run.records) == 1
    _assert_counter(run.profile, ("header", "address", "dropped"))
    _assert_counter(run.profile, ("oversized", "to", "item"))
    rejection = (run.root / "rejections.jsonl").read_text(encoding="utf-8")
    assert "oversized_to_item" in rejection
    assert "x" * 100 not in rejection


def test_full_visible_near_duplicate_feature_preserves_forward_leakage_edge(tmp_path: Path) -> None:
    original_body = " ".join(f"contract-token-{index}" for index in range(120))
    rows = [
        {
            "message_id": "",
            "subject": "Contract review",
            "from": "author@fixture.invalid",
            "to": ["reviewer@fixture.invalid"],
            "cc": [],
            "bcc": [],
            "date": "2001-01-01T00:00:00Z",
            "body": original_body,
            "file_name": "fixture/original",
        },
        {
            "message_id": "",
            "subject": "Fwd: Contract review",
            "from": "forwarder@fixture.invalid",
            "to": ["outside@fixture.invalid"],
            "cc": [],
            "bcc": [],
            "date": "2001-01-02T00:00:00Z",
            "body": (
                "FYI.\n\n----- Forwarded Message -----\n"
                "From: author@fixture.invalid\nSubject: Contract review\n\n" + original_body
            ),
            "file_name": "fixture/forward",
        },
    ]
    _, run = _prepare(_write_jsonl(tmp_path / "forward.jsonl", rows), tmp_path / "run")
    original, forwarded = sorted(run.records, key=lambda record: len(record["views"]["full_visible_body"]))

    original_bands = set(original["grouping"]["near_duplicate"]["full_visible_body"]["band_sha256s"])
    forwarded_bands = set(forwarded["grouping"]["near_duplicate"]["full_visible_body"]["band_sha256s"])
    assert original_bands & forwarded_bands
    assert forwarded["views"]["current_body"] == "FYI."


def test_pathological_integer_and_escaped_surrogate_are_counted_without_aborting(tmp_path: Path) -> None:
    valid = {
        "message_id": "<valid@fixture.invalid>",
        "subject": "Valid",
        "from": "sender@fixture.invalid",
        "to": [],
        "cc": [],
        "bcc": [],
        "date": "2001-01-01T00:00:00Z",
        "body": "VALID-AFTER-ERRORS",
        "file_name": "fixture/valid",
    }
    source = tmp_path / "pathological.jsonl"
    source.write_bytes(
        b'{"message_id":"huge","date":'
        + b"9" * 5_000
        + b',"body":"x"}\n'
        + b'{"message_id":"\\ud800","body":"x"}\n'
        + (json.dumps(valid, separators=(",", ":")) + "\n").encode()
    )

    _, run = _prepare(source, tmp_path / "run", max_jsonl_line_bytes=16 * 1024)

    assert len(run.records) == 1
    assert any("VALID-AFTER-ERRORS" in value for value in _strings(run.records))
    _assert_counter(run.profile, ("malformed", "json"))
    _assert_counter(run.profile, ("invalid", "message", "unicode"), ("invalid", "unicode"))


def test_huggingface_source_is_pinned_streaming_and_records_package_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, dict[str, Any]]] = []

    class SinglePassRows:
        def __init__(self) -> None:
            self.iterations = 0

        def __iter__(self) -> Iterable[Mapping[str, Any]]:
            self.iterations += 1
            assert self.iterations == 1
            yield {
                "message_id": "<hf-fixture@fixture.invalid>",
                "subject": "HF fixture",
                "from": "hf@fixture.invalid",
                "to": [],
                "cc": [],
                "bcc": [],
                "date": datetime(2001, 1, 1, tzinfo=timezone.utc),
                "body": "HF-PRIVATE-BODY-MARKER",
                "file_name": "fixture/hf",
            }

        def __len__(self) -> int:
            raise AssertionError("streaming source must not be materialized or length-probed")

    rows = SinglePassRows()
    datasets_module = ModuleType("datasets")
    setattr(datasets_module, "__version__", "99.1.0-fixture")

    def load_dataset(dataset_id: str, **kwargs: Any) -> SinglePassRows:
        calls.append((dataset_id, kwargs))
        return rows

    setattr(datasets_module, "load_dataset", load_dataset)
    monkeypatch.setitem(sys.modules, "datasets", datasets_module)
    options = _options(
        None,
        tmp_path / "run",
        dataset_id="corbt/enron-emails",
        dataset_revision="cfc06c758093d90993abce1a43668fb7357258a6",
        dataset_split="train",
        max_rows=1,
    )

    result = prepare_enron_source(options)
    assert isinstance(result, Mapping)
    run = _discover_run(tmp_path / "run")

    assert calls == [
        (
            "corbt/enron-emails",
            {
                "split": "train",
                "streaming": True,
                "revision": "cfc06c758093d90993abce1a43668fb7357258a6",
            },
        )
    ]
    assert rows.iterations == 1
    aggregate = json.dumps({"profile": run.profile, "manifest": run.manifest}, sort_keys=True)
    assert "corbt/enron-emails" in aggregate
    assert "cfc06c758093d90993abce1a43668fb7357258a6" in aggregate
    assert "99.1.0-fixture" in aggregate
    assert "HF-PRIVATE-BODY-MARKER" not in aggregate
    assert "hf@fixture.invalid" not in aggregate


def test_huggingface_source_rejects_mutable_revision_before_loading(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    datasets_module = ModuleType("datasets")

    def unexpected_load(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("mutable revision must fail before source loading")

    setattr(datasets_module, "load_dataset", unexpected_load)
    monkeypatch.setitem(sys.modules, "datasets", datasets_module)

    with pytest.raises(ValueError, match="immutable commit revision"):
        prepare_enron_source(_options(None, tmp_path / "run", dataset_revision="main"))
    assert not (tmp_path / "run").exists()


def test_public_provenance_labels_reject_free_form_or_identifier_bearing_values(
    tmp_path: Path, test_data_path: Path
) -> None:
    source = test_data_path / "enron_preparation.jsonl"
    for dataset_id in ("Private Person", "private.person@example.test"):
        with pytest.raises(ValueError, match="public identifier token"):
            prepare_enron_source(_options(source, tmp_path / dataset_id.replace("@", "-"), dataset_id=dataset_id))


def test_huggingface_source_rejects_empty_stream_transactionally(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    datasets_module = ModuleType("datasets")
    setattr(datasets_module, "__version__", "99.1.0-fixture")
    setattr(datasets_module, "load_dataset", lambda *_args, **_kwargs: iter(()))
    monkeypatch.setitem(sys.modules, "datasets", datasets_module)

    with pytest.raises(ValueError, match="no usable source records"):
        prepare_enron_source(
            _options(
                None,
                tmp_path / "run",
                dataset_id="corbt/enron-emails",
                dataset_revision="cfc06c758093d90993abce1a43668fb7357258a6",
                max_rows=1,
            )
        )
    assert not (tmp_path / "run").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission and symlink semantics")
def test_outputs_are_owner_only_and_source_or_output_symlinks_are_rejected(
    tmp_path: Path, test_data_path: Path
) -> None:
    source = test_data_path / "enron_preparation.jsonl"
    _, run = _prepare(source, tmp_path / "private-run")

    for path in (run.root, *run.root.rglob("*")):
        mode = path.lstat().st_mode & 0o777
        if path.is_dir():
            assert mode == 0o700, path
        elif path.is_file():
            assert mode == 0o600, path
        assert not path.is_symlink()

    source_link = tmp_path / "source-link.jsonl"
    source_link.symlink_to(source)
    with pytest.raises((OSError, ValueError), match="(?i)symlink|regular|unsafe"):
        prepare_enron_source(_options(source_link, tmp_path / "source-link-run"))

    real_output = tmp_path / "real-output"
    real_output.mkdir()
    output_link = tmp_path / "output-link"
    output_link.symlink_to(real_output, target_is_directory=True)
    with pytest.raises((OSError, ValueError), match="(?i)symlink|unsafe"):
        prepare_enron_source(_options(source, output_link / "run", allow_unignored_output=True))
    assert not any(real_output.iterdir())


@pytest.mark.skipif(os.name == "nt", reason="git path and POSIX symlink semantics")
def test_repo_visible_output_requires_ignore_or_explicit_override_without_weakening_symlink_checks(
    tmp_path: Path, test_data_path: Path
) -> None:
    source = test_data_path / "enron_preparation.jsonl"
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    (repo / ".gitignore").write_text(".nerb/\n", encoding="utf-8")
    subprocess.run(["git", "add", ".gitignore"], cwd=repo, check=True)

    with pytest.raises(ValueError, match="(?i)ignored|tracked|repository|unsafe"):
        prepare_enron_source(_options(source, repo / "visible" / "run"))

    prepare_enron_source(_options(source, repo / ".nerb" / "accepted"))
    _discover_run(repo / ".nerb" / "accepted")

    prepare_enron_source(_options(source, repo / "override" / "accepted", allow_unignored_output=True))
    _discover_run(repo / "override" / "accepted")

    real_output = repo / "override-target"
    real_output.mkdir()
    linked_output = repo / "linked-override"
    linked_output.symlink_to(real_output, target_is_directory=True)
    with pytest.raises((OSError, ValueError), match="(?i)symlink|unsafe"):
        prepare_enron_source(_options(source, linked_output / "run", allow_unignored_output=True))
    assert not any(real_output.iterdir())


@pytest.mark.skipif(os.name == "nt", reason="atomic directory promotion uses POSIX rename semantics")
def test_promotion_failure_cleans_staging_and_preserves_an_existing_valid_run(
    tmp_path: Path, test_data_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = test_data_path / "enron_preparation.jsonl"
    _, stable = _prepare(source, tmp_path / "stable")
    stable_bytes = {
        path.relative_to(stable.root): path.read_bytes() for path in stable.root.rglob("*") if path.is_file()
    }

    def fail_promotion(*_args: Any, **_kwargs: Any) -> None:
        raise OSError("injected promotion failure")

    monkeypatch.setattr(enron_preparation.PrivateRun, "commit", fail_promotion)
    failed_output = tmp_path / "failed"
    with pytest.raises(OSError, match="injected promotion failure"):
        prepare_enron_source(_options(source, failed_output))

    assert stable_bytes == {
        path.relative_to(stable.root): path.read_bytes() for path in stable.root.rglob("*") if path.is_file()
    }
    if failed_output.exists():
        assert not any(path.suffix in {".json", ".jsonl"} for path in failed_output.rglob("*"))
    assert not [path for path in tmp_path.rglob("*") if "staging" in path.name.lower() or path.name.startswith(".tmp-")]


def test_loader_verifies_artifact_hashes_and_rejects_tampering(tmp_path: Path, test_data_path: Path) -> None:
    _, run = _prepare(test_data_path / "enron_preparation.jsonl", tmp_path / "run")

    loaded = load_enron_preparation_run(tmp_path / "run")
    assert isinstance(loaded, Mapping)
    bound_hashes = {value for value in _strings(loaded) if SHA256_RE.fullmatch(value)}
    assert _sha256_file(run.records_path) in bound_hashes
    assert _sha256_file(run.profile_path) in bound_hashes

    with run.records_path.open("ab") as file:
        file.write(b" ")
    with pytest.raises((OSError, ValueError), match="(?i)hash|artifact|invalid|mismatch"):
        load_enron_preparation_run(tmp_path / "run")


def test_loader_recomputes_conservation_instead_of_trusting_rebound_aggregate(
    tmp_path: Path, test_data_path: Path
) -> None:
    _, run = _prepare(test_data_path / "enron_preparation.jsonl", tmp_path / "run")
    profile = json.loads(run.profile_path.read_text(encoding="utf-8"))
    manifest = json.loads(run.manifest_path.read_text(encoding="utf-8"))
    profile["records"]["prepared_occurrences"] = 999
    profile["records"]["rejected_records"] = -991
    manifest["preparation"]["output_occurrences"] = 999
    run.profile_path.write_text(
        json.dumps(profile, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    manifest["artifacts"]["profile"]["sha256"] = _sha256_file(run.profile_path)
    manifest["artifacts"]["profile"]["bytes"] = run.profile_path.stat().st_size
    run.manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="(?i)count|conservation|invalid"):
        load_enron_preparation_run(tmp_path / "run")


def test_loader_recomputes_duplicate_aggregates_after_full_rebinding(tmp_path: Path, test_data_path: Path) -> None:
    _, run = _prepare(test_data_path / "enron_preparation.jsonl", tmp_path / "run")
    profile = json.loads(run.profile_path.read_text(encoding="utf-8"))
    manifest = json.loads(run.manifest_path.read_text(encoding="utf-8"))
    profile["duplicates"]["duplicate_exact_content_occurrences"] += 1
    _rebind_run(run, profile, manifest)

    with pytest.raises(ValueError, match="(?i)duplicate|private records"):
        load_enron_preparation_run(run.root)


def test_loader_cross_checks_rejection_reasons_against_ingestion_counters(tmp_path: Path, test_data_path: Path) -> None:
    fixture = (test_data_path / "enron_preparation.jsonl").read_text(encoding="utf-8")
    source = tmp_path / "source.jsonl"
    source.write_text("\n" + fixture, encoding="utf-8")
    _, run = _prepare(source, tmp_path / "run")
    profile = json.loads(run.profile_path.read_text(encoding="utf-8"))
    manifest = json.loads(run.manifest_path.read_text(encoding="utf-8"))
    rejection_path = run.root / "rejections.jsonl"
    rejections = [json.loads(line) for line in rejection_path.read_text(encoding="utf-8").splitlines()]
    rejections[0]["reason"] = "tampered_reason"
    rejections.sort(key=lambda row: (row["source_digest_sha256"], row["reason"]))
    _write_jsonl(rejection_path, rejections)
    _rebind_run(run, profile, manifest)

    with pytest.raises(ValueError, match="(?i)ingestion counters|private artifacts"):
        load_enron_preparation_run(run.root)


def test_loader_rejects_fabricated_source_provenance_and_row_limits(tmp_path: Path, test_data_path: Path) -> None:
    source = test_data_path / "enron_preparation.jsonl"
    mutations = (
        ("kind", "fabricated_reader"),
        ("reader_package_version", "fabricated-package"),
        ("row_limit", 1),
    )
    for index, (field, value) in enumerate(mutations):
        _, run = _prepare(source, tmp_path / f"run-{index}")
        profile = json.loads(run.profile_path.read_text(encoding="utf-8"))
        manifest = json.loads(run.manifest_path.read_text(encoding="utf-8"))
        profile["source"][field] = value
        _rebind_run(run, profile, manifest)

        with pytest.raises(ValueError, match="(?i)source|row limit|provenance"):
            load_enron_preparation_run(run.root)


def test_loader_rejects_fabricated_nerb_version_provenance(tmp_path: Path, test_data_path: Path) -> None:
    _, run = _prepare(test_data_path / "enron_preparation.jsonl", tmp_path / "run")
    profile = json.loads(run.profile_path.read_text(encoding="utf-8"))
    manifest = json.loads(run.manifest_path.read_text(encoding="utf-8"))
    profile["software"]["nerb_version"] = "999.0.0-fabricated"
    _rebind_run(run, profile, manifest)

    with pytest.raises(ValueError, match="(?i)software|provenance"):
        load_enron_preparation_run(run.root)


def test_aggregate_privacy_validation_checks_mapping_keys() -> None:
    with pytest.raises(ValueError, match="(?i)identifier|path"):
        enron_preparation._validate_aggregate_privacy({"alice.private@example.test": 1})


def test_loader_rejects_invalid_commit_marker_and_profile_descriptor(tmp_path: Path, test_data_path: Path) -> None:
    source = test_data_path / "enron_preparation.jsonl"
    _, marker_run = _prepare(source, tmp_path / "marker-run")
    (marker_run.root / "COMMITTED").write_text("fabricated\n", encoding="utf-8")
    with pytest.raises(ValueError, match="(?i)commit marker"):
        load_enron_preparation_run(marker_run.root)

    _, descriptor_run = _prepare(source, tmp_path / "descriptor-run")
    manifest = json.loads(descriptor_run.manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"]["profile"]["id"] = "fabricated"
    _write_json(descriptor_run.manifest_path, manifest)
    with pytest.raises(ValueError, match="(?i)descriptor|artifact"):
        load_enron_preparation_run(descriptor_run.root)


def test_loader_rejects_unknown_aggregate_and_prepared_answer_fields(tmp_path: Path, test_data_path: Path) -> None:
    source = test_data_path / "enron_preparation.jsonl"
    _, profile_run = _prepare(source, tmp_path / "profile-run")
    profile = json.loads(profile_run.profile_path.read_text(encoding="utf-8"))
    manifest = json.loads(profile_run.manifest_path.read_text(encoding="utf-8"))
    profile["raw_phone"] = "+1 555 0100"
    _rebind_run(profile_run, profile, manifest)
    with pytest.raises(ValueError, match="(?i)schema|closed"):
        load_enron_preparation_run(profile_run.root)

    _, manifest_run = _prepare(source, tmp_path / "manifest-run")
    manifest = json.loads(manifest_run.manifest_path.read_text(encoding="utf-8"))
    manifest["raw_name"] = "Private Person"
    _write_json(manifest_run.manifest_path, manifest)
    with pytest.raises(ValueError, match="(?i)schema|closed"):
        load_enron_preparation_run(manifest_run.root)

    _, prepared_run = _prepare(source, tmp_path / "prepared-run")
    profile = json.loads(prepared_run.profile_path.read_text(encoding="utf-8"))
    manifest = json.loads(prepared_run.manifest_path.read_text(encoding="utf-8"))
    records = [dict(row) for row in prepared_run.records]
    records[0]["views"]["synthetic_address_inventory"] = "private.person@example.test"
    _write_jsonl(prepared_run.records_path, records)
    _rebind_run(prepared_run, profile, manifest)
    with pytest.raises(ValueError, match="(?i)headers|views|schema"):
        load_enron_preparation_run(prepared_run.root)


def test_loader_rejects_unknown_transform_counter_keys_even_when_aggregates_match(
    tmp_path: Path, test_data_path: Path
) -> None:
    _, run = _prepare(test_data_path / "enron_preparation.jsonl", tmp_path / "run")
    profile = json.loads(run.profile_path.read_text(encoding="utf-8"))
    manifest = json.loads(run.manifest_path.read_text(encoding="utf-8"))
    records = [dict(row) for row in run.records]
    records[0]["cleaning"]["transform_counts"]["alice_example_test"] = 1
    occurrences = records[0]["source"]["identical_occurrence_count"]
    profile["cleaning"]["alice_example_test"] = occurrences
    _write_jsonl(run.records_path, records)
    _rebind_run(run, profile, manifest)

    with pytest.raises(ValueError, match="(?i)counter name|cleaning"):
        load_enron_preparation_run(run.root)


def test_loader_binds_view_truncation_metadata_to_cleaning_audit(tmp_path: Path, test_data_path: Path) -> None:
    _, run = _prepare(
        test_data_path / "enron_preparation.jsonl",
        tmp_path / "run",
        max_body_chars=32,
        max_body_bytes=128,
        max_subject_chars=16,
        max_subject_bytes=64,
    )
    profile = json.loads(run.profile_path.read_text(encoding="utf-8"))
    manifest = json.loads(run.manifest_path.read_text(encoding="utf-8"))
    records = [dict(row) for row in run.records]
    record = next(row for row in records if row["cleaning"]["body_truncated"])
    record["view_metadata"]["current_body"]["truncated"] = False
    _write_jsonl(run.records_path, records)
    _rebind_run(run, profile, manifest)

    with pytest.raises(ValueError, match="(?i)view metadata|truncat"):
        load_enron_preparation_run(run.root)


def test_blank_lines_are_explicit_rejected_source_occurrences(tmp_path: Path) -> None:
    row = {
        "message_id": "<valid@fixture.invalid>",
        "subject": "Valid",
        "from": "valid@fixture.invalid",
        "to": [],
        "cc": [],
        "bcc": [],
        "date": "2001-01-01T00:00:00Z",
        "body": "Visible",
        "file_name": "fixture/valid",
    }
    source = tmp_path / "source.jsonl"
    source.write_text("\n" + json.dumps(row) + "\n", encoding="utf-8")

    _, run = _prepare(source, tmp_path / "run")

    assert run.profile["records"]["input_records"] == 2
    assert run.profile["records"]["rejected_records"] == 1
    assert run.profile["records"]["ingestion_errors"]["blank_line"] == 1
    assert load_enron_preparation_run(run.root)["valid"] is True


def test_malformed_rfc2047_headers_fall_back_without_aborting_preparation(tmp_path: Path) -> None:
    row = {
        "message_id": "<valid@fixture.invalid>",
        "subject": "=?utf-8?b?A?=",
        "from": "=?utf-8?b?A?= <alice.private@example.test>",
        "to": [],
        "cc": [],
        "bcc": [],
        "date": "2001-01-01T00:00:00Z",
        "body": "Visible body",
        "file_name": "fixture/valid",
    }
    source = _write_jsonl(tmp_path / "source.jsonl", [row])

    _, run = _prepare(source, tmp_path / "run")

    assert run.records[0]["headers"]["subject"] == "=?utf-8?b?A?="
    assert run.profile["cleaning"]["header_decode_errors"] >= 1
    assert load_enron_preparation_run(run.root)["valid"] is True


def test_date_policy_boundaries_and_ambiguous_timezone_are_frozen() -> None:
    assert enron_preparation._parse_date("1990-01-01T00:00:00Z")["status"] == "valid"
    assert enron_preparation._parse_date("2010-12-31T23:59:59Z")["status"] == "valid"
    assert enron_preparation._parse_date("1989-12-31T23:59:59Z")["status"] == "out_of_range"
    assert enron_preparation._parse_date("2011-01-01T00:00:00Z")["status"] == "out_of_range"
    assert enron_preparation._parse_date("2001-01-01 00:00:00")["status"] == "ambiguous_timezone"


def test_empty_grouping_core_uses_declared_current_body_near_duplicate_fallback(tmp_path: Path) -> None:
    row = {
        "message_id": "<mobile@fixture.invalid>",
        "subject": "",
        "from": "mobile@fixture.invalid",
        "to": [],
        "cc": [],
        "bcc": [],
        "date": "2001-01-01T00:00:00Z",
        "body": "Sent from my iPhone.",
        "file_name": "fixture/mobile",
    }
    source = _write_jsonl(tmp_path / "source.jsonl", [row])

    _, run = _prepare(source, tmp_path / "run")
    record = run.records[0]

    assert record["views"]["current_body_core"] == ""
    assert record["views"]["current_body"] == "Sent from my iPhone."
    assert record["grouping"]["near_duplicate"]["current_body_core"]["simhash64"] is not None


def test_equal_near_duplicate_views_reuse_one_feature_computation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    row = {
        "message_id": "<plain@fixture.invalid>",
        "subject": "Plain",
        "from": "plain@fixture.invalid",
        "to": [],
        "cc": [],
        "bcc": [],
        "date": "2001-01-01T00:00:00Z",
        "body": "Three plain tokens remain equal.",
        "file_name": "owner/inbox/1",
    }
    source = _write_jsonl(tmp_path / "source.jsonl", [row])
    real_features = enron_preparation._near_duplicate_features
    calls: list[str] = []

    def recording_features(text: str) -> dict[str, Any]:
        calls.append(text)
        return real_features(text)

    monkeypatch.setattr(enron_preparation, "_near_duplicate_features", recording_features)
    _, run = _prepare(source, tmp_path / "run")

    assert calls == ["Three plain tokens remain equal."]
    near = run.records[0]["grouping"]["near_duplicate"]
    assert near["current_body_core"] == near["full_visible_body"]


def test_bit_sliced_simhash_majority_matches_naive_tie_semantics() -> None:
    values = {0, 1, 2, 3, 0x0123456789ABCDEF, 0xFEDCBA9876543210}
    expected = 0
    for bit in range(64):
        ones = sum(bool(value & (1 << bit)) for value in values)
        if ones * 2 >= len(values):
            expected |= 1 << bit

    assert enron_preparation._simhash64_majority(values) == expected

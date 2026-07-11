from __future__ import annotations

import hashlib
import json
import os
import stat
import warnings
import zipfile
from collections.abc import Mapping, Sequence
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest

import nerb.enron_annotations as enron_annotations
from nerb.enron_annotations import (  # noqa: PLC2701
    ARCHIVE_FILENAME,
    CMU_AUXILIARY_NONPROMOTABLE_REASON,
    CMU_ENRON_MEETINGS_ARCHIVE_BYTES,
    CMU_ENRON_MEETINGS_POPULATIONS,
    CMU_ENRON_MEETINGS_SHA256,
    CMU_ENRON_MEETINGS_URL,
    DOCUMENTS_FILENAME,
    LABELS_FILENAME,
    MANIFEST_FILENAME,
    RECEIPT_FILENAME,
    EnronAnnotationError,
    EnronAnnotationIngestOptions,
    _canonical_line,
    _descriptor_from_bytes,
    _pretty_json_bytes,
    _receipt_payload,
    download_cmu_enron_annotations,
    ingest_cmu_enron_annotations,
    load_cmu_enron_training_quality_source,
    parse_cmu_annotation_fragment,
    verify_cmu_enron_annotations,
)
from nerb.enron_quality import evaluate_cmu_enron_training_quality

_ROOT = "EnronMeetings-XML"
_TRAIN_ONE = f"{_ROOT}/train/bunch1/fixture-alpha__calendar__1.txt"
_TRAIN_TWO = f"{_ROOT}/train/bunch2/fixture-beta__calendar__2.txt"
_TEST_ONE = f"{_ROOT}/test/bunch4/fixture-gamma__calendar__3.txt"


class _DownloadResponse:
    def __init__(self, payload: bytes, *, final_url: str = CMU_ENRON_MEETINGS_URL) -> None:
        self._source = BytesIO(payload)
        self._final_url = final_url
        self.headers = {"Content-Length": str(len(payload)), "Content-Encoding": "identity"}

    def __enter__(self) -> _DownloadResponse:
        return self

    def __exit__(self, *_args: Any) -> None:
        return None

    def geturl(self) -> str:
        return self._final_url

    def read(self, size: int) -> bytes:
        return self._source.read(size)


def _members() -> list[tuple[str, bytes]]:
    return [
        (
            _TRAIN_ONE,
            b"Agenda <not_markup> & <desk@example.invalid>\n<true_name> Alpha Persona </true_name> confirmed.",
        ),
        (_TRAIN_TWO, b"A complete negative document with A < B and no annotation."),
        (
            _TEST_ONE,
            "Prefix 😀 <true_name> Beta\n Persona \t</true_name> suffix <opaque>.".encode(),
        ),
    ]


def _write_archive(
    path: Path,
    members: Sequence[tuple[str | zipfile.ZipInfo, bytes]],
    *,
    compression: int = zipfile.ZIP_DEFLATED,
) -> Path:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(path, "w", compression=compression) as archive:
            for name, payload in members:
                archive.writestr(name, payload)
    return path


def _expected_populations(members: Sequence[tuple[str | zipfile.ZipInfo, bytes]]) -> dict[str, dict[str, int]]:
    result = {"train": {"documents": 0, "spans": 0}, "test": {"documents": 0, "spans": 0}}
    for raw_name, payload in members:
        name = raw_name.filename if isinstance(raw_name, zipfile.ZipInfo) else raw_name
        role = name.split("/")[1]
        if role not in result:
            continue
        parsed = parse_cmu_annotation_fragment(payload)
        result[role]["documents"] += 1
        result[role]["spans"] += len(parsed.spans)
    return result


def _fixture_options(
    archive: Path,
    output: Path,
    *,
    expected: Mapping[str, Mapping[str, int]] | None = None,
) -> EnronAnnotationIngestOptions:
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    return EnronAnnotationIngestOptions(
        archive_path=archive,
        output_dir=output,
        fixture_mode=True,
        fixture_expected_sha256=digest,
        fixture_expected_populations=expected or _expected_populations(_members()),
    )


def _ingest_fixture(
    tmp_path: Path,
    *,
    members: Sequence[tuple[str | zipfile.ZipInfo, bytes]] | None = None,
    name: str = "fixture",
) -> tuple[Path, Path, dict[str, Any]]:
    selected = list(members or _members())
    archive = _write_archive(tmp_path / f"{name}.zip", selected)
    output = tmp_path / f"{name}-run"
    result = ingest_cmu_enron_annotations(_fixture_options(archive, output, expected=_expected_populations(selected)))
    return archive, output, result


def _jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _private_mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_pinned_production_constants_are_exact() -> None:
    assert CMU_ENRON_MEETINGS_SHA256 == "e7d8dbd9e066eddd6d706a041e379ca93daf9e441a73009646ead41e94a60202"
    assert CMU_ENRON_MEETINGS_ARCHIVE_BYTES == 568_012
    assert CMU_ENRON_MEETINGS_POPULATIONS == {
        "train": {"documents": 729, "spans": 1_896},
        "test": {"documents": 247, "spans": 527},
    }
    assert CMU_AUXILIARY_NONPROMOTABLE_REASON == "auxiliary_source_without_bound_content_adjudication"


def test_downloader_fetches_only_the_pinned_source_and_commits_it_privately(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    payload = b"synthetic pinned archive bytes"
    monkeypatch.setattr(enron_annotations, "CMU_ENRON_MEETINGS_ARCHIVE_BYTES", len(payload))
    monkeypatch.setattr(enron_annotations, "CMU_ENRON_MEETINGS_SHA256", hashlib.sha256(payload).hexdigest())
    observed = {}

    def fake_download(request: Any, *, timeout: float) -> _DownloadResponse:
        observed["url"] = request.full_url
        observed["accept_encoding"] = request.get_header("Accept-encoding")
        observed["timeout"] = timeout
        return _DownloadResponse(payload)

    monkeypatch.setattr(enron_annotations, "_open_pinned_annotation_download", fake_download)
    output = tmp_path / "source-run"
    receipt = download_cmu_enron_annotations(output, timeout_seconds=12.5, allow_unignored_output=True)

    assert observed == {"url": CMU_ENRON_MEETINGS_URL, "accept_encoding": "identity", "timeout": 12.5}
    assert receipt["verified"] is True
    assert receipt["artifact"] == {
        "name": ARCHIVE_FILENAME,
        "bytes": len(payload),
        "sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
    }
    assert (output / ARCHIVE_FILENAME).read_bytes() == payload
    assert json.loads((output / RECEIPT_FILENAME).read_text(encoding="utf-8")) == receipt
    assert (output / "COMMITTED").is_file()
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert stat.S_IMODE((output / ARCHIVE_FILENAME).stat().st_mode) == 0o600
    assert payload.decode() not in json.dumps(receipt)


@pytest.mark.parametrize(
    ("payload", "final_url", "expected_message"),
    [
        (b"expacted", CMU_ENRON_MEETINGS_URL, "hash verification"),
        (b"expected", "https://example.invalid/EnronMeetings-XML.zip", "identity"),
    ],
)
def test_downloader_rejects_unpinned_or_redirected_content_without_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    payload: bytes,
    final_url: str,
    expected_message: str,
) -> None:
    expected = b"expected"
    monkeypatch.setattr(enron_annotations, "CMU_ENRON_MEETINGS_ARCHIVE_BYTES", len(expected))
    monkeypatch.setattr(enron_annotations, "CMU_ENRON_MEETINGS_SHA256", hashlib.sha256(expected).hexdigest())
    monkeypatch.setattr(
        enron_annotations,
        "_open_pinned_annotation_download",
        lambda *_args, **_kwargs: _DownloadResponse(payload, final_url=final_url),
    )
    output = tmp_path / "source-run"

    with pytest.raises(EnronAnnotationError, match=expected_message):
        download_cmu_enron_annotations(output, allow_unignored_output=True)

    assert not output.exists()


def test_literal_marker_parser_preserves_nonmarker_text_and_uses_scalar_offsets() -> None:
    prefix = "😀 Prefix <desk@example.invalid> & A < B; the words true name remain text.\n"
    payload = " Alpha\n Persona \t"
    suffix = " suffix <opaque>."

    parsed = parse_cmu_annotation_fragment((prefix + "<true_name>" + payload + "</true_name>" + suffix).encode())

    assert parsed.text == prefix + payload + suffix
    assert len(parsed.spans) == 1
    span = parsed.spans[0]
    assert (span.start, span.end) == (len(prefix) + 1, len(prefix) + len(payload.rstrip()))
    assert parsed.text[span.start : span.end] == "Alpha\n Persona"
    assert parsed.text.encode().find(b"Alpha") != span.start
    assert "<desk@example.invalid>" in parsed.text
    assert "<opaque>" in parsed.text


@pytest.mark.parametrize(
    "raw",
    [
        b"orphan </true_name>",
        b"<true_name> missing close",
        b"<true_name> outer <true_name> inner </true_name>",
        b"<true_name> \t\n </true_name>",
        b"<TRUE_NAME> Alpha </TRUE_NAME>",
        b"< true_name > Alpha </ true_name >",
        b"<" + b"x" * 70 + b" true_name " + b"y" * 70 + b">Secret Person</long_variant>",
        b"\xff",
    ],
)
def test_literal_marker_parser_fails_closed_on_malformed_input(raw: bytes) -> None:
    with pytest.raises(EnronAnnotationError, match="Annotation fragment") as caught:
        parse_cmu_annotation_fragment(raw)

    assert "Alpha" not in str(caught.value)
    assert "Secret Person" not in str(caught.value)


def test_fixture_ingest_separates_text_and_labels_and_returns_only_aggregates(tmp_path: Path) -> None:
    _archive, output, result = _ingest_fixture(tmp_path)

    assert result["verified"] is True
    assert result["promotable"] is False
    assert result["nonpromotable_reason"] == "synthetic_fixture_override"
    assert result["source"]["fixture_mode"] is True
    assert result["source"]["url"] is None
    assert result["populations"]["train"] == {
        "documents": 2,
        "positive_documents": 1,
        "negative_documents": 1,
        "spans": 1,
        "text_scalars": 129,
        "gold_scalars": 13,
    }
    assert result["populations"]["test"]["documents"] == 1
    assert result["populations"]["test"]["spans"] == 1

    documents = _jsonl(output / DOCUMENTS_FILENAME)
    labels = _jsonl(output / LABELS_FILENAME)
    assert len(documents) == len(labels) == 3
    assert [row["document_id"] for row in documents] == sorted(row["document_id"] for row in documents)
    assert [row["document_id"] for row in labels] == [row["document_id"] for row in documents]
    assert {row["role"] for row in documents} == {"train", "test"}
    assert any("Alpha Persona" in row["text"] for row in documents)
    assert "Alpha Persona" not in (output / LABELS_FILENAME).read_text(encoding="utf-8")
    assert "Alpha Persona" not in json.dumps(result)
    assert "Alpha Persona" not in (output / MANIFEST_FILENAME).read_text(encoding="utf-8")
    assert "Alpha Persona" not in (output / RECEIPT_FILENAME).read_text(encoding="utf-8")
    assert all(
        set(row) == {"annotation_completeness", "document_id", "entity_class", "label_strength", "role", "spans"}
        for row in labels
    )
    assert any(not row["spans"] for row in labels)
    assert verify_cmu_enron_annotations(output) == result

    assert _private_mode(output) == 0o700
    for name in ("COMMITTED", DOCUMENTS_FILENAME, LABELS_FILENAME, MANIFEST_FILENAME, RECEIPT_FILENAME):
        assert _private_mode(output / name) == 0o600


def test_verified_training_loader_binds_private_rows_to_quality_descriptors(tmp_path: Path) -> None:
    _archive, output, receipt = _ingest_fixture(tmp_path)

    source = load_cmu_enron_training_quality_source(output)

    assert len(source["documents"]) == receipt["populations"]["train"]["documents"]
    assert len(source["labels"]) == receipt["populations"]["train"]["spans"]
    assert all(document["split_role"] == "train" for document in source["documents"])
    assert all(document["text_view"] == "cmu_published_document" for document in source["documents"])
    assert source["annotation_scope"]["span_policy_sha256"] == receipt["span_policy_sha256"]
    assert source["text_view_descriptor"]["artifact_sha256"] == receipt["artifacts"]["documents"]["sha256"]
    assert source["public_binding"]["labels_sha256"] == receipt["artifacts"]["person_labels"]["sha256"]
    assert source["public_binding"]["promotable"] is False


def test_verified_training_loader_rechecks_the_exact_bytes_after_verification(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _archive, output, _receipt = _ingest_fixture(tmp_path)
    original_verify = enron_annotations.verify_cmu_enron_annotations

    def verify_then_change_documents(run_dir: Path) -> dict[str, Any]:
        receipt = original_verify(run_dir)
        rows = _jsonl(output / DOCUMENTS_FILENAME)
        rows[0]["text"] += " PRIVATE-RACE-SENTINEL"
        rows[0]["text_sha256"] = "sha256:" + hashlib.sha256(rows[0]["text"].encode()).hexdigest()
        (output / DOCUMENTS_FILENAME).write_bytes(b"".join(_canonical_line(row) for row in rows))
        return receipt

    monkeypatch.setattr(enron_annotations, "verify_cmu_enron_annotations", verify_then_change_documents)
    with pytest.raises(EnronAnnotationError, match="artifact binding") as caught:
        load_cmu_enron_training_quality_source(output)

    assert "PRIVATE-RACE-SENTINEL" not in str(caught.value)


def test_verified_training_bundle_executes_quality_without_manual_text_projection(
    tmp_path: Path, test_data_path: Path
) -> None:
    _archive, output, receipt = _ingest_fixture(tmp_path)
    source = load_cmu_enron_training_quality_source(output)
    bindings = [
        {
            "document_id": label["document_id"],
            "start": label["start"],
            "end": label["end"],
            "catalog_identity": None,
        }
        for label in source["labels"]
    ]
    bank = json.loads((test_data_path / "minimal_bank.json").read_text(encoding="utf-8"))

    result = evaluate_cmu_enron_training_quality(
        bank,
        annotation_run_dir=output,
        catalog_bindings=bindings,
    )

    assert result["annotation_source"]["source_sha256"] == receipt["source"]["archive_sha256"]
    assert result["quality"]["slices"][0]["gold_spans"] == receipt["populations"]["train"]["spans"]
    assert result["quality"]["slices"][0]["false_negative"] == receipt["populations"]["train"]["spans"]
    assert "Alpha Persona" not in json.dumps(result)


def test_fixture_outputs_are_deterministic_across_zip_entry_order(tmp_path: Path) -> None:
    members = _members()
    _archive_a, output_a, result_a = _ingest_fixture(tmp_path, members=members, name="ordered")
    _archive_b, output_b, result_b = _ingest_fixture(tmp_path, members=list(reversed(members)), name="reversed")

    assert (output_a / DOCUMENTS_FILENAME).read_bytes() == (output_b / DOCUMENTS_FILENAME).read_bytes()
    assert (output_a / LABELS_FILENAME).read_bytes() == (output_b / LABELS_FILENAME).read_bytes()
    assert result_a["artifacts"]["documents"] == result_b["artifacts"]["documents"]
    assert result_a["artifacts"]["person_labels"] == result_b["artifacts"]["person_labels"]
    assert result_a["source"]["archive_sha256"] != result_b["source"]["archive_sha256"]


def test_production_mode_rejects_an_unpinned_fixture_without_output(tmp_path: Path) -> None:
    archive = _write_archive(tmp_path / "fixture.zip", _members())
    output = tmp_path / "run"

    with pytest.raises(EnronAnnotationError, match="archive verification"):
        ingest_cmu_enron_annotations(EnronAnnotationIngestOptions(archive_path=archive, output_dir=output))

    assert not output.exists()


@pytest.mark.parametrize(
    ("fixture_hash", "fixture_populations"),
    [
        (None, None),
        ("0" * 64, None),
        (None, {"train": {"documents": 1, "spans": 1}, "test": {"documents": 1, "spans": 1}}),
    ],
)
def test_fixture_mode_requires_both_explicit_gates(
    tmp_path: Path,
    fixture_hash: str | None,
    fixture_populations: Mapping[str, Mapping[str, int]] | None,
) -> None:
    archive = _write_archive(tmp_path / "fixture.zip", _members())
    with pytest.raises(EnronAnnotationError, match="requires explicit hash and population"):
        ingest_cmu_enron_annotations(
            EnronAnnotationIngestOptions(
                archive_path=archive,
                output_dir=tmp_path / "run",
                fixture_mode=True,
                fixture_expected_sha256=fixture_hash,
                fixture_expected_populations=fixture_populations,
            )
        )


def test_hash_and_population_failures_are_atomic_and_privacy_safe(tmp_path: Path) -> None:
    members = _members()
    archive = _write_archive(tmp_path / "secret.zip", members)

    wrong_hash_output = tmp_path / "wrong-hash"
    with pytest.raises(EnronAnnotationError, match="archive verification") as hash_error:
        ingest_cmu_enron_annotations(
            EnronAnnotationIngestOptions(
                archive_path=archive,
                output_dir=wrong_hash_output,
                fixture_mode=True,
                fixture_expected_sha256="0" * 64,
                fixture_expected_populations=_expected_populations(members),
            )
        )
    assert "Alpha Persona" not in str(hash_error.value)
    assert not wrong_hash_output.exists()

    wrong_count_output = tmp_path / "wrong-count"
    wrong_counts = _expected_populations(members)
    wrong_counts["test"]["spans"] += 1
    with pytest.raises(EnronAnnotationError, match="population verification") as population_error:
        ingest_cmu_enron_annotations(_fixture_options(archive, wrong_count_output, expected=wrong_counts))
    assert "Alpha Persona" not in str(population_error.value)
    assert not wrong_count_output.exists()
    assert not list(tmp_path.glob(".wrong-*.stage-*"))


def test_malformed_private_fragment_leaves_no_partial_output_or_secret_in_error(tmp_path: Path) -> None:
    members = _members()
    members[0] = (_TRAIN_ONE, b"TOP-SECRET <true_name> missing-close")
    archive = _write_archive(tmp_path / "malformed.zip", members)
    output = tmp_path / "run"
    expected = {"train": {"documents": 2, "spans": 1}, "test": {"documents": 1, "spans": 1}}

    with pytest.raises(EnronAnnotationError) as caught:
        ingest_cmu_enron_annotations(_fixture_options(archive, output, expected=expected))

    assert "TOP-SECRET" not in str(caught.value)
    assert not output.exists()
    assert not list(tmp_path.glob(".run.stage-*"))


def _symlink_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name)
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    return info


@pytest.mark.parametrize(
    "mutation",
    [
        "traversal",
        "wrong_bunch",
        "symlink",
        "case_collision",
        "duplicate",
        "oversized",
        "compression_ratio",
    ],
)
def test_archive_inventory_and_resource_limits_fail_closed(tmp_path: Path, mutation: str) -> None:
    members: list[tuple[str | zipfile.ZipInfo, bytes]] = list(_members())
    if mutation == "traversal":
        members.append((f"{_ROOT}/train/bunch1/../escape.txt", b"private"))
    elif mutation == "wrong_bunch":
        members.append((f"{_ROOT}/test/bunch1/fixture__calendar__9.txt", b"private"))
    elif mutation == "symlink":
        members.append((_symlink_info(f"{_ROOT}/train/bunch1/link__calendar__9.txt"), b"target"))
    elif mutation == "case_collision":
        members.extend(
            [
                (f"{_ROOT}/train/bunch1/Collision__calendar__9.txt", b"private"),
                (f"{_ROOT}/train/bunch1/collision__calendar__9.txt", b"private"),
            ]
        )
    elif mutation == "duplicate":
        members.append((_TRAIN_ONE, b"different private payload"))
    elif mutation == "oversized":
        members.append((f"{_ROOT}/train/bunch1/large__calendar__9.txt", b"x" * (1024 * 1024 + 1)))
    elif mutation == "compression_ratio":
        members.append((f"{_ROOT}/train/bunch1/ratio__calendar__9.txt", b"x" * 200_000))
    archive = _write_archive(tmp_path / f"{mutation}.zip", members)
    output = tmp_path / f"{mutation}-run"

    with pytest.raises(EnronAnnotationError, match="archive") as caught:
        ingest_cmu_enron_annotations(
            _fixture_options(
                archive,
                output,
                expected={"train": {"documents": 2, "spans": 1}, "test": {"documents": 1, "spans": 1}},
            )
        )

    assert "private" not in str(caught.value).casefold()
    assert not output.exists()


def test_verifier_rejects_artifact_tampering_without_echoing_text(tmp_path: Path) -> None:
    _archive, output, _result = _ingest_fixture(tmp_path)
    documents = _jsonl(output / DOCUMENTS_FILENAME)
    documents[0]["text"] = "DO-NOT-ECHO"
    (output / DOCUMENTS_FILENAME).write_bytes(b"".join(_canonical_line(row) for row in documents))
    os.chmod(output / DOCUMENTS_FILENAME, 0o600)

    with pytest.raises(EnronAnnotationError) as caught:
        verify_cmu_enron_annotations(output)

    assert "DO-NOT-ECHO" not in str(caught.value)


def test_verifier_rejects_out_of_bounds_span_even_when_descriptor_is_rebound(tmp_path: Path) -> None:
    _archive, output, _result = _ingest_fixture(tmp_path)
    labels = _jsonl(output / LABELS_FILENAME)
    target = next(row for row in labels if row["spans"])
    target["spans"][0]["end"] = 10**6
    label_bytes = b"".join(_canonical_line(row) for row in labels)
    (output / LABELS_FILENAME).write_bytes(label_bytes)
    os.chmod(output / LABELS_FILENAME, 0o600)

    manifest = json.loads((output / MANIFEST_FILENAME).read_text(encoding="utf-8"))
    manifest["artifacts"]["person_labels"] = _descriptor_from_bytes(
        label_bytes,
        artifact_id="cmu_enron_meetings_person_labels",
        name=LABELS_FILENAME,
        records=len(labels),
    )
    manifest_bytes = _pretty_json_bytes(manifest)
    (output / MANIFEST_FILENAME).write_bytes(manifest_bytes)
    os.chmod(output / MANIFEST_FILENAME, 0o600)
    manifest_descriptor = _descriptor_from_bytes(
        manifest_bytes,
        artifact_id="cmu_enron_meetings_manifest",
        name=MANIFEST_FILENAME,
        records=1,
    )
    receipt = _receipt_payload(manifest, manifest_descriptor)
    (output / RECEIPT_FILENAME).write_bytes(_pretty_json_bytes(receipt))
    os.chmod(output / RECEIPT_FILENAME, 0o600)

    with pytest.raises(EnronAnnotationError, match="span is invalid"):
        verify_cmu_enron_annotations(output)


@pytest.mark.parametrize("mutation", ["missing_commit", "extra_file", "public_permissions", "stale_implementation"])
def test_verifier_fails_closed_on_bundle_state_and_provenance_mutations(tmp_path: Path, mutation: str) -> None:
    _archive, output, _result = _ingest_fixture(tmp_path, name=mutation)
    if mutation == "missing_commit":
        (output / "COMMITTED").unlink()
    elif mutation == "extra_file":
        (output / "unexpected.txt").write_text("private", encoding="utf-8")
        os.chmod(output / "unexpected.txt", 0o600)
    elif mutation == "public_permissions":
        os.chmod(output / LABELS_FILENAME, 0o644)
    else:
        manifest = json.loads((output / MANIFEST_FILENAME).read_text(encoding="utf-8"))
        manifest["software"]["implementation_sha256"] = "sha256:" + "0" * 64
        (output / MANIFEST_FILENAME).write_bytes(_pretty_json_bytes(manifest))
        os.chmod(output / MANIFEST_FILENAME, 0o600)

    with pytest.raises(EnronAnnotationError):
        verify_cmu_enron_annotations(output)


def test_verifier_rejects_noncanonical_json_and_unknown_fields(tmp_path: Path) -> None:
    _archive, output, _result = _ingest_fixture(tmp_path)
    manifest = json.loads((output / MANIFEST_FILENAME).read_text(encoding="utf-8"))
    manifest["private_member_path"] = "mailbox-owner/calendar/1"
    (output / MANIFEST_FILENAME).write_text(json.dumps(manifest), encoding="utf-8")
    os.chmod(output / MANIFEST_FILENAME, 0o600)

    with pytest.raises(EnronAnnotationError):
        verify_cmu_enron_annotations(output)

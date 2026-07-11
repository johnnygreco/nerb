"""Private ingestion for the independently annotated CMU Enron Meetings corpus.

The published ``XML`` release is a ZIP of plain-text fragments with literal
``<true_name>`` markers.  The fragments are intentionally not parsed as XML:
unrelated angle-bracket text is part of the evaluated document and must remain
byte-for-byte intact after the two annotation markers are removed.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import platform
import re
import stat
import unicodedata
import urllib.error
import urllib.request
import zipfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO
from urllib.parse import urlsplit

from . import __version__
from .enron_private_io import EnronPrivateIOError, PrivateRun, open_private_binary_input

CMU_ENRON_MEETINGS_URL = "https://www.cs.cmu.edu/~einat/EnronMeetings-XML.zip"
CMU_ENRON_MEETINGS_SHA256 = "e7d8dbd9e066eddd6d706a041e379ca93daf9e441a73009646ead41e94a60202"
CMU_ENRON_MEETINGS_ARCHIVE_BYTES = 568_012
CMU_ENRON_MEETINGS_POPULATIONS: Mapping[str, Mapping[str, int]] = {
    "train": {"documents": 729, "spans": 1_896},
    "test": {"documents": 247, "spans": 527},
}
CMU_AUXILIARY_NONPROMOTABLE_REASON = "auxiliary_source_without_bound_content_adjudication"
_PRODUCTION_POPULATION_SUMMARY: Mapping[str, Mapping[str, int]] = {
    "train": {
        "documents": 729,
        "positive_documents": 540,
        "negative_documents": 189,
        "spans": 1_896,
        "text_scalars": 529_788,
        "gold_scalars": 20_028,
    },
    "test": {
        "documents": 247,
        "positive_documents": 197,
        "negative_documents": 50,
        "spans": 527,
        "text_scalars": 119_169,
        "gold_scalars": 4_978,
    },
}

ANNOTATION_RUN_SCHEMA_VERSION = "nerb.enron_cmu_annotations.v1"
ANNOTATION_RECEIPT_SCHEMA_VERSION = "nerb.enron_cmu_annotation_receipt.v1"
ANNOTATION_SOURCE_RECEIPT_SCHEMA_VERSION = "nerb.enron_cmu_annotation_source_receipt.v1"
ARCHIVE_FILENAME = "EnronMeetings-XML.zip"
DOCUMENTS_FILENAME = "documents.jsonl"
LABELS_FILENAME = "person_labels.jsonl"
MANIFEST_FILENAME = "manifest.json"
RECEIPT_FILENAME = "receipt.json"

_OPEN_MARKER = "<true_name>"
_CLOSE_MARKER = "</true_name>"
_ASCII_WHITESPACE = " \t\r\n\f\v"
_SHA256_RE = re.compile(r"^(?:sha256:)?[0-9a-f]{64}$")
_SHA256_REF_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_DOCUMENT_ID_RE = re.compile(r"^cmu-document:sha256:[0-9a-f]{64}$")
_MEMBER_RE = re.compile(
    r"^EnronMeetings-XML/(?P<role>train|test)/(?P<bunch>bunch[1-4])/"
    r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}__calendar__[0-9]{1,10}\.txt$"
)
_ANGLE_CONSTRUCT_RE = re.compile(r"<[^<>]*>")
_TRUE_NAME_TOKEN_RE = re.compile(r"\btrue[\s_-]*name\b", re.IGNORECASE)
_ALLOWED_DIRECTORIES = frozenset(
    {
        "EnronMeetings-XML/",
        "EnronMeetings-XML/train/",
        "EnronMeetings-XML/train/bunch1/",
        "EnronMeetings-XML/train/bunch2/",
        "EnronMeetings-XML/train/bunch3/",
        "EnronMeetings-XML/test/",
        "EnronMeetings-XML/test/bunch4/",
    }
)
_EXPECTED_BUNCH_DOCUMENTS = {
    ("train", "bunch1"): 244,
    ("train", "bunch2"): 242,
    ("train", "bunch3"): 243,
    ("test", "bunch4"): 247,
}
_EXPECTED_FILES = frozenset({"COMMITTED", DOCUMENTS_FILENAME, LABELS_FILENAME, MANIFEST_FILENAME, RECEIPT_FILENAME})
_EXPECTED_STAGED_FILES = _EXPECTED_FILES - {"COMMITTED"}
_MAX_ARCHIVE_BYTES = 2 * 1024 * 1024
_MAX_ARCHIVE_ENTRIES = 4_096
_MAX_MEMBER_BYTES = 1024 * 1024
_MAX_UNCOMPRESSED_BYTES = 16 * 1024 * 1024
_MAX_COMPRESSION_RATIO = 200
_MAX_BUNDLE_FILE_BYTES = 64 * 1024 * 1024
_MAX_JSONL_LINE_BYTES = 2 * 1024 * 1024
_COMMIT_PAYLOAD = b"nerb.enron.private-run.v2\n"
_DOWNLOAD_CHUNK_BYTES = 64 * 1024
_MAX_DOWNLOAD_TIMEOUT_SECONDS = 300.0

_SPAN_POLICY = {
    "id": "cmu-enron-meetings-inline-true-name",
    "version": "1",
    "encoding": "utf-8-strict",
    "markers": {"open": _OPEN_MARKER, "close": _CLOSE_MARKER, "matching": "exact-literal"},
    "text_projection": "remove-only-the-two-exact-marker-tokens",
    "span_projection": "maximal-inner-interval-after-outer-ascii-whitespace-trim",
    "offset_unit": "unicode_scalar",
    "interval": "half_open",
    "normalization": "none",
    "entity_class": "person",
}
SPAN_POLICY_SHA256 = (
    "sha256:"
    + hashlib.sha256(
        json.dumps(_SPAN_POLICY, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
)


class EnronAnnotationError(RuntimeError):
    """Raised when annotations cannot be ingested or verified safely."""


@dataclass(frozen=True)
class AnnotationSpan:
    """A half-open Unicode-scalar span in marker-free text."""

    start: int
    end: int


@dataclass(frozen=True)
class ParsedAnnotationDocument:
    """The exact marker-free document and independently annotated spans."""

    text: str
    spans: tuple[AnnotationSpan, ...]


@dataclass(frozen=True)
class EnronAnnotationIngestOptions:
    """Options for a pinned production ingest or an explicit synthetic fixture."""

    archive_path: Path
    output_dir: Path
    fixture_mode: bool = False
    fixture_expected_sha256: str | None = None
    fixture_expected_populations: Mapping[str, Mapping[str, int]] | None = None
    allow_unignored_output: bool = False


@dataclass(frozen=True)
class _Expectation:
    fixture_mode: bool
    archive_sha256: str
    archive_bytes: int | None
    populations: Mapping[str, Mapping[str, int]]


@dataclass(frozen=True)
class _Document:
    document_id: str
    role: str
    text: str
    spans: tuple[AnnotationSpan, ...]


class _DuplicateJsonKey(ValueError):
    pass


class _NonfiniteJsonNumber(ValueError):
    pass


class _RejectAnnotationRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        raise EnronAnnotationError("Annotation download redirects are not permitted.")


def _open_pinned_annotation_download(request: urllib.request.Request, *, timeout: float) -> Any:
    opener = urllib.request.build_opener(_RejectAnnotationRedirects())
    return opener.open(request, timeout=timeout)  # noqa: S310


def download_cmu_enron_annotations(
    output_dir: Path,
    *,
    timeout_seconds: float = 30.0,
    allow_unignored_output: bool = False,
) -> dict[str, Any]:
    """Download the one pinned CMU archive into a new private transactional directory."""

    if (
        not isinstance(output_dir, Path)
        or isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
        or timeout_seconds > _MAX_DOWNLOAD_TIMEOUT_SECONDS
        or not isinstance(allow_unignored_output, bool)
    ):
        raise EnronAnnotationError("Annotation download options are invalid.")
    try:
        request = urllib.request.Request(
            CMU_ENRON_MEETINGS_URL,
            headers={"Accept-Encoding": "identity", "User-Agent": f"nerb/{__version__}"},
            method="GET",
        )
        with _open_pinned_annotation_download(request, timeout=float(timeout_seconds)) as response:
            _validate_download_response(response)
            archive = _read_bounded_download(response)
        actual_sha256 = hashlib.sha256(archive).hexdigest()
        if len(archive) != CMU_ENRON_MEETINGS_ARCHIVE_BYTES or actual_sha256 != CMU_ENRON_MEETINGS_SHA256:
            raise EnronAnnotationError("Annotation download failed pinned size or hash verification.")
        receipt = {
            "schema_version": ANNOTATION_SOURCE_RECEIPT_SCHEMA_VERSION,
            "verified": True,
            "source": {
                "id": "cmu-enron-meetings-xml",
                "url": CMU_ENRON_MEETINGS_URL,
            },
            "artifact": {
                "name": ARCHIVE_FILENAME,
                "bytes": len(archive),
                "sha256": "sha256:" + actual_sha256,
            },
            "privacy": {
                "aggregate_only": True,
                "raw_text_included": False,
                "direct_identifiers_included": False,
                "private_archive_committed": True,
            },
        }
        _validate_aggregate_privacy(receipt)
        with PrivateRun(output_dir, allow_unignored_output=allow_unignored_output) as run:
            with run.open_binary(ARCHIVE_FILENAME) as handle:
                handle.write(archive)
            with run.open_binary(RECEIPT_FILENAME) as handle:
                handle.write(_pretty_json_bytes(receipt))
            run.commit()
    except EnronAnnotationError:
        raise
    except (EnronPrivateIOError, OSError, TimeoutError, ValueError, urllib.error.URLError):
        raise EnronAnnotationError("Annotation download failed safely.") from None
    return receipt


def _validate_download_response(response: Any) -> None:
    final_url = response.geturl()
    if not isinstance(final_url, str):
        raise EnronAnnotationError("Annotation download response identity is invalid.")
    parsed = urlsplit(final_url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "www.cs.cmu.edu"
        or parsed.port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != "/~einat/EnronMeetings-XML.zip"
        or parsed.query
        or parsed.fragment
    ):
        raise EnronAnnotationError("Annotation download response identity is invalid.")
    content_encoding = response.headers.get("Content-Encoding")
    if content_encoding not in {None, "", "identity"}:
        raise EnronAnnotationError("Annotation download response encoding is invalid.")
    content_length = response.headers.get("Content-Length")
    if content_length is not None:
        try:
            declared_length = int(content_length)
        except (TypeError, ValueError):
            raise EnronAnnotationError("Annotation download response length is invalid.") from None
        if declared_length != CMU_ENRON_MEETINGS_ARCHIVE_BYTES:
            raise EnronAnnotationError("Annotation download response length is invalid.")


def _read_bounded_download(response: Any) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(_DOWNLOAD_CHUNK_BYTES)
        if not isinstance(chunk, bytes):
            raise EnronAnnotationError("Annotation download response body is invalid.")
        if not chunk:
            break
        total += len(chunk)
        if total > CMU_ENRON_MEETINGS_ARCHIVE_BYTES:
            raise EnronAnnotationError("Annotation download exceeds the pinned byte limit.")
        chunks.append(chunk)
    return b"".join(chunks)


def parse_cmu_annotation_fragment(raw: bytes) -> ParsedAnnotationDocument:
    """Parse one CMU fragment without treating unrelated angle text as markup."""

    if not isinstance(raw, bytes):
        raise TypeError("CMU annotation fragments must be bytes.")
    try:
        source = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EnronAnnotationError("Annotation fragment encoding is invalid.") from None

    # Unknown variants must not silently turn answer-bearing markup into text.
    residual = source.replace(_OPEN_MARKER, "").replace(_CLOSE_MARKER, "")
    if any(_TRUE_NAME_TOKEN_RE.search(match.group()) for match in _ANGLE_CONSTRUCT_RE.finditer(residual)):
        raise EnronAnnotationError("Annotation fragment marker structure is invalid.")

    output: list[str] = []
    output_scalars = 0
    spans: list[AnnotationSpan] = []
    cursor = 0
    while cursor < len(source):
        open_at = source.find(_OPEN_MARKER, cursor)
        close_at = source.find(_CLOSE_MARKER, cursor)
        if open_at < 0:
            if close_at >= 0:
                raise EnronAnnotationError("Annotation fragment marker structure is invalid.")
            remainder = source[cursor:]
            output.append(remainder)
            output_scalars += len(remainder)
            break
        if close_at >= 0 and close_at < open_at:
            raise EnronAnnotationError("Annotation fragment marker structure is invalid.")

        prefix = source[cursor:open_at]
        output.append(prefix)
        output_scalars += len(prefix)
        payload_start = open_at + len(_OPEN_MARKER)
        payload_end = source.find(_CLOSE_MARKER, payload_start)
        if payload_end < 0 or source.find(_OPEN_MARKER, payload_start, payload_end) >= 0:
            raise EnronAnnotationError("Annotation fragment marker structure is invalid.")
        payload = source[payload_start:payload_end]
        leading = len(payload) - len(payload.lstrip(_ASCII_WHITESPACE))
        trailing = len(payload) - len(payload.rstrip(_ASCII_WHITESPACE))
        content_end = len(payload) - trailing if trailing else len(payload)
        if leading >= content_end:
            raise EnronAnnotationError("Annotation fragment contains an empty annotation.")

        output.append(payload)
        span = AnnotationSpan(output_scalars + leading, output_scalars + content_end)
        spans.append(span)
        output_scalars += len(payload)
        cursor = payload_end + len(_CLOSE_MARKER)

    text = "".join(output)
    if output_scalars != len(text):
        raise EnronAnnotationError("Annotation fragment scalar accounting failed.")
    previous_end = 0
    for span in spans:
        if span.start < previous_end or span.start >= span.end or span.end > len(text):
            raise EnronAnnotationError("Annotation fragment span structure is invalid.")
        surface = text[span.start : span.end]
        if surface != surface.strip(_ASCII_WHITESPACE):
            raise EnronAnnotationError("Annotation fragment span boundary is invalid.")
        previous_end = span.end
    return ParsedAnnotationDocument(text=text, spans=tuple(spans))


def ingest_cmu_enron_annotations(options: EnronAnnotationIngestOptions) -> dict[str, Any]:
    """Ingest an explicit verified archive into a deterministic private bundle."""

    expectation = _validate_options(options)
    try:
        archive = _read_archive(options.archive_path)
        actual_sha256 = hashlib.sha256(archive).hexdigest()
        if actual_sha256 != expectation.archive_sha256:
            raise EnronAnnotationError("Annotation archive verification failed.")
        if expectation.archive_bytes is not None and len(archive) != expectation.archive_bytes:
            raise EnronAnnotationError("Annotation archive verification failed.")
        documents, bunch_counts = _parse_archive(archive, archive_sha256=actual_sha256)
        populations = _population_summary(documents)
        _validate_expected_populations(populations, expectation.populations)
        if not expectation.fixture_mode:
            if bunch_counts != _EXPECTED_BUNCH_DOCUMENTS:
                raise EnronAnnotationError("Annotation archive inventory is invalid.")
            if populations != _PRODUCTION_POPULATION_SUMMARY:
                raise EnronAnnotationError("Annotation archive population verification failed.")

        implementation_sha256 = _implementation_sha256()
        with PrivateRun(
            options.output_dir,
            allow_unignored_output=options.allow_unignored_output,
        ) as run:
            document_rows = [_document_row(document) for document in documents]
            label_rows = [_label_row(document) for document in documents]
            with run.open_binary(DOCUMENTS_FILENAME) as handle:
                documents_descriptor = _write_jsonl_artifact(
                    handle,
                    document_rows,
                    artifact_id="cmu_enron_meetings_documents",
                    name=DOCUMENTS_FILENAME,
                )
            with run.open_binary(LABELS_FILENAME) as handle:
                labels_descriptor = _write_jsonl_artifact(
                    handle,
                    label_rows,
                    artifact_id="cmu_enron_meetings_person_labels",
                    name=LABELS_FILENAME,
                )
            manifest = _manifest_payload(
                expectation,
                populations,
                documents_descriptor,
                labels_descriptor,
                archive_bytes=len(archive),
                implementation_sha256=implementation_sha256,
            )
            _validate_aggregate_privacy(manifest)
            with run.open_binary(MANIFEST_FILENAME) as handle:
                manifest_bytes = _pretty_json_bytes(manifest)
                handle.write(manifest_bytes)
            manifest_descriptor = _descriptor_from_bytes(
                manifest_bytes,
                artifact_id="cmu_enron_meetings_manifest",
                name=MANIFEST_FILENAME,
                records=1,
            )
            receipt = _receipt_payload(manifest, manifest_descriptor)
            _validate_aggregate_privacy(receipt)
            with run.open_binary(RECEIPT_FILENAME) as handle:
                handle.write(_pretty_json_bytes(receipt))
            _verify_bundle(run.stage_dir, require_commit=False)
            run.commit()
    except EnronAnnotationError:
        raise
    except EnronPrivateIOError as exc:
        raise EnronAnnotationError(str(exc)) from exc
    except (KeyError, OSError, RuntimeError, ValueError, zipfile.BadZipFile):
        raise EnronAnnotationError("Annotation archive ingestion failed safely.") from None

    return verify_cmu_enron_annotations(options.output_dir)


def verify_cmu_enron_annotations(run_dir: Path) -> dict[str, Any]:
    """Deeply verify a committed annotation bundle and return aggregate receipt data."""

    try:
        return _verify_bundle(run_dir, require_commit=True)
    except EnronAnnotationError:
        raise
    except EnronPrivateIOError as exc:
        raise EnronAnnotationError(str(exc)) from exc
    except (OSError, RuntimeError, TypeError, ValueError):
        raise EnronAnnotationError("Annotation bundle verification failed safely.") from None


def load_cmu_enron_training_quality_source(run_dir: Path) -> dict[str, Any]:
    """Load the verified auxiliary training population for private quality execution."""

    try:
        return _load_cmu_enron_training_quality_source(run_dir)
    except EnronAnnotationError:
        raise
    except EnronPrivateIOError:
        raise EnronAnnotationError("Annotation quality source could not be read safely.") from None
    except (KeyError, OSError, RuntimeError, TypeError, ValueError):
        raise EnronAnnotationError("Annotation quality source could not be loaded safely.") from None


def _load_cmu_enron_training_quality_source(run_dir: Path) -> dict[str, Any]:
    receipt = verify_cmu_enron_annotations(run_dir)
    root = _validate_bundle_root(run_dir, require_commit=True)
    manifest_bytes = _read_private_file(root / MANIFEST_FILENAME)
    documents_bytes = _read_private_file(root / DOCUMENTS_FILENAME)
    labels_bytes = _read_private_file(root / LABELS_FILENAME)
    manifest = _load_json_object(manifest_bytes)
    document_rows = _load_jsonl_objects(documents_bytes)
    label_rows = _load_jsonl_objects(labels_bytes)
    receipt_artifacts = _mapping(receipt["artifacts"])
    loaded_descriptors = {
        "documents": _descriptor_from_bytes(
            documents_bytes,
            artifact_id="cmu_enron_meetings_documents",
            name=DOCUMENTS_FILENAME,
            records=len(document_rows),
        ),
        "person_labels": _descriptor_from_bytes(
            labels_bytes,
            artifact_id="cmu_enron_meetings_person_labels",
            name=LABELS_FILENAME,
            records=len(label_rows),
        ),
        "manifest": _descriptor_from_bytes(
            manifest_bytes,
            artifact_id="cmu_enron_meetings_manifest",
            name=MANIFEST_FILENAME,
            records=1,
        ),
    }
    if any(loaded_descriptors[name] != receipt_artifacts[name] for name in loaded_descriptors):
        raise EnronAnnotationError("Annotation quality-source artifact binding is invalid.")
    documents = _validate_artifact_rows(document_rows, label_rows)
    selected = [document for document in documents if document.role == "train"]
    if len(selected) != _mapping(receipt["populations"])["train"]["documents"]:
        raise EnronAnnotationError("Annotation training population binding is invalid.")
    artifacts = _mapping(manifest["artifacts"])
    annotation = _mapping(manifest["annotation"])
    return {
        "documents": [
            {
                "document_id": document.document_id,
                "text": document.text,
                "text_view": "cmu_published_document",
                "split_role": "train",
            }
            for document in selected
        ],
        "labels": [
            {
                "document_id": document.document_id,
                "entity_class": "person",
                "start": span.start,
                "end": span.end,
            }
            for document in selected
            for span in document.spans
        ],
        "label_artifact_id": "cmu_enron_meetings_person_labels",
        "annotation_scope": {
            "entity_classes": ["person"],
            "document_regions": list(annotation["document_regions"]),
            "span_policy_sha256": annotation["span_policy_sha256"],
            "exclusions": list(annotation["out_of_class_forms"]),
        },
        "annotation_completeness": annotation["annotation_completeness"],
        "label_strength": annotation["label_strength"],
        "text_view_descriptor": {
            "id": "cmu_published_document",
            "artifact_sha256": _mapping(artifacts["documents"])["sha256"],
            "content_policy_sha256": annotation["span_policy_sha256"],
            "document_regions": list(annotation["document_regions"]),
            "primary_for_quality": True,
            "answer_bearing_fields_included": False,
        },
        "public_binding": {
            "source_sha256": _mapping(receipt["source"])["archive_sha256"],
            "documents_sha256": _mapping(_mapping(receipt["artifacts"])["documents"])["sha256"],
            "labels_sha256": _mapping(_mapping(receipt["artifacts"])["person_labels"])["sha256"],
            "span_policy_sha256": receipt["span_policy_sha256"],
            "promotable": receipt["promotable"],
            "nonpromotable_reason": receipt["nonpromotable_reason"],
        },
    }


def _validate_options(options: EnronAnnotationIngestOptions) -> _Expectation:
    if not isinstance(options, EnronAnnotationIngestOptions):
        raise TypeError("options must be EnronAnnotationIngestOptions.")
    if not isinstance(options.archive_path, Path) or not isinstance(options.output_dir, Path):
        raise EnronAnnotationError("Annotation ingest paths are invalid.")
    if not isinstance(options.fixture_mode, bool) or not isinstance(options.allow_unignored_output, bool):
        raise EnronAnnotationError("Annotation ingest mode is invalid.")
    if not options.fixture_mode:
        if options.fixture_expected_sha256 is not None or options.fixture_expected_populations is not None:
            raise EnronAnnotationError("Production annotation ingest does not accept fixture overrides.")
        return _Expectation(
            fixture_mode=False,
            archive_sha256=CMU_ENRON_MEETINGS_SHA256,
            archive_bytes=CMU_ENRON_MEETINGS_ARCHIVE_BYTES,
            populations=_copy_expected_populations(CMU_ENRON_MEETINGS_POPULATIONS),
        )
    if options.fixture_expected_sha256 is None or options.fixture_expected_populations is None:
        raise EnronAnnotationError("Fixture annotation ingest requires explicit hash and population gates.")
    return _Expectation(
        fixture_mode=True,
        archive_sha256=_bare_sha256(options.fixture_expected_sha256),
        archive_bytes=None,
        populations=_copy_expected_populations(options.fixture_expected_populations),
    )


def _copy_expected_populations(value: Mapping[str, Mapping[str, int]]) -> dict[str, dict[str, int]]:
    if not isinstance(value, Mapping) or set(value) != {"train", "test"}:
        raise EnronAnnotationError("Annotation population gates are invalid.")
    copied: dict[str, dict[str, int]] = {}
    for role in ("train", "test"):
        item = value.get(role)
        if not isinstance(item, Mapping) or set(item) != {"documents", "spans"}:
            raise EnronAnnotationError("Annotation population gates are invalid.")
        documents = _integer(item.get("documents"), minimum=1)
        spans = _integer(item.get("spans"), minimum=0)
        copied[role] = {"documents": documents, "spans": spans}
    return copied


def _bare_sha256(value: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise EnronAnnotationError("Annotation archive hash gate is invalid.")
    return value.removeprefix("sha256:")


def _read_archive(path: Path) -> bytes:
    with open_private_binary_input(path) as handle:
        archive = handle.read(_MAX_ARCHIVE_BYTES + 1)
    if len(archive) > _MAX_ARCHIVE_BYTES:
        raise EnronAnnotationError("Annotation archive exceeds the byte limit.")
    return archive


def _parse_archive(archive: bytes, *, archive_sha256: str) -> tuple[list[_Document], dict[tuple[str, str], int]]:
    try:
        source = zipfile.ZipFile(_BytesReader(archive))
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile):
        raise EnronAnnotationError("Annotation archive structure is invalid.") from None
    with source:
        infos = source.infolist()
        if len(infos) > _MAX_ARCHIVE_ENTRIES:
            raise EnronAnnotationError("Annotation archive inventory is invalid.")
        seen: set[str] = set()
        seen_normalized: set[str] = set()
        total_uncompressed = 0
        files: list[tuple[zipfile.ZipInfo, str, str]] = []
        bunch_counts: dict[tuple[str, str], int] = {}
        for info in infos:
            _validate_member_name(info.filename)
            normalized = unicodedata.normalize("NFC", info.filename).casefold()
            if info.filename in seen or normalized in seen_normalized:
                raise EnronAnnotationError("Annotation archive inventory is invalid.")
            seen.add(info.filename)
            seen_normalized.add(normalized)
            unix_mode = info.external_attr >> 16
            file_type = stat.S_IFMT(unix_mode)
            if (
                _zipinfo_is_symlink(info)
                or info.flag_bits & 1
                or (file_type and file_type not in {stat.S_IFREG, stat.S_IFDIR})
            ):
                raise EnronAnnotationError("Annotation archive inventory is invalid.")
            if info.is_dir():
                if info.filename not in _ALLOWED_DIRECTORIES:
                    raise EnronAnnotationError("Annotation archive inventory is invalid.")
                continue
            match = _MEMBER_RE.fullmatch(info.filename)
            if match is None:
                raise EnronAnnotationError("Annotation archive inventory is invalid.")
            role = match.group("role")
            bunch = match.group("bunch")
            if (role == "train" and bunch == "bunch4") or (role == "test" and bunch != "bunch4"):
                raise EnronAnnotationError("Annotation archive inventory is invalid.")
            if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                raise EnronAnnotationError("Annotation archive compression is invalid.")
            if info.file_size < 0 or info.file_size > _MAX_MEMBER_BYTES:
                raise EnronAnnotationError("Annotation archive member exceeds the byte limit.")
            total_uncompressed += info.file_size
            if total_uncompressed > _MAX_UNCOMPRESSED_BYTES:
                raise EnronAnnotationError("Annotation archive expands beyond the byte limit.")
            if info.file_size and info.compress_size == 0:
                raise EnronAnnotationError("Annotation archive compression is invalid.")
            if info.compress_size and info.file_size > info.compress_size * _MAX_COMPRESSION_RATIO:
                raise EnronAnnotationError("Annotation archive compression is invalid.")
            bunch_counts[(role, bunch)] = bunch_counts.get((role, bunch), 0) + 1
            files.append((info, role, bunch))

        documents: list[_Document] = []
        document_ids: set[str] = set()
        for info, role, _bunch in files:
            try:
                raw = source.read(info)
            except (KeyError, OSError, RuntimeError, ValueError, zipfile.BadZipFile):
                raise EnronAnnotationError("Annotation archive member validation failed.") from None
            if len(raw) != info.file_size:
                raise EnronAnnotationError("Annotation archive member validation failed.")
            parsed = parse_cmu_annotation_fragment(raw)
            document_id = _document_id(info.filename)
            if document_id in document_ids:
                raise EnronAnnotationError("Annotation archive document identity is invalid.")
            document_ids.add(document_id)
            documents.append(_Document(document_id=document_id, role=role, text=parsed.text, spans=parsed.spans))
        if not documents:
            raise EnronAnnotationError("Annotation archive contains no documents.")
        documents.sort(key=lambda item: item.document_id)
        if hashlib.sha256(archive).hexdigest() != archive_sha256:
            raise EnronAnnotationError("Annotation archive changed during parsing.")
        return documents, bunch_counts


class _BytesReader:
    """Minimal immutable seekable reader accepted by :class:`zipfile.ZipFile`."""

    def __init__(self, value: bytes) -> None:
        self._value = value
        self._position = 0

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = len(self._value) - self._position
        start = self._position
        end = min(len(self._value), start + size)
        self._position = end
        return self._value[start:end]

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        if whence == os.SEEK_SET:
            position = offset
        elif whence == os.SEEK_CUR:
            position = self._position + offset
        elif whence == os.SEEK_END:
            position = len(self._value) + offset
        else:
            raise ValueError("Invalid seek mode.")
        if position < 0:
            raise ValueError("Negative seek position.")
        self._position = position
        return position

    def tell(self) -> int:
        return self._position

    def seekable(self) -> bool:
        return True


def _validate_member_name(name: str) -> None:
    if not isinstance(name, str) or not name or "\0" in name or "\\" in name:
        raise EnronAnnotationError("Annotation archive inventory is invalid.")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise EnronAnnotationError("Annotation archive inventory is invalid.")


def _zipinfo_is_symlink(info: zipfile.ZipInfo) -> bool:
    return stat.S_ISLNK(info.external_attr >> 16)


def _document_id(member_name: str) -> str:
    digest = hashlib.sha256(b"nerb.enron.cmu-document-id.v1\0" + member_name.encode("ascii")).hexdigest()
    return "cmu-document:sha256:" + digest


def _population_summary(documents: Sequence[_Document]) -> dict[str, dict[str, int]]:
    result = {
        role: {
            "documents": 0,
            "positive_documents": 0,
            "negative_documents": 0,
            "spans": 0,
            "text_scalars": 0,
            "gold_scalars": 0,
        }
        for role in ("train", "test")
    }
    for document in documents:
        if document.role not in result:
            raise EnronAnnotationError("Annotation document role is invalid.")
        item = result[document.role]
        item["documents"] += 1
        item["positive_documents"] += int(bool(document.spans))
        item["negative_documents"] += int(not document.spans)
        item["spans"] += len(document.spans)
        item["text_scalars"] += len(document.text)
        item["gold_scalars"] += sum(span.end - span.start for span in document.spans)
    return result


def _validate_expected_populations(
    populations: Mapping[str, Mapping[str, int]], expected: Mapping[str, Mapping[str, int]]
) -> None:
    for role in ("train", "test"):
        if (
            populations[role]["documents"] != expected[role]["documents"]
            or populations[role]["spans"] != expected[role]["spans"]
        ):
            raise EnronAnnotationError("Annotation archive population verification failed.")


def _document_row(document: _Document) -> dict[str, Any]:
    return {
        "document_id": document.document_id,
        "role": document.role,
        "text": document.text,
        "text_sha256": _hash_bytes(document.text.encode("utf-8")),
    }


def _label_row(document: _Document) -> dict[str, Any]:
    return {
        "annotation_completeness": "exhaustive_within_scope",
        "document_id": document.document_id,
        "entity_class": "person",
        "label_strength": "independent",
        "role": document.role,
        "spans": [{"end": span.end, "start": span.start} for span in document.spans],
    }


def _write_jsonl_artifact(
    handle: BinaryIO,
    rows: Sequence[Mapping[str, Any]],
    *,
    artifact_id: str,
    name: str,
) -> dict[str, Any]:
    digest = hashlib.sha256()
    size = 0
    for row in rows:
        line = _canonical_line(row)
        handle.write(line)
        digest.update(line)
        size += len(line)
    handle.flush()
    return {
        "id": artifact_id,
        "name": name,
        "sha256": "sha256:" + digest.hexdigest(),
        "bytes": size,
        "records": len(rows),
    }


def _manifest_payload(
    expectation: _Expectation,
    populations: Mapping[str, Mapping[str, int]],
    documents_descriptor: Mapping[str, Any],
    labels_descriptor: Mapping[str, Any],
    *,
    archive_bytes: int,
    implementation_sha256: str,
) -> dict[str, Any]:
    fixture_mode = expectation.fixture_mode
    return {
        "schema_version": ANNOTATION_RUN_SCHEMA_VERSION,
        "source": {
            "id": "synthetic-cmu-enron-meetings-fixture" if fixture_mode else "cmu-enron-meetings-xml",
            "url": None if fixture_mode else CMU_ENRON_MEETINGS_URL,
            "archive_sha256": "sha256:" + expectation.archive_sha256,
            "archive_bytes": archive_bytes,
            "fixture_mode": fixture_mode,
        },
        "annotation": {
            "entity_class": "person",
            "label_strength": "independent",
            "annotation_completeness": "exhaustive_within_scope",
            "document_regions": ["published_source_fragment"],
            "included_forms": ["nicknames", "misspelled_person_names"],
            "out_of_class_forms": [
                "person_name_substrings_inside_email_addresses",
                "person_name_substrings_within_larger_organization_or_location_names",
            ],
            "span_policy_sha256": SPAN_POLICY_SHA256,
            "character_position_semantics": "document_id_unicode_scalar_index",
        },
        "expected_populations": {role: dict(expectation.populations[role]) for role in ("train", "test")},
        "populations": {role: dict(populations[role]) for role in ("train", "test")},
        "artifacts": {
            "documents": dict(documents_descriptor),
            "person_labels": dict(labels_descriptor),
        },
        "software": {
            "nerb_version": __version__,
            "implementation_sha256": implementation_sha256,
            "python_implementation": platform.python_implementation(),
            "python_version": platform.python_version(),
            "unicode_data_version": unicodedata.unidata_version,
        },
        "privacy": {
            "manifest_aggregate_only": True,
            "manifest_contains_direct_identifiers": False,
            "manifest_contains_document_ids": False,
            "manifest_contains_member_paths": False,
            "private_documents_contain_raw_text": True,
            "private_labels_contain_surfaces": False,
        },
        "promotable": False,
        "nonpromotable_reason": ("synthetic_fixture_override" if fixture_mode else CMU_AUXILIARY_NONPROMOTABLE_REASON),
    }


def _receipt_payload(manifest: Mapping[str, Any], manifest_descriptor: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": ANNOTATION_RECEIPT_SCHEMA_VERSION,
        "verified": True,
        "source": dict(_mapping(manifest.get("source"))),
        "populations": {
            role: dict(_mapping(_mapping(manifest.get("populations")).get(role))) for role in ("train", "test")
        },
        "artifacts": {
            "documents": dict(_mapping(_mapping(manifest.get("artifacts")).get("documents"))),
            "person_labels": dict(_mapping(_mapping(manifest.get("artifacts")).get("person_labels"))),
            "manifest": dict(manifest_descriptor),
        },
        "span_policy_sha256": _mapping(manifest.get("annotation")).get("span_policy_sha256"),
        "implementation_sha256": _mapping(manifest.get("software")).get("implementation_sha256"),
        "promotable": manifest.get("promotable"),
        "nonpromotable_reason": manifest.get("nonpromotable_reason"),
        "privacy": {
            "aggregate_only": True,
            "raw_text_included": False,
            "direct_identifiers_included": False,
            "document_ids_included": False,
            "member_paths_included": False,
        },
    }


def _verify_bundle(run_dir: Path, *, require_commit: bool) -> dict[str, Any]:
    root = _validate_bundle_root(run_dir, require_commit=require_commit)
    manifest_bytes = _read_private_file(root / MANIFEST_FILENAME)
    manifest = _load_json_object(manifest_bytes)
    if manifest_bytes != _pretty_json_bytes(manifest):
        raise EnronAnnotationError("Annotation manifest encoding is invalid.")
    _validate_manifest_schema(manifest)
    _validate_aggregate_privacy(manifest)

    documents_bytes = _read_private_file(root / DOCUMENTS_FILENAME)
    labels_bytes = _read_private_file(root / LABELS_FILENAME)
    document_rows = _load_jsonl_objects(documents_bytes)
    label_rows = _load_jsonl_objects(labels_bytes)
    documents_descriptor = _descriptor_from_bytes(
        documents_bytes,
        artifact_id="cmu_enron_meetings_documents",
        name=DOCUMENTS_FILENAME,
        records=len(document_rows),
    )
    labels_descriptor = _descriptor_from_bytes(
        labels_bytes,
        artifact_id="cmu_enron_meetings_person_labels",
        name=LABELS_FILENAME,
        records=len(label_rows),
    )
    artifacts = _mapping(manifest["artifacts"])
    if artifacts["documents"] != documents_descriptor or artifacts["person_labels"] != labels_descriptor:
        raise EnronAnnotationError("Annotation artifact binding is invalid.")

    documents = _validate_artifact_rows(document_rows, label_rows)
    populations = _population_summary(documents)
    if manifest["populations"] != populations:
        raise EnronAnnotationError("Annotation population binding is invalid.")
    expected = _copy_expected_populations(_mapping(manifest["expected_populations"]))
    _validate_expected_populations(populations, expected)

    source = _mapping(manifest["source"])
    fixture_mode = source["fixture_mode"]
    if not isinstance(fixture_mode, bool):
        raise EnronAnnotationError("Annotation source binding is invalid.")
    if fixture_mode:
        fixture_source = {
            "id": "synthetic-cmu-enron-meetings-fixture",
            "url": None,
            "archive_sha256": source["archive_sha256"],
            "archive_bytes": source["archive_bytes"],
            "fixture_mode": True,
        }
        if source != fixture_source:
            raise EnronAnnotationError("Fixture annotation source binding is invalid.")
        if manifest["promotable"] is not False or manifest["nonpromotable_reason"] != "synthetic_fixture_override":
            raise EnronAnnotationError("Fixture annotation bundle is not marked nonpromotable.")
    else:
        production_source = {
            "id": "cmu-enron-meetings-xml",
            "url": CMU_ENRON_MEETINGS_URL,
            "archive_sha256": "sha256:" + CMU_ENRON_MEETINGS_SHA256,
            "archive_bytes": CMU_ENRON_MEETINGS_ARCHIVE_BYTES,
            "fixture_mode": False,
        }
        if source != production_source or expected != _copy_expected_populations(CMU_ENRON_MEETINGS_POPULATIONS):
            raise EnronAnnotationError("Production annotation source binding is invalid.")
        if populations != _PRODUCTION_POPULATION_SUMMARY:
            raise EnronAnnotationError("Production annotation population binding is invalid.")
        if (
            manifest["promotable"] is not False
            or manifest["nonpromotable_reason"] != CMU_AUXILIARY_NONPROMOTABLE_REASON
        ):
            raise EnronAnnotationError("Production annotation promotability binding is invalid.")

    manifest_descriptor = _descriptor_from_bytes(
        manifest_bytes,
        artifact_id="cmu_enron_meetings_manifest",
        name=MANIFEST_FILENAME,
        records=1,
    )
    expected_receipt = _receipt_payload(manifest, manifest_descriptor)
    receipt_bytes = _read_private_file(root / RECEIPT_FILENAME)
    receipt = _load_json_object(receipt_bytes)
    if receipt_bytes != _pretty_json_bytes(receipt) or receipt != expected_receipt:
        raise EnronAnnotationError("Annotation receipt binding is invalid.")
    _validate_aggregate_privacy(receipt)
    return dict(receipt)


def _validate_bundle_root(run_dir: Path, *, require_commit: bool) -> Path:
    try:
        root = Path(run_dir).expanduser()
        if not root.is_absolute():
            root = Path.cwd() / root
        if ".." in root.parts:
            raise EnronAnnotationError("Annotation bundle path is invalid.")
        info = root.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise EnronAnnotationError("Annotation bundle path is invalid.")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise EnronAnnotationError("Annotation bundle permissions are not private.")
        names = set(os.listdir(root))
        expected_names = _EXPECTED_FILES if require_commit else _EXPECTED_STAGED_FILES
        if names != expected_names:
            raise EnronAnnotationError("Annotation bundle inventory is invalid.")
        for name in expected_names:
            child = root / name
            child_info = child.lstat()
            if stat.S_ISLNK(child_info.st_mode) or not stat.S_ISREG(child_info.st_mode):
                raise EnronAnnotationError("Annotation bundle inventory is invalid.")
            if stat.S_IMODE(child_info.st_mode) & 0o077:
                raise EnronAnnotationError("Annotation bundle permissions are not private.")
        if require_commit and _read_private_file(root / "COMMITTED") != _COMMIT_PAYLOAD:
            raise EnronAnnotationError("Annotation bundle commit marker is invalid.")
        return root
    except EnronAnnotationError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError):
        raise EnronAnnotationError("Annotation bundle path could not be inspected safely.") from None


def _validate_manifest_schema(manifest: Mapping[str, Any]) -> None:
    _require_keys(
        manifest,
        {
            "annotation",
            "artifacts",
            "expected_populations",
            "nonpromotable_reason",
            "populations",
            "privacy",
            "promotable",
            "schema_version",
            "software",
            "source",
        },
    )
    if manifest["schema_version"] != ANNOTATION_RUN_SCHEMA_VERSION or not isinstance(manifest["promotable"], bool):
        raise EnronAnnotationError("Annotation manifest schema is invalid.")
    source = _mapping(manifest["source"])
    _require_keys(source, {"archive_bytes", "archive_sha256", "fixture_mode", "id", "url"})
    if (
        not isinstance(source["id"], str)
        or not isinstance(source["fixture_mode"], bool)
        or not isinstance(source["archive_sha256"], str)
        or not _SHA256_REF_RE.fullmatch(source["archive_sha256"])
        or (source["archive_bytes"] is not None and _integer(source["archive_bytes"], minimum=1) > _MAX_ARCHIVE_BYTES)
        or (source["url"] is not None and not isinstance(source["url"], str))
    ):
        raise EnronAnnotationError("Annotation source schema is invalid.")
    annotation = _mapping(manifest["annotation"])
    expected_annotation = {
        "entity_class": "person",
        "label_strength": "independent",
        "annotation_completeness": "exhaustive_within_scope",
        "document_regions": ["published_source_fragment"],
        "included_forms": ["nicknames", "misspelled_person_names"],
        "out_of_class_forms": [
            "person_name_substrings_inside_email_addresses",
            "person_name_substrings_within_larger_organization_or_location_names",
        ],
        "span_policy_sha256": SPAN_POLICY_SHA256,
        "character_position_semantics": "document_id_unicode_scalar_index",
    }
    if annotation != expected_annotation:
        raise EnronAnnotationError("Annotation policy binding is invalid.")
    expected_populations = _copy_expected_populations(_mapping(manifest["expected_populations"]))
    if set(expected_populations) != {"train", "test"}:
        raise EnronAnnotationError("Annotation expected-population schema is invalid.")
    _validate_population_schema(_mapping(manifest["populations"]))
    artifacts = _mapping(manifest["artifacts"])
    _require_keys(artifacts, {"documents", "person_labels"})
    _validate_descriptor(_mapping(artifacts["documents"]), DOCUMENTS_FILENAME)
    _validate_descriptor(_mapping(artifacts["person_labels"]), LABELS_FILENAME)
    software = _mapping(manifest["software"])
    _require_keys(
        software,
        {"implementation_sha256", "nerb_version", "python_implementation", "python_version", "unicode_data_version"},
    )
    expected_software = {
        "implementation_sha256": _implementation_sha256(),
        "nerb_version": __version__,
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "unicode_data_version": unicodedata.unidata_version,
    }
    if software != expected_software:
        raise EnronAnnotationError("Annotation software binding is stale or invalid.")
    expected_privacy = {
        "manifest_aggregate_only": True,
        "manifest_contains_direct_identifiers": False,
        "manifest_contains_document_ids": False,
        "manifest_contains_member_paths": False,
        "private_documents_contain_raw_text": True,
        "private_labels_contain_surfaces": False,
    }
    if manifest["privacy"] != expected_privacy:
        raise EnronAnnotationError("Annotation privacy attestation is invalid.")


def _validate_population_schema(value: Mapping[str, Any]) -> None:
    _require_keys(value, {"train", "test"})
    keys = {"documents", "gold_scalars", "negative_documents", "positive_documents", "spans", "text_scalars"}
    for role in ("train", "test"):
        item = _mapping(value[role])
        _require_keys(item, keys)
        for key in keys:
            _integer(item[key], minimum=0)
        if item["documents"] != item["positive_documents"] + item["negative_documents"]:
            raise EnronAnnotationError("Annotation population conservation is invalid.")


def _validate_descriptor(value: Mapping[str, Any], expected_name: str) -> None:
    _require_keys(value, {"bytes", "id", "name", "records", "sha256"})
    if (
        value["name"] != expected_name
        or not isinstance(value["id"], str)
        or not isinstance(value["sha256"], str)
        or not _SHA256_REF_RE.fullmatch(value["sha256"])
    ):
        raise EnronAnnotationError("Annotation artifact descriptor is invalid.")
    _integer(value["bytes"], minimum=1)
    _integer(value["records"], minimum=1)


def _validate_artifact_rows(
    document_rows: Sequence[Mapping[str, Any]], label_rows: Sequence[Mapping[str, Any]]
) -> list[_Document]:
    if not document_rows or len(document_rows) != len(label_rows):
        raise EnronAnnotationError("Annotation artifact row conservation is invalid.")
    documents: list[_Document] = []
    previous_id = ""
    seen: set[str] = set()
    for document_row, label_row in zip(document_rows, label_rows, strict=True):
        _require_keys(document_row, {"document_id", "role", "text", "text_sha256"})
        _require_keys(
            label_row,
            {
                "annotation_completeness",
                "document_id",
                "entity_class",
                "label_strength",
                "role",
                "spans",
            },
        )
        document_id = document_row["document_id"]
        role = document_row["role"]
        text = document_row["text"]
        if (
            not isinstance(document_id, str)
            or not _DOCUMENT_ID_RE.fullmatch(document_id)
            or document_id <= previous_id
            or document_id in seen
            or role not in {"train", "test"}
            or not isinstance(text, str)
            or not text
            or not isinstance(document_row["text_sha256"], str)
            or document_row["text_sha256"] != _hash_bytes(text.encode("utf-8"))
        ):
            raise EnronAnnotationError("Annotation document artifact is invalid.")
        if (
            label_row["document_id"] != document_id
            or label_row["role"] != role
            or label_row["entity_class"] != "person"
            or label_row["label_strength"] != "independent"
            or label_row["annotation_completeness"] != "exhaustive_within_scope"
            or not isinstance(label_row["spans"], list)
        ):
            raise EnronAnnotationError("Annotation label artifact is invalid.")
        spans: list[AnnotationSpan] = []
        previous_end = 0
        for raw_span in label_row["spans"]:
            span_value = _mapping(raw_span)
            _require_keys(span_value, {"end", "start"})
            start = _integer(span_value["start"], minimum=0)
            end = _integer(span_value["end"], minimum=1)
            if start < previous_end or start >= end or end > len(text):
                raise EnronAnnotationError("Annotation label span is invalid.")
            surface = text[start:end]
            if not surface or surface != surface.strip(_ASCII_WHITESPACE):
                raise EnronAnnotationError("Annotation label span boundary is invalid.")
            spans.append(AnnotationSpan(start, end))
            previous_end = end
        documents.append(_Document(document_id=document_id, role=str(role), text=text, spans=tuple(spans)))
        previous_id = document_id
        seen.add(document_id)
    return documents


def _read_private_file(path: Path) -> bytes:
    with open_private_binary_input(path) as handle:
        value = handle.read(_MAX_BUNDLE_FILE_BYTES + 1)
    if len(value) > _MAX_BUNDLE_FILE_BYTES:
        raise EnronAnnotationError("Annotation bundle file exceeds the byte limit.")
    return value


def _load_jsonl_objects(value: bytes) -> list[Mapping[str, Any]]:
    if not value or not value.endswith(b"\n"):
        raise EnronAnnotationError("Annotation JSONL artifact encoding is invalid.")
    rows: list[Mapping[str, Any]] = []
    for line in value.splitlines(keepends=True):
        if len(line) > _MAX_JSONL_LINE_BYTES:
            raise EnronAnnotationError("Annotation JSONL line exceeds the byte limit.")
        row = _load_json_object(line)
        if line != _canonical_line(row):
            raise EnronAnnotationError("Annotation JSONL artifact is not canonical.")
        rows.append(row)
    return rows


def _load_json_object(value: bytes) -> Mapping[str, Any]:
    try:
        decoded = value.decode("utf-8", errors="strict")
        parsed = json.loads(
            decoded,
            parse_constant=_reject_json_constant,
            parse_float=_parse_finite_float,
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (
        _DuplicateJsonKey,
        _NonfiniteJsonNumber,
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ):
        raise EnronAnnotationError("Annotation JSON artifact is invalid.") from None
    if not isinstance(parsed, dict):
        raise EnronAnnotationError("Annotation JSON artifact must contain an object.")
    return parsed


def _reject_json_constant(_value: str) -> None:
    raise _NonfiniteJsonNumber


def _parse_finite_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise _NonfiniteJsonNumber
    return result


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey
        result[key] = value
    return result


def _canonical_line(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode("utf-8")


def _pretty_json_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")


def _descriptor_from_bytes(
    value: bytes,
    *,
    artifact_id: str,
    name: str,
    records: int,
) -> dict[str, Any]:
    return {"id": artifact_id, "name": name, "sha256": _hash_bytes(value), "bytes": len(value), "records": records}


def _hash_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _implementation_sha256() -> str:
    try:
        value = Path(__file__).read_bytes()
    except OSError:
        raise EnronAnnotationError("Annotation implementation could not be fingerprinted.") from None
    return _hash_bytes(value)


def _mapping(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise EnronAnnotationError("Annotation object schema is invalid.")
    return value


def _require_keys(value: Mapping[str, Any], expected: set[str]) -> None:
    if set(value) != expected:
        raise EnronAnnotationError("Annotation object schema is not closed.")


def _integer(value: Any, *, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise EnronAnnotationError("Annotation integer field is invalid.")
    return value


def _validate_aggregate_privacy(value: Any) -> None:
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, Mapping):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, (list, tuple)):
            stack.extend(item)
        elif isinstance(item, str):
            lowered = item.casefold()
            if (
                "@" in item
                or "mailto:" in lowered
                or "file:" in lowered
                or item.startswith(("/", "\\\\"))
                or re.match(r"^[A-Za-z]:[\\/]", item)
                or _DOCUMENT_ID_RE.fullmatch(item)
            ):
                raise EnronAnnotationError("Aggregate annotation metadata contains a private identifier or path.")


__all__ = [
    "ANNOTATION_RECEIPT_SCHEMA_VERSION",
    "ANNOTATION_RUN_SCHEMA_VERSION",
    "ANNOTATION_SOURCE_RECEIPT_SCHEMA_VERSION",
    "ARCHIVE_FILENAME",
    "CMU_ENRON_MEETINGS_ARCHIVE_BYTES",
    "CMU_AUXILIARY_NONPROMOTABLE_REASON",
    "CMU_ENRON_MEETINGS_POPULATIONS",
    "CMU_ENRON_MEETINGS_SHA256",
    "CMU_ENRON_MEETINGS_URL",
    "DOCUMENTS_FILENAME",
    "LABELS_FILENAME",
    "MANIFEST_FILENAME",
    "RECEIPT_FILENAME",
    "SPAN_POLICY_SHA256",
    "AnnotationSpan",
    "EnronAnnotationError",
    "EnronAnnotationIngestOptions",
    "ParsedAnnotationDocument",
    "download_cmu_enron_annotations",
    "ingest_cmu_enron_annotations",
    "load_cmu_enron_training_quality_source",
    "parse_cmu_annotation_fragment",
    "verify_cmu_enron_annotations",
]

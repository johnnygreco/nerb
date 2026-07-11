from __future__ import annotations

import hashlib
import heapq
import importlib
import json
import math
import os
import platform
import re
import sqlite3
import stat
import tempfile
import time
import unicodedata
import zlib
from collections import Counter, deque
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from email.errors import HeaderParseError
from email.header import decode_header
from email.utils import getaddresses, parsedate_to_datetime
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as package_version
from pathlib import Path
from typing import Any, BinaryIO, TextIO

from . import __version__
from .enron_cleaning import (
    CLEANING_COUNTER_NAMES,
    CLEANING_POLICY_SHA256,
    CLEANING_POLICY_VERSION,
    GROUPING_TEXT_POLICY_SHA256,
    GROUPING_TEXT_POLICY_VERSION,
    EnronCleaningError,
    clean_email_body,
    clean_subject,
    normalize_grouping_text,
    normalize_natural_text,
    normalize_thread_subject,
)
from .enron_private_io import EnronPrivateIOError, PrivateRun, open_private_binary_input

PREPARED_RECORD_SCHEMA_VERSION = "nerb.enron_prepared_record.v2"
PROFILE_SCHEMA_VERSION = "nerb.enron_preparation_profile.v2"
RUN_MANIFEST_SCHEMA_VERSION = "nerb.enron_preparation_manifest.v2"
REJECTION_RECORD_SCHEMA_VERSION = "nerb.enron_preparation_rejection.v2"

DEFAULT_DATASET_ID = "corbt/enron-emails"
DEFAULT_DATASET_REVISION = "cfc06c758093d90993abce1a43668fb7357258a6"
DEFAULT_DATASET_SPLIT = "train"
PINNED_DATASET_RECORDS = 517_401
DEFAULT_OUTPUT_DIR = ".nerb/enron-preparation/enron-v2"
DEFAULT_MAX_JSONL_LINE_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_BODY_CHARS = 2_500_000
DEFAULT_MAX_BODY_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_SUBJECT_CHARS = 4_096
DEFAULT_MAX_SUBJECT_BYTES = 16 * 1024
DEFAULT_MAX_RECIPIENTS_PER_FIELD = 2_048
DEFAULT_MAX_HEADER_CHARS = 16_384
DEFAULT_MAX_PREPARED_LINE_BYTES = 64 * 1024 * 1024
HARD_MAX_JSONL_LINE_BYTES = 64 * 1024 * 1024
HARD_MAX_BODY_CHARS = 4_000_000
HARD_MAX_BODY_BYTES = 32 * 1024 * 1024
HARD_MAX_SUBJECT_CHARS = 65_536
HARD_MAX_SUBJECT_BYTES = 256 * 1024
HARD_MAX_RECIPIENTS_PER_FIELD = 8_192
HARD_MAX_PREPARED_LINE_BYTES = 384 * 1024 * 1024

_PREPARED_FILENAME = "prepared.jsonl"
_REJECTIONS_FILENAME = "rejections.jsonl"
_PROFILE_FILENAME = "profile.json"
_MANIFEST_FILENAME = "manifest.json"
_TRANSPORT_FILENAME = "transport-receipt.json"
_COMMITTED_FILENAME = "COMMITTED"
_COMMITTED_PAYLOAD = b"nerb.enron.private-run.v2\n"
_EXPECTED_FIELDS = frozenset({"message_id", "subject", "from", "to", "cc", "bcc", "date", "body", "file_name"})
_TEXT_FIELDS = ("message_id", "subject", "from", "body", "file_name")
_RECIPIENT_FIELDS = ("to", "cc", "bcc")
_MESSAGE_ID_RE = re.compile(r"(?im)^(?:message-id|in-reply-to|references)\s*:\s*(.+)$")
_ANGLE_MESSAGE_ID_RE = re.compile(r"<[^<>\s]{1,512}>")
_TOKEN_RE = re.compile(r"\w+", re.UNICODE)
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_IMMUTABLE_REVISION_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_DOCUMENT_ID_RE = re.compile(r"^doc_[0-9a-f]{64}$")
_SIMHASH_RE = re.compile(r"^[0-9a-f]{16}$")
_PROVENANCE_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/+\-]{0,511}$")
_TEXT_VIEW_NAMES = ("full_visible_body", "current_body", "subject_current_body", "current_body_core")
_SOURCE_MULTISET_HASH_ALGORITHM = "sha256_sha512_additive_multiset_v1"
_SOURCE_MULTISET_MODULUS = 1 << 512
_SIMHASH_COUNTER_BITS = 13
_SIMHASH_COUNTER_MASK = (1 << _SIMHASH_COUNTER_BITS) - 1
_SIMHASH_BYTE_EXPANSIONS = tuple(
    sum(((byte >> bit) & 1) << (bit * _SIMHASH_COUNTER_BITS) for bit in range(8)) for byte in range(256)
)
_DATE_STATUSES = frozenset({"valid", "out_of_range", "missing", "invalid", "ambiguous_timezone"})
_ALLOWED_TRANSFORM_COUNTERS = frozenset(CLEANING_COUNTER_NAMES) | frozenset(
    {f"subject_{name}" for name in CLEANING_COUNTER_NAMES}
    | {f"header_{name}" for name in CLEANING_COUNTER_NAMES}
    | {
        "bcc_recipient_truncated",
        "body_truncated",
        "cc_recipient_truncated",
        "embedded_message_ids_truncated",
        "header_addresses_dropped",
        "header_decode_errors",
        "header_decode_replacement_chars",
        "header_encoded_words_decoded",
        "header_noncanonical_addresses",
        "header_parse_errors",
        "header_scalars_truncated",
        "header_whitespace_collapsed",
        "html_decoded",
        "mime_decoded",
        "mailbox_folder_archive",
        "mailbox_folder_deleted",
        "mailbox_folder_draft",
        "mailbox_folder_inbox",
        "mailbox_folder_other",
        "mailbox_folder_sent",
        "mailbox_locator_invalid",
        "mailbox_locator_missing",
        "mailbox_locator_parsed",
        "recipient_values_truncated",
        "sender_values_truncated",
        "subject_truncated",
        "to_recipient_truncated",
    }
    | {f"date_{status}" for status in _DATE_STATUSES}
)

_SOURCE_SCHEMA_DESCRIPTOR = {
    "id": "corbt-enron-parsed-row",
    "version": "2",
    "fields": {
        "message_id": "string|null",
        "subject": "string|null",
        "from": "string|null",
        "to": "array<string>|null",
        "cc": "array<string>|null",
        "bcc": "array<string>|null",
        "date": "aware-datetime|rfc3339-or-rfc2822-string|null",
        "body": "string|null",
        "file_name": "string|null",
    },
    "unknown_fields": "rejected",
}
INPUT_SCHEMA_SHA256 = (
    "sha256:"
    + hashlib.sha256(
        json.dumps(_SOURCE_SCHEMA_DESCRIPTOR, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
)
CLEANING_POLICY_REF = "sha256:" + CLEANING_POLICY_SHA256.removeprefix("sha256:")
GROUPING_TEXT_POLICY_REF = "sha256:" + GROUPING_TEXT_POLICY_SHA256.removeprefix("sha256:")

_MAILBOX_FOLDER_ROLE_TOKENS = {
    "archive": frozenset({"all", "all_documents", "archive", "archives"}),
    "deleted": frozenset({"deleted", "deleted_items", "trash", "trash_bin"}),
    "draft": frozenset({"draft", "drafts"}),
    "inbox": frozenset({"in", "inbox"}),
    "sent": frozenset({"outbox", "sent", "sent_items", "sent_mail", "sent_messages", "sentmail"}),
}

_GROUPING_POLICY_DESCRIPTOR = {
    "id": "nerb.enron.grouping-features",
    "version": "2",
    "cleaning_policy_sha256": CLEANING_POLICY_REF,
    "text_policy_sha256": GROUPING_TEXT_POLICY_REF,
    "identity": "sha256-domain-separated-canonical-source-row",
    "exact_hashes": ["full_visible_body", "current_body", "subject_current_body", "current_body_core"],
    "thread": ["normalized_message_id", "normalized_subject", "participant_set", "embedded_message_ids"],
    "embedded_message_id_limit": 64,
    "near_duplicate": {
        "algorithm": "simhash64",
        "views": {
            "current_body_core": {"fallback_if_empty": "current_body"},
            "full_visible_body": {"fallback_if_empty": None},
        },
        "shingle_tokens": 3,
        "max_shingles": 4096,
        "bands": 4,
    },
    "mailbox": {
        "owner": "sha256-domain-separated-nfc-casefold-first-component-after-optional-maildir-prefix",
        "folder_role": ["archive", "deleted", "draft", "inbox", "other", "sent"],
        "folder_role_tokens": {role: sorted(tokens) for role, tokens in sorted(_MAILBOX_FOLDER_ROLE_TOKENS.items())},
    },
}
GROUPING_POLICY_SHA256 = (
    "sha256:"
    + hashlib.sha256(
        json.dumps(_GROUPING_POLICY_DESCRIPTOR, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
)

_DATE_POLICY_DESCRIPTOR = {
    "id": "nerb.enron.date-normalization",
    "version": "2",
    "input_types": ["null", "aware-or-naive-datetime", "iso8601-or-rfc2822-string"],
    "parse_order": ["python-datetime-fromisoformat", "stdlib-email-parsedate-to-datetime"],
    "naive_timezone": "ambiguous_and_ineligible",
    "eligible_utc_interval": {
        "start_inclusive": "1990-01-01T00:00:00Z",
        "end_exclusive": "2011-01-01T00:00:00Z",
    },
    "output": "canonical-utc-seconds-or-microseconds",
}
DATE_POLICY_SHA256 = (
    "sha256:"
    + hashlib.sha256(
        json.dumps(_DATE_POLICY_DESCRIPTOR, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
)


class EnronPreparationError(ValueError):
    """Raised when an Enron preparation run cannot be produced safely."""


@dataclass(frozen=True)
class EnronPreparationOptions:
    output_dir: Path
    input_jsonl: Path | None = None
    dataset_id: str = DEFAULT_DATASET_ID
    dataset_revision: str = DEFAULT_DATASET_REVISION
    dataset_split: str = DEFAULT_DATASET_SPLIT
    max_rows: int | None = None
    max_jsonl_line_bytes: int = DEFAULT_MAX_JSONL_LINE_BYTES
    max_body_chars: int = DEFAULT_MAX_BODY_CHARS
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
    max_subject_chars: int = DEFAULT_MAX_SUBJECT_CHARS
    max_subject_bytes: int = DEFAULT_MAX_SUBJECT_BYTES
    max_recipients_per_field: int = DEFAULT_MAX_RECIPIENTS_PER_FIELD
    allow_unignored_output: bool = False


@dataclass(frozen=True)
class _InputEvent:
    row: Mapping[str, Any] | None
    error_code: str | None
    source_digest: str
    raw_bytes: int


@dataclass(frozen=True)
class _SourceContext:
    kind: str
    reader: str
    package_version: str | None
    events: Iterable[_InputEvent]
    transport: _TransportState


@dataclass
class _TransportState:
    digest: Any
    bytes_read: int = 0
    physical_lines: int = 0
    complete: bool = False


@dataclass(frozen=True)
class _ValidatedRow:
    source_projection: Mapping[str, Any]
    message_id: str
    subject: str
    sender: str
    recipients: Mapping[str, tuple[str, ...]]
    date: Any
    body: str
    file_name: str


@dataclass(frozen=True)
class _PreparedUnique:
    payload: Mapping[str, Any]
    date_utc: str | None
    exact_content_sha256: str
    message_id_sha256: str | None
    thread_subject_sha256: str | None
    current_near_duplicate_available: bool
    full_near_duplicate_available: bool
    mailbox_owner_available: bool


@dataclass(frozen=True)
class _PreparedVerification:
    records: int
    occurrences: int
    views: Mapping[str, Mapping[str, Any]]
    cleaning: Mapping[str, int]
    dates: Mapping[str, Any]
    current_body_utf8_bytes_histogram: Mapping[str, int]
    grouping_features: Mapping[str, int]
    source_accumulator: int
    source_occurrences: int


@dataclass(frozen=True)
class _RejectionVerification:
    records: int
    occurrences: int
    source_accumulator: int
    reason_occurrences: Mapping[str, int]
    body_truncated_occurrences: int
    subject_truncated_occurrences: int


class _DuplicateJsonKey(ValueError):
    pass


class _NonfiniteJsonNumber(ValueError):
    pass


def prepare_enron_source(options: EnronPreparationOptions) -> dict[str, Any]:
    """Prepare a pinned Enron-like source into a deterministic private v2 run."""
    _validate_options(options)
    implementation_sha256 = _implementation_sha256()
    runtime_provenance = {
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "unicode_data_version": unicodedata.unidata_version,
    }
    started = time.perf_counter()
    try:
        with PrivateRun(
            options.output_dir,
            allow_unignored_output=options.allow_unignored_output,
        ) as run:
            database_path = run.stage_dir / ".records.sqlite3"
            connection = _open_spool(database_path)
            try:
                source = _source_context(options)
                ingest = _ingest_source(connection, source.events, options)
                with run.open_text(_PREPARED_FILENAME) as prepared_file:
                    prepared_descriptor, view_descriptors, aggregates = _write_prepared_records(
                        connection,
                        prepared_file,
                    )
                with run.open_text(_REJECTIONS_FILENAME) as rejections_file:
                    rejection_descriptor = _write_rejections(connection, rejections_file)
                _validate_source_volume(options, source, ingest, aggregates)
                profile = _profile_payload(
                    options,
                    source,
                    ingest,
                    aggregates,
                    prepared_descriptor,
                    rejection_descriptor,
                    view_descriptors,
                    implementation_sha256=implementation_sha256,
                    runtime_provenance=runtime_provenance,
                )
                _validate_aggregate_privacy(profile)
                with run.open_text(_PROFILE_FILENAME) as profile_file:
                    _write_json_file(profile_file, profile)
                profile_path = run.stage_dir / _PROFILE_FILENAME
                profile_descriptor = _artifact_descriptor(_PROFILE_FILENAME, profile_path, records=1)
                manifest = _manifest_payload(
                    profile,
                    prepared_descriptor,
                    rejection_descriptor,
                    profile_descriptor,
                )
                _validate_aggregate_privacy(manifest)
                with run.open_text(_MANIFEST_FILENAME) as manifest_file:
                    _write_json_file(manifest_file, manifest)
                with run.open_text(_TRANSPORT_FILENAME) as receipt_file:
                    _write_transport_receipt(receipt_file, source, started)
                _validate_staged_run(run.stage_dir, source_connection=connection)
            finally:
                connection.close()
                if database_path.exists():
                    database_path.unlink()
            run.commit()
    except (EnronPrivateIOError, EnronCleaningError) as exc:
        raise EnronPreparationError(str(exc)) from exc

    return {
        "schema_version": RUN_MANIFEST_SCHEMA_VERSION,
        "committed": True,
        "source_records": profile["source"]["input_records"],
        "prepared_records": profile["records"]["unique_prepared_records"],
        "prepared_occurrences": profile["records"]["prepared_occurrences"],
        "rejected_records": profile["records"]["rejected_records"],
        "prepared_artifact_sha256": prepared_descriptor["sha256"],
        "profile_artifact_sha256": profile_descriptor["sha256"],
        "rejection_artifact_sha256": rejection_descriptor["sha256"],
        "elapsed_seconds": round(time.perf_counter() - started, 6),
    }


def load_enron_preparation_run(path: Path) -> dict[str, Any]:
    """Verify a committed preparation run without returning its private records."""
    root = path.expanduser()
    _assert_safe_existing_directory(root)
    marker = root / _COMMITTED_FILENAME
    if not marker.is_file() or marker.is_symlink():
        raise EnronPreparationError("Enron preparation run is not committed.")
    with _open_regular_binary(marker) as marker_file:
        if marker_file.read(len(_COMMITTED_PAYLOAD) + 1) != _COMMITTED_PAYLOAD:
            raise EnronPreparationError("Enron preparation commit marker is invalid.")
    manifest = _read_json_object(root / _MANIFEST_FILENAME, 16 * 1024 * 1024)
    profile = _read_json_object(root / _PROFILE_FILENAME, 16 * 1024 * 1024)
    if manifest.get("schema_version") != RUN_MANIFEST_SCHEMA_VERSION:
        raise EnronPreparationError("Enron preparation manifest schema is invalid.")
    if profile.get("schema_version") != PROFILE_SCHEMA_VERSION:
        raise EnronPreparationError("Enron preparation profile schema is invalid.")
    _validate_manifest_shape(manifest)
    _validate_profile_shape(profile)
    _validate_aggregate_privacy(manifest)
    _validate_aggregate_privacy(profile)
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, Mapping):
        raise EnronPreparationError("Enron preparation manifest artifacts are invalid.")
    for artifact_id, expected_name, expected_records in (
        ("prepared_records", _PREPARED_FILENAME, None),
        ("rejections", _REJECTIONS_FILENAME, None),
        ("profile", _PROFILE_FILENAME, 1),
    ):
        descriptor = artifacts.get(artifact_id)
        if (
            not isinstance(descriptor, Mapping)
            or descriptor.get("id") != artifact_id
            or descriptor.get("name") != expected_name
            or (expected_records is not None and descriptor.get("records") != expected_records)
        ):
            raise EnronPreparationError("Enron preparation artifact descriptor is invalid.")
        artifact_path = root / expected_name
        if descriptor.get("sha256") != _sha256_file(artifact_path):
            raise EnronPreparationError("Enron preparation artifact hash mismatch.")
        if descriptor.get("bytes") != artifact_path.stat().st_size:
            raise EnronPreparationError("Enron preparation artifact size mismatch.")

    prepared_descriptor = artifacts["prepared_records"]
    profile_artifacts = profile.get("artifacts")
    profile_prepared = profile_artifacts.get("prepared_records") if isinstance(profile_artifacts, Mapping) else None
    rejection_descriptor = artifacts["rejections"]
    profile_rejections = profile_artifacts.get("rejections") if isinstance(profile_artifacts, Mapping) else None
    if profile_prepared != prepared_descriptor or profile_rejections != rejection_descriptor:
        raise EnronPreparationError("Enron preparation profile artifact binding is invalid.")
    expected_records, expected_occurrences, prepared_line_limit = _verify_profile_contract(profile, prepared_descriptor)
    with tempfile.TemporaryDirectory(prefix="nerb-enron-verify-") as temporary_directory:
        verification_root = Path(temporary_directory)
        verification_root.chmod(0o700)
        duplicate_connection = _open_duplicate_verification_spool(verification_root / "duplicates.sqlite3")
        try:
            verification = _verify_prepared_jsonl(
                root / _PREPARED_FILENAME,
                profile["source"],
                max_line_bytes=prepared_line_limit,
                duplicate_connection=duplicate_connection,
            )
            verified_duplicates = _duplicate_aggregates(duplicate_connection)
        finally:
            duplicate_connection.close()
    if verification.records != expected_records or verification.occurrences != expected_occurrences:
        raise EnronPreparationError("Enron preparation record or occurrence count mismatch.")
    _verify_view_projections(profile, verification)
    _verify_prepared_aggregates(profile, verification)
    _verify_duplicate_aggregates(profile, verified_duplicates)
    rejection_verification = _verify_rejections_jsonl(root / _REJECTIONS_FILENAME, rejection_descriptor)
    if rejection_verification.occurrences != profile["records"]["rejected_records"]:
        raise EnronPreparationError("Enron preparation rejection count mismatch.")
    _verify_ingestion_counters(profile, verification, rejection_verification)
    _verify_source_multiset(profile, verification, rejection_verification)
    _verify_manifest_profile_binding(manifest, profile)
    return {
        "valid": True,
        "schema_version": RUN_MANIFEST_SCHEMA_VERSION,
        "manifest": manifest,
        "profile": profile,
        "artifacts": dict(artifacts),
    }


def _validate_options(options: EnronPreparationOptions) -> None:
    if not isinstance(options.output_dir, Path):
        raise EnronPreparationError("output_dir must be a path.")
    if not options.dataset_id.strip() or not options.dataset_revision.strip() or not options.dataset_split.strip():
        raise EnronPreparationError("Dataset id, revision, and split must be non-empty.")
    if any(
        not _PROVENANCE_TOKEN_RE.fullmatch(value)
        for value in (options.dataset_id, options.dataset_revision, options.dataset_split)
    ):
        raise EnronPreparationError("Dataset provenance must use a bounded public identifier token.")
    if options.max_rows is not None and (isinstance(options.max_rows, bool) or options.max_rows <= 0):
        raise EnronPreparationError("max_rows must be a positive integer when provided.")
    for name in (
        "max_jsonl_line_bytes",
        "max_body_chars",
        "max_body_bytes",
        "max_subject_chars",
        "max_subject_bytes",
        "max_recipients_per_field",
    ):
        value = getattr(options, name)
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise EnronPreparationError(f"{name} must be a positive integer.")
    hard_limits = {
        "max_jsonl_line_bytes": HARD_MAX_JSONL_LINE_BYTES,
        "max_body_chars": HARD_MAX_BODY_CHARS,
        "max_body_bytes": HARD_MAX_BODY_BYTES,
        "max_subject_chars": HARD_MAX_SUBJECT_CHARS,
        "max_subject_bytes": HARD_MAX_SUBJECT_BYTES,
        "max_recipients_per_field": HARD_MAX_RECIPIENTS_PER_FIELD,
    }
    for name, maximum in hard_limits.items():
        if getattr(options, name) > maximum:
            raise EnronPreparationError(f"{name} exceeds the supported safety limit.")


def _source_context(options: EnronPreparationOptions) -> _SourceContext:
    transport = _TransportState(hashlib.sha256())
    if options.input_jsonl is not None:
        return _SourceContext(
            kind="local_jsonl",
            reader="nerb.strict-bounded-jsonl.v2",
            package_version=None,
            events=_iter_local_events(options.input_jsonl, options.max_jsonl_line_bytes, transport),
            transport=transport,
        )

    if not _IMMUTABLE_REVISION_RE.fullmatch(options.dataset_revision):
        raise EnronPreparationError("Hugging Face Enron preparation requires an immutable commit revision.")
    try:
        datasets_module = importlib.import_module("datasets")
    except ImportError as exc:
        raise EnronPreparationError(
            "Hugging Face streaming requires the optional datasets package and a pinned dataset revision."
        ) from exc
    load_dataset = datasets_module.load_dataset
    rows = load_dataset(
        options.dataset_id,
        split=options.dataset_split,
        streaming=True,
        revision=options.dataset_revision,
    )
    discovered_version = getattr(datasets_module, "__version__", None)
    if not isinstance(discovered_version, str):
        try:
            discovered_version = package_version("datasets")
        except PackageNotFoundError:
            discovered_version = "unknown"
    return _SourceContext(
        kind="huggingface_streaming",
        reader="datasets.load_dataset(streaming=True)",
        package_version=discovered_version,
        events=_iter_huggingface_events(rows),
        transport=transport,
    )


def _iter_local_events(path: Path, max_line_bytes: int, transport: _TransportState) -> Iterator[_InputEvent]:
    with _open_regular_binary(path) as file:
        while True:
            first = file.readline(max_line_bytes + 1)
            if not first:
                break
            transport.physical_lines += 1
            transport.digest.update(first)
            transport.bytes_read += len(first)
            if len(first) > max_line_bytes and not first.endswith(b"\n"):
                line_digest = hashlib.sha256(b"nerb/enron/invalid-source-line/v2\0" + first)
                while not first.endswith(b"\n"):
                    first = file.readline(max_line_bytes + 1)
                    if not first:
                        break
                    line_digest.update(first)
                    transport.digest.update(first)
                    transport.bytes_read += len(first)
                yield _InputEvent(None, "oversized_line", "sha256:" + line_digest.hexdigest(), 0)
                continue
            raw = first[:-1] if first.endswith(b"\n") else first
            if raw.endswith(b"\r"):
                raw = raw[:-1]
            if not raw.strip():
                yield _InputEvent(None, "blank_line", _hash_bytes(b"nerb/enron/blank-line/v2\0" + raw), len(first))
                continue
            raw_digest = _hash_bytes(b"nerb/enron/invalid-source-line/v2\0" + raw)
            try:
                text = raw.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                yield _InputEvent(None, "invalid_utf8", raw_digest, len(first))
                continue
            try:
                value = json.loads(
                    text,
                    object_pairs_hook=_reject_duplicate_keys,
                    parse_constant=_reject_nonfinite,
                    parse_float=_parse_finite_json_float,
                )
            except _DuplicateJsonKey:
                yield _InputEvent(None, "duplicate_json_key", raw_digest, len(first))
                continue
            except _NonfiniteJsonNumber:
                yield _InputEvent(None, "nonfinite_json_number", raw_digest, len(first))
                continue
            except (json.JSONDecodeError, RecursionError, ValueError):
                yield _InputEvent(None, "malformed_json", raw_digest, len(first))
                continue
            if not isinstance(value, Mapping):
                yield _InputEvent(None, "nonobject_json", raw_digest, len(first))
                continue
            yield _InputEvent(value, None, "", len(first))
    transport.complete = True


def _iter_huggingface_events(rows: Iterable[Any]) -> Iterator[_InputEvent]:
    for row in rows:
        if not isinstance(row, Mapping):
            yield _InputEvent(None, "nonobject_row", _hash_text("nerb/enron/nonobject-hf-row/v2"), 0)
            continue
        yield _InputEvent(row, None, "", 0)


def _ingest_source(
    connection: sqlite3.Connection,
    events: Iterable[_InputEvent],
    options: EnronPreparationOptions,
) -> dict[str, Any]:
    counters: Counter[str] = Counter()
    input_records = 0
    event_iterator = iter(events)
    while options.max_rows is None or input_records < options.max_rows:
        try:
            event = next(event_iterator)
        except StopIteration:
            break
        input_records += 1
        if event.error_code is not None:
            counters[event.error_code] += 1
            _record_source_item(connection, event.source_digest)
            _record_rejection(connection, event.source_digest, event.error_code)
            continue
        assert event.row is not None
        validated, validation_error = _validate_source_row(event.row)
        if validated is None:
            counters[validation_error or "invalid_source_schema"] += 1
            digest = _source_mapping_digest(event.row)
            _record_source_item(connection, digest)
            _record_rejection(connection, digest, validation_error or "invalid_source_schema")
            continue
        source_bytes = _canonical_source_bytes(validated.source_projection)
        source_sha256 = _domain_hash("nerb/enron/source-record/v2", source_bytes)
        source_digest = "sha256:" + source_sha256
        _record_source_item(connection, source_digest)
        existing = connection.execute(
            "SELECT source_bytes, source_sha512, occurrence_count FROM records WHERE source_sha256 = ?",
            (source_digest,),
        ).fetchone()
        if existing is not None:
            source_sha512 = hashlib.sha512(source_bytes).digest()
            if int(existing[0]) != len(source_bytes) or bytes(existing[1]) != source_sha512:
                raise EnronPreparationError("A source-record digest collision was detected.")
            connection.execute(
                "UPDATE records SET occurrence_count = occurrence_count + 1 WHERE source_sha256 = ?",
                (source_digest,),
            )
            counters["duplicate_source_rows"] += 1
            continue

        try:
            prepared = _prepare_unique_row(validated, source_digest, options)
        except EnronCleaningError as exc:
            reason = getattr(exc, "code", "cleaning_error")
            if not isinstance(reason, str) or not re.fullmatch(r"[a-z0-9_]{1,64}", reason):
                reason = "cleaning_error"
            body_truncated, subject_truncated = _preclean_truncation_flags(validated, options)
            counters[f"cleaning_rejected_{reason}"] += 1
            if body_truncated:
                counters["body_truncated_before_rejection"] += 1
            if subject_truncated:
                counters["subject_truncated_before_rejection"] += 1
            _record_rejection(
                connection,
                source_digest,
                f"cleaning_{reason}",
                body_truncated=body_truncated,
                subject_truncated=subject_truncated,
            )
            continue
        document_id = _document_id(options.dataset_id, options.dataset_revision, source_sha256)
        payload = dict(prepared.payload)
        payload["document_id"] = document_id
        payload["source"] = {
            **dict(payload["source"]),
            "source_record_sha256": source_digest,
            "identical_occurrence_count": 1,
        }
        connection.execute(
            """
            INSERT INTO records (
                document_id, source_sha256, source_bytes, source_sha512, payload_json_zlib,
                occurrence_count,
                date_utc, exact_content_sha256, message_id_sha256, thread_subject_sha256,
                current_near_duplicate_available, full_near_duplicate_available, mailbox_owner_available
            ) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                document_id,
                source_digest,
                len(source_bytes),
                hashlib.sha512(source_bytes).digest(),
                zlib.compress(_canonical_json(payload).encode("utf-8"), level=1),
                prepared.date_utc,
                prepared.exact_content_sha256,
                prepared.message_id_sha256,
                prepared.thread_subject_sha256,
                int(prepared.current_near_duplicate_available),
                int(prepared.full_near_duplicate_available),
                int(prepared.mailbox_owner_available),
            ),
        )
        counters["accepted_unique_rows"] += 1
    connection.commit()
    return {
        "input_records": input_records,
        "ingestion_counters": dict(sorted(counters.items())),
        "source_multiset_sha256": _source_multiset_hash(connection),
    }


def _validate_source_row(row: Mapping[str, Any]) -> tuple[_ValidatedRow | None, str | None]:
    if any(not isinstance(key, str) for key in row):
        return None, "nonstring_field_name"
    unknown = set(row) - _EXPECTED_FIELDS
    if unknown:
        return None, "unknown_source_fields"
    projected: dict[str, Any] = {}
    strings: dict[str, str] = {}
    for field in _TEXT_FIELDS:
        value = row.get(field)
        if value is None:
            strings[field] = ""
            projected[field] = None
        elif isinstance(value, str):
            try:
                value.encode("utf-8", errors="strict")
            except UnicodeEncodeError:
                return None, f"invalid_{field}_unicode"
            strings[field] = value
            projected[field] = value
        else:
            return None, f"invalid_{field}_type"
        if field in {"message_id", "from", "file_name"} and len(strings[field]) > DEFAULT_MAX_HEADER_CHARS:
            return None, f"oversized_{field}"
    recipients: dict[str, tuple[str, ...]] = {}
    for field in _RECIPIENT_FIELDS:
        value = row.get(field)
        if value is None:
            recipients[field] = ()
            projected[field] = None
            continue
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
            return None, f"invalid_{field}_type"
        if any(not isinstance(item, str) for item in value):
            return None, f"invalid_{field}_item_type"
        try:
            for item in value:
                item.encode("utf-8", errors="strict")
                if len(item) > DEFAULT_MAX_HEADER_CHARS:
                    return None, f"oversized_{field}_item"
        except UnicodeEncodeError:
            return None, f"invalid_{field}_unicode"
        recipients[field] = tuple(value)
        projected[field] = list(value)
    raw_date = row.get("date")
    if raw_date is not None and not isinstance(raw_date, (str, datetime)):
        return None, "invalid_date_type"
    if isinstance(raw_date, str):
        try:
            raw_date.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            return None, "invalid_date_unicode"
    projected["date"] = _source_date_projection(raw_date)
    return (
        _ValidatedRow(
            source_projection=projected,
            message_id=strings["message_id"],
            subject=strings["subject"],
            sender=strings["from"],
            recipients=recipients,
            date=raw_date,
            body=strings["body"],
            file_name=strings["file_name"],
        ),
        None,
    )


def _prepare_unique_row(
    row: _ValidatedRow,
    source_sha256: str,
    options: EnronPreparationOptions,
) -> _PreparedUnique:
    stats: Counter[str] = Counter()
    decoded_subject, subject_decode_stats = _decode_header_text_with_audit(row.subject)
    stats.update(subject_decode_stats)
    limited_subject, subject_truncated = _truncate_utf8(
        decoded_subject,
        options.max_subject_chars,
        options.max_subject_bytes,
    )
    if subject_truncated:
        stats["subject_truncated"] += 1
    cleaned_subject, subject_cleaning_stats = _cleaned_subject_text(limited_subject, options)
    for key, value in subject_cleaning_stats.items():
        stats[f"subject_{key}"] += value

    limited_body, body_truncated = _truncate_utf8(row.body, options.max_body_chars, options.max_body_bytes)
    if body_truncated:
        stats["body_truncated"] += 1
    cleaned_body = clean_email_body(
        limited_body,
        max_chars=options.max_body_chars,
        max_utf8_bytes=options.max_body_bytes,
    )
    full_visible_body = _clean_body_value(cleaned_body, "full_visible_body")
    current_body = _clean_body_value(cleaned_body, "current_body")
    current_body_core = _clean_body_value(cleaned_body, "current_body_core")
    body_counters = _cleaning_counters(cleaned_body)
    for key, value in body_counters.items():
        stats[key] += value
    if body_counters.get("html_detected", 0):
        stats["html_decoded"] += 1
    if any(body_counters.get(key, 0) for key in ("mime_detected", "quoted_printable_decoded", "base64_decoded")):
        stats["mime_decoded"] += 1

    subject_current_body = "\n\n".join(part for part in (cleaned_subject, current_body) if part)
    headers, header_stats = _structured_headers(row, options.max_recipients_per_field)
    stats.update(header_stats)
    normalized_header_message_id, message_id_stats = _normalize_header_scalar_with_audit(row.message_id)
    stats.update(message_id_stats)
    date_payload = _parse_date(row.date)
    stats[f"date_{date_payload['status']}"] += 1
    mailbox_owner_sha256, mailbox_folder_role, mailbox_status = _mailbox_locator_features(row.file_name)
    stats[f"mailbox_locator_{mailbox_status}"] += 1
    if mailbox_folder_role is not None:
        stats[f"mailbox_folder_{mailbox_folder_role}"] += 1

    normalized_message_id = _normalize_message_id(normalized_header_message_id)
    message_id_sha256 = _private_feature_hash("message-id", normalized_message_id) if normalized_message_id else None
    thread_subject = normalize_thread_subject(cleaned_subject)
    thread_subject_sha256 = _private_feature_hash("thread-subject", thread_subject) if thread_subject else None
    participant_values = _participant_values(headers)
    participant_set_sha256 = (
        _private_feature_hash("participant-set", "\n".join(sorted(participant_values))) if participant_values else None
    )
    embedded_message_ids, embedded_message_ids_truncated = _embedded_message_id_features(full_visible_body)
    if embedded_message_ids_truncated:
        stats["embedded_message_ids_truncated"] += 1
    current_near_text = current_body_core or current_body
    current_near_duplicate = _near_duplicate_features(current_near_text)
    full_near_duplicate = (
        current_near_duplicate
        if full_visible_body == current_near_text
        else _near_duplicate_features(full_visible_body)
    )

    view_metadata = {
        name: _text_metadata(
            value,
            truncated=body_truncated or (subject_truncated and name == "subject_current_body"),
        )
        for name, value in (
            ("full_visible_body", full_visible_body),
            ("current_body", current_body),
            ("subject_current_body", subject_current_body),
            ("current_body_core", current_body_core),
        )
    }
    exact_content_sha256 = _private_feature_hash("subject-current-body", subject_current_body)
    grouping = {
        "policy_sha256": GROUPING_POLICY_SHA256,
        "exact": {
            "content_sha256": exact_content_sha256,
            "full_visible_body_sha256": _private_feature_hash("full-visible-body", full_visible_body),
            "current_body_sha256": _private_feature_hash("current-body", current_body),
            "current_body_core_sha256": _private_feature_hash("current-body-core", current_body_core),
        },
        "normalized_message_id_sha256": message_id_sha256,
        "normalized_thread_subject_sha256": thread_subject_sha256,
        "participant_set_sha256": participant_set_sha256,
        "embedded_message_id_sha256s": embedded_message_ids,
        "embedded_message_id_scan": {
            "body_chars_scanned": len(full_visible_body),
            "ids_truncated": embedded_message_ids_truncated,
            "max_ids": 64,
        },
        "near_duplicate": {
            "current_body_core": current_near_duplicate,
            "full_visible_body": full_near_duplicate,
        },
    }
    payload = {
        "schema_version": PREPARED_RECORD_SCHEMA_VERSION,
        "status": "prepared",
        "source": {
            "dataset_id": options.dataset_id,
            "revision": options.dataset_revision,
            "split": options.dataset_split,
            "source_locator_sha256": _private_feature_hash("source-locator", row.file_name) if row.file_name else None,
            "mailbox_owner_sha256": mailbox_owner_sha256,
            "mailbox_folder_role": mailbox_folder_role,
        },
        "date": date_payload,
        "headers": {
            "message_id": normalized_header_message_id,
            "subject": cleaned_subject,
            **headers,
        },
        "views": {
            "full_visible_body": full_visible_body,
            "current_body": current_body,
            "subject_current_body": subject_current_body,
            "current_body_core": current_body_core,
            "structured_headers": headers,
        },
        "view_metadata": view_metadata,
        "cleaning": {
            "policy_version": CLEANING_POLICY_VERSION,
            "policy_sha256": CLEANING_POLICY_REF,
            "source_body_sha256": _private_feature_hash("source-body", row.body),
            "transform_counts": dict(sorted(stats.items())),
            "body_truncated": body_truncated,
            "subject_truncated": subject_truncated,
        },
        "grouping": grouping,
    }
    return _PreparedUnique(
        payload=payload,
        date_utc=date_payload.get("utc") if isinstance(date_payload.get("utc"), str) else None,
        exact_content_sha256=exact_content_sha256,
        message_id_sha256=message_id_sha256,
        thread_subject_sha256=thread_subject_sha256,
        current_near_duplicate_available=bool(current_near_duplicate.get("simhash64")),
        full_near_duplicate_available=bool(full_near_duplicate.get("simhash64")),
        mailbox_owner_available=mailbox_owner_sha256 is not None,
    )


def _write_prepared_records(
    connection: sqlite3.Connection,
    file: TextIO,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    artifact_digest = hashlib.sha256()
    artifact_bytes = 0
    unique_records = 0
    occurrence_count = 0
    stats: Counter[str] = Counter()
    date_counts: Counter[str] = Counter()
    size_histogram: Counter[str] = Counter()
    view_digests = {
        name: hashlib.sha256(f"nerb/enron/view/{name}/v2\0".encode())
        for name in ("full_visible_body", "current_body", "subject_current_body", "current_body_core")
    }
    view_bytes: Counter[str] = Counter()
    view_empty: Counter[str] = Counter()
    earliest_date: str | None = None
    latest_date: str | None = None
    earliest_eligible_date: str | None = None
    latest_eligible_date: str | None = None
    rows = connection.execute(
        """
        SELECT document_id, payload_json_zlib, occurrence_count, date_utc
        FROM records ORDER BY document_id
        """
    )
    for document_id, payload_json_zlib, occurrences, date_utc in rows:
        payload = json.loads(zlib.decompress(payload_json_zlib))
        payload["source"]["identical_occurrence_count"] = occurrences
        line = (_canonical_json(payload) + "\n").encode("utf-8")
        file.write(line.decode("utf-8"))
        artifact_digest.update(line)
        artifact_bytes += len(line)
        unique_records += 1
        occurrence_count += occurrences
        row_stats = payload["cleaning"]["transform_counts"]
        for key, value in row_stats.items():
            stats[str(key)] += int(value) * occurrences
        date_status = str(payload["date"]["status"])
        date_counts[date_status] += occurrences
        if isinstance(date_utc, str):
            earliest_date = date_utc if earliest_date is None or date_utc < earliest_date else earliest_date
            latest_date = date_utc if latest_date is None or date_utc > latest_date else latest_date
            if date_status == "valid":
                earliest_eligible_date = (
                    date_utc
                    if earliest_eligible_date is None or date_utc < earliest_eligible_date
                    else earliest_eligible_date
                )
                latest_eligible_date = (
                    date_utc
                    if latest_eligible_date is None or date_utc > latest_eligible_date
                    else latest_eligible_date
                )
        current_bytes = len(payload["views"]["current_body"].encode("utf-8"))
        size_histogram[_size_bucket(current_bytes)] += occurrences
        for name, digest in view_digests.items():
            text = payload["views"][name]
            projection = (_canonical_json({"document_id": document_id, "text": text}) + "\n").encode("utf-8")
            digest.update(projection)
            view_bytes[name] += len(projection)
            if not text:
                view_empty[name] += occurrences
    file.flush()

    prepared_descriptor = {
        "id": "prepared_records",
        "name": _PREPARED_FILENAME,
        "sha256": "sha256:" + artifact_digest.hexdigest(),
        "bytes": artifact_bytes,
        "records": unique_records,
        "occurrences": occurrence_count,
        "ordering": "document_id_ascending",
    }
    view_descriptors = [
        {
            "id": name,
            "artifact_kind": "virtual_prepared_projection",
            "artifact_sha256": "sha256:" + view_digests[name].hexdigest(),
            "projection_bytes": view_bytes[name],
            "records": unique_records,
            "empty_occurrences": view_empty[name],
            "regions": _view_regions(name),
            "answer_bearing_fields_included": False,
            "primary_for_quality": name == "subject_current_body",
        }
        for name in view_digests
    ]
    duplicates = _duplicate_aggregates(connection)
    features = _feature_aggregates(connection)
    return (
        prepared_descriptor,
        view_descriptors,
        {
            "unique_records": unique_records,
            "occurrences": occurrence_count,
            "cleaning": dict(sorted(stats.items())),
            "dates": {
                "status_counts": dict(sorted(date_counts.items())),
                "all_parseable_earliest_month": earliest_date[:7] if earliest_date is not None else None,
                "all_parseable_latest_month": latest_date[:7] if latest_date is not None else None,
                "temporal_eligible_earliest_month": (
                    earliest_eligible_date[:7] if earliest_eligible_date is not None else None
                ),
                "temporal_eligible_latest_month": (
                    latest_eligible_date[:7] if latest_eligible_date is not None else None
                ),
            },
            "current_body_utf8_bytes_histogram": dict(sorted(size_histogram.items())),
            "duplicates": duplicates,
            "grouping_features": features,
        },
    )


def _write_rejections(connection: sqlite3.Connection, file: TextIO) -> dict[str, Any]:
    digest = hashlib.sha256()
    artifact_bytes = 0
    records = 0
    occurrences = 0
    for source_digest, reason, body_truncated, subject_truncated, occurrence_count in connection.execute(
        """
        SELECT source_digest, reason, body_truncated, subject_truncated, occurrence_count
        FROM rejections ORDER BY source_digest, reason
        """
    ):
        payload = {
            "schema_version": REJECTION_RECORD_SCHEMA_VERSION,
            "source_digest_sha256": source_digest,
            "reason": reason,
            "occurrence_count": occurrence_count,
            "body_truncated_before_rejection": bool(body_truncated),
            "subject_truncated_before_rejection": bool(subject_truncated),
        }
        line = (_canonical_json(payload) + "\n").encode("utf-8")
        file.write(line.decode("utf-8"))
        digest.update(line)
        artifact_bytes += len(line)
        records += 1
        occurrences += int(occurrence_count)
    file.flush()
    return {
        "id": "rejections",
        "name": _REJECTIONS_FILENAME,
        "sha256": "sha256:" + digest.hexdigest(),
        "bytes": artifact_bytes,
        "records": records,
        "occurrences": occurrences,
        "ordering": "source_digest_reason_ascending",
    }


def _validate_source_volume(
    options: EnronPreparationOptions,
    source: _SourceContext,
    ingest: Mapping[str, Any],
    aggregates: Mapping[str, Any],
) -> None:
    if source.kind != "huggingface_streaming":
        return
    input_records = int(ingest["input_records"])
    prepared_occurrences = int(aggregates["occurrences"])
    if input_records == 0 or prepared_occurrences == 0:
        raise EnronPreparationError("Hugging Face Enron preparation produced no usable source records.")
    is_pinned_full_source = (
        options.dataset_id == DEFAULT_DATASET_ID
        and options.dataset_revision == DEFAULT_DATASET_REVISION
        and options.dataset_split == DEFAULT_DATASET_SPLIT
        and options.max_rows is None
    )
    if is_pinned_full_source and input_records != PINNED_DATASET_RECORDS:
        raise EnronPreparationError("Pinned Enron source record count does not match its frozen descriptor.")


def _profile_payload(
    options: EnronPreparationOptions,
    source: _SourceContext,
    ingest: Mapping[str, Any],
    aggregates: Mapping[str, Any],
    prepared_descriptor: Mapping[str, Any],
    rejection_descriptor: Mapping[str, Any],
    view_descriptors: Sequence[Mapping[str, Any]],
    *,
    implementation_sha256: str,
    runtime_provenance: Mapping[str, str],
) -> dict[str, Any]:
    source_multiset_sha256 = str(ingest["source_multiset_sha256"])
    if not _SHA256_RE.fullmatch(source_multiset_sha256):
        raise EnronPreparationError("The source row-multiset commitment is invalid.")
    input_records = int(ingest["input_records"])
    occurrences = int(aggregates["occurrences"])
    rejected = input_records - occurrences
    if rejection_descriptor.get("occurrences") != rejected:
        raise EnronPreparationError("Private rejection audit does not conserve source records.")
    return {
        "schema_version": PROFILE_SCHEMA_VERSION,
        "artifact_kind": "privacy_safe_aggregate",
        "source": {
            "kind": source.kind,
            "dataset_id": options.dataset_id,
            "revision": options.dataset_revision,
            "split": options.dataset_split,
            "reader": source.reader,
            "reader_package_version": source.package_version,
            "input_schema_sha256": INPUT_SCHEMA_SHA256,
            "canonical_row_multiset_hash_algorithm": _SOURCE_MULTISET_HASH_ALGORITHM,
            "canonical_row_multiset_sha256": source_multiset_sha256,
            "input_records": input_records,
            "row_limit": options.max_rows,
        },
        "policies": {
            "cleaning_version": CLEANING_POLICY_VERSION,
            "cleaning_policy_sha256": CLEANING_POLICY_REF,
            "date_policy_sha256": DATE_POLICY_SHA256,
            "grouping_text_version": GROUPING_TEXT_POLICY_VERSION,
            "grouping_text_policy_sha256": GROUPING_TEXT_POLICY_REF,
            "grouping_policy_sha256": GROUPING_POLICY_SHA256,
        },
        "records": {
            "input_records": input_records,
            "prepared_occurrences": occurrences,
            "unique_prepared_records": aggregates["unique_records"],
            "rejected_records": rejected,
            "conservation_valid": input_records == occurrences + rejected,
            "ingestion_errors": ingest["ingestion_counters"],
        },
        "cleaning": aggregates["cleaning"],
        "dates": aggregates["dates"],
        "sizes": {"current_body_utf8_bytes": aggregates["current_body_utf8_bytes_histogram"]},
        "duplicates": aggregates["duplicates"],
        "grouping_features": aggregates["grouping_features"],
        "limits": {
            "max_jsonl_line_bytes": options.max_jsonl_line_bytes,
            "max_body_chars": options.max_body_chars,
            "max_body_bytes": options.max_body_bytes,
            "max_subject_chars": options.max_subject_chars,
            "max_subject_bytes": options.max_subject_bytes,
            "max_recipients_per_field": options.max_recipients_per_field,
        },
        "artifacts": {
            "prepared_records": dict(prepared_descriptor),
            "rejections": dict(rejection_descriptor),
        },
        "text_views": [dict(item) for item in view_descriptors],
        "software": {
            "nerb_version": __version__,
            "preparation_implementation_sha256": implementation_sha256,
            **dict(runtime_provenance),
        },
        "privacy": {
            "raw_text_included": False,
            "direct_identifiers_included": False,
            "absolute_paths_included": False,
            "per_record_features_included": False,
            "aggregate_only": True,
        },
    }


def _manifest_payload(
    profile: Mapping[str, Any],
    prepared_descriptor: Mapping[str, Any],
    rejection_descriptor: Mapping[str, Any],
    profile_descriptor: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": RUN_MANIFEST_SCHEMA_VERSION,
        "source": dict(profile["source"]),
        "preparation": {
            "cleaning_policy_sha256": CLEANING_POLICY_REF,
            "date_policy_sha256": DATE_POLICY_SHA256,
            "grouping_policy_sha256": GROUPING_POLICY_SHA256,
            "output_records": profile["records"]["unique_prepared_records"],
            "output_occurrences": profile["records"]["prepared_occurrences"],
            "text_views": profile["text_views"],
        },
        "artifacts": {
            "prepared_records": dict(prepared_descriptor),
            "rejections": dict(rejection_descriptor),
            "profile": dict(profile_descriptor),
        },
        "privacy": dict(profile["privacy"]),
    }


def _write_transport_receipt(file: TextIO, source: _SourceContext, started: float) -> None:
    local_source = source.kind == "local_jsonl"
    payload = {
        "schema_version": "nerb.enron_transport_receipt.v2",
        "canonical": False,
        "source_kind": source.kind,
        "transport_complete": source.transport.complete if local_source else None,
        "transport_sha256": (
            "sha256:" + source.transport.digest.hexdigest() if local_source and source.transport.complete else None
        ),
        "transport_prefix_sha256": (
            "sha256:" + source.transport.digest.hexdigest() if local_source and not source.transport.complete else None
        ),
        "transport_bytes": source.transport.bytes_read if local_source else None,
        "physical_lines": source.transport.physical_lines if local_source else None,
        "elapsed_seconds": round(time.perf_counter() - started, 6),
    }
    _write_json_file(file, payload)


def _open_spool(path: Path) -> sqlite3.Connection:
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    os.close(descriptor)
    path.chmod(0o600)
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA journal_mode=DELETE")
    connection.execute("PRAGMA synchronous=FULL")
    connection.execute("PRAGMA temp_store=MEMORY")
    connection.execute("PRAGMA cache_size=-16384")
    connection.execute(
        """
        CREATE TABLE records (
            document_id TEXT PRIMARY KEY,
            source_sha256 TEXT NOT NULL UNIQUE,
            source_bytes INTEGER NOT NULL,
            source_sha512 BLOB NOT NULL,
            payload_json_zlib BLOB NOT NULL,
            occurrence_count INTEGER NOT NULL,
            date_utc TEXT,
            exact_content_sha256 TEXT NOT NULL,
            message_id_sha256 TEXT,
            thread_subject_sha256 TEXT,
            current_near_duplicate_available INTEGER NOT NULL,
            full_near_duplicate_available INTEGER NOT NULL,
            mailbox_owner_available INTEGER NOT NULL
        )
        """
    )
    connection.execute("CREATE TABLE source_items (source_digest TEXT PRIMARY KEY, occurrence_count INTEGER NOT NULL)")
    connection.execute(
        """
        CREATE TABLE rejections (
            source_digest TEXT NOT NULL,
            reason TEXT NOT NULL,
            body_truncated INTEGER NOT NULL,
            subject_truncated INTEGER NOT NULL,
            occurrence_count INTEGER NOT NULL,
            PRIMARY KEY (source_digest, reason)
        )
        """
    )
    connection.execute("CREATE INDEX records_exact_content_idx ON records (exact_content_sha256)")
    connection.execute("CREATE INDEX records_message_id_idx ON records (message_id_sha256)")
    return connection


def _open_duplicate_verification_spool(path: Path) -> sqlite3.Connection:
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    os.close(descriptor)
    path.chmod(0o600)
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA journal_mode=OFF")
    connection.execute("PRAGMA synchronous=OFF")
    connection.execute("PRAGMA temp_store=FILE")
    connection.execute("PRAGMA cache_size=-16384")
    connection.execute(
        """
        CREATE TABLE records (
            occurrence_count INTEGER NOT NULL,
            exact_content_sha256 TEXT NOT NULL,
            message_id_sha256 TEXT
        )
        """
    )
    connection.execute("CREATE INDEX records_exact_content_idx ON records (exact_content_sha256)")
    connection.execute("CREATE INDEX records_message_id_idx ON records (message_id_sha256)")
    return connection


def _record_source_item(connection: sqlite3.Connection, digest: str) -> None:
    connection.execute(
        """
        INSERT INTO source_items (source_digest, occurrence_count) VALUES (?, 1)
        ON CONFLICT(source_digest) DO UPDATE SET occurrence_count = occurrence_count + 1
        """,
        (digest,),
    )


def _record_rejection(
    connection: sqlite3.Connection,
    source_digest: str,
    reason: str,
    *,
    body_truncated: bool = False,
    subject_truncated: bool = False,
) -> None:
    if not _SHA256_RE.fullmatch(source_digest) or not re.fullmatch(r"[a-z0-9_]{1,96}", reason):
        raise EnronPreparationError("Private rejection audit value is invalid.")
    connection.execute(
        """
        INSERT INTO rejections (
            source_digest, reason, body_truncated, subject_truncated, occurrence_count
        ) VALUES (?, ?, ?, ?, 1)
        ON CONFLICT(source_digest, reason) DO UPDATE SET
            body_truncated = MAX(body_truncated, excluded.body_truncated),
            subject_truncated = MAX(subject_truncated, excluded.subject_truncated),
            occurrence_count = occurrence_count + 1
        """,
        (source_digest, reason, int(body_truncated), int(subject_truncated)),
    )


def _preclean_truncation_flags(
    row: _ValidatedRow,
    options: EnronPreparationOptions,
) -> tuple[bool, bool]:
    _, body_truncated = _truncate_utf8(row.body, options.max_body_chars, options.max_body_bytes)
    decoded_subject = _decode_header_text(row.subject)
    _, subject_truncated = _truncate_utf8(
        decoded_subject,
        options.max_subject_chars,
        options.max_subject_bytes,
    )
    return body_truncated, subject_truncated


def _source_multiset_hash(connection: sqlite3.Connection) -> str:
    accumulator = 0
    occurrences = 0
    for source_digest, occurrence_count in connection.execute(
        "SELECT source_digest, occurrence_count FROM source_items"
    ):
        accumulator, occurrences = _add_source_multiset_item(
            accumulator,
            occurrences,
            str(source_digest),
            int(occurrence_count),
        )
    return _finalize_source_multiset_hash(accumulator, occurrences)


def _add_source_multiset_item(
    accumulator: int,
    total_occurrences: int,
    source_digest: str,
    occurrence_count: int,
) -> tuple[int, int]:
    if not _SHA256_RE.fullmatch(source_digest) or occurrence_count <= 0:
        raise EnronPreparationError("Source multiset item is invalid.")
    leaf = int.from_bytes(
        hashlib.sha512(b"nerb/enron/source-row-multiset-leaf/v2\0" + source_digest.encode("ascii")).digest(),
        "big",
    )
    return (
        (accumulator + leaf * occurrence_count) % _SOURCE_MULTISET_MODULUS,
        total_occurrences + occurrence_count,
    )


def _finalize_source_multiset_hash(accumulator: int, occurrences: int) -> str:
    payload = occurrences.to_bytes(16, "big") + accumulator.to_bytes(64, "big")
    return _domain_hash_prefixed("nerb/enron/source-row-multiset/v2", payload.hex())


def _duplicate_aggregates(connection: sqlite3.Connection) -> dict[str, Any]:
    source_duplicates, source_duplicate_groups, source_histogram = _fold_group_sizes(
        connection.execute("SELECT occurrence_count FROM records")
    )
    content_duplicates, content_duplicate_groups, content_histogram = _fold_group_sizes(
        connection.execute("SELECT SUM(occurrence_count) FROM records GROUP BY exact_content_sha256")
    )
    message_duplicates, message_duplicate_groups, message_histogram = _fold_group_sizes(
        connection.execute(
            """
            SELECT SUM(occurrence_count) FROM records
            WHERE message_id_sha256 IS NOT NULL GROUP BY message_id_sha256
            """
        )
    )
    return {
        "duplicate_source_row_occurrences": source_duplicates,
        "duplicate_source_groups": source_duplicate_groups,
        "source_group_size_histogram": source_histogram,
        "duplicate_exact_content_occurrences": content_duplicates,
        "duplicate_exact_content_groups": content_duplicate_groups,
        "exact_content_group_size_histogram": content_histogram,
        "duplicate_message_id_occurrences": message_duplicates,
        "duplicate_message_id_groups": message_duplicate_groups,
        "message_id_group_size_histogram": message_histogram,
    }


def _fold_group_sizes(rows: Iterable[Sequence[Any]]) -> tuple[int, int, dict[str, int]]:
    duplicate_occurrences = 0
    duplicate_groups = 0
    histogram: Counter[str] = Counter()
    for row in rows:
        size = int(row[0])
        duplicate_occurrences += max(0, size - 1)
        duplicate_groups += int(size > 1)
        histogram[_group_size_bucket(size)] += 1
    return duplicate_occurrences, duplicate_groups, dict(sorted(histogram.items()))


def _feature_aggregates(connection: sqlite3.Connection) -> dict[str, Any]:
    row = connection.execute(
        """
        SELECT
            COALESCE(SUM(occurrence_count), 0),
            COALESCE(SUM(CASE WHEN message_id_sha256 IS NOT NULL THEN occurrence_count ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN thread_subject_sha256 IS NOT NULL THEN occurrence_count ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN current_near_duplicate_available = 1 THEN occurrence_count ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN full_near_duplicate_available = 1 THEN occurrence_count ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN mailbox_owner_available = 1 THEN occurrence_count ELSE 0 END), 0)
        FROM records
        """
    ).fetchone()
    return {
        "prepared_occurrences": int(row[0]),
        "message_id_available": int(row[1]),
        "thread_subject_available": int(row[2]),
        "current_near_duplicate_signature_available": int(row[3]),
        "full_visible_near_duplicate_signature_available": int(row[4]),
        "mailbox_owner_available": int(row[5]),
    }


def _cleaned_subject_text(value: str, options: EnronPreparationOptions) -> tuple[str, dict[str, int]]:
    cleaned = clean_subject(value, max_chars=options.max_subject_chars, max_utf8_bytes=options.max_subject_bytes)
    if isinstance(cleaned, str):
        return cleaned, {}
    for attribute in ("text", "value", "cleaned"):
        candidate = getattr(cleaned, attribute, None)
        if isinstance(candidate, str):
            return candidate, _cleaning_counters(cleaned)
    raise EnronPreparationError("The subject cleaner returned an invalid result.")


def _clean_body_value(cleaned: Any, name: str) -> str:
    candidate = getattr(cleaned, name, None)
    if isinstance(candidate, str):
        return candidate
    if isinstance(cleaned, Mapping) and isinstance(cleaned.get(name), str):
        return str(cleaned[name])
    raise EnronPreparationError("The body cleaner returned an invalid result.")


def _cleaning_counters(cleaned: Any) -> dict[str, int]:
    for attribute in ("transform_counts", "counters", "actions"):
        candidate = getattr(cleaned, attribute, None)
        if isinstance(candidate, Mapping):
            return {
                str(key): int(value)
                for key, value in candidate.items()
                if isinstance(value, int) and not isinstance(value, bool) and value > 0
            }
    return {}


def _structured_headers(row: _ValidatedRow, limit: int) -> tuple[dict[str, Any], Counter[str]]:
    stats: Counter[str] = Counter()
    sender_values, sender_dropped, sender_stats = _normalize_address_values((row.sender,), 1)
    stats.update(sender_stats)
    if sender_dropped:
        stats["sender_values_truncated"] += sender_dropped
    headers: dict[str, Any] = {"from": sender_values}
    for field in _RECIPIENT_FIELDS:
        values = row.recipients[field]
        normalized, dropped, field_stats = _normalize_address_values(values, limit)
        stats.update(field_stats)
        if dropped:
            stats["recipient_values_truncated"] += dropped
            stats[f"{field}_recipient_truncated"] += 1
        headers[field] = normalized
    return headers, stats


def _normalize_address_values(
    values: Sequence[str],
    limit: int,
) -> tuple[list[dict[str, str]], int, Counter[str]]:
    normalized: list[dict[str, str]] = []
    dropped = 0
    stats: Counter[str] = Counter()
    for value in values:
        try:
            parsed = getaddresses([value])
        except (TypeError, ValueError):
            stats["header_parse_errors"] += 1
            continue
        if value.strip() and not parsed:
            stats["header_addresses_dropped"] += 1
        for raw_name, raw_address in parsed:
            decoded_name, decode_stats = _decode_header_text_with_audit(raw_name)
            stats.update(decode_stats)
            name, name_stats = _normalize_header_scalar_with_audit(decoded_name)
            address, address_stats = _normalize_header_scalar_with_audit(raw_address)
            stats.update(name_stats)
            stats.update(address_stats)
            address = address.casefold()
            if not name and not address:
                stats["header_addresses_dropped"] += 1
                continue
            if address and "@" not in address:
                stats["header_noncanonical_addresses"] += 1
            if len(normalized) < limit:
                normalized.append({"name": name, "address": address})
            else:
                dropped += 1
    return normalized, dropped, stats


def _normalize_header_scalar(value: str) -> str:
    return _normalize_header_scalar_with_audit(value)[0]


def _normalize_header_scalar_with_audit(value: str) -> tuple[str, Counter[str]]:
    stats: Counter[str] = Counter()
    limited, truncated = _truncate_utf8(value, DEFAULT_MAX_HEADER_CHARS, DEFAULT_MAX_HEADER_CHARS * 4)
    if truncated:
        stats["header_scalars_truncated"] += 1
    cleaned = normalize_natural_text(
        limited,
        "structured_header",
        max_chars=DEFAULT_MAX_HEADER_CHARS,
        max_utf8_bytes=DEFAULT_MAX_HEADER_CHARS * 4,
    )
    for key, count in _cleaning_counters(cleaned).items():
        stats[f"header_{key}"] += count
    collapsed = " ".join(cleaned.text.split())
    if collapsed != cleaned.text:
        stats["header_whitespace_collapsed"] += 1
    return collapsed, stats


def _decode_header_text(value: str) -> str:
    return _decode_header_text_with_audit(value)[0]


def _decode_header_text_with_audit(value: str) -> tuple[str, Counter[str]]:
    stats: Counter[str] = Counter()
    if not value:
        return "", stats
    parts: list[str] = []
    try:
        decoded = decode_header(value)
    except (HeaderParseError, LookupError, ValueError):
        stats["header_decode_errors"] += 1
        return value, stats
    for item, charset in decoded:
        if isinstance(item, bytes):
            stats["header_encoded_words_decoded"] += 1
            try:
                decoded_item = item.decode(charset or "ascii", errors="replace")
            except (LookupError, UnicodeError):
                stats["header_decode_errors"] += 1
                decoded_item = item.decode("utf-8", errors="replace")
            replacement_chars = decoded_item.count("\ufffd")
            if replacement_chars:
                stats["header_decode_replacement_chars"] += replacement_chars
            parts.append(decoded_item)
        else:
            parts.append(item)
    return "".join(parts), stats


def _parse_date(value: Any) -> dict[str, Any]:
    if value is None or value == "":
        return {"status": "missing", "utc": None, "original_offset_minutes": None, "temporal_eligible": False}
    parsed: datetime
    try:
        if isinstance(value, datetime):
            parsed = value
        elif isinstance(value, str):
            candidate = value.strip()
            if not candidate:
                return {
                    "status": "missing",
                    "utc": None,
                    "original_offset_minutes": None,
                    "temporal_eligible": False,
                }
            try:
                parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
            except ValueError:
                parsed = parsedate_to_datetime(candidate)
        else:
            raise ValueError
    except (TypeError, ValueError, OverflowError):
        return {"status": "invalid", "utc": None, "original_offset_minutes": None, "temporal_eligible": False}
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return {
            "status": "ambiguous_timezone",
            "utc": None,
            "original_offset_minutes": None,
            "temporal_eligible": False,
        }
    offset = parsed.utcoffset()
    assert offset is not None
    offset_minutes = int(offset.total_seconds() // 60)
    normalized = parsed.astimezone(timezone.utc)
    utc_text = _format_utc(normalized)
    out_of_range = normalized < datetime(1990, 1, 1, tzinfo=timezone.utc) or normalized >= datetime(
        2011, 1, 1, tzinfo=timezone.utc
    )
    return {
        "status": "out_of_range" if out_of_range else "valid",
        "utc": utc_text,
        "original_offset_minutes": offset_minutes,
        "temporal_eligible": not out_of_range,
    }


def _format_utc(value: datetime) -> str:
    if value.microsecond:
        return value.isoformat(timespec="microseconds").replace("+00:00", "Z")
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _source_date_projection(value: Any) -> Any:
    if isinstance(value, datetime):
        if value.tzinfo is not None and value.utcoffset() is not None:
            return {"type": "datetime", "value": _format_utc(value.astimezone(timezone.utc))}
        return {"type": "naive_datetime", "value": value.isoformat(timespec="microseconds")}
    return value


def _mailbox_locator_features(value: str) -> tuple[str | None, str | None, str]:
    if not value:
        return None, None, "missing"
    normalized = unicodedata.normalize("NFC", value).replace("\\", "/")
    parts = normalized.split("/")
    if len(parts) < 2 or any(not part or part in {".", ".."} for part in parts):
        return None, None, "invalid"
    owner_index = 1 if parts[0].casefold() == "maildir" else 0
    if owner_index >= len(parts) - 1:
        return None, None, "invalid"
    owner = parts[owner_index].strip().casefold()
    if not owner:
        return None, None, "invalid"
    folder_parts = [re.sub(r"[^a-z0-9]+", "_", part.casefold()).strip("_") for part in parts[owner_index + 1 : -1]]
    folder_role = _mailbox_folder_role(folder_parts)
    return _private_feature_hash("mailbox-owner", owner), folder_role, "parsed"


def _mailbox_folder_role(parts: Sequence[str]) -> str:
    for role in ("sent", "inbox", "deleted", "draft", "archive"):
        if any(part in _MAILBOX_FOLDER_ROLE_TOKENS[role] for part in parts):
            return role
    return "other"


def _normalize_message_id(value: str) -> str | None:
    normalized = unicodedata.normalize("NFC", value).strip().strip("<>").casefold()
    normalized = "".join(normalized.split())
    return normalized or None


def _participant_values(headers: Mapping[str, Any]) -> set[str]:
    values: set[str] = set()
    for field in ("from", "to", "cc", "bcc"):
        entries = headers.get(field)
        if not isinstance(entries, Sequence):
            continue
        for entry in entries:
            if not isinstance(entry, Mapping):
                continue
            address = entry.get("address")
            name = entry.get("name")
            if isinstance(address, str) and address:
                values.add("address:" + address)
            elif isinstance(name, str) and name:
                values.add("name:" + normalize_grouping_text(name))
    return values


def _embedded_message_id_features(text: str) -> tuple[list[str], bool]:
    normalized: set[str] = set()
    truncated = False
    for header_match in _MESSAGE_ID_RE.finditer(text):
        for match in _ANGLE_MESSAGE_ID_RE.finditer(header_match.group(1)):
            message_id = _normalize_message_id(match.group(0))
            if message_id:
                normalized.add(message_id)
            if len(normalized) > 64:
                truncated = True
                break
        if truncated:
            break
    retained = sorted(normalized)[:64]
    return [_private_feature_hash("message-id", value) for value in retained], truncated


def _near_duplicate_features(text: str) -> dict[str, Any]:
    normalized = normalize_grouping_text(text)
    window: deque[str] = deque(maxlen=3)
    selected: set[int] = set()
    largest_first: list[int] = []
    token_count = 0
    for match in _TOKEN_RE.finditer(normalized):
        token_count += 1
        window.append(match.group(0))
        if len(window) < 3:
            continue
        shingle_hash = _hash64("near-shingle", "\x1f".join(window))
        if shingle_hash in selected:
            continue
        if len(selected) < 4096:
            selected.add(shingle_hash)
            heapq.heappush(largest_first, -shingle_hash)
        elif shingle_hash < -largest_first[0]:
            removed = -heapq.heapreplace(largest_first, -shingle_hash)
            selected.remove(removed)
            selected.add(shingle_hash)
    if not token_count:
        return {
            "policy_sha256": GROUPING_POLICY_SHA256,
            "token_count": 0,
            "shingle_count": 0,
            "simhash64": None,
            "band_sha256s": [],
        }
    if not selected:
        selected.add(_hash64("near-shingle", "\x1f".join(window)))
    signature = _simhash64_majority(selected)
    simhash = f"{signature:016x}"
    bands = [
        _private_feature_hash("near-band", f"{index}:{simhash[index * 4 : (index + 1) * 4]}") for index in range(4)
    ]
    return {
        "policy_sha256": GROUPING_POLICY_SHA256,
        "token_count": token_count,
        "shingle_count": len(selected),
        "simhash64": simhash,
        "band_sha256s": bands,
    }


def _simhash64_majority(values: set[int]) -> int:
    """Return bitwise majority with ties set, using bounded bit-sliced counters."""

    if not values or len(values) > 4096:
        raise EnronPreparationError("Near-duplicate shingle inventory is invalid.")
    counters = 0
    for value in values:
        expanded = 0
        for index, byte in enumerate(value.to_bytes(8, "little")):
            expanded |= _SIMHASH_BYTE_EXPANSIONS[byte] << (index * 8 * _SIMHASH_COUNTER_BITS)
        counters += expanded
    threshold = (len(values) + 1) // 2
    signature = 0
    for bit in range(64):
        count = (counters >> (bit * _SIMHASH_COUNTER_BITS)) & _SIMHASH_COUNTER_MASK
        if count >= threshold:
            signature |= 1 << bit
    return signature


def _text_metadata(value: str, *, truncated: bool) -> dict[str, Any]:
    return {
        "sha256": _private_feature_hash("prepared-view", value),
        "chars": len(value),
        "utf8_bytes": len(value.encode("utf-8")),
        "truncated": truncated,
    }


def _truncate_utf8(value: str, max_chars: int, max_bytes: int) -> tuple[str, bool]:
    if len(value) <= max_chars and len(value.encode("utf-8", errors="surrogatepass")) <= max_bytes:
        return value, False
    candidate = value[:max_chars]
    while candidate and len(candidate.encode("utf-8", errors="surrogatepass")) > max_bytes:
        low = 0
        high = len(candidate)
        while low < high:
            middle = (low + high + 1) // 2
            if len(candidate[:middle].encode("utf-8", errors="surrogatepass")) <= max_bytes:
                low = middle
            else:
                high = middle - 1
        candidate = candidate[:low]
    return candidate, True


def _size_bucket(value: int) -> str:
    boundaries = (
        (0, "0"),
        (255, "1-255"),
        (1_023, "256-1023"),
        (4_095, "1024-4095"),
        (16_383, "4096-16383"),
        (65_535, "16384-65535"),
        (262_143, "65536-262143"),
        (1_048_575, "262144-1048575"),
    )
    for upper, label in boundaries:
        if value <= upper:
            return label
    return "1048576+"


def _group_size_bucket(value: int) -> str:
    if value <= 1:
        return "1"
    if value == 2:
        return "2"
    if value <= 4:
        return "3-4"
    if value <= 9:
        return "5-9"
    if value <= 99:
        return "10-99"
    return "100+"


def _view_regions(name: str) -> list[str]:
    if name == "subject_current_body":
        return ["subject", "current_body"]
    return [name]


def _document_id(dataset_id: str, revision: str, source_sha256: str) -> str:
    payload = _canonical_json({"dataset_id": dataset_id, "revision": revision, "source_sha256": source_sha256})
    return "doc_" + _domain_hash("nerb/enron/document/v2", payload.encode("utf-8"))


def _private_feature_hash(kind: str, value: str) -> str:
    return _domain_hash_prefixed(f"nerb/enron/private-feature/{kind}/v2", value)


def _hash64(kind: str, value: str) -> int:
    digest = hashlib.sha256(f"nerb/enron/{kind}/v2\0{value}".encode()).digest()
    return int.from_bytes(digest[:8], "big")


def _canonical_source_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def _source_mapping_digest(value: Mapping[str, Any]) -> str:
    try:
        payload = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError, RecursionError):
        payload = _canonical_json({"invalid_mapping_keys": sorted(str(key) for key in value)[:128]})
    return _domain_hash_prefixed("nerb/enron/invalid-source-mapping/v2", payload)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _domain_hash(domain: str, value: bytes) -> str:
    return hashlib.sha256(domain.encode("ascii") + b"\0" + value).hexdigest()


def _domain_hash_prefixed(domain: str, value: str) -> str:
    return "sha256:" + _domain_hash(domain, value.encode("utf-8"))


def _hash_text(value: str) -> str:
    return _domain_hash_prefixed("nerb/enron/text/v2", value)


def _hash_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _artifact_descriptor(name: str, path: Path, *, records: int) -> dict[str, Any]:
    return {
        "id": Path(name).stem,
        "name": name,
        "sha256": _sha256_file(path),
        "bytes": path.stat().st_size,
        "records": records,
    }


def _implementation_sha256() -> str:
    digest = hashlib.sha256(b"nerb/enron/preparation-implementation/v2\0")
    directory = Path(__file__).parent
    for name in ("enron_cleaning.py", "enron_preparation.py", "enron_private_io.py"):
        component = hashlib.sha256()
        with (directory / name).open("rb") as file:
            for chunk in iter(lambda: file.read(1024 * 1024), b""):
                component.update(chunk)
        encoded_name = name.encode("ascii")
        digest.update(len(encoded_name).to_bytes(2, "big"))
        digest.update(encoded_name)
        digest.update(component.digest())
    return "sha256:" + digest.hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with _open_regular_binary(path) as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _write_json_file(file: TextIO, payload: Mapping[str, Any]) -> None:
    file.write(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n")
    file.flush()


def _reject_duplicate_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey
        result[key] = value
    return result


def _reject_nonfinite(_value: str) -> Any:
    raise _NonfiniteJsonNumber


def _parse_finite_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise _NonfiniteJsonNumber
    return parsed


def _open_regular_binary(path: Path) -> BinaryIO:
    try:
        return open_private_binary_input(path.expanduser())
    except EnronPrivateIOError as exc:
        raise EnronPreparationError(str(exc)) from exc


def _assert_no_symlink_components(path: Path) -> None:
    absolute = path.absolute()
    parts = absolute.parts
    current = Path(parts[0])
    for part in parts[1:]:
        current = current / part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode):
            raise EnronPreparationError("Symlink paths are unsafe for Enron preparation artifacts.")


def _assert_safe_existing_directory(path: Path) -> None:
    _assert_no_symlink_components(path)
    try:
        metadata = path.stat()
    except OSError as exc:
        raise EnronPreparationError("Could not inspect the Enron preparation run.") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise EnronPreparationError("Enron preparation run path must be a directory.")


def _read_json_object(path: Path, max_bytes: int) -> dict[str, Any]:
    with _open_regular_binary(path) as file:
        payload = file.read(max_bytes + 1)
    if len(payload) > max_bytes:
        raise EnronPreparationError("Enron preparation JSON artifact exceeds its size limit.")
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
            parse_float=_parse_finite_json_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateJsonKey, _NonfiniteJsonNumber) as exc:
        raise EnronPreparationError("Enron preparation JSON artifact is invalid.") from exc
    if not isinstance(value, dict):
        raise EnronPreparationError("Enron preparation JSON artifact must be an object.")
    return value


def _require_mapping_keys(value: Any, keys: set[str], error: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise EnronPreparationError(error)
    return value


def _validate_profile_shape(profile: Mapping[str, Any]) -> None:
    _require_mapping_keys(
        profile,
        {
            "artifact_kind",
            "artifacts",
            "cleaning",
            "dates",
            "duplicates",
            "grouping_features",
            "limits",
            "policies",
            "privacy",
            "records",
            "schema_version",
            "sizes",
            "software",
            "source",
            "text_views",
        },
        "Enron preparation profile schema is not closed.",
    )
    _require_mapping_keys(
        profile.get("source"),
        {
            "canonical_row_multiset_hash_algorithm",
            "canonical_row_multiset_sha256",
            "dataset_id",
            "input_records",
            "input_schema_sha256",
            "kind",
            "reader",
            "reader_package_version",
            "revision",
            "row_limit",
            "split",
        },
        "Enron preparation source schema is not closed.",
    )
    _require_mapping_keys(
        profile.get("records"),
        {
            "conservation_valid",
            "ingestion_errors",
            "input_records",
            "prepared_occurrences",
            "rejected_records",
            "unique_prepared_records",
        },
        "Enron preparation record aggregate schema is not closed.",
    )
    _require_mapping_keys(
        profile.get("policies"),
        {
            "cleaning_policy_sha256",
            "cleaning_version",
            "date_policy_sha256",
            "grouping_policy_sha256",
            "grouping_text_policy_sha256",
            "grouping_text_version",
        },
        "Enron preparation policy schema is not closed.",
    )
    _require_mapping_keys(
        profile.get("dates"),
        {
            "all_parseable_earliest_month",
            "all_parseable_latest_month",
            "status_counts",
            "temporal_eligible_earliest_month",
            "temporal_eligible_latest_month",
        },
        "Enron preparation date aggregate schema is not closed.",
    )
    _require_mapping_keys(
        profile.get("sizes"),
        {"current_body_utf8_bytes"},
        "Enron preparation size aggregate schema is not closed.",
    )
    _require_mapping_keys(
        profile.get("duplicates"),
        {
            "duplicate_exact_content_groups",
            "duplicate_exact_content_occurrences",
            "duplicate_message_id_groups",
            "duplicate_message_id_occurrences",
            "duplicate_source_groups",
            "duplicate_source_row_occurrences",
            "exact_content_group_size_histogram",
            "message_id_group_size_histogram",
            "source_group_size_histogram",
        },
        "Enron preparation duplicate aggregate schema is not closed.",
    )
    _require_mapping_keys(
        profile.get("grouping_features"),
        {
            "current_near_duplicate_signature_available",
            "full_visible_near_duplicate_signature_available",
            "mailbox_owner_available",
            "message_id_available",
            "prepared_occurrences",
            "thread_subject_available",
        },
        "Enron preparation grouping aggregate schema is not closed.",
    )
    _require_mapping_keys(
        profile.get("limits"),
        {
            "max_body_bytes",
            "max_body_chars",
            "max_jsonl_line_bytes",
            "max_recipients_per_field",
            "max_subject_bytes",
            "max_subject_chars",
        },
        "Enron preparation limit schema is not closed.",
    )
    artifacts = _require_mapping_keys(
        profile.get("artifacts"),
        {"prepared_records", "rejections"},
        "Enron preparation profile artifact schema is not closed.",
    )
    _validate_artifact_descriptor_shape(artifacts.get("prepared_records"), prepared=True)
    _validate_artifact_descriptor_shape(artifacts.get("rejections"), prepared=True)
    _require_mapping_keys(
        profile.get("software"),
        {
            "nerb_version",
            "preparation_implementation_sha256",
            "python_implementation",
            "python_version",
            "unicode_data_version",
        },
        "Enron preparation software schema is not closed.",
    )
    _require_mapping_keys(
        profile.get("privacy"),
        {
            "absolute_paths_included",
            "aggregate_only",
            "direct_identifiers_included",
            "per_record_features_included",
            "raw_text_included",
        },
        "Enron preparation privacy schema is not closed.",
    )


def _validate_manifest_shape(manifest: Mapping[str, Any]) -> None:
    _require_mapping_keys(
        manifest,
        {"artifacts", "preparation", "privacy", "schema_version", "source"},
        "Enron preparation manifest schema is not closed.",
    )
    source = _require_mapping_keys(
        manifest.get("source"),
        {
            "canonical_row_multiset_hash_algorithm",
            "canonical_row_multiset_sha256",
            "dataset_id",
            "input_records",
            "input_schema_sha256",
            "kind",
            "reader",
            "reader_package_version",
            "revision",
            "row_limit",
            "split",
        },
        "Enron preparation manifest source schema is not closed.",
    )
    del source
    _require_mapping_keys(
        manifest.get("preparation"),
        {
            "cleaning_policy_sha256",
            "date_policy_sha256",
            "grouping_policy_sha256",
            "output_occurrences",
            "output_records",
            "text_views",
        },
        "Enron preparation manifest preparation schema is not closed.",
    )
    artifacts = _require_mapping_keys(
        manifest.get("artifacts"),
        {"prepared_records", "profile", "rejections"},
        "Enron preparation manifest artifact schema is not closed.",
    )
    _validate_artifact_descriptor_shape(artifacts.get("prepared_records"), prepared=True)
    _validate_artifact_descriptor_shape(artifacts.get("rejections"), prepared=True)
    _validate_artifact_descriptor_shape(artifacts.get("profile"), prepared=False)
    _require_mapping_keys(
        manifest.get("privacy"),
        {
            "absolute_paths_included",
            "aggregate_only",
            "direct_identifiers_included",
            "per_record_features_included",
            "raw_text_included",
        },
        "Enron preparation manifest privacy schema is not closed.",
    )


def _validate_artifact_descriptor_shape(value: Any, *, prepared: bool) -> None:
    keys = {"bytes", "id", "name", "records", "sha256"}
    if prepared:
        keys |= {"occurrences", "ordering"}
    _require_mapping_keys(value, keys, "Enron preparation artifact descriptor schema is not closed.")


def _verify_prepared_jsonl(
    path: Path,
    expected_source: Mapping[str, Any],
    *,
    max_line_bytes: int,
    deep: bool = True,
    duplicate_connection: sqlite3.Connection | None = None,
) -> _PreparedVerification:
    count = 0
    occurrences = 0
    previous_id: str | None = None
    view_digests = {name: hashlib.sha256(f"nerb/enron/view/{name}/v2\0".encode()) for name in _TEXT_VIEW_NAMES}
    view_bytes: Counter[str] = Counter()
    view_empty: Counter[str] = Counter()
    cleaning_counts: Counter[str] = Counter()
    date_counts: Counter[str] = Counter()
    body_size_histogram: Counter[str] = Counter()
    grouping_feature_counts: Counter[str] = Counter(
        {
            "prepared_occurrences": 0,
            "mailbox_owner_available": 0,
            "message_id_available": 0,
            "thread_subject_available": 0,
            "current_near_duplicate_signature_available": 0,
            "full_visible_near_duplicate_signature_available": 0,
        }
    )
    earliest_date: str | None = None
    latest_date: str | None = None
    earliest_eligible_date: str | None = None
    latest_eligible_date: str | None = None
    source_accumulator = 0
    source_occurrences = 0
    with _open_regular_binary(path) as file:
        while line := file.readline(max_line_bytes + 1):
            if len(line) > max_line_bytes and not line.endswith(b"\n"):
                raise EnronPreparationError("Prepared record exceeds its line-size limit.")
            try:
                row = json.loads(
                    line.decode("utf-8"),
                    object_pairs_hook=_reject_duplicate_keys,
                    parse_constant=_reject_nonfinite,
                    parse_float=_parse_finite_json_float,
                )
            except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateJsonKey, _NonfiniteJsonNumber) as exc:
                raise EnronPreparationError("Prepared record artifact is invalid.") from exc
            document_id, row_occurrences, row_views = _verify_prepared_record(row, expected_source, deep=deep)
            assert isinstance(row, Mapping)
            if previous_id is not None and document_id <= previous_id:
                raise EnronPreparationError("Prepared records are not canonically ordered.")
            previous_id = document_id
            count += 1
            occurrences += row_occurrences
            for name, digest in view_digests.items():
                text = row_views[name]
                projection = (_canonical_json({"document_id": document_id, "text": text}) + "\n").encode("utf-8")
                digest.update(projection)
                view_bytes[name] += len(projection)
                if not text:
                    view_empty[name] += row_occurrences
            cleaning = row["cleaning"]
            date = row["date"]
            grouping = row["grouping"]
            assert isinstance(cleaning, Mapping)
            assert isinstance(date, Mapping)
            assert isinstance(grouping, Mapping)
            if duplicate_connection is not None:
                exact = grouping["exact"]
                assert isinstance(exact, Mapping)
                duplicate_connection.execute(
                    "INSERT INTO records (occurrence_count, exact_content_sha256, message_id_sha256) VALUES (?, ?, ?)",
                    (
                        row_occurrences,
                        str(exact["content_sha256"]),
                        grouping.get("normalized_message_id_sha256"),
                    ),
                )
            source_record = row["source"]
            assert isinstance(source_record, Mapping)
            source_accumulator, source_occurrences = _add_source_multiset_item(
                source_accumulator,
                source_occurrences,
                str(source_record["source_record_sha256"]),
                row_occurrences,
            )
            if source_record.get("mailbox_owner_sha256") is not None:
                grouping_feature_counts["mailbox_owner_available"] += row_occurrences
            transform_counts = cleaning["transform_counts"]
            assert isinstance(transform_counts, Mapping)
            for key, count_value in transform_counts.items():
                cleaning_counts[str(key)] += int(count_value) * row_occurrences
            date_status = str(date["status"])
            date_counts[date_status] += row_occurrences
            utc_value = date.get("utc")
            if isinstance(utc_value, str):
                earliest_date = utc_value if earliest_date is None or utc_value < earliest_date else earliest_date
                latest_date = utc_value if latest_date is None or utc_value > latest_date else latest_date
                if date_status == "valid":
                    earliest_eligible_date = (
                        utc_value
                        if earliest_eligible_date is None or utc_value < earliest_eligible_date
                        else earliest_eligible_date
                    )
                    latest_eligible_date = (
                        utc_value
                        if latest_eligible_date is None or utc_value > latest_eligible_date
                        else latest_eligible_date
                    )
            body_size_histogram[_size_bucket(len(row_views["current_body"].encode("utf-8")))] += row_occurrences
            grouping_feature_counts["prepared_occurrences"] += row_occurrences
            if grouping.get("normalized_message_id_sha256") is not None:
                grouping_feature_counts["message_id_available"] += row_occurrences
            if grouping.get("normalized_thread_subject_sha256") is not None:
                grouping_feature_counts["thread_subject_available"] += row_occurrences
            near_inventory = grouping["near_duplicate"]
            assert isinstance(near_inventory, Mapping)
            current_near = near_inventory["current_body_core"]
            full_near = near_inventory["full_visible_body"]
            assert isinstance(current_near, Mapping)
            assert isinstance(full_near, Mapping)
            if current_near.get("simhash64") is not None:
                grouping_feature_counts["current_near_duplicate_signature_available"] += row_occurrences
            if full_near.get("simhash64") is not None:
                grouping_feature_counts["full_visible_near_duplicate_signature_available"] += row_occurrences
    return _PreparedVerification(
        records=count,
        occurrences=occurrences,
        views={
            name: {
                "artifact_sha256": "sha256:" + view_digests[name].hexdigest(),
                "projection_bytes": view_bytes[name],
                "records": count,
                "empty_occurrences": view_empty[name],
            }
            for name in _TEXT_VIEW_NAMES
        },
        cleaning=dict(sorted(cleaning_counts.items())),
        dates={
            "status_counts": dict(sorted(date_counts.items())),
            "all_parseable_earliest_month": earliest_date[:7] if earliest_date is not None else None,
            "all_parseable_latest_month": latest_date[:7] if latest_date is not None else None,
            "temporal_eligible_earliest_month": (
                earliest_eligible_date[:7] if earliest_eligible_date is not None else None
            ),
            "temporal_eligible_latest_month": latest_eligible_date[:7] if latest_eligible_date is not None else None,
        },
        current_body_utf8_bytes_histogram=dict(sorted(body_size_histogram.items())),
        grouping_features=dict(sorted(grouping_feature_counts.items())),
        source_accumulator=source_accumulator,
        source_occurrences=source_occurrences,
    )


def _verify_prepared_record(
    row: Any,
    expected_source: Mapping[str, Any],
    *,
    deep: bool,
) -> tuple[str, int, Mapping[str, str]]:
    if (
        not isinstance(row, Mapping)
        or set(row)
        != {
            "cleaning",
            "date",
            "document_id",
            "grouping",
            "headers",
            "schema_version",
            "source",
            "status",
            "view_metadata",
            "views",
        }
        or row.get("schema_version") != PREPARED_RECORD_SCHEMA_VERSION
    ):
        raise EnronPreparationError("Prepared record schema is invalid.")
    if row.get("status") != "prepared" or "source_index" in row:
        raise EnronPreparationError("Prepared record status or provenance is invalid.")
    document_id = row.get("document_id")
    source = row.get("source")
    if (
        not isinstance(document_id, str)
        or not _DOCUMENT_ID_RE.fullmatch(document_id)
        or not isinstance(source, Mapping)
        or set(source)
        != {
            "dataset_id",
            "identical_occurrence_count",
            "mailbox_folder_role",
            "mailbox_owner_sha256",
            "revision",
            "source_locator_sha256",
            "source_record_sha256",
            "split",
        }
    ):
        raise EnronPreparationError("Prepared record identity is invalid.")
    for field in ("dataset_id", "revision", "split"):
        if not isinstance(source.get(field), str) or source.get(field) != expected_source.get(field):
            raise EnronPreparationError("Prepared record source binding is invalid.")
    source_sha256 = source.get("source_record_sha256")
    if not isinstance(source_sha256, str) or not _SHA256_RE.fullmatch(source_sha256):
        raise EnronPreparationError("Prepared record source hash is invalid.")
    occurrence_count = _nonnegative_integer(source.get("identical_occurrence_count"), minimum=1)
    source_locator = source.get("source_locator_sha256")
    if source_locator is not None and (not isinstance(source_locator, str) or not _SHA256_RE.fullmatch(source_locator)):
        raise EnronPreparationError("Prepared record source locator is invalid.")
    mailbox_owner = source.get("mailbox_owner_sha256")
    mailbox_role = source.get("mailbox_folder_role")
    if mailbox_owner is None:
        if mailbox_role is not None:
            raise EnronPreparationError("Prepared mailbox locator feature is invalid.")
    elif (
        not isinstance(mailbox_owner, str)
        or not _SHA256_RE.fullmatch(mailbox_owner)
        or mailbox_role not in {"archive", "deleted", "draft", "inbox", "other", "sent"}
    ):
        raise EnronPreparationError("Prepared mailbox locator feature is invalid.")
    expected_document_id = _document_id(
        str(source["dataset_id"]),
        str(source["revision"]),
        source_sha256.removeprefix("sha256:"),
    )
    if document_id != expected_document_id:
        raise EnronPreparationError("Prepared record document identity does not match its source commitment.")

    headers = row.get("headers")
    views = row.get("views")
    if (
        not isinstance(headers, Mapping)
        or set(headers) != {"bcc", "cc", "from", "message_id", "subject", "to"}
        or not isinstance(views, Mapping)
        or set(views) != {*_TEXT_VIEW_NAMES, "structured_headers"}
    ):
        raise EnronPreparationError("Prepared record headers or views are invalid.")
    message_id = headers.get("message_id")
    subject = headers.get("subject")
    if not isinstance(message_id, str) or not isinstance(subject, str):
        raise EnronPreparationError("Prepared record scalar headers are invalid.")
    structured_headers = views.get("structured_headers")
    expected_structured = {field: headers.get(field) for field in ("from", "to", "cc", "bcc")}
    if not isinstance(structured_headers, Mapping) or dict(structured_headers) != expected_structured:
        raise EnronPreparationError("Prepared structured headers are invalid.")
    _verify_structured_headers(structured_headers)
    text_views: dict[str, str] = {}
    for name in _TEXT_VIEW_NAMES:
        value = views.get(name)
        if not isinstance(value, str):
            raise EnronPreparationError("Prepared natural text view is invalid.")
        text_views[name] = value
    expected_subject_body = "\n\n".join(part for part in (subject, text_views["current_body"]) if part)
    if text_views["subject_current_body"] != expected_subject_body:
        raise EnronPreparationError("Prepared subject/body view is not a natural field composition.")
    body_truncated, subject_truncated = _verify_cleaning_record(row.get("cleaning"))
    _verify_mailbox_audit(source, row.get("cleaning"))
    _verify_view_metadata(
        row.get("view_metadata"),
        text_views,
        body_truncated=body_truncated,
        subject_truncated=subject_truncated,
    )
    _verify_grouping_shape(row.get("grouping"))
    if deep:
        _verify_grouping_record(row.get("grouping"), message_id, subject, structured_headers, text_views)
    _verify_date_record(row.get("date"))
    return document_id, occurrence_count, text_views


def _verify_structured_headers(value: Mapping[str, Any]) -> None:
    for field in ("from", "to", "cc", "bcc"):
        entries = value.get(field)
        if not isinstance(entries, list):
            raise EnronPreparationError("Prepared structured header list is invalid.")
        for entry in entries:
            if (
                not isinstance(entry, Mapping)
                or set(entry) != {"name", "address"}
                or not isinstance(entry.get("name"), str)
                or not isinstance(entry.get("address"), str)
            ):
                raise EnronPreparationError("Prepared structured header entry is invalid.")


def _verify_view_metadata(
    value: Any,
    views: Mapping[str, str],
    *,
    body_truncated: bool,
    subject_truncated: bool,
) -> None:
    if not isinstance(value, Mapping) or set(value) != set(_TEXT_VIEW_NAMES):
        raise EnronPreparationError("Prepared view metadata is invalid.")
    for name, text in views.items():
        metadata = value.get(name)
        if not isinstance(metadata, Mapping) or set(metadata) != {"chars", "sha256", "truncated", "utf8_bytes"}:
            raise EnronPreparationError("Prepared view metadata entry is invalid.")
        expected = {
            "sha256": _private_feature_hash("prepared-view", text),
            "chars": len(text),
            "utf8_bytes": len(text.encode("utf-8")),
        }
        expected_truncated = body_truncated or (name == "subject_current_body" and subject_truncated)
        if any(metadata.get(field) != expected_value for field, expected_value in expected.items()) or (
            metadata.get("truncated") is not expected_truncated
        ):
            raise EnronPreparationError("Prepared view metadata does not match its text.")


def _verify_cleaning_record(value: Any) -> tuple[bool, bool]:
    if not isinstance(value, Mapping) or set(value) != {
        "body_truncated",
        "policy_sha256",
        "policy_version",
        "source_body_sha256",
        "subject_truncated",
        "transform_counts",
    }:
        raise EnronPreparationError("Prepared cleaning audit is invalid.")
    if value.get("policy_version") != CLEANING_POLICY_VERSION or value.get("policy_sha256") != CLEANING_POLICY_REF:
        raise EnronPreparationError("Prepared cleaning policy binding is invalid.")
    source_body_sha256 = value.get("source_body_sha256")
    if not isinstance(source_body_sha256, str) or not _SHA256_RE.fullmatch(source_body_sha256):
        raise EnronPreparationError("Prepared source-body commitment is invalid.")
    transform_counts = value.get("transform_counts")
    if not isinstance(transform_counts, Mapping):
        raise EnronPreparationError("Prepared cleaning counters are invalid.")
    if any(not isinstance(key, str) or key not in _ALLOWED_TRANSFORM_COUNTERS for key in transform_counts):
        raise EnronPreparationError("Prepared cleaning counter name is invalid.")
    for count in transform_counts.values():
        _nonnegative_integer(count)
    body_truncated = value.get("body_truncated")
    subject_truncated = value.get("subject_truncated")
    if not isinstance(body_truncated, bool) or not isinstance(subject_truncated, bool):
        raise EnronPreparationError("Prepared truncation audit is invalid.")
    if transform_counts.get("body_truncated", 0) != int(body_truncated) or transform_counts.get(
        "subject_truncated", 0
    ) != int(subject_truncated):
        raise EnronPreparationError("Prepared truncation counters are invalid.")
    return body_truncated, subject_truncated


def _verify_mailbox_audit(source: Mapping[str, Any], cleaning: Any) -> None:
    if not isinstance(cleaning, Mapping) or not isinstance(cleaning.get("transform_counts"), Mapping):
        raise EnronPreparationError("Prepared mailbox audit is invalid.")
    counts = cleaning["transform_counts"]
    assert isinstance(counts, Mapping)
    folder_roles = {"archive", "deleted", "draft", "inbox", "other", "sent"}
    folder_count = sum(int(counts.get(f"mailbox_folder_{role}", 0)) for role in folder_roles)
    if source.get("mailbox_owner_sha256") is not None:
        role = source.get("mailbox_folder_role")
        if (
            counts.get("mailbox_locator_parsed", 0) != 1
            or folder_count != 1
            or not isinstance(role, str)
            or counts.get(f"mailbox_folder_{role}", 0) != 1
        ):
            raise EnronPreparationError("Prepared mailbox audit is invalid.")
    elif (
        counts.get("mailbox_locator_parsed", 0) != 0
        or folder_count != 0
        or int(counts.get("mailbox_locator_missing", 0)) + int(counts.get("mailbox_locator_invalid", 0)) != 1
    ):
        raise EnronPreparationError("Prepared mailbox audit is invalid.")


def _verify_grouping_record(
    value: Any,
    message_id: str,
    subject: str,
    structured_headers: Mapping[str, Any],
    views: Mapping[str, str],
) -> None:
    if not isinstance(value, Mapping) or value.get("policy_sha256") != GROUPING_POLICY_SHA256:
        raise EnronPreparationError("Prepared grouping policy binding is invalid.")
    exact = value.get("exact")
    expected_exact = {
        "content_sha256": _private_feature_hash("subject-current-body", views["subject_current_body"]),
        "full_visible_body_sha256": _private_feature_hash("full-visible-body", views["full_visible_body"]),
        "current_body_sha256": _private_feature_hash("current-body", views["current_body"]),
        "current_body_core_sha256": _private_feature_hash("current-body-core", views["current_body_core"]),
    }
    if exact != expected_exact:
        raise EnronPreparationError("Prepared exact grouping features are invalid.")
    normalized_message_id = _normalize_message_id(message_id)
    expected_message_id = (
        _private_feature_hash("message-id", normalized_message_id) if normalized_message_id is not None else None
    )
    if value.get("normalized_message_id_sha256") != expected_message_id:
        raise EnronPreparationError("Prepared Message-ID grouping feature is invalid.")
    thread_subject = normalize_thread_subject(subject)
    expected_thread = _private_feature_hash("thread-subject", thread_subject) if thread_subject else None
    if value.get("normalized_thread_subject_sha256") != expected_thread:
        raise EnronPreparationError("Prepared thread-subject grouping feature is invalid.")
    participants = _participant_values(structured_headers)
    expected_participants = (
        _private_feature_hash("participant-set", "\n".join(sorted(participants))) if participants else None
    )
    if value.get("participant_set_sha256") != expected_participants:
        raise EnronPreparationError("Prepared participant grouping feature is invalid.")
    embedded_ids, embedded_truncated = _embedded_message_id_features(views["full_visible_body"])
    if value.get("embedded_message_id_sha256s") != embedded_ids:
        raise EnronPreparationError("Prepared reference Message-ID features are invalid.")
    if value.get("embedded_message_id_scan") != {
        "body_chars_scanned": len(views["full_visible_body"]),
        "ids_truncated": embedded_truncated,
        "max_ids": 64,
    }:
        raise EnronPreparationError("Prepared reference Message-ID scan audit is invalid.")
    current_near_text = views["current_body_core"] or views["current_body"]
    current_near = _near_duplicate_features(current_near_text)
    expected_near = {
        "current_body_core": current_near,
        "full_visible_body": (
            current_near
            if views["full_visible_body"] == current_near_text
            else _near_duplicate_features(views["full_visible_body"])
        ),
    }
    if value.get("near_duplicate") != expected_near:
        raise EnronPreparationError("Prepared near-duplicate feature is invalid.")


def _verify_grouping_shape(value: Any) -> None:
    if (
        not isinstance(value, Mapping)
        or set(value)
        != {
            "embedded_message_id_scan",
            "embedded_message_id_sha256s",
            "exact",
            "near_duplicate",
            "normalized_message_id_sha256",
            "normalized_thread_subject_sha256",
            "participant_set_sha256",
            "policy_sha256",
        }
        or value.get("policy_sha256") != GROUPING_POLICY_SHA256
    ):
        raise EnronPreparationError("Prepared grouping policy binding is invalid.")
    exact = value.get("exact")
    if not isinstance(exact, Mapping) or set(exact) != {
        "content_sha256",
        "full_visible_body_sha256",
        "current_body_sha256",
        "current_body_core_sha256",
    }:
        raise EnronPreparationError("Prepared exact grouping feature shape is invalid.")
    for feature in exact.values():
        if not isinstance(feature, str) or not _SHA256_RE.fullmatch(feature):
            raise EnronPreparationError("Prepared exact grouping hash is invalid.")
    for field in (
        "normalized_message_id_sha256",
        "normalized_thread_subject_sha256",
        "participant_set_sha256",
    ):
        feature = value.get(field)
        if feature is not None and (not isinstance(feature, str) or not _SHA256_RE.fullmatch(feature)):
            raise EnronPreparationError("Prepared optional grouping hash is invalid.")
    embedded = value.get("embedded_message_id_sha256s")
    scan = value.get("embedded_message_id_scan")
    if (
        not isinstance(embedded, list)
        or len(embedded) > 64
        or any(not isinstance(item, str) or not _SHA256_RE.fullmatch(item) for item in embedded)
        or not isinstance(scan, Mapping)
        or set(scan) != {"body_chars_scanned", "ids_truncated", "max_ids"}
        or _nonnegative_integer(scan.get("body_chars_scanned")) < 0
        or not isinstance(scan.get("ids_truncated"), bool)
        or scan.get("max_ids") != 64
    ):
        raise EnronPreparationError("Prepared reference Message-ID feature shape is invalid.")
    near_inventory = value.get("near_duplicate")
    if not isinstance(near_inventory, Mapping) or set(near_inventory) != {
        "current_body_core",
        "full_visible_body",
    }:
        raise EnronPreparationError("Prepared near-duplicate feature shape is invalid.")
    for near in near_inventory.values():
        _verify_near_duplicate_shape(near)


def _verify_near_duplicate_shape(near: Any) -> None:
    if (
        not isinstance(near, Mapping)
        or set(near) != {"band_sha256s", "policy_sha256", "shingle_count", "simhash64", "token_count"}
        or near.get("policy_sha256") != GROUPING_POLICY_SHA256
    ):
        raise EnronPreparationError("Prepared near-duplicate feature shape is invalid.")
    token_count = _nonnegative_integer(near.get("token_count"))
    shingle_count = _nonnegative_integer(near.get("shingle_count"))
    if shingle_count > 4096:
        raise EnronPreparationError("Prepared near-duplicate shingle count is invalid.")
    simhash = near.get("simhash64")
    bands = near.get("band_sha256s")
    if token_count == 0:
        if simhash is not None or bands != [] or shingle_count != 0:
            raise EnronPreparationError("Prepared empty near-duplicate feature is invalid.")
    elif (
        not isinstance(simhash, str)
        or not _SIMHASH_RE.fullmatch(simhash)
        or not isinstance(bands, list)
        or len(bands) != 4
        or any(not isinstance(item, str) or not _SHA256_RE.fullmatch(item) for item in bands)
    ):
        raise EnronPreparationError("Prepared near-duplicate signature is invalid.")


def _verify_date_record(value: Any) -> None:
    if not isinstance(value, Mapping) or set(value) != {
        "status",
        "utc",
        "original_offset_minutes",
        "temporal_eligible",
    }:
        raise EnronPreparationError("Prepared date audit is invalid.")
    status_value = value.get("status")
    if status_value not in {"valid", "out_of_range", "missing", "invalid", "ambiguous_timezone"}:
        raise EnronPreparationError("Prepared date status is invalid.")
    utc_value = value.get("utc")
    if status_value in {"valid", "out_of_range"}:
        if not isinstance(utc_value, str) or not utc_value.endswith("Z"):
            raise EnronPreparationError("Prepared normalized date is invalid.")
        try:
            parsed = datetime.fromisoformat(utc_value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise EnronPreparationError("Prepared normalized date is invalid.") from exc
        if (
            parsed.tzinfo is None
            or parsed.utcoffset() != timezone.utc.utcoffset(parsed)
            or _format_utc(parsed) != utc_value
        ):
            raise EnronPreparationError("Prepared normalized date is not canonical UTC.")
        out_of_range = parsed < datetime(1990, 1, 1, tzinfo=timezone.utc) or parsed >= datetime(
            2011, 1, 1, tzinfo=timezone.utc
        )
        if (status_value == "out_of_range") is not out_of_range:
            raise EnronPreparationError("Prepared date range status is invalid.")
    elif utc_value is not None:
        raise EnronPreparationError("Prepared missing or invalid date must not contain a normalized timestamp.")
    temporal_eligible = value.get("temporal_eligible")
    if not isinstance(temporal_eligible, bool) or temporal_eligible is not (status_value == "valid"):
        raise EnronPreparationError("Prepared temporal eligibility is invalid.")
    offset = value.get("original_offset_minutes")
    if status_value in {"valid", "out_of_range"}:
        if not isinstance(offset, int) or isinstance(offset, bool) or not -1_439 <= offset <= 1_439:
            raise EnronPreparationError("Prepared date offset is invalid.")
    elif offset is not None:
        raise EnronPreparationError("Prepared date offset is invalid.")


def _verify_rejections_jsonl(path: Path, descriptor: Mapping[str, Any]) -> _RejectionVerification:
    records = 0
    occurrences = 0
    source_accumulator = 0
    reasons: Counter[str] = Counter()
    body_truncated_occurrences = 0
    subject_truncated_occurrences = 0
    previous_key: tuple[str, str] | None = None
    with _open_regular_binary(path) as file:
        while line := file.readline(64 * 1024 + 1):
            if len(line) > 64 * 1024 and not line.endswith(b"\n"):
                raise EnronPreparationError("Private rejection record exceeds its size limit.")
            try:
                row = json.loads(
                    line.decode("utf-8"),
                    object_pairs_hook=_reject_duplicate_keys,
                    parse_constant=_reject_nonfinite,
                    parse_float=_parse_finite_json_float,
                )
            except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateJsonKey, _NonfiniteJsonNumber) as exc:
                raise EnronPreparationError("Private rejection artifact is invalid.") from exc
            if not isinstance(row, Mapping) or set(row) != {
                "schema_version",
                "source_digest_sha256",
                "reason",
                "occurrence_count",
                "body_truncated_before_rejection",
                "subject_truncated_before_rejection",
            }:
                raise EnronPreparationError("Private rejection record schema is invalid.")
            source_digest = row.get("source_digest_sha256")
            reason = row.get("reason")
            if (
                row.get("schema_version") != REJECTION_RECORD_SCHEMA_VERSION
                or not isinstance(source_digest, str)
                or not _SHA256_RE.fullmatch(source_digest)
                or not isinstance(reason, str)
                or not re.fullmatch(r"[a-z0-9_]{1,96}", reason)
                or not isinstance(row.get("body_truncated_before_rejection"), bool)
                or not isinstance(row.get("subject_truncated_before_rejection"), bool)
            ):
                raise EnronPreparationError("Private rejection record value is invalid.")
            occurrence_count = _nonnegative_integer(row.get("occurrence_count"), minimum=1)
            key = (source_digest, reason)
            if previous_key is not None and key <= previous_key:
                raise EnronPreparationError("Private rejection records are not canonically ordered.")
            previous_key = key
            records += 1
            occurrences += occurrence_count
            reasons[reason] += occurrence_count
            if row["body_truncated_before_rejection"]:
                body_truncated_occurrences += occurrence_count
            if row["subject_truncated_before_rejection"]:
                subject_truncated_occurrences += occurrence_count
            source_accumulator, _ = _add_source_multiset_item(
                source_accumulator,
                0,
                source_digest,
                occurrence_count,
            )
    if records != descriptor.get("records") or occurrences != descriptor.get("occurrences"):
        raise EnronPreparationError("Private rejection artifact count mismatch.")
    return _RejectionVerification(
        records=records,
        occurrences=occurrences,
        source_accumulator=source_accumulator,
        reason_occurrences=dict(sorted(reasons.items())),
        body_truncated_occurrences=body_truncated_occurrences,
        subject_truncated_occurrences=subject_truncated_occurrences,
    )


def _verify_profile_contract(
    profile: Mapping[str, Any],
    prepared_descriptor: Mapping[str, Any],
) -> tuple[int, int, int]:
    if profile.get("artifact_kind") != "privacy_safe_aggregate":
        raise EnronPreparationError("Enron preparation profile kind is invalid.")
    source = profile.get("source")
    records = profile.get("records")
    policies = profile.get("policies")
    limits = profile.get("limits")
    privacy = profile.get("privacy")
    software = profile.get("software")
    if not all(isinstance(value, Mapping) for value in (source, records, policies, limits, privacy, software)):
        raise EnronPreparationError("Enron preparation profile structure is invalid.")
    assert isinstance(source, Mapping)
    assert isinstance(records, Mapping)
    assert isinstance(policies, Mapping)
    assert isinstance(limits, Mapping)
    assert isinstance(privacy, Mapping)
    assert isinstance(software, Mapping)

    input_records = _nonnegative_integer(source.get("input_records"))
    if records.get("input_records") != input_records:
        raise EnronPreparationError("Enron preparation input count binding is invalid.")
    unique_records = _nonnegative_integer(records.get("unique_prepared_records"))
    prepared_occurrences = _nonnegative_integer(records.get("prepared_occurrences"))
    rejected_records = _nonnegative_integer(records.get("rejected_records"))
    if (
        unique_records > prepared_occurrences
        or input_records != prepared_occurrences + rejected_records
        or records.get("conservation_valid") is not True
    ):
        raise EnronPreparationError("Enron preparation conservation arithmetic is invalid.")
    ingestion = records.get("ingestion_errors")
    if not isinstance(ingestion, Mapping):
        raise EnronPreparationError("Enron preparation ingestion counters are invalid.")
    _verify_nonnegative_counts(ingestion)

    if prepared_descriptor.get("id") != "prepared_records" or prepared_descriptor.get("name") != _PREPARED_FILENAME:
        raise EnronPreparationError("Prepared artifact identity is invalid.")
    if not isinstance(prepared_descriptor.get("sha256"), str) or not _SHA256_RE.fullmatch(
        str(prepared_descriptor["sha256"])
    ):
        raise EnronPreparationError("Prepared artifact hash is invalid.")
    _nonnegative_integer(prepared_descriptor.get("bytes"))
    if (
        prepared_descriptor.get("records") != unique_records
        or prepared_descriptor.get("occurrences") != prepared_occurrences
        or prepared_descriptor.get("ordering") != "document_id_ascending"
    ):
        raise EnronPreparationError("Prepared artifact counts or ordering are invalid.")
    profile_artifacts = profile.get("artifacts")
    rejection_descriptor = profile_artifacts.get("rejections") if isinstance(profile_artifacts, Mapping) else None
    if (
        not isinstance(rejection_descriptor, Mapping)
        or rejection_descriptor.get("id") != "rejections"
        or rejection_descriptor.get("name") != _REJECTIONS_FILENAME
        or not isinstance(rejection_descriptor.get("sha256"), str)
        or not _SHA256_RE.fullmatch(str(rejection_descriptor["sha256"]))
        or rejection_descriptor.get("occurrences") != rejected_records
        or rejection_descriptor.get("ordering") != "source_digest_reason_ascending"
    ):
        raise EnronPreparationError("Private rejection artifact contract is invalid.")
    _nonnegative_integer(rejection_descriptor.get("bytes"))
    _nonnegative_integer(rejection_descriptor.get("records"))

    dataset_id = source.get("dataset_id")
    source_kind = source.get("kind")
    reader = source.get("reader")
    package = source.get("reader_package_version")
    if (
        source.get("input_schema_sha256") != INPUT_SCHEMA_SHA256
        or source.get("canonical_row_multiset_hash_algorithm") != _SOURCE_MULTISET_HASH_ALGORITHM
        or not isinstance(dataset_id, str)
        or not _PROVENANCE_TOKEN_RE.fullmatch(dataset_id)
        or (source_kind, reader)
        not in {
            ("local_jsonl", "nerb.strict-bounded-jsonl.v2"),
            ("huggingface_streaming", "datasets.load_dataset(streaming=True)"),
        }
        or (source_kind == "local_jsonl" and package is not None)
        or (
            source_kind == "huggingface_streaming"
            and (not isinstance(package, str) or not _PROVENANCE_TOKEN_RE.fullmatch(package))
        )
    ):
        raise EnronPreparationError("Enron preparation source schema binding is invalid.")
    for field in ("revision", "split", "reader"):
        if not isinstance(source.get(field), str) or not source.get(field):
            raise EnronPreparationError("Enron preparation source provenance is invalid.")
    if any(
        not isinstance(source.get(field), str) or not _PROVENANCE_TOKEN_RE.fullmatch(str(source[field]))
        for field in ("revision", "split")
    ):
        raise EnronPreparationError("Enron preparation source provenance token is invalid.")
    source_commitment = source.get("canonical_row_multiset_sha256")
    if not isinstance(source_commitment, str) or not _SHA256_RE.fullmatch(source_commitment):
        raise EnronPreparationError("Enron preparation source commitment is invalid.")
    row_limit = source.get("row_limit")
    if row_limit is not None:
        if _nonnegative_integer(row_limit, minimum=1) < input_records:
            raise EnronPreparationError("Enron preparation row limit is inconsistent with its input count.")
    if source_kind == "huggingface_streaming" and not _IMMUTABLE_REVISION_RE.fullmatch(str(source.get("revision"))):
        raise EnronPreparationError("Enron preparation source revision is not immutable.")

    expected_policies = {
        "cleaning_version": CLEANING_POLICY_VERSION,
        "cleaning_policy_sha256": CLEANING_POLICY_REF,
        "date_policy_sha256": DATE_POLICY_SHA256,
        "grouping_text_version": GROUPING_TEXT_POLICY_VERSION,
        "grouping_text_policy_sha256": GROUPING_TEXT_POLICY_REF,
        "grouping_policy_sha256": GROUPING_POLICY_SHA256,
    }
    if dict(policies) != expected_policies:
        raise EnronPreparationError("Enron preparation policy binding is invalid.")
    if dict(privacy) != {
        "raw_text_included": False,
        "direct_identifiers_included": False,
        "absolute_paths_included": False,
        "per_record_features_included": False,
        "aggregate_only": True,
    }:
        raise EnronPreparationError("Enron preparation privacy attestation is invalid.")
    implementation_sha256 = software.get("preparation_implementation_sha256")
    if (
        software.get("nerb_version") != __version__
        or not isinstance(implementation_sha256, str)
        or not _SHA256_RE.fullmatch(implementation_sha256)
    ):
        raise EnronPreparationError("Enron preparation software provenance is invalid.")
    if implementation_sha256 != _implementation_sha256():
        raise EnronPreparationError("Preparation verification requires the recorded implementation.")
    expected_runtime = {
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "unicode_data_version": unicodedata.unidata_version,
    }
    if any(software.get(field) != expected for field, expected in expected_runtime.items()):
        raise EnronPreparationError("Deep preparation verification requires the recorded Python and Unicode runtime.")

    hard_limits = {
        "max_jsonl_line_bytes": HARD_MAX_JSONL_LINE_BYTES,
        "max_body_chars": HARD_MAX_BODY_CHARS,
        "max_body_bytes": HARD_MAX_BODY_BYTES,
        "max_subject_chars": HARD_MAX_SUBJECT_CHARS,
        "max_subject_bytes": HARD_MAX_SUBJECT_BYTES,
        "max_recipients_per_field": HARD_MAX_RECIPIENTS_PER_FIELD,
    }
    validated_limits: dict[str, int] = {}
    for name, maximum in hard_limits.items():
        validated = _nonnegative_integer(limits.get(name), minimum=1)
        if validated > maximum:
            raise EnronPreparationError("Enron preparation profile limit exceeds its safety bound.")
        validated_limits[name] = validated

    cleaning = profile.get("cleaning")
    dates = profile.get("dates")
    sizes = profile.get("sizes")
    duplicates = profile.get("duplicates")
    features = profile.get("grouping_features")
    if not all(isinstance(value, Mapping) for value in (cleaning, dates, sizes, duplicates, features)):
        raise EnronPreparationError("Enron preparation aggregate counters are invalid.")
    assert isinstance(cleaning, Mapping)
    assert isinstance(dates, Mapping)
    assert isinstance(sizes, Mapping)
    assert isinstance(duplicates, Mapping)
    assert isinstance(features, Mapping)
    _verify_nonnegative_counts(cleaning)
    _verify_nonnegative_counts(duplicates, recursive=True)
    _verify_nonnegative_counts(features)
    date_statuses = dates.get("status_counts")
    body_histogram = sizes.get("current_body_utf8_bytes")
    if not isinstance(date_statuses, Mapping) or not isinstance(body_histogram, Mapping):
        raise EnronPreparationError("Enron preparation date or size histogram is invalid.")
    _verify_nonnegative_counts(date_statuses)
    _verify_nonnegative_counts(body_histogram)
    if sum(int(value) for value in date_statuses.values()) != prepared_occurrences:
        raise EnronPreparationError("Enron preparation date counts do not cover prepared occurrences.")
    if sum(int(value) for value in body_histogram.values()) != prepared_occurrences:
        raise EnronPreparationError("Enron preparation size counts do not cover prepared occurrences.")

    _verify_profile_view_descriptors(profile.get("text_views"), unique_records, prepared_occurrences)
    line_limit = max(
        DEFAULT_MAX_PREPARED_LINE_BYTES,
        validated_limits["max_body_bytes"] * 10 + validated_limits["max_subject_bytes"] * 4 + 2 * 1024 * 1024,
    )
    if line_limit > HARD_MAX_PREPARED_LINE_BYTES:
        raise EnronPreparationError("Prepared record line bound exceeds its safety limit.")
    return unique_records, prepared_occurrences, line_limit


def _verify_profile_view_descriptors(value: Any, records: int, occurrences: int) -> None:
    if not isinstance(value, list) or len(value) != len(_TEXT_VIEW_NAMES):
        raise EnronPreparationError("Enron preparation text-view inventory is invalid.")
    by_id: dict[str, Mapping[str, Any]] = {}
    for descriptor in value:
        if (
            not isinstance(descriptor, Mapping)
            or set(descriptor)
            != {
                "answer_bearing_fields_included",
                "artifact_kind",
                "artifact_sha256",
                "empty_occurrences",
                "id",
                "primary_for_quality",
                "projection_bytes",
                "records",
                "regions",
            }
            or not isinstance(descriptor.get("id"), str)
        ):
            raise EnronPreparationError("Enron preparation text-view descriptor is invalid.")
        identifier = str(descriptor["id"])
        if identifier in by_id:
            raise EnronPreparationError("Enron preparation text-view identifiers are duplicated.")
        by_id[identifier] = descriptor
    if set(by_id) != set(_TEXT_VIEW_NAMES):
        raise EnronPreparationError("Enron preparation text-view inventory is incomplete.")
    for identifier, descriptor in by_id.items():
        if (
            descriptor.get("artifact_kind") != "virtual_prepared_projection"
            or not isinstance(descriptor.get("artifact_sha256"), str)
            or not _SHA256_RE.fullmatch(str(descriptor["artifact_sha256"]))
            or descriptor.get("records") != records
            or descriptor.get("answer_bearing_fields_included") is not False
            or descriptor.get("primary_for_quality") is not (identifier == "subject_current_body")
            or descriptor.get("regions") != _view_regions(identifier)
        ):
            raise EnronPreparationError("Enron preparation text-view contract is invalid.")
        _nonnegative_integer(descriptor.get("projection_bytes"))
        empty = _nonnegative_integer(descriptor.get("empty_occurrences"))
        if empty > occurrences:
            raise EnronPreparationError("Enron preparation empty-view count is invalid.")


def _verify_view_projections(profile: Mapping[str, Any], verification: _PreparedVerification) -> None:
    descriptors = profile.get("text_views")
    assert isinstance(descriptors, list)
    by_id = {str(item["id"]): item for item in descriptors if isinstance(item, Mapping)}
    for identifier, actual in verification.views.items():
        expected = by_id.get(identifier)
        if expected is None or any(expected.get(field) != value for field, value in actual.items()):
            raise EnronPreparationError("Prepared text-view projection hash or count mismatch.")


def _verify_prepared_aggregates(profile: Mapping[str, Any], verification: _PreparedVerification) -> None:
    sizes = profile.get("sizes")
    if (
        profile.get("cleaning") != verification.cleaning
        or profile.get("dates") != verification.dates
        or profile.get("grouping_features") != verification.grouping_features
        or not isinstance(sizes, Mapping)
        or sizes.get("current_body_utf8_bytes") != verification.current_body_utf8_bytes_histogram
    ):
        raise EnronPreparationError("Prepared aggregate profile does not match private records.")


def _verify_duplicate_aggregates(profile: Mapping[str, Any], duplicates: Mapping[str, Any]) -> None:
    if profile.get("duplicates") != duplicates:
        raise EnronPreparationError("Prepared duplicate aggregates do not match private records.")


def _verify_nonnegative_counts(value: Mapping[str, Any], *, recursive: bool = False) -> None:
    for child in value.values():
        if recursive and isinstance(child, Mapping):
            _verify_nonnegative_counts(child, recursive=True)
        else:
            _nonnegative_integer(child)


def _nonnegative_integer(value: Any, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise EnronPreparationError("Enron preparation count is invalid.")
    return value


def _validate_staged_run(stage_dir: Path, *, source_connection: sqlite3.Connection) -> None:
    manifest_path = stage_dir / _MANIFEST_FILENAME
    profile_path = stage_dir / _PROFILE_FILENAME
    prepared_path = stage_dir / _PREPARED_FILENAME
    rejection_path = stage_dir / _REJECTIONS_FILENAME
    manifest = _read_json_object(manifest_path, 16 * 1024 * 1024)
    profile = _read_json_object(profile_path, 16 * 1024 * 1024)
    if (
        manifest.get("schema_version") != RUN_MANIFEST_SCHEMA_VERSION
        or profile.get("schema_version") != PROFILE_SCHEMA_VERSION
    ):
        raise EnronPreparationError("Staged Enron preparation artifacts failed schema validation.")
    _validate_manifest_shape(manifest)
    _validate_profile_shape(profile)
    prepared_descriptor = manifest["artifacts"]["prepared_records"]
    rejection_descriptor = manifest["artifacts"]["rejections"]
    profile_descriptor = manifest["artifacts"]["profile"]
    if (
        profile_descriptor.get("id") != "profile"
        or profile_descriptor.get("name") != _PROFILE_FILENAME
        or profile_descriptor.get("records") != 1
    ):
        raise EnronPreparationError("Staged profile artifact descriptor is invalid.")
    if prepared_descriptor["sha256"] != _sha256_file(prepared_path):
        raise EnronPreparationError("Staged prepared artifact failed hash validation.")
    if profile_descriptor["sha256"] != _sha256_file(profile_path):
        raise EnronPreparationError("Staged profile artifact failed hash validation.")
    if rejection_descriptor["sha256"] != _sha256_file(rejection_path):
        raise EnronPreparationError("Staged rejection artifact failed hash validation.")
    expected_records, expected_occurrences, prepared_line_limit = _verify_profile_contract(profile, prepared_descriptor)
    verification = _verify_prepared_jsonl(
        prepared_path,
        profile["source"],
        max_line_bytes=prepared_line_limit,
        deep=False,
    )
    if verification.records != expected_records or verification.occurrences != expected_occurrences:
        raise EnronPreparationError("Staged prepared artifact failed count validation.")
    _verify_view_projections(profile, verification)
    _verify_prepared_aggregates(profile, verification)
    _verify_duplicate_aggregates(profile, _duplicate_aggregates(source_connection))
    rejection_verification = _verify_rejections_jsonl(rejection_path, rejection_descriptor)
    if rejection_verification.occurrences != profile["records"]["rejected_records"]:
        raise EnronPreparationError("Staged rejection artifact failed count validation.")
    _verify_ingestion_counters(profile, verification, rejection_verification)
    _verify_source_multiset(profile, verification, rejection_verification)
    _verify_manifest_profile_binding(manifest, profile)


def _verify_source_multiset(
    profile: Mapping[str, Any],
    prepared: _PreparedVerification,
    rejections: _RejectionVerification,
) -> None:
    source = profile.get("source")
    if not isinstance(source, Mapping):
        raise EnronPreparationError("Enron preparation source commitment is invalid.")
    combined_occurrences = prepared.source_occurrences + rejections.occurrences
    combined_accumulator = (prepared.source_accumulator + rejections.source_accumulator) % _SOURCE_MULTISET_MODULUS
    expected = source.get("canonical_row_multiset_sha256")
    if combined_occurrences != source.get("input_records") or (
        _finalize_source_multiset_hash(combined_accumulator, combined_occurrences) != expected
    ):
        raise EnronPreparationError("Enron preparation source commitment mismatch.")


def _verify_ingestion_counters(
    profile: Mapping[str, Any],
    prepared: _PreparedVerification,
    rejections: _RejectionVerification,
) -> None:
    expected: Counter[str] = Counter()
    expected["accepted_unique_rows"] = prepared.records
    expected["duplicate_source_rows"] = prepared.occurrences - prepared.records
    for reason, occurrences in rejections.reason_occurrences.items():
        key = f"cleaning_rejected_{reason.removeprefix('cleaning_')}" if reason.startswith("cleaning_") else reason
        expected[key] += occurrences
    expected["body_truncated_before_rejection"] = rejections.body_truncated_occurrences
    expected["subject_truncated_before_rejection"] = rejections.subject_truncated_occurrences
    canonical_expected = dict(sorted((key, count) for key, count in expected.items() if count))
    records = profile.get("records")
    ingestion = records.get("ingestion_errors") if isinstance(records, Mapping) else None
    if ingestion != canonical_expected:
        raise EnronPreparationError("Enron preparation ingestion counters do not match private artifacts.")


def _verify_manifest_profile_binding(manifest: Mapping[str, Any], profile: Mapping[str, Any]) -> None:
    source = profile.get("source")
    records = profile.get("records")
    policies = profile.get("policies")
    views = profile.get("text_views")
    privacy = profile.get("privacy")
    if not all(isinstance(value, Mapping) for value in (source, records, policies, privacy)) or not isinstance(
        views, list
    ):
        raise EnronPreparationError("Enron preparation profile structure is invalid.")
    assert isinstance(source, Mapping)
    assert isinstance(records, Mapping)
    assert isinstance(policies, Mapping)
    assert isinstance(privacy, Mapping)
    expected_source = dict(source)
    if manifest.get("source") != expected_source:
        raise EnronPreparationError("Enron preparation source binding is invalid.")
    expected_preparation = {
        "cleaning_policy_sha256": policies.get("cleaning_policy_sha256"),
        "date_policy_sha256": policies.get("date_policy_sha256"),
        "grouping_policy_sha256": policies.get("grouping_policy_sha256"),
        "output_records": records.get("unique_prepared_records"),
        "output_occurrences": records.get("prepared_occurrences"),
        "text_views": views,
    }
    if manifest.get("preparation") != expected_preparation or manifest.get("privacy") != privacy:
        raise EnronPreparationError("Enron preparation manifest binding is invalid.")


def _validate_aggregate_privacy(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            _validate_aggregate_privacy(str(key))
            _validate_aggregate_privacy(child)
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for child in value:
            _validate_aggregate_privacy(child)
        return
    if not isinstance(value, str):
        return
    lowered = value.casefold()
    if "@" in value or lowered.startswith(("file:", "mailto:")) or Path(value).is_absolute():
        raise EnronPreparationError("Aggregate Enron preparation artifacts contain a direct identifier or path.")


__all__ = [
    "DEFAULT_DATASET_ID",
    "DEFAULT_DATASET_REVISION",
    "DEFAULT_DATASET_SPLIT",
    "DEFAULT_OUTPUT_DIR",
    "DATE_POLICY_SHA256",
    "EnronPreparationError",
    "EnronPreparationOptions",
    "GROUPING_POLICY_SHA256",
    "INPUT_SCHEMA_SHA256",
    "PREPARED_RECORD_SCHEMA_VERSION",
    "PROFILE_SCHEMA_VERSION",
    "RUN_MANIFEST_SCHEMA_VERSION",
    "load_enron_preparation_run",
    "prepare_enron_source",
]

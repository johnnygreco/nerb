"""Privacy-first, leakage-aware train/validation/sealed-test splitting for Enron.

The public development surface deliberately has no generic role selector.  Test
records live in a separate private run and can only be opened by the one-shot
steward access context at the bottom of this module.
"""

from __future__ import annotations

import hashlib
import heapq
import json
import math
import os
import re
import secrets
import sqlite3
import stat
import time
from array import array
from collections import Counter, defaultdict
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import AbstractContextManager, ExitStack, contextmanager
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, TextIO

from .enron_activity import ACTIVITY_RECORD_INTERVAL, sqlite_activity
from .enron_preparation import (
    _normalize_message_id,
    _participant_values,
    _size_bucket,
    _verify_prepared_record,
    load_enron_preparation_run,
)
from .enron_private_io import (
    EnronPrivateIOError,
    PrivateRun,
    _iter_strict_jsonl,
    _rename_noreplace_at,
    open_private_binary_input,
    open_private_binary_input_at,
    open_private_directory_input,
)

SPLIT_MANIFEST_SCHEMA_VERSION = "nerb.enron_split_manifest.v2"
SPLIT_FREEZE_RECEIPT_SCHEMA_VERSION = "nerb.enron_split_freeze_receipt.v2"
SPLIT_MEMBERSHIP_SCHEMA_VERSION = "nerb.enron_split_membership.v2"
SPLIT_SAMPLE_SCHEMA_VERSION = "nerb.enron_split_sample.v2"
SPLIT_GROUP_SCHEMA_VERSION = "nerb.enron_split_group.v2"
SPLIT_LEAKAGE_AUDIT_SCHEMA_VERSION = "nerb.enron_split_leakage_audit.v2"
FINAL_TEST_ACCESS_SCHEMA_VERSION = "nerb.enron_final_test_access.v2"
FINAL_TEST_EVIDENCE_BINDING_SCHEMA_VERSION = "nerb.enron_final_test_evidence_binding.v2"
SPLIT_PAIR_RECEIPT_SCHEMA_VERSION = "nerb.enron_split_pair_receipt.v2"
SPLIT_PRESEAL_VERIFICATION_SCHEMA_VERSION = "nerb.enron_split_preseal_verification.v2"

DEFAULT_SPLIT_SEED = "nerb-enron-split"
_BENCHMARK_ID = "enron"
DEFAULT_MAX_PREPARED_LINE_BYTES = 384 * 1024 * 1024
PRODUCTION_MIN_ROLE_RECORDS = 10_000
PRODUCTION_MIN_ROLE_GROUPS = 1_000
PRODUCTION_MIN_REQUIRED_COHORT_RECORDS = 100
PRODUCTION_MIN_ROLE_FRACTION = 0.05
PRODUCTION_MAX_COMPONENT_FRACTION = 0.05
IDENTITY_HEAD_MIN_TRAIN_GROUPS = 10
_COMMIT_MARKER = "COMMITTED"
_COMMIT_PAYLOAD = b"nerb.enron.private-run.v2\n"
_ROLE_NAMES = ("train", "validation", "test")
_VIEW_NAMES = ("full_visible_body", "current_body", "subject_current_body", "current_body_core")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_DOCUMENT_ID_RE = re.compile(r"^doc_[0-9a-f]{64}$")
_MESSAGE_ID_HEADER_RE = re.compile(
    r"(?im)^(?:message-id|in-reply-to|references)\s*:[^\r\n]*"
    r"(?:\r?\n(?:[ \t]+[^\r\n]*|[ \t]*<[^<>\s]{1,512}>(?:[ \t,]+<[^<>\s]{1,512}>)*[ \t]*))*"
)
_ANGLE_MESSAGE_ID_RE = re.compile(r"<[^<>\s]{1,512}>")
_FROZEN_TARGET_KEYS = frozenset(
    {
        "frozen_at",
        "audit_plan_sha256",
        "bank_hash",
        "evaluator_source_sha256",
        "split_manifest_sha256",
        "test_artifact_sha256",
        "thresholds_sha256",
        "performance_manifest_sha256",
        "git_commit",
    }
)
_NEAR_BAND_BITS = (13, 13, 13, 13, 12)
_NEAR_BAND_PAIRS = tuple((left, right) for left in range(5) for right in range(left + 1, 5))
_GROUPING_TRUNCATION_COUNTERS = (
    "bcc_recipient_truncated",
    "cc_recipient_truncated",
    "header_scalars_truncated",
    "recipient_values_truncated",
    "sender_values_truncated",
    "to_recipient_truncated",
)
_PREPARATION_BINDING_KEYS = {
    "manifest_sha256",
    "profile_sha256",
    "prepared_sha256",
    "prepared_records",
    "prepared_occurrences",
    "dataset_id",
    "dataset_revision",
    "dataset_split",
    "cleaning_policy_sha256",
    "grouping_policy_sha256",
    "date_policy_sha256",
}
_RECEIPT_NAMES = frozenset({"PAIR_COMMITTED.json", "EVIDENCE_BOUND.json", "ACCESS_CLAIMED.json", "ACCESS_OUTCOME.json"})
_RECEIPT_STAGE_RE = re.compile(
    r"^\.(?:PAIR_COMMITTED\.json|EVIDENCE_BOUND\.json|ACCESS_CLAIMED\.json|ACCESS_OUTCOME\.json)"
    r"\.stage-[0-9a-f]{24}$"
)
_RECEIPT_TOMBSTONE_RE = re.compile(r"^\.nerb-cleanup-[0-9a-f]{48}$")
_MAX_RECEIPT_TOMBSTONES = 32
_MAX_PRIVATE_JSON_DEPTH = 256
_MAX_PRIVATE_JSON_INTEGER_DIGITS = 256

_DEVELOPMENT_FILES = (
    "train.jsonl",
    "validation.jsonl",
    "memberships.jsonl",
    "samples.jsonl",
    "manifest.json",
    "split-freeze-receipt.json",
)
_SEALED_FILES = (
    "test.jsonl",
    "memberships.jsonl",
    "samples.jsonl",
    "group-assignments.jsonl",
    "leakage-audit.json",
    "manifest.json",
    "PRESEAL_VERIFIED.json",
    "PAIR_COMMITTED.json",
)


class EnronSplitError(ValueError):
    """Raised when a split cannot be constructed or verified safely."""


class EnronDevelopmentAdmissionError(EnronSplitError):
    """Raised before large development artifacts are hashed when declared limits fail."""


@dataclass(frozen=True)
class EnronSplitOptions:
    preparation_run: Path
    development_output_dir: Path
    sealed_output_dir: Path
    scratch_dir: Path
    seed: str = DEFAULT_SPLIT_SEED
    train_fraction: float = 0.8
    validation_fraction: float = 0.1
    near_hamming: int = 3
    max_near_candidate_pairs: int = 100_000_000
    sample_per_role: int = 10_000
    fixture_mode: bool = False
    allow_unignored_output: bool = False
    progress_callback: Callable[[int], None] | None = None
    activity_callback: Callable[[], None] | None = None
    cleanup_successor: PrivateRun | None = dataclass_field(default=None, repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class EnronDevelopmentAdmissionLimits:
    """Builder-owned limits applied to frozen manifest metadata before artifact hashing."""

    max_train_records: int
    max_train_artifact_bytes: int
    max_validation_records: int
    max_validation_artifact_bytes: int
    max_development_memberships_bytes: int
    max_development_samples_bytes: int


@dataclass(frozen=True)
class _Component:
    group_id: str
    nodes: tuple[int, ...]
    records: int
    occurrences: int
    temporal: bool
    anchor_utc: str | None


@dataclass(frozen=True, slots=True)
class _Membership:
    document_id: str
    group_id: str
    role: str
    occurrence_count: int
    temporal_eligible: bool
    date_status: str
    anchor_utc: str | None
    mailbox: str
    mailbox_recurrence: str
    size: str
    group_size: str
    identity_recurrence: str
    identity_count: int
    identity_frequencies: tuple[str, ...]
    natural: bool
    structured: bool
    challenges: tuple[str, ...]

    def payload(self) -> dict[str, Any]:
        return {
            "schema_version": SPLIT_MEMBERSHIP_SCHEMA_VERSION,
            "document_id": self.document_id,
            "group_id": self.group_id,
            "role": self.role,
            "occurrence_count": self.occurrence_count,
            "temporal": {
                "eligible": self.temporal_eligible,
                "status": self.date_status,
                "anchor_utc": self.anchor_utc,
            },
            "mailbox": self.mailbox,
            "mailbox_recurrence": self.mailbox_recurrence,
            "size": self.size,
            "group_size": self.group_size,
            "identities": {
                "recurrence": self.identity_recurrence,
                "count": self.identity_count,
                "contains_frequency": list(self.identity_frequencies),
            },
            "views": {"natural": self.natural, "structured": self.structured},
            "challenges": list(self.challenges),
        }


@dataclass(frozen=True)
class _BuildState:
    components: tuple[_Component, ...]
    node_roles: tuple[str, ...]
    node_groups: tuple[str, ...]
    memberships: tuple[_Membership, ...]
    selected_nodes: frozenset[int]
    edge_counts: Mapping[str, int]
    near_candidate_emissions: int
    near_candidate_pairs: int
    grouping_truncated_records: int
    role_records: Mapping[str, int]
    role_groups: Mapping[str, int]
    cohort_counts: Mapping[str, Mapping[str, int]]
    sample_counts: Mapping[str, int]
    allocation_audit: Mapping[str, Any]


@dataclass(slots=True)
class _ActivityReporter:
    """Emit deterministic liveness signals without changing split progress."""

    callback: Callable[[], None] | None
    pending_work: int = 0

    def worked(self, units: int = 1) -> None:
        self.pending_work += units
        while self.pending_work >= ACTIVITY_RECORD_INTERVAL:
            self._report()
            self.pending_work -= ACTIVITY_RECORD_INTERVAL

    def boundary(self) -> None:
        self._report()
        self.pending_work = 0

    def _report(self) -> None:
        if self.callback is None:
            return
        try:
            self.callback()
        except Exception:
            raise EnronSplitError("Split activity callback failed.") from None


class _UnionFind:
    def __init__(self, count: int) -> None:
        if count < 0 or count >= 2**32:
            raise EnronSplitError("Prepared record count exceeds the compact grouping limit.")
        self.parent = array("I", range(count))
        self.size = array("I", (1 for _ in range(count)))

    def find(self, node: int) -> int:
        parent = self.parent
        root = node
        while parent[root] != root:
            root = parent[root]
        while parent[node] != node:
            next_node = parent[node]
            parent[node] = root
            node = next_node
        return root

    def union(self, left: int, right: int) -> bool:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root == right_root:
            return False
        # A stable minimum-node root makes grouping row-order independent.
        if left_root > right_root:
            left_root, right_root = right_root, left_root
        self.parent[right_root] = left_root
        self.size[left_root] += self.size[right_root]
        return True


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _canonical_line(value: Any) -> bytes:
    return (_canonical_json(value) + "\n").encode("utf-8")


def _hash_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _hash_value(domain: str, value: str) -> str:
    digest = hashlib.sha256(domain.encode("ascii") + b"\0" + value.encode("utf-8")).hexdigest()
    return "sha256:" + digest


def _hash_file(path: Path, *, activity_reporter: _ActivityReporter | None = None) -> str:
    digest = hashlib.sha256()
    with open_private_binary_input(path) as handle:
        for chunk_index, chunk in enumerate(iter(lambda: handle.read(1024 * 1024), b""), start=1):
            digest.update(chunk)
            if activity_reporter is not None and chunk_index % 256 == 0:
                activity_reporter.boundary()
    return "sha256:" + digest.hexdigest()


def _utc_instant(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EnronSplitError("Prepared temporal timestamp is invalid.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise EnronSplitError("Prepared temporal timestamp is not timezone-aware.")
    return parsed.astimezone(timezone.utc)


def _artifact_descriptor(
    path: Path,
    *,
    records: int,
    artifact_id: str | None = None,
    activity_reporter: _ActivityReporter | None = None,
) -> dict[str, Any]:
    return {
        "id": artifact_id or path.stem,
        "name": path.name,
        "sha256": _hash_file(path, activity_reporter=activity_reporter),
        "bytes": path.stat().st_size,
        "records": records,
    }


def _write_json(handle: TextIO, value: Mapping[str, Any]) -> None:
    handle.write(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n")
    handle.flush()


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
                raise EnronSplitError("Aggregate split metadata contains a private identifier or path.")


def _require_split_mapping(value: Any, error: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise EnronSplitError(error)
    return value


def _sealed_test_role(manifest: Mapping[str, Any]) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    roles = _require_split_mapping(manifest.get("roles"), "Sealed split role inventory is invalid.")
    role = _require_split_mapping(roles.get("test"), "Sealed test descriptor is invalid.")
    artifact = _require_split_mapping(role.get("artifact"), "Sealed test artifact descriptor is invalid.")
    return role, artifact


def _validate_sealed_access_manifest(
    manifest: Mapping[str, Any],
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    expected_keys = {
        "schema_version",
        "benchmark_version",
        "artifact_kind",
        "fixture_mode",
        "promotable",
        "preparation",
        "policy",
        "roles",
        "aggregates",
        "allocation",
        "cohorts",
        "sampling",
        "leakage",
        "sealing",
        "artifacts",
        "privacy",
    }
    sealing = _require_split_mapping(
        manifest.get("sealing"),
        "Sealed split sealing metadata is invalid for final access.",
    )
    leakage = _require_split_mapping(
        manifest.get("leakage"),
        "Sealed split leakage metadata is invalid for final access.",
    )
    roles = _require_split_mapping(
        manifest.get("roles"),
        "Sealed split role inventory is invalid for final access.",
    )
    role, artifact = _sealed_test_role(manifest)
    if (
        set(manifest) != expected_keys
        or manifest.get("schema_version") != SPLIT_MANIFEST_SCHEMA_VERSION
        or sealing.get("test_sealed") is not True
        or leakage.get("crossing_groups") != 0
        or set(roles) != set(_ROLE_NAMES)
    ):
        raise EnronSplitError("Sealed split is not structurally valid for final access.")
    return role, artifact


def _validate_preparation_binding(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _PREPARATION_BINDING_KEYS:
        raise EnronSplitError("Split preparation binding schema is invalid.")
    hash_fields = {
        "manifest_sha256",
        "profile_sha256",
        "prepared_sha256",
        "cleaning_policy_sha256",
        "grouping_policy_sha256",
        "date_policy_sha256",
    }
    if any(not isinstance(value[field], str) or not _SHA256_RE.fullmatch(value[field]) for field in hash_fields):
        raise EnronSplitError("Split preparation binding hash is invalid.")
    records = value["prepared_records"]
    occurrences = value["prepared_occurrences"]
    if (
        type(records) is not int
        or type(occurrences) is not int
        or records <= 0
        or occurrences < records
        or any(
            not isinstance(value[field], str) or not value[field]
            for field in ("dataset_id", "dataset_revision", "dataset_split")
        )
    ):
        raise EnronSplitError("Split preparation binding count or provenance is invalid.")
    return value


def _validate_options(options: EnronSplitOptions) -> None:
    for name in ("preparation_run", "development_output_dir", "sealed_output_dir"):
        if not isinstance(getattr(options, name), Path):
            raise EnronSplitError(f"{name} must be a path.")
    try:
        paths = [
            getattr(options, name).expanduser().absolute()
            for name in ("preparation_run", "development_output_dir", "sealed_output_dir")
        ]
    except (OSError, RuntimeError, ValueError):
        raise EnronSplitError("Split paths are invalid.") from None
    if len(set(paths)) != 3:
        raise EnronSplitError("Preparation, development, and sealed directories must be distinct.")
    if any(
        left in right.parents or right in left.parents
        for index, left in enumerate(paths)
        for right in paths[index + 1 :]
    ):
        raise EnronSplitError("Preparation, development, and sealed directories must not be nested.")
    if not isinstance(options.seed, str) or not options.seed or len(options.seed) > 512:
        raise EnronSplitError("seed must be a bounded non-empty string.")
    for name in ("train_fraction", "validation_fraction"):
        value = getattr(options, name)
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or not 0 < value < 1
        ):
            raise EnronSplitError(f"{name} must be finite and strictly between zero and one.")
    if options.train_fraction + options.validation_fraction >= 1:
        raise EnronSplitError("Train and validation fractions must leave a non-empty test fraction.")
    if (
        isinstance(options.near_hamming, bool)
        or not isinstance(options.near_hamming, int)
        or not 0 <= options.near_hamming <= 3
    ):
        raise EnronSplitError("near_hamming must be an integer from zero through three.")
    if (
        isinstance(options.max_near_candidate_pairs, bool)
        or not isinstance(options.max_near_candidate_pairs, int)
        or not 1 <= options.max_near_candidate_pairs <= 100_000_000
    ):
        raise EnronSplitError("max_near_candidate_pairs must be from 1 through 100000000.")
    if (
        isinstance(options.sample_per_role, bool)
        or not isinstance(options.sample_per_role, int)
        or options.sample_per_role <= 0
    ):
        raise EnronSplitError("sample_per_role must be a positive integer.")
    if not isinstance(options.fixture_mode, bool) or not isinstance(options.allow_unignored_output, bool):
        raise EnronSplitError("Boolean split options must be booleans.")
    if options.progress_callback is not None and not callable(options.progress_callback):
        raise EnronSplitError("progress_callback must be callable when provided.")
    if options.activity_callback is not None and not callable(options.activity_callback):
        raise EnronSplitError("activity_callback must be callable when provided.")
    if options.cleanup_successor is not None and not isinstance(options.cleanup_successor, PrivateRun):
        raise EnronSplitError("cleanup_successor must be a private run when provided.")
    if not isinstance(options.scratch_dir, Path):
        raise EnronSplitError("scratch_dir must be a path.")
    if not options.fixture_mode and (
        options.train_fraction != 0.8 or options.validation_fraction != 0.1 or options.near_hamming != 3
    ):
        raise EnronSplitError(
            "Promotable Enron splits require the frozen 80/10/10 allocation and Hamming-radius-three policy."
        )


def _open_spool(path: Path, *, precreated: bool = False) -> sqlite3.Connection:
    expected_identity: tuple[int, int] | None = None
    if precreated:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) & 0o077
            or before.st_size != 0
        ):
            raise EnronSplitError("Precreated split spool is unsafe.")
        expected_identity = int(before.st_dev), int(before.st_ino)
    else:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.close(descriptor)
        os.chmod(path, 0o600, follow_symlinks=False)
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA journal_mode=OFF")
    connection.execute("PRAGMA synchronous=OFF")
    connection.execute("PRAGMA temp_store=MEMORY")
    if expected_identity is not None:
        after = path.lstat()
        if (
            not stat.S_ISREG(after.st_mode)
            or stat.S_ISLNK(after.st_mode)
            or after.st_nlink != 1
            or after.st_uid != os.geteuid()
            or (after.st_dev, after.st_ino) != expected_identity
        ):
            connection.close()
            raise EnronSplitError("Split spool changed while SQLite opened it.")
    connection.executescript(
        """
        CREATE TABLE records (
            node INTEGER PRIMARY KEY,
            document_id TEXT NOT NULL UNIQUE,
            occurrences INTEGER NOT NULL,
            date_utc TEXT,
            date_status TEXT NOT NULL,
            temporal INTEGER NOT NULL,
            mailbox TEXT NOT NULL,
            mailbox_owner TEXT,
            size_bucket TEXT NOT NULL,
            natural INTEGER NOT NULL,
            structured INTEGER NOT NULL,
            grouping_truncated INTEGER NOT NULL
        );
        CREATE TABLE exact_features (feature TEXT NOT NULL, node INTEGER NOT NULL);
        CREATE TABLE own_message_ids (feature TEXT NOT NULL, node INTEGER NOT NULL);
        CREATE TABLE reference_message_ids (feature TEXT NOT NULL, node INTEGER NOT NULL);
        CREATE TABLE thread_participants (thread TEXT NOT NULL, identity TEXT NOT NULL, node INTEGER NOT NULL);
        CREATE TABLE identities (node INTEGER NOT NULL, identity TEXT NOT NULL);
        CREATE TABLE near_signatures (node INTEGER NOT NULL, signature TEXT NOT NULL, UNIQUE(node, signature));
        CREATE TABLE near_bands (
            band INTEGER NOT NULL, value INTEGER NOT NULL, node INTEGER NOT NULL, PRIMARY KEY(band, value, node)
        ) WITHOUT ROWID;
        CREATE TABLE near_candidates (
            left_node INTEGER NOT NULL, right_node INTEGER NOT NULL, PRIMARY KEY(left_node, right_node)
        ) WITHOUT ROWID;
        CREATE TABLE edge_provenance (edge TEXT NOT NULL, node INTEGER NOT NULL, PRIMARY KEY(edge, node));
        """
    )
    return connection


def _identity_hashes(row: Mapping[str, Any]) -> list[str]:
    views = row.get("views")
    structured = views.get("structured_headers") if isinstance(views, Mapping) else None
    if not isinstance(structured, Mapping):
        return []
    return sorted(_hash_value("nerb/enron/split-participant/v2", value) for value in _participant_values(structured))


def _exhaustive_message_id_references(text: str) -> list[str]:
    values: set[str] = set()
    for header in _MESSAGE_ID_HEADER_RE.finditer(text):
        unfolded = re.sub(r"\r?\n[ \t]+", " ", header.group(0))
        for match in _ANGLE_MESSAGE_ID_RE.finditer(unfolded):
            normalized = _normalize_message_id(match.group(0))
            if normalized:
                values.add(_hash_value("nerb/enron/split-message-id/v2", normalized))
    return sorted(values)


def _near_pair_keys(signature: str) -> tuple[tuple[int, int], ...]:
    signature_value = int(signature, 16)
    bands: list[int] = []
    offset = 0
    for bits in _NEAR_BAND_BITS:
        bands.append((signature_value >> offset) & ((1 << bits) - 1))
        offset += bits
    return tuple(
        (pair_index, (bands[left] << _NEAR_BAND_BITS[right]) | bands[right])
        for pair_index, (left, right) in enumerate(_NEAR_BAND_PAIRS)
    )


def _grouping_was_truncated(row: Mapping[str, Any]) -> bool:
    cleaning = row.get("cleaning")
    grouping = row.get("grouping")
    if not isinstance(cleaning, Mapping) or not isinstance(grouping, Mapping):
        return True
    if cleaning.get("body_truncated") is True or cleaning.get("subject_truncated") is True:
        return True
    counts = cleaning.get("transform_counts")
    if not isinstance(counts, Mapping):
        return True
    return any(isinstance(counts.get(name), int) and counts.get(name, 0) > 0 for name in _GROUPING_TRUNCATION_COUNTERS)


def _ingest_prepared(
    connection: sqlite3.Connection,
    prepared_path: Path,
    expected_source: Mapping[str, Any],
    *,
    start_node: int = 0,
    finalize: bool = True,
    expected_snapshot: _PrivateFileSnapshot | None = None,
    progress_callback: Callable[[int], None] | None = None,
    activity_reporter: _ActivityReporter | None = None,
) -> int:
    records = 0
    previous_document_id: str | None = None
    record_stream = (
        _iter_snapshot_jsonl(prepared_path, expected_snapshot)
        if expected_snapshot is not None
        else _iter_strict_jsonl(prepared_path, DEFAULT_MAX_PREPARED_LINE_BYTES)
    )
    for _, raw, row in record_stream:
        if activity_reporter is not None:
            activity_reporter.worked()
        document_id = row.get("document_id")
        if not isinstance(document_id, str) or not _DOCUMENT_ID_RE.fullmatch(document_id):
            raise EnronSplitError("Prepared document identity is invalid.")
        if previous_document_id is not None and document_id <= previous_document_id:
            raise EnronSplitError("Prepared records are not canonically ordered.")
        if raw != _canonical_line(row):
            raise EnronSplitError("Prepared records must use canonical JSONL serialization.")
        _verify_prepared_record(row, expected_source, deep=True)
        previous_document_id = document_id
        node = start_node + records
        source = row["source"]
        date = row["date"]
        views = row["views"]
        grouping = row["grouping"]
        occurrences = int(source["identical_occurrence_count"])
        temporal = bool(date["temporal_eligible"])
        date_utc = date["utc"] if temporal else None
        mailbox = source["mailbox_folder_role"] if source["mailbox_owner_sha256"] is not None else "unavailable"
        mailbox_owner = source["mailbox_owner_sha256"]
        natural = bool(views["subject_current_body"])
        identities = _identity_hashes(row)
        structured = bool(identities)
        grouping_truncated = _grouping_was_truncated(row)
        connection.execute(
            "INSERT INTO records VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                node,
                document_id,
                occurrences,
                date_utc,
                str(date["status"]),
                int(temporal),
                mailbox,
                mailbox_owner,
                _size_bucket(len(views["subject_current_body"].encode("utf-8"))),
                int(natural),
                int(structured),
                int(grouping_truncated),
            ),
        )
        for text in (views[name] for name in _VIEW_NAMES):
            if text:
                connection.execute(
                    "INSERT INTO exact_features VALUES (?, ?)",
                    (_hash_value("nerb/enron/split-plaintext/v2", text), node),
                )
        normalized_message_id = _normalize_message_id(row["headers"]["message_id"])
        if normalized_message_id:
            feature = _hash_value("nerb/enron/split-message-id/v2", normalized_message_id)
            connection.execute("INSERT INTO own_message_ids VALUES (?, ?)", (feature, node))
        for feature in _exhaustive_message_id_references(views["full_visible_body"]):
            connection.execute("INSERT INTO reference_message_ids VALUES (?, ?)", (feature, node))
        thread = grouping["normalized_thread_subject_sha256"]
        for identity in identities:
            connection.execute("INSERT INTO identities VALUES (?, ?)", (node, identity))
            if thread is not None:
                connection.execute("INSERT INTO thread_participants VALUES (?, ?, ?)", (thread, identity, node))
        for near in grouping["near_duplicate"].values():
            if near["token_count"] < 12 or near["shingle_count"] < 8 or near["simhash64"] is None:
                continue
            signature = str(near["simhash64"])
            connection.execute("INSERT OR IGNORE INTO near_signatures VALUES (?, ?)", (node, signature))
        records += 1
        if progress_callback is not None and records % 10_000 == 0:
            try:
                progress_callback(records)
            except (KeyboardInterrupt, SystemExit):
                raise
            except BaseException:
                raise EnronSplitError("Split progress callback failed.") from None
    if progress_callback is not None and records % 10_000 != 0:
        try:
            progress_callback(records)
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException:
            raise EnronSplitError("Split progress callback failed.") from None
    if finalize:
        if activity_reporter is not None:
            activity_reporter.boundary()
        for node, signature in connection.execute(
            "SELECT node, signature FROM near_signatures ORDER BY node, signature"
        ):
            if activity_reporter is not None:
                activity_reporter.worked()
            for pair_index, value in _near_pair_keys(str(signature)):
                connection.execute("INSERT OR IGNORE INTO near_bands VALUES (?, ?, ?)", (pair_index, value, node))
        for table, columns in (
            ("exact_features", "feature, node"),
            ("own_message_ids", "feature, node"),
            ("reference_message_ids", "feature, node"),
            ("thread_participants", "thread, identity, node"),
            ("identities", "identity, node"),
        ):
            if activity_reporter is not None:
                activity_reporter.boundary()
            connection.execute(f"CREATE INDEX {table}_lookup ON {table} ({columns})")
    connection.commit()
    if records == 0:
        raise EnronSplitError("Prepared run contains no records.")
    return records


def _union_runs(
    connection: sqlite3.Connection,
    union_find: _UnionFind,
    query: str,
    edge_name: str,
    edge_counts: Counter[str],
    *,
    activity_reporter: _ActivityReporter | None = None,
) -> None:
    previous_key: tuple[Any, ...] | None = None
    first_node: int | None = None
    for *keys, node_value in connection.execute(query):
        if activity_reporter is not None:
            activity_reporter.worked()
        key = tuple(keys)
        node = int(node_value)
        if key != previous_key:
            previous_key = key
            first_node = node
        elif first_node is not None and union_find.union(first_node, node):
            connection.execute("INSERT OR IGNORE INTO edge_provenance VALUES (?, ?)", (edge_name, first_node))
            connection.execute("INSERT OR IGNORE INTO edge_provenance VALUES (?, ?)", (edge_name, node))
            edge_counts[edge_name] += 1
        elif first_node is not None:
            connection.execute("INSERT OR IGNORE INTO edge_provenance VALUES (?, ?)", (edge_name, first_node))
            connection.execute("INSERT OR IGNORE INTO edge_provenance VALUES (?, ?)", (edge_name, node))


def _build_leakage_graph(
    connection: sqlite3.Connection,
    records: int,
    options: EnronSplitOptions,
    *,
    activity_reporter: _ActivityReporter | None = None,
) -> tuple[_UnionFind, Counter[str], int, int]:
    union_find = _UnionFind(records)
    edge_counts: Counter[str] = Counter()
    _union_runs(
        connection,
        union_find,
        "SELECT feature, node FROM exact_features GROUP BY feature, node ORDER BY feature, node",
        "exact_plaintext",
        edge_counts,
        activity_reporter=activity_reporter,
    )
    _union_runs(
        connection,
        union_find,
        "SELECT feature, node FROM own_message_ids GROUP BY feature, node ORDER BY feature, node",
        "same_message_id",
        edge_counts,
        activity_reporter=activity_reporter,
    )
    _union_runs(
        connection,
        union_find,
        """
        SELECT feature, node FROM own_message_ids
        UNION
        SELECT feature, node FROM reference_message_ids
        ORDER BY feature, node
        """,
        "message_id_reference",
        edge_counts,
        activity_reporter=activity_reporter,
    )
    _union_runs(
        connection,
        union_find,
        """
        SELECT thread, identity, node FROM thread_participants
        GROUP BY thread, identity, node ORDER BY thread, identity, node
        """,
        "thread_shared_participant",
        edge_counts,
        activity_reporter=activity_reporter,
    )

    # Five disjoint 13/13/13/13/12-bit bands indexed by all ten band pairs
    # are complete for Hamming distance <= 3: at least two bands must remain
    # unchanged. Materialize each pair-key index incrementally and enforce
    # budgets against both raw join emissions and unique candidates. Per-node
    # band keys are unique, so the bucket sum exactly bounds SQL join work.
    near_candidate_emissions = 0
    for (bucket_size,) in connection.execute("SELECT COUNT(*) FROM near_bands GROUP BY band, value"):
        if activity_reporter is not None:
            activity_reporter.worked()
        size = int(bucket_size)
        near_candidate_emissions += size * (size - 1) // 2
        if near_candidate_emissions > options.max_near_candidate_pairs:
            raise EnronSplitError("Near-duplicate raw-emission budget exceeded; split aborted fail-closed.")
    connection.execute("CREATE TEMP TABLE near_candidate_budget (candidate_count INTEGER NOT NULL)")
    connection.execute("INSERT INTO near_candidate_budget VALUES (0)")
    connection.executescript(
        f"""
        CREATE TEMP TRIGGER enforce_near_candidate_budget AFTER INSERT ON near_candidates
        BEGIN
            UPDATE near_candidate_budget SET candidate_count = candidate_count + 1;
            SELECT CASE WHEN (SELECT candidate_count FROM near_candidate_budget) >
                {options.max_near_candidate_pairs}
                THEN RAISE(ABORT, 'near candidate budget exceeded') END;
        END;
        """
    )
    near_candidate_pairs = 0
    for pair_index in range(len(_NEAR_BAND_PAIRS)):
        for first_node in range(0, records, ACTIVITY_RECORD_INTERVAL):
            try:
                connection.execute(
                    """
                    INSERT OR IGNORE INTO near_candidates
                    SELECT left_band.node, right_band.node
                    FROM near_bands AS left_band JOIN near_bands AS right_band
                      ON left_band.band = right_band.band AND left_band.value = right_band.value
                     AND left_band.node < right_band.node
                    WHERE left_band.band = ? AND left_band.node >= ? AND left_band.node < ?
                    """,
                    (pair_index, first_node, min(first_node + ACTIVITY_RECORD_INTERVAL, records)),
                )
            except sqlite3.IntegrityError as exc:
                if "near candidate budget exceeded" in str(exc):
                    raise EnronSplitError(
                        "Near-duplicate candidate budget exceeded; split aborted fail-closed."
                    ) from exc
                raise
            near_candidate_pairs = int(
                connection.execute("SELECT candidate_count FROM near_candidate_budget").fetchone()[0]
            )
            if near_candidate_pairs > options.max_near_candidate_pairs:
                raise EnronSplitError("Near-duplicate candidate budget exceeded; split aborted fail-closed.")
            if activity_reporter is not None:
                activity_reporter.boundary()
    signatures_by_node: list[tuple[int, ...]] = [()] * records
    current_node: int | None = None
    current_values: list[int] = []
    for node, signature in connection.execute("SELECT node, signature FROM near_signatures ORDER BY node, signature"):
        if activity_reporter is not None:
            activity_reporter.worked()
        node_int = int(node)
        if current_node is not None and node_int != current_node:
            signatures_by_node[current_node] = tuple(current_values)
            current_values = []
        current_node = node_int
        current_values.append(int(str(signature), 16))
    if current_node is not None:
        signatures_by_node[current_node] = tuple(current_values)
    for left, right in connection.execute(
        "SELECT left_node, right_node FROM near_candidates ORDER BY left_node, right_node"
    ):
        if activity_reporter is not None:
            activity_reporter.worked()
        # SQLite builds do not consistently expose bit_count; compare the
        # small signature inventories in Python while preserving disk-bounded
        # candidate enumeration.
        left_signatures = signatures_by_node[int(left)]
        right_signatures = signatures_by_node[int(right)]
        if any((a ^ b).bit_count() <= options.near_hamming for a in left_signatures for b in right_signatures):
            connection.execute("INSERT OR IGNORE INTO edge_provenance VALUES ('near_duplicate', ?)", (left,))
            connection.execute("INSERT OR IGNORE INTO edge_provenance VALUES ('near_duplicate', ?)", (right,))
            if union_find.union(int(left), int(right)):
                edge_counts["near_duplicate"] += 1
    return union_find, edge_counts, near_candidate_emissions, near_candidate_pairs


def _component_id(document_ids: Sequence[str]) -> str:
    return _hash_value("nerb/enron/split-component/v2", "\n".join(sorted(document_ids)))


def _components(
    connection: sqlite3.Connection,
    union_find: _UnionFind,
    *,
    activity_reporter: _ActivityReporter | None = None,
) -> tuple[_Component, ...]:
    members: dict[int, list[int]] = defaultdict(list)
    metadata: dict[int, tuple[str, int, str | None, bool]] = {}
    for node, document_id, occurrences, date_utc, temporal in connection.execute(
        "SELECT node, document_id, occurrences, date_utc, temporal FROM records ORDER BY node"
    ):
        if activity_reporter is not None:
            activity_reporter.worked()
        node_int = int(node)
        members[union_find.find(node_int)].append(node_int)
        metadata[node_int] = (str(document_id), int(occurrences), date_utc, bool(temporal))
    result: list[_Component] = []
    for nodes in members.values():
        document_ids: list[str] = []
        eligible_dates: list[str | None] = []
        occurrences = 0
        for node in nodes:
            if activity_reporter is not None:
                activity_reporter.worked()
            document_ids.append(metadata[node][0])
            occurrences += metadata[node][1]
            if metadata[node][3]:
                eligible_dates.append(metadata[node][2])
        result.append(
            _Component(
                group_id=_component_id(document_ids),
                nodes=tuple(nodes),
                records=len(nodes),
                occurrences=occurrences,
                temporal=bool(eligible_dates),
                anchor_utc=max((str(value) for value in eligible_dates), key=_utc_instant) if eligible_dates else None,
            )
        )
    return tuple(sorted(result, key=lambda component: component.group_id))


def _temporal_cut_indices(
    components: Sequence[_Component], train_fraction: float, validation_fraction: float
) -> tuple[int, int]:
    total = sum(component.records for component in components)
    cumulative = [0]
    for component in components:
        cumulative.append(cumulative[-1] + component.records)

    def closest(target: float, low: int, high: int) -> int:
        return min(range(low, high + 1), key=lambda index: (abs(cumulative[index] - target), index))

    if len(components) < 3:
        return 1, max(1, len(components) - 1)
    train_end = closest(total * train_fraction, 1, len(components) - 2)
    validation_end = closest(total * (train_fraction + validation_fraction), train_end + 1, len(components) - 1)
    return train_end, validation_end


def _assign_components(
    components: Sequence[_Component],
    options: EnronSplitOptions,
    *,
    activity_reporter: _ActivityReporter | None = None,
) -> tuple[tuple[str, ...], tuple[str, ...], Counter[str], Counter[str]]:
    temporal = sorted(
        (component for component in components if component.temporal),
        key=lambda component: (_utc_instant(str(component.anchor_utc)), component.group_id),
    )
    non_temporal = [component for component in components if not component.temporal]
    roles: dict[str, str] = {}
    if temporal:
        train_end, validation_end = _temporal_cut_indices(temporal, options.train_fraction, options.validation_fraction)
        for index, component in enumerate(temporal):
            if activity_reporter is not None:
                activity_reporter.worked()
            roles[component.group_id] = (
                "train" if index < train_end else "validation" if index < validation_end else "test"
            )
    validation_boundary = options.train_fraction + options.validation_fraction
    for component in non_temporal:
        if activity_reporter is not None:
            activity_reporter.worked()
        value = (
            int(
                hashlib.sha256(
                    (
                        "nerb/enron/non-temporal/v2\0" + _BENCHMARK_ID + "\0" + options.seed + "\0" + component.group_id
                    ).encode()
                ).hexdigest(),
                16,
            )
            / 2**256
        )
        roles[component.group_id] = (
            "train" if value < options.train_fraction else "validation" if value < validation_boundary else "test"
        )
    node_count = sum(component.records for component in components)
    node_roles = [""] * node_count
    node_groups = [""] * node_count
    role_records: Counter[str] = Counter()
    role_groups: Counter[str] = Counter()
    for component in components:
        role = roles[component.group_id]
        role_groups[role] += 1
        role_records[role] += component.records
        for node in component.nodes:
            if activity_reporter is not None:
                activity_reporter.worked()
            node_roles[node] = role
            node_groups[node] = component.group_id
    return tuple(node_roles), tuple(node_groups), role_records, role_groups


def _group_size_bucket(size: int) -> str:
    if size == 1:
        return "1"
    if size == 2:
        return "2"
    if size <= 4:
        return "3-4"
    if size <= 9:
        return "5-9"
    if size <= 99:
        return "10-99"
    return "100+"


def _derive_memberships(
    connection: sqlite3.Connection,
    components: Sequence[_Component],
    node_roles: Sequence[str],
    node_groups: Sequence[str],
    *,
    activity_reporter: _ActivityReporter | None = None,
) -> tuple[tuple[_Membership, ...], dict[str, dict[str, int]]]:
    component_by_group = {component.group_id: component for component in components}
    connection.execute("DROP TABLE IF EXISTS node_assignments")
    connection.execute(
        "CREATE TEMP TABLE node_assignments (node INTEGER PRIMARY KEY, role TEXT NOT NULL, group_id TEXT NOT NULL)"
    )
    if activity_reporter is not None:
        activity_reporter.boundary()
    connection.executemany(
        "INSERT INTO node_assignments VALUES (?, ?, ?)",
        ((node, node_roles[node], node_groups[node]) for node in range(len(node_roles))),
    )
    connection.execute("DROP TABLE IF EXISTS train_identity_counts")
    connection.execute(
        """
        CREATE TEMP TABLE train_identity_counts AS
        SELECT identities.identity AS identity, COUNT(DISTINCT node_assignments.group_id) AS train_groups
        FROM identities JOIN node_assignments USING(node)
        WHERE node_assignments.role = 'train'
        GROUP BY identities.identity
        """
    )
    connection.execute("CREATE UNIQUE INDEX train_identity_counts_key ON train_identity_counts(identity)")
    if activity_reporter is not None:
        activity_reporter.boundary()
    connection.execute("DROP TABLE IF EXISTS train_mailbox_counts")
    connection.execute(
        """
        CREATE TEMP TABLE train_mailbox_counts AS
        SELECT records.mailbox_owner AS mailbox_owner,
               COUNT(DISTINCT node_assignments.group_id) AS train_groups
        FROM records JOIN node_assignments USING(node)
        WHERE node_assignments.role = 'train' AND records.mailbox_owner IS NOT NULL
        GROUP BY records.mailbox_owner
        """
    )
    connection.execute("CREATE UNIQUE INDEX train_mailbox_counts_key ON train_mailbox_counts(mailbox_owner)")
    if activity_reporter is not None:
        activity_reporter.boundary()
    edge_families_by_group: dict[str, set[str]] = defaultdict(set)
    for edge, node in connection.execute("SELECT edge, node FROM edge_provenance ORDER BY edge, node"):
        if activity_reporter is not None:
            activity_reporter.worked()
        edge_families_by_group[node_groups[int(node)]].add(str(edge))

    memberships: list[_Membership] = []
    cohorts: dict[str, Counter[str]] = {role: Counter() for role in _ROLE_NAMES}
    identity_rows = iter(
        connection.execute(
            """
            SELECT identities.node, COALESCE(train_identity_counts.train_groups, 0)
            FROM identities LEFT JOIN train_identity_counts USING(identity)
            ORDER BY identities.node, identities.identity
            """
        )
    )
    next_identity = next(identity_rows, None)
    for row in connection.execute(
        """
        SELECT records.node, records.document_id, records.occurrences, records.date_utc,
               records.date_status, records.temporal, records.mailbox, records.mailbox_owner,
               records.size_bucket, records.natural, records.structured,
               COALESCE(train_mailbox_counts.train_groups, 0)
        FROM records LEFT JOIN train_mailbox_counts USING(mailbox_owner)
        ORDER BY records.node
        """
    ):
        if activity_reporter is not None:
            activity_reporter.worked()
        node = int(row[0])
        document_id = str(row[1])
        occurrences = int(row[2])
        date_status = str(row[4])
        temporal = bool(row[5])
        mailbox = str(row[6])
        mailbox_owner = row[7]
        size = str(row[8])
        natural = bool(row[9])
        structured = bool(row[10])
        mailbox_train_groups = int(row[11])
        mailbox_recurrence = (
            "unavailable" if mailbox_owner is None else "known" if mailbox_train_groups > 0 else "novel"
        )
        role = node_roles[node]
        group_id = node_groups[node]
        component = component_by_group[group_id]
        counts: list[int] = []
        while next_identity is not None and int(next_identity[0]) == node:
            counts.append(int(next_identity[1]))
            next_identity = next(identity_rows, None)
        if not counts:
            recurrence = "unavailable"
        elif all(count > 0 for count in counts):
            recurrence = "all_known"
        elif all(count == 0 for count in counts):
            recurrence = "all_novel"
        else:
            recurrence = "mixed"
        frequency: set[str] = set()
        for count in counts:
            if count == 0:
                frequency.add("novel")
            elif count == 1:
                frequency.add("tail")
            elif count < IDENTITY_HEAD_MIN_TRAIN_GROUPS:
                frequency.add("mid")
            else:
                frequency.add("head")
        group_size = _group_size_bucket(component.records)
        challenges: list[str] = []
        if not temporal:
            challenges.append("non_temporal")
        if mailbox == "unavailable":
            challenges.append("mailbox_unavailable")
        if mailbox_recurrence == "novel":
            challenges.append("mailbox_novelty")
        if component.records > 1:
            challenges.append("multi_record_leakage_group")
        edge_families = edge_families_by_group[group_id]
        if "exact_plaintext" in edge_families:
            challenges.append("exact_duplicate_group")
        if edge_families & {"same_message_id", "message_id_reference", "thread_shared_participant"}:
            challenges.append("thread_or_reply_group")
        if "near_duplicate" in edge_families:
            challenges.append("near_duplicate_group")
        if role != "train" and temporal:
            challenges.append("temporal_future")
        if not natural:
            challenges.append("natural_empty")
        if not structured:
            challenges.append("structured_empty")
        if recurrence in {"all_novel", "mixed"}:
            challenges.append("identity_novelty")
        membership = _Membership(
            document_id=document_id,
            group_id=group_id,
            role=role,
            occurrence_count=occurrences,
            temporal_eligible=temporal,
            date_status=date_status,
            anchor_utc=component.anchor_utc,
            mailbox=mailbox,
            mailbox_recurrence=mailbox_recurrence,
            size=size,
            group_size=group_size,
            identity_recurrence=recurrence,
            identity_count=len(counts),
            identity_frequencies=tuple(sorted(frequency)),
            natural=natural,
            structured=structured,
            challenges=tuple(sorted(challenges)),
        )
        memberships.append(membership)
        counter = cohorts[role]
        counter[f"identity:{recurrence}"] += 1
        for frequency_name in frequency:
            counter[f"frequency:{frequency_name}"] += 1
        counter[f"mailbox:{mailbox}"] += 1
        counter[f"mailbox_recurrence:{mailbox_recurrence}"] += 1
        counter[f"temporal:{date_status}"] += 1
        counter[f"size:{size}"] += 1
        counter[f"group_size:{group_size}"] += 1
        counter[f"natural:{'present' if natural else 'empty'}"] += 1
        counter[f"structured:{'present' if structured else 'empty'}"] += 1
        for challenge in challenges:
            counter[f"challenge:{challenge}"] += 1
    return tuple(memberships), {role: dict(sorted(values.items())) for role, values in cohorts.items()}


def _sample_stratum(membership: _Membership) -> str:
    return "\x1f".join(
        (
            membership.role,
            "eligible" if membership.temporal_eligible else "ineligible",
            membership.mailbox,
            membership.mailbox_recurrence,
            membership.size,
            membership.group_size,
            membership.identity_recurrence,
        )
    )


def _sample_margins(membership: _Membership) -> tuple[str, ...]:
    margins = {
        f"date_status:{membership.date_status}",
        f"natural:{'present' if membership.natural else 'empty'}",
        f"structured:{'present' if membership.structured else 'empty'}",
    }
    margins.update(f"identity_frequency:{name}" for name in membership.identity_frequencies)
    margins.update(f"challenge:{name}" for name in membership.challenges)
    return tuple(sorted(margins))


def _sample_rank(membership: _Membership, options: EnronSplitOptions) -> tuple[str, str]:
    return (
        _hash_value(
            "nerb/enron/split-sample/v2",
            _BENCHMARK_ID + "\0" + options.seed + "\0" + membership.document_id,
        ),
        membership.document_id,
    )


def _select_samples(
    memberships: Sequence[_Membership],
    options: EnronSplitOptions,
    *,
    activity_reporter: _ActivityReporter | None = None,
) -> tuple[frozenset[int], dict[str, int]]:
    selected: set[int] = set()
    sample_counts: dict[str, int] = {}
    for role in _ROLE_NAMES:
        strata: dict[str, list[int]] = defaultdict(list)
        margins: dict[str, list[int]] = defaultdict(list)
        role_nodes = [index for index, membership in enumerate(memberships) if membership.role == role]
        ranks = {node: _sample_rank(memberships[node], options) for node in role_nodes}
        for node in role_nodes:
            if activity_reporter is not None:
                activity_reporter.worked()
            strata[_sample_stratum(memberships[node])].append(node)
            for margin in _sample_margins(memberships[node]):
                margins[margin].append(node)

        role_selected: set[int] = set()
        for nodes in (*strata.values(), *margins.values()):
            role_selected.add(min(nodes, key=ranks.__getitem__))
        target = min(options.sample_per_role, len(role_nodes))
        if target < len(role_selected):
            if not options.fixture_mode:
                raise EnronSplitError(
                    "Representative sample budget cannot cover every base stratum and named marginal cohort."
                )
            target = len(role_selected)
        remaining = target - len(role_selected)
        capacities = {stratum: sum(node not in role_selected for node in nodes) for stratum, nodes in strata.items()}
        capacity_total = sum(capacities.values())
        quotas = {stratum: 0 for stratum in strata}
        if remaining and capacity_total:
            floors: dict[str, int] = {}
            remainders: list[tuple[int, str]] = []
            for stratum in sorted(strata):
                numerator = remaining * capacities[stratum]
                floors[stratum] = numerator // capacity_total
                remainders.append((numerator % capacity_total, stratum))
            for stratum, amount in floors.items():
                quotas[stratum] += amount
            residual = remaining - sum(floors.values())
            for _, stratum in sorted(remainders, key=lambda item: (-item[0], item[1]))[:residual]:
                quotas[stratum] += 1
        for stratum, nodes in sorted(strata.items()):
            ranked = sorted(
                (node for node in nodes if node not in role_selected),
                key=ranks.__getitem__,
            )
            role_selected.update(ranked[: quotas[stratum]])
        if len(role_selected) != target:
            raise EnronSplitError("Representative sample allocation did not fill its deterministic budget.")
        selected.update(role_selected)
        sample_counts[role] = len(role_selected)
    return frozenset(selected), sample_counts


def _enforce_support(
    components: Sequence[_Component],
    records: int,
    role_records: Mapping[str, int],
    role_groups: Mapping[str, int],
    grouping_truncated_records: int,
    options: EnronSplitOptions,
) -> None:
    if len(components) < 3 or any(
        role_records.get(role, 0) < 1 or role_groups.get(role, 0) < 1 for role in _ROLE_NAMES
    ):
        raise EnronSplitError("Split has insufficient support for all three roles.")
    if options.fixture_mode:
        return
    if grouping_truncated_records:
        raise EnronSplitError("Grouping-affecting truncation is not allowed in a production split.")
    minimum_role_records = max(
        math.ceil(records * PRODUCTION_MIN_ROLE_FRACTION),
        PRODUCTION_MIN_ROLE_RECORDS,
    )
    if any(
        role_records.get(role, 0) < minimum_role_records or role_groups.get(role, 0) < PRODUCTION_MIN_ROLE_GROUPS
        for role in _ROLE_NAMES
    ):
        raise EnronSplitError(
            "Production split requires each role to contain at least five percent/10000 records and 1000 groups."
        )
    largest = max(component.records for component in components)
    if largest / records >= PRODUCTION_MAX_COMPONENT_FRACTION:
        raise EnronSplitError("A leakage component covers at least five percent of the corpus.")


def _enforce_cohort_support(cohort_counts: Mapping[str, Mapping[str, int]], options: EnronSplitOptions) -> None:
    if options.fixture_mode:
        return
    required = (
        "identity:all_known",
        "identity:all_novel",
        "frequency:head",
        "frequency:tail",
        "natural:present",
        "structured:present",
    )
    for role in ("validation", "test"):
        if any(cohort_counts[role].get(cohort, 0) < PRODUCTION_MIN_REQUIRED_COHORT_RECORDS for cohort in required):
            raise EnronSplitError(
                "Production validation/test known, novel, head, tail, natural, and structured cohorts "
                "must each contain at least 100 records."
            )


def _allocation_audit(
    connection: sqlite3.Connection,
    components: Sequence[_Component],
    node_roles: Sequence[str],
    node_groups: Sequence[str],
    role_records: Mapping[str, int],
    records: int,
    options: EnronSplitOptions,
    *,
    activity_reporter: _ActivityReporter | None = None,
) -> dict[str, Any]:
    component_by_group = {component.group_id: component for component in components}
    component_anchor_instants = {
        component.group_id: _utc_instant(str(component.anchor_utc)) for component in components if component.temporal
    }
    temporal_components = sorted(
        (component for component in components if component.temporal),
        key=lambda component: (_utc_instant(str(component.anchor_utc)), component.group_id),
    )
    cumulative = 0
    boundary_rows: dict[str, dict[str, Any] | None] = {"train": None, "validation": None}
    for component in temporal_components:
        if activity_reporter is not None:
            activity_reporter.worked()
        cumulative += component.records
        role = node_roles[component.nodes[0]]
        if role in boundary_rows:
            exact_tuple = {
                "anchor_utc": component.anchor_utc,
                "group_id": component.group_id,
                "cumulative_temporal_records": cumulative,
            }
            boundary_rows[role] = {
                "cutoff_month": str(component.anchor_utc)[:7],
                "cumulative_temporal_records": cumulative,
                "boundary_tuple_sha256": _hash_bytes(_canonical_json(exact_tuple).encode("utf-8")),
            }
    eligibility: dict[str, Counter[str]] = {role: Counter() for role in _ROLE_NAMES}
    date_status: dict[str, Counter[str]] = {role: Counter() for role in _ROLE_NAMES}
    boundary_promoted_records = 0
    for node, date_utc, record_temporal, record_date_status in connection.execute(
        "SELECT node, date_utc, temporal, date_status FROM records ORDER BY node"
    ):
        if activity_reporter is not None:
            activity_reporter.worked()
        node_int = int(node)
        role = node_roles[node_int]
        component = component_by_group[node_groups[node_int]]
        key = "eligible" if bool(record_temporal) else "non_temporal"
        eligibility[role][f"{key}_records"] += 1
        date_status[role][str(record_date_status)] += 1
        if component.temporal and (
            not bool(record_temporal) or _utc_instant(str(date_utc)) < component_anchor_instants[component.group_id]
        ):
            boundary_promoted_records += 1
    for component in components:
        if activity_reporter is not None:
            activity_reporter.worked()
        role = node_roles[component.nodes[0]]
        key = "eligible" if component.temporal else "non_temporal"
        eligibility[role][f"{key}_groups"] += 1
    fractions = {
        "train": options.train_fraction,
        "validation": options.validation_fraction,
        "test": 1.0 - options.train_fraction - options.validation_fraction,
    }
    boundary_payload = {
        "benchmark_version": _BENCHMARK_ID,
        "temporal_boundaries": boundary_rows,
        "seed_sha256": _hash_value("nerb/enron/split-seed/v2", options.seed),
    }
    return {
        "temporal_boundaries": boundary_rows,
        "boundary_commitment_sha256": _hash_bytes(_canonical_json(boundary_payload).encode("utf-8")),
        "eligibility_by_role": {role: dict(sorted(eligibility[role].items())) for role in _ROLE_NAMES},
        "date_status_by_role": {role: dict(sorted(date_status[role].items())) for role in _ROLE_NAMES},
        "target_deviation_records": {role: role_records[role] - records * fractions[role] for role in _ROLE_NAMES},
        "component_anchored_forward_records": boundary_promoted_records,
    }


def _build_state(
    connection: sqlite3.Connection,
    records: int,
    options: EnronSplitOptions,
    *,
    activity_reporter: _ActivityReporter | None = None,
) -> _BuildState:
    union_find, edge_counts, near_candidate_emissions, near_candidate_pairs = _build_leakage_graph(
        connection,
        records,
        options,
        activity_reporter=activity_reporter,
    )
    if activity_reporter is not None:
        activity_reporter.boundary()
    components = _components(connection, union_find, activity_reporter=activity_reporter)
    node_roles, node_groups, role_records, role_groups = _assign_components(
        components,
        options,
        activity_reporter=activity_reporter,
    )
    grouping_truncated_records = int(
        connection.execute("SELECT COUNT(*) FROM records WHERE grouping_truncated = 1").fetchone()[0]
    )
    _enforce_support(
        components,
        records,
        role_records,
        role_groups,
        grouping_truncated_records,
        options,
    )
    memberships, cohort_counts = _derive_memberships(
        connection,
        components,
        node_roles,
        node_groups,
        activity_reporter=activity_reporter,
    )
    _enforce_cohort_support(cohort_counts, options)
    selected_nodes, sample_counts = _select_samples(
        memberships,
        options,
        activity_reporter=activity_reporter,
    )
    allocation_audit = _allocation_audit(
        connection,
        components,
        node_roles,
        node_groups,
        role_records,
        records,
        options,
        activity_reporter=activity_reporter,
    )
    return _BuildState(
        components=components,
        node_roles=node_roles,
        node_groups=node_groups,
        memberships=memberships,
        selected_nodes=selected_nodes,
        edge_counts=dict(sorted(edge_counts.items())),
        near_candidate_emissions=near_candidate_emissions,
        near_candidate_pairs=near_candidate_pairs,
        grouping_truncated_records=grouping_truncated_records,
        role_records=dict(role_records),
        role_groups=dict(role_groups),
        cohort_counts=cohort_counts,
        sample_counts=sample_counts,
        allocation_audit=allocation_audit,
    )


def _split_policy(options: EnronSplitOptions) -> dict[str, Any]:
    policy = {
        "version": "nerb.enron-split-policy.v2",
        "implementation_sha256": _hash_file(Path(__file__)),
        "seed_sha256": _hash_value("nerb/enron/split-seed/v2", options.seed),
        "train_fraction": options.train_fraction,
        "validation_fraction": options.validation_fraction,
        "test_fraction": 1.0 - options.train_fraction - options.validation_fraction,
        "fixture_mode": options.fixture_mode,
        "promotable": not options.fixture_mode,
        "grouping": {
            "exact": "same_nonempty_plaintext_across_four_views",
            "message_id": "same_normalized_id_or_exhaustive_full-body_reference",
            "thread": "same_normalized_subject_and_shared_structured_participant",
            "near": {
                "views": ["current_body_core", "full_visible_body"],
                "minimum_tokens": 12,
                "minimum_shingles": 8,
                "hamming_maximum": options.near_hamming,
                "bands": [13, 13, 13, 13, 12],
                "index": "all_10_pairs_of_band_positions_and_values",
                "raw_emission_and_unique_pair_budget": options.max_near_candidate_pairs,
            },
            "identity_alone_is_edge": False,
        },
        "assignment": {
            "temporal_component_anchor": "maximum_eligible_utc",
            "temporal_boundaries": "closest_cumulative_record_targets_whole_components",
            "non_temporal": "independent_seeded_hash_thresholds",
        },
        "sampling": {
            "per_role": options.sample_per_role,
            "allocation": "named_marginal_reservations_then_hamilton_over_base_strata",
            "selection": "seeded_min_hash",
            "base_strata": [
                "role",
                "temporal",
                "mailbox",
                "mailbox_recurrence",
                "size",
                "group_size",
                "identity_recurrence",
            ],
            "marginal_reservations": [
                "date_status",
                "identity_frequency",
                "natural_availability",
                "structured_availability",
                "challenge_family",
            ],
        },
        "cohorts": {
            "identity_reference": "distinct_train_leakage_groups",
            "identity_surface": "normalized_address_else_normalized_name",
            "identity_recurrence": ["all_known", "mixed", "all_novel", "unavailable"],
            "identity_frequency": {
                "tail_train_groups": 1,
                "mid_train_groups_inclusive": [2, IDENTITY_HEAD_MIN_TRAIN_GROUPS - 1],
                "head_min_train_groups": IDENTITY_HEAD_MIN_TRAIN_GROUPS,
                "novel_train_groups": 0,
            },
            "mailbox_reference": "distinct_train_leakage_groups_by_owner_hash",
            "mailbox_recurrence": ["known", "novel", "unavailable"],
            "negative": "unsupported_without_exhaustive_labels",
            "challenge_families": ["exact_duplicate", "thread_or_reply", "near_duplicate"],
        },
        "support": {
            "production_min_role_records": PRODUCTION_MIN_ROLE_RECORDS,
            "production_min_role_fraction": PRODUCTION_MIN_ROLE_FRACTION,
            "production_min_role_groups": PRODUCTION_MIN_ROLE_GROUPS,
            "production_max_component_fraction_exclusive": PRODUCTION_MAX_COMPONENT_FRACTION,
            "production_min_required_validation_test_cohort_records": (PRODUCTION_MIN_REQUIRED_COHORT_RECORDS),
            "required_validation_test_cohorts": [
                "identity:all_known",
                "identity:all_novel",
                "frequency:head",
                "frequency:tail",
                "natural:present",
                "structured:present",
            ],
            "grouping_truncation_policy": "production_fail_fixture_audit",
            "grouping_truncation_flags": ["body_truncated", "subject_truncated"],
            "grouping_truncation_counters": list(_GROUPING_TRUNCATION_COUNTERS),
            "fixture_policy": "nonempty_roles_nonpromotable",
        },
    }
    return {**policy, "sha256": _hash_bytes(_canonical_json(policy).encode("utf-8"))}


def _write_role_records(
    prepared_path: Path,
    connection: sqlite3.Connection,
    expected_prepared_sha256: str,
    state: _BuildState,
    train_file: BinaryIO,
    validation_file: BinaryIO,
    test_file: BinaryIO,
    *,
    activity_reporter: _ActivityReporter | None = None,
) -> None:
    handles = {"train": train_file, "validation": validation_file, "test": test_file}
    count = 0
    digest = hashlib.sha256()
    expected_documents = connection.execute("SELECT document_id FROM records ORDER BY node")
    for (_, raw, row), (expected_document_id,) in zip(
        _iter_strict_jsonl(prepared_path, DEFAULT_MAX_PREPARED_LINE_BYTES),
        expected_documents,
        strict=True,
    ):
        if activity_reporter is not None:
            activity_reporter.worked()
        if row.get("document_id") != expected_document_id:
            raise EnronSplitError("Prepared record stream changed during splitting.")
        digest.update(raw)
        handles[state.node_roles[count]].write(raw)
        count += 1
    if count != len(state.node_roles) or "sha256:" + digest.hexdigest() != expected_prepared_sha256:
        raise EnronSplitError("Prepared record stream changed during splitting.")
    for handle in handles.values():
        handle.flush()


def _write_memberships_and_samples(
    state: _BuildState,
    development_memberships: BinaryIO,
    development_samples: BinaryIO,
    sealed_memberships: BinaryIO,
    sealed_samples: BinaryIO,
    *,
    activity_reporter: _ActivityReporter | None = None,
) -> tuple[int, int]:
    dev_membership_count = 0
    sealed_membership_count = 0
    for node, membership in enumerate(state.memberships):
        if activity_reporter is not None:
            activity_reporter.worked()
        membership_payload = membership.payload()
        encoded = _canonical_line(membership_payload)
        sample = {
            "schema_version": SPLIT_SAMPLE_SCHEMA_VERSION,
            "document_id": membership.document_id,
            "role": membership.role,
            "stratum_sha256": _hash_value("nerb/enron/split-sample-stratum/v2", _sample_stratum(membership)),
            "membership": membership_payload,
        }
        if membership.role == "test":
            sealed_memberships.write(encoded)
            sealed_membership_count += 1
            if node in state.selected_nodes:
                sealed_samples.write(_canonical_line(sample))
        else:
            development_memberships.write(encoded)
            dev_membership_count += 1
            if node in state.selected_nodes:
                development_samples.write(_canonical_line(sample))
    for handle in (development_memberships, development_samples, sealed_memberships, sealed_samples):
        handle.flush()
    return dev_membership_count, sealed_membership_count


def _write_groups(
    handle: BinaryIO,
    state: _BuildState,
    *,
    activity_reporter: _ActivityReporter | None = None,
) -> None:
    for component in state.components:
        if activity_reporter is not None:
            activity_reporter.worked()
        role = state.node_roles[component.nodes[0]]
        challenges = {challenge for node in component.nodes for challenge in state.memberships[node].challenges}
        value = {
            "schema_version": SPLIT_GROUP_SCHEMA_VERSION,
            "group_id": component.group_id,
            "role": role,
            "records": component.records,
            "occurrences": component.occurrences,
            "temporal": component.temporal,
            "anchor_utc": component.anchor_utc,
            "edge_families": sorted(
                challenge
                for challenge in challenges
                if challenge in {"exact_duplicate_group", "thread_or_reply_group", "near_duplicate_group"}
            ),
            "member_document_ids": [state.memberships[node].document_id for node in component.nodes],
        }
        handle.write(_canonical_line(value))
    handle.flush()


def _leakage_audit(state: _BuildState) -> dict[str, Any]:
    largest = max(component.records for component in state.components)
    return {
        "schema_version": SPLIT_LEAKAGE_AUDIT_SCHEMA_VERSION,
        "records": len(state.node_roles),
        "groups": len(state.components),
        "crossing_groups": 0,
        "edge_counts": dict(state.edge_counts),
        "near_candidate_raw_emissions": state.near_candidate_emissions,
        "near_candidate_pairs": state.near_candidate_pairs,
        "largest_group_records": largest,
        "largest_group_fraction": largest / len(state.node_roles),
        "grouping_truncated_records": state.grouping_truncated_records,
    }


def _role_descriptors(
    state: _BuildState,
    development_stage: Path,
    sealed_stage: Path,
    *,
    activity_reporter: _ActivityReporter | None = None,
) -> dict[str, Any]:
    return {
        "train": {
            "records": state.role_records["train"],
            "groups": state.role_groups["train"],
            "artifact": _artifact_descriptor(
                development_stage / "train.jsonl",
                records=state.role_records["train"],
                artifact_id="train",
                activity_reporter=activity_reporter,
            ),
        },
        "validation": {
            "records": state.role_records["validation"],
            "groups": state.role_groups["validation"],
            "artifact": _artifact_descriptor(
                development_stage / "validation.jsonl",
                records=state.role_records["validation"],
                artifact_id="validation",
                activity_reporter=activity_reporter,
            ),
        },
        "test": {
            "records": state.role_records["test"],
            "groups": state.role_groups["test"],
            "artifact": _artifact_descriptor(
                sealed_stage / "test.jsonl",
                records=state.role_records["test"],
                artifact_id="test",
                activity_reporter=activity_reporter,
            ),
        },
    }


def _preparation_binding(
    preparation_run: Path,
    verified: Mapping[str, Any],
    *,
    activity_reporter: _ActivityReporter | None = None,
) -> dict[str, Any]:
    profile = verified["profile"]
    source = profile["source"]
    prepared = verified["artifacts"]["prepared_records"]
    verified_manifest_sha256 = verified.get("manifest_sha256")
    if (
        not isinstance(verified_manifest_sha256, str)
        or not _SHA256_RE.fullmatch(verified_manifest_sha256)
        or _hash_file(preparation_run / "manifest.json", activity_reporter=activity_reporter)
        != verified_manifest_sha256
    ):
        raise EnronSplitError("Verified preparation manifest changed before split construction.")
    return {
        # This is the hash of the exact manifest handle pinned and deep-verified
        # by ``load_enron_preparation_run``. Reopening the path here would let a
        # substituted manifest become bound to the already-verified profile.
        "manifest_sha256": verified_manifest_sha256,
        "profile_sha256": verified["artifacts"]["profile"]["sha256"],
        "prepared_sha256": prepared["sha256"],
        "prepared_records": prepared["records"],
        "prepared_occurrences": prepared["occurrences"],
        "dataset_id": source["dataset_id"],
        "dataset_revision": source["revision"],
        "dataset_split": source["split"],
        "cleaning_policy_sha256": profile["policies"]["cleaning_policy_sha256"],
        "grouping_policy_sha256": profile["policies"]["grouping_policy_sha256"],
        "date_policy_sha256": profile["policies"]["date_policy_sha256"],
    }


def _full_manifest(
    options: EnronSplitOptions,
    preparation: Mapping[str, Any],
    policy: Mapping[str, Any],
    state: _BuildState,
    roles: Mapping[str, Any],
    sealed_artifacts: Mapping[str, Any],
) -> dict[str, Any]:
    date_status_counts = {
        role: {
            key.removeprefix("temporal:"): value
            for key, value in state.cohort_counts[role].items()
            if key.startswith("temporal:")
        }
        for role in _ROLE_NAMES
    }
    return {
        "schema_version": SPLIT_MANIFEST_SCHEMA_VERSION,
        "benchmark_version": _BENCHMARK_ID,
        "artifact_kind": "synthetic_fixture" if options.fixture_mode else "real_benchmark",
        "fixture_mode": options.fixture_mode,
        "promotable": not options.fixture_mode,
        "preparation": dict(preparation),
        "policy": dict(policy),
        "roles": dict(roles),
        "aggregates": {
            "records": len(state.node_roles),
            "groups": len(state.components),
            "occurrences": sum(component.occurrences for component in state.components),
            "date_status_by_role": date_status_counts,
            "grouping_truncated_records": state.grouping_truncated_records,
        },
        "allocation": {
            **dict(state.allocation_audit),
            "group_assignments_sha256": sealed_artifacts["group_assignments"]["sha256"],
        },
        "cohorts": {
            "roles": {role: dict(state.cohort_counts[role]) for role in _ROLE_NAMES},
            "negative": {
                "status": "unsupported_without_exhaustive_labels",
                "records": 0,
            },
        },
        "sampling": {
            "role_records": dict(state.sample_counts),
            "representative_not_first_n": True,
        },
        "leakage": {
            "crossing_groups": 0,
            "audit": sealed_artifacts["leakage_audit"],
        },
        "sealing": {
            "test_sealed": True,
            "access_claim_file": "ACCESS_CLAIMED.json",
            "initial_access_state": "sealed_unbound",
            "one_shot": True,
            "required_frozen_target_fields": sorted(_FROZEN_TARGET_KEYS),
        },
        "artifacts": dict(sealed_artifacts),
        "privacy": {
            "artifacts_private": True,
            "aggregate_manifest_contains_raw_text": False,
            "aggregate_manifest_contains_direct_identifiers": False,
            "canonical_outputs_include_timestamps": False,
        },
    }


def _redacted_development_manifest(
    options: EnronSplitOptions,
    preparation: Mapping[str, Any],
    policy: Mapping[str, Any],
    state: _BuildState,
    roles: Mapping[str, Any],
    development_artifacts: Mapping[str, Any],
    full_manifest_sha256: str,
) -> dict[str, Any]:
    return {
        "schema_version": SPLIT_MANIFEST_SCHEMA_VERSION,
        "benchmark_version": _BENCHMARK_ID,
        "artifact_kind": "synthetic_fixture" if options.fixture_mode else "real_benchmark",
        "fixture_mode": options.fixture_mode,
        "promotable": not options.fixture_mode,
        "redacted": True,
        "preparation": dict(preparation),
        "policy": dict(policy),
        "development_roles": {role: roles[role] for role in ("train", "validation")},
        "sealed_test": {
            "records": state.role_records["test"],
            "groups": state.role_groups["test"],
            "test_sealed": True,
        },
        "development_cohorts": {role: dict(state.cohort_counts[role]) for role in ("train", "validation")},
        "allocation": dict(state.allocation_audit),
        "negative_cohort": {
            "status": "unsupported_without_exhaustive_labels",
            "records": 0,
        },
        "full_split_manifest_sha256": full_manifest_sha256,
        "artifacts": dict(development_artifacts),
        "privacy": {
            "test_artifact_hash_included": False,
            "test_artifact_name_included": False,
            "test_document_ids_included": False,
        },
    }


def _preseal_verification_receipt(
    *,
    options: EnronSplitOptions,
    preparation: Mapping[str, Any],
    policy: Mapping[str, Any],
    development_root: Path,
    sealed_root: Path,
    full_manifest: Mapping[str, Any],
    development_manifest: Mapping[str, Any],
    roles: Mapping[str, Any],
    development_artifacts: Mapping[str, Any],
    sealed_artifacts: Mapping[str, Any],
    replay_root: Path,
    activity_reporter: _ActivityReporter | None = None,
) -> dict[str, Any]:
    """Deep-check both staging roots and bind the proof before test sealing."""

    full_manifest_snapshot = _read_json_object_snapshot(sealed_root / "manifest.json")
    development_manifest_snapshot = _read_json_object_snapshot(development_root / "manifest.json")
    freeze_receipt_snapshot = _read_json_object_snapshot(development_root / "split-freeze-receipt.json")
    if full_manifest_snapshot.value != full_manifest or development_manifest_snapshot.value != development_manifest:
        raise EnronSplitError("Staged split manifests changed before pre-seal verification.")

    artifact_snapshots: dict[Path, _PrivateFileSnapshot] = {}
    role_snapshots: dict[str, _PrivateFileSnapshot] = {}
    for role in _ROLE_NAMES:
        if activity_reporter is not None:
            activity_reporter.boundary()
        root = sealed_root if role == "test" else development_root
        path = root / f"{role}.jsonl"
        snapshot = _verify_descriptor(
            root,
            roles[role]["artifact"],
            path.name,
            int(roles[role]["records"]),
            activity_reporter=activity_reporter,
        )
        role_snapshots[role] = snapshot
        artifact_snapshots[path] = snapshot
    for artifact_id, filename in (("memberships", "memberships.jsonl"), ("samples", "samples.jsonl")):
        path = development_root / filename
        artifact_snapshots[path] = _verify_descriptor(
            development_root,
            development_artifacts[artifact_id],
            filename,
            activity_reporter=activity_reporter,
        )
    artifact_snapshots[development_root / "split-freeze-receipt.json"] = _verify_descriptor(
        development_root,
        development_artifacts["freeze_receipt"],
        "split-freeze-receipt.json",
        observed=freeze_receipt_snapshot.file,
        activity_reporter=activity_reporter,
    )
    leakage_audit_snapshot = _read_json_object_snapshot(sealed_root / "leakage-audit.json")
    for artifact_id, filename in (
        ("memberships", "memberships.jsonl"),
        ("samples", "samples.jsonl"),
        ("group_assignments", "group-assignments.jsonl"),
        ("leakage_audit", "leakage-audit.json"),
    ):
        path = sealed_root / filename
        artifact_snapshots[path] = _verify_descriptor(
            sealed_root,
            sealed_artifacts[artifact_id],
            filename,
            observed=leakage_audit_snapshot.file if artifact_id == "leakage_audit" else None,
            activity_reporter=activity_reporter,
        )

    _verify_prepared_conservation(
        development_root,
        sealed_root,
        str(preparation["prepared_sha256"]),
        int(preparation["prepared_records"]),
        role_snapshots,
        activity_reporter=activity_reporter,
    )
    replayed_state = _rebuild_preseal_state(
        options=options,
        preparation=preparation,
        policy=policy,
        development_root=development_root,
        sealed_root=sealed_root,
        full_manifest=full_manifest,
        development_manifest=development_manifest,
        roles=roles,
        development_artifacts=development_artifacts,
        sealed_artifacts=sealed_artifacts,
        artifact_snapshots=artifact_snapshots,
        role_snapshots=role_snapshots,
        leakage_audit=leakage_audit_snapshot.value,
        freeze_receipt=freeze_receipt_snapshot.value,
        replay_root=replay_root,
        activity_reporter=activity_reporter,
    )
    for path, snapshot in artifact_snapshots.items():
        _assert_private_snapshot_current(path, snapshot)
    _assert_private_snapshot_current(sealed_root / "manifest.json", full_manifest_snapshot.file)
    _assert_private_snapshot_current(development_root / "manifest.json", development_manifest_snapshot.file)

    artifact_commitments = {
        "roles": {role: dict(roles[role]["artifact"]) for role in _ROLE_NAMES},
        "development": {name: dict(value) for name, value in sorted(development_artifacts.items())},
        "sealed": {name: dict(value) for name, value in sorted(sealed_artifacts.items())},
    }
    core = {
        "schema_version": SPLIT_PRESEAL_VERIFICATION_SCHEMA_VERSION,
        "benchmark_version": _BENCHMARK_ID,
        "fixture_mode": options.fixture_mode,
        "full_split_manifest_sha256": full_manifest_snapshot.file.sha256,
        "development_manifest_sha256": development_manifest_snapshot.file.sha256,
        "freeze_receipt_sha256": freeze_receipt_snapshot.file.sha256,
        "preparation_manifest_sha256": preparation["manifest_sha256"],
        "prepared_artifact_sha256": preparation["prepared_sha256"],
        "prepared_records": preparation["prepared_records"],
        "split_policy_sha256": policy["sha256"],
        "artifact_commitments_sha256": _hash_bytes(_canonical_json(artifact_commitments).encode("utf-8")),
        "roles": {
            role: {"records": replayed_state.role_records[role], "groups": replayed_state.role_groups[role]}
            for role in _ROLE_NAMES
        },
        "leakage_groups_crossing": 0,
        "test_content_verified_before_seal": True,
        "implementation_sha256": _hash_file(Path(__file__)),
    }
    return {**core, "receipt_sha256": _hash_bytes(_canonical_json(core).encode("utf-8"))}


@contextmanager
def _private_split_spool(
    scratch_root: Path,
    *,
    purpose: str,
    allow_unignored_output: bool,
    activity_callback: Callable[[], None] | None = None,
) -> Iterator[sqlite3.Connection]:
    """Own one SQLite spool in a pinned transaction that wipes to a tombstone."""

    if not re.fullmatch(r"[a-z0-9-]{1,48}", purpose):
        raise EnronSplitError("Private split spool purpose is invalid.")
    final = scratch_root / f".nerb-enron-{purpose}-{secrets.token_hex(12)}"
    connection: sqlite3.Connection | None = None
    operation_error: BaseException | None = None
    try:
        with PrivateRun(final, allow_unignored_output=allow_unignored_output) as run:
            try:
                spool_path = run.create_external_file("split.sqlite3")
                connection = _open_spool(spool_path, precreated=True)
                run.pin_cleanup_file("split.sqlite3")
                with sqlite_activity(connection, activity_callback):
                    yield connection
            except BaseException as exc:
                operation_error = exc
                raise
            finally:
                if connection is not None:
                    try:
                        connection.close()
                    except sqlite3.Error:
                        cleanup_error = EnronSplitError("Private split spool could not be closed safely.")
                        if operation_error is not None:
                            raise cleanup_error from operation_error
                        raise cleanup_error from None
    except EnronPrivateIOError as exc:
        raise EnronSplitError("Private split spool could not be cleaned safely.") from exc


@contextmanager
def _preseal_replay_connection(
    scratch_root: Path,
    *,
    allow_unignored_output: bool,
    activity_callback: Callable[[], None] | None = None,
) -> Iterator[sqlite3.Connection]:
    """Own the independent replay spool outside either committed split run."""

    with _private_split_spool(
        scratch_root,
        purpose="preseal-replay",
        allow_unignored_output=allow_unignored_output,
        activity_callback=activity_callback,
    ) as connection:
        yield connection


def _rebuild_preseal_state(
    *,
    options: EnronSplitOptions,
    preparation: Mapping[str, Any],
    policy: Mapping[str, Any],
    development_root: Path,
    sealed_root: Path,
    full_manifest: Mapping[str, Any],
    development_manifest: Mapping[str, Any],
    roles: Mapping[str, Any],
    development_artifacts: Mapping[str, Any],
    sealed_artifacts: Mapping[str, Any],
    artifact_snapshots: Mapping[Path, _PrivateFileSnapshot],
    role_snapshots: Mapping[str, _PrivateFileSnapshot],
    leakage_audit: Mapping[str, Any],
    freeze_receipt: Mapping[str, Any],
    replay_root: Path,
    activity_reporter: _ActivityReporter | None = None,
) -> _BuildState:
    """Independently reconstruct the split from staged role bytes before sealing."""

    expected_policy = _split_policy(options)
    if _canonical_json(policy) != _canonical_json(expected_policy):
        raise EnronSplitError("Frozen split policy differs from its canonical implementation.")
    expected_source = {
        "dataset_id": preparation["dataset_id"],
        "revision": preparation["dataset_revision"],
        "split": preparation["dataset_split"],
    }
    with _preseal_replay_connection(
        replay_root,
        allow_unignored_output=options.allow_unignored_output,
        activity_callback=None if activity_reporter is None else activity_reporter.boundary,
    ) as connection:
        try:
            role_counts: dict[str, int] = {}
            start_node = 0
            for index, role in enumerate(_ROLE_NAMES):
                count = _ingest_prepared(
                    connection,
                    (sealed_root if role == "test" else development_root) / f"{role}.jsonl",
                    expected_source,
                    start_node=start_node,
                    finalize=index == len(_ROLE_NAMES) - 1,
                    expected_snapshot=role_snapshots[role],
                    activity_reporter=activity_reporter,
                )
                role_counts[role] = count
                start_node += count
            observed_roles = tuple(role for role in _ROLE_NAMES for _ in range(role_counts[role]))
            union_find, edge_counts, near_candidate_emissions, near_candidate_pairs = _build_leakage_graph(
                connection,
                start_node,
                options,
                activity_reporter=activity_reporter,
            )
            components = _components(connection, union_find, activity_reporter=activity_reporter)
            expected_roles, node_groups, role_records, role_groups = _assign_components(
                components,
                options,
                activity_reporter=activity_reporter,
            )
            if expected_roles != observed_roles:
                raise EnronSplitError("Pre-seal role assignment differs from deterministic replay.")
            if any(
                role_records[role] != roles[role]["records"] or role_groups[role] != roles[role]["groups"]
                for role in _ROLE_NAMES
            ):
                raise EnronSplitError("Pre-seal role aggregates differ from deterministic replay.")
            grouping_truncated_records = int(
                connection.execute("SELECT COUNT(*) FROM records WHERE grouping_truncated = 1").fetchone()[0]
            )
            _enforce_support(
                components,
                start_node,
                role_records,
                role_groups,
                grouping_truncated_records,
                options,
            )
            memberships, cohorts = _derive_memberships(
                connection,
                components,
                expected_roles,
                node_groups,
                activity_reporter=activity_reporter,
            )
            _enforce_cohort_support(cohorts, options)
            selected_nodes, sample_counts = _select_samples(
                memberships,
                options,
                activity_reporter=activity_reporter,
            )
            state = _BuildState(
                components=components,
                node_roles=expected_roles,
                node_groups=node_groups,
                memberships=memberships,
                selected_nodes=selected_nodes,
                edge_counts=dict(sorted(edge_counts.items())),
                near_candidate_emissions=near_candidate_emissions,
                near_candidate_pairs=near_candidate_pairs,
                grouping_truncated_records=grouping_truncated_records,
                role_records=dict(role_records),
                role_groups=dict(role_groups),
                cohort_counts=cohorts,
                sample_counts=sample_counts,
                allocation_audit=_allocation_audit(
                    connection,
                    components,
                    expected_roles,
                    node_groups,
                    role_records,
                    start_node,
                    options,
                    activity_reporter=activity_reporter,
                ),
            )
            _verify_private_membership_artifacts(
                development_root,
                sealed_root,
                full_manifest,
                state,
                artifact_snapshots,
                activity_reporter=activity_reporter,
            )
            _verify_group_artifact(
                sealed_root,
                state,
                artifact_snapshots[sealed_root / "group-assignments.jsonl"],
                activity_reporter=activity_reporter,
            )
            expected_allocation = {
                **dict(state.allocation_audit),
                "group_assignments_sha256": sealed_artifacts["group_assignments"]["sha256"],
            }
            if (
                full_manifest.get("allocation") != expected_allocation
                or development_manifest.get("allocation") != state.allocation_audit
                or full_manifest.get("cohorts", {}).get("roles") != {role: dict(cohorts[role]) for role in _ROLE_NAMES}
                or full_manifest.get("sampling", {}).get("role_records") != sample_counts
                or leakage_audit != _leakage_audit(state)
            ):
                raise EnronSplitError("Pre-seal aggregate evidence differs from deterministic replay.")
            manifest_sha256 = _hash_file(
                sealed_root / "manifest.json",
                activity_reporter=activity_reporter,
            )
            expected_full_manifest = _full_manifest(
                options,
                preparation,
                expected_policy,
                state,
                roles,
                sealed_artifacts,
            )
            expected_development_manifest = _redacted_development_manifest(
                options,
                preparation,
                expected_policy,
                state,
                roles,
                development_artifacts,
                manifest_sha256,
            )
            expected_freeze_receipt = {
                "schema_version": SPLIT_FREEZE_RECEIPT_SCHEMA_VERSION,
                "benchmark_version": _BENCHMARK_ID,
                "fixture_mode": options.fixture_mode,
                "promotable": not options.fixture_mode,
                "preparation_manifest_sha256": preparation["manifest_sha256"],
                "split_policy_sha256": expected_policy["sha256"],
                "full_split_manifest_sha256": manifest_sha256,
                "roles": {
                    role: {"records": state.role_records[role], "groups": state.role_groups[role]}
                    for role in _ROLE_NAMES
                },
                "leakage_groups_crossing": 0,
                "test_sealed": True,
            }
            if (
                _canonical_json(full_manifest) != _canonical_json(expected_full_manifest)
                or _canonical_json(development_manifest) != _canonical_json(expected_development_manifest)
                or _canonical_json(freeze_receipt) != _canonical_json(expected_freeze_receipt)
            ):
                raise EnronSplitError("Pre-seal manifests differ from deterministic replay.")
            return state
        finally:
            # The replay spool context owns the connection and must remove its
            # SQLite progress handler before closing it.
            connection.rollback()


def split_enron_preparation(options: EnronSplitOptions) -> dict[str, Any]:
    """Create immutable development and sealed split runs from a verified preparation run."""

    _validate_options(options)
    activity = _ActivityReporter(options.activity_callback)
    try:
        activity.boundary()
        verified = load_enron_preparation_run(
            options.preparation_run,
            scratch_dir=options.scratch_dir,
            activity_callback=options.activity_callback,
        )
        preparation = _preparation_binding(
            options.preparation_run,
            verified,
            activity_reporter=activity,
        )
        policy = _split_policy(options)
        prepared_path = options.preparation_run / "prepared.jsonl"
        with (
            PrivateRun(
                options.development_output_dir,
                allow_unignored_output=options.allow_unignored_output,
            ) as development_run,
            PrivateRun(
                options.sealed_output_dir,
                allow_unignored_output=options.allow_unignored_output,
            ) as sealed_run,
        ):
            spool_stack = ExitStack()
            connection = spool_stack.enter_context(
                _private_split_spool(
                    options.scratch_dir,
                    purpose="construction",
                    allow_unignored_output=options.allow_unignored_output,
                    activity_callback=activity.boundary,
                )
            )
            try:
                records = _ingest_prepared(
                    connection,
                    prepared_path,
                    verified["profile"]["source"],
                    progress_callback=options.progress_callback,
                    activity_reporter=activity,
                )
                activity.boundary()
                state = _build_state(connection, records, options, activity_reporter=activity)
                activity.boundary()
                with (
                    development_run.open_binary("train.jsonl") as train_file,
                    development_run.open_binary("validation.jsonl") as validation_file,
                    sealed_run.open_binary("test.jsonl") as test_file,
                ):
                    _write_role_records(
                        prepared_path,
                        connection,
                        str(preparation["prepared_sha256"]),
                        state,
                        train_file,
                        validation_file,
                        test_file,
                        activity_reporter=activity,
                    )
                with (
                    development_run.open_binary("memberships.jsonl") as development_memberships,
                    development_run.open_binary("samples.jsonl") as development_samples,
                    sealed_run.open_binary("memberships.jsonl") as sealed_memberships,
                    sealed_run.open_binary("samples.jsonl") as sealed_samples,
                ):
                    development_membership_count, sealed_membership_count = _write_memberships_and_samples(
                        state,
                        development_memberships,
                        development_samples,
                        sealed_memberships,
                        sealed_samples,
                        activity_reporter=activity,
                    )
                with sealed_run.open_binary("group-assignments.jsonl") as group_file:
                    _write_groups(group_file, state, activity_reporter=activity)
                audit = _leakage_audit(state)
                with sealed_run.open_text("leakage-audit.json") as audit_file:
                    _write_json(audit_file, audit)

                activity.boundary()
                roles = _role_descriptors(
                    state,
                    development_run.stage_dir,
                    sealed_run.stage_dir,
                    activity_reporter=activity,
                )
                sealed_artifacts = {
                    "test": roles["test"]["artifact"],
                    "memberships": _artifact_descriptor(
                        sealed_run.stage_dir / "memberships.jsonl",
                        records=sealed_membership_count,
                        artifact_id="test_memberships",
                        activity_reporter=activity,
                    ),
                    "samples": _artifact_descriptor(
                        sealed_run.stage_dir / "samples.jsonl",
                        records=state.sample_counts["test"],
                        artifact_id="test_samples",
                        activity_reporter=activity,
                    ),
                    "group_assignments": _artifact_descriptor(
                        sealed_run.stage_dir / "group-assignments.jsonl",
                        records=len(state.components),
                        artifact_id="group_assignments",
                        activity_reporter=activity,
                    ),
                    "leakage_audit": _artifact_descriptor(
                        sealed_run.stage_dir / "leakage-audit.json",
                        records=1,
                        artifact_id="leakage_audit",
                        activity_reporter=activity,
                    ),
                }
                full_manifest = _full_manifest(options, preparation, policy, state, roles, sealed_artifacts)
                _validate_aggregate_privacy(full_manifest)
                with sealed_run.open_text("manifest.json") as manifest_file:
                    _write_json(manifest_file, full_manifest)
                full_manifest_sha256 = _hash_file(
                    sealed_run.stage_dir / "manifest.json",
                    activity_reporter=activity,
                )

                freeze_receipt = {
                    "schema_version": SPLIT_FREEZE_RECEIPT_SCHEMA_VERSION,
                    "benchmark_version": _BENCHMARK_ID,
                    "fixture_mode": options.fixture_mode,
                    "promotable": not options.fixture_mode,
                    "preparation_manifest_sha256": preparation["manifest_sha256"],
                    "split_policy_sha256": policy["sha256"],
                    "full_split_manifest_sha256": full_manifest_sha256,
                    "roles": {
                        role: {"records": state.role_records[role], "groups": state.role_groups[role]}
                        for role in _ROLE_NAMES
                    },
                    "leakage_groups_crossing": 0,
                    "test_sealed": True,
                }
                _validate_aggregate_privacy(freeze_receipt)
                with development_run.open_text("split-freeze-receipt.json") as receipt_file:
                    _write_json(receipt_file, freeze_receipt)
                development_artifacts = {
                    "train": roles["train"]["artifact"],
                    "validation": roles["validation"]["artifact"],
                    "memberships": _artifact_descriptor(
                        development_run.stage_dir / "memberships.jsonl",
                        records=development_membership_count,
                        artifact_id="development_memberships",
                        activity_reporter=activity,
                    ),
                    "samples": _artifact_descriptor(
                        development_run.stage_dir / "samples.jsonl",
                        records=state.sample_counts["train"] + state.sample_counts["validation"],
                        artifact_id="development_samples",
                        activity_reporter=activity,
                    ),
                    "freeze_receipt": _artifact_descriptor(
                        development_run.stage_dir / "split-freeze-receipt.json",
                        records=1,
                        artifact_id="freeze_receipt",
                        activity_reporter=activity,
                    ),
                }
                development_manifest = _redacted_development_manifest(
                    options,
                    preparation,
                    policy,
                    state,
                    roles,
                    development_artifacts,
                    full_manifest_sha256,
                )
                _validate_aggregate_privacy(development_manifest)
                with development_run.open_text("manifest.json") as manifest_file:
                    _write_json(manifest_file, development_manifest)
                development_manifest_sha256 = _hash_file(
                    development_run.stage_dir / "manifest.json",
                    activity_reporter=activity,
                )
                summary_groups = len(state.components)
                summary_roles = {
                    role: {"records": state.role_records[role], "groups": state.role_groups[role]}
                    for role in _ROLE_NAMES
                }
                spool_stack.close()
                del state
                preseal_verification = _preseal_verification_receipt(
                    options=options,
                    preparation=preparation,
                    policy=policy,
                    development_root=development_run.stage_dir,
                    sealed_root=sealed_run.stage_dir,
                    full_manifest=full_manifest,
                    development_manifest=development_manifest,
                    roles=roles,
                    development_artifacts=development_artifacts,
                    sealed_artifacts=sealed_artifacts,
                    replay_root=options.scratch_dir,
                    activity_reporter=activity,
                )
                _validate_aggregate_privacy(preseal_verification)
                with sealed_run.open_text("PRESEAL_VERIFIED.json") as receipt_file:
                    _write_json(receipt_file, preseal_verification)
                preseal_verification_sha256 = _hash_file(
                    sealed_run.stage_dir / "PRESEAL_VERIFIED.json",
                    activity_reporter=activity,
                )
                activity.boundary()
            finally:
                spool_stack.close()
            # Sealed data becomes immutable before its redacted development
            # receipt, preventing a visible receipt for an absent sealed run.
            sealed_run.commit(cleanup_successor=options.cleanup_successor)
            development_run.commit(cleanup_successor=options.cleanup_successor)
            pair_receipt = {
                "schema_version": SPLIT_PAIR_RECEIPT_SCHEMA_VERSION,
                "benchmark_version": _BENCHMARK_ID,
                "sealed_manifest_sha256": full_manifest_sha256,
                "development_manifest_sha256": development_manifest_sha256,
                "freeze_receipt_sha256": development_artifacts["freeze_receipt"]["sha256"],
                "preseal_verification_sha256": preseal_verification_sha256,
            }
            _validate_aggregate_privacy(pair_receipt)
            _write_exclusive_private_json(sealed_run.final_dir, "PAIR_COMMITTED.json", pair_receipt)
    except EnronSplitError:
        raise
    except Exception:
        raise EnronSplitError("Enron split construction failed safely.") from None

    return {
        "schema_version": SPLIT_MANIFEST_SCHEMA_VERSION,
        "committed": True,
        "benchmark_version": _BENCHMARK_ID,
        "fixture_mode": options.fixture_mode,
        "promotable": not options.fixture_mode,
        "records": records,
        "groups": summary_groups,
        "roles": summary_roles,
        "manifest_sha256": full_manifest_sha256,
        "policy_sha256": policy["sha256"],
    }


def _reject_duplicate_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EnronSplitError("JSON object contains a duplicate key.")
        result[key] = value
    return result


@dataclass(frozen=True, slots=True)
class _PrivateFileSnapshot:
    sha256: str
    bytes: int
    identity: tuple[int, int, int, int, int, int, int]


@dataclass(frozen=True, slots=True)
class _PrivateJSONObjectSnapshot:
    value: dict[str, Any]
    file: _PrivateFileSnapshot


def _assert_private_snapshot_current(path: Path, snapshot: _PrivateFileSnapshot) -> None:
    try:
        with open_private_binary_input(path) as current:
            current_identity = _private_regular_identity(os.fstat(current.fileno()))
    except EnronSplitError:
        raise
    except (EnronPrivateIOError, OSError, OverflowError, ValueError):
        raise EnronSplitError(f"{path.name} changed while it was being verified.") from None
    if current_identity != snapshot.identity:
        raise EnronSplitError(f"{path.name} changed while it was being verified.")


def _assert_private_snapshot_current_at(
    directory_fd: int,
    name: str,
    snapshot: _PrivateFileSnapshot,
) -> None:
    try:
        with open_private_binary_input_at(directory_fd, name) as current:
            current_identity = _private_regular_identity(os.fstat(current.fileno()))
    except EnronSplitError:
        raise
    except (EnronPrivateIOError, OSError, OverflowError, ValueError):
        raise EnronSplitError(f"{name} changed while it was being verified.") from None
    if current_identity != snapshot.identity:
        raise EnronSplitError(f"{name} changed while it was being verified.")


def _read_json_snapshot_from_handle(
    handle: BinaryIO,
    name: str,
    max_bytes: int,
) -> _PrivateJSONObjectSnapshot:
    before_identity = _private_regular_identity(os.fstat(handle.fileno()))
    if before_identity[4] > max_bytes:
        raise EnronSplitError(f"{name} exceeds its byte limit.")
    raw = handle.read(max_bytes + 1)
    after_identity = _private_regular_identity(os.fstat(handle.fileno()))
    if before_identity != after_identity or len(raw) != before_identity[4]:
        raise EnronSplitError(f"{name} changed while it was being read.")
    value = json.loads(
        raw.decode("utf-8"),
        parse_constant=lambda _value: (_ for _ in ()).throw(EnronSplitError("Non-finite JSON is invalid.")),
        parse_float=_parse_finite_split_float,
        parse_int=_parse_bounded_split_int,
        object_pairs_hook=_reject_duplicate_keys,
    )
    if not isinstance(value, dict):
        raise EnronSplitError(f"{name} must contain a JSON object.")
    _validate_private_json_depth(value)
    return _PrivateJSONObjectSnapshot(
        value=value,
        file=_PrivateFileSnapshot(
            sha256="sha256:" + hashlib.sha256(raw).hexdigest(),
            bytes=len(raw),
            identity=after_identity,
        ),
    )


def _read_json_object_snapshot(
    path: Path,
    *,
    max_bytes: int = 16 * 1024 * 1024,
) -> _PrivateJSONObjectSnapshot:
    if type(max_bytes) is not int or max_bytes <= 0:
        raise EnronSplitError("Private JSON byte limit must be a positive integer.")
    try:
        with open_private_binary_input(path) as handle:
            snapshot = _read_json_snapshot_from_handle(handle, path.name, max_bytes)
    except EnronSplitError:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        OverflowError,
        ValueError,
        EnronPrivateIOError,
        OSError,
    ):
        raise EnronSplitError(f"{path.name} is not a valid private JSON object.") from None
    _assert_private_snapshot_current(path, snapshot.file)
    return snapshot


def _read_json_object_snapshot_at(
    directory_fd: int,
    name: str,
    *,
    max_bytes: int = 16 * 1024 * 1024,
) -> _PrivateJSONObjectSnapshot:
    if type(max_bytes) is not int or max_bytes <= 0:
        raise EnronSplitError("Private JSON byte limit must be a positive integer.")
    try:
        with open_private_binary_input_at(directory_fd, name) as handle:
            snapshot = _read_json_snapshot_from_handle(handle, name, max_bytes)
    except EnronSplitError:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        OverflowError,
        ValueError,
        EnronPrivateIOError,
        OSError,
    ):
        raise EnronSplitError(f"{name} is not a valid private JSON object.") from None
    _assert_private_snapshot_current_at(directory_fd, name, snapshot.file)
    return snapshot


def _read_json_object(path: Path, *, max_bytes: int = 16 * 1024 * 1024) -> dict[str, Any]:
    return _read_json_object_snapshot(path, max_bytes=max_bytes).value


def _validate_private_json_depth(value: Any) -> None:
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if depth > _MAX_PRIVATE_JSON_DEPTH:
            raise EnronSplitError("Private JSON nesting depth exceeds the safety limit.")
        if isinstance(item, Mapping):
            stack.extend((nested, depth + 1) for nested in item.values())
        elif isinstance(item, list):
            stack.extend((nested, depth + 1) for nested in item)


def _assert_committed_run_at(
    directory_fd: int,
    expected_files: Sequence[str],
    *,
    allow_access_files: bool = False,
) -> None:
    try:
        root_info = os.fstat(directory_fd)
        if not stat.S_ISDIR(root_info.st_mode) or stat.S_IMODE(root_info.st_mode) & 0o077:
            raise EnronSplitError("Split run directory is not private.")
        with open_private_binary_input_at(directory_fd, _COMMIT_MARKER) as handle:
            if handle.read(len(_COMMIT_PAYLOAD) + 1) != _COMMIT_PAYLOAD:
                raise EnronSplitError("Split commit marker is invalid.")
    except EnronSplitError:
        raise
    except (EnronPrivateIOError, OSError, ValueError):
        raise EnronSplitError("Split run contains an unsafe private file.") from None
    allowed = set(expected_files) | {_COMMIT_MARKER}
    if allow_access_files:
        allowed |= {"EVIDENCE_BOUND.json", "ACCESS_CLAIMED.json", "ACCESS_OUTCOME.json"}
    try:
        actual = set(os.listdir(directory_fd))
    except OSError:
        raise EnronSplitError("Split run could not be enumerated safely.") from None
    if any(_RECEIPT_STAGE_RE.fullmatch(name) for name in actual):
        _cleanup_stale_receipt_stages_at(directory_fd)
        try:
            actual = set(os.listdir(directory_fd))
        except OSError:
            raise EnronSplitError("Split run could not be re-enumerated after receipt recovery.") from None
    tombstones = {name for name in actual if _RECEIPT_TOMBSTONE_RE.fullmatch(name)}
    if len(tombstones) > _MAX_RECEIPT_TOMBSTONES:
        raise EnronSplitError("Split run contains too many retained receipt tombstones.")
    visible = actual - tombstones
    if visible != allowed and not (allow_access_files and set(expected_files) | {_COMMIT_MARKER} <= visible <= allowed):
        raise EnronSplitError("Split run file inventory is invalid.")
    for name in actual:
        try:
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError:
            raise EnronSplitError("Split run file inventory changed during validation.") from None
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) & 0o077
            or (_RECEIPT_TOMBSTONE_RE.fullmatch(name) is not None and info.st_size != 0)
        ):
            raise EnronSplitError("Split run contains an unsafe file.")


def _assert_committed_run(root: Path, expected_files: Sequence[str], *, allow_access_files: bool = False) -> Path:
    try:
        normalized = root.expanduser().absolute()
    except (OSError, RuntimeError, ValueError):
        raise EnronSplitError("Split run path is invalid.") from None
    directory_fd = _open_pinned_private_root(normalized)
    try:
        _assert_committed_run_at(directory_fd, expected_files, allow_access_files=allow_access_files)
    finally:
        os.close(directory_fd)
    return normalized


def _snapshot_private_artifact(
    path: Path,
    expected_bytes: int,
    *,
    activity_reporter: _ActivityReporter | None = None,
) -> _PrivateFileSnapshot:
    digest = hashlib.sha256()
    byte_count = 0
    try:
        with open_private_binary_input(path) as handle:
            before_identity = _private_regular_identity(os.fstat(handle.fileno()))
            if before_identity[4] != expected_bytes:
                raise EnronSplitError("Split artifact size differs from its descriptor.")
            chunk_count = 0
            while chunk := handle.read(1024 * 1024):
                chunk_count += 1
                byte_count += len(chunk)
                if byte_count > expected_bytes:
                    raise EnronSplitError("Split artifact size differs from its descriptor.")
                digest.update(chunk)
                if activity_reporter is not None and chunk_count % 256 == 0:
                    activity_reporter.boundary()
            after_identity = _private_regular_identity(os.fstat(handle.fileno()))
    except EnronSplitError:
        raise
    except (EnronPrivateIOError, OSError, OverflowError, ValueError):
        raise EnronSplitError("Split artifact could not be verified safely.") from None
    if before_identity != after_identity or byte_count != expected_bytes:
        raise EnronSplitError("Split artifact changed while it was being verified.")
    snapshot = _PrivateFileSnapshot(
        sha256="sha256:" + digest.hexdigest(),
        bytes=byte_count,
        identity=after_identity,
    )
    _assert_private_snapshot_current(path, snapshot)
    return snapshot


def _verify_descriptor(
    root: Path,
    descriptor: Any,
    expected_name: str,
    expected_records: int | None = None,
    *,
    observed: _PrivateFileSnapshot | None = None,
    activity_reporter: _ActivityReporter | None = None,
) -> _PrivateFileSnapshot:
    if not isinstance(descriptor, Mapping) or set(descriptor) != {"id", "name", "sha256", "bytes", "records"}:
        raise EnronSplitError("Split artifact descriptor is invalid.")
    if (
        descriptor.get("name") != expected_name
        or not isinstance(descriptor.get("id"), str)
        or not isinstance(descriptor.get("sha256"), str)
        or not _SHA256_RE.fullmatch(descriptor["sha256"])
        or isinstance(descriptor.get("bytes"), bool)
        or not isinstance(descriptor.get("bytes"), int)
        or descriptor["bytes"] < 0
        or isinstance(descriptor.get("records"), bool)
        or not isinstance(descriptor.get("records"), int)
        or descriptor["records"] < 0
    ):
        raise EnronSplitError("Split artifact descriptor name is invalid.")
    if expected_records is not None and descriptor.get("records") != expected_records:
        raise EnronSplitError("Split artifact descriptor record count is invalid.")
    artifact = root / expected_name
    snapshot = observed or _snapshot_private_artifact(
        artifact,
        int(descriptor["bytes"]),
        activity_reporter=activity_reporter,
    )
    if descriptor.get("sha256") != snapshot.sha256 or descriptor.get("bytes") != snapshot.bytes:
        raise EnronSplitError("Split artifact descriptor does not match its file.")
    return snapshot


def _verify_descriptor_metadata(
    root: Path,
    descriptor: Any,
    expected_name: str,
    expected_records: int | None = None,
    *,
    directory_fd: int | None = None,
) -> None:
    """Validate a sealed descriptor and file metadata without opening its content."""

    if not isinstance(descriptor, Mapping) or set(descriptor) != {"id", "name", "sha256", "bytes", "records"}:
        raise EnronSplitError("Split artifact descriptor is invalid.")
    if (
        descriptor.get("name") != expected_name
        or not isinstance(descriptor.get("id"), str)
        or not isinstance(descriptor.get("sha256"), str)
        or not _SHA256_RE.fullmatch(str(descriptor["sha256"]))
        or type(descriptor.get("bytes")) is not int
        or int(descriptor["bytes"]) < 0
        or type(descriptor.get("records")) is not int
        or int(descriptor["records"]) < 0
        or (expected_records is not None and descriptor["records"] != expected_records)
    ):
        raise EnronSplitError("Split artifact descriptor metadata is invalid.")
    try:
        info = (
            os.stat(expected_name, dir_fd=directory_fd, follow_symlinks=False)
            if directory_fd is not None
            else (root / expected_name).lstat()
        )
    except OSError:
        raise EnronSplitError("Sealed split artifact metadata could not be inspected safely.") from None
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) & 0o077
        or info.st_size != descriptor["bytes"]
    ):
        raise EnronSplitError("Sealed split artifact metadata differs from its pre-seal descriptor.")


def _frozen_artifact_contract(path: Path, descriptor: Mapping[str, Any]) -> tuple[str, int, int]:
    if (
        set(descriptor) != {"id", "name", "sha256", "bytes", "records"}
        or descriptor.get("name") != path.name
        or not isinstance(descriptor.get("sha256"), str)
        or not _SHA256_RE.fullmatch(str(descriptor["sha256"]))
        or type(descriptor.get("bytes")) is not int
        or int(descriptor["bytes"]) < 0
        or type(descriptor.get("records")) is not int
        or int(descriptor["records"]) < 0
    ):
        raise EnronSplitError("Frozen development artifact descriptor is invalid.")
    return str(descriptor["sha256"]), int(descriptor["bytes"]), int(descriptor["records"])


def _private_regular_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    mode = stat.S_IMODE(info.st_mode)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or mode & 0o077:
        raise EnronSplitError("Frozen development artifacts must remain private single-link regular files.")
    return (
        info.st_dev,
        info.st_ino,
        mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _parse_frozen_jsonl_object(path: Path, line_no: int, raw: bytes) -> dict[str, Any]:
    try:
        payload = raw.decode("utf-8")
        value = json.loads(
            payload,
            parse_constant=lambda _value: (_ for _ in ()).throw(EnronSplitError("Non-finite JSON is invalid.")),
            parse_float=_parse_finite_split_float,
            parse_int=_parse_bounded_split_int,
            object_pairs_hook=_reject_duplicate_keys,
        )
    except EnronSplitError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, OverflowError, ValueError):
        raise EnronSplitError(f"{path.name} line {line_no} is not valid strict JSON.") from None
    if not isinstance(value, dict):
        raise EnronSplitError(f"{path.name} line {line_no} must contain a JSON object.")
    _validate_private_json_depth(value)
    return value


def _parse_finite_split_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise EnronSplitError("Non-finite JSON is invalid.")
    return parsed


def _parse_bounded_split_int(value: str) -> int:
    digits = value[1:] if value.startswith("-") else value
    if len(digits) > _MAX_PRIVATE_JSON_INTEGER_DIGITS:
        raise EnronSplitError("JSON integer exceeds the digit limit.")
    try:
        return int(value)
    except (OverflowError, ValueError):
        raise EnronSplitError("JSON integer is invalid.") from None


def _iter_snapshot_jsonl(
    path: Path,
    expected_snapshot: _PrivateFileSnapshot,
) -> Iterator[tuple[int, bytes, dict[str, Any]]]:
    digest = hashlib.sha256()
    byte_count = 0
    record_count = 0
    before_identity: tuple[int, int, int, int, int, int, int] | None = None
    after_identity: tuple[int, int, int, int, int, int, int] | None = None
    try:
        with open_private_binary_input(path) as handle:
            before_identity = _private_regular_identity(os.fstat(handle.fileno()))
            if before_identity != expected_snapshot.identity or before_identity[4] != expected_snapshot.bytes:
                raise EnronSplitError("Split artifact identity differs from its frozen snapshot.")
            while True:
                raw = handle.readline(DEFAULT_MAX_PREPARED_LINE_BYTES + 1)
                if not raw:
                    break
                record_count += 1
                byte_count += len(raw)
                digest.update(raw)
                if len(raw) > DEFAULT_MAX_PREPARED_LINE_BYTES:
                    raise EnronSplitError(f"{path.name} line {record_count} exceeds the byte limit.")
                yield record_count, raw, _parse_frozen_jsonl_object(path, record_count, raw)
            after_identity = _private_regular_identity(os.fstat(handle.fileno()))
    except EnronSplitError:
        raise
    except (EnronPrivateIOError, OSError, OverflowError, ValueError):
        raise EnronSplitError("Frozen development artifact could not be consumed safely.") from None

    if before_identity is None or after_identity is None or before_identity != after_identity:
        raise EnronSplitError("Split artifact changed while it was consumed.")
    if byte_count != expected_snapshot.bytes or "sha256:" + digest.hexdigest() != expected_snapshot.sha256:
        raise EnronSplitError("Consumed split artifact differs from its frozen snapshot.")

    _assert_private_snapshot_current(path, expected_snapshot)


def _iter_frozen_development_jsonl(
    path: Path,
    descriptor: Mapping[str, Any],
    expected_snapshot: _PrivateFileSnapshot,
) -> Iterator[tuple[int, bytes, dict[str, Any]]]:
    expected_sha256, expected_bytes, expected_records = _frozen_artifact_contract(path, descriptor)
    if expected_snapshot.sha256 != expected_sha256 or expected_snapshot.bytes != expected_bytes:
        raise EnronSplitError("Frozen development artifact snapshot does not match its descriptor.")

    records = 0
    for line_no, raw, row in _iter_snapshot_jsonl(path, expected_snapshot):
        records += 1
        yield line_no, raw, row
    if records != expected_records:
        raise EnronSplitError("Frozen development artifact record count differs from its descriptor.")


def _iter_role_records(
    path: Path,
    descriptor: Mapping[str, Any],
    expected_snapshot: _PrivateFileSnapshot,
) -> Iterator[dict[str, Any]]:
    _expected_sha256, _expected_bytes, expected_records = _frozen_artifact_contract(path, descriptor)
    records = 0
    previous: str | None = None
    for _, raw, row in _iter_frozen_development_jsonl(path, descriptor, expected_snapshot):
        document_id = row.get("document_id")
        if (
            not isinstance(document_id, str)
            or not _DOCUMENT_ID_RE.fullmatch(document_id)
            or (previous is not None and document_id <= previous)
            or raw != _canonical_line(row)
        ):
            raise EnronSplitError("Split role record stream is not canonical.")
        previous = document_id
        records += 1
        yield dict(row)
    if records != expected_records:
        raise EnronSplitError("Split role record count is invalid.")


class EnronDevelopmentSplit:
    """Verified train/validation-only access to a redacted development run."""

    __slots__ = (
        "_artifact_snapshots",
        "_expected_memberships_by_role",
        "_freeze_receipt_snapshot",
        "_manifest_snapshot",
        "_memberships_descriptor",
        "_root",
        "_train_descriptor",
        "_validation_descriptor",
        "freeze_receipt",
        "manifest",
    )

    def __init__(
        self,
        root: Path,
        manifest: Mapping[str, Any],
        freeze_receipt: Mapping[str, Any],
        *,
        artifact_snapshots: Mapping[str, _PrivateFileSnapshot],
        manifest_snapshot: _PrivateFileSnapshot,
        freeze_receipt_snapshot: _PrivateFileSnapshot,
    ) -> None:
        self._root = root
        self.manifest = dict(manifest)
        self.freeze_receipt = dict(freeze_receipt)
        self._artifact_snapshots = dict(artifact_snapshots)
        self._manifest_snapshot = manifest_snapshot
        self._freeze_receipt_snapshot = freeze_receipt_snapshot
        self._train_descriptor = dict(manifest["development_roles"]["train"]["artifact"])
        self._validation_descriptor = dict(manifest["development_roles"]["validation"]["artifact"])
        self._memberships_descriptor = dict(manifest["artifacts"]["memberships"])
        self._expected_memberships_by_role = {
            role: int(manifest["development_roles"][role]["records"]) for role in ("train", "validation")
        }

    def _assert_metadata_current(self) -> None:
        _assert_private_snapshot_current(self._root / "manifest.json", self._manifest_snapshot)
        _assert_private_snapshot_current(
            self._root / "split-freeze-receipt.json",
            self._freeze_receipt_snapshot,
        )

    def _guard_metadata(self, records: Iterator[dict[str, Any]]) -> Iterator[dict[str, Any]]:
        self._assert_metadata_current()
        yield from records
        self._assert_metadata_current()

    @property
    def manifest_sha256(self) -> str:
        """Return the exact loaded manifest hash while its frozen metadata remains current."""

        self._assert_metadata_current()
        return self._manifest_snapshot.sha256

    def iter_train_records(self) -> Iterator[dict[str, Any]]:
        return self._guard_metadata(
            _iter_role_records(
                self._root / "train.jsonl",
                self._train_descriptor,
                self._artifact_snapshots["train"],
            )
        )

    def iter_validation_records(self) -> Iterator[dict[str, Any]]:
        return self._guard_metadata(
            _iter_role_records(
                self._root / "validation.jsonl",
                self._validation_descriptor,
                self._artifact_snapshots["validation"],
            )
        )

    def _iter_memberships(self) -> Iterator[dict[str, Any]]:
        return self._guard_metadata(
            _iter_development_memberships(
                self._root / "memberships.jsonl",
                descriptor=self._memberships_descriptor,
                expected_by_role=self._expected_memberships_by_role,
                expected_snapshot=self._artifact_snapshots["memberships"],
            )
        )

    def iter_train_memberships(self) -> Iterator[dict[str, Any]]:
        """Iterate verified train memberships in train-record order."""

        return (row for row in self._iter_memberships() if row["role"] == "train")

    def iter_validation_memberships(self) -> Iterator[dict[str, Any]]:
        """Iterate verified validation memberships in validation-record order."""

        return (row for row in self._iter_memberships() if row["role"] == "validation")


def _validate_development_admission_limits(
    contracts: Mapping[str, tuple[str, int, int]],
    limits: EnronDevelopmentAdmissionLimits | None,
) -> None:
    if limits is None:
        return
    if type(limits) is not EnronDevelopmentAdmissionLimits:
        raise EnronDevelopmentAdmissionError("Development admission limits are invalid.")
    configured = (
        limits.max_train_records,
        limits.max_train_artifact_bytes,
        limits.max_validation_records,
        limits.max_validation_artifact_bytes,
        limits.max_development_memberships_bytes,
        limits.max_development_samples_bytes,
    )
    if any(type(value) is not int or value <= 0 for value in configured):
        raise EnronDevelopmentAdmissionError("Development admission limits must be positive integers.")
    checks = (
        ("train records", contracts["train"][2], limits.max_train_records),
        ("train artifact bytes", contracts["train"][1], limits.max_train_artifact_bytes),
        ("validation records", contracts["validation"][2], limits.max_validation_records),
        (
            "validation artifact bytes",
            contracts["validation"][1],
            limits.max_validation_artifact_bytes,
        ),
        (
            "development memberships artifact bytes",
            contracts["memberships"][1],
            limits.max_development_memberships_bytes,
        ),
        (
            "development samples artifact bytes",
            contracts["samples"][1],
            limits.max_development_samples_bytes,
        ),
    )
    for description, declared, maximum in checks:
        if declared > maximum:
            raise EnronDevelopmentAdmissionError(f"Declared {description} exceed the development admission limit.")


def load_enron_development_split(
    path: Path,
    *,
    admission_limits: EnronDevelopmentAdmissionLimits | None = None,
    activity_callback: Callable[[], None] | None = None,
) -> EnronDevelopmentSplit:
    """Load a redacted development run without exposing any test selector."""

    if activity_callback is not None and not callable(activity_callback):
        raise EnronSplitError("Development activity callback must be callable when provided.")
    activity = _ActivityReporter(activity_callback)
    activity.boundary()
    root = _assert_committed_run(path, _DEVELOPMENT_FILES)
    manifest_snapshot = _read_json_object_snapshot(root / "manifest.json")
    freeze_receipt_snapshot = _read_json_object_snapshot(root / "split-freeze-receipt.json")
    manifest = manifest_snapshot.value
    receipt = freeze_receipt_snapshot.value
    artifact_snapshots: dict[str, _PrivateFileSnapshot] = {}
    _validate_aggregate_privacy(manifest)
    _validate_aggregate_privacy(receipt)
    expected_manifest_keys = {
        "schema_version",
        "benchmark_version",
        "artifact_kind",
        "fixture_mode",
        "promotable",
        "redacted",
        "preparation",
        "policy",
        "development_roles",
        "sealed_test",
        "development_cohorts",
        "allocation",
        "negative_cohort",
        "full_split_manifest_sha256",
        "artifacts",
        "privacy",
    }
    if set(manifest) != expected_manifest_keys or manifest.get("schema_version") != SPLIT_MANIFEST_SCHEMA_VERSION:
        raise EnronSplitError("Development split manifest schema is invalid.")
    _validate_preparation_binding(manifest.get("preparation"))
    if manifest.get("redacted") is not True or manifest.get("sealed_test", {}).get("test_sealed") is not True:
        raise EnronSplitError("Development split is not redacted and sealed.")
    if set(manifest["development_roles"]) != {"train", "validation"}:
        raise EnronSplitError("Development role inventory is invalid.")
    if set(manifest["sealed_test"]) != {"records", "groups", "test_sealed"}:
        raise EnronSplitError("Redacted sealed-test descriptor is invalid.")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, Mapping) or set(artifacts) != {
        "train",
        "validation",
        "memberships",
        "samples",
        "freeze_receipt",
    }:
        raise EnronSplitError("Development artifact inventory is invalid.")
    role_records: dict[str, int] = {}
    for role in ("train", "validation"):
        role_value = manifest["development_roles"].get(role)
        if not isinstance(role_value, Mapping) or set(role_value) != {"records", "groups", "artifact"}:
            raise EnronSplitError("Development role descriptor is invalid.")
        if role_value["artifact"] != artifacts[role]:
            raise EnronSplitError("Development role artifact binding is invalid.")
        if not isinstance(artifacts[role], Mapping) or artifacts[role].get("id") != role:
            raise EnronSplitError("Development role artifact identity is invalid.")
        records = role_value.get("records")
        if type(records) is not int or records < 0:
            raise EnronSplitError("Development role record count is invalid.")
        role_records[role] = records
    expected_artifact_ids = {
        "memberships": "development_memberships",
        "samples": "development_samples",
        "freeze_receipt": "freeze_receipt",
    }
    if any(
        not isinstance(artifacts.get(key), Mapping) or artifacts[key].get("id") != value
        for key, value in expected_artifact_ids.items()
    ):
        raise EnronSplitError("Development supporting artifact identity is invalid.")
    artifact_names = {
        "train": "train.jsonl",
        "validation": "validation.jsonl",
        "memberships": "memberships.jsonl",
        "samples": "samples.jsonl",
        "freeze_receipt": "split-freeze-receipt.json",
    }
    contracts = {key: _frozen_artifact_contract(root / name, artifacts[key]) for key, name in artifact_names.items()}
    if any(contracts[role][2] != role_records[role] for role in ("train", "validation")):
        raise EnronSplitError("Development role artifact record count is invalid.")
    if contracts["memberships"][2] != role_records["train"] + role_records["validation"]:
        raise EnronSplitError("Development membership artifact record count is invalid.")
    _validate_development_admission_limits(contracts, admission_limits)

    for role in ("train", "validation"):
        artifact_snapshots[role] = _verify_descriptor(
            root,
            artifacts[role],
            artifact_names[role],
            role_records[role],
            activity_reporter=activity,
        )
    artifact_snapshots["memberships"] = _verify_descriptor(
        root,
        artifacts["memberships"],
        "memberships.jsonl",
        activity_reporter=activity,
    )
    artifact_snapshots["samples"] = _verify_descriptor(
        root,
        artifacts["samples"],
        "samples.jsonl",
        activity_reporter=activity,
    )
    artifact_snapshots["freeze_receipt"] = _verify_descriptor(
        root,
        artifacts["freeze_receipt"],
        "split-freeze-receipt.json",
        1,
        observed=freeze_receipt_snapshot.file,
        activity_reporter=activity,
    )
    if (
        set(receipt)
        != {
            "schema_version",
            "benchmark_version",
            "fixture_mode",
            "promotable",
            "preparation_manifest_sha256",
            "split_policy_sha256",
            "full_split_manifest_sha256",
            "roles",
            "leakage_groups_crossing",
            "test_sealed",
        }
        or receipt.get("schema_version") != SPLIT_FREEZE_RECEIPT_SCHEMA_VERSION
        or receipt.get("full_split_manifest_sha256") != manifest.get("full_split_manifest_sha256")
        or receipt.get("benchmark_version") != manifest.get("benchmark_version")
        or receipt.get("split_policy_sha256") != manifest.get("policy", {}).get("sha256")
    ):
        raise EnronSplitError("Development freeze receipt binding is invalid.")
    _assert_private_snapshot_current(root / "manifest.json", manifest_snapshot.file)
    _assert_private_snapshot_current(root / "split-freeze-receipt.json", freeze_receipt_snapshot.file)
    activity.boundary()
    return EnronDevelopmentSplit(
        root,
        manifest,
        receipt,
        artifact_snapshots=artifact_snapshots,
        manifest_snapshot=manifest_snapshot.file,
        freeze_receipt_snapshot=freeze_receipt_snapshot.file,
    )


def _iter_canonical_objects(
    path: Path,
    expected_records: int,
    schema_version: str,
    *,
    expected_snapshot: _PrivateFileSnapshot | None = None,
    activity_reporter: _ActivityReporter | None = None,
) -> Iterator[dict[str, Any]]:
    count = 0
    previous_document_id: str | None = None
    source = (
        _iter_snapshot_jsonl(path, expected_snapshot)
        if expected_snapshot is not None
        else _iter_strict_jsonl(path, DEFAULT_MAX_PREPARED_LINE_BYTES)
    )
    for _, raw, row in source:
        if activity_reporter is not None:
            activity_reporter.worked()
        if raw != _canonical_line(row) or row.get("schema_version") != schema_version:
            raise EnronSplitError(f"{path.name} is not canonical {schema_version} JSONL.")
        document_id = row.get("document_id")
        if isinstance(document_id, str):
            if previous_document_id is not None and document_id <= previous_document_id:
                raise EnronSplitError(f"{path.name} is not ordered by document_id.")
            previous_document_id = document_id
        count += 1
        yield dict(row)
    if count != expected_records:
        raise EnronSplitError(f"{path.name} record count is invalid.")


def _iter_development_memberships(
    path: Path,
    *,
    descriptor: Mapping[str, Any],
    expected_by_role: Mapping[str, int],
    expected_snapshot: _PrivateFileSnapshot,
) -> Iterator[dict[str, Any]]:
    _expected_sha256, _expected_bytes, expected_records = _frozen_artifact_contract(path, descriptor)
    if set(expected_by_role) != {"train", "validation"} or expected_records != sum(expected_by_role.values()):
        raise EnronSplitError("Development membership descriptor count is invalid.")

    observed_by_role = {"train": 0, "validation": 0}
    count = 0
    previous_document_id: str | None = None
    for _, raw, row in _iter_frozen_development_jsonl(path, descriptor, expected_snapshot):
        if raw != _canonical_line(row) or row.get("schema_version") != SPLIT_MEMBERSHIP_SCHEMA_VERSION:
            raise EnronSplitError(f"{path.name} is not canonical {SPLIT_MEMBERSHIP_SCHEMA_VERSION} JSONL.")
        document_id = row.get("document_id")
        role = row.get("role")
        if (
            not isinstance(document_id, str)
            or not _DOCUMENT_ID_RE.fullmatch(document_id)
            or (previous_document_id is not None and document_id <= previous_document_id)
            or role not in observed_by_role
        ):
            raise EnronSplitError("Development membership schema or role is invalid.")
        previous_document_id = document_id
        count += 1
        observed_by_role[role] += 1
        yield dict(row)

    if count != expected_records or observed_by_role != expected_by_role:
        raise EnronSplitError("Development membership role counts are invalid.")


def _verify_private_membership_artifacts(
    development_root: Path,
    sealed_root: Path,
    full_manifest: Mapping[str, Any],
    state: _BuildState,
    artifact_snapshots: Mapping[Path, _PrivateFileSnapshot],
    *,
    activity_reporter: _ActivityReporter | None = None,
) -> None:
    expected = {row.document_id: row for row in state.memberships}
    observed: set[str] = set()
    paths = (
        (
            development_root / "memberships.jsonl",
            int(full_manifest["roles"]["train"]["records"]) + int(full_manifest["roles"]["validation"]["records"]),
            {"train", "validation"},
        ),
        (sealed_root / "memberships.jsonl", int(full_manifest["roles"]["test"]["records"]), {"test"}),
    )
    for path, count, allowed_roles in paths:
        for row in _iter_canonical_objects(
            path,
            count,
            SPLIT_MEMBERSHIP_SCHEMA_VERSION,
            expected_snapshot=artifact_snapshots[path],
            activity_reporter=activity_reporter,
        ):
            document_id = row.get("document_id")
            if (
                not isinstance(document_id, str)
                or row.get("role") not in allowed_roles
                or document_id in observed
                or expected.get(document_id) is None
                or expected[document_id].payload() != row
            ):
                raise EnronSplitError("Split membership artifact does not match reconstructed membership.")
            observed.add(document_id)
    if observed != set(expected):
        raise EnronSplitError("Split membership coverage is incomplete.")

    expected_samples = {
        state.memberships[node].document_id: {
            "schema_version": SPLIT_SAMPLE_SCHEMA_VERSION,
            "document_id": state.memberships[node].document_id,
            "role": state.memberships[node].role,
            "stratum_sha256": _hash_value(
                "nerb/enron/split-sample-stratum/v2", _sample_stratum(state.memberships[node])
            ),
            "membership": state.memberships[node].payload(),
        }
        for node in state.selected_nodes
    }
    observed_samples: set[str] = set()
    for path, roles in (
        (development_root / "samples.jsonl", {"train", "validation"}),
        (sealed_root / "samples.jsonl", {"test"}),
    ):
        expected_count = sum(state.sample_counts[role] for role in roles)
        for row in _iter_canonical_objects(
            path,
            expected_count,
            SPLIT_SAMPLE_SCHEMA_VERSION,
            expected_snapshot=artifact_snapshots[path],
            activity_reporter=activity_reporter,
        ):
            document_id = row.get("document_id")
            if (
                not isinstance(document_id, str)
                or row.get("role") not in roles
                or document_id in observed_samples
                or expected_samples.get(document_id) != row
            ):
                raise EnronSplitError("Representative sample is not the frozen Hamilton/min-hash sample.")
            observed_samples.add(document_id)
    if observed_samples != set(expected_samples):
        raise EnronSplitError("Representative sample coverage is incomplete.")


def _verify_group_artifact(
    sealed_root: Path,
    state: _BuildState,
    expected_snapshot: _PrivateFileSnapshot,
    *,
    activity_reporter: _ActivityReporter | None = None,
) -> None:
    expected: list[dict[str, Any]] = []
    for component in state.components:
        if activity_reporter is not None:
            activity_reporter.worked()
        challenges = {challenge for node in component.nodes for challenge in state.memberships[node].challenges}
        expected.append(
            {
                "schema_version": SPLIT_GROUP_SCHEMA_VERSION,
                "group_id": component.group_id,
                "role": state.node_roles[component.nodes[0]],
                "records": component.records,
                "occurrences": component.occurrences,
                "temporal": component.temporal,
                "anchor_utc": component.anchor_utc,
                "edge_families": sorted(
                    challenge
                    for challenge in challenges
                    if challenge in {"exact_duplicate_group", "thread_or_reply_group", "near_duplicate_group"}
                ),
                "member_document_ids": [state.memberships[node].document_id for node in component.nodes],
            }
        )
    observed = list(
        _iter_canonical_objects(
            sealed_root / "group-assignments.jsonl",
            len(expected),
            SPLIT_GROUP_SCHEMA_VERSION,
            expected_snapshot=expected_snapshot,
            activity_reporter=activity_reporter,
        )
    )
    if observed != expected:
        raise EnronSplitError("Sealed group assignment artifact does not match reconstructed leakage groups.")


def _verify_prepared_conservation(
    development_root: Path,
    sealed_root: Path,
    expected_sha256: str,
    expected_records: int,
    role_snapshots: Mapping[str, _PrivateFileSnapshot],
    *,
    activity_reporter: _ActivityReporter | None = None,
) -> None:
    streams: list[Iterator[tuple[int, bytes, Mapping[str, Any]]]] = []
    for role in _ROLE_NAMES:
        root = sealed_root if role == "test" else development_root
        streams.append(iter(_iter_snapshot_jsonl(root / f"{role}.jsonl", role_snapshots[role])))
    heap: list[tuple[str, int, bytes, Mapping[str, Any]]] = []
    for index, stream in enumerate(streams):
        try:
            _, raw, row = next(stream)
        except StopIteration:
            continue
        document_id = row.get("document_id")
        if not isinstance(document_id, str):
            raise EnronSplitError("Split role contains an invalid document identity.")
        heapq.heappush(heap, (document_id, index, raw, row))
    digest = hashlib.sha256()
    records = 0
    previous: str | None = None
    while heap:
        if activity_reporter is not None:
            activity_reporter.worked()
        document_id, index, raw, _ = heapq.heappop(heap)
        if previous is not None and document_id <= previous:
            raise EnronSplitError("Split roles duplicate or reorder a prepared document.")
        previous = document_id
        digest.update(raw)
        records += 1
        try:
            _, next_raw, next_row = next(streams[index])
        except StopIteration:
            continue
        next_document_id = next_row.get("document_id")
        if not isinstance(next_document_id, str):
            raise EnronSplitError("Split role contains an invalid document identity.")
        heapq.heappush(heap, (next_document_id, index, next_raw, next_row))
    if records != expected_records or "sha256:" + digest.hexdigest() != expected_sha256:
        raise EnronSplitError("Split roles do not exactly conserve the frozen prepared artifact.")


def _verify_preseal_receipt(
    sealed_root: Path,
    *,
    manifest: Mapping[str, Any],
    manifest_sha256: str,
    development: EnronDevelopmentSplit,
) -> _PrivateJSONObjectSnapshot:
    snapshot = _read_json_object_snapshot(sealed_root / "PRESEAL_VERIFIED.json")
    receipt = snapshot.value
    expected_keys = {
        "schema_version",
        "benchmark_version",
        "fixture_mode",
        "full_split_manifest_sha256",
        "development_manifest_sha256",
        "freeze_receipt_sha256",
        "preparation_manifest_sha256",
        "prepared_artifact_sha256",
        "prepared_records",
        "split_policy_sha256",
        "artifact_commitments_sha256",
        "roles",
        "leakage_groups_crossing",
        "test_content_verified_before_seal",
        "implementation_sha256",
        "receipt_sha256",
    }
    if set(receipt) != expected_keys or receipt.get("schema_version") != SPLIT_PRESEAL_VERIFICATION_SCHEMA_VERSION:
        raise EnronSplitError("Pre-seal verification receipt schema is invalid.")
    receipt_core = {key: receipt[key] for key in receipt if key != "receipt_sha256"}
    if receipt.get("receipt_sha256") != _hash_bytes(_canonical_json(receipt_core).encode("utf-8")):
        raise EnronSplitError("Pre-seal verification receipt hash is invalid.")
    roles = _require_split_mapping(manifest.get("roles"), "Pre-seal manifest role inventory is invalid.")
    development_artifacts = _require_split_mapping(
        development.manifest.get("artifacts"),
        "Development artifact inventory is invalid for pre-seal verification.",
    )
    sealed_artifacts = _require_split_mapping(
        manifest.get("artifacts"),
        "Sealed artifact inventory is invalid for pre-seal verification.",
    )
    role_values = {
        role: _require_split_mapping(roles.get(role), "Pre-seal manifest role descriptor is invalid.")
        for role in _ROLE_NAMES
    }
    artifact_commitments = {
        "roles": {
            role: dict(
                _require_split_mapping(
                    role_values[role].get("artifact"),
                    "Pre-seal role artifact descriptor is invalid.",
                )
            )
            for role in _ROLE_NAMES
        },
        "development": {
            name: dict(_require_split_mapping(value, "Development artifact descriptor is invalid."))
            for name, value in sorted(development_artifacts.items())
        },
        "sealed": {
            name: dict(_require_split_mapping(value, "Sealed artifact descriptor is invalid."))
            for name, value in sorted(sealed_artifacts.items())
        },
    }
    expected_roles = {
        role: {"records": role_values[role].get("records"), "groups": role_values[role].get("groups")}
        for role in _ROLE_NAMES
    }
    expected = {
        "benchmark_version": manifest["benchmark_version"],
        "fixture_mode": manifest["fixture_mode"],
        "full_split_manifest_sha256": manifest_sha256,
        "development_manifest_sha256": development._manifest_snapshot.sha256,
        "freeze_receipt_sha256": development._freeze_receipt_snapshot.sha256,
        "preparation_manifest_sha256": manifest["preparation"]["manifest_sha256"],
        "prepared_artifact_sha256": manifest["preparation"]["prepared_sha256"],
        "prepared_records": manifest["preparation"]["prepared_records"],
        "split_policy_sha256": manifest["policy"]["sha256"],
        "artifact_commitments_sha256": _hash_bytes(_canonical_json(artifact_commitments).encode("utf-8")),
        "roles": expected_roles,
        "leakage_groups_crossing": 0,
        "test_content_verified_before_seal": True,
        "implementation_sha256": _hash_file(Path(__file__)),
    }
    if any(receipt.get(field) != value for field, value in expected.items()):
        raise EnronSplitError("Pre-seal verification receipt does not bind the committed split.")
    return snapshot


def _verify_preseal_access_metadata(
    sealed_root: Path,
    *,
    manifest: Mapping[str, Any],
    manifest_sha256: str,
    directory_fd: int | None = None,
) -> _PrivateJSONObjectSnapshot:
    """Validate the self-bound pre-seal proof without reading any sealed artifact."""

    snapshot = (
        _read_json_object_snapshot_at(directory_fd, "PRESEAL_VERIFIED.json")
        if directory_fd is not None
        else _read_json_object_snapshot(sealed_root / "PRESEAL_VERIFIED.json")
    )
    receipt = snapshot.value
    preparation = _require_split_mapping(
        manifest.get("preparation"),
        "Sealed manifest preparation binding is invalid.",
    )
    policy = _require_split_mapping(manifest.get("policy"), "Sealed manifest split policy is invalid.")
    roles = _require_split_mapping(manifest.get("roles"), "Sealed manifest role inventory is invalid.")
    expected_roles: dict[str, dict[str, Any]] = {}
    for role in _ROLE_NAMES:
        role_value = _require_split_mapping(roles.get(role), "Sealed manifest role descriptor is invalid.")
        if "records" not in role_value or "groups" not in role_value:
            raise EnronSplitError("Sealed manifest role descriptor is incomplete.")
        expected_roles[role] = {"records": role_value["records"], "groups": role_value["groups"]}
    expected_keys = {
        "schema_version",
        "benchmark_version",
        "fixture_mode",
        "full_split_manifest_sha256",
        "development_manifest_sha256",
        "freeze_receipt_sha256",
        "preparation_manifest_sha256",
        "prepared_artifact_sha256",
        "prepared_records",
        "split_policy_sha256",
        "artifact_commitments_sha256",
        "roles",
        "leakage_groups_crossing",
        "test_content_verified_before_seal",
        "implementation_sha256",
        "receipt_sha256",
    }
    receipt_core = {key: receipt[key] for key in receipt if key != "receipt_sha256"}
    if (
        set(receipt) != expected_keys
        or receipt.get("schema_version") != SPLIT_PRESEAL_VERIFICATION_SCHEMA_VERSION
        or receipt.get("benchmark_version") != manifest.get("benchmark_version")
        or receipt.get("fixture_mode") != manifest.get("fixture_mode")
        or receipt.get("full_split_manifest_sha256") != manifest_sha256
        or receipt.get("preparation_manifest_sha256") != preparation.get("manifest_sha256")
        or receipt.get("prepared_artifact_sha256") != preparation.get("prepared_sha256")
        or receipt.get("prepared_records") != preparation.get("prepared_records")
        or receipt.get("split_policy_sha256") != policy.get("sha256")
        or receipt.get("roles") != expected_roles
        or receipt.get("test_content_verified_before_seal") is not True
        or receipt.get("leakage_groups_crossing") != 0
        or receipt.get("implementation_sha256") != _hash_file(Path(__file__))
        or not isinstance(receipt.get("artifact_commitments_sha256"), str)
        or not _SHA256_RE.fullmatch(str(receipt["artifact_commitments_sha256"]))
        or any(
            not isinstance(receipt.get(field), str) or not _SHA256_RE.fullmatch(str(receipt[field]))
            for field in (
                "development_manifest_sha256",
                "freeze_receipt_sha256",
                "preparation_manifest_sha256",
                "prepared_artifact_sha256",
                "split_policy_sha256",
                "implementation_sha256",
            )
        )
        or receipt.get("receipt_sha256") != _hash_bytes(_canonical_json(receipt_core).encode("utf-8"))
    ):
        raise EnronSplitError("Pre-seal verification receipt is invalid for final-test access.")
    return snapshot


def _verify_pair_receipt(
    sealed_root: Path,
    sealed_manifest_sha256: str,
    benchmark_version: str,
    *,
    preseal_verification_sha256: str,
    development_manifest_sha256: str | None = None,
    development_freeze_receipt_sha256: str | None = None,
    directory_fd: int | None = None,
) -> _PrivateJSONObjectSnapshot:
    snapshot = (
        _read_json_object_snapshot_at(directory_fd, "PAIR_COMMITTED.json")
        if directory_fd is not None
        else _read_json_object_snapshot(sealed_root / "PAIR_COMMITTED.json")
    )
    receipt = snapshot.value
    if (
        set(receipt)
        != {
            "schema_version",
            "benchmark_version",
            "sealed_manifest_sha256",
            "development_manifest_sha256",
            "freeze_receipt_sha256",
            "preseal_verification_sha256",
        }
        or receipt.get("schema_version") != SPLIT_PAIR_RECEIPT_SCHEMA_VERSION
    ):
        raise EnronSplitError("Split pair receipt schema is invalid.")
    if (
        receipt.get("benchmark_version") != benchmark_version
        or receipt.get("sealed_manifest_sha256") != sealed_manifest_sha256
        or receipt.get("preseal_verification_sha256") != preseal_verification_sha256
        or any(
            not isinstance(receipt.get(field), str) or not _SHA256_RE.fullmatch(str(receipt[field]))
            for field in (
                "sealed_manifest_sha256",
                "development_manifest_sha256",
                "freeze_receipt_sha256",
                "preseal_verification_sha256",
            )
        )
    ):
        raise EnronSplitError("Split pair receipt does not bind the sealed run.")
    if (development_manifest_sha256 is None) != (development_freeze_receipt_sha256 is None):
        raise EnronSplitError("Split pair receipt development binding is incomplete.")
    if development_manifest_sha256 is not None and (
        receipt["development_manifest_sha256"] != development_manifest_sha256
        or receipt["freeze_receipt_sha256"] != development_freeze_receipt_sha256
    ):
        raise EnronSplitError("Split pair receipt does not bind the committed development run.")
    return snapshot


def _verify_evidence_binding(
    sealed_root: Path,
    manifest: Mapping[str, Any],
    manifest_sha256: str,
    *,
    preseal_verification_sha256: str,
    directory_fd: int | None = None,
    latest_allowed: datetime | None = None,
) -> _PrivateJSONObjectSnapshot | None:
    if directory_fd is None:
        binding_exists = (sealed_root / "EVIDENCE_BOUND.json").exists()
    else:
        try:
            binding_exists = "EVIDENCE_BOUND.json" in os.listdir(directory_fd)
        except OSError:
            raise EnronSplitError("Final-test evidence binding inventory could not be read safely.") from None
    if not binding_exists:
        return None
    snapshot = (
        _read_json_object_snapshot_at(directory_fd, "EVIDENCE_BOUND.json")
        if directory_fd is not None
        else _read_json_object_snapshot(sealed_root / "EVIDENCE_BOUND.json")
    )
    binding = snapshot.value
    expected_keys = {
        "schema_version",
        "benchmark_version",
        "bound_at",
        "audit_plan_sha256",
        "frozen_target",
        "preseal_verification_sha256",
        "binding_sha256",
    }
    if (
        set(binding) != expected_keys
        or binding.get("schema_version") != FINAL_TEST_EVIDENCE_BINDING_SCHEMA_VERSION
        or binding.get("benchmark_version") != manifest.get("benchmark_version")
        or not isinstance(binding.get("audit_plan_sha256"), str)
        or not _SHA256_RE.fullmatch(str(binding["audit_plan_sha256"]))
        or binding.get("preseal_verification_sha256") != preseal_verification_sha256
    ):
        raise EnronSplitError("Final-test evidence binding schema is invalid.")
    frozen_target = binding.get("frozen_target")
    if not isinstance(frozen_target, Mapping):
        raise EnronSplitError("Final-test evidence binding target is invalid.")
    _, test_artifact = _sealed_test_role(manifest)
    normalized_target = _validate_frozen_target(
        frozen_target,
        manifest_sha256,
        str(test_artifact.get("sha256")),
    )
    if binding["audit_plan_sha256"] != normalized_target["audit_plan_sha256"]:
        raise EnronSplitError("Final-test audit-plan binding does not match its frozen target.")
    binding_core = {key: binding[key] for key in binding if key != "binding_sha256"}
    expected_binding_sha256 = _hash_bytes(_canonical_json(binding_core).encode("utf-8"))
    if binding.get("binding_sha256") != expected_binding_sha256:
        raise EnronSplitError("Final-test evidence binding hash is invalid.")
    try:
        bound_at = datetime.fromisoformat(str(binding["bound_at"]).replace("Z", "+00:00"))
        frozen_at = datetime.fromisoformat(normalized_target["frozen_at"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise EnronSplitError("Final-test evidence binding timestamp is invalid.") from exc
    if bound_at.tzinfo is None or bound_at.utcoffset() is None or bound_at < frozen_at:
        raise EnronSplitError("Final-test evidence binding predates its frozen target.")
    if bound_at > (latest_allowed or datetime.now(timezone.utc)):
        raise EnronSplitError("Final-test evidence binding is ordered after the access transition.")
    return snapshot


def _verify_access_state(
    sealed_root: Path,
    manifest: Mapping[str, Any],
    manifest_sha256: str,
    *,
    preseal_verification_sha256: str,
    directory_fd: int | None = None,
) -> dict[str, Any]:
    binding_snapshot = _verify_evidence_binding(
        sealed_root,
        manifest,
        manifest_sha256,
        preseal_verification_sha256=preseal_verification_sha256,
        directory_fd=directory_fd,
    )
    binding = None if binding_snapshot is None else binding_snapshot.value
    if directory_fd is None:
        claim_exists = (sealed_root / "ACCESS_CLAIMED.json").exists()
        outcome_exists = (sealed_root / "ACCESS_OUTCOME.json").exists()
    else:
        try:
            names = set(os.listdir(directory_fd))
        except OSError:
            raise EnronSplitError("Final-test access inventory could not be read safely.") from None
        claim_exists = "ACCESS_CLAIMED.json" in names
        outcome_exists = "ACCESS_OUTCOME.json" in names
    if outcome_exists and not claim_exists:
        raise EnronSplitError("Final-test access outcome exists without its immutable claim.")
    if claim_exists and binding is None:
        raise EnronSplitError("Final-test access claim exists without its immutable evidence binding.")
    if not claim_exists:
        return {
            "status": "sealed_unbound" if binding is None else "evidence_bound",
            "access_count": 0,
            "accessed_at": None,
            "audit_plan_sha256": None if binding is None else binding["audit_plan_sha256"],
            "audit_output_binding_sha256": None,
        }
    assert binding is not None
    claim = (
        _read_json_object_snapshot_at(directory_fd, "ACCESS_CLAIMED.json").value
        if directory_fd is not None
        else _read_json_object(sealed_root / "ACCESS_CLAIMED.json")
    )
    if (
        set(claim)
        != {
            "schema_version",
            "benchmark_version",
            "accessed_at",
            "frozen_target",
            "evidence_binding_sha256",
            "claim_sha256",
        }
        or claim.get("schema_version") != FINAL_TEST_ACCESS_SCHEMA_VERSION
    ):
        raise EnronSplitError("Final-test access claim schema is invalid.")
    if claim.get("benchmark_version") != manifest.get("benchmark_version"):
        raise EnronSplitError("Final-test access claim benchmark binding is invalid.")
    if claim.get("evidence_binding_sha256") != binding.get("binding_sha256"):
        raise EnronSplitError("Final-test access claim evidence binding is invalid.")
    frozen_target = claim.get("frozen_target")
    if not isinstance(frozen_target, Mapping):
        raise EnronSplitError("Final-test access claim target is invalid.")
    normalized_target = _validate_frozen_target(
        frozen_target,
        manifest_sha256,
        str(manifest["roles"]["test"]["artifact"]["sha256"]),
    )
    if normalized_target != binding.get("frozen_target"):
        raise EnronSplitError("Final-test access claim target differs from its evidence binding.")
    if not manifest.get("fixture_mode") and (
        "sha256:" + "0" * 64 in normalized_target.values() or normalized_target["git_commit"] == "0" * 40
    ):
        raise EnronSplitError("Production final-test target contains a placeholder commitment.")
    claim_core = {key: claim[key] for key in claim if key != "claim_sha256"}
    expected_claim_sha256 = _hash_bytes(_canonical_json(claim_core).encode("utf-8"))
    if claim.get("claim_sha256") != expected_claim_sha256:
        raise EnronSplitError("Final-test access claim hash is invalid.")
    try:
        accessed_at = datetime.fromisoformat(str(claim["accessed_at"]).replace("Z", "+00:00"))
        frozen_at = datetime.fromisoformat(normalized_target["frozen_at"].replace("Z", "+00:00"))
        bound_at = datetime.fromisoformat(str(binding["bound_at"]).replace("Z", "+00:00"))
    except ValueError as exc:
        raise EnronSplitError("Final-test access timestamp is invalid.") from exc
    if (
        accessed_at.tzinfo is None
        or accessed_at.utcoffset() is None
        or accessed_at < frozen_at
        or accessed_at < bound_at
        or accessed_at > datetime.now(timezone.utc)
    ):
        raise EnronSplitError("Final-test access timestamp is outside its valid transition order.")
    if not outcome_exists:
        return {
            "status": "claimed",
            "access_count": 1,
            "accessed_at": claim["accessed_at"],
            "audit_plan_sha256": binding["audit_plan_sha256"],
            "audit_output_binding_sha256": None,
        }
    outcome = (
        _read_json_object_snapshot_at(directory_fd, "ACCESS_OUTCOME.json").value
        if directory_fd is not None
        else _read_json_object(sealed_root / "ACCESS_OUTCOME.json")
    )
    if (
        set(outcome)
        != {
            "schema_version",
            "benchmark_version",
            "accessed_at",
            "status",
            "frozen_target_sha256",
            "evidence_binding_sha256",
            "claim_sha256",
            "audit_output_binding_sha256",
        }
        or outcome.get("schema_version") != FINAL_TEST_ACCESS_SCHEMA_VERSION
    ):
        raise EnronSplitError("Final-test access outcome schema is invalid.")
    if (
        outcome.get("benchmark_version") != claim.get("benchmark_version")
        or outcome.get("accessed_at") != claim.get("accessed_at")
        or outcome.get("evidence_binding_sha256") != binding.get("binding_sha256")
        or outcome.get("claim_sha256") != expected_claim_sha256
        or outcome.get("frozen_target_sha256") != _hash_bytes(_canonical_json(normalized_target).encode("utf-8"))
        or outcome.get("status") not in {"completed", "failed", "aborted"}
    ):
        raise EnronSplitError("Final-test access outcome does not bind its claim.")
    audit_output_binding_sha256 = outcome.get("audit_output_binding_sha256")
    if (
        outcome["status"] == "completed"
        and (not isinstance(audit_output_binding_sha256, str) or not _SHA256_RE.fullmatch(audit_output_binding_sha256))
    ) or (outcome["status"] != "completed" and audit_output_binding_sha256 is not None):
        raise EnronSplitError("Final-test access outcome has an invalid audit-output binding.")
    return {
        "status": outcome["status"],
        "access_count": 1,
        "accessed_at": claim["accessed_at"],
        "audit_plan_sha256": binding["audit_plan_sha256"],
        "audit_output_binding_sha256": audit_output_binding_sha256,
    }


def _verify_enron_splits_metadata(
    development_path: Path,
    sealed_path: Path,
    *,
    seed: str,
    activity_callback: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Verify development content and sealed receipts without opening test content."""

    if activity_callback is not None and not callable(activity_callback):
        raise EnronSplitError("Split verification activity callback must be callable when provided.")
    activity = _ActivityReporter(activity_callback)
    activity.boundary()
    development = load_enron_development_split(
        development_path,
        activity_callback=activity_callback,
    )
    activity.boundary()
    sealed_root = _assert_committed_run(sealed_path, _SEALED_FILES, allow_access_files=True)
    full_manifest_snapshot = _read_json_object_snapshot(sealed_root / "manifest.json")
    full_manifest = full_manifest_snapshot.value
    _validate_aggregate_privacy(full_manifest)
    expected_keys = {
        "schema_version",
        "benchmark_version",
        "artifact_kind",
        "fixture_mode",
        "promotable",
        "preparation",
        "policy",
        "roles",
        "aggregates",
        "allocation",
        "cohorts",
        "sampling",
        "leakage",
        "sealing",
        "artifacts",
        "privacy",
    }
    if set(full_manifest) != expected_keys or full_manifest.get("schema_version") != SPLIT_MANIFEST_SCHEMA_VERSION:
        raise EnronSplitError("Sealed split manifest schema is invalid.")
    _validate_preparation_binding(full_manifest.get("preparation"))
    sealing = _require_split_mapping(full_manifest.get("sealing"), "Sealed split sealing metadata is invalid.")
    leakage = _require_split_mapping(full_manifest.get("leakage"), "Sealed split leakage metadata is invalid.")
    roles = _require_split_mapping(full_manifest.get("roles"), "Sealed split role inventory is invalid.")
    artifacts = _require_split_mapping(full_manifest.get("artifacts"), "Sealed split artifact inventory is invalid.")
    policy = _require_split_mapping(full_manifest.get("policy"), "Sealed split policy is invalid.")
    aggregates = _require_split_mapping(full_manifest.get("aggregates"), "Sealed split aggregates are invalid.")
    manifest_sha256 = full_manifest_snapshot.file.sha256
    if manifest_sha256 != development.freeze_receipt.get("full_split_manifest_sha256"):
        raise EnronSplitError("Development receipt does not commit to the sealed split manifest.")
    preseal_snapshot = _verify_preseal_receipt(
        sealed_root,
        manifest=full_manifest,
        manifest_sha256=manifest_sha256,
        development=development,
    )
    _verify_pair_receipt(
        sealed_root,
        manifest_sha256,
        str(full_manifest.get("benchmark_version")),
        preseal_verification_sha256=preseal_snapshot.file.sha256,
        development_manifest_sha256=development._manifest_snapshot.sha256,
        development_freeze_receipt_sha256=development._freeze_receipt_snapshot.sha256,
    )
    if (
        full_manifest.get("benchmark_version") != development.manifest.get("benchmark_version")
        or full_manifest.get("preparation") != development.manifest.get("preparation")
        or full_manifest.get("policy") != development.manifest.get("policy")
        or sealing.get("test_sealed") is not True
        or leakage.get("crossing_groups") != 0
    ):
        raise EnronSplitError("Development and sealed split metadata are not consistently bound.")
    if set(roles) != set(_ROLE_NAMES) or set(artifacts) != {
        "test",
        "memberships",
        "samples",
        "group_assignments",
        "leakage_audit",
    }:
        raise EnronSplitError("Sealed role or artifact inventory is invalid.")
    for role in _ROLE_NAMES:
        role_value = roles.get(role)
        if not isinstance(role_value, Mapping) or set(role_value) != {"records", "groups", "artifact"}:
            raise EnronSplitError("Sealed role descriptor is invalid.")
        if not isinstance(role_value["artifact"], Mapping) or role_value["artifact"].get("id") != role:
            raise EnronSplitError("Sealed role artifact identity is invalid.")
        if role == "test":
            _verify_descriptor_metadata(
                sealed_root,
                role_value["artifact"],
                "test.jsonl",
                int(role_value["records"]),
            )
    for artifact_id, expected_id, filename in (
        ("memberships", "test_memberships", "memberships.jsonl"),
        ("samples", "test_samples", "samples.jsonl"),
        ("group_assignments", "group_assignments", "group-assignments.jsonl"),
        ("leakage_audit", "leakage_audit", "leakage-audit.json"),
    ):
        descriptor = artifacts.get(artifact_id)
        if not isinstance(descriptor, Mapping) or descriptor.get("id") != expected_id:
            raise EnronSplitError("Sealed supporting artifact identity is invalid.")
        _verify_descriptor_metadata(sealed_root, descriptor, filename)
    if artifacts.get("test") != roles["test"]["artifact"]:
        raise EnronSplitError("Sealed test artifact binding is invalid.")

    if policy.get("seed_sha256") != _hash_value("nerb/enron/split-seed/v2", seed):
        raise EnronSplitError("Steward split seed does not match the frozen seed commitment.")
    if full_manifest.get("benchmark_version") != _BENCHMARK_ID:
        raise EnronSplitError("Steward split benchmark identity is invalid.")
    rebuild_options = EnronSplitOptions(
        preparation_run=Path("unused-preparation"),
        development_output_dir=Path("unused-development"),
        sealed_output_dir=Path("unused-sealed"),
        scratch_dir=Path("unused-scratch"),
        seed=seed,
        train_fraction=float(policy["train_fraction"]),
        validation_fraction=float(policy["validation_fraction"]),
        near_hamming=int(policy["grouping"]["near"]["hamming_maximum"]),
        max_near_candidate_pairs=int(policy["grouping"]["near"]["raw_emission_and_unique_pair_budget"]),
        sample_per_role=int(policy["sampling"]["per_role"]),
        fixture_mode=bool(full_manifest["fixture_mode"]),
        allow_unignored_output=True,
    )
    _validate_options(rebuild_options)
    if _canonical_json(policy) != _canonical_json(_split_policy(rebuild_options)):
        raise EnronSplitError("Frozen split policy does not match its canonical implementation and hash.")

    access_state = _verify_access_state(
        sealed_root,
        full_manifest,
        manifest_sha256,
        preseal_verification_sha256=preseal_snapshot.file.sha256,
    )
    development._assert_metadata_current()
    _assert_private_snapshot_current(sealed_root / "manifest.json", full_manifest_snapshot.file)
    _assert_private_snapshot_current(sealed_root / "PRESEAL_VERIFIED.json", preseal_snapshot.file)
    contract_splits = _contract_split_projection(full_manifest, manifest_sha256)
    activity.boundary()
    return {
        "valid": True,
        "schema_version": SPLIT_MANIFEST_SCHEMA_VERSION,
        "benchmark_version": full_manifest["benchmark_version"],
        "fixture_mode": full_manifest["fixture_mode"],
        "promotable": full_manifest["promotable"],
        "preparation": dict(full_manifest["preparation"]),
        "records": sum(int(roles[role]["records"]) for role in _ROLE_NAMES),
        "groups": int(aggregates["groups"]),
        "roles": {
            role: {"records": int(roles[role]["records"]), "groups": int(roles[role]["groups"])} for role in _ROLE_NAMES
        },
        "manifest_sha256": manifest_sha256,
        "development_manifest_sha256": development.manifest_sha256,
        "preseal_verification_sha256": preseal_snapshot.file.sha256,
        "leakage_groups_crossing": 0,
        "test_sealed": True,
        "contract_splits": contract_splits,
        "access": access_state,
    }


def _verify_enron_splits(
    development_path: Path,
    sealed_path: Path,
    *,
    seed: str = DEFAULT_SPLIT_SEED,
    activity_callback: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Verify development content and sealed metadata with a stable boundary."""

    return _verify_enron_splits_metadata(
        development_path,
        sealed_path,
        seed=seed,
        activity_callback=activity_callback,
    )


def verify_enron_splits(
    development_path: Path,
    sealed_path: Path,
    *,
    seed: str = DEFAULT_SPLIT_SEED,
    activity_callback: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Deep steward verification with a stable, privacy-safe error boundary."""

    try:
        return _verify_enron_splits(
            development_path,
            sealed_path,
            seed=seed,
            activity_callback=activity_callback,
        )
    except EnronSplitError:
        raise
    except Exception:
        raise EnronSplitError("Enron split verification failed safely.") from None


def _contract_split_projection(manifest: Mapping[str, Any], manifest_sha256: str) -> dict[str, Any]:
    roles = manifest["roles"]
    projected_roles: dict[str, Any] = {}
    for role in _ROLE_NAMES:
        artifact = roles[role]["artifact"]
        projected_roles[role] = {
            "records": roles[role]["records"],
            "groups": roles[role]["groups"],
            "artifact": {
                "id": artifact["id"],
                "sha256": artifact["sha256"],
                "bytes": artifact["bytes"],
            },
        }
    return {
        "manifest_sha256": manifest_sha256,
        "policy_sha256": manifest["policy"]["sha256"],
        "leakage_audit_sha256": manifest["artifacts"]["leakage_audit"]["sha256"],
        "leakage_groups_crossing": 0,
        "test_sealed": True,
        "seed": manifest["policy"]["seed_sha256"],
        "roles": projected_roles,
    }


def project_enron_contract_splits(
    development_path: Path,
    sealed_path: Path,
    *,
    seed: str = DEFAULT_SPLIT_SEED,
) -> dict[str, Any]:
    """Verify split roots and project the exact closed ``enron_contract._SPLITS`` shape."""

    verification = verify_enron_splits(development_path, sealed_path, seed=seed)
    return dict(verification["contract_splits"])


def _validate_frozen_target(
    target: Mapping[str, str],
    sealed_manifest_sha256: str,
    test_artifact_sha256: str,
) -> dict[str, str]:
    if set(target) != _FROZEN_TARGET_KEYS or any(not isinstance(value, str) for value in target.values()):
        raise EnronSplitError("Final-test frozen target must use the exact closed target schema.")
    if target.get("split_manifest_sha256") != sealed_manifest_sha256:
        raise EnronSplitError("Final-test target does not bind the exact sealed split manifest.")
    if target.get("test_artifact_sha256") != test_artifact_sha256:
        raise EnronSplitError("Final-test target does not bind the exact sealed test artifact.")
    for name in _FROZEN_TARGET_KEYS - {"frozen_at", "git_commit"}:
        if not _SHA256_RE.fullmatch(target[name]):
            raise EnronSplitError("Final-test frozen target hashes are invalid.")
    if not re.fullmatch(r"[0-9a-f]{40}", target["git_commit"]):
        raise EnronSplitError("Final-test frozen target Git commit is invalid.")
    try:
        frozen_at = datetime.fromisoformat(target["frozen_at"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise EnronSplitError("Final-test frozen timestamp is invalid.") from exc
    if frozen_at.tzinfo is None or frozen_at.utcoffset() is None:
        raise EnronSplitError("Final-test frozen timestamp must be timezone-aware.")
    if frozen_at > datetime.now(timezone.utc):
        raise EnronSplitError("Final-test frozen timestamp cannot be in the future.")
    return {name: target[name] for name in sorted(target)}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _transition_timestamp(
    value: str,
    *,
    description: str,
    earliest: datetime | None = None,
    latest: datetime | None = None,
) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError):
        raise EnronSplitError(f"{description} timestamp is invalid.") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise EnronSplitError(f"{description} timestamp must be timezone-aware.")
    normalized = parsed.astimezone(timezone.utc)
    if earliest is not None and normalized < earliest.astimezone(timezone.utc):
        raise EnronSplitError(f"{description} timestamp violates the frozen transition order.")
    if latest is not None and normalized > latest.astimezone(timezone.utc):
        raise EnronSplitError(f"{description} timestamp is later than the current UTC wall clock.")
    return normalized


def _open_pinned_private_root(root: Path) -> int:
    if root.parent == root or not root.name:
        raise EnronSplitError("Private receipt root is invalid.")
    try:
        return open_private_directory_input(root)
    except EnronPrivateIOError:
        raise EnronSplitError("Private receipt root could not be pinned safely.") from None


def _open_locked_transition_root(root: Path) -> tuple[Path, int]:
    """Pin and exclusively lock the sealed transition capability."""

    import fcntl

    try:
        normalized = root.expanduser().absolute()
    except (OSError, RuntimeError, ValueError):
        raise EnronSplitError("Final-test transition root is invalid.") from None
    directory_fd = _open_pinned_private_root(normalized)
    try:
        try:
            fcntl.flock(directory_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise EnronSplitError("A final-test transition owner is still active.") from None
        except OSError:
            raise EnronSplitError("The final-test transition capability could not be locked safely.") from None
        _assert_committed_run_at(directory_fd, _SEALED_FILES, allow_access_files=True)
        return normalized, directory_fd
    except BaseException:
        try:
            os.close(directory_fd)
        except OSError:
            pass
        raise


def _write_exclusive_private_json_at(
    directory_fd: int,
    name: str,
    value: Mapping[str, Any],
) -> None:
    import fcntl

    if name not in _RECEIPT_NAMES:
        raise EnronSplitError("Private receipt name is invalid.")
    payload = _canonical_line(value)
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    temporary_name: str | None = None
    file_fd: int | None = None
    staged_identity: tuple[int, int] | None = None
    published = False
    try:
        for _ in range(128):
            candidate = f".{name}.stage-{secrets.token_hex(12)}"
            try:
                file_fd = os.open(candidate, flags, 0o600, dir_fd=directory_fd)
            except FileExistsError:
                continue
            temporary_name = candidate
            break
        if file_fd is None or temporary_name is None:
            raise EnronSplitError("A unique private receipt staging file could not be created.")
        os.fchmod(file_fd, 0o600)
        staged_identity = _receipt_file_identity(os.fstat(file_fd))
        fcntl.flock(file_fd, fcntl.LOCK_EX)
        offset = 0
        while offset < len(payload):
            written = os.write(file_fd, payload[offset:])
            if written <= 0:
                raise OSError("Private receipt write made no progress.")
            offset += written
        os.fsync(file_fd)
        _require_pinned_receipt_file_at(directory_fd, temporary_name, file_fd, staged_identity)
        _rename_noreplace_at(directory_fd, temporary_name, directory_fd, name)
        published = True
        try:
            _require_pinned_receipt_file_at(directory_fd, name, file_fd, staged_identity)
        except EnronSplitError:
            _restore_mismatched_receipt_publication_at(directory_fd, name, temporary_name)
            published = False
            raise
        os.fsync(directory_fd)
        try:
            _require_pinned_receipt_file_at(directory_fd, name, file_fd, staged_identity)
        except EnronSplitError:
            _restore_mismatched_receipt_publication_at(directory_fd, name, temporary_name)
            published = False
            raise
    except FileExistsError:
        raise EnronSplitError("Final-test access has already been claimed; retries are forbidden.") from None
    except EnronPrivateIOError as exc:
        raise EnronSplitError("Private receipt could not be published safely.") from exc
    except OSError as exc:
        raise EnronSplitError("Private receipt could not be published atomically.") from exc
    finally:
        if file_fd is not None and temporary_name is not None and staged_identity is not None and not published:
            try:
                _wipe_and_quarantine_receipt_file_at(
                    directory_fd,
                    temporary_name,
                    file_fd,
                    staged_identity,
                )
            except EnronSplitError:
                pass
        if file_fd is not None:
            os.close(file_fd)


def _receipt_file_identity(info: os.stat_result) -> tuple[int, int]:
    return int(info.st_dev), int(info.st_ino)


def _require_pinned_receipt_file_at(
    directory_fd: int,
    name: str,
    descriptor: int,
    expected_identity: tuple[int, int],
) -> None:
    try:
        opened = os.fstat(descriptor)
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError:
        raise EnronSplitError("Private receipt staging identity changed.") from None
    if (
        not stat.S_ISREG(opened.st_mode)
        or stat.S_ISLNK(current.st_mode)
        or opened.st_uid != os.geteuid()
        or current.st_uid != os.geteuid()
        or opened.st_nlink != 1
        or current.st_nlink != 1
        or stat.S_IMODE(opened.st_mode) != 0o600
        or stat.S_IMODE(current.st_mode) != 0o600
        or _receipt_file_identity(opened) != expected_identity
        or _receipt_file_identity(current) != expected_identity
    ):
        raise EnronSplitError("Private receipt staging identity changed.")


def _wipe_and_quarantine_receipt_file_at(
    directory_fd: int,
    name: str,
    descriptor: int,
    expected_identity: tuple[int, int],
) -> str:
    """Wipe one pinned receipt inode and retain its authenticated empty shell."""

    try:
        parent = os.fstat(directory_fd)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.geteuid()
            or stat.S_IMODE(parent.st_mode) != 0o700
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or _receipt_file_identity(opened) != expected_identity
        ):
            raise OSError
        os.fchmod(descriptor, 0o600)
        os.ftruncate(descriptor, 0)
        os.fsync(descriptor)
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(current.st_mode)
            or stat.S_ISLNK(current.st_mode)
            or current.st_uid != os.geteuid()
            or current.st_nlink != 1
            or stat.S_IMODE(current.st_mode) != 0o600
            or _receipt_file_identity(current) != expected_identity
        ):
            raise OSError
        tombstone_name: str | None = None
        for _ in range(128):
            candidate = f".nerb-cleanup-{secrets.token_hex(24)}"
            try:
                _rename_noreplace_at(directory_fd, name, directory_fd, candidate)
            except FileExistsError:
                continue
            tombstone_name = candidate
            break
        if tombstone_name is None:
            raise OSError
        tombstone = os.stat(tombstone_name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(tombstone.st_mode)
            or stat.S_ISLNK(tombstone.st_mode)
            or tombstone.st_uid != os.geteuid()
            or tombstone.st_nlink != 1
            or stat.S_IMODE(tombstone.st_mode) != 0o600
            or tombstone.st_size != 0
            or _receipt_file_identity(tombstone) != expected_identity
        ):
            _restore_mismatched_receipt_quarantine_at(
                directory_fd,
                tombstone_name,
                name,
                _receipt_file_identity(tombstone),
            )
            raise OSError
        os.fsync(directory_fd)
        return tombstone_name
    except (EnronPrivateIOError, OSError, ValueError):
        raise EnronSplitError("Private receipt staging file could not be wiped safely.") from None


def _restore_mismatched_receipt_quarantine_at(
    directory_fd: int,
    quarantine_name: str,
    original_name: str,
    observed_identity: tuple[int, int],
) -> None:
    """Restore a raced receipt substitute without overwriting either entry."""

    try:
        _rename_noreplace_at(directory_fd, quarantine_name, directory_fd, original_name)
        restored = os.stat(original_name, dir_fd=directory_fd, follow_symlinks=False)
        if _receipt_file_identity(restored) != observed_identity:
            raise OSError
        os.fsync(directory_fd)
    except (EnronPrivateIOError, OSError, ValueError):
        # A concurrent entry at the original name and the mismatched quarantine
        # are both retained when an atomic no-replace rollback cannot succeed.
        raise EnronSplitError("Raced private receipt substitute could not be restored safely.") from None


def _restore_mismatched_receipt_publication_at(
    directory_fd: int,
    published_name: str,
    staging_name: str,
) -> None:
    """Move a raced receipt back to its absent staging name without overwriting."""

    try:
        published = os.stat(published_name, dir_fd=directory_fd, follow_symlinks=False)
        observed_identity = _receipt_file_identity(published)
        _rename_noreplace_at(directory_fd, published_name, directory_fd, staging_name)
        restored = os.stat(staging_name, dir_fd=directory_fd, follow_symlinks=False)
        if _receipt_file_identity(restored) != observed_identity:
            raise OSError
        os.fsync(directory_fd)
    except (EnronPrivateIOError, OSError, ValueError):
        raise EnronSplitError("Raced private receipt publication could not be restored safely.") from None


def _cleanup_stale_receipt_stages_at(directory_fd: int) -> None:
    import fcntl

    recovered = False
    names = os.listdir(directory_fd)
    for name in names:
        if not _RECEIPT_STAGE_RE.fullmatch(name):
            continue
        stage_fd: int | None = None
        try:
            before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.geteuid()
                or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o600
            ):
                raise EnronSplitError("Stale private receipt staging entry is unsafe.")
            if time.time_ns() - before.st_mtime_ns < 5_000_000_000:
                raise EnronSplitError("Private receipt publication is still in progress; retry shortly.")
            stage_fd = os.open(
                name,
                os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_fd,
            )
            after = os.fstat(stage_fd)
            if (
                not stat.S_ISREG(after.st_mode)
                or after.st_nlink != 1
                or after.st_uid != os.geteuid()
                or stat.S_IMODE(after.st_mode) != 0o600
                or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            ):
                raise EnronSplitError("Stale private receipt staging file is unsafe.")
            try:
                fcntl.flock(stage_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise EnronSplitError("Private receipt publication is still in progress; retry shortly.") from exc
            _wipe_and_quarantine_receipt_file_at(
                directory_fd,
                name,
                stage_fd,
                _receipt_file_identity(after),
            )
            recovered = True
        except FileNotFoundError:
            continue
        except EnronSplitError:
            raise
        except OSError as exc:
            raise EnronSplitError("Stale private receipt staging entry could not be inspected safely.") from exc
        finally:
            if stage_fd is not None:
                os.close(stage_fd)
    if recovered:
        os.fsync(directory_fd)


def _cleanup_stale_receipt_stages(root: Path) -> None:
    directory_fd = _open_pinned_private_root(root)
    try:
        _cleanup_stale_receipt_stages_at(directory_fd)
    finally:
        os.close(directory_fd)


def _write_exclusive_private_json(root: Path, name: str, value: Mapping[str, Any]) -> None:
    normalized = root.expanduser().absolute()
    directory_fd = _open_pinned_private_root(normalized)
    try:
        _write_exclusive_private_json_at(directory_fd, name, value)
    finally:
        os.close(directory_fd)


def _validate_final_test_membership(row: Mapping[str, Any]) -> str:
    expected_keys = {
        "schema_version",
        "document_id",
        "group_id",
        "role",
        "occurrence_count",
        "temporal",
        "mailbox",
        "mailbox_recurrence",
        "size",
        "group_size",
        "identities",
        "views",
        "challenges",
    }
    temporal = row.get("temporal")
    identities = row.get("identities")
    views = row.get("views")
    document_id = row.get("document_id")
    group_id = row.get("group_id")
    occurrence_count = row.get("occurrence_count")
    challenges = row.get("challenges")
    if (
        set(row) != expected_keys
        or row.get("schema_version") != SPLIT_MEMBERSHIP_SCHEMA_VERSION
        or not isinstance(document_id, str)
        or not _DOCUMENT_ID_RE.fullmatch(document_id)
        or not isinstance(group_id, str)
        or not _SHA256_RE.fullmatch(group_id)
        or row.get("role") != "test"
        or type(occurrence_count) is not int
        or occurrence_count <= 0
        or not isinstance(temporal, Mapping)
        or set(temporal) != {"eligible", "status", "anchor_utc"}
        or type(temporal.get("eligible")) is not bool
        or not isinstance(temporal.get("status"), str)
        or not temporal["status"]
        or (temporal.get("anchor_utc") is not None and not isinstance(temporal.get("anchor_utc"), str))
        or any(
            not isinstance(row.get(field), str) or not row[field]
            for field in ("mailbox", "mailbox_recurrence", "size", "group_size")
        )
        or not isinstance(identities, Mapping)
        or set(identities) != {"recurrence", "count", "contains_frequency"}
        or not isinstance(identities.get("recurrence"), str)
        or not identities["recurrence"]
        or type(identities.get("count")) is not int
        or identities["count"] < 0
        or not isinstance(identities.get("contains_frequency"), list)
        or any(not isinstance(value, str) or not value for value in identities["contains_frequency"])
        or identities["contains_frequency"] != sorted(set(identities["contains_frequency"]))
        or not isinstance(views, Mapping)
        or set(views) != {"natural", "structured"}
        or any(type(views.get(field)) is not bool for field in ("natural", "structured"))
        or not isinstance(challenges, list)
        or any(not isinstance(value, str) or not value for value in challenges)
        or challenges != sorted(set(challenges))
    ):
        raise EnronSplitError("Sealed test membership schema or role is invalid.")
    return document_id


class EnronFinalTestAccess(AbstractContextManager["EnronFinalTestAccess"]):
    """One-shot, preverified final-test descriptor owned by a release steward."""

    __slots__ = (
        "_root",
        "_target",
        "_handle",
        "_membership_handle",
        "_membership_descriptor",
        "_expected_records",
        "_expected_sha256",
        "_expected_bytes",
        "_expected_membership_records",
        "_expected_membership_sha256",
        "_expected_membership_bytes",
        "_opened_identity",
        "_opened_membership_identity",
        "_benchmark_version",
        "_accessed_at",
        "_evidence_binding_sha256",
        "_audit_output_binding_sha256",
        "_claim_sha256",
        "_claim_published",
        "_directory_fd",
        "_entered",
        "_iterated",
        "_exhausted",
        "_stream_failed",
    )

    def __init__(self, root: Path, target: Mapping[str, str]) -> None:
        self._root = root
        self._target = dict(target)
        self._handle: BinaryIO | None = None
        self._membership_handle: BinaryIO | None = None
        self._membership_descriptor: Any = None
        self._expected_records = 0
        self._expected_sha256 = ""
        self._expected_bytes = 0
        self._expected_membership_records = 0
        self._expected_membership_sha256 = ""
        self._expected_membership_bytes = 0
        self._opened_identity: tuple[int, int, int, int, int, int, int] | None = None
        self._opened_membership_identity: tuple[int, int, int, int, int, int, int] | None = None
        self._benchmark_version = ""
        self._accessed_at = ""
        self._evidence_binding_sha256 = ""
        self._audit_output_binding_sha256: str | None = None
        self._claim_sha256 = ""
        self._claim_published = False
        self._directory_fd: int | None = None
        self._entered = False
        self._iterated = False
        self._exhausted = False
        self._stream_failed = False

    def bind_audit_plan(self, audit_plan_sha256: str) -> dict[str, Any]:
        """Durably bind the preregistered audit plan through a stable error boundary."""

        try:
            return self._bind_audit_plan(audit_plan_sha256)
        except EnronSplitError:
            raise
        except Exception:
            raise EnronSplitError("Final-test audit-plan binding failed safely.") from None

    def _bind_audit_plan(self, audit_plan_sha256: str) -> dict[str, Any]:
        """Durably bind the exact frozen audit plan before access."""

        if self._entered:
            raise EnronSplitError("Final-test evidence must be bound before entering the access context.")
        if not isinstance(audit_plan_sha256, str) or not _SHA256_RE.fullmatch(audit_plan_sha256):
            raise EnronSplitError("Final-test audit plan hash is invalid.")
        root, directory_fd = _open_locked_transition_root(self._root)
        try:
            try:
                names = set(os.listdir(directory_fd))
            except OSError:
                raise EnronSplitError("Final-test transition inventory could not be read safely.") from None
            if names & {"EVIDENCE_BOUND.json", "ACCESS_CLAIMED.json", "ACCESS_OUTCOME.json"}:
                raise EnronSplitError("Final-test evidence or access has already been bound; replay is forbidden.")
            manifest_snapshot = _read_json_object_snapshot_at(directory_fd, "manifest.json")
            manifest = manifest_snapshot.value
            _, artifact = _validate_sealed_access_manifest(manifest)
            target = _validate_frozen_target(
                self._target,
                manifest_snapshot.file.sha256,
                str(artifact.get("sha256")),
            )
            if audit_plan_sha256 != target["audit_plan_sha256"]:
                raise EnronSplitError("Final-test audit plan hash does not match the frozen target.")
            preseal_snapshot = _verify_preseal_access_metadata(
                root,
                manifest=manifest,
                manifest_sha256=manifest_snapshot.file.sha256,
                directory_fd=directory_fd,
            )
            pair_snapshot = _verify_pair_receipt(
                root,
                manifest_snapshot.file.sha256,
                str(manifest.get("benchmark_version")),
                preseal_verification_sha256=preseal_snapshot.file.sha256,
                development_manifest_sha256=str(preseal_snapshot.value["development_manifest_sha256"]),
                development_freeze_receipt_sha256=str(preseal_snapshot.value["freeze_receipt_sha256"]),
                directory_fd=directory_fd,
            )
            bound_at = _utc_now()
            frozen_at = _transition_timestamp(
                target["frozen_at"],
                description="Final-test frozen",
                latest=datetime.now(timezone.utc),
            )
            _transition_timestamp(
                bound_at,
                description="Final-test evidence binding",
                earliest=frozen_at,
                latest=datetime.now(timezone.utc),
            )
            binding_core = {
                "schema_version": FINAL_TEST_EVIDENCE_BINDING_SCHEMA_VERSION,
                "benchmark_version": manifest["benchmark_version"],
                "bound_at": bound_at,
                "audit_plan_sha256": audit_plan_sha256,
                "frozen_target": target,
                "preseal_verification_sha256": preseal_snapshot.file.sha256,
            }
            binding = {
                **binding_core,
                "binding_sha256": _hash_bytes(_canonical_json(binding_core).encode("utf-8")),
            }
            _assert_private_snapshot_current_at(directory_fd, "manifest.json", manifest_snapshot.file)
            _assert_private_snapshot_current_at(directory_fd, "PRESEAL_VERIFIED.json", preseal_snapshot.file)
            _assert_private_snapshot_current_at(directory_fd, "PAIR_COMMITTED.json", pair_snapshot.file)
            _write_exclusive_private_json_at(directory_fd, "EVIDENCE_BOUND.json", binding)
            self._root = root
            self._target = target
            self._evidence_binding_sha256 = str(binding["binding_sha256"])
            return {
                "status": "evidence_bound",
                "audit_plan_sha256": audit_plan_sha256,
                "binding_sha256": binding["binding_sha256"],
            }
        finally:
            os.close(directory_fd)

    def _publish_outcome(self, status: str) -> None:
        directory_fd = self._directory_fd
        if directory_fd is None or not self._claim_published:
            raise EnronSplitError("Final-test access claim is not durably published.")
        outcome = {
            "schema_version": FINAL_TEST_ACCESS_SCHEMA_VERSION,
            "benchmark_version": self._benchmark_version,
            "accessed_at": self._accessed_at,
            "status": status,
            "frozen_target_sha256": _hash_bytes(_canonical_json(self._target).encode("utf-8")),
            "evidence_binding_sha256": self._evidence_binding_sha256,
            "claim_sha256": self._claim_sha256,
            "audit_output_binding_sha256": (self._audit_output_binding_sha256 if status == "completed" else None),
        }
        _write_exclusive_private_json_at(directory_fd, "ACCESS_OUTCOME.json", outcome)

    def bind_audit_output(self, audit_output_binding_sha256: str) -> dict[str, Any]:
        """Bind the committed audit output after the complete sealed stream was consumed."""

        try:
            return self._bind_audit_output(audit_output_binding_sha256)
        except EnronSplitError:
            raise
        except Exception:
            raise EnronSplitError("Final-test audit-output binding failed safely.") from None

    def _bind_audit_output(self, audit_output_binding_sha256: str) -> dict[str, Any]:
        if (
            not self._entered
            or self._directory_fd is None
            or not self._claim_published
            or not self._exhausted
            or self._stream_failed
        ):
            raise EnronSplitError(
                "Final-test audit output can be bound only after the complete sealed stream was consumed."
            )
        if self._audit_output_binding_sha256 is not None:
            raise EnronSplitError("Final-test audit output has already been bound.")
        if not isinstance(audit_output_binding_sha256, str) or not _SHA256_RE.fullmatch(audit_output_binding_sha256):
            raise EnronSplitError("Final-test audit-output binding hash is invalid.")
        self._audit_output_binding_sha256 = audit_output_binding_sha256
        return {
            "status": "audit_output_bound",
            "audit_output_binding_sha256": audit_output_binding_sha256,
        }

    def _claim_and_open(self) -> EnronFinalTestAccess:
        root, directory_fd = _open_locked_transition_root(self._root)
        self._root = root
        self._directory_fd = directory_fd
        handle: BinaryIO | None = None
        try:
            try:
                names = set(os.listdir(directory_fd))
            except OSError:
                raise EnronSplitError("Final-test transition inventory could not be read safely.") from None
            if names & {"ACCESS_CLAIMED.json", "ACCESS_OUTCOME.json"}:
                raise EnronSplitError("Final-test access has already been claimed; retries are forbidden.")
            manifest_snapshot = _read_json_object_snapshot_at(directory_fd, "manifest.json")
            manifest = manifest_snapshot.value
            role, artifact = _validate_sealed_access_manifest(manifest)
            manifest_sha256 = manifest_snapshot.file.sha256
            preseal_snapshot = _verify_preseal_access_metadata(
                root,
                manifest=manifest,
                manifest_sha256=manifest_sha256,
                directory_fd=directory_fd,
            )
            pair_snapshot = _verify_pair_receipt(
                root,
                manifest_sha256,
                str(manifest.get("benchmark_version")),
                preseal_verification_sha256=preseal_snapshot.file.sha256,
                development_manifest_sha256=str(preseal_snapshot.value["development_manifest_sha256"]),
                development_freeze_receipt_sha256=str(preseal_snapshot.value["freeze_receipt_sha256"]),
                directory_fd=directory_fd,
            )
            target = _validate_frozen_target(
                self._target,
                manifest_sha256,
                str(artifact.get("sha256")),
            )
            if not manifest.get("fixture_mode") and (
                "sha256:" + "0" * 64 in target.values() or target["git_commit"] == "0" * 40
            ):
                raise EnronSplitError("Production final-test target contains a placeholder commitment.")
            artifacts = _require_split_mapping(
                manifest.get("artifacts"),
                "Sealed split artifact inventory is invalid for final access.",
            )
            if artifacts.get("test") != artifact:
                raise EnronSplitError("Sealed test artifact binding is invalid.")
            self._membership_descriptor = artifacts.get("memberships")
            _verify_descriptor_metadata(
                root,
                artifact,
                "test.jsonl",
                int(role["records"]),
                directory_fd=directory_fd,
            )
            self._accessed_at = _utc_now()
            accessed_at = _transition_timestamp(
                self._accessed_at,
                description="Final-test access",
                latest=datetime.now(timezone.utc),
            )
            binding_snapshot = _verify_evidence_binding(
                root,
                manifest,
                manifest_sha256,
                preseal_verification_sha256=preseal_snapshot.file.sha256,
                directory_fd=directory_fd,
                latest_allowed=accessed_at,
            )
            if binding_snapshot is None or binding_snapshot.value.get("frozen_target") != target:
                raise EnronSplitError("Final-test evidence must be durably bound before access.")
            binding = binding_snapshot.value
            self._expected_records = int(role["records"])
            self._expected_sha256 = str(artifact["sha256"])
            self._expected_bytes = int(artifact["bytes"])
            self._target = target
            self._benchmark_version = str(manifest["benchmark_version"])
            self._evidence_binding_sha256 = str(binding["binding_sha256"])
            claim_core = {
                "schema_version": FINAL_TEST_ACCESS_SCHEMA_VERSION,
                "benchmark_version": self._benchmark_version,
                "accessed_at": self._accessed_at,
                "frozen_target": target,
                "evidence_binding_sha256": self._evidence_binding_sha256,
            }
            self._claim_sha256 = _hash_bytes(_canonical_json(claim_core).encode("utf-8"))
            claim = {**claim_core, "claim_sha256": self._claim_sha256}
            _assert_private_snapshot_current_at(directory_fd, "manifest.json", manifest_snapshot.file)
            _assert_private_snapshot_current_at(directory_fd, "PRESEAL_VERIFIED.json", preseal_snapshot.file)
            _assert_private_snapshot_current_at(directory_fd, "PAIR_COMMITTED.json", pair_snapshot.file)
            _assert_private_snapshot_current_at(directory_fd, "EVIDENCE_BOUND.json", binding_snapshot.file)
            _write_exclusive_private_json_at(directory_fd, "ACCESS_CLAIMED.json", claim)
            self._claim_published = True
            handle = open_private_binary_input_at(directory_fd, "test.jsonl")
            if os.fstat(handle.fileno()).st_size != self._expected_bytes:
                raise EnronSplitError("Sealed test size changed after final access was claimed.")
            self._opened_identity = _private_regular_identity(os.fstat(handle.fileno()))
            self._handle = handle
            return self
        except BaseException:
            if handle is not None and not handle.closed:
                try:
                    handle.close()
                except OSError:
                    pass
            if self._handle is not None:
                try:
                    self._handle.close()
                except OSError:
                    pass
                self._handle = None
            if self._claim_published:
                try:
                    self._publish_outcome("failed")
                except EnronSplitError:
                    pass
            try:
                os.close(directory_fd)
            except OSError:
                pass
            self._directory_fd = None
            raise

    def __enter__(self) -> EnronFinalTestAccess:
        if self._entered:
            raise EnronSplitError("Final-test access context cannot be entered twice.")
        self._entered = True
        try:
            return self._claim_and_open()
        except EnronSplitError:
            raise
        except Exception:
            raise EnronSplitError("Final-test access transition failed safely.") from None

    def iter_records(self) -> Iterator[dict[str, Any]]:
        if self._handle is None or not self._entered:
            raise EnronSplitError("Final-test access context is not active.")
        if self._iterated:
            raise EnronSplitError("Final-test records can be iterated only once.")
        self._iterated = True
        handle = self._handle
        try:
            yield from self._consume_records(handle)
        except GeneratorExit:
            raise
        except EnronSplitError:
            self._stream_failed = True
            raise
        except (OSError, OverflowError, ValueError):
            self._stream_failed = True
            raise EnronSplitError("Sealed test content could not be consumed safely.") from None
        except BaseException:
            self._stream_failed = True
            raise
        self._exhausted = True

    def iter_records_with_memberships(self) -> Iterator[tuple[dict[str, Any], dict[str, Any]]]:
        """Yield each final-test record with its exact bound test membership."""

        if self._handle is None or not self._entered:
            raise EnronSplitError("Final-test access context is not active.")
        if self._iterated:
            raise EnronSplitError("Final-test records can be iterated only once.")
        self._iterated = True
        try:
            membership_handle = self._open_membership_stream()
            yield from self._consume_record_membership_pairs(self._handle, membership_handle)
        except GeneratorExit:
            raise
        except EnronSplitError:
            self._stream_failed = True
            raise
        except (EnronPrivateIOError, OSError, OverflowError, ValueError):
            self._stream_failed = True
            raise EnronSplitError("Sealed test content and memberships could not be consumed safely.") from None
        except BaseException:
            self._stream_failed = True
            raise
        self._exhausted = True

    def _open_membership_stream(self) -> BinaryIO:
        directory_fd = self._directory_fd
        descriptor = self._membership_descriptor
        if directory_fd is None:
            raise EnronSplitError("Final-test access directory is no longer pinned.")
        if not isinstance(descriptor, Mapping) or descriptor.get("id") != "test_memberships":
            raise EnronSplitError("Sealed test membership artifact binding is invalid.")
        _verify_descriptor_metadata(
            self._root,
            descriptor,
            "memberships.jsonl",
            self._expected_records,
            directory_fd=directory_fd,
        )
        self._expected_membership_records = int(descriptor["records"])
        self._expected_membership_sha256 = str(descriptor["sha256"])
        self._expected_membership_bytes = int(descriptor["bytes"])
        handle = open_private_binary_input_at(directory_fd, "memberships.jsonl")
        try:
            if os.fstat(handle.fileno()).st_size != self._expected_membership_bytes:
                raise EnronSplitError("Sealed test memberships changed after final access was claimed.")
            self._opened_membership_identity = _private_regular_identity(os.fstat(handle.fileno()))
            self._membership_handle = handle
            return handle
        except BaseException:
            try:
                handle.close()
            except OSError:
                pass
            raise

    def _consume_record_membership_pairs(
        self,
        record_handle: BinaryIO,
        membership_handle: BinaryIO,
    ) -> Iterator[tuple[dict[str, Any], dict[str, Any]]]:
        records = self._consume_records(record_handle)
        memberships = self._consume_memberships(membership_handle)
        while True:
            record = next(records, None)
            membership = next(memberships, None)
            if record is None or membership is None:
                if record is not None or membership is not None:
                    raise EnronSplitError("Sealed test records and memberships differ in length.")
                return
            if record.get("document_id") != membership.get("document_id"):
                raise EnronSplitError("Sealed test records and memberships are not aligned.")
            yield record, membership

    def _consume_memberships(self, handle: BinaryIO) -> Iterator[dict[str, Any]]:
        records = 0
        digest = hashlib.sha256()
        byte_count = 0
        previous: str | None = None
        path = Path("memberships.jsonl")
        while raw := handle.readline(DEFAULT_MAX_PREPARED_LINE_BYTES + 1):
            if len(raw) > DEFAULT_MAX_PREPARED_LINE_BYTES:
                raise EnronSplitError("Sealed test membership record exceeds its byte limit.")
            row = _parse_frozen_jsonl_object(path, records + 1, raw)
            if raw != _canonical_line(row):
                raise EnronSplitError("Sealed test membership record is not canonical.")
            document_id = _validate_final_test_membership(row)
            if previous is not None and document_id <= previous:
                raise EnronSplitError("Sealed test memberships are not canonically ordered.")
            previous = document_id
            digest.update(raw)
            byte_count += len(raw)
            records += 1
            yield row
        if (
            records != self._expected_membership_records
            or byte_count != self._expected_membership_bytes
            or "sha256:" + digest.hexdigest() != self._expected_membership_sha256
            or self._opened_membership_identity is None
            or _private_regular_identity(os.fstat(handle.fileno())) != self._opened_membership_identity
        ):
            raise EnronSplitError("Sealed test memberships changed during final access.")

    def _consume_records(self, handle: BinaryIO) -> Iterator[dict[str, Any]]:
        records = 0
        digest = hashlib.sha256()
        byte_count = 0
        previous: str | None = None
        while raw := handle.readline(DEFAULT_MAX_PREPARED_LINE_BYTES + 1):
            if len(raw) > DEFAULT_MAX_PREPARED_LINE_BYTES:
                raise EnronSplitError("Sealed test record exceeds its byte limit.")
            try:
                row = json.loads(
                    raw.decode("utf-8"),
                    parse_constant=lambda _value: (_ for _ in ()).throw(EnronSplitError("Non-finite JSON is invalid.")),
                    parse_float=_parse_finite_split_float,
                    parse_int=_parse_bounded_split_int,
                    object_pairs_hook=_reject_duplicate_keys,
                )
            except EnronSplitError:
                raise
            except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, OverflowError, ValueError):
                raise EnronSplitError("Sealed test record is invalid JSON.") from None
            if not isinstance(row, dict):
                raise EnronSplitError("Sealed test record must contain a JSON object.")
            _validate_private_json_depth(row)
            if raw != _canonical_line(row):
                raise EnronSplitError("Sealed test record is not canonical.")
            document_id = row.get("document_id")
            if (
                not isinstance(document_id, str)
                or not _DOCUMENT_ID_RE.fullmatch(document_id)
                or (previous is not None and document_id <= previous)
            ):
                raise EnronSplitError("Sealed test records are not canonically ordered.")
            previous = document_id
            digest.update(raw)
            byte_count += len(raw)
            records += 1
            yield row
        if (
            records != self._expected_records
            or byte_count != self._expected_bytes
            or "sha256:" + digest.hexdigest() != self._expected_sha256
            or self._opened_identity is None
            or _private_regular_identity(os.fstat(handle.fileno())) != self._opened_identity
        ):
            raise EnronSplitError("Sealed test content changed during final access.")

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        directory_fd = self._directory_fd
        if directory_fd is None:
            raise EnronSplitError("Final-test access directory is no longer pinned.")
        close_failed = False
        try:
            for attribute in ("_membership_handle", "_handle"):
                handle = getattr(self, attribute)
                if handle is not None:
                    try:
                        handle.close()
                    except OSError:
                        close_failed = True
                    setattr(self, attribute, None)
            missing_audit_output_binding = (
                exc is None and self._exhausted and not close_failed and self._audit_output_binding_sha256 is None
            )
            if exc is None and self._exhausted and not close_failed and self._audit_output_binding_sha256 is not None:
                status = "completed"
            elif exc is not None or self._stream_failed or close_failed or missing_audit_output_binding:
                status = "failed"
            else:
                status = "aborted"
            self._publish_outcome(status)
            if close_failed and exc is None:
                raise EnronSplitError("Final-test content handle could not be closed safely.")
            if missing_audit_output_binding:
                raise EnronSplitError("Final-test access exhausted without a committed audit-output binding.")
        except EnronSplitError:
            if exc is None:
                raise
        finally:
            os.close(directory_fd)
            self._directory_fd = None


def begin_enron_final_test_access(
    sealed_path: Path,
    *,
    frozen_target: Mapping[str, str],
) -> EnronFinalTestAccess:
    """Return the one-shot steward context; no test byte is read before entering it."""

    try:
        return EnronFinalTestAccess(sealed_path, frozen_target)
    except EnronSplitError:
        raise
    except Exception:
        raise EnronSplitError("Final-test access request is invalid.") from None


def verify_enron_final_test_access_outcome(
    sealed_path: Path,
    *,
    expected_audit_plan_sha256: str,
    expected_audit_output_binding_sha256: str,
) -> dict[str, Any]:
    """Verify the closed completed-access metadata without reopening sealed content."""

    try:
        return _verify_enron_final_test_access_outcome(
            sealed_path,
            expected_audit_plan_sha256=expected_audit_plan_sha256,
            expected_audit_output_binding_sha256=expected_audit_output_binding_sha256,
        )
    except EnronSplitError:
        raise
    except Exception:
        raise EnronSplitError("Final-test access outcome verification failed safely.") from None


def _verify_enron_final_test_access_outcome(
    sealed_path: Path,
    *,
    expected_audit_plan_sha256: str,
    expected_audit_output_binding_sha256: str,
) -> dict[str, Any]:
    if (
        not isinstance(sealed_path, Path)
        or not isinstance(expected_audit_plan_sha256, str)
        or not _SHA256_RE.fullmatch(expected_audit_plan_sha256)
        or not isinstance(expected_audit_output_binding_sha256, str)
        or not _SHA256_RE.fullmatch(expected_audit_output_binding_sha256)
    ):
        raise EnronSplitError("Final-test access outcome verification options are invalid.")
    root, directory_fd = _open_locked_transition_root(sealed_path)
    try:
        manifest_snapshot = _read_json_object_snapshot_at(directory_fd, "manifest.json")
        manifest = manifest_snapshot.value
        _validate_sealed_access_manifest(manifest)
        preseal_snapshot = _verify_preseal_access_metadata(
            root,
            manifest=manifest,
            manifest_sha256=manifest_snapshot.file.sha256,
            directory_fd=directory_fd,
        )
        _verify_pair_receipt(
            root,
            manifest_snapshot.file.sha256,
            str(manifest.get("benchmark_version")),
            preseal_verification_sha256=preseal_snapshot.file.sha256,
            development_manifest_sha256=str(preseal_snapshot.value["development_manifest_sha256"]),
            development_freeze_receipt_sha256=str(preseal_snapshot.value["freeze_receipt_sha256"]),
            directory_fd=directory_fd,
        )
        result = _verify_access_state(
            root,
            manifest,
            manifest_snapshot.file.sha256,
            preseal_verification_sha256=preseal_snapshot.file.sha256,
            directory_fd=directory_fd,
        )
        if (
            result.get("status") != "completed"
            or result.get("audit_plan_sha256") != expected_audit_plan_sha256
            or result.get("audit_output_binding_sha256") != expected_audit_output_binding_sha256
        ):
            raise EnronSplitError("Final-test access outcome does not match the expected audit output.")
        _validate_aggregate_privacy(result)
        return result
    finally:
        os.close(directory_fd)


def finalize_aborted_enron_final_test_access(sealed_path: Path) -> dict[str, Any]:
    """Finalize a stranded claim through a stable, path-free error boundary."""

    try:
        return _finalize_aborted_enron_final_test_access(sealed_path)
    except EnronSplitError:
        raise
    except Exception:
        raise EnronSplitError("Final-test aborted outcome could not be finalized safely.") from None


def _finalize_aborted_enron_final_test_access(sealed_path: Path) -> dict[str, Any]:
    """Record an aborted outcome for a valid crash-stranded claim without reopening test data."""

    root, directory_fd = _open_locked_transition_root(sealed_path)
    try:
        manifest_snapshot = _read_json_object_snapshot_at(directory_fd, "manifest.json")
        manifest = manifest_snapshot.value
        _validate_sealed_access_manifest(manifest)
        manifest_sha256 = manifest_snapshot.file.sha256
        preseal_snapshot = _verify_preseal_access_metadata(
            root,
            manifest=manifest,
            manifest_sha256=manifest_sha256,
            directory_fd=directory_fd,
        )
        pair_snapshot = _verify_pair_receipt(
            root,
            manifest_sha256,
            str(manifest.get("benchmark_version")),
            preseal_verification_sha256=preseal_snapshot.file.sha256,
            development_manifest_sha256=str(preseal_snapshot.value["development_manifest_sha256"]),
            development_freeze_receipt_sha256=str(preseal_snapshot.value["freeze_receipt_sha256"]),
            directory_fd=directory_fd,
        )
        binding_snapshot = _verify_evidence_binding(
            root,
            manifest,
            manifest_sha256,
            preseal_verification_sha256=preseal_snapshot.file.sha256,
            directory_fd=directory_fd,
        )
        access_state = _verify_access_state(
            root,
            manifest,
            manifest_sha256,
            preseal_verification_sha256=preseal_snapshot.file.sha256,
            directory_fd=directory_fd,
        )
        if access_state.get("status") != "claimed" or binding_snapshot is None:
            raise EnronSplitError("Final-test access does not have a valid claim awaiting an outcome.")
        claim_snapshot = _read_json_object_snapshot_at(directory_fd, "ACCESS_CLAIMED.json")
        claim = claim_snapshot.value
        frozen_target = claim["frozen_target"]
        outcome = {
            "schema_version": FINAL_TEST_ACCESS_SCHEMA_VERSION,
            "benchmark_version": claim["benchmark_version"],
            "accessed_at": claim["accessed_at"],
            "status": "aborted",
            "frozen_target_sha256": _hash_bytes(_canonical_json(frozen_target).encode("utf-8")),
            "evidence_binding_sha256": claim["evidence_binding_sha256"],
            "claim_sha256": claim["claim_sha256"],
            "audit_output_binding_sha256": None,
        }
        _assert_private_snapshot_current_at(directory_fd, "manifest.json", manifest_snapshot.file)
        _assert_private_snapshot_current_at(directory_fd, "PRESEAL_VERIFIED.json", preseal_snapshot.file)
        _assert_private_snapshot_current_at(directory_fd, "PAIR_COMMITTED.json", pair_snapshot.file)
        _assert_private_snapshot_current_at(directory_fd, "EVIDENCE_BOUND.json", binding_snapshot.file)
        _assert_private_snapshot_current_at(directory_fd, "ACCESS_CLAIMED.json", claim_snapshot.file)
        _write_exclusive_private_json_at(directory_fd, "ACCESS_OUTCOME.json", outcome)
        result = _verify_access_state(
            root,
            manifest,
            manifest_sha256,
            preseal_verification_sha256=preseal_snapshot.file.sha256,
            directory_fd=directory_fd,
        )
        _validate_aggregate_privacy(result)
        return result
    finally:
        os.close(directory_fd)

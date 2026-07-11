"""Privacy-first, leakage-aware train/validation/sealed-test splitting for Enron v2.

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
import tempfile
from array import array
from collections import Counter, defaultdict
from collections.abc import Iterator, Mapping, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, TextIO

from .enron_preparation import (
    EnronPreparationError,
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
)

SPLIT_MANIFEST_SCHEMA_VERSION = "nerb.enron_split_manifest.v2"
SPLIT_FREEZE_RECEIPT_SCHEMA_VERSION = "nerb.enron_split_freeze_receipt.v2"
SPLIT_MEMBERSHIP_SCHEMA_VERSION = "nerb.enron_split_membership.v2"
SPLIT_SAMPLE_SCHEMA_VERSION = "nerb.enron_split_sample.v2"
SPLIT_GROUP_SCHEMA_VERSION = "nerb.enron_split_group.v2"
SPLIT_LEAKAGE_AUDIT_SCHEMA_VERSION = "nerb.enron_split_leakage_audit.v2"
FINAL_TEST_ACCESS_SCHEMA_VERSION = "nerb.enron_final_test_access.v2"
SPLIT_PAIR_RECEIPT_SCHEMA_VERSION = "nerb.enron_split_pair_receipt.v2"

DEFAULT_SPLIT_SEED = "nerb-enron-v2-split-v1"
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
_BENCHMARK_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+\-/]{0,127}$")
_FROZEN_TARGET_KEYS = frozenset(
    {
        "frozen_at",
        "manifest_sha256",
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
    "PAIR_COMMITTED.json",
)


class EnronSplitError(ValueError):
    """Raised when a split cannot be constructed or verified safely."""


@dataclass(frozen=True)
class EnronSplitOptions:
    preparation_run: Path
    development_output_dir: Path
    sealed_output_dir: Path
    benchmark_version: str = "enron-v2"
    seed: str = DEFAULT_SPLIT_SEED
    train_fraction: float = 0.8
    validation_fraction: float = 0.1
    near_hamming: int = 3
    max_near_candidate_pairs: int = 100_000_000
    sample_per_role: int = 10_000
    fixture_mode: bool = False
    allow_unignored_output: bool = False


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


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open_private_binary_input(path) as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _utc_instant(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EnronSplitError("Prepared temporal timestamp is invalid.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise EnronSplitError("Prepared temporal timestamp is not timezone-aware.")
    return parsed.astimezone(timezone.utc)


def _artifact_descriptor(path: Path, *, records: int, artifact_id: str | None = None) -> dict[str, Any]:
    return {
        "id": artifact_id or path.stem,
        "name": path.name,
        "sha256": _hash_file(path),
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
    if not isinstance(options.benchmark_version, str) or not _BENCHMARK_RE.fullmatch(options.benchmark_version):
        raise EnronSplitError("benchmark_version is invalid.")
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
    if not options.fixture_mode and (
        options.train_fraction != 0.8 or options.validation_fraction != 0.1 or options.near_hamming != 3
    ):
        raise EnronSplitError(
            "Promotable Enron v2 splits require the frozen 80/10/10 allocation and Hamming-radius-three policy."
        )


def _open_spool(path: Path) -> sqlite3.Connection:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    os.close(descriptor)
    os.chmod(path, 0o600, follow_symlinks=False)
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA journal_mode=OFF")
    connection.execute("PRAGMA synchronous=OFF")
    connection.execute("PRAGMA temp_store=FILE")
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
) -> int:
    records = 0
    previous_document_id: str | None = None
    for _, raw, row in _iter_strict_jsonl(prepared_path, DEFAULT_MAX_PREPARED_LINE_BYTES):
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
    if finalize:
        for node, signature in connection.execute(
            "SELECT node, signature FROM near_signatures ORDER BY node, signature"
        ):
            for pair_index, value in _near_pair_keys(str(signature)):
                connection.execute("INSERT OR IGNORE INTO near_bands VALUES (?, ?, ?)", (pair_index, value, node))
        for table, columns in (
            ("exact_features", "feature, node"),
            ("own_message_ids", "feature, node"),
            ("reference_message_ids", "feature, node"),
            ("thread_participants", "thread, identity, node"),
            ("identities", "identity, node"),
        ):
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
) -> None:
    previous_key: tuple[Any, ...] | None = None
    first_node: int | None = None
    for *keys, node_value in connection.execute(query):
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
) -> tuple[_UnionFind, Counter[str], int, int]:
    union_find = _UnionFind(records)
    edge_counts: Counter[str] = Counter()
    _union_runs(
        connection,
        union_find,
        "SELECT feature, node FROM exact_features GROUP BY feature, node ORDER BY feature, node",
        "exact_plaintext",
        edge_counts,
    )
    _union_runs(
        connection,
        union_find,
        "SELECT feature, node FROM own_message_ids GROUP BY feature, node ORDER BY feature, node",
        "same_message_id",
        edge_counts,
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
    )

    # Five disjoint 13/13/13/13/12-bit bands indexed by all ten band pairs
    # are complete for Hamming distance <= 3: at least two bands must remain
    # unchanged. Materialize each pair-key index incrementally and enforce
    # budgets against both raw join emissions and unique candidates. Per-node
    # band keys are unique, so the bucket sum exactly bounds SQL join work.
    near_candidate_emissions = 0
    for (bucket_size,) in connection.execute("SELECT COUNT(*) FROM near_bands GROUP BY band, value"):
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
        try:
            connection.execute(
                """
                INSERT OR IGNORE INTO near_candidates
                SELECT left_band.node, right_band.node
                FROM near_bands AS left_band JOIN near_bands AS right_band
                  ON left_band.band = right_band.band AND left_band.value = right_band.value
                 AND left_band.node < right_band.node
                WHERE left_band.band = ?
                """,
                (pair_index,),
            )
        except sqlite3.IntegrityError as exc:
            if "near candidate budget exceeded" in str(exc):
                raise EnronSplitError("Near-duplicate candidate budget exceeded; split aborted fail-closed.") from exc
            raise
        near_candidate_pairs = int(connection.execute("SELECT COUNT(*) FROM near_candidates").fetchone()[0])
        if near_candidate_pairs > options.max_near_candidate_pairs:
            raise EnronSplitError("Near-duplicate candidate budget exceeded; split aborted fail-closed.")
    signatures_by_node: list[tuple[int, ...]] = [()] * records
    current_node: int | None = None
    current_values: list[int] = []
    for node, signature in connection.execute("SELECT node, signature FROM near_signatures ORDER BY node, signature"):
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


def _components(connection: sqlite3.Connection, union_find: _UnionFind) -> tuple[_Component, ...]:
    members: dict[int, list[int]] = defaultdict(list)
    metadata: dict[int, tuple[str, int, str | None, bool]] = {}
    for node, document_id, occurrences, date_utc, temporal in connection.execute(
        "SELECT node, document_id, occurrences, date_utc, temporal FROM records ORDER BY node"
    ):
        node_int = int(node)
        members[union_find.find(node_int)].append(node_int)
        metadata[node_int] = (str(document_id), int(occurrences), date_utc, bool(temporal))
    result: list[_Component] = []
    for nodes in members.values():
        document_ids = [metadata[node][0] for node in nodes]
        eligible_dates = [metadata[node][2] for node in nodes if metadata[node][3]]
        result.append(
            _Component(
                group_id=_component_id(document_ids),
                nodes=tuple(nodes),
                records=len(nodes),
                occurrences=sum(metadata[node][1] for node in nodes),
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
    components: Sequence[_Component], options: EnronSplitOptions
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
            roles[component.group_id] = (
                "train" if index < train_end else "validation" if index < validation_end else "test"
            )
    validation_boundary = options.train_fraction + options.validation_fraction
    for component in non_temporal:
        value = (
            int(
                hashlib.sha256(
                    (
                        "nerb/enron/non-temporal/v2\0"
                        + options.benchmark_version
                        + "\0"
                        + options.seed
                        + "\0"
                        + component.group_id
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
) -> tuple[tuple[_Membership, ...], dict[str, dict[str, int]]]:
    component_by_group = {component.group_id: component for component in components}
    connection.execute("DROP TABLE IF EXISTS node_assignments")
    connection.execute(
        "CREATE TEMP TABLE node_assignments (node INTEGER PRIMARY KEY, role TEXT NOT NULL, group_id TEXT NOT NULL)"
    )
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
    edge_families_by_group: dict[str, set[str]] = defaultdict(set)
    for edge, node in connection.execute("SELECT edge, node FROM edge_provenance ORDER BY edge, node"):
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
            options.benchmark_version + "\0" + options.seed + "\0" + membership.document_id,
        ),
        membership.document_id,
    )


def _select_samples(
    memberships: Sequence[_Membership], options: EnronSplitOptions
) -> tuple[frozenset[int], dict[str, int]]:
    selected: set[int] = set()
    sample_counts: dict[str, int] = {}
    for role in _ROLE_NAMES:
        strata: dict[str, list[int]] = defaultdict(list)
        margins: dict[str, list[int]] = defaultdict(list)
        role_nodes = [index for index, membership in enumerate(memberships) if membership.role == role]
        ranks = {node: _sample_rank(memberships[node], options) for node in role_nodes}
        for node in role_nodes:
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
        role = node_roles[component.nodes[0]]
        key = "eligible" if component.temporal else "non_temporal"
        eligibility[role][f"{key}_groups"] += 1
    fractions = {
        "train": options.train_fraction,
        "validation": options.validation_fraction,
        "test": 1.0 - options.train_fraction - options.validation_fraction,
    }
    boundary_payload = {
        "benchmark_version": options.benchmark_version,
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


def _build_state(connection: sqlite3.Connection, records: int, options: EnronSplitOptions) -> _BuildState:
    union_find, edge_counts, near_candidate_emissions, near_candidate_pairs = _build_leakage_graph(
        connection, records, options
    )
    components = _components(connection, union_find)
    node_roles, node_groups, role_records, role_groups = _assign_components(components, options)
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
    memberships, cohort_counts = _derive_memberships(connection, components, node_roles, node_groups)
    _enforce_cohort_support(cohort_counts, options)
    selected_nodes, sample_counts = _select_samples(memberships, options)
    allocation_audit = _allocation_audit(
        connection,
        components,
        node_roles,
        node_groups,
        role_records,
        records,
        options,
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
) -> tuple[int, int]:
    dev_membership_count = 0
    sealed_membership_count = 0
    for node, membership in enumerate(state.memberships):
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


def _write_groups(handle: BinaryIO, state: _BuildState) -> None:
    for component in state.components:
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
) -> dict[str, Any]:
    return {
        "train": {
            "records": state.role_records["train"],
            "groups": state.role_groups["train"],
            "artifact": _artifact_descriptor(
                development_stage / "train.jsonl", records=state.role_records["train"], artifact_id="train"
            ),
        },
        "validation": {
            "records": state.role_records["validation"],
            "groups": state.role_groups["validation"],
            "artifact": _artifact_descriptor(
                development_stage / "validation.jsonl",
                records=state.role_records["validation"],
                artifact_id="validation",
            ),
        },
        "test": {
            "records": state.role_records["test"],
            "groups": state.role_groups["test"],
            "artifact": _artifact_descriptor(
                sealed_stage / "test.jsonl", records=state.role_records["test"], artifact_id="test"
            ),
        },
    }


def _preparation_binding(preparation_run: Path, verified: Mapping[str, Any]) -> dict[str, Any]:
    profile = verified["profile"]
    source = profile["source"]
    prepared = verified["artifacts"]["prepared_records"]
    return {
        "manifest_sha256": _hash_file(preparation_run / "manifest.json"),
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
        "benchmark_version": options.benchmark_version,
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
            "initial_access_state": "sealed",
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
        "benchmark_version": options.benchmark_version,
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


def split_enron_preparation(options: EnronSplitOptions) -> dict[str, Any]:
    """Create immutable development and sealed split runs from a verified preparation run."""

    _validate_options(options)
    try:
        verified = load_enron_preparation_run(options.preparation_run)
        preparation = _preparation_binding(options.preparation_run, verified)
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
            spool_path = development_run.stage_dir / ".split.sqlite3"
            connection = _open_spool(spool_path)
            try:
                records = _ingest_prepared(connection, prepared_path, verified["profile"]["source"])
                state = _build_state(connection, records, options)
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
                    )
                with sealed_run.open_binary("group-assignments.jsonl") as group_file:
                    _write_groups(group_file, state)
                audit = _leakage_audit(state)
                with sealed_run.open_text("leakage-audit.json") as audit_file:
                    _write_json(audit_file, audit)

                roles = _role_descriptors(state, development_run.stage_dir, sealed_run.stage_dir)
                sealed_artifacts = {
                    "test": roles["test"]["artifact"],
                    "memberships": _artifact_descriptor(
                        sealed_run.stage_dir / "memberships.jsonl",
                        records=sealed_membership_count,
                        artifact_id="test_memberships",
                    ),
                    "samples": _artifact_descriptor(
                        sealed_run.stage_dir / "samples.jsonl",
                        records=state.sample_counts["test"],
                        artifact_id="test_samples",
                    ),
                    "group_assignments": _artifact_descriptor(
                        sealed_run.stage_dir / "group-assignments.jsonl",
                        records=len(state.components),
                        artifact_id="group_assignments",
                    ),
                    "leakage_audit": _artifact_descriptor(
                        sealed_run.stage_dir / "leakage-audit.json", records=1, artifact_id="leakage_audit"
                    ),
                }
                full_manifest = _full_manifest(options, preparation, policy, state, roles, sealed_artifacts)
                _validate_aggregate_privacy(full_manifest)
                with sealed_run.open_text("manifest.json") as manifest_file:
                    _write_json(manifest_file, full_manifest)
                full_manifest_sha256 = _hash_file(sealed_run.stage_dir / "manifest.json")

                freeze_receipt = {
                    "schema_version": SPLIT_FREEZE_RECEIPT_SCHEMA_VERSION,
                    "benchmark_version": options.benchmark_version,
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
                    ),
                    "samples": _artifact_descriptor(
                        development_run.stage_dir / "samples.jsonl",
                        records=state.sample_counts["train"] + state.sample_counts["validation"],
                        artifact_id="development_samples",
                    ),
                    "freeze_receipt": _artifact_descriptor(
                        development_run.stage_dir / "split-freeze-receipt.json",
                        records=1,
                        artifact_id="freeze_receipt",
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
                development_manifest_sha256 = _hash_file(development_run.stage_dir / "manifest.json")
            finally:
                connection.close()
                for candidate in (spool_path, Path(str(spool_path) + "-journal")):
                    if candidate.exists():
                        candidate.unlink()
            # Sealed data becomes immutable before its redacted development
            # receipt, preventing a visible receipt for an absent sealed run.
            sealed_run.commit()
            development_run.commit()
            pair_receipt = {
                "schema_version": SPLIT_PAIR_RECEIPT_SCHEMA_VERSION,
                "benchmark_version": options.benchmark_version,
                "sealed_manifest_sha256": full_manifest_sha256,
                "development_manifest_sha256": development_manifest_sha256,
                "freeze_receipt_sha256": development_artifacts["freeze_receipt"]["sha256"],
            }
            _validate_aggregate_privacy(pair_receipt)
            _write_exclusive_private_json(sealed_run.final_dir, "PAIR_COMMITTED.json", pair_receipt)
    except (EnronPreparationError, EnronPrivateIOError, OSError, sqlite3.Error) as exc:
        raise EnronSplitError(str(exc)) from exc

    return {
        "schema_version": SPLIT_MANIFEST_SCHEMA_VERSION,
        "committed": True,
        "benchmark_version": options.benchmark_version,
        "fixture_mode": options.fixture_mode,
        "promotable": not options.fixture_mode,
        "records": records,
        "groups": len(state.components),
        "roles": {
            role: {"records": state.role_records[role], "groups": state.role_groups[role]} for role in _ROLE_NAMES
        },
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


def _read_json_object(path: Path, *, max_bytes: int = 16 * 1024 * 1024) -> dict[str, Any]:
    try:
        with open_private_binary_input(path) as handle:
            raw = handle.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise EnronSplitError(f"{path.name} exceeds its byte limit.")
        value = json.loads(
            raw.decode("utf-8"),
            parse_constant=lambda _value: (_ for _ in ()).throw(EnronSplitError("Non-finite JSON is invalid.")),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, EnronPrivateIOError) as exc:
        raise EnronSplitError(f"{path.name} is not a valid private JSON object.") from exc
    if not isinstance(value, dict):
        raise EnronSplitError(f"{path.name} must contain a JSON object.")
    return value


def _assert_committed_run(root: Path, expected_files: Sequence[str], *, allow_access_files: bool = False) -> Path:
    try:
        root = root.expanduser().absolute()
    except (OSError, RuntimeError, ValueError) as exc:
        raise EnronSplitError("Split run path is invalid.") from exc
    try:
        root_info = root.lstat()
    except OSError as exc:
        raise EnronSplitError("Split run does not exist.") from exc
    if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode):
        raise EnronSplitError("Split run must be a non-symlink directory.")
    marker = root / _COMMIT_MARKER
    with open_private_binary_input(marker) as handle:
        if handle.read(len(_COMMIT_PAYLOAD) + 1) != _COMMIT_PAYLOAD:
            raise EnronSplitError("Split commit marker is invalid.")
    allowed = set(expected_files) | {_COMMIT_MARKER}
    if allow_access_files:
        allowed |= {"ACCESS_CLAIMED.json", "ACCESS_OUTCOME.json"}
    try:
        actual = set(os.listdir(root))
    except OSError as exc:
        raise EnronSplitError("Split run could not be enumerated safely.") from exc
    if actual != allowed and not (allow_access_files and set(expected_files) | {_COMMIT_MARKER} <= actual <= allowed):
        raise EnronSplitError("Split run file inventory is invalid.")
    for name in actual:
        info = (root / name).lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise EnronSplitError("Split run contains an unsafe file.")
    if stat.S_IMODE(root_info.st_mode) & 0o077:
        raise EnronSplitError("Split run directory is not private.")
    return root


def _verify_descriptor(root: Path, descriptor: Any, expected_name: str, expected_records: int | None = None) -> None:
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
    if descriptor.get("sha256") != _hash_file(artifact) or descriptor.get("bytes") != artifact.stat().st_size:
        raise EnronSplitError("Split artifact descriptor does not match its file.")


def _iter_role_records(path: Path, expected_records: int) -> Iterator[dict[str, Any]]:
    records = 0
    previous: str | None = None
    for _, raw, row in _iter_strict_jsonl(path, DEFAULT_MAX_PREPARED_LINE_BYTES):
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

    __slots__ = ("_root", "manifest", "freeze_receipt")

    def __init__(self, root: Path, manifest: Mapping[str, Any], freeze_receipt: Mapping[str, Any]) -> None:
        self._root = root
        self.manifest = dict(manifest)
        self.freeze_receipt = dict(freeze_receipt)

    def iter_train_records(self) -> Iterator[dict[str, Any]]:
        descriptor = self.manifest["development_roles"]["train"]["artifact"]
        return _iter_role_records(self._root / "train.jsonl", int(descriptor["records"]))

    def iter_validation_records(self) -> Iterator[dict[str, Any]]:
        descriptor = self.manifest["development_roles"]["validation"]["artifact"]
        return _iter_role_records(self._root / "validation.jsonl", int(descriptor["records"]))


def load_enron_development_split(path: Path) -> EnronDevelopmentSplit:
    """Load a redacted development run without exposing any test selector."""

    root = _assert_committed_run(path, _DEVELOPMENT_FILES)
    manifest = _read_json_object(root / "manifest.json")
    receipt = _read_json_object(root / "split-freeze-receipt.json")
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
    for role in ("train", "validation"):
        role_value = manifest["development_roles"].get(role)
        if not isinstance(role_value, Mapping) or set(role_value) != {"records", "groups", "artifact"}:
            raise EnronSplitError("Development role descriptor is invalid.")
        if role_value["artifact"] != artifacts[role]:
            raise EnronSplitError("Development role artifact binding is invalid.")
        if not isinstance(artifacts[role], Mapping) or artifacts[role].get("id") != role:
            raise EnronSplitError("Development role artifact identity is invalid.")
        _verify_descriptor(root, artifacts[role], f"{role}.jsonl", int(role_value["records"]))
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
    _verify_descriptor(root, artifacts["memberships"], "memberships.jsonl")
    _verify_descriptor(root, artifacts["samples"], "samples.jsonl")
    _verify_descriptor(root, artifacts["freeze_receipt"], "split-freeze-receipt.json", 1)
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
    return EnronDevelopmentSplit(root, manifest, receipt)


def _iter_canonical_objects(path: Path, expected_records: int, schema_version: str) -> Iterator[dict[str, Any]]:
    count = 0
    previous_document_id: str | None = None
    for _, raw, row in _iter_strict_jsonl(path, DEFAULT_MAX_PREPARED_LINE_BYTES):
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


def _verify_private_membership_artifacts(
    development_root: Path,
    sealed_root: Path,
    full_manifest: Mapping[str, Any],
    state: _BuildState,
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
        for row in _iter_canonical_objects(path, count, SPLIT_MEMBERSHIP_SCHEMA_VERSION):
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
        for row in _iter_canonical_objects(path, expected_count, SPLIT_SAMPLE_SCHEMA_VERSION):
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


def _verify_group_artifact(sealed_root: Path, state: _BuildState) -> None:
    expected: list[dict[str, Any]] = []
    for component in state.components:
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
        _iter_canonical_objects(sealed_root / "group-assignments.jsonl", len(expected), SPLIT_GROUP_SCHEMA_VERSION)
    )
    if observed != expected:
        raise EnronSplitError("Sealed group assignment artifact does not match reconstructed leakage groups.")


def _verify_prepared_conservation(
    development_root: Path,
    sealed_root: Path,
    expected_sha256: str,
    expected_records: int,
) -> None:
    streams: list[Iterator[tuple[int, bytes, Mapping[str, Any]]]] = []
    for role in _ROLE_NAMES:
        root = sealed_root if role == "test" else development_root
        streams.append(iter(_iter_strict_jsonl(root / f"{role}.jsonl", DEFAULT_MAX_PREPARED_LINE_BYTES)))
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


def _verify_pair_receipt(
    sealed_root: Path,
    sealed_manifest_sha256: str,
    benchmark_version: str,
    *,
    development_root: Path | None = None,
) -> dict[str, Any]:
    receipt = _read_json_object(sealed_root / "PAIR_COMMITTED.json")
    if (
        set(receipt)
        != {
            "schema_version",
            "benchmark_version",
            "sealed_manifest_sha256",
            "development_manifest_sha256",
            "freeze_receipt_sha256",
        }
        or receipt.get("schema_version") != SPLIT_PAIR_RECEIPT_SCHEMA_VERSION
    ):
        raise EnronSplitError("Split pair receipt schema is invalid.")
    if (
        receipt.get("benchmark_version") != benchmark_version
        or receipt.get("sealed_manifest_sha256") != sealed_manifest_sha256
        or any(
            not isinstance(receipt.get(field), str) or not _SHA256_RE.fullmatch(str(receipt[field]))
            for field in ("sealed_manifest_sha256", "development_manifest_sha256", "freeze_receipt_sha256")
        )
    ):
        raise EnronSplitError("Split pair receipt does not bind the sealed run.")
    if development_root is not None and (
        receipt["development_manifest_sha256"] != _hash_file(development_root / "manifest.json")
        or receipt["freeze_receipt_sha256"] != _hash_file(development_root / "split-freeze-receipt.json")
    ):
        raise EnronSplitError("Split pair receipt does not bind the committed development run.")
    return receipt


def _verify_access_state(
    sealed_root: Path,
    manifest: Mapping[str, Any],
    manifest_sha256: str,
) -> dict[str, Any]:
    claim_path = sealed_root / "ACCESS_CLAIMED.json"
    outcome_path = sealed_root / "ACCESS_OUTCOME.json"
    claim_exists = claim_path.exists()
    outcome_exists = outcome_path.exists()
    if outcome_exists and not claim_exists:
        raise EnronSplitError("Final-test access outcome exists without its immutable claim.")
    if not claim_exists:
        return {"status": "sealed", "access_count": 0, "accessed_at": None}
    claim = _read_json_object(claim_path)
    if (
        set(claim)
        != {
            "schema_version",
            "benchmark_version",
            "accessed_at",
            "frozen_target",
            "claim_sha256",
        }
        or claim.get("schema_version") != FINAL_TEST_ACCESS_SCHEMA_VERSION
    ):
        raise EnronSplitError("Final-test access claim schema is invalid.")
    if claim.get("benchmark_version") != manifest.get("benchmark_version"):
        raise EnronSplitError("Final-test access claim benchmark binding is invalid.")
    frozen_target = claim.get("frozen_target")
    if not isinstance(frozen_target, Mapping):
        raise EnronSplitError("Final-test access claim target is invalid.")
    normalized_target = _validate_frozen_target(
        frozen_target,
        manifest_sha256,
        str(manifest["roles"]["test"]["artifact"]["sha256"]),
    )
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
    except ValueError as exc:
        raise EnronSplitError("Final-test access timestamp is invalid.") from exc
    if accessed_at.tzinfo is None or accessed_at.utcoffset() is None or accessed_at < frozen_at:
        raise EnronSplitError("Final-test access predates its frozen target.")
    if not outcome_exists:
        return {"status": "claimed", "access_count": 1, "accessed_at": claim["accessed_at"]}
    outcome = _read_json_object(outcome_path)
    if (
        set(outcome)
        != {
            "schema_version",
            "benchmark_version",
            "accessed_at",
            "status",
            "frozen_target_sha256",
            "claim_sha256",
        }
        or outcome.get("schema_version") != FINAL_TEST_ACCESS_SCHEMA_VERSION
    ):
        raise EnronSplitError("Final-test access outcome schema is invalid.")
    if (
        outcome.get("benchmark_version") != claim.get("benchmark_version")
        or outcome.get("accessed_at") != claim.get("accessed_at")
        or outcome.get("claim_sha256") != expected_claim_sha256
        or outcome.get("frozen_target_sha256") != _hash_bytes(_canonical_json(normalized_target).encode("utf-8"))
        or outcome.get("status") not in {"completed", "failed", "aborted"}
    ):
        raise EnronSplitError("Final-test access outcome does not bind its claim.")
    return {"status": outcome["status"], "access_count": 1, "accessed_at": claim["accessed_at"]}


def _verify_enron_splits(
    development_path: Path,
    sealed_path: Path,
    *,
    seed: str = DEFAULT_SPLIT_SEED,
) -> dict[str, Any]:
    """Deep steward verification over copied role records and both immutable roots."""

    development = load_enron_development_split(development_path)
    development_root = development._root
    sealed_root = _assert_committed_run(sealed_path, _SEALED_FILES, allow_access_files=True)
    full_manifest = _read_json_object(sealed_root / "manifest.json")
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
    manifest_sha256 = _hash_file(sealed_root / "manifest.json")
    if manifest_sha256 != development.freeze_receipt.get("full_split_manifest_sha256"):
        raise EnronSplitError("Development receipt does not commit to the sealed split manifest.")
    _verify_pair_receipt(
        sealed_root,
        manifest_sha256,
        str(full_manifest.get("benchmark_version")),
        development_root=development_root,
    )
    if (
        full_manifest.get("benchmark_version") != development.manifest.get("benchmark_version")
        or full_manifest.get("preparation") != development.manifest.get("preparation")
        or full_manifest.get("policy") != development.manifest.get("policy")
        or full_manifest.get("sealing", {}).get("test_sealed") is not True
        or full_manifest.get("leakage", {}).get("crossing_groups") != 0
    ):
        raise EnronSplitError("Development and sealed split metadata are not consistently bound.")
    roles = full_manifest.get("roles")
    artifacts = full_manifest.get("artifacts")
    if (
        not isinstance(roles, Mapping)
        or set(roles) != set(_ROLE_NAMES)
        or not isinstance(artifacts, Mapping)
        or set(artifacts) != {"test", "memberships", "samples", "group_assignments", "leakage_audit"}
    ):
        raise EnronSplitError("Sealed role or artifact inventory is invalid.")
    for role in _ROLE_NAMES:
        role_value = roles.get(role)
        if not isinstance(role_value, Mapping) or set(role_value) != {"records", "groups", "artifact"}:
            raise EnronSplitError("Sealed role descriptor is invalid.")
        root = sealed_root if role == "test" else development_root
        if not isinstance(role_value["artifact"], Mapping) or role_value["artifact"].get("id") != role:
            raise EnronSplitError("Sealed role artifact identity is invalid.")
        _verify_descriptor(root, role_value["artifact"], f"{role}.jsonl", int(role_value["records"]))
    for artifact_id, expected_id, filename in (
        ("memberships", "test_memberships", "memberships.jsonl"),
        ("samples", "test_samples", "samples.jsonl"),
        ("group_assignments", "group_assignments", "group-assignments.jsonl"),
        ("leakage_audit", "leakage_audit", "leakage-audit.json"),
    ):
        if not isinstance(artifacts.get(artifact_id), Mapping) or artifacts[artifact_id].get("id") != expected_id:
            raise EnronSplitError("Sealed supporting artifact identity is invalid.")
        _verify_descriptor(sealed_root, artifacts.get(artifact_id), filename)
    if artifacts.get("test") != roles["test"]["artifact"]:
        raise EnronSplitError("Sealed test artifact binding is invalid.")

    policy = full_manifest["policy"]
    preparation = full_manifest["preparation"]
    if policy.get("seed_sha256") != _hash_value("nerb/enron/split-seed/v2", seed):
        raise EnronSplitError("Steward split seed does not match the frozen seed commitment.")
    rebuild_options = EnronSplitOptions(
        preparation_run=Path("unused-preparation"),
        development_output_dir=Path("unused-development"),
        sealed_output_dir=Path("unused-sealed"),
        benchmark_version=str(full_manifest["benchmark_version"]),
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
    expected_policy = _split_policy(rebuild_options)
    if _canonical_json(policy) != _canonical_json(expected_policy):
        raise EnronSplitError("Frozen split policy does not match its canonical implementation and hash.")
    expected_source = {
        "dataset_id": preparation["dataset_id"],
        "revision": preparation["dataset_revision"],
        "split": preparation["dataset_split"],
    }
    _verify_prepared_conservation(
        development_root,
        sealed_root,
        str(preparation["prepared_sha256"]),
        int(preparation["prepared_records"]),
    )
    with tempfile.TemporaryDirectory(prefix="nerb-enron-split-verify-") as temporary:
        temporary_root = Path(temporary)
        temporary_root.chmod(0o700)
        spool = temporary_root / "split.sqlite3"
        connection = _open_spool(spool)
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
                )
                role_counts[role] = count
                start_node += count
            observed_roles = tuple(role for role in _ROLE_NAMES for _ in range(role_counts[role]))
            union_find, edge_counts, near_candidate_emissions, near_candidate_pairs = _build_leakage_graph(
                connection, start_node, rebuild_options
            )
            components = _components(connection, union_find)
            expected_roles, node_groups, rebuilt_role_records, rebuilt_role_groups = _assign_components(
                components, rebuild_options
            )
            if expected_roles != observed_roles:
                raise EnronSplitError("Role assignment differs from the frozen deterministic split policy.")
            if any(
                rebuilt_role_records[role] != roles[role]["records"]
                or rebuilt_role_groups[role] != roles[role]["groups"]
                for role in _ROLE_NAMES
            ):
                raise EnronSplitError("Reconstructed role aggregates do not match the sealed manifest.")
            grouping_truncated_records = int(
                connection.execute("SELECT COUNT(*) FROM records WHERE grouping_truncated = 1").fetchone()[0]
            )
            _enforce_support(
                components,
                start_node,
                rebuilt_role_records,
                rebuilt_role_groups,
                grouping_truncated_records,
                rebuild_options,
            )
            memberships, cohorts = _derive_memberships(connection, components, expected_roles, node_groups)
            _enforce_cohort_support(cohorts, rebuild_options)
            selected_nodes, sample_counts = _select_samples(memberships, rebuild_options)
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
                role_records=dict(rebuilt_role_records),
                role_groups=dict(rebuilt_role_groups),
                cohort_counts=cohorts,
                sample_counts=sample_counts,
                allocation_audit=_allocation_audit(
                    connection,
                    components,
                    expected_roles,
                    node_groups,
                    rebuilt_role_records,
                    start_node,
                    rebuild_options,
                ),
            )
            _verify_private_membership_artifacts(development_root, sealed_root, full_manifest, state)
            _verify_group_artifact(sealed_root, state)
            expected_allocation = {
                **dict(state.allocation_audit),
                "group_assignments_sha256": artifacts["group_assignments"]["sha256"],
            }
            if (
                full_manifest.get("allocation") != expected_allocation
                or development.manifest.get("allocation") != state.allocation_audit
            ):
                raise EnronSplitError("Allocation audit does not match reconstructed temporal boundaries.")
            if _read_json_object(sealed_root / "leakage-audit.json") != _leakage_audit(state):
                raise EnronSplitError("Leakage audit does not match the reconstructed leakage graph.")
            if full_manifest.get("cohorts", {}).get("roles") != {role: dict(cohorts[role]) for role in _ROLE_NAMES}:
                raise EnronSplitError("Cohort aggregates do not match reconstructed memberships.")
            if full_manifest.get("sampling", {}).get("role_records") != sample_counts:
                raise EnronSplitError("Sample aggregates do not match reconstructed representative samples.")
            expected_full_manifest = _full_manifest(
                rebuild_options,
                preparation,
                expected_policy,
                state,
                roles,
                artifacts,
            )
            if _canonical_json(full_manifest) != _canonical_json(expected_full_manifest):
                raise EnronSplitError("Sealed split manifest does not match its full reconstructed canonical form.")
            expected_development_manifest = _redacted_development_manifest(
                rebuild_options,
                preparation,
                expected_policy,
                state,
                roles,
                development.manifest["artifacts"],
                manifest_sha256,
            )
            if _canonical_json(development.manifest) != _canonical_json(expected_development_manifest):
                raise EnronSplitError("Development manifest does not match its redacted canonical projection.")
            expected_receipt = {
                "schema_version": SPLIT_FREEZE_RECEIPT_SCHEMA_VERSION,
                "benchmark_version": rebuild_options.benchmark_version,
                "fixture_mode": rebuild_options.fixture_mode,
                "promotable": not rebuild_options.fixture_mode,
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
            if _canonical_json(development.freeze_receipt) != _canonical_json(expected_receipt):
                raise EnronSplitError("Freeze receipt does not match the reconstructed split.")
        finally:
            connection.close()

    access_state = _verify_access_state(sealed_root, full_manifest, manifest_sha256)
    contract_splits = _contract_split_projection(full_manifest, manifest_sha256)
    return {
        "valid": True,
        "schema_version": SPLIT_MANIFEST_SCHEMA_VERSION,
        "benchmark_version": full_manifest["benchmark_version"],
        "fixture_mode": full_manifest["fixture_mode"],
        "promotable": full_manifest["promotable"],
        "records": sum(int(roles[role]["records"]) for role in _ROLE_NAMES),
        "groups": len(components),
        "roles": {
            role: {"records": int(roles[role]["records"]), "groups": int(roles[role]["groups"])} for role in _ROLE_NAMES
        },
        "manifest_sha256": manifest_sha256,
        "leakage_groups_crossing": 0,
        "test_sealed": True,
        "contract_splits": contract_splits,
        "access": access_state,
    }


def verify_enron_splits(
    development_path: Path,
    sealed_path: Path,
    *,
    seed: str = DEFAULT_SPLIT_SEED,
) -> dict[str, Any]:
    """Deep steward verification with a stable, privacy-safe error boundary."""

    try:
        return _verify_enron_splits(development_path, sealed_path, seed=seed)
    except EnronSplitError:
        raise
    except (
        EnronPreparationError,
        EnronPrivateIOError,
        OSError,
        sqlite3.Error,
        TypeError,
        ValueError,
        KeyError,
        IndexError,
    ) as exc:
        raise EnronSplitError(str(exc)) from exc


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


def _open_pinned_private_root(root: Path) -> tuple[int, int]:
    if root.parent == root or not root.name:
        raise EnronSplitError("Private receipt root is invalid.")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        before = root.lstat()
        parent_fd = os.open(root.parent, flags)
    except OSError as exc:
        raise EnronSplitError("Private receipt root could not be opened safely.") from exc
    directory_fd: int | None = None
    try:
        directory_fd = os.open(root.name, flags, dir_fd=parent_fd)
        after = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(after.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
        ):
            raise EnronSplitError("Private receipt root changed while it was opened.")
        return parent_fd, directory_fd
    except BaseException as exc:
        if directory_fd is not None:
            os.close(directory_fd)
        os.close(parent_fd)
        if isinstance(exc, EnronSplitError):
            raise
        raise EnronSplitError("Private receipt root could not be pinned safely.") from exc


def _write_exclusive_private_json_at(
    root: Path,
    parent_fd: int,
    directory_fd: int,
    name: str,
    value: Mapping[str, Any],
) -> None:
    if Path(name).name != name or name in {"", ".", ".."}:
        raise EnronSplitError("Private receipt name is invalid.")
    payload = _canonical_line(value)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    temporary_name: str | None = None
    file_fd: int | None = None
    published = False
    try:
        for _ in range(128):
            candidate = f".{root.name}.{name}.stage-{secrets.token_hex(12)}"
            try:
                file_fd = os.open(candidate, flags, 0o600, dir_fd=parent_fd)
            except FileExistsError:
                continue
            temporary_name = candidate
            break
        if file_fd is None or temporary_name is None:
            raise EnronSplitError("A unique private receipt staging file could not be created.")
        os.fchmod(file_fd, 0o600)
        offset = 0
        while offset < len(payload):
            written = os.write(file_fd, payload[offset:])
            if written <= 0:
                raise OSError("Private receipt write made no progress.")
            offset += written
        os.fsync(file_fd)
        os.close(file_fd)
        file_fd = None
        _rename_noreplace_at(parent_fd, temporary_name, directory_fd, name)
        published = True
        os.fsync(directory_fd)
        os.fsync(parent_fd)
    except FileExistsError:
        raise EnronSplitError("Final-test access has already been claimed; retries are forbidden.") from None
    except EnronPrivateIOError as exc:
        raise EnronSplitError(str(exc)) from exc
    except OSError as exc:
        raise EnronSplitError("Private receipt could not be published atomically.") from exc
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if temporary_name is not None and not published:
            try:
                os.unlink(temporary_name, dir_fd=parent_fd)
                os.fsync(parent_fd)
            except FileNotFoundError:
                pass


def _write_exclusive_private_json(root: Path, name: str, value: Mapping[str, Any]) -> None:
    normalized = root.expanduser().absolute()
    parent_fd, directory_fd = _open_pinned_private_root(normalized)
    try:
        _write_exclusive_private_json_at(normalized, parent_fd, directory_fd, name, value)
    finally:
        os.close(directory_fd)
        os.close(parent_fd)


class EnronFinalTestAccess(AbstractContextManager["EnronFinalTestAccess"]):
    """One-shot, preverified final-test descriptor owned by a release steward."""

    __slots__ = (
        "_root",
        "_target",
        "_handle",
        "_expected_records",
        "_expected_sha256",
        "_expected_bytes",
        "_benchmark_version",
        "_accessed_at",
        "_claim_sha256",
        "_parent_fd",
        "_directory_fd",
        "_entered",
        "_iterated",
        "_exhausted",
    )

    def __init__(self, root: Path, target: Mapping[str, str]) -> None:
        self._root = root
        self._target = dict(target)
        self._handle: BinaryIO | None = None
        self._expected_records = 0
        self._expected_sha256 = ""
        self._expected_bytes = 0
        self._benchmark_version = ""
        self._accessed_at = ""
        self._claim_sha256 = ""
        self._parent_fd: int | None = None
        self._directory_fd: int | None = None
        self._entered = False
        self._iterated = False
        self._exhausted = False

    def __enter__(self) -> EnronFinalTestAccess:
        if self._entered:
            raise EnronSplitError("Final-test access context cannot be entered twice.")
        self._entered = True
        root = _assert_committed_run(self._root, _SEALED_FILES, allow_access_files=True)
        self._root = root
        if (root / "ACCESS_CLAIMED.json").exists() or (root / "ACCESS_OUTCOME.json").exists():
            raise EnronSplitError("Final-test access has already been claimed; retries are forbidden.")
        manifest = _read_json_object(root / "manifest.json")
        expected_manifest_keys = {
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
        if (
            set(manifest) != expected_manifest_keys
            or manifest.get("schema_version") != SPLIT_MANIFEST_SCHEMA_VERSION
            or manifest.get("sealing", {}).get("test_sealed") is not True
            or manifest.get("leakage", {}).get("crossing_groups") != 0
            or set(manifest.get("roles", {})) != set(_ROLE_NAMES)
        ):
            raise EnronSplitError("Sealed split is not structurally valid for final access.")
        manifest_sha256 = _hash_file(root / "manifest.json")
        _verify_pair_receipt(root, manifest_sha256, str(manifest.get("benchmark_version")))
        role = manifest.get("roles", {}).get("test")
        if not isinstance(role, Mapping) or not isinstance(role.get("artifact"), Mapping):
            raise EnronSplitError("Sealed test descriptor is invalid.")
        target = _validate_frozen_target(
            self._target,
            manifest_sha256,
            str(role["artifact"].get("sha256")),
        )
        if not manifest.get("fixture_mode") and (
            "sha256:" + "0" * 64 in target.values() or target["git_commit"] == "0" * 40
        ):
            raise EnronSplitError("Production final-test target contains a placeholder commitment.")
        if manifest.get("artifacts", {}).get("test") != role["artifact"]:
            raise EnronSplitError("Sealed test artifact binding is invalid.")
        _verify_descriptor(root, role["artifact"], "test.jsonl", int(role["records"]))
        parent_fd, directory_fd = _open_pinned_private_root(root)
        handle: BinaryIO | None = None
        try:
            handle = open_private_binary_input(root / "test.jsonl")
            digest = hashlib.sha256()
            byte_count = 0
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
                byte_count += len(chunk)
            artifact = role["artifact"]
            if artifact.get("sha256") != "sha256:" + digest.hexdigest() or artifact.get("bytes") != byte_count:
                raise EnronSplitError("Sealed test changed before final access could be claimed.")
            handle.seek(0)
            self._expected_records = int(role["records"])
            self._expected_sha256 = str(artifact["sha256"])
            self._expected_bytes = int(artifact["bytes"])
            self._handle = handle
            self._parent_fd = parent_fd
            self._directory_fd = directory_fd
            self._target = target
            self._benchmark_version = str(manifest["benchmark_version"])
            self._accessed_at = _utc_now()
            claim_core = {
                "schema_version": FINAL_TEST_ACCESS_SCHEMA_VERSION,
                "benchmark_version": self._benchmark_version,
                "accessed_at": self._accessed_at,
                "frozen_target": target,
            }
            self._claim_sha256 = _hash_bytes(_canonical_json(claim_core).encode("utf-8"))
            claim = {**claim_core, "claim_sha256": self._claim_sha256}
            _write_exclusive_private_json_at(root, parent_fd, directory_fd, "ACCESS_CLAIMED.json", claim)
        except BaseException:
            if handle is not None:
                handle.close()
            self._handle = None
            self._parent_fd = None
            self._directory_fd = None
            os.close(directory_fd)
            os.close(parent_fd)
            raise
        return self

    def iter_records(self) -> Iterator[dict[str, Any]]:
        if self._handle is None or not self._entered:
            raise EnronSplitError("Final-test access context is not active.")
        if self._iterated:
            raise EnronSplitError("Final-test records can be iterated only once.")
        self._iterated = True
        records = 0
        digest = hashlib.sha256()
        byte_count = 0
        previous: str | None = None
        while raw := self._handle.readline(DEFAULT_MAX_PREPARED_LINE_BYTES + 1):
            if len(raw) > DEFAULT_MAX_PREPARED_LINE_BYTES:
                raise EnronSplitError("Sealed test record exceeds its byte limit.")
            try:
                row = json.loads(
                    raw.decode("utf-8"),
                    parse_constant=lambda _value: (_ for _ in ()).throw(EnronSplitError("Non-finite JSON is invalid.")),
                    object_pairs_hook=_reject_duplicate_keys,
                )
            except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
                raise EnronSplitError("Sealed test record is invalid JSON.") from exc
            if not isinstance(row, dict) or raw != _canonical_line(row):
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
        ):
            raise EnronSplitError("Sealed test record count changed during final access.")
        self._exhausted = True

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None
        status = "completed" if exc is None and self._exhausted else "failed" if exc is not None else "aborted"
        outcome = {
            "schema_version": FINAL_TEST_ACCESS_SCHEMA_VERSION,
            "benchmark_version": self._benchmark_version,
            "accessed_at": self._accessed_at,
            "status": status,
            "frozen_target_sha256": _hash_bytes(_canonical_json(self._target).encode("utf-8")),
            "claim_sha256": self._claim_sha256,
        }
        parent_fd = self._parent_fd
        directory_fd = self._directory_fd
        if parent_fd is None or directory_fd is None:
            raise EnronSplitError("Final-test access directory is no longer pinned.")
        try:
            _write_exclusive_private_json_at(
                self._root,
                parent_fd,
                directory_fd,
                "ACCESS_OUTCOME.json",
                outcome,
            )
        except EnronSplitError:
            if exc is None:
                raise
        finally:
            os.close(directory_fd)
            os.close(parent_fd)
            self._directory_fd = None
            self._parent_fd = None


def begin_enron_final_test_access(
    sealed_path: Path,
    *,
    frozen_target: Mapping[str, str],
) -> EnronFinalTestAccess:
    """Return the one-shot steward context; no test byte is read before entering it."""

    return EnronFinalTestAccess(sealed_path, frozen_target)


def finalize_aborted_enron_final_test_access(sealed_path: Path) -> dict[str, Any]:
    """Record an aborted outcome for a valid crash-stranded claim without reopening test data."""

    root = _assert_committed_run(sealed_path, _SEALED_FILES, allow_access_files=True)
    manifest = _read_json_object(root / "manifest.json")
    manifest_sha256 = _hash_file(root / "manifest.json")
    _verify_pair_receipt(root, manifest_sha256, str(manifest.get("benchmark_version")))
    access_state = _verify_access_state(root, manifest, manifest_sha256)
    if access_state.get("status") != "claimed":
        raise EnronSplitError("Final-test access does not have a valid claim awaiting an outcome.")
    claim = _read_json_object(root / "ACCESS_CLAIMED.json")
    frozen_target = claim["frozen_target"]
    outcome = {
        "schema_version": FINAL_TEST_ACCESS_SCHEMA_VERSION,
        "benchmark_version": claim["benchmark_version"],
        "accessed_at": claim["accessed_at"],
        "status": "aborted",
        "frozen_target_sha256": _hash_bytes(_canonical_json(frozen_target).encode("utf-8")),
        "claim_sha256": claim["claim_sha256"],
    }
    _write_exclusive_private_json(root, "ACCESS_OUTCOME.json", outcome)
    result = _verify_access_state(root, manifest, manifest_sha256)
    _validate_aggregate_privacy(result)
    return result

"""Privacy-safe, streaming quality aggregation for the Enron benchmark.

The only execution path is a prepare/consume/finish session.  It compiles one
bank, holds at most one document's predictions and interval state, and writes
only text-free commitment metadata to a private SQLite spool.  Raw documents
and native predictions are never retained by the session.
"""

from __future__ import annotations

import errno
import heapq
import json
import os
import re
import secrets
import sqlite3
import stat
import tempfile
import threading
from collections import defaultdict
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from hashlib import sha256, sha512
from pathlib import Path
from typing import Any, NoReturn

from . import enron_contract
from .bank import hash_bank
from .engine import DEFAULT_MAX_SCAN_INPUT_BYTES
from .engines import compile_bank, extraction_semantics_sha256
from .enron_contract import CHARACTER_POSITION_SEMANTICS, MATCHING_SEMANTICS, validate_enron_quality_output
from .enron_private_io import (
    EnronPrivateIOError,
    PrivateRun,
    _wipe_and_quarantine_pinned_private_file,
    iter_strict_jsonl,
    open_private_directory_input,
)

__all__ = [
    "EnronQualitySession",
    "EnronQualityError",
    "evaluate_cmu_enron_training_quality",
    "evaluate_cmu_enron_training_quality_files",
    "evaluate_enron_quality",
    "evaluate_enron_quality_files",
    "prepare_enron_quality",
]

QUALITY_EXECUTION_SCHEMA_VERSION = "nerb.enron_quality_execution.v2"
EVALUATOR_ID = "nerb-enron-quality"
EVALUATOR_VERSION = "2.0.0"
DEFAULT_MAX_QUALITY_LINE_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_QUALITY_INPUT_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_QUALITY_RECORDS = 2_000_000
DEFAULT_MAX_QUALITY_PREDICTIONS_PER_DOCUMENT = 100_000
DEFAULT_MAX_QUALITY_PREDICTIONS_TOTAL = 5_000_000
DEFAULT_MAX_QUALITY_GOLD_PER_DOCUMENT = 100_000
DEFAULT_MAX_QUALITY_GOLD_TOTAL = 2_000_000
DEFAULT_MAX_QUALITY_DOCUMENTS = 2_000_000
DEFAULT_MAX_QUALITY_MEMBERSHIPS_TOTAL = 5_000_000
DEFAULT_MAX_QUALITY_SLICES = 256
DEFAULT_MAX_QUALITY_DIAGNOSTICS = 100
DEFAULT_MAX_QUALITY_SPOOL_BYTES = 2 * 1024**3
_METADATA_COMMITMENT_MODULUS = 1 << 512
_QUALITY_ACTIVITY_INTERVAL = 10_000

_DOCUMENT_FIELDS = frozenset({"document_id", "text", "text_view", "split_role"})
_GOLD_FIELDS = frozenset({"document_id", "entity_class", "start", "end", "catalog_identity"})
_CATALOG_IDENTITY_FIELDS = frozenset({"entity_id", "name_id", "pattern_id"})
_ANNOTATION_SCOPE_FIELDS = frozenset({"entity_classes", "document_regions", "span_policy_sha256", "exclusions"})
_UNSUPPORTED_SLICE_FIELDS = frozenset({"id", "dimension", "reason_code"})
_TEXT_VIEW_DESCRIPTOR_FIELDS = frozenset(
    {
        "id",
        "artifact_sha256",
        "content_policy_sha256",
        "document_regions",
        "primary_for_quality",
        "answer_bearing_fields_included",
    }
)
_CMU_CATALOG_BINDING_FIELDS = frozenset({"document_id", "start", "end", "catalog_identity"})
_SLICE_FIELDS = frozenset(
    {
        "id",
        "label_artifact_id",
        "label_strength",
        "annotation_scope",
        "annotation_completeness",
        "entity_class",
        "cohort",
        "split_role",
        "text_view",
        "text_view_descriptor",
        "promotion_gate",
    }
)
_STREAM_RECORD_FIELDS = frozenset({"document", "gold_spans", "slice_ids"})
_SPLIT_ROLES = frozenset({"train", "validation", "test"})
_LABEL_STRENGTHS = frozenset({"independent", "structured_weak"})
_ANNOTATION_COMPLETENESS = frozenset({"exhaustive_within_scope", "partial"})
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_PUBLIC_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")

_LABEL_SCHEMA_DESCRIPTOR = {
    "documents": sorted(_DOCUMENT_FIELDS),
    "gold_spans": sorted(_GOLD_FIELDS),
    "catalog_identity": sorted(_CATALOG_IDENTITY_FIELDS),
    "slice_specs": sorted(_SLICE_FIELDS),
    "stream_records": sorted(_STREAM_RECORD_FIELDS),
    "slice_membership": "per_document_declared_slice_ids",
    "position_semantics": CHARACTER_POSITION_SEMANTICS,
}
_POLICY_DESCRIPTOR = {
    "version": "nerb.enron-quality-policy.v2",
    "matching": MATCHING_SEMANTICS,
    "native_offsets": "utf8_byte",
    "quality_offsets": CHARACTER_POSITION_SEMANTICS,
    "catalog_eligibility": "explicit_frozen_gold_active_entity_name_and_pattern_qualification_or_null",
    "catalog_inventory": "active_bank_names_with_active_patterns",
    "prediction_class": "bank_entity_id",
    "canonical_identity": "entity_id_and_name_id",
    "character_sets": "document_disjoint_interval_unions",
    "partial_and_weak_policy": "labeled_span_and_catalog_diagnostics_only",
    "empty_policy": "fail_closed",
    "prediction_limits": {
        "per_document": DEFAULT_MAX_QUALITY_PREDICTIONS_PER_DOCUMENT,
        "total": DEFAULT_MAX_QUALITY_PREDICTIONS_TOTAL,
    },
}


def _execution_policy_descriptor(
    *,
    max_predictions_per_document: int,
    max_predictions_total: int,
    max_gold_per_document: int,
    max_diagnostics: int,
    max_memberships_total: int,
    max_spool_bytes: int,
) -> dict[str, Any]:
    return {
        **_POLICY_DESCRIPTOR,
        "prediction_limits": {
            "per_document": max_predictions_per_document,
            "total": max_predictions_total,
        },
        "streaming_limits": {
            "document_utf8_bytes": DEFAULT_MAX_SCAN_INPUT_BYTES,
            "documents_total": DEFAULT_MAX_QUALITY_DOCUMENTS,
            "gold_spans_per_document": max_gold_per_document,
            "gold_spans_total": DEFAULT_MAX_QUALITY_GOLD_TOTAL,
            "memberships_total": max_memberships_total,
            "metadata_spool_bytes": max_spool_bytes,
            "diagnostic_sample": max_diagnostics,
        },
        "metadata_commitment": "domain_separated_sha512_additive_multiset",
    }


class EnronQualityError(ValueError):
    """Raised when quality inputs cannot be evaluated without ambiguity."""


class _EnronQualityCleanupError(EnronQualityError):
    """Raised when a private quality spool cannot prove cleanup completed."""


@dataclass(frozen=True, slots=True)
class _Document:
    document_id: str
    text: str
    text_view: str
    split_role: str


@dataclass(frozen=True, slots=True)
class _GoldSpan:
    document_id: str
    entity_class: str
    start: int
    end: int
    catalog_identity: tuple[str, str, str] | None

    @property
    def key(self) -> tuple[str, str, int, int]:
        return (self.document_id, self.entity_class, self.start, self.end)


@dataclass(frozen=True, slots=True)
class _Prediction:
    document_id: str
    entity_class: str
    start: int
    end: int
    entity_id: str
    name_id: str
    pattern_id: str

    @property
    def key(self) -> tuple[str, str, int, int]:
        return (self.document_id, self.entity_class, self.start, self.end)

    @property
    def identity(self) -> tuple[str, str]:
        return (self.entity_id, self.name_id)


@dataclass(frozen=True, slots=True)
class _SliceSpec:
    id: str
    label_artifact_id: str
    label_strength: str
    annotation_entity_classes: tuple[str, ...]
    annotation_document_regions: tuple[str, ...]
    annotation_span_policy_sha256: str
    annotation_exclusions: tuple[str, ...]
    annotation_completeness: str
    entity_class: str
    cohort: str
    split_role: str
    text_view: str
    text_view_artifact_sha256: str
    text_view_content_policy_sha256: str
    text_view_document_regions: tuple[str, ...]
    text_view_primary_for_quality: bool
    text_view_answer_bearing_fields_included: bool
    promotion_gate: bool

    @property
    def open_world_eligible(self) -> bool:
        return (
            self.label_strength == "independent"
            and self.annotation_completeness == "exhaustive_within_scope"
            and set(self.annotation_document_regions) == set(self.text_view_document_regions)
        )

    def fingerprint_payload(self, document_ids: Sequence[str]) -> dict[str, Any]:
        return {
            "id": self.id,
            "label_artifact_id": self.label_artifact_id,
            "label_strength": self.label_strength,
            "annotation_scope": self.annotation_scope,
            "annotation_completeness": self.annotation_completeness,
            "entity_class": self.entity_class,
            "cohort": self.cohort,
            "split_role": self.split_role,
            "text_view": self.text_view,
            "text_view_descriptor": self.text_view_descriptor,
            "promotion_gate": self.promotion_gate,
            "document_ids": list(document_ids),
        }

    @property
    def annotation_scope(self) -> dict[str, Any]:
        return {
            "entity_classes": list(self.annotation_entity_classes),
            "document_regions": list(self.annotation_document_regions),
            "span_policy_sha256": self.annotation_span_policy_sha256,
            "exclusions": list(self.annotation_exclusions),
        }

    @property
    def text_view_descriptor(self) -> dict[str, Any]:
        return {
            "id": self.text_view,
            "artifact_sha256": self.text_view_artifact_sha256,
            "content_policy_sha256": self.text_view_content_policy_sha256,
            "document_regions": list(self.text_view_document_regions),
            "primary_for_quality": self.text_view_primary_for_quality,
            "answer_bearing_fields_included": self.text_view_answer_bearing_fields_included,
        }


@dataclass(slots=True)
class _SliceAccumulator:
    documents: int = 0
    documents_with_sensitive_gold: int = 0
    documents_with_any_miss: int = 0
    documents_with_cataloged_gold: int = 0
    documents_with_any_cataloged_miss: int = 0
    documents_with_any_leaked_character: int = 0
    gold_spans: int = 0
    predicted_spans: int = 0
    true_positive: int = 0
    false_positive: int = 0
    false_negative: int = 0
    cataloged_gold_spans: int = 0
    cataloged_true_positive: int = 0
    cataloged_false_negative: int = 0
    cataloged_wrong_canonical: int = 0
    sensitive_gold_characters: int = 0
    covered_sensitive_characters: int = 0
    leaked_sensitive_characters: int = 0
    predicted_characters: int = 0
    over_redacted_characters: int = 0
    evaluated_characters: int = 0
    negative_documents: int = 0
    negative_documents_with_predictions: int = 0


@dataclass(frozen=True, slots=True)
class _SpoolIdentity:
    device: int
    inode: int
    mode: int
    links: int


@dataclass(slots=True)
class _SpoolCleanup:
    file_fd: int
    parent_fd: int
    parent_path: Path
    owned_run: PrivateRun | None


@dataclass(slots=True)
class _PendingSpoolCleanup:
    connection: sqlite3.Connection
    spool_cleanup: _SpoolCleanup
    spool_path: Path
    spool_identity: _SpoolIdentity
    writer_closed: bool = False
    settled: bool = False


_PENDING_SPOOL_CLEANUP_LOCK = threading.RLock()
_PENDING_SPOOL_CLEANUPS: dict[tuple[int, int], _PendingSpoolCleanup] = {}


def _remember_control_error(
    current: KeyboardInterrupt | SystemExit | None,
    candidate: KeyboardInterrupt | SystemExit,
) -> KeyboardInterrupt | SystemExit:
    return candidate if current is None else current


def _close_metadata_connection(
    connection: sqlite3.Connection,
    *,
    deferred_control: KeyboardInterrupt | SystemExit | None = None,
) -> tuple[bool, KeyboardInterrupt | SystemExit | None]:
    """Close a spool writer before cleanup, deferring control interruptions."""

    while True:
        try:
            connection.close()
        except (KeyboardInterrupt, SystemExit) as exc:
            deferred_control = _remember_control_error(deferred_control, exc)
            continue
        except sqlite3.Error:
            # ProgrammingError includes live, thread-affine connections used
            # from the wrong thread.  No sqlite exception proves quiescence.
            return False, deferred_control
        else:
            return True, deferred_control


def _authenticated_spool_payload_is_zero(pending: _PendingSpoolCleanup) -> bool:
    expected_identity = (pending.spool_identity.device, pending.spool_identity.inode)
    before = os.fstat(pending.spool_cleanup.file_fd)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.geteuid()
        or (before.st_dev, before.st_ino) != expected_identity
        or before.st_size != 0
    ):
        return False
    os.fsync(pending.spool_cleanup.file_fd)
    after = os.fstat(pending.spool_cleanup.file_fd)
    return (
        stat.S_ISREG(after.st_mode)
        and after.st_uid == os.geteuid()
        and (after.st_dev, after.st_ino) == expected_identity
        and after.st_size == 0
    )


def _settle_metadata_spool(
    pending: _PendingSpoolCleanup,
    *,
    deferred_control: KeyboardInterrupt | SystemExit | None = None,
) -> tuple[str, bool, KeyboardInterrupt | SystemExit | None]:
    """Quiesce the SQLite writer, wipe its file, and release cleanup ownership."""

    if pending.settled:
        return "settled", False, deferred_control
    if not pending.writer_closed:
        connection_closed, deferred_control = _close_metadata_connection(
            pending.connection,
            deferred_control=deferred_control,
        )
        if not connection_closed:
            return "writer_live", False, deferred_control
        pending.writer_closed = True

    cleanup_failed = False
    wipe_control_observed = False
    while True:
        try:
            _wipe_and_quarantine_pinned_private_file(
                pending.spool_cleanup.file_fd,
                pending.spool_cleanup.parent_fd,
                pending.spool_cleanup.parent_path,
                pending.spool_path.name,
                (pending.spool_identity.device, pending.spool_identity.inode),
                workspace_root=None,
                allow_unignored_output=True,
            )
        except (KeyboardInterrupt, SystemExit) as exc:
            deferred_control = _remember_control_error(deferred_control, exc)
            wipe_control_observed = True
            continue
        except (EnronPrivateIOError, EnronQualityError, OSError):
            if wipe_control_observed:
                while True:
                    try:
                        if _authenticated_spool_payload_is_zero(pending):
                            break
                    except (KeyboardInterrupt, SystemExit) as exc:
                        deferred_control = _remember_control_error(deferred_control, exc)
                        continue
                    except OSError:
                        pass
                    return "wipe_pending", False, deferred_control
                break
            return "wipe_pending", False, deferred_control
        break

    for descriptor in (pending.spool_cleanup.file_fd, pending.spool_cleanup.parent_fd):
        while True:
            try:
                os.close(descriptor)
            except (KeyboardInterrupt, SystemExit) as exc:
                deferred_control = _remember_control_error(deferred_control, exc)
                continue
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    cleanup_failed = True
            break
    if pending.spool_cleanup.owned_run is not None:
        while True:
            try:
                pending.spool_cleanup.owned_run.__exit__(None, None, None)
            except (KeyboardInterrupt, SystemExit) as exc:
                deferred_control = _remember_control_error(deferred_control, exc)
                continue
            except EnronPrivateIOError as exc:
                cleanup_failed = True
                cause = exc.__cause__
                if isinstance(cause, (KeyboardInterrupt, SystemExit)):
                    deferred_control = _remember_control_error(deferred_control, cause)
            break
    pending.settled = True
    return "settled", cleanup_failed, deferred_control


def _publish_pending_spool_cleanup_once(pending: _PendingSpoolCleanup) -> None:
    identity = (pending.spool_identity.device, pending.spool_identity.inode)
    with _PENDING_SPOOL_CLEANUP_LOCK:
        existing = _PENDING_SPOOL_CLEANUPS.get(identity)
        if existing is not None and existing is not pending:
            raise _EnronQualityCleanupError("Quality metadata spool cleanup ownership is not unique.")
        _PENDING_SPOOL_CLEANUPS[identity] = pending


def _publish_pending_spool_cleanup(
    pending: _PendingSpoolCleanup,
    *,
    deferred_control: KeyboardInterrupt | SystemExit | None = None,
) -> KeyboardInterrupt | SystemExit | None:
    while True:
        try:
            _publish_pending_spool_cleanup_once(pending)
        except (KeyboardInterrupt, SystemExit) as exc:
            deferred_control = _remember_control_error(deferred_control, exc)
            continue
        return deferred_control


def _remove_pending_spool_cleanup(pending: _PendingSpoolCleanup) -> None:
    identity = (pending.spool_identity.device, pending.spool_identity.inode)
    with _PENDING_SPOOL_CLEANUP_LOCK:
        if _PENDING_SPOOL_CLEANUPS.get(identity) is pending:
            _PENDING_SPOOL_CLEANUPS.pop(identity, None)


def _settle_or_publish_pending_spool_cleanup(
    pending: _PendingSpoolCleanup,
    *,
    deferred_control: KeyboardInterrupt | SystemExit | None = None,
) -> tuple[str, bool, KeyboardInterrupt | SystemExit | None]:
    with _PENDING_SPOOL_CLEANUP_LOCK:
        status, cleanup_failed, deferred_control = _settle_metadata_spool(
            pending,
            deferred_control=deferred_control,
        )
        if status == "settled":
            _remove_pending_spool_cleanup(pending)
        else:
            deferred_control = _publish_pending_spool_cleanup(
                pending,
                deferred_control=deferred_control,
            )
        return status, cleanup_failed, deferred_control


def _settle_or_publish_pending_spool_cleanup_to_completion(
    pending: _PendingSpoolCleanup,
    *,
    deferred_control: KeyboardInterrupt | SystemExit | None = None,
) -> tuple[str, bool, KeyboardInterrupt | SystemExit | None]:
    result: tuple[str, bool, KeyboardInterrupt | SystemExit | None] | None = None
    with _PENDING_SPOOL_CLEANUP_LOCK:
        try:
            try:
                result = _settle_or_publish_pending_spool_cleanup(
                    pending,
                    deferred_control=deferred_control,
                )
            except (KeyboardInterrupt, SystemExit) as exc:
                deferred_control = _remember_control_error(deferred_control, exc)
        finally:
            while result is None and not pending.settled:
                try:
                    deferred_control = _publish_pending_spool_cleanup(
                        pending,
                        deferred_control=deferred_control,
                    )
                except (KeyboardInterrupt, SystemExit) as exc:
                    deferred_control = _remember_control_error(deferred_control, exc)
                    continue
                break
    if result is not None:
        return result
    status = "settled" if pending.settled else ("wipe_pending" if pending.writer_closed else "writer_live")
    return status, False, deferred_control


def _retry_pending_spool_cleanups() -> None:
    with _PENDING_SPOOL_CLEANUP_LOCK:
        for identity, pending in tuple(_PENDING_SPOOL_CLEANUPS.items()):
            status, cleanup_failed, deferred_control = _settle_metadata_spool(pending)
            if status == "writer_live":
                raise _EnronQualityCleanupError("A prior quality metadata spool writer is still live.")
            if status == "wipe_pending":
                raise _EnronQualityCleanupError("A prior quality metadata spool still contains private bytes.")
            _PENDING_SPOOL_CLEANUPS.pop(identity, None)
            if cleanup_failed:
                raise _EnronQualityCleanupError("A prior quality metadata spool could not be cleaned safely.")
            if deferred_control is not None:
                raise deferred_control


@dataclass(slots=True)
class _DiagnosticReservoir:
    capacity: int
    total_events: int = 0
    _items: list[tuple[int, str, str, str]] = field(default_factory=list)

    def add(self, document_id: str, slice_id: str, reason_code: str) -> None:
        self.total_events += 1
        opaque_id = _hash_bytes(
            ("nerb/enron/quality-diagnostic\0" + document_id + "\0" + slice_id + "\0" + reason_code).encode("utf-8")
        )
        rank = int(opaque_id.removeprefix("sha256:"), 16)
        candidate = (-rank, opaque_id, slice_id, reason_code)
        if len(self._items) < self.capacity:
            heapq.heappush(self._items, candidate)
        elif self.capacity and candidate > self._items[0]:
            heapq.heapreplace(self._items, candidate)

    def values(self) -> tuple[dict[str, str], ...]:
        return tuple(
            {"id": opaque_id, "slice_id": slice_id, "reason_code": reason_code}
            for _negative_rank, opaque_id, slice_id, reason_code in sorted(
                self._items,
                key=lambda item: (-item[0], item[1], item[2], item[3]),
            )
        )


class EnronQualitySession:
    """One compiled-bank, aggregate-only streaming quality execution."""

    __slots__ = (
        "_accumulators",
        "_active_patterns",
        "_activity_callback",
        "_canonical_bank_sha256",
        "_compiled",
        "_connection",
        "_declared_unsupported",
        "_diagnostics",
        "_engine_bank_sha256",
        "_evaluator",
        "_gold_count",
        "_max_gold_per_document",
        "_max_memberships_total",
        "_max_predictions_per_document",
        "_max_predictions_total",
        "_max_spool_bytes",
        "_membership_count",
        "_metadata_accumulator",
        "_metadata_items",
        "_pending_cleanup",
        "_pending_terminal_state",
        "_spool_cleanup",
        "_policy_sha256",
        "_prediction_count",
        "_result",
        "_spec_by_id",
        "_specs",
        "_spool_identity",
        "_spool_path",
        "_state",
        "_stream_records",
    )

    def __init__(
        self,
        *,
        compiled: Any,
        specs: tuple[_SliceSpec, ...],
        declared_unsupported: tuple[dict[str, str], ...],
        spool_path: Path,
        spool_identity: _SpoolIdentity,
        connection: sqlite3.Connection,
        spool_cleanup: _SpoolCleanup,
        pending_cleanup: _PendingSpoolCleanup,
        max_predictions_per_document: int,
        max_predictions_total: int,
        max_gold_per_document: int,
        max_diagnostics: int,
        max_memberships_total: int,
        max_spool_bytes: int,
        activity_callback: Callable[[], None] | None,
    ) -> None:
        self._compiled = compiled
        self._specs = specs
        self._spec_by_id = {spec.id: spec for spec in specs}
        self._declared_unsupported = declared_unsupported
        self._active_patterns = _active_pattern_inventory(compiled.extractable_bank)
        self._canonical_bank_sha256 = hash_bank(compiled.bank)
        self._engine_bank_sha256 = compiled.bank_hash
        self._evaluator = _evaluator_identity()
        self._policy_sha256 = _canonical_hash(
            _execution_policy_descriptor(
                max_predictions_per_document=max_predictions_per_document,
                max_predictions_total=max_predictions_total,
                max_gold_per_document=max_gold_per_document,
                max_diagnostics=max_diagnostics,
                max_memberships_total=max_memberships_total,
                max_spool_bytes=max_spool_bytes,
            )
        )
        self._spool_path = spool_path
        self._spool_identity = spool_identity
        self._connection = connection
        self._spool_cleanup = spool_cleanup
        self._pending_cleanup = pending_cleanup
        self._max_predictions_per_document = max_predictions_per_document
        self._max_predictions_total = max_predictions_total
        self._max_gold_per_document = max_gold_per_document
        self._max_memberships_total = max_memberships_total
        self._max_spool_bytes = max_spool_bytes
        self._activity_callback = activity_callback
        self._diagnostics = _DiagnosticReservoir(max_diagnostics)
        self._accumulators = {spec.id: _SliceAccumulator() for spec in specs}
        self._prediction_count = 0
        self._gold_count = 0
        self._membership_count = 0
        self._metadata_accumulator = 0
        self._metadata_items = 0
        self._stream_records = 0
        self._result: dict[str, Any] | None = None
        self._pending_terminal_state: str | None = None
        self._state = "active"

    def __enter__(self) -> EnronQualitySession:
        self._require_active()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if self._state in {"active", "cleanup_pending"}:
            terminal_state = self._pending_terminal_state or "failed"
            cleanup_error = self._terminate(terminal_state)
            if cleanup_error is not None:
                if isinstance(exc, BaseException):
                    raise cleanup_error from exc
                raise cleanup_error from None

    def __del__(self) -> None:
        pending_cleanup = getattr(self, "_pending_cleanup", None)
        if pending_cleanup is None:
            return
        try:
            if getattr(self, "_state", None) in {"active", "cleanup_pending"}:
                try:
                    terminal_state = getattr(self, "_pending_terminal_state", None) or "failed"
                    self._terminate(terminal_state)
                except BaseException:
                    pass
        finally:
            while not pending_cleanup.settled:
                try:
                    with _PENDING_SPOOL_CLEANUP_LOCK:
                        if pending_cleanup.settled:
                            break
                        _publish_pending_spool_cleanup(pending_cleanup)
                except (KeyboardInterrupt, SystemExit):
                    continue
                self._state = "cleanup_parked"
                break

    @property
    def diagnostics(self) -> tuple[dict[str, str], ...]:
        """Return the bounded opaque diagnostic reservoir without private text."""

        return self._diagnostics.values()

    @property
    def retained_state(self) -> dict[str, int]:
        """Return aggregate-only state-size evidence for tests and capacity reports."""

        return {
            "slice_accumulators": len(self._accumulators),
            "retained_documents": 0,
            "retained_predictions": 0,
            "diagnostics": len(self._diagnostics._items),
            "diagnostic_capacity": self._diagnostics.capacity,
            "diagnostic_events": self._diagnostics.total_events,
            "consumed_documents": self._stream_records,
            "consumed_gold_spans": self._gold_count,
            "consumed_memberships": self._membership_count,
        }

    def consume(
        self,
        document: Mapping[str, Any],
        gold_spans: Iterable[Mapping[str, Any]],
        slice_ids: Sequence[str],
    ) -> None:
        """Consume one document and its complete gold/membership envelope."""

        self._require_active()
        try:
            if self._stream_records >= DEFAULT_MAX_QUALITY_DOCUMENTS:
                raise EnronQualityError("Quality document stream exceeds the cumulative record limit.")
            prepared_document = _prepare_stream_document(document)
            prepared_gold = _prepare_stream_gold(
                gold_spans,
                prepared_document,
                max_items=self._max_gold_per_document,
            )
            if self._gold_count + len(prepared_gold) > DEFAULT_MAX_QUALITY_GOLD_TOTAL:
                raise EnronQualityError("Quality gold spans exceed the cumulative record limit.")
            prepared_slice_ids = _prepare_stream_slice_ids(slice_ids, self._spec_by_id)
            if self._membership_count + len(prepared_slice_ids) > self._max_memberships_total:
                raise EnronQualityError("Quality slice memberships exceed the cumulative record limit.")
            assigned_specs = tuple(self._spec_by_id[slice_id] for slice_id in prepared_slice_ids)
            _validate_stream_coverage(prepared_document, prepared_gold, assigned_specs, self._specs)
            _validate_catalog_identities(prepared_gold, self._active_patterns)
            self._record_commitment_metadata(prepared_document, prepared_gold, prepared_slice_ids)
            predictions = _scan_document(
                self._compiled,
                prepared_document,
                max_predictions=self._max_predictions_per_document,
            )
            self._prediction_count += len(predictions)
            if self._prediction_count > self._max_predictions_total:
                raise EnronQualityError("Quality scan exceeded the cumulative prediction limit.")
            for spec in assigned_specs:
                reasons = _accumulate_slice_document(
                    self._accumulators[spec.id],
                    spec,
                    prepared_document,
                    prepared_gold,
                    predictions,
                )
                for reason in reasons:
                    self._diagnostics.add(prepared_document.document_id, spec.id, reason)
            self._stream_records += 1
            self._gold_count += len(prepared_gold)
            self._membership_count += len(prepared_slice_ids)
            if self._stream_records % 1_024 == 0:
                self._connection.commit()
                self._assert_spool_current()
        except BaseException as exc:
            if self._state != "active":
                raise exc
            self._fail(exc)

    def finish(self) -> dict[str, Any]:
        """Finalize commitments and aggregate metrics exactly once."""

        self._require_active()
        try:
            activity = _QualityActivityReporter(self._activity_callback)
            activity.boundary()
            self._connection.commit()
            self._assert_spool_current()
            self._verify_metadata_commitment(activity.worked)
            activity.boundary()
            protocol_sha256 = _streaming_protocol_hash(
                self._connection,
                self._evaluator,
                self._policy_sha256,
                self._specs,
                self._declared_unsupported,
                activity_callback=activity.worked,
            )
            activity.boundary()
            catalog_binding_sha256 = _streaming_catalog_binding_hash(
                self._connection,
                self._canonical_bank_sha256,
                activity_callback=activity.worked,
            )
            activity.boundary()
            evaluated_slices: list[dict[str, Any]] = []
            unsupported_slices: list[dict[str, str]] = list(self._declared_unsupported)
            for spec in self._specs:
                activity.worked()
                accumulator = self._accumulators[spec.id]
                reason = _streaming_unsupported_reason(spec, accumulator)
                if reason is not None:
                    unsupported_slices.append({"id": spec.id, "dimension": "population", "reason_code": reason})
                else:
                    evaluated_slices.append(_finish_slice(spec, accumulator))
            activity.boundary()
            quality = {
                "evaluated": bool(evaluated_slices),
                "matching_semantics": MATCHING_SEMANTICS,
                "character_position_semantics": CHARACTER_POSITION_SEMANTICS,
                "slices": evaluated_slices,
            }
            raw_contract_validation = validate_enron_quality_output(quality)
            contract_validation = {
                "valid": raw_contract_validation["valid"],
                "diagnostic_codes": sorted({str(item["code"]) for item in raw_contract_validation["diagnostics"]}),
            }
            if any(spec.promotion_gate for spec in self._specs) and contract_validation["valid"] is not True:
                raise EnronQualityError("Promotion-gated quality output failed standalone contract validation.")
            run_sha256 = _canonical_hash(
                {
                    "protocol_sha256": protocol_sha256,
                    "catalog_binding_sha256": catalog_binding_sha256,
                    "canonical_bank_sha256": self._canonical_bank_sha256,
                    "engine_bank_sha256": self._engine_bank_sha256,
                    "quality": quality,
                    "contract_validation": contract_validation,
                    "unsupported_slices": unsupported_slices,
                }
            )
            result = {
                "schema_version": QUALITY_EXECUTION_SCHEMA_VERSION,
                "evaluator": self._evaluator,
                "evaluator_sha256": _canonical_hash(self._evaluator),
                "policy_sha256": self._policy_sha256,
                "protocol_sha256": protocol_sha256,
                "catalog_binding_sha256": catalog_binding_sha256,
                "run_sha256": run_sha256,
                "bank": {
                    "canonical_sha256": self._canonical_bank_sha256,
                    "engine_sha256": self._engine_bank_sha256,
                },
                "evaluated": bool(evaluated_slices),
                "quality": quality,
                "contract_validation": contract_validation,
                "unsupported_slices": unsupported_slices,
            }
            self._result = result
            cleanup_error = self._terminate("finished")
            if cleanup_error is not None:
                raise cleanup_error
            return result
        except BaseException as exc:
            if self._state != "active":
                raise exc
            self._fail(exc)

    def _record_commitment_metadata(
        self,
        document: _Document,
        gold_spans: Sequence[_GoldSpan],
        slice_ids: Sequence[str],
    ) -> None:
        document_metadata = {
            "document_id": document.document_id,
            "text_sha256": _hash_bytes(document.text.encode("utf-8")),
            "unicode_scalars": len(document.text),
            "text_view": document.text_view,
            "split_role": document.split_role,
        }
        try:
            self._connection.execute(
                "INSERT INTO documents VALUES (?, ?, ?, ?, ?)",
                (
                    document_metadata["document_id"],
                    document_metadata["text_sha256"],
                    document_metadata["unicode_scalars"],
                    document_metadata["text_view"],
                    document_metadata["split_role"],
                ),
            )
        except sqlite3.IntegrityError:
            raise EnronQualityError("Document identifiers must be unique.") from None
        self._add_metadata_commitment("document", document_metadata)
        for item in gold_spans:
            identity = item.catalog_identity
            gold_metadata = {
                "document_id": item.document_id,
                "entity_class": item.entity_class,
                "start": item.start,
                "end": item.end,
                "catalog_entity_id": None if identity is None else identity[0],
                "catalog_name_id": None if identity is None else identity[1],
                "catalog_pattern_id": None if identity is None else identity[2],
            }
            try:
                self._connection.execute(
                    "INSERT INTO gold VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        gold_metadata["document_id"],
                        gold_metadata["entity_class"],
                        gold_metadata["start"],
                        gold_metadata["end"],
                        gold_metadata["catalog_entity_id"],
                        gold_metadata["catalog_name_id"],
                        gold_metadata["catalog_pattern_id"],
                    ),
                )
            except sqlite3.IntegrityError:
                raise EnronQualityError("Gold exact-span/class keys must be unique.") from None
            self._add_metadata_commitment("gold", gold_metadata)
        self._connection.executemany(
            "INSERT INTO memberships VALUES (?, ?)",
            ((slice_id, document.document_id) for slice_id in slice_ids),
        )
        for slice_id in slice_ids:
            self._add_metadata_commitment(
                "membership",
                {"slice_id": slice_id, "document_id": document.document_id},
            )

    def _add_metadata_commitment(self, kind: str, value: Mapping[str, Any]) -> None:
        self._metadata_accumulator = (
            self._metadata_accumulator + _metadata_commitment_item(kind, value)
        ) % _METADATA_COMMITMENT_MODULUS
        self._metadata_items += 1

    def _verify_metadata_commitment(self, activity_callback: Callable[[], None] | None = None) -> None:
        accumulator, items = _spool_metadata_commitment(
            self._connection,
            activity_callback=activity_callback,
        )
        if accumulator != self._metadata_accumulator or items != self._metadata_items:
            raise EnronQualityError("Quality metadata spool content changed during evaluation.")

    def _assert_spool_current(self) -> None:
        if _spool_identity(self._spool_path) != self._spool_identity:
            raise EnronQualityError("Quality metadata spool changed during evaluation.")
        if self._spool_path.stat().st_size > self._max_spool_bytes:
            raise EnronQualityError("Quality metadata spool exceeds its byte limit.")

    def _require_active(self) -> None:
        if self._state != "active":
            raise EnronQualityError("Quality session is not active.")

    def _fail(self, exc: BaseException) -> NoReturn:
        cleanup_error = self._terminate("failed")
        if cleanup_error is not None:
            raise cleanup_error from exc
        if isinstance(exc, (EnronQualityError, KeyboardInterrupt, SystemExit)):
            raise exc
        if isinstance(exc, Exception):
            raise EnronQualityError("Quality session failed safely.") from None
        raise exc

    def _terminate(self, state: str) -> EnronQualityError | None:
        with _PENDING_SPOOL_CLEANUP_LOCK:
            terminal_state = self._pending_terminal_state or state
            if not self._pending_cleanup.writer_closed:
                self._pending_cleanup.connection = self._connection
            status, cleanup_failed, deferred_control = _settle_metadata_spool(self._pending_cleanup)
            if status != "settled":
                deferred_control = _publish_pending_spool_cleanup(
                    self._pending_cleanup,
                    deferred_control=deferred_control,
                )
                self._pending_terminal_state = terminal_state
                self._state = "cleanup_pending"
                message = (
                    "Quality metadata spool writer could not be closed safely."
                    if status == "writer_live"
                    else "Quality metadata spool could not be cleaned safely."
                )
                close_error = EnronQualityError(message)
                if deferred_control is not None:
                    raise close_error from deferred_control
                return close_error

            _remove_pending_spool_cleanup(self._pending_cleanup)
            self._compiled = None
            self._pending_terminal_state = None
            self._state = terminal_state
            cleanup_error = (
                EnronQualityError("Quality metadata spool could not be cleaned safely.") if cleanup_failed else None
            )
            if deferred_control is not None:
                if cleanup_error is not None:
                    raise cleanup_error from deferred_control
                raise deferred_control
            return cleanup_error


def prepare_enron_quality(
    bank: Mapping[str, Any],
    *,
    slice_specs: Sequence[Mapping[str, Any]],
    unsupported_slice_specs: Sequence[Mapping[str, Any]] = (),
    spool_path: str | Path | None = None,
    max_predictions_per_document: int = DEFAULT_MAX_QUALITY_PREDICTIONS_PER_DOCUMENT,
    max_predictions_total: int = DEFAULT_MAX_QUALITY_PREDICTIONS_TOTAL,
    max_gold_per_document: int = DEFAULT_MAX_QUALITY_GOLD_PER_DOCUMENT,
    max_diagnostics: int = DEFAULT_MAX_QUALITY_DIAGNOSTICS,
    max_memberships_total: int = DEFAULT_MAX_QUALITY_MEMBERSHIPS_TOTAL,
    max_spool_bytes: int = DEFAULT_MAX_QUALITY_SPOOL_BYTES,
    activity_callback: Callable[[], None] | None = None,
) -> EnronQualitySession:
    """Prepare one streaming quality session and compile its bank exactly once."""

    _retry_pending_spool_cleanups()
    if activity_callback is not None and not callable(activity_callback):
        raise EnronQualityError("Quality activity callback must be callable when provided.")
    limits = {
        "per-document prediction": max_predictions_per_document,
        "cumulative prediction": max_predictions_total,
        "per-document gold": max_gold_per_document,
        "cumulative membership": max_memberships_total,
        "metadata spool byte": max_spool_bytes,
    }
    if any(type(value) is not int or value <= 0 for value in limits.values()):
        raise EnronQualityError("Quality session limits must be positive integers.")
    if (
        max_predictions_per_document > DEFAULT_MAX_QUALITY_PREDICTIONS_PER_DOCUMENT
        or max_predictions_total > DEFAULT_MAX_QUALITY_PREDICTIONS_TOTAL
        or max_gold_per_document > DEFAULT_MAX_QUALITY_GOLD_PER_DOCUMENT
        or max_memberships_total > DEFAULT_MAX_QUALITY_MEMBERSHIPS_TOTAL
        or max_spool_bytes > DEFAULT_MAX_QUALITY_SPOOL_BYTES
    ):
        raise EnronQualityError("Quality session limits cannot exceed the frozen execution envelope.")
    if max_spool_bytes < 64 * 1024:
        raise EnronQualityError("Quality metadata spool limit must be at least 64 KiB.")
    if type(max_diagnostics) is not int or not 0 <= max_diagnostics <= DEFAULT_MAX_QUALITY_DIAGNOSTICS:
        raise EnronQualityError("Quality diagnostic capacity must be between zero and 100.")
    specs = _prepare_slices(slice_specs)
    declared_unsupported = _prepare_declared_unsupported(unsupported_slice_specs, specs)
    try:
        compiled, _cache_hit = compile_bank(bank, options={"include_statuses": ["active"]})
    except Exception:
        raise EnronQualityError("Quality bank could not be compiled safely.") from None
    try:
        path, identity, connection, spool_cleanup = _open_metadata_spool(
            spool_path,
            max_spool_bytes=max_spool_bytes,
        )
    except _EnronQualityCleanupError:
        raise
    except (OSError, sqlite3.Error, ValueError, EnronQualityError):
        raise EnronQualityError("Quality metadata spool could not be created safely.") from None
    pending_cleanup = _PendingSpoolCleanup(connection, spool_cleanup, path, identity)
    try:
        return EnronQualitySession(
            compiled=compiled,
            specs=specs,
            declared_unsupported=declared_unsupported,
            spool_path=path,
            spool_identity=identity,
            connection=connection,
            spool_cleanup=spool_cleanup,
            pending_cleanup=pending_cleanup,
            max_predictions_per_document=max_predictions_per_document,
            max_predictions_total=max_predictions_total,
            max_gold_per_document=max_gold_per_document,
            max_diagnostics=max_diagnostics,
            max_memberships_total=max_memberships_total,
            max_spool_bytes=max_spool_bytes,
            activity_callback=activity_callback,
        )
    except BaseException as exc:
        initial_control = exc if isinstance(exc, (KeyboardInterrupt, SystemExit)) else None
        status, cleanup_failed, deferred_control = _settle_or_publish_pending_spool_cleanup_to_completion(
            pending_cleanup,
            deferred_control=initial_control,
        )
        if status != "settled":
            message = (
                "Quality metadata spool writer could not be closed safely."
                if status == "writer_live"
                else "Quality metadata spool could not be cleaned safely."
            )
            close_error = EnronQualityError(message)
            raise close_error from (deferred_control or exc)
        if cleanup_failed:
            cleanup_error = EnronQualityError("Quality metadata spool could not be cleaned safely.")
            raise cleanup_error from (deferred_control or exc)
        if deferred_control is not None:
            raise deferred_control
        if isinstance(exc, EnronQualityError):
            raise
        raise EnronQualityError("Quality session could not be prepared safely.") from None


def evaluate_enron_quality(
    bank: Mapping[str, Any],
    *,
    records: Iterable[Mapping[str, Any]],
    slice_specs: Sequence[Mapping[str, Any]],
    unsupported_slice_specs: Sequence[Mapping[str, Any]] = (),
    spool_path: str | Path | None = None,
    max_predictions_per_document: int = DEFAULT_MAX_QUALITY_PREDICTIONS_PER_DOCUMENT,
    max_predictions_total: int = DEFAULT_MAX_QUALITY_PREDICTIONS_TOTAL,
    max_gold_per_document: int = DEFAULT_MAX_QUALITY_GOLD_PER_DOCUMENT,
    max_diagnostics: int = DEFAULT_MAX_QUALITY_DIAGNOSTICS,
    max_memberships_total: int = DEFAULT_MAX_QUALITY_MEMBERSHIPS_TOTAL,
    max_spool_bytes: int = DEFAULT_MAX_QUALITY_SPOOL_BYTES,
    activity_callback: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Stream closed per-document envelopes through the sole session path."""

    if activity_callback is not None and not callable(activity_callback):
        raise EnronQualityError("Quality activity callback must be callable when provided.")
    _report_quality_activity(activity_callback)
    session = prepare_enron_quality(
        bank,
        slice_specs=slice_specs,
        unsupported_slice_specs=unsupported_slice_specs,
        spool_path=spool_path,
        max_predictions_per_document=max_predictions_per_document,
        max_predictions_total=max_predictions_total,
        max_gold_per_document=max_gold_per_document,
        max_diagnostics=max_diagnostics,
        max_memberships_total=max_memberships_total,
        max_spool_bytes=max_spool_bytes,
        activity_callback=activity_callback,
    )
    with session:
        try:
            for index, record in enumerate(records):
                _require_closed_mapping(record, _STREAM_RECORD_FIELDS, "quality stream record", index)
                session.consume(record["document"], record["gold_spans"], record["slice_ids"])
                if (index + 1) % 10_000 == 0:
                    _report_quality_activity(activity_callback)
            _report_quality_activity(activity_callback)
            result = session.finish()
            _report_quality_activity(activity_callback)
            return result
        except (EnronQualityError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise EnronQualityError("Quality input stream failed safely.") from None


def evaluate_enron_quality_files(
    bank: Mapping[str, Any],
    *,
    records_path: str | Path,
    slice_specs_path: str | Path,
    unsupported_slice_specs_path: str | Path | None = None,
    spool_path: str | Path | None = None,
    max_line_bytes: int = DEFAULT_MAX_QUALITY_LINE_BYTES,
    max_input_bytes: int = DEFAULT_MAX_QUALITY_INPUT_BYTES,
    max_records: int = DEFAULT_MAX_QUALITY_RECORDS,
    activity_callback: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Stream strict private JSONL envelopes through the same session path."""

    if any(type(value) is not int or value <= 0 for value in (max_line_bytes, max_input_bytes, max_records)):
        raise EnronQualityError("Quality JSONL limits must be positive integers.")
    budget = _JSONLBudget(max_input_bytes, max_records)
    try:
        slice_specs = _load_small_quality_plan(
            Path(slice_specs_path),
            budget=budget,
            max_line_bytes=max_line_bytes,
            max_items=DEFAULT_MAX_QUALITY_SLICES,
        )
        unsupported = (
            ()
            if unsupported_slice_specs_path is None
            else _load_small_quality_plan(
                Path(unsupported_slice_specs_path),
                budget=budget,
                max_line_bytes=max_line_bytes,
                max_items=DEFAULT_MAX_QUALITY_SLICES,
            )
        )
        records = _iter_quality_records(
            Path(records_path),
            budget=budget,
            max_line_bytes=max_line_bytes,
        )
        return evaluate_enron_quality(
            bank,
            records=records,
            slice_specs=slice_specs,
            unsupported_slice_specs=unsupported,
            spool_path=spool_path,
            activity_callback=activity_callback,
        )
    except EnronPrivateIOError:
        raise EnronQualityError("Quality JSONL input could not be read safely.") from None


def evaluate_cmu_enron_training_quality(
    bank: Mapping[str, Any],
    *,
    annotation_run_dir: str | Path,
    catalog_bindings: Sequence[Mapping[str, Any]],
    spool_path: str | Path | None = None,
    max_spool_bytes: int = DEFAULT_MAX_QUALITY_SPOOL_BYTES,
    activity_callback: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Evaluate the verifier-bound CMU training population with explicit catalog adjudication."""

    from .enron_annotations import load_cmu_enron_training_quality_source

    _report_quality_activity(activity_callback)
    source = load_cmu_enron_training_quality_source(Path(annotation_run_dir))
    _report_quality_activity(activity_callback)
    bindings = _prepare_cmu_catalog_bindings(catalog_bindings, source["labels"])
    slice_spec = {
        "id": "cmu_person_all_train",
        "label_artifact_id": source["label_artifact_id"],
        "label_strength": source["label_strength"],
        "annotation_scope": source["annotation_scope"],
        "annotation_completeness": source["annotation_completeness"],
        "entity_class": "person",
        "cohort": "all",
        "split_role": "train",
        "text_view": source["text_view_descriptor"]["id"],
        "text_view_descriptor": source["text_view_descriptor"],
        "promotion_gate": False,
    }
    slice_specs = [slice_spec]
    unsupported = [
        {
            "id": "cmu_identity_known_novel",
            "dimension": "known_novel",
            "reason_code": "canonical_identity_linkage_unavailable",
        },
        {
            "id": "cmu_identity_head_tail",
            "dimension": "head_tail",
            "reason_code": "train_identity_frequency_unavailable",
        },
        {
            "id": "cmu_alternate_text_view",
            "dimension": "text_view",
            "reason_code": "alternate_text_view_unavailable",
        },
    ]
    has_negative_documents = _cmu_has_negative_documents(source["documents"], source["labels"])
    if has_negative_documents:
        slice_specs.append(
            {
                **slice_spec,
                "id": "cmu_person_negative_train",
                "cohort": "negative",
            }
        )
    else:
        unsupported.append(
            {
                "id": "cmu_person_negative_train",
                "dimension": "negative",
                "reason_code": "zero_negative_documents",
            }
        )
    result = evaluate_enron_quality(
        bank,
        records=_iter_cmu_quality_records(
            source["documents"],
            source["labels"],
            bindings,
            include_negative_slice=has_negative_documents,
        ),
        slice_specs=slice_specs,
        unsupported_slice_specs=unsupported,
        spool_path=spool_path,
        max_spool_bytes=max_spool_bytes,
        activity_callback=activity_callback,
    )
    annotation_source = dict(source["public_binding"])
    annotation_binding_sha256 = _canonical_hash(annotation_source)
    quality_run_sha256 = result["run_sha256"]
    return {
        **result,
        "quality_run_sha256": quality_run_sha256,
        "annotation_source": annotation_source,
        "annotation_binding_sha256": annotation_binding_sha256,
        "run_sha256": _canonical_hash(
            {
                "schema_version": "nerb.enron-cmu-training-quality-run.v2",
                "quality_run_sha256": quality_run_sha256,
                "annotation_binding_sha256": annotation_binding_sha256,
            }
        ),
    }


def evaluate_cmu_enron_training_quality_files(
    bank: Mapping[str, Any],
    *,
    annotation_run_dir: str | Path,
    catalog_bindings_path: str | Path,
    spool_path: str | Path | None = None,
    max_line_bytes: int = DEFAULT_MAX_QUALITY_LINE_BYTES,
    max_input_bytes: int = DEFAULT_MAX_QUALITY_INPUT_BYTES,
    max_records: int = DEFAULT_MAX_QUALITY_RECORDS,
    max_spool_bytes: int = DEFAULT_MAX_QUALITY_SPOOL_BYTES,
    activity_callback: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Evaluate a verified CMU training bundle using strict private catalog-binding JSONL."""

    if any(type(value) is not int or value <= 0 for value in (max_line_bytes, max_input_bytes, max_records)):
        raise EnronQualityError("CMU catalog-binding JSONL limits must be positive integers.")
    try:
        budget = _JSONLBudget(max_input_bytes, max_records)
        bindings = _load_small_quality_plan(
            Path(catalog_bindings_path),
            budget=budget,
            max_line_bytes=max_line_bytes,
            max_items=max_records,
        )
    except EnronPrivateIOError:
        raise EnronQualityError("CMU catalog-binding JSONL could not be read safely.") from None
    return evaluate_cmu_enron_training_quality(
        bank,
        annotation_run_dir=annotation_run_dir,
        catalog_bindings=bindings,
        spool_path=spool_path,
        max_spool_bytes=max_spool_bytes,
        activity_callback=activity_callback,
    )


def _report_quality_activity(callback: Callable[[], None] | None) -> None:
    if callback is None:
        return
    try:
        callback()
    except Exception:
        raise EnronQualityError("Quality activity callback failed.") from None


@dataclass(slots=True)
class _QualityActivityReporter:
    callback: Callable[[], None] | None
    pending_work: int = 0

    def worked(self) -> None:
        self.pending_work += 1
        if self.pending_work == _QUALITY_ACTIVITY_INTERVAL:
            self.boundary()

    def boundary(self) -> None:
        _report_quality_activity(self.callback)
        self.pending_work = 0


def _prepare_cmu_catalog_bindings(
    values: Sequence[Mapping[str, Any]], labels: Sequence[Mapping[str, Any]]
) -> dict[tuple[str, int, int], Mapping[str, str] | None]:
    _require_sequence(values, "CMU catalog bindings")
    _require_item_limit(values, "CMU catalog bindings")
    expected = {(str(label["document_id"]), int(label["start"]), int(label["end"])) for label in labels}
    result: dict[tuple[str, int, int], Mapping[str, str] | None] = {}
    for index, value in enumerate(values):
        _require_closed_mapping(value, _CMU_CATALOG_BINDING_FIELDS, "CMU catalog binding", index)
        document_id = _required_id(value["document_id"], "CMU binding document_id", index)
        start = _nonnegative_integer(value["start"], "CMU binding start", index)
        end = _nonnegative_integer(value["end"], "CMU binding end", index)
        catalog_identity = _prepare_catalog_identity(value["catalog_identity"], "person", index)
        key = (document_id, start, end)
        if key in result or start >= end:
            raise EnronQualityError("CMU catalog bindings must contain unique valid spans.")
        result[key] = (
            None
            if catalog_identity is None
            else {
                "entity_id": catalog_identity[0],
                "name_id": catalog_identity[1],
                "pattern_id": catalog_identity[2],
            }
        )
    if set(result) != expected:
        raise EnronQualityError("CMU catalog bindings must exactly cover the verified annotation spans.")
    return result


def _cmu_has_negative_documents(documents: Sequence[Mapping[str, Any]], labels: Sequence[Mapping[str, Any]]) -> bool:
    label_ids = iter(str(label["document_id"]) for label in labels)
    current = next(label_ids, None)
    for document in documents:
        document_id = str(document["document_id"])
        while current is not None and current < document_id:
            current = next(label_ids, None)
        if current != document_id:
            return True
        while current == document_id:
            current = next(label_ids, None)
    return False


def _iter_cmu_quality_records(
    documents: Sequence[Mapping[str, Any]],
    labels: Sequence[Mapping[str, Any]],
    bindings: Mapping[tuple[str, int, int], Mapping[str, str] | None],
    *,
    include_negative_slice: bool,
) -> Iterator[dict[str, Any]]:
    label_iterator = iter(labels)
    current = next(label_iterator, None)
    for document in documents:
        document_id = str(document["document_id"])
        document_gold: list[dict[str, Any]] = []
        while current is not None and str(current["document_id"]) == document_id:
            start = int(current["start"])
            end = int(current["end"])
            document_gold.append(
                {
                    **current,
                    "catalog_identity": bindings[(document_id, start, end)],
                }
            )
            current = next(label_iterator, None)
        slice_ids = ["cmu_person_all_train"]
        if include_negative_slice and not document_gold:
            slice_ids.append("cmu_person_negative_train")
        yield {"document": document, "gold_spans": document_gold, "slice_ids": slice_ids}
    if current is not None:
        raise EnronQualityError("CMU labels are not aligned with their document population.")


def _prepare_stream_document(value: Mapping[str, Any]) -> _Document:
    _require_closed_mapping(value, _DOCUMENT_FIELDS, "document", 0)
    document_id = _required_id(value["document_id"], "document_id", 0)
    text = value["text"]
    text_view = _required_id(value["text_view"], "text_view", 0)
    split_role = value["split_role"]
    if not isinstance(text, str):
        raise EnronQualityError("Quality document text must be a string.")
    _bounded_utf8_size(text, maximum=DEFAULT_MAX_SCAN_INPUT_BYTES)
    if not isinstance(split_role, str) or split_role not in _SPLIT_ROLES:
        raise EnronQualityError("Quality document split_role is invalid.")
    return _Document(document_id, text, text_view, split_role)


def _bounded_utf8_size(text: str, *, maximum: int) -> int:
    """Validate UTF-8 and its byte ceiling without an input-sized temporary."""

    if len(text) > maximum:
        raise EnronQualityError("Quality document text exceeds the native scan byte limit.")
    total = 0
    for offset in range(0, len(text), 64 * 1024):
        try:
            chunk = text[offset : offset + 64 * 1024].encode("utf-8")
        except UnicodeEncodeError:
            raise EnronQualityError("Quality document text must be valid UTF-8 text.") from None
        total += len(chunk)
        if total > maximum:
            raise EnronQualityError("Quality document text exceeds the native scan byte limit.")
    return total


def _prepare_stream_gold(
    values: Iterable[Mapping[str, Any]],
    document: _Document,
    *,
    max_items: int,
) -> tuple[_GoldSpan, ...]:
    if isinstance(values, (str, bytes, bytearray, Mapping)) or not isinstance(values, Iterable):
        raise EnronQualityError("Per-document gold spans must be iterable mappings.")
    spans: list[_GoldSpan] = []
    seen: set[tuple[str, str, int, int]] = set()
    for index, value in enumerate(values):
        if index >= max_items:
            raise EnronQualityError("Per-document gold spans exceed the quality limit.")
        _require_closed_mapping(value, _GOLD_FIELDS, "gold span", index)
        document_id = _required_id(value["document_id"], "document_id", index)
        entity_class = _required_id(value["entity_class"], "entity_class", index)
        if document_id != document.document_id:
            raise EnronQualityError(f"Gold span {index} references a different document.")
        start = _nonnegative_integer(value["start"], "start", index)
        end = _nonnegative_integer(value["end"], "end", index)
        if start >= end or end > len(document.text):
            raise EnronQualityError(f"Gold span {index} has invalid scalar bounds.")
        catalog_identity = _prepare_catalog_identity(value["catalog_identity"], entity_class, index)
        span = _GoldSpan(document_id, entity_class, start, end, catalog_identity)
        if span.key in seen:
            raise EnronQualityError("Gold exact-span/class keys must be unique.")
        seen.add(span.key)
        spans.append(span)
    return tuple(sorted(spans, key=lambda item: item.key))


def _prepare_catalog_identity(value: Any, entity_class: str, index: int) -> tuple[str, str, str] | None:
    if value is None:
        return None
    _require_closed_mapping(value, _CATALOG_IDENTITY_FIELDS, "catalog identity", index)
    entity_id = _required_id(value["entity_id"], "catalog entity_id", index)
    name_id = _required_id(value["name_id"], "catalog name_id", index)
    pattern_id = _required_id(value["pattern_id"], "catalog pattern_id", index)
    if entity_id != entity_class:
        raise EnronQualityError(f"Gold span {index} catalog identity must use its declared entity class.")
    return entity_id, name_id, pattern_id


def _prepare_slices(values: Sequence[Mapping[str, Any]]) -> tuple[_SliceSpec, ...]:
    _require_sequence(values, "slice_specs")
    if len(values) > DEFAULT_MAX_QUALITY_SLICES:
        raise EnronQualityError("Slice plans exceed the bounded quality limit.")
    slices: list[_SliceSpec] = []
    seen_ids: set[str] = set()
    for index, value in enumerate(values):
        _require_closed_mapping(value, _SLICE_FIELDS, "slice spec", index)
        slice_id = _required_public_id(value["id"], "slice id", index)
        if slice_id in seen_ids:
            raise EnronQualityError("Slice identifiers must be unique.")
        seen_ids.add(slice_id)
        label_artifact_id = _required_public_id(value["label_artifact_id"], "label_artifact_id", index)
        label_strength = value["label_strength"]
        annotation_scope = _prepare_annotation_scope(value["annotation_scope"], index)
        completeness = value["annotation_completeness"]
        entity_class = _required_public_id(value["entity_class"], "entity_class", index)
        cohort = _required_public_id(value["cohort"], "cohort", index)
        split_role = value["split_role"]
        text_view = _required_public_id(value["text_view"], "text_view", index)
        text_view_descriptor = _prepare_text_view_descriptor(value["text_view_descriptor"], text_view, index)
        promotion_gate = value["promotion_gate"]
        if not isinstance(label_strength, str) or label_strength not in _LABEL_STRENGTHS:
            raise EnronQualityError(f"Slice spec {index} label_strength is unsupported.")
        if not isinstance(completeness, str) or completeness not in _ANNOTATION_COMPLETENESS:
            raise EnronQualityError(f"Slice spec {index} annotation_completeness is unsupported.")
        if (
            label_strength == "independent"
            and completeness == "exhaustive_within_scope"
            and set(annotation_scope["document_regions"]) != set(text_view_descriptor["document_regions"])
        ):
            raise EnronQualityError(
                f"Slice spec {index} exhaustive independent evidence must cover the complete text view."
            )
        if not isinstance(split_role, str) or split_role not in _SPLIT_ROLES:
            raise EnronQualityError(f"Slice spec {index} split_role is invalid.")
        if type(promotion_gate) is not bool:
            raise EnronQualityError(f"Slice spec {index} promotion_gate must be a boolean.")
        if promotion_gate and (
            label_strength != "independent" or completeness != "exhaustive_within_scope" or split_role != "test"
        ):
            raise EnronQualityError(
                f"Slice spec {index} promotion gate requires independent exhaustive final-test evidence."
            )
        if promotion_gate and (
            annotation_scope["entity_classes"] != (entity_class,)
            or set(annotation_scope["document_regions"]) != set(text_view_descriptor["document_regions"])
            or annotation_scope["exclusions"]
            or cohort != "all"
            or not text_view_descriptor["primary_for_quality"]
            or text_view_descriptor["answer_bearing_fields_included"]
        ):
            raise EnronQualityError(
                f"Slice spec {index} promotion gate requires a complete unexcluded annotation scope."
            )
        if entity_class not in annotation_scope["entity_classes"] or not set(
            annotation_scope["document_regions"]
        ).issubset(text_view_descriptor["document_regions"]):
            raise EnronQualityError(f"Slice spec {index} is outside its annotation scope.")
        slices.append(
            _SliceSpec(
                slice_id,
                label_artifact_id,
                label_strength,
                annotation_scope["entity_classes"],
                annotation_scope["document_regions"],
                annotation_scope["span_policy_sha256"],
                annotation_scope["exclusions"],
                completeness,
                entity_class,
                cohort,
                split_role,
                text_view,
                text_view_descriptor["artifact_sha256"],
                text_view_descriptor["content_policy_sha256"],
                text_view_descriptor["document_regions"],
                text_view_descriptor["primary_for_quality"],
                text_view_descriptor["answer_bearing_fields_included"],
                promotion_gate,
            )
        )
    return tuple(slices)


def _prepare_text_view_descriptor(value: Any, text_view: str, index: int) -> dict[str, Any]:
    _require_closed_mapping(value, _TEXT_VIEW_DESCRIPTOR_FIELDS, "text view descriptor", index)
    descriptor_id = _required_public_id(value["id"], "text view descriptor id", index)
    artifact_sha256 = value["artifact_sha256"]
    content_policy_sha256 = value["content_policy_sha256"]
    document_regions = tuple(
        sorted(_bounded_public_id_sequence(value["document_regions"], "text view document region", index))
    )
    primary_for_quality = value["primary_for_quality"]
    answer_bearing_fields_included = value["answer_bearing_fields_included"]
    if descriptor_id != text_view:
        raise EnronQualityError(f"Slice spec {index} text view descriptor id does not match its text view.")
    if (
        not isinstance(artifact_sha256, str)
        or not _SHA256_RE.fullmatch(artifact_sha256)
        or not isinstance(content_policy_sha256, str)
        or not _SHA256_RE.fullmatch(content_policy_sha256)
        or type(primary_for_quality) is not bool
        or type(answer_bearing_fields_included) is not bool
    ):
        raise EnronQualityError(f"Slice spec {index} text view descriptor is invalid.")
    return {
        "id": descriptor_id,
        "artifact_sha256": artifact_sha256,
        "content_policy_sha256": content_policy_sha256,
        "document_regions": document_regions,
        "primary_for_quality": primary_for_quality,
        "answer_bearing_fields_included": answer_bearing_fields_included,
    }


def _prepare_declared_unsupported(
    values: Sequence[Mapping[str, Any]], slices: Sequence[_SliceSpec]
) -> tuple[dict[str, str], ...]:
    _require_sequence(values, "unsupported_slice_specs")
    if len(values) > DEFAULT_MAX_QUALITY_SLICES:
        raise EnronQualityError("Unsupported slice plans exceed the bounded quality limit.")
    occupied = {item.id for item in slices}
    result: list[dict[str, str]] = []
    for index, value in enumerate(values):
        _require_closed_mapping(value, _UNSUPPORTED_SLICE_FIELDS, "unsupported slice spec", index)
        item = {
            "id": _required_public_id(value["id"], "unsupported slice id", index),
            "dimension": _required_public_id(value["dimension"], "unsupported slice dimension", index),
            "reason_code": _required_public_id(value["reason_code"], "unsupported slice reason code", index),
        }
        if item["id"] in occupied:
            raise EnronQualityError("Supported and unsupported slice identifiers must be unique.")
        occupied.add(item["id"])
        result.append(item)
    return tuple(sorted(result, key=lambda item: item["id"]))


def _prepare_stream_slice_ids(values: Sequence[str], specs: Mapping[str, _SliceSpec]) -> tuple[str, ...]:
    _require_sequence(values, "slice_ids")
    if not values or len(values) > DEFAULT_MAX_QUALITY_SLICES:
        raise EnronQualityError("Every quality document must have bounded slice membership.")
    result = tuple(_required_public_id(value, "slice id", index) for index, value in enumerate(values))
    if len(result) != len(set(result)) or any(value not in specs for value in result):
        raise EnronQualityError("Quality slice membership must be unique and declared.")
    return result


def _validate_stream_coverage(
    document: _Document,
    gold_spans: Sequence[_GoldSpan],
    assigned_specs: Sequence[_SliceSpec],
    all_specs: Sequence[_SliceSpec],
) -> None:
    if any(spec.split_role != document.split_role or spec.text_view != document.text_view for spec in assigned_specs):
        raise EnronQualityError("A quality slice membership differs from the document role or text view.")
    covered_classes = {spec.entity_class for spec in assigned_specs}
    if any(gold.entity_class not in covered_classes for gold in gold_spans):
        raise EnronQualityError("Every gold span must be assigned to an in-class supported slice.")
    assigned_ids = {spec.id for spec in assigned_specs}
    required_promotion_ids = {
        spec.id
        for spec in all_specs
        if spec.promotion_gate and spec.split_role == document.split_role and spec.text_view == document.text_view
    }
    if not required_promotion_ids.issubset(assigned_ids):
        raise EnronQualityError("A promotion-gated slice must cover its complete role and text-view population.")


def _prepare_annotation_scope(value: Any, index: int) -> dict[str, Any]:
    _require_closed_mapping(value, _ANNOTATION_SCOPE_FIELDS, "annotation scope", index)
    entity_classes = _bounded_public_id_sequence(value["entity_classes"], "annotation entity class", index)
    document_regions = _bounded_public_id_sequence(value["document_regions"], "annotation document region", index)
    exclusions = _bounded_public_id_sequence(value["exclusions"], "annotation exclusion", index, allow_empty=True)
    span_policy_sha256 = value["span_policy_sha256"]
    if not isinstance(span_policy_sha256, str) or not _SHA256_RE.fullmatch(span_policy_sha256):
        raise EnronQualityError(f"Slice spec {index} annotation span policy hash is invalid.")
    return {
        "entity_classes": entity_classes,
        "document_regions": document_regions,
        "span_policy_sha256": span_policy_sha256,
        "exclusions": exclusions,
    }


def _bounded_public_id_sequence(
    value: Any,
    description: str,
    index: int,
    *,
    allow_empty: bool = False,
) -> tuple[str, ...]:
    _require_sequence(value, f"slice spec {index} {description}s")
    if len(value) > DEFAULT_MAX_QUALITY_SLICES:
        raise EnronQualityError(f"Slice spec {index} {description}s exceed the bounded item limit.")
    items = tuple(_required_public_id(item, description, index) for item in value)
    if (not items and not allow_empty) or len(items) != len(set(items)):
        raise EnronQualityError(f"Slice spec {index} {description}s must be a unique bounded list.")
    return items


def _active_pattern_inventory(bank: Mapping[str, Any] | None) -> frozenset[tuple[str, str, str]]:
    if bank is None:
        return frozenset()
    inventory: set[tuple[str, str, str]] = set()
    entities = bank.get("entities")
    if not isinstance(entities, Mapping):
        return frozenset()
    for entity_id, entity in entities.items():
        if not isinstance(entity_id, str) or not isinstance(entity, Mapping):
            continue
        names = entity.get("names")
        if not isinstance(names, Mapping):
            continue
        for name_id, name in names.items():
            if not isinstance(name_id, str) or not isinstance(name, Mapping):
                continue
            patterns = name.get("patterns")
            if not isinstance(patterns, Mapping):
                continue
            for pattern_id in patterns:
                if isinstance(pattern_id, str):
                    inventory.add((entity_id, name_id, pattern_id))
    return frozenset(inventory)


def _validate_catalog_identities(
    gold_spans: Sequence[_GoldSpan], active_patterns: frozenset[tuple[str, str, str]]
) -> None:
    if any(item.catalog_identity is not None and item.catalog_identity not in active_patterns for item in gold_spans):
        raise EnronQualityError("A frozen catalog qualification is not present in the active pattern inventory.")


def _scan_document(
    compiled: Any,
    document: _Document,
    *,
    max_predictions: int,
) -> tuple[_Prediction, ...]:
    predictions: list[_Prediction] = []
    try:
        records = compiled.finditer(document.text, max_matches=max_predictions)
    except MemoryError:
        raise EnronQualityError("Quality scan exceeded the per-document prediction limit.") from None
    except Exception:
        raise EnronQualityError("A private quality document could not be scanned safely.") from None
    if len(records) > max_predictions:
        raise EnronQualityError("Quality scan exceeded the per-document prediction limit.")
    raw_offsets: set[int] = set()
    for record in records:
        try:
            start = record["start"]
            end = record["end"]
        except KeyError as exc:
            raise EnronQualityError("A native prediction did not contain bounded offsets.") from exc
        if (
            record.get("offset_unit") != "byte"
            or type(start) is not int
            or type(end) is not int
            or start < 0
            or end <= start
        ):
            raise EnronQualityError("A native prediction did not contain bounded offsets.")
        raw_offsets.update((start, end))
    byte_to_scalar = _selected_byte_to_scalar_boundaries(document.text, raw_offsets)
    for record in records:
        try:
            start = byte_to_scalar[record["start"]]
            end = byte_to_scalar[record["end"]]
        except KeyError as exc:
            raise EnronQualityError("A native prediction did not align to Unicode scalar boundaries.") from exc
        predictions.append(
            _Prediction(
                document.document_id,
                str(record["entity_id"]),
                start,
                end,
                str(record["entity_id"]),
                str(record["name_id"]),
                str(record["pattern_id"]),
            )
        )
    return tuple(
        sorted(
            predictions,
            key=lambda item: (*item.key, item.entity_id, item.name_id, item.pattern_id),
        )
    )


def _selected_byte_to_scalar_boundaries(text: str, requested: set[int]) -> dict[int, int]:
    targets = sorted(requested)
    boundaries: dict[int, int] = {}
    target_index = 0
    while target_index < len(targets) and targets[target_index] == 0:
        boundaries[0] = 0
        target_index += 1
    byte_offset = 0
    for scalar_offset, character in enumerate(text, start=1):
        byte_offset += len(character.encode("utf-8"))
        if target_index < len(targets) and targets[target_index] < byte_offset:
            raise EnronQualityError("A native prediction did not align to Unicode scalar boundaries.")
        while target_index < len(targets) and targets[target_index] == byte_offset:
            boundaries[byte_offset] = scalar_offset
            target_index += 1
        if target_index == len(targets):
            break
    if target_index != len(targets):
        raise EnronQualityError("A native prediction exceeded the document byte length.")
    return boundaries


def _accumulate_slice_document(
    accumulator: _SliceAccumulator,
    spec: _SliceSpec,
    document: _Document,
    document_gold: Sequence[_GoldSpan],
    document_predictions: Sequence[_Prediction],
) -> tuple[str, ...]:
    gold = tuple(item for item in document_gold if item.entity_class == spec.entity_class)
    predictions = tuple(item for item in document_predictions if item.entity_class == spec.entity_class)
    prediction_indices: dict[tuple[str, str, int, int], list[int]] = defaultdict(list)
    for index, prediction in enumerate(predictions):
        prediction_indices[prediction.key].append(index)
    selected_predictions: dict[tuple[str, str, int, int], int] = {}
    for item in gold:
        candidates = prediction_indices.get(item.key, [])
        if not candidates:
            continue
        selected = candidates[0]
        if item.catalog_identity is not None:
            expected_identity = item.catalog_identity[:2]
            selected = next(
                (
                    prediction_index
                    for prediction_index in candidates
                    if predictions[prediction_index].identity == expected_identity
                ),
                selected,
            )
        selected_predictions[item.key] = selected

    true_positive = len(selected_predictions)
    false_negative = len(gold) - true_positive
    false_positive = len(predictions) - true_positive if spec.open_world_eligible else 0
    predicted_spans = len(predictions) if spec.open_world_eligible else true_positive

    any_miss = False
    any_catalog_miss = False
    cataloged_true_positive = 0
    cataloged_false_negative = 0
    cataloged_wrong_canonical = 0
    for item in gold:
        selected_index = selected_predictions.get(item.key)
        if selected_index is None:
            any_miss = True
        if item.catalog_identity is None:
            continue
        if selected_index is None:
            cataloged_false_negative += 1
            any_catalog_miss = True
        elif predictions[selected_index].identity == item.catalog_identity[:2]:
            cataloged_true_positive += 1
        else:
            cataloged_wrong_canonical += 1
            any_catalog_miss = True

    has_gold = bool(gold)
    has_cataloged_gold = any(item.catalog_identity is not None for item in gold)
    cataloged_gold_spans = cataloged_true_positive + cataloged_false_negative + cataloged_wrong_canonical

    if spec.open_world_eligible:
        character_counts = _document_character_counts(document, gold, predictions)
        negative_documents = int(not has_gold)
        negative_documents_with_predictions = int(not has_gold and bool(predictions))
    else:
        character_counts = {
            "sensitive_gold_characters": 0,
            "covered_sensitive_characters": 0,
            "leaked_sensitive_characters": 0,
            "predicted_characters": 0,
            "over_redacted_characters": 0,
            "evaluated_characters": 0,
            "documents_with_any_leaked_character": 0,
        }
        negative_documents = 0
        negative_documents_with_predictions = 0

    accumulator.documents += 1
    accumulator.documents_with_sensitive_gold += int(has_gold)
    accumulator.documents_with_any_miss += int(any_miss)
    accumulator.documents_with_cataloged_gold += int(has_cataloged_gold)
    accumulator.documents_with_any_cataloged_miss += int(any_catalog_miss)
    accumulator.documents_with_any_leaked_character += character_counts["documents_with_any_leaked_character"]
    accumulator.gold_spans += len(gold)
    accumulator.predicted_spans += predicted_spans
    accumulator.true_positive += true_positive
    accumulator.false_positive += false_positive
    accumulator.false_negative += false_negative
    accumulator.cataloged_gold_spans += cataloged_gold_spans
    accumulator.cataloged_true_positive += cataloged_true_positive
    accumulator.cataloged_false_negative += cataloged_false_negative
    accumulator.cataloged_wrong_canonical += cataloged_wrong_canonical
    accumulator.sensitive_gold_characters += character_counts["sensitive_gold_characters"]
    accumulator.covered_sensitive_characters += character_counts["covered_sensitive_characters"]
    accumulator.leaked_sensitive_characters += character_counts["leaked_sensitive_characters"]
    accumulator.predicted_characters += character_counts["predicted_characters"]
    accumulator.over_redacted_characters += character_counts["over_redacted_characters"]
    accumulator.evaluated_characters += character_counts["evaluated_characters"]
    accumulator.negative_documents += negative_documents
    accumulator.negative_documents_with_predictions += negative_documents_with_predictions

    reasons: set[str] = set()
    if any_miss:
        reasons.add("exact_span_miss")
    if any_catalog_miss:
        reasons.add("cataloged_miss")
    if cataloged_wrong_canonical:
        reasons.add("wrong_canonical")
    if character_counts["documents_with_any_leaked_character"]:
        reasons.add("sensitive_character_leak")
    if negative_documents_with_predictions:
        reasons.add("negative_document_prediction")
    return tuple(sorted(reasons))


def _streaming_unsupported_reason(spec: _SliceSpec, accumulator: _SliceAccumulator) -> str | None:
    if accumulator.documents == 0:
        return "empty_document_population"
    if spec.promotion_gate and accumulator.gold_spans == 0:
        return "zero_gold_promotion_support"
    if not spec.open_world_eligible and accumulator.gold_spans == 0:
        return "zero_labeled_spans"
    return None


def _finish_slice(spec: _SliceSpec, item: _SliceAccumulator) -> dict[str, Any]:
    metrics = {
        "precision": _ratio(item.true_positive, item.predicted_spans) if spec.open_world_eligible else None,
        "open_world_recall": _ratio(item.true_positive, item.gold_spans) if spec.open_world_eligible else None,
        "f1": (_f1(item.true_positive, item.false_positive, item.false_negative) if spec.open_world_eligible else None),
        "catalog_coverage": _ratio(item.cataloged_gold_spans, item.gold_spans),
        "cataloged_recall": _ratio(item.cataloged_true_positive, item.cataloged_gold_spans),
        "document_leak_rate": (
            _ratio(item.documents_with_any_miss, item.documents_with_sensitive_gold)
            if spec.open_world_eligible
            else None
        ),
        "cataloged_document_leak_rate": (
            _ratio(item.documents_with_any_cataloged_miss, item.documents_with_cataloged_gold)
            if spec.open_world_eligible
            else None
        ),
        "sensitive_character_recall": (
            _ratio(item.covered_sensitive_characters, item.sensitive_gold_characters)
            if spec.open_world_eligible
            else None
        ),
        "sensitive_character_leak_rate": (
            _ratio(item.leaked_sensitive_characters, item.sensitive_gold_characters)
            if spec.open_world_eligible
            else None
        ),
        "negative_document_false_alarm_rate": (
            _ratio(item.negative_documents_with_predictions, item.negative_documents)
            if spec.open_world_eligible
            else None
        ),
        "over_redaction_rate": (
            _ratio(item.over_redacted_characters, item.evaluated_characters) if spec.open_world_eligible else None
        ),
    }
    return {
        "id": spec.id,
        "label_artifact_id": spec.label_artifact_id,
        "label_strength": spec.label_strength,
        "annotation_scope": spec.annotation_scope,
        "annotation_completeness": spec.annotation_completeness,
        "entity_class": spec.entity_class,
        "cohort": spec.cohort,
        "split_role": spec.split_role,
        "text_view": spec.text_view,
        "promotion_gate": spec.promotion_gate,
        "documents": item.documents,
        "documents_with_sensitive_gold": item.documents_with_sensitive_gold,
        "documents_with_any_miss": item.documents_with_any_miss,
        "documents_with_cataloged_gold": item.documents_with_cataloged_gold,
        "documents_with_any_cataloged_miss": item.documents_with_any_cataloged_miss,
        "documents_with_any_leaked_character": item.documents_with_any_leaked_character,
        "gold_spans": item.gold_spans,
        "predicted_spans": item.predicted_spans,
        "true_positive": item.true_positive,
        "false_positive": item.false_positive,
        "false_negative": item.false_negative,
        "cataloged_gold_spans": item.cataloged_gold_spans,
        "cataloged_true_positive": item.cataloged_true_positive,
        "cataloged_false_negative": item.cataloged_false_negative,
        "cataloged_wrong_canonical": item.cataloged_wrong_canonical,
        "sensitive_gold_characters": item.sensitive_gold_characters,
        "covered_sensitive_characters": item.covered_sensitive_characters,
        "leaked_sensitive_characters": item.leaked_sensitive_characters,
        "predicted_characters": item.predicted_characters,
        "over_redacted_characters": item.over_redacted_characters,
        "evaluated_characters": item.evaluated_characters,
        "negative_documents": item.negative_documents,
        "negative_documents_with_predictions": item.negative_documents_with_predictions,
        "metrics": metrics,
    }


def _document_character_counts(
    document: _Document,
    gold: Sequence[_GoldSpan],
    predictions: Sequence[_Prediction],
) -> dict[str, int]:
    gold_union = _merge_intervals(tuple((item.start, item.end) for item in gold))
    prediction_union = _merge_intervals(tuple((item.start, item.end) for item in predictions))
    sensitive = _interval_length(gold_union)
    covered = _intersection_length(gold_union, prediction_union)
    predicted = _interval_length(prediction_union)
    return {
        "sensitive_gold_characters": sensitive,
        "covered_sensitive_characters": covered,
        "leaked_sensitive_characters": sensitive - covered,
        "predicted_characters": predicted,
        "over_redacted_characters": predicted - covered,
        "evaluated_characters": len(document.text),
        "documents_with_any_leaked_character": int(sensitive > covered),
    }


def _merge_intervals(values: Sequence[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(values):
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
    return tuple(merged)


def _interval_length(values: Sequence[tuple[int, int]]) -> int:
    return sum(end - start for start, end in values)


def _intersection_length(first: Sequence[tuple[int, int]], second: Sequence[tuple[int, int]]) -> int:
    total = 0
    first_index = 0
    second_index = 0
    while first_index < len(first) and second_index < len(second):
        first_start, first_end = first[first_index]
        second_start, second_end = second[second_index]
        total += max(0, min(first_end, second_end) - max(first_start, second_start))
        if first_end <= second_end:
            first_index += 1
        else:
            second_index += 1
    return total


def _streaming_protocol_hash(
    connection: sqlite3.Connection,
    evaluator: Mapping[str, Any],
    policy_sha256: str,
    slices: Sequence[_SliceSpec],
    unsupported_slices: Sequence[Mapping[str, str]],
    *,
    activity_callback: Callable[[], None] | None = None,
) -> str:
    digest = sha256()
    digest.update(b'{"documents":[')
    documents = (
        {
            "document_id": str(row[0]),
            "text_sha256": str(row[1]),
            "unicode_scalars": int(row[2]),
            "text_view": str(row[3]),
            "split_role": str(row[4]),
        }
        for row in connection.execute(
            "SELECT document_id, text_sha256, unicode_scalars, text_view, split_role "
            "FROM documents ORDER BY document_id"
        )
    )
    _update_canonical_array(digest, documents, activity_callback=activity_callback)
    digest.update(b'],"evaluator":')
    digest.update(_canonical_json_bytes(evaluator))
    digest.update(b',"gold_spans":[')
    gold = (
        {"document_id": str(row[0]), "entity_class": str(row[1]), "start": int(row[2]), "end": int(row[3])}
        for row in connection.execute(
            "SELECT document_id, entity_class, start, end FROM gold ORDER BY document_id, entity_class, start, end"
        )
    )
    _update_canonical_array(digest, gold, activity_callback=activity_callback)
    digest.update(b'],"policy_sha256":')
    digest.update(_canonical_json_bytes(policy_sha256))
    digest.update(b',"slice_specs":[')
    for index, spec in enumerate(slices):
        if activity_callback is not None:
            activity_callback()
        if index:
            digest.update(b",")
        _update_slice_fingerprint(digest, connection, spec, activity_callback=activity_callback)
    digest.update(b'],"unsupported_slice_specs":[')
    _update_canonical_array(digest, unsupported_slices, activity_callback=activity_callback)
    digest.update(b"]}")
    return "sha256:" + digest.hexdigest()


def _streaming_catalog_binding_hash(
    connection: sqlite3.Connection,
    canonical_bank_sha256: str,
    *,
    activity_callback: Callable[[], None] | None = None,
) -> str:
    digest = sha256()
    digest.update(b'{"bank_sha256":')
    digest.update(_canonical_json_bytes(canonical_bank_sha256))
    digest.update(b',"bindings":[')
    bindings = (
        {
            "document_id": str(row[0]),
            "entity_class": str(row[1]),
            "start": int(row[2]),
            "end": int(row[3]),
            "catalog_identity": (
                None
                if row[4] is None
                else {"entity_id": str(row[4]), "name_id": str(row[5]), "pattern_id": str(row[6])}
            ),
        }
        for row in connection.execute(
            "SELECT document_id, entity_class, start, end, catalog_entity_id, catalog_name_id, catalog_pattern_id "
            "FROM gold ORDER BY document_id, entity_class, start, end"
        )
    )
    _update_canonical_array(digest, bindings, activity_callback=activity_callback)
    digest.update(b'],"schema_version":"nerb.enron-catalog-binding.v2"}')
    return "sha256:" + digest.hexdigest()


def _update_canonical_array(
    digest: Any,
    values: Iterable[Any],
    *,
    activity_callback: Callable[[], None] | None = None,
) -> None:
    for index, value in enumerate(values):
        if activity_callback is not None:
            activity_callback()
        if index:
            digest.update(b",")
        digest.update(_canonical_json_bytes(value))


def _update_slice_fingerprint(
    digest: Any,
    connection: sqlite3.Connection,
    spec: _SliceSpec,
    *,
    activity_callback: Callable[[], None] | None = None,
) -> None:
    payload = spec.fingerprint_payload(())
    digest.update(b"{")
    for index, key in enumerate(sorted(payload)):
        if index:
            digest.update(b",")
        digest.update(_canonical_json_bytes(key))
        digest.update(b":")
        if key != "document_ids":
            digest.update(_canonical_json_bytes(payload[key]))
            continue
        digest.update(b"[")
        document_ids = (
            str(row[0])
            for row in connection.execute(
                "SELECT document_id FROM memberships WHERE slice_id = ? ORDER BY document_id",
                (spec.id,),
            )
        )
        _update_canonical_array(digest, document_ids, activity_callback=activity_callback)
        digest.update(b"]")
    digest.update(b"}")


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _metadata_commitment_item(kind: str, value: Mapping[str, Any]) -> int:
    payload = _canonical_json_bytes({"kind": kind, "value": value})
    return int.from_bytes(sha512(b"nerb/enron/quality-metadata\0" + payload).digest(), "big")


def _spool_metadata_commitment(
    connection: sqlite3.Connection,
    *,
    activity_callback: Callable[[], None] | None = None,
) -> tuple[int, int]:
    accumulator = 0
    items = 0

    def add(kind: str, value: Mapping[str, Any]) -> None:
        nonlocal accumulator, items
        accumulator = (accumulator + _metadata_commitment_item(kind, value)) % _METADATA_COMMITMENT_MODULUS
        items += 1

    for row in connection.execute(
        "SELECT document_id, text_sha256, unicode_scalars, text_view, split_role FROM documents"
    ):
        if activity_callback is not None:
            activity_callback()
        add(
            "document",
            {
                "document_id": str(row[0]),
                "text_sha256": str(row[1]),
                "unicode_scalars": int(row[2]),
                "text_view": str(row[3]),
                "split_role": str(row[4]),
            },
        )
    for row in connection.execute(
        "SELECT document_id, entity_class, start, end, catalog_entity_id, catalog_name_id, catalog_pattern_id FROM gold"
    ):
        if activity_callback is not None:
            activity_callback()
        add(
            "gold",
            {
                "document_id": str(row[0]),
                "entity_class": str(row[1]),
                "start": int(row[2]),
                "end": int(row[3]),
                "catalog_entity_id": None if row[4] is None else str(row[4]),
                "catalog_name_id": None if row[5] is None else str(row[5]),
                "catalog_pattern_id": None if row[6] is None else str(row[6]),
            },
        )
    for row in connection.execute("SELECT slice_id, document_id FROM memberships"):
        if activity_callback is not None:
            activity_callback()
        add("membership", {"slice_id": str(row[0]), "document_id": str(row[1])})
    return accumulator, items


@dataclass(slots=True)
class _JSONLBudget:
    remaining_bytes: int
    remaining_records: int

    def consume(self, raw: bytes) -> None:
        self.remaining_bytes -= len(raw)
        self.remaining_records -= 1
        if self.remaining_bytes < 0:
            raise EnronQualityError("Quality JSONL inputs exceed the cumulative byte limit.")
        if self.remaining_records < 0:
            raise EnronQualityError("Quality JSONL inputs exceed the cumulative record limit.")


def _load_small_quality_plan(
    path: Path,
    *,
    budget: _JSONLBudget,
    max_line_bytes: int,
    max_items: int,
) -> tuple[Mapping[str, Any], ...]:
    rows: list[Mapping[str, Any]] = []
    for _line, raw, row in iter_strict_jsonl(path, max_line_bytes):
        budget.consume(raw)
        if len(rows) >= max_items:
            raise EnronQualityError("Quality plan input exceeds its bounded item limit.")
        rows.append(row)
    return tuple(rows)


def _iter_quality_records(
    path: Path,
    *,
    budget: _JSONLBudget,
    max_line_bytes: int,
) -> Iterator[Mapping[str, Any]]:
    for _line, raw, row in iter_strict_jsonl(path, max_line_bytes):
        budget.consume(raw)
        yield row


def _open_metadata_spool(
    requested_path: str | Path | None,
    *,
    max_spool_bytes: int,
) -> tuple[Path, _SpoolIdentity, sqlite3.Connection, _SpoolCleanup]:
    owned_run: PrivateRun | None = None
    if requested_path is None:
        temp_root = Path(tempfile.gettempdir()).resolve(strict=True)
        final = temp_root / f"nerb-enron-quality-{secrets.token_hex(16)}"
        owned_run = PrivateRun(final, allow_unignored_output=True)
        owned_run.__enter__()
        path = owned_run.stage_dir / "metadata.sqlite3"
    else:
        candidate = Path(requested_path).expanduser()
        if any(part == os.pardir for part in candidate.parts):
            raise EnronQualityError("Quality metadata spool path is invalid.")
        path = candidate if candidate.is_absolute() else Path.cwd() / candidate
        _reject_symlink_components(path.parent)
        parent_info = path.parent.stat()
        if not stat.S_ISDIR(parent_info.st_mode) or stat.S_IMODE(parent_info.st_mode) & 0o077:
            raise EnronQualityError("Quality metadata spool parent must be private.")
    flags = os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor: int | None = None
    parent_fd: int | None = None
    connection: sqlite3.Connection | None = None
    identity: _SpoolIdentity | None = None
    cleanup_identity: tuple[int, int] | None = None
    try:
        if owned_run is not None:
            if owned_run._stage_fd is None:  # noqa: SLF001 - same-package pinned cleanup handoff
                raise EnronQualityError("Quality metadata spool parent is unavailable.")
            parent_fd = os.dup(owned_run._stage_fd)  # noqa: SLF001
        else:
            parent_fd = open_private_directory_input(path.parent)
        descriptor = os.open(path.name, flags, 0o600, dir_fd=parent_fd)
        os.fchmod(descriptor, 0o600)
        before = os.fstat(descriptor)
        cleanup_identity = int(before.st_dev), int(before.st_ino)
        identity = _identity_from_stat(before)
        connection = sqlite3.connect(path, check_same_thread=False)
        if _spool_identity(path) != identity:
            raise EnronQualityError("Quality metadata spool changed while it was opened.")
        locking_mode = connection.execute("PRAGMA locking_mode=EXCLUSIVE").fetchone()
        if locking_mode is None or str(locking_mode[0]).lower() != "exclusive":
            raise EnronQualityError("Quality metadata spool cannot hold an exclusive lock.")
        journal_mode = connection.execute("PRAGMA journal_mode=MEMORY").fetchone()
        if journal_mode is None or str(journal_mode[0]).lower() != "memory":
            raise EnronQualityError("Quality metadata spool could not keep its journal in memory.")
        connection.execute("PRAGMA synchronous=OFF")
        connection.execute("PRAGMA temp_store=MEMORY")
        temp_store = connection.execute("PRAGMA temp_store").fetchone()
        if temp_store is None or int(temp_store[0]) != 2:
            raise EnronQualityError("Quality metadata spool could not disable external temporary files.")
        connection.execute("PRAGMA cache_size=-2048")
        connection.execute("PRAGMA foreign_keys=ON")
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        maximum_pages = max_spool_bytes // page_size
        observed_maximum = int(connection.execute(f"PRAGMA max_page_count={maximum_pages}").fetchone()[0])
        if maximum_pages < 1 or observed_maximum > maximum_pages:
            raise EnronQualityError("Quality metadata spool byte limit could not be enforced.")
        connection.executescript(
            """
            CREATE TABLE documents (
                document_id TEXT PRIMARY KEY,
                text_sha256 TEXT NOT NULL,
                unicode_scalars INTEGER NOT NULL,
                text_view TEXT NOT NULL,
                split_role TEXT NOT NULL
            ) WITHOUT ROWID;
            CREATE TABLE gold (
                document_id TEXT NOT NULL,
                entity_class TEXT NOT NULL,
                start INTEGER NOT NULL,
                end INTEGER NOT NULL,
                catalog_entity_id TEXT,
                catalog_name_id TEXT,
                catalog_pattern_id TEXT,
                PRIMARY KEY (document_id, entity_class, start, end)
            ) WITHOUT ROWID;
            CREATE TABLE memberships (
                slice_id TEXT NOT NULL,
                document_id TEXT NOT NULL,
                PRIMARY KEY (slice_id, document_id)
            ) WITHOUT ROWID;
            """
        )
        connection.commit()
        return path, identity, connection, _SpoolCleanup(descriptor, parent_fd, path.parent, owned_run)
    except BaseException as exc:
        cleanup_failed = False
        deferred_control = exc if isinstance(exc, (KeyboardInterrupt, SystemExit)) else None
        if (
            connection is not None
            and descriptor is not None
            and parent_fd is not None
            and cleanup_identity is not None
            and identity is not None
        ):
            spool_cleanup = _SpoolCleanup(descriptor, parent_fd, path.parent, owned_run)
            pending_cleanup = _PendingSpoolCleanup(connection, spool_cleanup, path, identity)
            status, cleanup_failed, deferred_control = _settle_or_publish_pending_spool_cleanup_to_completion(
                pending_cleanup,
                deferred_control=deferred_control,
            )
            if status != "settled":
                message = (
                    "Quality metadata spool writer could not be closed safely."
                    if status == "writer_live"
                    else "Quality metadata spool could not be cleaned safely."
                )
                close_error = _EnronQualityCleanupError(message)
                raise close_error from (deferred_control or exc)
            if cleanup_failed:
                raise _EnronQualityCleanupError("Quality metadata spool could not be cleaned safely.") from (
                    deferred_control or exc
                )
            if deferred_control is not None:
                raise deferred_control
            raise
        if connection is not None:
            # Connection assignment occurs only after every cleanup authority
            # above is established.  Preserve fail-closed behavior if that
            # invariant is ever changed without updating this rollback path.
            raise _EnronQualityCleanupError("Quality metadata spool cleanup authority is incomplete.") from exc
        if descriptor is not None and parent_fd is not None and cleanup_identity is not None:
            while True:
                try:
                    _wipe_and_quarantine_pinned_private_file(
                        descriptor,
                        parent_fd,
                        path.parent,
                        path.name,
                        cleanup_identity,
                        workspace_root=None,
                        allow_unignored_output=True,
                    )
                except (KeyboardInterrupt, SystemExit) as cleanup_control:
                    deferred_control = _remember_control_error(deferred_control, cleanup_control)
                    continue
                except EnronPrivateIOError:
                    cleanup_failed = True
                break
        elif descriptor is not None:
            cleanup_failed = True
        for descriptor_to_close in (descriptor, parent_fd):
            if descriptor_to_close is not None:
                while True:
                    try:
                        os.close(descriptor_to_close)
                    except (KeyboardInterrupt, SystemExit) as cleanup_control:
                        deferred_control = _remember_control_error(deferred_control, cleanup_control)
                        continue
                    except OSError as close_error:
                        if close_error.errno != errno.EBADF:
                            cleanup_failed = True
                    break
        if owned_run is not None:
            while True:
                try:
                    owned_run.__exit__(None, None, None)
                except (KeyboardInterrupt, SystemExit) as cleanup_control:
                    deferred_control = _remember_control_error(deferred_control, cleanup_control)
                    continue
                except EnronPrivateIOError as cleanup_error:
                    cleanup_failed = True
                    cause = cleanup_error.__cause__
                    if isinstance(cause, (KeyboardInterrupt, SystemExit)):
                        deferred_control = _remember_control_error(deferred_control, cause)
                break
        if cleanup_failed:
            raise _EnronQualityCleanupError("Quality metadata spool could not be cleaned safely.") from (
                deferred_control or exc
            )
        if deferred_control is not None:
            raise deferred_control
        raise


def _reject_symlink_components(path: Path) -> None:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise EnronQualityError("Quality metadata spool path contains an unsafe component.")


def _identity_from_stat(info: os.stat_result) -> _SpoolIdentity:
    mode = stat.S_IMODE(info.st_mode)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or mode & 0o077:
        raise EnronQualityError("Quality metadata spool must be a private single-link regular file.")
    return _SpoolIdentity(info.st_dev, info.st_ino, mode, info.st_nlink)


def _spool_identity(path: Path) -> _SpoolIdentity:
    try:
        return _identity_from_stat(path.lstat())
    except (FileNotFoundError, OSError):
        raise EnronQualityError("Quality metadata spool is unavailable.") from None


def _evaluator_identity() -> dict[str, str]:
    try:
        source_sha256 = _normalized_source_sha256(Path(__file__))
        contract_validator_source_sha256 = _normalized_source_sha256(Path(enron_contract.__file__))
        execution_semantics_sha256 = extraction_semantics_sha256()
    except (OSError, RuntimeError, ValueError):
        raise EnronQualityError("Quality evaluator source could not be fingerprinted.") from None
    return {
        "id": EVALUATOR_ID,
        "version": EVALUATOR_VERSION,
        "source_sha256": source_sha256,
        "label_schema_sha256": _canonical_hash(_LABEL_SCHEMA_DESCRIPTOR),
        "contract_validator_source_sha256": contract_validator_source_sha256,
        "contract_schema_sha256": _canonical_hash(enron_contract.ENRON_QUALITY_OUTPUT_SCHEMA),
        "execution_semantics_sha256": execution_semantics_sha256,
    }


def _normalized_source_sha256(path: Path) -> str:
    payload = path.read_bytes().replace(b"\r\n", b"\n")
    if b"\r" in payload:
        raise ValueError("source contains a bare carriage return")
    return _hash_bytes(payload)


def _canonical_hash(value: Any) -> str:
    return _hash_bytes(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def _hash_bytes(value: bytes) -> str:
    return "sha256:" + sha256(value).hexdigest()


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _f1(true_positive: int, false_positive: int, false_negative: int) -> float | None:
    denominator = 2 * true_positive + false_positive + false_negative
    return (2 * true_positive) / denominator if denominator else None


def _required_id(value: Any, field: str, index: int) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise EnronQualityError(f"Item {index} {field} must be a non-empty bounded string.")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise EnronQualityError(f"Item {index} {field} must be valid UTF-8 text.") from None
    return value


def _required_public_id(value: Any, field: str, index: int) -> str:
    item = _required_id(value, field, index)
    if not _PUBLIC_ID_RE.fullmatch(item):
        raise EnronQualityError(f"Item {index} {field} must be a privacy-safe logical identifier.")
    return item


def _nonnegative_integer(value: Any, field: str, index: int) -> int:
    if type(value) is not int or value < 0:
        raise EnronQualityError(f"Item {index} {field} must be a non-negative integer.")
    return value


def _require_sequence(value: Any, description: str) -> None:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise EnronQualityError(f"{description} must be a sequence.")


def _require_item_limit(value: Sequence[Any], description: str) -> None:
    if len(value) > DEFAULT_MAX_QUALITY_RECORDS:
        raise EnronQualityError(f"{description} exceeds the quality record limit.")


def _require_closed_mapping(value: Any, fields: frozenset[str], description: str, index: int) -> None:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise EnronQualityError(f"{description.capitalize()} {index} must use the closed quality schema.")

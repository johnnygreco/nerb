"""Fail-closed, aggregate-only capacity evidence for the pinned Enron source.

Only :func:`run_enron_capacity` can produce production evidence.  It selects
the operating-system resource probe and the phase implementations internally.
The private test seam emits explicitly non-production fixture evidence.

The report deliberately contains no source path, document identifier, matched
surface, or correctness row.  Production evidence is promotable only when a
closed five-phase commitment chain, continuous resource monitoring, checkpoint
progress, private-tree validation, and the durable attempt receipt all pass.
"""

from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import importlib
import inspect
import json
import os
import platform
import re
import resource
import secrets
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from importlib import metadata as importlib_metadata
from importlib import util as importlib_util
from pathlib import Path
from typing import Any, Protocol, cast

from . import _capacity_bootstrap as _capacity_import_guard
from . import enron_private_io as _private_io
from .enron_activity import ACTIVITY_RECORD_INTERVAL
from .enron_private_io import (
    EnronPrivateIOError,
    PrivateRun,
    ensure_private_output_allowed,
    is_owner_only_private_mode,
    open_private_binary_input,
)

_native_engine = importlib.import_module("nerb._engine")

__all__ = [
    "CAPACITY_PHASES",
    "CAPACITY_REPORT_SCHEMA_VERSION",
    "ENRON_DATASET_ID",
    "ENRON_DATASET_REVISION",
    "ENRON_SOURCE_ROWS",
    "CapacityDiskUsage",
    "CapacityResourceProbe",
    "EnronCapacityError",
    "EnronCapacityOptions",
    "EnronCapacityPhaseContext",
    "EnronCapacityPhaseResult",
    "capacity_policy",
    "export_capacity_decision",
    "hash_capacity_report",
    "run_enron_capacity",
    "verify_capacity_attempt_ledger",
    "verify_capacity_decision",
    "verify_capacity_report",
    "verify_capacity_run",
    "verify_portable_capacity_decision",
]

CAPACITY_REPORT_SCHEMA_VERSION = "nerb.enron_capacity_report.v1"
CAPACITY_POLICY_SCHEMA_VERSION = "nerb.enron_capacity_policy.v1"
CAPACITY_ATTEMPT_SCHEMA_VERSION = "nerb.enron_capacity_attempt.v1"
CAPACITY_INFLIGHT_SCHEMA_VERSION = "nerb.enron_capacity_inflight"
CAPACITY_STAGE_BINDING_SCHEMA_VERSION = "nerb.enron_capacity_stage_binding"
CAPACITY_CLEANUP_INVENTORY_SCHEMA_VERSION = "nerb.enron_capacity_cleanup_inventory"
CAPACITY_CLEANUP_INTENT_SCHEMA_VERSION = "nerb.enron_capacity_cleanup_intent"
CAPACITY_PORTABLE_DECISION_SCHEMA_VERSION = "nerb.enron_capacity_portable_decision"

ENRON_DATASET_ID = "corbt/enron-emails"
ENRON_DATASET_REVISION = "cfc06c758093d90993abce1a43668fb7357258a6"
ENRON_SOURCE_ROWS = 517_401
CAPACITY_PHASES = (
    "preparation",
    "split",
    "build",
    "streaming_validation",
    "deep_replay",
)

MAX_ABSOLUTE_RSS_BYTES = 8 * 1024**3
PHYSICAL_MEMORY_FRACTION_NUMERATOR = 3
PHYSICAL_MEMORY_FRACTION_DENOMINATOR = 4
PEAK_RSS_FRACTION_NUMERATOR = 3
PEAK_RSS_FRACTION_DENOMINATOR = 4
MIN_PREFLIGHT_FREE_DISK_BYTES = 25 * 1024**3
MAX_OWNED_DISK_BYTES = 20 * 1024**3
MIN_RUNTIME_FREE_DISK_BYTES = 5 * 1024**3
MAX_TOTAL_RUNTIME_NS = 4 * 60 * 60 * 1_000_000_000
MIN_PHASE_RECORDS_PER_SECOND = 100
MAX_CHECKPOINT_RECORD_GAP = 10_000
MAX_CHECKPOINTS_PER_PHASE = 1_024
MAX_PROGRESS_SIGNALS_PER_PHASE = 2_048
MAX_RESOURCE_SAMPLES_PER_PHASE = 256
PRODUCTION_MONITOR_INTERVAL_NS = 100_000_000
MAX_RESOURCE_OBSERVATION_WALL_GAP_NS = 500_000_000
MAX_RESOURCE_ACQUISITION_DURATION_NS = 500_000_000
RESOURCE_OBSERVER_START_TIMEOUT_NS = 5_000_000_000
RESOURCE_OBSERVER_COMMAND_TIMEOUT_NS = 2_000_000_000
PRODUCTION_WORKER_CLEANUP_GRACE_NS = 60_000_000_000
MAX_RESOURCE_OBSERVER_FRAME_BYTES = 4 * 1024
_RUNTIME_RESOURCE_ACQUISITION_MAX_ATTEMPTS = 3
_DARWIN_PS_TIMEOUT_SECONDS = 0.1
MAX_PROGRESS_CHECKPOINT_WALL_GAP_NS = 30_000_000_000
ACTIVITY_PRIVATE_TREE_VALIDATION_INTERVAL_NS = 5_000_000_000
MAX_CAPACITY_REPORT_BYTES = 4 * 1024 * 1024
MAX_PRODUCTION_WORKER_RESPONSE_BYTES = MAX_CAPACITY_REPORT_BYTES + 64 * 1024
MAX_ATTEMPT_RECEIPT_BYTES = 64 * 1024
MAX_INFLIGHT_RECORD_BYTES = 16 * 1024
MAX_PRIVATE_TREE_ENTRIES = _private_io._MAX_PRIVATE_TREE_ENTRIES  # noqa: SLF001
MAX_PRIVATE_TREE_DEPTH = _private_io._MAX_PRIVATE_TREE_DEPTH  # noqa: SLF001
MAX_RETAINED_PRIVATE_TOMBSTONES = 1_024
MAX_CLEANUP_INTENT_GENERATIONS = 128
MAX_RECOVERY_OUTPUT_PARENT_ENTRIES = 1_000_000
MAX_PORTABLE_DECISION_BYTES = 16 * 1024 * 1024
MAX_PORTABLE_ATTEMPTS = 1_024
MAX_LEDGER_TOMBSTONES = (MAX_CLEANUP_INTENT_GENERATIONS + 3) * MAX_PORTABLE_ATTEMPTS
MAX_READER_DISTRIBUTIONS = 4_096
MAX_DATASETS_DISTRIBUTION_FILES = 16_384
MAX_DATASETS_DISTRIBUTION_BYTES = 512 * 1024 * 1024

_REPORT_FILENAME = "capacity-report.json"
_COMMIT_FILENAME = "COMMITTED"
_COMMIT_PAYLOAD = _private_io._COMMIT_PAYLOAD  # noqa: SLF001
_REPORT_MEASUREMENT_BOUNDARY = "resource_observations_through_phase_execution_and_pre_report_staging_tree_scan"
_ATTEMPT_MEASUREMENT_BOUNDARY = (
    "resource_observations_through_report_write_fsync_staging_scan_atomic_promotion_and_promoted_final_tree_scan_"
    "before_attempt_append"
)
_PROCESSED_BYTES_MEASUREMENT_BOUNDARY = (
    "deterministic_logical_primary_artifact_bytes_excluding_repeated_verification_and_hash_passes"
)
_PINNED_DATASETS_VERSION = "5.0.0"
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_GIT_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_ATTEMPT_NAME_RE = re.compile(r"^attempt-([0-9]{8})\.json$")
_ATTEMPT_TEMP_RE = re.compile(r"^\.attempt-stage-[0-9a-f]{64}\.tmp$")
_INFLIGHT_NAME_RE = re.compile(r"^\.attempt-inflight-([0-9a-f]{64})\.json$")
_INFLIGHT_TEMP_RE = re.compile(r"^\.attempt-inflight-stage-([0-9a-f]{64})-[0-9a-f]{64}\.tmp$")
_STAGE_BINDING_NAME_RE = re.compile(r"^\.attempt-inflight-([0-9a-f]{64})\.stage\.json$")
_STAGE_BINDING_TEMP_RE = re.compile(r"^\.attempt-inflight-stage-binding-([0-9a-f]{64})-[0-9a-f]{64}\.tmp$")
_CLEANUP_INVENTORY_NAME_RE = re.compile(r"^\.attempt-inflight-([0-9a-f]{64})\.cleanup\.json$")
_CLEANUP_INVENTORY_TEMP_RE = re.compile(r"^\.attempt-inflight-cleanup-inventory-([0-9a-f]{64})-[0-9a-f]{64}\.tmp$")
_CLEANUP_INTENT_NAME_RE = re.compile(r"^\.attempt-inflight-([0-9a-f]{64})\.cleanup-intent-([0-9a-f]{64})\.json$")
_CLEANUP_INTENT_TEMP_RE = re.compile(r"^\.attempt-inflight-cleanup-intent-([0-9a-f]{64})-[0-9a-f]{64}\.tmp$")
_STAGE_TOKEN_RE = re.compile(r"^[0-9a-f]{24}$")
_PRIVATE_TOMBSTONE_RE = re.compile(r"^\.nerb-cleanup-[0-9a-f]{48}$")
_MAX_JSON_INTEGER_DIGITS = 256
_MAX_RESOURCE_INTEGER = 2**63 - 1
_MAX_CAPACITY_REPORT_STRUCTURAL_BOUND_BYTES = 512 * 1024 + len(CAPACITY_PHASES) * (
    MAX_RESOURCE_SAMPLES_PER_PHASE * 512
    + MAX_CHECKPOINTS_PER_PHASE * 160
    + MAX_PROGRESS_SIGNALS_PER_PHASE * 128
    + 16 * 1024
)
assert _MAX_CAPACITY_REPORT_STRUCTURAL_BOUND_BYTES < MAX_CAPACITY_REPORT_BYTES
_PRODUCTION_WORKER_ARGUMENT = "--nerb-capacity-production-worker"
_PRODUCTION_WORKER_ENV = "NERB_CAPACITY_FRESH_WORKER"
_DARWIN_PROCESS_FORK_SANDBOX_PROFILE = b"(version 1) (allow default) (deny process-fork)"
_DARWIN_PROCESS_CONTAINMENT = "darwin_sandbox_deny_process_fork"
_LINUX_PROCESS_CONTAINMENT = "linux_seccomp_deny_process_creation"
_FIXTURE_PROCESS_CONTAINMENT = "fixture_uncontained"
_RESOURCE_OBSERVER_PROTOCOL = "nerb.enron_capacity.resource_observer"
_BOOTSTRAP_ATTRIBUTE = "_nerb_capacity_bootstrap"
_BOOTSTRAP_SCHEMA = "nerb.enron_capacity.bootstrap.v1"
_CAPACITY_LAUNCHER_PATH = "scripts/run_enron_capacity.py"
_PRODUCTION_WORKER_BOOTSTRAP = (
    "import importlib.machinery,importlib.util,os,sys;"
    "source=sys.argv.pop(1);count=int(sys.argv.pop(1));"
    "roots=[sys.argv.pop(1) for _ in range(count)];"
    "observer_fd=int(sys.argv.pop(1));"
    "baseline=list(sys.path);"
    "path=os.path.join(source,'nerb','_capacity_bootstrap.py');"
    "loader=importlib.machinery.SourceFileLoader('_nerb_capacity_bootstrap_impl',path);"
    "spec=importlib.util.spec_from_file_location('_nerb_capacity_bootstrap_impl',path,loader=loader);"
    "module=importlib.util.module_from_spec(spec);sys.modules['_nerb_capacity_bootstrap_impl']=module;"
    "loader.exec_module(module);module.install(source);"
    "sys.path[:]=[*baseline,*roots,source];"
    "setattr(sys,'_nerb_capacity_bootstrap',"
    "{'schema':'nerb.enron_capacity.bootstrap.v1','source_root':source,'dependency_roots':roots,"
    "'baseline_path':baseline,'pycache_root':sys.pycache_prefix,'resource_observer_fd':observer_fd});"
    "sys.exit(module.run(source) "
    "if sys.argv==[sys.argv[0],'--nerb-capacity-production-worker'] else 2)"
)
_FRESH_PRODUCTION_WORKER = False
_PRODUCTION_PROCESS_CONTAINMENT: str | None = None
_PRODUCTION_GIT_COMMIT: str | None = None
_PRODUCTION_GIT_ROOT: Path | None = None
_PRODUCTION_RELEVANT_WORKTREE_PATHS: tuple[str, ...] | None = None
_PRODUCTION_CPU_MODEL: str | None = None
_PRODUCTION_PHYSICAL_MEMORY_BYTES: int | None = None
_PHASE_SCOPED_READER_LOADED = False
_PRODUCTION_CORE_SOURCE_NAMES = (
    "_capacity_bootstrap.py",
    "engine.py",
    "engines.py",
    "enron_activity.py",
    "enron_bank_builder.py",
    "enron_bank_workflow.py",
    "enron_capacity.py",
    "enron_preparation.py",
    "enron_private_io.py",
    "enron_quality.py",
    "enron_splitting.py",
)
_READER_MODULE_PREFIXES = ("datasets", "huggingface_hub", "httpx", "fsspec", "pyarrow", "transformers")
_READER_OFFICIAL_ENDPOINT = "https://huggingface.co"
_PHASE_RUNTIME_PATH_ENVIRONMENT_KEYS = frozenset(
    {
        "HOME",
        "TMPDIR",
        "TMP",
        "TEMP",
        "HF_HOME",
        "HF_DATASETS_CACHE",
        "HF_MODULES_CACHE",
        "HF_DATASETS_DOWNLOADED_DATASETS_PATH",
        "HF_DATASETS_EXTRACTED_DATASETS_PATH",
        "HUGGINGFACE_HUB_CACHE",
        "HF_HUB_CACHE",
        "HUGGINGFACE_ASSETS_CACHE",
        "HF_ASSETS_CACHE",
        "HF_XET_CACHE",
        "HF_TOKEN_PATH",
        "TRANSFORMERS_CACHE",
        "XDG_CACHE_HOME",
    }
)
_READER_POLICY_ENVIRONMENT = {
    "HF_ENDPOINT": _READER_OFFICIAL_ENDPOINT,
    "HF_HUB_DISABLE_IMPLICIT_TOKEN": "1",
    "HF_HUB_DISABLE_SYMLINKS": "1",
    "HF_HUB_DISABLE_TELEMETRY": "1",
    "HF_HUB_DISABLE_XET": "1",
    "HF_HUB_OFFLINE": "0",
    "HF_DATASETS_OFFLINE": "0",
    "TRANSFORMERS_OFFLINE": "0",
}
_READER_CREDENTIAL_ENVIRONMENT_KEYS = (
    "HF_TOKEN",
    "HUGGING_FACE_HUB_TOKEN",
    "HF_OIDC_RESOURCE",
    "HF_OIDC_ID_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_URL",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
)
_READER_EFFECTIVE_PATH_LABELS = (
    "datasets_xdg_cache_home",
    "datasets_hf_cache_home",
    "datasets_cache",
    "datasets_modules_cache",
    "datasets_downloads",
    "datasets_extracted",
    "hub_home",
    "hub_huggingface_cache",
    "hub_huggingface_assets_cache",
    "hub_cache",
    "hub_assets_cache",
    "hub_update_marker",
    "hub_agent_harnesses",
    "hub_token",
    "hub_stored_tokens",
    "hub_xet_cache",
)
_CRITICAL_READER_DISTRIBUTIONS = (
    ("datasets", "datasets", "datasets/__init__.py", "5.0.0"),
    ("huggingface-hub", "huggingface_hub", "huggingface_hub/__init__.py", "1.23.0"),
    ("httpx", "httpx", "httpx/__init__.py", "0.28.1"),
    ("fsspec", "fsspec", "fsspec/__init__.py", "2026.4.0"),
    ("pyarrow", "pyarrow", "pyarrow/__init__.py", "25.0.0"),
)
_READER_UPSTREAM_CACHE_LOCK_MODE = 0o664
_READER_OWNER_ONLY_CACHE_LOCK_MODE = 0o600
_ACTIVE_READER_CACHE_LOCK_ADAPTER: _ReaderCacheLockAdapter | None = None
_ACTIVE_READER_NETWORK_ACTIVITY_ADAPTER: _ReaderNetworkActivityAdapter | None = None
_NATIVE_BUILD_SOURCE_DOMAIN = b"nerb-native-build-source-v1\0"
_NATIVE_BUILD_SOURCE_FILES = (
    "Cargo.lock",
    "Cargo.toml",
    "build.rs",
    "src/bank.rs",
    "src/engine.rs",
    "src/error.rs",
    "src/flags.rs",
    "src/formats.rs",
    "src/ids.rs",
    "src/lib.rs",
    "src/match_buffer.rs",
)
_UNAVAILABLE_NATIVE_BUILD_SOURCE_SHA256 = (
    "sha256:" + hashlib.sha256(b"nerb/native-build-source-unavailable").hexdigest()
)


_ERROR_MESSAGES = {
    "capacity_failed": "Capacity run failed safely.",
    "options_invalid": "Capacity options are invalid.",
    "production_identity_invalid": "Capacity production implementation identity is invalid.",
    "production_integration_unavailable": "Capacity production phase integration is unavailable.",
    "phase_execution_failed": "Capacity phase execution failed safely.",
    "bank_candidate_observation_limit": "Capacity bank-build candidate observations exceed the frozen limit.",
    "bank_unique_candidate_limit": "Capacity bank-build unique candidates exceed the frozen limit.",
    "bank_private_scratch_bytes_limit": "Capacity bank-build private scratch use exceeds the frozen limit.",
    "bank_active_pattern_bytes_limit": "Capacity bank-build active-pattern bytes exceed the frozen limit.",
    "bank_json_bytes_limit": "Capacity bank canonical JSON bytes exceed the frozen limit.",
    "bank_active_compile_limit": "Capacity active bank failed native engine validation safely.",
    "phase_interrupted": "Capacity phase was interrupted safely.",
    "phase_result_invalid": "Capacity phase returned an invalid closed result.",
    "phase_commitment_invalid": "Capacity phase commitment chain is invalid.",
    "checkpoint_required": "Capacity phase omitted required progress checkpoints.",
    "checkpoint_gap": "Capacity phase checkpoint progress exceeds the frozen gap.",
    "checkpoint_invalid": "Capacity phase checkpoint progress is invalid.",
    "checkpoint_limit": "Capacity phase exceeds its checkpoint limit.",
    "checkpoint_wall_gap": "Capacity phase progress-checkpoint wall gap exceeds the frozen limit.",
    "resource_observation_gap": "Capacity resource-observation wall gap exceeds the frozen limit.",
    "resource_acquisition_timeout": "Capacity resource acquisition exceeds the frozen limit.",
    "watchdog_unsupported": "Capacity watchdog interruption is unsupported.",
    "rss_limit": "Capacity process-tree RSS exceeds the frozen limit.",
    "runtime_disk_floor": "Capacity filesystem free space fell below the frozen abort floor.",
    "owned_disk_limit": "Capacity owned-disk use exceeds the frozen limit.",
    "runtime_limit": "Capacity runtime exceeds the frozen limit.",
    "throughput_limit": "Capacity phase throughput is below the frozen minimum.",
    "resource_measurement_failed": "Capacity continuous resource measurement failed safely.",
    "rss_acquisition_exhausted": "Capacity process-tree RSS acquisition was exhausted safely.",
    "disk_acquisition_exhausted": "Capacity filesystem measurement acquisition was exhausted safely.",
    "monitor_shutdown_failed": "Capacity resource monitor shutdown failed safely.",
    "clock_invalid": "Capacity monotonic clock is invalid.",
    "private_tree_invalid": "Capacity private tree changed or became unsafe.",
    "owned_root_invalid": "Capacity owned output root is outside or unsafe for the transaction.",
    "preflight_memory": "Capacity physical-memory measurement is unsupported.",
    "preflight_rss": "Capacity process-tree RSS measurement is unsupported.",
    "preflight_disk": "Capacity disk measurement is unsupported.",
    "preflight_rss_limit": "Capacity process-tree RSS exceeds the frozen limit before execution.",
    "preflight_disk_limit": "Capacity preflight free space is below the frozen minimum.",
    "private_transaction_failed": "Capacity private transaction failed safely.",
    "report_invalid": "Capacity aggregate report is invalid.",
    "report_write_failed": "Capacity aggregate report could not be persisted safely.",
    "promotion_failed": "Capacity private output could not be promoted safely.",
    "attempt_ledger_invalid": "Capacity attempt ledger is invalid.",
    "attempt_ledger_write_failed": "Capacity attempt receipt could not be appended safely.",
    "runtime_filesystem_changed": "Capacity owned or evidence filesystem identity changed during execution.",
    "decision_invalid": "Capacity decision evidence is invalid.",
    "production_worker_failed": "Capacity production worker failed safely.",
    "worker_process_leak": "Capacity worker processes remained live at the terminal boundary.",
    "portable_decision_invalid": "Portable capacity decision evidence is invalid.",
    "portable_write_failed": "Portable capacity decision evidence could not be written safely.",
}

_BANK_BUILD_FAILURE_CODES = {
    "Candidate observations exceed the bank-build limit.": "bank_candidate_observation_limit",
    "Unique candidates exceed the bank-build limit.": "bank_unique_candidate_limit",
    "Private scratch tree exceeds its declared byte budget.": "bank_private_scratch_bytes_limit",
    "Curated bank exceeds the active-pattern byte limit.": "bank_active_pattern_bytes_limit",
    "Curated bank exceeds the canonical JSON byte limit.": "bank_json_bytes_limit",
    "Curated bank exceeds the canonical JSON byte limit after commitment binding.": "bank_json_bytes_limit",
    "Active bank failed Rust engine validation.": "bank_active_compile_limit",
}

_FAILURE_DIAGNOSTIC_FIELDS = frozenset(
    {
        "phase",
        "origin",
        "last_accepted_progress_kind",
        "attempted_progress_kind",
        "last_completed_records",
        "checkpoint_count",
        "progress_signal_count",
        "phase_wall_elapsed_ns",
        "observed_progress_gap_ns",
    }
)
_FAILURE_DIAGNOSTIC_ORIGINS = frozenset(
    {
        "continuous_observation",
        "checkpoint_call",
        "heartbeat_call",
        "activity_call",
        "phase_finish",
    }
)
_FAILURE_ACCEPTED_PROGRESS_KINDS = frozenset(
    {
        "phase_start",
        "checkpoint",
        "heartbeat",
        "activity",
    }
)
_FAILURE_ATTEMPT_BY_ORIGIN = {
    "continuous_observation": "continuous_observation",
    "checkpoint_call": "checkpoint",
    "heartbeat_call": "heartbeat",
    "activity_call": "activity",
    "phase_finish": "phase_finish",
}
_RESOURCE_FAILURE_DIAGNOSTIC_FIELDS = frozenset(
    {
        "diagnostic_kind",
        "phase",
        "sample_kind",
        "sequence",
        "observed_resource_gap_ns",
        "maximum_resource_gap_ns",
        "acquisition_duration_ns",
        "rss_duration_ns",
        "filesystem_duration_ns",
        "acquisition_retry_count",
        "scheduler_lateness_ns",
    }
)
_RESOURCE_SAMPLE_KINDS = frozenset(
    {"startup", "continuous", "boundary", "checkpoint", "heartbeat", "activity", "terminal"}
)


def _validated_resource_failure_diagnostic(value: object) -> dict[str, Any] | None:
    if not isinstance(value, dict) or set(value) != _RESOURCE_FAILURE_DIAGNOSTIC_FIELDS:
        return None
    candidate = cast(dict[str, Any], value)
    if (
        candidate.get("diagnostic_kind") != "resource_observation_gap"
        or (candidate.get("phase") is not None and candidate.get("phase") not in CAPACITY_PHASES)
        or candidate.get("sample_kind") not in _RESOURCE_SAMPLE_KINDS
        or candidate.get("maximum_resource_gap_ns") != MAX_RESOURCE_OBSERVATION_WALL_GAP_NS
    ):
        return None
    for field in (
        "sequence",
        "observed_resource_gap_ns",
        "maximum_resource_gap_ns",
        "acquisition_duration_ns",
        "rss_duration_ns",
        "filesystem_duration_ns",
        "acquisition_retry_count",
        "scheduler_lateness_ns",
    ):
        field_value = candidate.get(field)
        if type(field_value) is not int or field_value < 0 or field_value > _MAX_RESOURCE_INTEGER:
            return None
    if (
        int(candidate["sequence"]) <= 0
        or int(candidate["observed_resource_gap_ns"]) <= MAX_RESOURCE_OBSERVATION_WALL_GAP_NS
        or int(candidate["rss_duration_ns"]) + int(candidate["filesystem_duration_ns"])
        != int(candidate["acquisition_duration_ns"])
        or int(candidate["acquisition_retry_count"]) > 2 * (_RUNTIME_RESOURCE_ACQUISITION_MAX_ATTEMPTS - 1)
    ):
        return None
    return dict(candidate)


def _validated_failure_diagnostic(value: object) -> dict[str, Any] | None:
    resource = _validated_resource_failure_diagnostic(value)
    if resource is not None:
        return resource
    if not isinstance(value, dict) or set(value) != _FAILURE_DIAGNOSTIC_FIELDS:
        return None
    candidate = cast(dict[str, Any], value)
    origin = candidate.get("origin")
    if (
        candidate.get("phase") not in CAPACITY_PHASES
        or candidate.get("origin") not in _FAILURE_DIAGNOSTIC_ORIGINS
        or candidate.get("last_accepted_progress_kind") not in _FAILURE_ACCEPTED_PROGRESS_KINDS
        or candidate.get("attempted_progress_kind") != _FAILURE_ATTEMPT_BY_ORIGIN.get(cast(str, origin))
    ):
        return None
    for field in (
        "last_completed_records",
        "checkpoint_count",
        "progress_signal_count",
        "phase_wall_elapsed_ns",
        "observed_progress_gap_ns",
    ):
        field_value = candidate.get(field)
        if type(field_value) is not int or field_value < 0:
            return None
    if (
        int(candidate["last_completed_records"]) > ENRON_SOURCE_ROWS
        or int(candidate["checkpoint_count"]) > MAX_CHECKPOINTS_PER_PHASE
        or int(candidate["observed_progress_gap_ns"]) <= MAX_PROGRESS_CHECKPOINT_WALL_GAP_NS
        or int(candidate["phase_wall_elapsed_ns"]) < int(candidate["observed_progress_gap_ns"])
        or int(candidate["checkpoint_count"]) > int(candidate["progress_signal_count"])
        or (int(candidate["checkpoint_count"]) == 0) != (int(candidate["last_completed_records"]) == 0)
        or (candidate["last_accepted_progress_kind"] == "phase_start") != (int(candidate["progress_signal_count"]) == 0)
    ):
        return None
    return dict(candidate)


class EnronCapacityError(RuntimeError):
    """Raised when full-source capacity cannot be proved safely."""

    def __init__(
        self,
        message: str = _ERROR_MESSAGES["capacity_failed"],
        *,
        code: str = "capacity_failed",
        diagnostic: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.diagnostic = (
            _validated_failure_diagnostic(diagnostic)
            if code in {"checkpoint_wall_gap", "resource_observation_gap"}
            else None
        )


class _CapacityAbort(BaseException):
    """Internal payload-free phase abort that a checkpoint may raise."""

    def __init__(self, code: str) -> None:
        self.code = code if code in _ERROR_MESSAGES else "capacity_failed"


class _ProductionWorkerExchangeFailure(EnronCapacityError):
    """Bounded parent/worker exchange failure with cleanup-grace state."""

    def __init__(
        self,
        *,
        cleanup_deadline_ns: int | None = None,
        cleanup_grace_consumed: bool = False,
    ) -> None:
        super().__init__(_ERROR_MESSAGES["production_worker_failed"], code="production_worker_failed")
        self.cleanup_deadline_ns = cleanup_deadline_ns
        self.cleanup_grace_consumed = cleanup_grace_consumed


class _RuntimeDiskFloor(Exception):
    """Internal aggregate-only signal for a bracketed below-floor disk reading."""

    def __init__(self, minimum_free: int, output_disk: CapacityDiskUsage | None, retry_count: int) -> None:
        self.minimum_free = minimum_free
        self.output_disk = output_disk
        self.retry_count = retry_count


def _error(code: str, *, diagnostic: Mapping[str, Any] | None = None) -> EnronCapacityError:
    safe_code = code if code in _ERROR_MESSAGES else "capacity_failed"
    return EnronCapacityError(_ERROR_MESSAGES[safe_code], code=safe_code, diagnostic=diagnostic)


@dataclass(frozen=True, slots=True)
class CapacityDiskUsage:
    """Filesystem capacity observed at one resource checkpoint."""

    total: int
    used: int
    free: int


class CapacityResourceProbe(Protocol):
    """Resource measurement contract used by the private test seam."""

    def physical_memory_bytes(self) -> int | None: ...

    def process_tree_rss_bytes(self, root_pid: int) -> int | None: ...

    def disk_usage(self, path: Path) -> CapacityDiskUsage | None: ...

    def filesystem_device(self, path: Path) -> int | None: ...

    def monotonic_ns(self) -> int: ...


@dataclass(frozen=True, slots=True)
class EnronCapacityOptions:
    """Private destination, durable attempt ledger, and workspace policy."""

    output_dir: Path
    attempt_ledger_dir: Path
    workspace_root: Path | None = None
    allow_unignored_output: bool = False


@dataclass(frozen=True, slots=True)
class EnronCapacityPhaseResult:
    """Closed phase-specific aggregate returned by an internal phase runner."""

    records: int
    processed_bytes: int
    commitments: Mapping[str, Any]


class EnronCapacityPhaseContext:
    """Private phase workspace and mandatory progress/resource hooks."""

    __slots__ = (
        "_activity",
        "_checkpoint",
        "_cleanup_successor",
        "_declare_owned_root",
        "_heartbeat",
        "_owned_root_count",
        "_phase",
        "_prior_commitment",
        "_runtime_environment",
        "_scratch_dir",
        "_spool_dir",
        "_work_dir",
    )

    def __init__(
        self,
        phase: str,
        work_dir: Path,
        checkpoint: Callable[[int], None],
        declare_owned_root: Callable[[Path], Path],
        heartbeat: Callable[[], None],
        activity: Callable[[], None],
        *,
        runtime_environment: Mapping[str, str],
        scratch_dir: Path,
        spool_dir: Path,
        owned_root_count: int,
        cleanup_successor: PrivateRun | None = None,
        prior_commitment: Mapping[str, Any] | None = None,
    ) -> None:
        self._phase = phase
        self._work_dir = work_dir
        self._checkpoint = checkpoint
        self._declare_owned_root = declare_owned_root
        self._heartbeat = heartbeat
        self._activity = activity
        self._runtime_environment = dict(runtime_environment)
        self._scratch_dir = scratch_dir
        self._spool_dir = spool_dir
        self._owned_root_count = owned_root_count
        self._cleanup_successor = cleanup_successor
        self._prior_commitment = None if prior_commitment is None else dict(prior_commitment)

    @property
    def phase(self) -> str:
        return self._phase

    @property
    def work_dir(self) -> Path:
        """Existing private root owned by this phase."""

        return self._work_dir

    @property
    def owned_root_count(self) -> int:
        return self._owned_root_count

    @property
    def scratch_dir(self) -> Path:
        """Existing accounted scratch root for explicit adapter spools."""

        return self._scratch_dir

    @property
    def spool_dir(self) -> Path:
        """Existing accounted root for disk-backed phase state."""

        return self._spool_dir

    @property
    def runtime_environment(self) -> dict[str, str]:
        """TMP/cache environment whose values are all phase-owned roots."""

        return dict(self._runtime_environment)

    @property
    def prior_commitment(self) -> dict[str, Any] | None:
        """Return the already-validated preceding aggregate commitment, if any."""

        return None if self._prior_commitment is None else dict(self._prior_commitment)

    @property
    def cleanup_successor(self) -> PrivateRun | None:
        """Outer transaction that retains sensitive phase inodes through final commit."""

        return self._cleanup_successor

    def checkpoint(self, completed_records: int) -> None:
        """Commit progress and synchronously enforce every resource gate."""

        self._checkpoint(completed_records)

    def heartbeat(self) -> None:
        """Prove liveness during bounded non-record work without inflating progress."""

        self._heartbeat()

    def activity(self) -> None:
        """Report genuine work while rate-limiting synchronous resource scans."""

        self._activity()

    def declare_owned_root(self, path: Path) -> Path:
        """Register an additional existing root inside the transaction."""

        registered = self._declare_owned_root(path)
        self._owned_root_count += 1
        return registered


CapacityPhaseRunner = Callable[[EnronCapacityPhaseContext], EnronCapacityPhaseResult]


class _SystemResourceProbe:
    def physical_memory_bytes(self) -> int | None:
        if _PRODUCTION_PROCESS_CONTAINMENT is not None:
            value = _PRODUCTION_PHYSICAL_MEMORY_BYTES
            return value if type(value) is int and value > 0 else None
        try:
            pages = os.sysconf("SC_PHYS_PAGES")
            page_size = os.sysconf("SC_PAGE_SIZE")
            value = int(pages) * int(page_size)
        except (AttributeError, OSError, TypeError, ValueError):
            value = 0
        if value > 0:
            return value
        if sys.platform == "darwin":
            try:
                completed = subprocess.run(
                    ["sysctl", "-n", "hw.memsize"],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=2,
                )
                value = int(completed.stdout.strip()) if completed.returncode == 0 else 0
            except (OSError, subprocess.SubprocessError, TypeError, ValueError):
                value = 0
        return value if value > 0 else None

    def process_tree_rss_bytes(self, root_pid: int) -> int | None:
        if sys.platform.startswith("linux"):
            current = _linux_process_tree_rss_bytes(root_pid)
        elif sys.platform == "darwin":
            # The production worker cannot have descendants after its
            # process-creation fence is installed.  Avoid spawning ``ps``
            # from that fenced process; the launcher independently measures
            # the complete launcher/worker tree throughout the run.
            current = (
                _root_process_peak_rss_bytes()
                if _PRODUCTION_PROCESS_CONTAINMENT is not None and root_pid == os.getpid()
                else _darwin_process_tree_rss_bytes(root_pid)
            )
        else:
            current = None
        if current is None:
            return None
        root_peak = _root_process_peak_rss_bytes()
        return max(current, root_peak) if root_peak is not None else current

    def disk_usage(self, path: Path) -> CapacityDiskUsage | None:
        try:
            usage = shutil.disk_usage(path)
        except OSError:
            return None
        return CapacityDiskUsage(total=int(usage.total), used=int(usage.used), free=int(usage.free))

    def filesystem_device(self, path: Path) -> int | None:
        try:
            info = path.lstat()
        except OSError:
            return None
        return int(info.st_dev) if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) else None

    def monotonic_ns(self) -> int:
        return time.monotonic_ns()


def _linux_process_tree_rss_bytes(root_pid: int, *, proc_root: Path = Path("/proc")) -> int | None:
    pending = [root_pid]
    seen: set[int] = set()
    total_kib = 0
    root_seen = False
    while pending:
        pid = pending.pop()
        if pid in seen:
            continue
        seen.add(pid)
        proc = proc_root / str(pid)
        try:
            status = (proc / "status").read_text(encoding="ascii", errors="strict")
        except FileNotFoundError:
            if pid == root_pid:
                return None
            continue
        except (OSError, UnicodeError):
            return None
        rss_kib: int | None = None
        for line in status.splitlines():
            if line.startswith("VmRSS:"):
                fields = line.split()
                if len(fields) != 3 or fields[2] != "kB":
                    return None
                try:
                    rss_kib = int(fields[1])
                except ValueError:
                    return None
                break
        if rss_kib is None or rss_kib <= 0:
            return None
        total_kib += rss_kib
        root_seen = root_seen or pid == root_pid
        task_root = proc / "task"
        try:
            tasks = tuple(task_root.iterdir())
        except FileNotFoundError:
            if pid == root_pid:
                return None
            continue
        except OSError:
            return None
        if not tasks:
            return None
        for task in tasks:
            try:
                tid = int(task.name)
                if tid <= 0:
                    return None
                raw_children = (task / "children").read_text(encoding="ascii", errors="strict")
                children = tuple(int(value) for value in raw_children.split())
            except FileNotFoundError:
                continue
            except (OSError, UnicodeError, ValueError):
                return None
            if any(child <= 0 for child in children):
                return None
            pending.extend(children)
    return total_kib * 1024 if root_seen and total_kib > 0 else None


def _darwin_process_tree_rss_bytes(root_pid: int) -> int | None:
    try:
        completed = subprocess.run(
            ["/bin/ps", "-axo", "pid=,ppid=,rss="],
            check=False,
            capture_output=True,
            encoding="ascii",
            env={"LC_ALL": "C"},
            errors="strict",
            text=True,
            timeout=_DARWIN_PS_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return None
    if completed.returncode != 0:
        return None
    parents: dict[int, int] = {}
    rss_by_pid: dict[int, int] = {}
    for line in completed.stdout.splitlines():
        fields = line.split()
        if len(fields) != 3 or any(
            not value.isascii() or not value.isdecimal() or len(value) > len(str(_MAX_RESOURCE_INTEGER))
            for value in fields
        ):
            return None
        pid, parent, rss_kib = (int(value) for value in fields)
        if pid <= 0 or parent < 0 or rss_kib < 0 or max(pid, parent, rss_kib) > _MAX_RESOURCE_INTEGER or pid in parents:
            return None
        parents[pid] = parent
        rss_by_pid[pid] = rss_kib
    if root_pid not in rss_by_pid or rss_by_pid[root_pid] <= 0:
        return None
    descendants = {root_pid}
    changed = True
    while changed:
        changed = False
        for pid, parent in parents.items():
            if pid not in descendants and parent in descendants:
                descendants.add(pid)
                changed = True
    total_kib = sum(rss_by_pid[pid] for pid in descendants)
    return total_kib * 1024 if total_kib <= _MAX_RESOURCE_INTEGER // 1024 else None


def _root_process_peak_rss_bytes() -> int | None:
    """Conservatively combine root and reaped-child kernel RSS high-water."""

    try:
        root = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        reaped_children = int(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
    except (OSError, TypeError, ValueError):
        return None
    if root <= 0 or reaped_children < 0:
        return None
    scale = 1 if sys.platform == "darwin" else 1024
    return (root + reaped_children) * scale


@dataclass(frozen=True, slots=True)
class _ProcessRecord:
    parent_pid: int
    process_group_id: int
    start_identity: str
    rss_bytes: int


@dataclass(frozen=True, slots=True)
class _TerminalProcessSnapshot:
    worker_tree_rss_bytes: int
    residuals: tuple[tuple[int, str], ...]


def _process_descendants(processes: Mapping[int, _ProcessRecord], root_pid: int) -> set[int] | None:
    if root_pid not in processes:
        return None
    descendants = {root_pid}
    changed = True
    while changed:
        changed = False
        for pid, record in processes.items():
            if pid not in descendants and record.parent_pid in descendants:
                descendants.add(pid)
                changed = True
    descendants.remove(root_pid)
    return descendants


def _linux_process_record(entry: Path, pid: int, *, page_size: int) -> _ProcessRecord | None:
    try:
        raw = (entry / "stat").read_bytes()
    except FileNotFoundError:
        return None
    except OSError:
        raise _error("resource_measurement_failed") from None
    opening = raw.find(b"(")
    closing = raw.rfind(b")")
    fields = raw[closing + 1 :].split() if opening > 0 and closing > opening else []
    raw_pid = raw[:opening].strip() if opening > 0 else b""
    numeric_fields = (fields[1], fields[2], fields[19], fields[21]) if len(fields) > 21 else ()
    if (
        not raw_pid.isascii()
        or not raw_pid.isdigit()
        or int(raw_pid) != pid
        or len(numeric_fields) != 4
        or any(not value.isascii() or not value.isdigit() for value in numeric_fields)
    ):
        raise _error("resource_measurement_failed")
    parent, process_group_id, start_time, resident_pages = (int(value) for value in numeric_fields)
    if (
        min(parent, process_group_id, resident_pages) < 0
        or start_time <= 0
        or max(parent, process_group_id, start_time, resident_pages) > _MAX_RESOURCE_INTEGER
        or resident_pages > _MAX_RESOURCE_INTEGER // page_size
    ):
        raise _error("resource_measurement_failed")
    return _ProcessRecord(
        parent_pid=parent,
        process_group_id=process_group_id,
        start_identity=str(start_time),
        rss_bytes=resident_pages * page_size,
    )


def _linux_process_table() -> dict[int, _ProcessRecord] | None:
    try:
        process_entries = tuple(Path("/proc").iterdir())
        page_size = int(os.sysconf("SC_PAGE_SIZE"))
    except (OSError, TypeError, ValueError):
        return None
    if page_size <= 0 or page_size > _MAX_RESOURCE_INTEGER:
        return None
    processes: dict[int, _ProcessRecord] = {}
    for entry in process_entries:
        if not entry.name.isascii() or not entry.name.isdecimal():
            continue
        pid = int(entry.name)
        if pid <= 0 or pid > _MAX_RESOURCE_INTEGER:
            return None
        try:
            record = _linux_process_record(entry, pid, page_size=page_size)
        except EnronCapacityError:
            return None
        if record is not None:
            if pid in processes:
                return None
            processes[pid] = record
    return processes


def _darwin_process_table() -> dict[int, _ProcessRecord] | None:
    process: subprocess.Popen[str] | None = None
    try:
        process = subprocess.Popen(
            ["/bin/ps", "-axo", "pid=,ppid=,pgid=,rss=,lstart="],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            encoding="ascii",
            env={"LC_ALL": "C"},
            errors="strict",
            text=True,
        )
        stdout, _stderr = process.communicate(timeout=_DARWIN_PS_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        if process is not None:
            try:
                process.kill()
                process.communicate(timeout=_DARWIN_PS_TIMEOUT_SECONDS)
            except (OSError, subprocess.SubprocessError, UnicodeError):
                pass
        return None
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return None
    if process.returncode != 0:
        return None
    return _parse_darwin_process_table(stdout, excluded_pid=process.pid)


def _parse_darwin_process_table(stdout: str, *, excluded_pid: int | None = None) -> dict[int, _ProcessRecord] | None:
    processes: dict[int, _ProcessRecord] = {}
    for line in stdout.splitlines():
        fields = line.split()
        if len(fields) != 9 or any(
            not value.isascii() or not value.isdecimal() or len(value) > len(str(_MAX_RESOURCE_INTEGER))
            for value in fields[:4]
        ):
            return None
        pid, parent, process_group_id, rss_kib = (int(value) for value in fields[:4])
        start_identity = " ".join(fields[4:])
        if (
            pid <= 0
            or parent < 0
            or process_group_id <= 0
            or rss_kib < 0
            or max(pid, parent, process_group_id, rss_kib) > _MAX_RESOURCE_INTEGER
            or rss_kib > _MAX_RESOURCE_INTEGER // 1024
            or not start_identity.isascii()
            or len(start_identity) > 64
            or pid in processes
        ):
            return None
        processes[pid] = _ProcessRecord(
            parent_pid=parent,
            process_group_id=process_group_id,
            start_identity=start_identity,
            rss_bytes=rss_kib * 1024,
        )
    if excluded_pid is not None:
        processes.pop(excluded_pid, None)
    return processes


def _process_table() -> dict[int, _ProcessRecord] | None:
    if sys.platform.startswith("linux"):
        return _linux_process_table()
    if sys.platform == "darwin":
        return _darwin_process_table()
    return None


def _terminal_process_snapshot(worker_pid: int) -> _TerminalProcessSnapshot | None:
    if type(worker_pid) is not int or worker_pid <= 1:
        return None
    processes = _process_table()
    if processes is None:
        return None
    worker = processes.get(worker_pid)
    worker_descendants = _process_descendants(processes, worker_pid)
    if worker is None or worker_descendants is None or worker.process_group_id != worker_pid:
        return None
    residual = set(worker_descendants)
    residual.update(
        pid for pid, record in processes.items() if pid != worker_pid and record.process_group_id == worker_pid
    )
    measured_processes = {worker_pid, *worker_descendants, *residual}
    worker_tree_rss = sum(processes[pid].rss_bytes for pid in measured_processes)
    if worker_tree_rss <= 0 or worker_tree_rss > _MAX_RESOURCE_INTEGER:
        return None
    return _TerminalProcessSnapshot(
        worker_tree_rss_bytes=worker_tree_rss,
        residuals=tuple((pid, processes[pid].start_identity) for pid in sorted(residual)),
    )


def _terminal_residual_process_pids(worker_pid: int) -> tuple[int, ...] | None:
    snapshot = _terminal_process_snapshot(worker_pid)
    return None if snapshot is None else tuple(pid for pid, _identity in snapshot.residuals)


def _expected_process_containment_mode() -> str:
    if sys.platform.startswith("linux"):
        return _LINUX_PROCESS_CONTAINMENT
    if sys.platform == "darwin":
        return _DARWIN_PROCESS_CONTAINMENT
    raise _error("production_identity_invalid")


class _LinuxSockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    ]


class _LinuxSockFprog(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_ushort),
        ("filters", ctypes.POINTER(_LinuxSockFilter)),
    ]


def _linux_process_creation_filter(machine: str | None = None) -> tuple[Any, _LinuxSockFprog]:
    machine = platform.machine().lower() if machine is None else machine.lower()
    fork_numbers: tuple[int, ...]
    reject_x32 = False
    if machine in {"x86_64", "amd64"}:
        audit_arch = 0xC000003E
        clone_nr = 56
        fork_numbers = (57, 58)
        reject_x32 = True
    elif machine in {"aarch64", "arm64"}:
        audit_arch = 0xC00000B7
        clone_nr = 220
        fork_numbers = ()
    else:
        raise _error("production_identity_invalid")

    bpf_load_word_absolute = 0x20
    bpf_jump_equal_constant = 0x15
    bpf_jump_greater_or_equal_constant = 0x35
    bpf_and_constant = 0x54
    bpf_return_constant = 0x06
    seccomp_data_arch_offset = 4
    seccomp_data_number_offset = 0
    seccomp_data_first_argument_offset = 16
    seccomp_return_kill_process = 0x80000000
    seccomp_return_allow = 0x7FFF0000
    seccomp_return_errno = 0x00050000
    clone_thread = 0x00010000
    clone3_nr = 435
    x32_syscall_bit = 0x40000000

    filters = [
        _LinuxSockFilter(bpf_load_word_absolute, 0, 0, seccomp_data_arch_offset),
        _LinuxSockFilter(bpf_jump_equal_constant, 1, 0, audit_arch),
        _LinuxSockFilter(bpf_return_constant, 0, 0, seccomp_return_kill_process),
        _LinuxSockFilter(bpf_load_word_absolute, 0, 0, seccomp_data_number_offset),
    ]
    if reject_x32:
        filters.extend(
            (
                _LinuxSockFilter(bpf_jump_greater_or_equal_constant, 0, 1, x32_syscall_bit),
                _LinuxSockFilter(bpf_return_constant, 0, 0, seccomp_return_errno | errno.EPERM),
            )
        )
    for syscall_number in fork_numbers:
        filters.extend(
            (
                _LinuxSockFilter(bpf_jump_equal_constant, 0, 1, syscall_number),
                _LinuxSockFilter(bpf_return_constant, 0, 0, seccomp_return_errno | errno.EPERM),
            )
        )
    filters.extend(
        (
            _LinuxSockFilter(bpf_jump_equal_constant, 0, 1, clone3_nr),
            _LinuxSockFilter(bpf_return_constant, 0, 0, seccomp_return_errno | errno.ENOSYS),
            _LinuxSockFilter(bpf_jump_equal_constant, 0, 4, clone_nr),
            _LinuxSockFilter(bpf_load_word_absolute, 0, 0, seccomp_data_first_argument_offset),
            _LinuxSockFilter(bpf_and_constant, 0, 0, clone_thread),
            _LinuxSockFilter(bpf_jump_equal_constant, 1, 0, clone_thread),
            _LinuxSockFilter(bpf_return_constant, 0, 0, seccomp_return_errno | errno.EPERM),
            _LinuxSockFilter(bpf_return_constant, 0, 0, seccomp_return_allow),
        )
    )
    array_type = _LinuxSockFilter * len(filters)
    filter_array = array_type(*filters)
    program = _LinuxSockFprog(
        length=len(filters),
        filters=ctypes.cast(filter_array, ctypes.POINTER(_LinuxSockFilter)),
    )
    return filter_array, program


def _process_containment_policy_sha256(mode: str, architecture: str) -> str:
    if mode == _FIXTURE_PROCESS_CONTAINMENT and architecture == "not_applicable":
        policy: dict[str, Any] = {"mode": mode, "architecture": architecture}
    elif mode == _LINUX_PROCESS_CONTAINMENT:
        instructions, _program = _linux_process_creation_filter(architecture)
        policy = {
            "mode": mode,
            "architecture": architecture,
            "instructions": [
                {"code": int(item.code), "jt": int(item.jt), "jf": int(item.jf), "k": int(item.k)}
                for item in instructions
            ],
        }
    elif mode == _DARWIN_PROCESS_CONTAINMENT and architecture in {"arm64", "aarch64", "x86_64"}:
        policy = {
            "mode": mode,
            "architecture": architecture,
            "sandbox_profile_sha256": _hash_bytes(_DARWIN_PROCESS_FORK_SANDBOX_PROFILE),
        }
    else:
        raise _error("production_identity_invalid")
    return _canonical_hash(policy)


def _process_containment_identity(*, production: bool) -> dict[str, Any]:
    if not production:
        architecture = "not_applicable"
        return {
            "mode": _FIXTURE_PROCESS_CONTAINMENT,
            "architecture": architecture,
            "policy_sha256": _process_containment_policy_sha256(_FIXTURE_PROCESS_CONTAINMENT, architecture),
            "installed_before_workload": False,
            "runtime_attested": False,
        }
    mode = _expected_process_containment_mode()
    architecture = platform.machine().lower()
    return {
        "mode": mode,
        "architecture": architecture,
        "policy_sha256": _process_containment_policy_sha256(mode, architecture),
        "installed_before_workload": True,
        "runtime_attested": True,
    }


def _install_linux_process_creation_filter() -> None:
    if not sys.platform.startswith("linux"):
        raise _error("production_identity_invalid")
    try:
        tasks = tuple((Path("/proc") / "self" / "task").iterdir())
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
        libc.prctl.restype = ctypes.c_int
    except (AttributeError, OSError):
        raise _error("production_identity_invalid") from None
    if len(tasks) != 1:
        raise _error("production_identity_invalid")
    _filter_array, program = _linux_process_creation_filter()
    if libc.prctl(38, 1, 0, 0, 0) != 0 or libc.prctl(39, 0, 0, 0, 0) != 1:
        raise _error("production_identity_invalid")
    if libc.prctl(22, 2, ctypes.addressof(program), 0, 0) != 0 or libc.prctl(21, 0, 0, 0, 0) != 2:
        raise _error("production_identity_invalid")
    if platform.machine().lower() in {"x86_64", "amd64"}:
        libc.syscall.restype = ctypes.c_long
        ctypes.set_errno(0)
        result = libc.syscall(ctypes.c_long(0x40000000 | 57))
        if result != -1 or ctypes.get_errno() != errno.EPERM:
            raise _error("production_identity_invalid")


def _attest_process_creation_denied() -> None:
    try:
        child_pid = os.fork()
    except OSError as exc:
        if exc.errno != errno.EPERM:
            raise _error("production_identity_invalid") from None
    else:
        if child_pid == 0:
            os._exit(193)
        try:
            os.waitpid(child_pid, 0)
        except OSError:
            pass
        raise _error("production_identity_invalid")
    try:
        spawned_pid = os.posix_spawn("/bin/true", ["/bin/true"], {})
    except OSError as exc:
        if exc.errno != errno.EPERM:
            raise _error("production_identity_invalid") from None
    else:
        try:
            os.waitpid(spawned_pid, 0)
        except OSError:
            pass
        raise _error("production_identity_invalid")
    try:
        subprocess.run(
            ["/bin/true"],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=1,
        )
    except OSError as exc:
        if exc.errno != errno.EPERM:
            raise _error("production_identity_invalid") from None
    else:
        raise _error("production_identity_invalid")
    thread = threading.Thread(target=lambda: None)
    try:
        thread.start()
        thread.join(1)
    except RuntimeError:
        raise _error("production_identity_invalid") from None
    if thread.is_alive():
        raise _error("production_identity_invalid")


def _prepare_production_subprocess_context() -> None:
    """Cache subprocess-derived facts before the production process fence."""

    global _PRODUCTION_CPU_MODEL
    global _PRODUCTION_GIT_COMMIT
    global _PRODUCTION_GIT_ROOT
    global _PRODUCTION_PHYSICAL_MEMORY_BYTES
    global _PRODUCTION_RELEVANT_WORKTREE_PATHS
    if (
        not _FRESH_PRODUCTION_WORKER
        or _PRODUCTION_PROCESS_CONTAINMENT is not None
        or _PRODUCTION_GIT_COMMIT is not None
        or _PRODUCTION_GIT_ROOT is not None
        or _PRODUCTION_RELEVANT_WORKTREE_PATHS is not None
        or _PRODUCTION_CPU_MODEL is not None
        or _PRODUCTION_PHYSICAL_MEMORY_BYTES is not None
    ):
        raise _error("production_identity_invalid")
    git_root = _git_root()
    git_commit = _git_head()
    relevant_paths = _relevant_tracked_worktree_paths()
    if relevant_paths != _relevant_module_paths_at_commit(git_commit):
        raise _error("production_identity_invalid")
    cpu_model = _cpu_model()
    physical_memory = _SystemResourceProbe().physical_memory_bytes()
    if not relevant_paths or type(physical_memory) is not int or physical_memory <= 0:
        raise _error("production_identity_invalid")
    _PRODUCTION_GIT_COMMIT = git_commit
    _PRODUCTION_GIT_ROOT = git_root
    _PRODUCTION_RELEVANT_WORKTREE_PATHS = relevant_paths
    _PRODUCTION_CPU_MODEL = cpu_model
    _PRODUCTION_PHYSICAL_MEMORY_BYTES = physical_memory


def _install_production_process_containment(expected_mode: str) -> None:
    global _PRODUCTION_PROCESS_CONTAINMENT
    if _PRODUCTION_PROCESS_CONTAINMENT is not None or expected_mode != _expected_process_containment_mode():
        raise _error("production_identity_invalid")
    if _FRESH_PRODUCTION_WORKER and (
        _PRODUCTION_GIT_COMMIT is None
        or _PRODUCTION_GIT_ROOT is None
        or _PRODUCTION_RELEVANT_WORKTREE_PATHS is None
        or _PRODUCTION_CPU_MODEL is None
        or _PRODUCTION_PHYSICAL_MEMORY_BYTES is None
    ):
        raise _error("production_identity_invalid")
    if _FRESH_PRODUCTION_WORKER:
        _require_globally_clean_checkout(cast(str, _PRODUCTION_GIT_COMMIT))
    if _terminal_residual_process_pids(os.getpid()) != ():
        raise _error("production_identity_invalid")
    if sys.platform.startswith("linux"):
        _install_linux_process_creation_filter()
    elif sys.platform == "darwin":
        try:
            sandbox = ctypes.CDLL("/usr/lib/libsandbox.dylib", use_errno=True)
            sandbox.sandbox_init.argtypes = [ctypes.c_char_p, ctypes.c_uint64, ctypes.POINTER(ctypes.c_char_p)]
            sandbox.sandbox_init.restype = ctypes.c_int
            sandbox.sandbox_free_error.argtypes = [ctypes.c_char_p]
            sandbox.sandbox_free_error.restype = None
        except (AttributeError, OSError):
            raise _error("production_identity_invalid") from None
        error_buffer = ctypes.c_char_p()
        result = -1
        try:
            result = sandbox.sandbox_init(
                _DARWIN_PROCESS_FORK_SANDBOX_PROFILE,
                0,
                ctypes.byref(error_buffer),
            )
        finally:
            if error_buffer.value is not None:
                sandbox.sandbox_free_error(error_buffer)
        if result != 0:
            raise _error("production_identity_invalid")
    else:
        raise _error("production_identity_invalid")
    _attest_process_creation_denied()
    _PRODUCTION_PROCESS_CONTAINMENT = expected_mode


def _activate_process_creation_guard(
    execution: Mapping[str, Any],
    *,
    production_evidence: bool,
    process_creation_guard: Callable[[], None] | None,
) -> None:
    if not production_evidence:
        if process_creation_guard is not None:
            raise _error("capacity_failed")
        return
    if process_creation_guard is None:
        raise _error("production_identity_invalid")
    try:
        process_creation_guard()
    except EnronCapacityError:
        raise
    except BaseException:
        raise _error("production_identity_invalid") from None
    containment = execution.get("process_containment")
    mode = containment.get("mode") if isinstance(containment, Mapping) else None
    if _PRODUCTION_PROCESS_CONTAINMENT != mode:
        raise _error("production_identity_invalid")


@dataclass(frozen=True, slots=True)
class _DirectoryIdentity:
    device: int
    inode: int
    mode: int
    owner: int


_DescriptorIdentity = tuple[int, int, int]


def _descriptor_identity(info: os.stat_result) -> _DescriptorIdentity:
    return int(info.st_dev), int(info.st_ino), stat.S_IFMT(info.st_mode)


def _close_owned_descriptor_to_completion(
    descriptor: int,
    _expected: _DescriptorIdentity,
    attempted: bytearray,
) -> BaseException | None:
    """Retire one owned fd with a native, GIL-held syscall commit byte."""

    first_error: BaseException | None = None
    if attempted != bytearray(b"\x00"):
        return None
    while True:
        try:
            close_errno = _native_engine._close_fd_once(attempted, descriptor)
        except (KeyboardInterrupt, SystemExit) as exc:
            if first_error is None:
                first_error = exc
            if attempted == bytearray(b"\x00"):
                continue
            return first_error
        if attempted != bytearray(b"\x01"):
            raise _error("private_tree_invalid")
        if close_errno and first_error is None:
            first_error = OSError(close_errno, os.strerror(close_errno))
        return first_error


class _OwnedDescriptor:
    """RAII owner for one descriptor acquired by the native open primitive."""

    def __init__(self) -> None:
        self._opened_fd = bytearray((-1).to_bytes(4, byteorder=sys.byteorder, signed=True))
        self._identity: _DescriptorIdentity | None = None
        self._close_attempted = bytearray(1)
        self._cleanup_dir_fd: int | None = None
        self._cleanup_name: str | None = None

    def __del__(self) -> None:
        try:
            if getattr(self, "_cleanup_name", None) is not None:
                try:
                    self.abort_private_path()
                except BaseException:
                    self._cleanup_dir_fd = None
                    self._cleanup_name = None
            while not getattr(self, "closed", True):
                try:
                    self.close()
                except BaseException:
                    continue
        except BaseException:
            pass

    @property
    def fd(self) -> int:
        descriptor = _opened_descriptor_value(self._opened_fd)
        if descriptor < 0 or self._close_attempted != bytearray(b"\x00"):
            raise _error("private_tree_invalid")
        return descriptor

    @property
    def identity(self) -> _DescriptorIdentity:
        if self._identity is None:
            raise _error("private_tree_invalid")
        return self._identity

    @property
    def closed(self) -> bool:
        return _opened_descriptor_value(self._opened_fd) < 0 or self._close_attempted != bytearray(b"\x00")

    def bind_identity(self, identity: _DescriptorIdentity) -> None:
        if self.closed or self._identity is not None:
            raise _error("private_tree_invalid")
        self._identity = identity

    def configure_private_path_cleanup(self, directory_fd: int, name: str) -> None:
        if self._cleanup_name is not None or not isinstance(name, str) or not name:
            raise _error("attempt_ledger_invalid")
        self._cleanup_dir_fd = directory_fd
        self._cleanup_name = name

    def disarm_private_path_cleanup(self) -> None:
        self._cleanup_dir_fd = None
        self._cleanup_name = None

    @property
    def private_path_cleanup_armed(self) -> bool:
        return self._cleanup_dir_fd is not None and self._cleanup_name is not None

    def abort_private_path(self) -> None:
        directory_fd = self._cleanup_dir_fd
        name = self._cleanup_name
        if directory_fd is None or name is None:
            return
        if not self.closed:
            descriptor = self.fd
            identity = _regular_file_identity(os.fstat(descriptor))
            _wipe_and_quarantine_private_file_at(directory_fd, name, descriptor, identity)
        self.disarm_private_path_cleanup()

    def close(self) -> None:
        first_control: KeyboardInterrupt | SystemExit | None = None
        while not self.closed:
            descriptor = _opened_descriptor_value(self._opened_fd)
            if descriptor < 0:
                break
            try:
                if self._identity is None:
                    close_errno = _native_engine._close_fd_once(self._close_attempted, descriptor)
                    close_error: BaseException | None = (
                        None if not close_errno else OSError(close_errno, os.strerror(close_errno))
                    )
                else:
                    close_error = _close_owned_descriptor_to_completion(
                        descriptor,
                        self._identity,
                        self._close_attempted,
                    )
            except (KeyboardInterrupt, SystemExit) as exc:
                if first_control is None:
                    first_control = exc
                if self._close_attempted == bytearray(b"\x00"):
                    continue
                close_error = None
            if self._close_attempted == bytearray(b"\x00"):
                continue
            self._opened_fd[:] = (-1).to_bytes(4, byteorder=sys.byteorder, signed=True)
            if isinstance(close_error, (KeyboardInterrupt, SystemExit)) and first_control is None:
                first_control = close_error
        if first_control is not None:
            raise first_control


def _close_owned_descriptor_during_unwind(owner: _OwnedDescriptor) -> BaseException | None:
    """Settle descriptor authority while preserving the first injected control."""

    first_control: BaseException | None = None
    while not owner.closed:
        try:
            owner.close()
        except (KeyboardInterrupt, SystemExit, MemoryError) as exc:
            if first_control is None:
                first_control = exc
    return first_control


def _abort_private_owner_during_unwind(owner: _OwnedDescriptor) -> BaseException | None:
    """Best-effort wipe an unpublished private path, then settle its descriptor."""

    first_control: BaseException | None = None
    while owner.private_path_cleanup_armed:
        try:
            owner.abort_private_path()
        except (KeyboardInterrupt, SystemExit, MemoryError) as exc:
            if first_control is None:
                first_control = exc
            continue
        except BaseException:
            # The path may have been substituted. Never delete an unauthenticated
            # entry merely to make cleanup appear successful.
            owner.disarm_private_path_cleanup()
    close_control = _close_owned_descriptor_during_unwind(owner)
    return first_control if first_control is not None else close_control


def _opened_descriptor_value(status: bytearray) -> int:
    if len(status) != 4:
        raise _error("private_tree_invalid")
    return int.from_bytes(status, byteorder=sys.byteorder, signed=True)


def _open_owned_directory_descriptor(path: str | bytes, *, dir_fd: int | None = None) -> _OwnedDescriptor:
    owner = _OwnedDescriptor()
    first_control: KeyboardInterrupt | SystemExit | None = None
    open_errno: int | None = None
    try:
        while owner.closed:
            try:
                open_errno = _native_engine._open_directory_fd_once(owner._opened_fd, os.fsencode(path), dir_fd)
            except (KeyboardInterrupt, SystemExit) as exc:
                if first_control is None:
                    first_control = exc
            if not owner.closed:
                break
            if open_errno is not None:
                if first_control is not None:
                    raise first_control
                if open_errno <= 0:
                    raise _error("private_tree_invalid")
                raise OSError(open_errno, os.strerror(open_errno))
        owner.bind_identity(_descriptor_identity(os.fstat(owner.fd)))
        if first_control is not None:
            raise first_control
        return owner
    except BaseException as active_error:
        cleanup_control = _close_owned_descriptor_during_unwind(owner)
        if first_control is not None:
            raise first_control
        if cleanup_control is not None and not isinstance(
            active_error,
            (KeyboardInterrupt, SystemExit, MemoryError),
        ):
            raise cleanup_control
        raise


def _repair_and_open_owned_recovery_directory_descriptor(
    path: str | bytes,
    *,
    dir_fd: int,
    expected_identity: tuple[int, int],
) -> _OwnedDescriptor:
    """Repair access to, open, and pin only one durably bound recovery inode."""

    if (
        type(dir_fd) is not int
        or dir_fd < 0
        or not isinstance(expected_identity, tuple)
        or len(expected_identity) != 2
        or any(type(value) is not int or value < 0 for value in expected_identity)
    ):
        raise _error("attempt_ledger_invalid")
    owner = _OwnedDescriptor()
    first_control: KeyboardInterrupt | SystemExit | None = None
    open_errno: int | None = None
    try:
        while owner.closed:
            try:
                open_errno = _native_engine._repair_and_open_directory_fd_once(
                    owner._opened_fd,  # noqa: SLF001
                    os.fsencode(path),
                    dir_fd,
                    expected_identity[0],
                    expected_identity[1],
                )
            except (KeyboardInterrupt, SystemExit) as exc:
                if first_control is None:
                    first_control = exc
            if not owner.closed:
                break
            if open_errno is not None:
                if first_control is not None:
                    raise first_control
                if open_errno <= 0:
                    raise _error("attempt_ledger_invalid")
                raise OSError(open_errno, os.strerror(open_errno))
        opened_identity = _descriptor_identity(os.fstat(owner.fd))
        if opened_identity[:2] != expected_identity:
            raise _error("attempt_ledger_invalid")
        owner.bind_identity(opened_identity)
        if first_control is not None:
            raise first_control
        return owner
    except BaseException as active_error:
        cleanup_control = _close_owned_descriptor_during_unwind(owner)
        if first_control is not None:
            raise first_control
        if cleanup_control is not None and not isinstance(
            active_error,
            (KeyboardInterrupt, SystemExit, MemoryError),
        ):
            raise cleanup_control
        raise


def _open_owned_recovery_directory_descriptor(
    path: str | bytes,
    *,
    dir_fd: int,
    expected_identity: tuple[int, int],
) -> _OwnedDescriptor:
    """Open a bound recovery inode, repairing access only after permission denial."""

    if (
        type(dir_fd) is not int
        or dir_fd < 0
        or not isinstance(expected_identity, tuple)
        or len(expected_identity) != 2
        or any(type(value) is not int or value < 0 for value in expected_identity)
    ):
        raise _error("attempt_ledger_invalid")
    try:
        owner = _open_owned_directory_descriptor(path, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno not in {errno.EACCES, errno.EPERM}:
            raise
    else:
        if owner.identity[:2] != expected_identity:
            owner.close()
            raise OSError(errno.ESTALE, os.strerror(errno.ESTALE))
        return owner
    return _repair_and_open_owned_recovery_directory_descriptor(
        path,
        dir_fd=dir_fd,
        expected_identity=expected_identity,
    )


def _open_owned_private_file_descriptor(path: str | bytes, *, dir_fd: int) -> _OwnedDescriptor:
    owner = _OwnedDescriptor()
    cleanup_name = os.fsdecode(path)
    owner.configure_private_path_cleanup(dir_fd, cleanup_name)
    first_control: KeyboardInterrupt | SystemExit | None = None
    open_errno: int | None = None
    try:
        while owner.closed:
            try:
                open_errno = _native_engine._open_private_file_fd_once(owner._opened_fd, os.fsencode(path), dir_fd)
            except (KeyboardInterrupt, SystemExit) as exc:
                if first_control is None:
                    first_control = exc
            if not owner.closed:
                break
            if open_errno is not None:
                if first_control is not None:
                    raise first_control
                if open_errno <= 0:
                    raise _error("attempt_ledger_invalid")
                raise OSError(open_errno, os.strerror(open_errno))
        owner.bind_identity(_descriptor_identity(os.fstat(owner.fd)))
        if first_control is not None:
            raise first_control
        return owner
    except BaseException as active_error:
        cleanup_control = _abort_private_owner_during_unwind(owner)
        if first_control is not None:
            raise first_control
        if cleanup_control is not None and not isinstance(
            active_error,
            (KeyboardInterrupt, SystemExit, MemoryError),
        ):
            raise cleanup_control
        raise


def _open_owned_existing_private_file_descriptor(path: str | bytes, *, dir_fd: int) -> _OwnedDescriptor:
    owner = _OwnedDescriptor()
    first_control: KeyboardInterrupt | SystemExit | None = None
    open_errno: int | None = None
    try:
        while owner.closed:
            try:
                open_errno = _native_engine._open_existing_private_file_fd_once(
                    owner._opened_fd,
                    os.fsencode(path),
                    dir_fd,
                )
            except (KeyboardInterrupt, SystemExit) as exc:
                if first_control is None:
                    first_control = exc
            if not owner.closed:
                break
            if open_errno is not None:
                if first_control is not None:
                    raise first_control
                if open_errno <= 0:
                    raise _error("attempt_ledger_invalid")
                raise OSError(open_errno, os.strerror(open_errno))
        owner.bind_identity(_descriptor_identity(os.fstat(owner.fd)))
        if first_control is not None:
            raise first_control
        return owner
    except BaseException as active_error:
        cleanup_control = _close_owned_descriptor_during_unwind(owner)
        if first_control is not None:
            raise first_control
        if cleanup_control is not None and not isinstance(
            active_error,
            (KeyboardInterrupt, SystemExit, MemoryError),
        ):
            raise cleanup_control
        raise


@dataclass(frozen=True, slots=True)
class _PinnedComponent:
    parent_fd: int
    name: str
    descriptor: _OwnedDescriptor
    identity: _DirectoryIdentity

    @property
    def fd(self) -> int:
        return self.descriptor.fd


class _PinnedDirectory:
    """No-follow component walk retained as one descriptor identity chain."""

    def __init__(
        self,
        path: Path,
        *,
        create_final: bool = False,
        require_private_final: bool = True,
        recovery_final_identity: tuple[int, int] | None = None,
    ) -> None:
        if type(require_private_final) is not bool or (
            recovery_final_identity is not None
            and (
                create_final
                or not require_private_final
                or not isinstance(recovery_final_identity, tuple)
                or len(recovery_final_identity) != 2
                or any(type(value) is not int or value < 0 for value in recovery_final_identity)
            )
        ):
            raise _error("private_tree_invalid")
        self.path = _absolute_private_path(path)
        self._require_private_final = require_private_final
        self._base: _OwnedDescriptor | None = None
        self._components: list[_PinnedComponent] = []
        try:
            self._base = _open_owned_directory_descriptor(self.path.anchor)
            parent_fd = self._base.fd
            parts = self.path.parts[1:]
            if not parts:
                raise OSError
            for index, name in enumerate(parts):
                final = index == len(parts) - 1
                if final and create_final:
                    try:
                        os.mkdir(name, 0o700, dir_fd=parent_fd)
                    except FileExistsError:
                        pass
                if final and recovery_final_identity is not None:
                    descriptor = _open_owned_recovery_directory_descriptor(
                        name,
                        dir_fd=parent_fd,
                        expected_identity=recovery_final_identity,
                    )
                    try:
                        opened = os.fstat(descriptor.fd)
                        owner = os.geteuid() if hasattr(os, "geteuid") else opened.st_uid
                        if (
                            not stat.S_ISDIR(opened.st_mode)
                            or stat.S_ISLNK(opened.st_mode)
                            or opened.st_uid != owner
                            or (int(opened.st_dev), int(opened.st_ino)) != recovery_final_identity
                        ):
                            raise OSError
                        os.fchmod(descriptor.fd, 0o700)
                        repaired = os.fstat(descriptor.fd)
                        if (
                            not _same_directory(opened, repaired)
                            or repaired.st_uid != owner
                            or stat.S_IMODE(repaired.st_mode) != 0o700
                        ):
                            raise OSError
                    except BaseException as active_error:
                        cleanup_control = _close_owned_descriptor_during_unwind(descriptor)
                        if cleanup_control is not None and not isinstance(
                            active_error,
                            (KeyboardInterrupt, SystemExit, MemoryError),
                        ):
                            raise cleanup_control
                        raise
                else:
                    descriptor = _open_owned_directory_descriptor(name, dir_fd=parent_fd)
                info = os.fstat(descriptor.fd)
                before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if not _same_directory(before, info):
                    descriptor.close()
                    raise OSError
                if final and self._require_private_final:
                    if not _safe_private_directory(info) or stat.S_IMODE(info.st_mode) != 0o700:
                        descriptor.close()
                        raise OSError
                component = _PinnedComponent(parent_fd, name, descriptor, _directory_identity(info))
                self._components.append(component)
                parent_fd = descriptor.fd
            self.assert_current()
        except BaseException:
            self.close()
            raise _error("attempt_ledger_invalid" if create_final else "private_tree_invalid") from None

    @property
    def fd(self) -> int:
        if not self._components:
            raise _error("private_tree_invalid")
        return self._components[-1].fd

    @property
    def parent_fd(self) -> int:
        if not self._components:
            raise _error("private_tree_invalid")
        return self._components[-1].parent_fd

    @property
    def name(self) -> str:
        if not self._components:
            raise _error("private_tree_invalid")
        return self._components[-1].name

    @property
    def identity(self) -> _DirectoryIdentity:
        if not self._components:
            raise _error("private_tree_invalid")
        return self._components[-1].identity

    def assert_current(self, *, code: str = "private_tree_invalid") -> None:
        try:
            for component in self._components:
                opened = os.fstat(component.fd)
                current = os.stat(component.name, dir_fd=component.parent_fd, follow_symlinks=False)
                if (
                    _directory_identity(opened) != component.identity
                    or not _same_directory(current, opened)
                    or _directory_identity(current) != component.identity
                ):
                    raise OSError
            if self._require_private_final and not _safe_private_directory(os.fstat(self.fd)):
                raise OSError
        except OSError:
            raise _error(code) from None

    @property
    def closed(self) -> bool:
        return self._base is None and not self._components

    def close(self) -> None:
        first_control: KeyboardInterrupt | SystemExit | None = None
        while self._components:
            component = self._components[-1]
            try:
                component.descriptor.close()
                self._components.pop()
            except (KeyboardInterrupt, SystemExit) as exc:
                if first_control is None:
                    first_control = exc
                if component.descriptor.closed:
                    self._components.pop()
        while self._base is not None:
            base = self._base
            try:
                base.close()
                self._base = None
            except (KeyboardInterrupt, SystemExit) as exc:
                if first_control is None:
                    first_control = exc
                if base.closed:
                    self._base = None
        if first_control is not None:
            raise first_control


class _PrivateTreeGuard:
    """Pin the transaction tree and every declared root by relative identity."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self._owner: _OwnedDescriptor | None = None
        self._directories: dict[Path, _DirectoryIdentity] = {}
        self._lock = threading.RLock()
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        if os.name != "posix" or not nofollow or not getattr(os, "O_DIRECTORY", 0):
            raise _error("private_tree_invalid")
        try:
            before = root.lstat()
            self._owner = _open_owned_directory_descriptor(os.fspath(root))
            after = os.fstat(self._owner.fd)
        except BaseException as exc:
            cleanup_control: BaseException | None = None
            try:
                self.close()
            except (KeyboardInterrupt, SystemExit, MemoryError) as cleanup_exc:
                cleanup_control = cleanup_exc
            if isinstance(exc, (EnronCapacityError, OSError)):
                if cleanup_control is not None:
                    raise cleanup_control
                raise _error("private_tree_invalid") from None
            raise
        self._identity = _directory_identity(after)
        if not _same_directory(before, after) or not _safe_private_directory(after):
            self.close()
            raise _error("private_tree_invalid")

    @property
    def identity(self) -> _DirectoryIdentity:
        return self._identity

    def close(self) -> None:
        with self._lock:
            owner = self._owner
            cleanup_control = None if owner is None else _close_owned_descriptor_during_unwind(owner)
            self._owner = None
        if cleanup_control is not None:
            raise cleanup_control

    def rebind(self, root: Path) -> None:
        with self._lock:
            self.root = root
            self.assert_current()

    def register_owned_root(self, path: Path) -> Path:
        with self._lock:
            candidate = _absolute_private_path(path)
            try:
                relative = candidate.relative_to(self.root)
            except ValueError:
                raise _CapacityAbort("owned_root_invalid") from None
            if relative == Path("."):
                return candidate
            current = self.root
            for part in relative.parts:
                current /= part
                try:
                    info = current.lstat()
                except OSError:
                    raise _CapacityAbort("owned_root_invalid") from None
                if not _safe_private_directory(info):
                    raise _CapacityAbort("owned_root_invalid")
                self._directories[current.relative_to(self.root)] = _directory_identity(info)
            return candidate

    def assert_current(self) -> None:
        with self._lock:
            owner = self._owner
            if owner is None or owner.closed:
                raise _error("private_tree_invalid")
            try:
                path_info = self.root.lstat()
                descriptor_info = os.fstat(owner.fd)
            except OSError:
                raise _error("private_tree_invalid") from None
            if (
                not _same_directory(path_info, descriptor_info)
                or _directory_identity(descriptor_info) != self._identity
                or not _safe_private_directory(descriptor_info)
            ):
                raise _error("private_tree_invalid")
            for relative, identity in tuple(self._directories.items()):
                try:
                    info = (self.root / relative).lstat()
                except OSError:
                    raise _error("private_tree_invalid") from None
                if _directory_identity(info) != identity or not _safe_private_directory(info):
                    raise _error("private_tree_invalid")

    def logical_bytes(self) -> int:
        scan: _OwnedDescriptor | None = None
        try:
            with self._lock:
                self.assert_current()
                owner = self._owner
                if owner is None or owner.closed:
                    raise _error("private_tree_invalid")
                scan = _open_owned_directory_descriptor(".", dir_fd=owner.fd)
                opened = os.fstat(scan.fd)
                if _directory_identity(opened) != self._identity or not _safe_private_directory(opened):
                    raise OSError
                scan_fd = scan.fd
            return _logical_tree_bytes(scan_fd, depth=0, entries=[0])
        except EnronCapacityError:
            raise
        except OSError:
            raise _error("private_tree_invalid") from None
        finally:
            active_error = sys.exc_info()[1]
            cleanup_control = None if scan is None else _close_owned_descriptor_during_unwind(scan)
            if cleanup_control is not None and not isinstance(
                active_error,
                (KeyboardInterrupt, SystemExit, MemoryError),
            ):
                raise cleanup_control


def _directory_identity(info: os.stat_result) -> _DirectoryIdentity:
    return _DirectoryIdentity(info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode), info.st_uid)


def _same_directory(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(first.st_mode)
        and stat.S_ISDIR(second.st_mode)
        and not stat.S_ISLNK(first.st_mode)
        and (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)
    )


def _safe_private_directory(info: os.stat_result) -> bool:
    owner = os.geteuid() if hasattr(os, "geteuid") else info.st_uid
    return (
        stat.S_ISDIR(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and info.st_uid == owner
        and is_owner_only_private_mode(stat.S_IMODE(info.st_mode))
    )


def _logical_tree_bytes(directory_fd: int, *, depth: int, entries: list[int]) -> int:
    if depth > _private_io._MAX_PRIVATE_TREE_DEPTH:  # noqa: SLF001
        raise _error("private_tree_invalid")
    try:
        names = _private_io._bounded_directory_names(  # noqa: SLF001
            directory_fd,
            entries=entries,
            maximum_entries=_private_io._MAX_PRIVATE_TREE_ENTRIES,  # noqa: SLF001
        )
    except _private_io._PrivateTreeEntryLimitExceeded:  # noqa: SLF001
        raise _error("private_tree_invalid") from None
    except OSError:
        raise _error("private_tree_invalid") from None
    total = 0
    for name in names:
        try:
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError:
            raise _error("private_tree_invalid") from None
        if stat.S_ISREG(info.st_mode):
            owner = os.geteuid() if hasattr(os, "geteuid") else info.st_uid
            if info.st_nlink == 0:
                # A directory entry can disappear after enumeration but before
                # the descriptor-relative stat completes.  Treat that as a
                # legitimate concurrent deletion; linked files remain subject
                # to the private-tree invariants below.
                continue
            if (
                info.st_nlink != 1
                or info.st_uid != owner
                or not is_owner_only_private_mode(stat.S_IMODE(info.st_mode))
                or info.st_size < 0
            ):
                raise _error("private_tree_invalid")
            total += int(info.st_size)
            continue
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise _error("private_tree_invalid")
        child: _OwnedDescriptor | None = None
        try:
            child = _open_owned_directory_descriptor(name, dir_fd=directory_fd)
            opened = os.fstat(child.fd)
            if not _same_directory(info, opened) or not _safe_private_directory(opened):
                raise _error("private_tree_invalid")
            total += _logical_tree_bytes(child.fd, depth=depth + 1, entries=entries)
        except EnronCapacityError:
            raise
        except FileNotFoundError:
            continue
        except OSError:
            raise _error("private_tree_invalid") from None
        finally:
            if child is not None:
                active_error = sys.exc_info()[1]
                cleanup_control = _close_owned_descriptor_during_unwind(child)
                if cleanup_control is not None and not isinstance(
                    active_error,
                    (KeyboardInterrupt, SystemExit, MemoryError),
                ):
                    raise cleanup_control
    return total


@dataclass(frozen=True, slots=True)
class _FilesystemPreflight:
    device: int
    probe_path: Path
    preflight_free_disk_bytes: int
    includes_output: bool


@dataclass(frozen=True, slots=True)
class _Preflight:
    physical_memory_bytes: int
    effective_rss_cap_bytes: int
    maximum_peak_rss_bytes: int
    preflight_process_tree_rss_bytes: int
    preflight_free_disk_bytes: int
    output_preflight_free_disk_bytes: int
    preexisting_private_tombstone_count: int
    filesystems: tuple[_FilesystemPreflight, ...]


_CleanupEvidence = tuple[bool | None, bool | None, int]


@dataclass(slots=True)
class _AttemptMetrics:
    started_ns: int | None = None
    elapsed_ns: int | None = None
    maximum_peak_rss_bytes: int | None = None
    peak_process_tree_rss_bytes: int | None = None
    minimum_free_disk_bytes: int | None = None
    resource_observation_count: int | None = None
    maximum_resource_observation_wall_gap_ns: int | None = None
    final_owned_disk_bytes: int | None = None
    report_sha256: str | None = None
    promoted_root_device: int | None = None
    promoted_root_inode: int | None = None
    promoted_parent_device: int | None = None
    promoted_parent_inode: int | None = None
    promoted_name_sha256: str | None = None
    preexisting_private_tombstone_count: int | None = None
    cleanup_evidence: _CleanupEvidence = (None, None, 0)


@dataclass(slots=True)
class _InflightAttempt:
    ledger: _AttemptLedger
    record: dict[str, Any]
    marker_name: str
    marker: _OwnedDescriptor | None
    output_parent: _PinnedDirectory
    output_name: str
    stage_binding: dict[str, Any] | None = None
    cleanup_inventory: dict[str, Any] | None = None
    cleanup_intent: dict[str, Any] | None = None
    receipt_appended: bool = False
    terminalized: bool = False
    transaction_owner: PrivateRun | None = None
    transaction_pin: _PinnedDirectory | None = None
    transaction_tree: _PrivateTreeGuard | None = None

    @property
    def closed(self) -> bool:
        return (self.marker is None or self.marker.closed) and self.output_parent.closed

    @property
    def marker_fd(self) -> int | None:
        return None if self.marker is None or self.marker.closed else self.marker.fd

    @property
    def nonce(self) -> str:
        return cast(str, self.record["attempt_nonce"])

    @property
    def stage_token(self) -> str:
        return cast(str, self.record["stage_token"])

    @property
    def binding_name(self) -> str:
        return f".attempt-inflight-{self.nonce}.stage.json"

    @property
    def cleanup_inventory_name(self) -> str:
        return f".attempt-inflight-{self.nonce}.cleanup.json"

    def close(self) -> None:
        first_control: KeyboardInterrupt | SystemExit | None = None
        while self.marker is not None and not self.marker.closed:
            marker = self.marker
            try:
                marker.close()
                self.marker = None
            except (KeyboardInterrupt, SystemExit) as exc:
                if first_control is None:
                    first_control = exc
                if marker.closed:
                    self.marker = None
        try:
            self.output_parent.close()
        except (KeyboardInterrupt, SystemExit) as exc:
            if first_control is None:
                first_control = exc
        if first_control is not None:
            raise first_control


@dataclass(slots=True)
class _CompletedCapacityRun:
    report: dict[str, Any]
    pinned: _PinnedDirectory
    cleanup_owner: PrivateRun


def _wipe_promoted_capacity_run(
    cleanup_owner: PrivateRun,
    pinned: _PinnedDirectory,
    *,
    workspace_root: Path | None,
    allow_unignored_output: bool,
    expected_identity: tuple[int, int] | None = None,
    metrics: _AttemptMetrics | None = None,
) -> tuple[bool, bool, int]:
    """Wipe retained inodes across tree cleanup, parking failures for retry."""

    authority_wiped = False
    tree_cleanup = (False, False, 0)
    first_error: BaseException | None = None
    try:
        if cleanup_owner.cleanup_authority_retained:
            try:
                authority_wiped = cleanup_owner.wipe_retained_cleanup_authority()
            except BaseException as exc:
                first_error = exc
        elif cleanup_owner.cleanup_authority_wiped:
            authority_wiped = True
        else:
            first_error = EnronPrivateIOError("Private cleanup authority was released without a proven wipe.")
        try:
            if (
                expected_identity is not None
                and (
                    pinned.identity.device,
                    pinned.identity.inode,
                )
                != expected_identity
            ):
                raise _error("promotion_failed")
            tree_cleanup = _remove_pinned_directory(
                pinned,
                workspace_root=workspace_root,
                allow_unignored_output=allow_unignored_output,
                cleanup_boundary=cleanup_owner._cleanup_boundary,  # noqa: SLF001
                effective_workspace_root=cleanup_owner._workspace_root,  # noqa: SLF001
                cleanup_result_observer=(
                    None
                    if metrics is None
                    else lambda result: _publish_incomplete_promoted_cleanup_metrics(metrics, result)
                ),
            )
        except BaseException as exc:
            if first_error is None:
                first_error = exc
        if cleanup_owner.cleanup_authority_retained:
            try:
                authority_wiped = cleanup_owner.wipe_retained_cleanup_authority()
            except BaseException as exc:
                authority_wiped = False
                if first_error is None:
                    first_error = exc
    finally:
        if cleanup_owner.cleanup_authority_retained:
            try:
                cleanup_owner.park_unresolved_cleanup_authority()
            except BaseException as exc:
                if first_error is None:
                    first_error = exc
            authority_wiped = False
        if not pinned.closed:
            pinned.close()
    if first_error is not None:
        raise first_error
    return authority_wiped and tree_cleanup[0], tree_cleanup[1], tree_cleanup[2]


def _open_promoted_capacity_pin(path: Path) -> _PinnedDirectory:
    """Normalize a missing or unsafe promoted path to the promotion contract."""

    try:
        return _PinnedDirectory(path)
    except EnronCapacityError:
        raise _error("promotion_failed") from None


@dataclass(slots=True)
class _PhaseMeasurements:
    started_ns: int
    started_wall_ns: int
    observations: int = 0
    resource_acquisition_retry_count: int = 0
    peak_rss: int = 0
    minimum_free: int | None = None
    owned_high_water: int = 0
    last_owned: int = 0
    last_completed: int = 0
    maximum_checkpoint_gap: int = 0
    checkpoint_count: int = 0
    samples: list[dict[str, Any]] | None = None
    sample_priorities: list[int] | None = None
    cadence_samples: list[dict[str, Any]] | None = None
    first_sample: dict[str, Any] | None = None
    peak_sample: dict[str, Any] | None = None
    owned_peak_sample: dict[str, Any] | None = None
    minimum_free_sample: dict[str, Any] | None = None
    maximum_wall_gap_sample: dict[str, Any] | None = None
    maximum_acquisition_sample: dict[str, Any] | None = None
    last_sample: dict[str, Any] | None = None
    last_resource_wall_ns: int | None = None
    last_progress_wall_ns: int | None = None
    last_progress_kind: str = "phase_start"
    last_activity_observation_wall_ns: int | None = None
    maximum_resource_wall_gap_ns: int = 0
    maximum_resource_acquisition_duration_ns: int = 0
    maximum_progress_wall_gap_ns: int = 0
    checkpoints: list[dict[str, int]] | None = None
    progress_signals: list[dict[str, Any]] | None = None
    liveness_samples: list[dict[str, Any]] | None = None
    liveness_priorities: list[int] | None = None
    progress_signal_count: int = 0
    maximum_progress_signal: dict[str, Any] | None = None
    last_liveness_signal: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        self.samples = []
        self.sample_priorities = []
        self.cadence_samples = []
        self.checkpoints = []
        self.progress_signals = []
        self.liveness_samples = []
        self.liveness_priorities = []


class _Watchdog:
    def __init__(self, failure_code: Callable[[], str | None]) -> None:
        self._failure_code = failure_code
        self._previous: Any = None
        self._installed = False
        self._abort_delivered = False

    def install(self) -> None:
        if (
            os.name != "posix"
            or threading.current_thread() is not threading.main_thread()
            or not hasattr(signal, "SIGUSR1")
        ):
            raise _error("watchdog_unsupported")
        try:
            self._abort_delivered = False
            self._previous = signal.getsignal(signal.SIGUSR1)
            # Publish restoration authority before installing the handler.
            # If control arrives after signal.signal changes process state,
            # cleanup must already know that the previous handler is owed.
            self._installed = True
            signal.signal(signal.SIGUSR1, self._handle)
        except (OSError, RuntimeError, ValueError):
            self.close()
            raise _error("watchdog_unsupported") from None

    def close(self) -> None:
        if self._installed:
            try:
                signal.signal(signal.SIGUSR1, self._previous)
            except (OSError, RuntimeError, ValueError):
                try:
                    restored = signal.getsignal(signal.SIGUSR1) is self._previous
                except (OSError, RuntimeError, ValueError):
                    raise
                if not restored:
                    raise
            self._installed = False

    def trigger(self) -> None:
        if self._installed and threading.current_thread() is not threading.main_thread():
            try:
                os.kill(os.getpid(), signal.SIGUSR1)
            except OSError:
                pass

    def _handle(self, _signum: int, _frame: Any) -> None:
        if self._abort_delivered:
            return
        self._abort_delivered = True
        code = self._failure_code()
        # The supervising launcher may need to request cooperative unwinding
        # after the response pipe fails before an observer failure frame can
        # be delivered.  SIGUSR1 is private to this isolated worker while the
        # watchdog is installed, so an otherwise-unclassified request still
        # aborts through the normal cleanup owner.
        raise _CapacityAbort(code or "production_worker_failed")


def _resource_observer_preflight_payload(preflight: _Preflight) -> dict[str, Any]:
    return {
        "physical_memory_bytes": preflight.physical_memory_bytes,
        "effective_rss_cap_bytes": preflight.effective_rss_cap_bytes,
        "maximum_peak_rss_bytes": preflight.maximum_peak_rss_bytes,
        "preflight_process_tree_rss_bytes": preflight.preflight_process_tree_rss_bytes,
        "preflight_free_disk_bytes": preflight.preflight_free_disk_bytes,
        "output_preflight_free_disk_bytes": preflight.output_preflight_free_disk_bytes,
        "preexisting_private_tombstone_count": preflight.preexisting_private_tombstone_count,
        "filesystems": [
            {
                "path": os.fspath(item.probe_path),
                "device": item.device,
                "preflight_free_disk_bytes": item.preflight_free_disk_bytes,
                "includes_output": item.includes_output,
            }
            for item in preflight.filesystems
        ],
    }


def _resource_sample_failure_code(
    *,
    process_tree_rss_bytes: int | None,
    maximum_peak_rss_bytes: int,
    minimum_free_disk_bytes: int | None,
    acquisition_duration_ns: int,
    observation_wall_gap_ns: int,
    total_runtime_ns: int,
    terminal_process_leak: bool,
    fallback_failure_code: str | None,
) -> str | None:
    """Apply acquisition > RSS > disk > gap > runtime > terminal > fallback precedence."""

    if acquisition_duration_ns > MAX_RESOURCE_ACQUISITION_DURATION_NS:
        return "resource_acquisition_timeout"
    if process_tree_rss_bytes is not None and process_tree_rss_bytes > maximum_peak_rss_bytes:
        return "rss_limit"
    if minimum_free_disk_bytes is not None and minimum_free_disk_bytes < MIN_RUNTIME_FREE_DISK_BYTES:
        return "runtime_disk_floor"
    if observation_wall_gap_ns > MAX_RESOURCE_OBSERVATION_WALL_GAP_NS:
        return "resource_observation_gap"
    if total_runtime_ns > MAX_TOTAL_RUNTIME_NS:
        return "runtime_limit"
    if terminal_process_leak:
        return "worker_process_leak"
    if fallback_failure_code is None:
        return None
    return fallback_failure_code if fallback_failure_code in _ERROR_MESSAGES else "resource_measurement_failed"


_RESOURCE_FAILURE_PRIORITY = {
    "resource_acquisition_timeout": 0,
    "rss_limit": 1,
    "runtime_disk_floor": 2,
    "owned_disk_limit": 3,
    "resource_observation_gap": 4,
    "runtime_limit": 5,
    "worker_process_leak": 6,
}


def _combine_resource_failure_codes(local_code: str | None, launcher_code: str | None) -> str | None:
    """Choose one resource failure without discarding worker-owned evidence."""

    if local_code is None:
        return launcher_code
    if launcher_code is None:
        return local_code
    fallback_priority = len(_RESOURCE_FAILURE_PRIORITY)
    if _RESOURCE_FAILURE_PRIORITY.get(launcher_code, fallback_priority) < _RESOURCE_FAILURE_PRIORITY.get(
        local_code,
        fallback_priority,
    ):
        return launcher_code
    return local_code


def _resource_gap_failure_diagnostic(
    *,
    phase: str | None,
    sample_kind: str,
    sequence: int,
    observed_resource_gap_ns: int,
    acquisition_duration_ns: int,
    rss_duration_ns: int,
    filesystem_duration_ns: int,
    acquisition_retry_count: int,
    scheduler_lateness_ns: int,
) -> dict[str, Any]:
    diagnostic = {
        "diagnostic_kind": "resource_observation_gap",
        "phase": phase,
        "sample_kind": sample_kind,
        "sequence": sequence,
        "observed_resource_gap_ns": observed_resource_gap_ns,
        "maximum_resource_gap_ns": MAX_RESOURCE_OBSERVATION_WALL_GAP_NS,
        "acquisition_duration_ns": acquisition_duration_ns,
        "rss_duration_ns": rss_duration_ns,
        "filesystem_duration_ns": filesystem_duration_ns,
        "acquisition_retry_count": acquisition_retry_count,
        "scheduler_lateness_ns": scheduler_lateness_ns,
    }
    validated = _validated_resource_failure_diagnostic(diagnostic)
    if validated is None:
        raise _error("resource_measurement_failed")
    return validated


class _RemoteResourceObserver:
    """Receive launcher-timestamped samples without sharing the workload GIL."""

    def __init__(
        self,
        monitor: _ContinuousResourceMonitor,
        endpoint: socket.socket,
        nonce: str,
    ) -> None:
        if not re.fullmatch(r"[0-9a-f]{64}", nonce):
            raise _error("production_identity_invalid")
        self.monitor = monitor
        self.endpoint = endpoint
        self.nonce = nonce
        self.reader = _ResourceObserverFrames(endpoint)
        self.thread = threading.Thread(target=self._loop, name="nerb-capacity-resource-observer-receiver", daemon=True)
        self.condition = threading.Condition()
        self.command_lock = threading.Lock()
        self.send_lock = threading.Lock()
        self.next_request_id = 1
        self.expected: dict[int, str] = {}
        self.completed: set[int] = set()
        self.event_sequence = 0
        self.last_frame_completed_ns: int | None = None
        self.last_valid_completed_ns: int | None = None
        self.started = False
        self.stop_requested = False
        self.stopped = False

    def start(self) -> None:
        # Publish receiver lifecycle state while holding the same condition
        # used by stop().  The receiver can start running before
        # Thread.start() returns, and Thread.start() can still raise after the
        # native thread exists.  In either case stop() must observe a settled
        # state instead of spinning forever on an unreported receiver.
        with self.condition:
            try:
                self.thread.start()
                self.started = True
            except BaseException:
                self.stopped = True
                self.condition.notify_all()
                raise
        self._send(
            {
                "type": "init",
                "protocol": _RESOURCE_OBSERVER_PROTOCOL,
                "nonce": self.nonce,
                "interval_ns": self.monitor.interval_ns,
                "maximum_gap_ns": MAX_RESOURCE_OBSERVATION_WALL_GAP_NS,
                "run_started_ns": self.monitor.run_started_ns,
                "preflight": _resource_observer_preflight_payload(self.monitor.preflight),
            },
        )
        deadline = time.monotonic_ns() + RESOURCE_OBSERVER_START_TIMEOUT_NS
        with self.condition:
            while self.event_sequence == 0 and self.monitor._failure_code is None:
                remaining = deadline - time.monotonic_ns()
                if remaining <= 0:
                    self.monitor._record_remote_failure("resource_measurement_failed")
                    break
                self.condition.wait(remaining / 1_000_000_000)
        self.monitor.raise_if_failed()

    def force(self, kind: str, *, stop: bool = False) -> None:
        if kind not in {"boundary", "checkpoint", "heartbeat", "activity", "terminal"} or (kind == "terminal") != stop:
            raise _error("resource_measurement_failed")
        with self.command_lock:
            worker_peak_rss = _root_process_peak_rss_bytes()
            if type(worker_peak_rss) is not int or worker_peak_rss <= 0 or worker_peak_rss > _MAX_RESOURCE_INTEGER:
                self.monitor._record_remote_failure("resource_measurement_failed")
                self.monitor.raise_if_failed()
            with self.condition:
                if not self.started or self.stopped or self.stop_requested:
                    self.monitor._record_remote_failure("resource_measurement_failed")
                    self.monitor.raise_if_failed()
                if not stop:
                    self.monitor.raise_if_failed()
                request_id = self.next_request_id
                self.next_request_id += 1
                self.expected[request_id] = kind
                if stop:
                    self.stop_requested = True
            command = {
                "type": "stop" if stop else "force",
                "protocol": _RESOURCE_OBSERVER_PROTOCOL,
                "nonce": self.nonce,
                "request_id": request_id,
                "sample_kind": kind,
                "worker_peak_rss_bytes": worker_peak_rss,
            }
            if stop:
                self._send_final(command)
            else:
                self._send(command)
            deadline = time.monotonic_ns() + RESOURCE_OBSERVER_COMMAND_TIMEOUT_NS
            with self.condition:
                while request_id not in self.completed and (stop or self.monitor._failure_code is None):
                    remaining = deadline - time.monotonic_ns()
                    if remaining <= 0:
                        self.monitor._record_remote_failure("resource_measurement_failed")
                        break
                    self.condition.wait(remaining / 1_000_000_000)
                self.expected.pop(request_id, None)
        if not stop:
            self.monitor.raise_if_failed()

    def stop(self) -> None:
        with self.condition:
            if not self.started:
                self.stopped = True
                self.condition.notify_all()
            settle_without_protocol = not self.started or self.stopped
        if settle_without_protocol:
            if self.thread.is_alive():
                try:
                    self.endpoint.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                self.thread.join(RESOURCE_OBSERVER_COMMAND_TIMEOUT_NS / 1_000_000_000)
            if self.thread.is_alive():
                self.monitor._record_remote_failure("resource_measurement_failed")
                raise _error("resource_measurement_failed")
            return
        first_error: BaseException | None = None
        try:
            self.force("terminal", stop=True)
        except BaseException as exc:
            first_error = exc
        with self.condition:
            self.stopped = True
            self.condition.notify_all()
        self.thread.join(RESOURCE_OBSERVER_COMMAND_TIMEOUT_NS / 1_000_000_000)
        if self.thread.is_alive():
            self.monitor._record_remote_failure("resource_measurement_failed")
            try:
                self.endpoint.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.thread.join(RESOURCE_OBSERVER_COMMAND_TIMEOUT_NS / 1_000_000_000)
        if self.thread.is_alive():
            if first_error is None:
                first_error = _error("resource_measurement_failed")
        if first_error is not None:
            raise first_error

    def _loop(self) -> None:
        failure_notified = False
        try:
            while True:
                with self.condition:
                    if self.stopped:
                        return
                frames = self.reader.receive(RESOURCE_OBSERVER_COMMAND_TIMEOUT_NS)
                if not frames:
                    self.monitor._record_remote_failure("resource_measurement_failed")
                    self.monitor._watchdog.trigger()
                    return
                for frame_index, frame in enumerate(frames):
                    if frame.get("type") == "observer_failure":
                        _observer_closed(
                            frame,
                            {"type", "protocol", "nonce", "failure_code"},
                        )
                        code = frame.get("failure_code")
                        if (
                            frame.get("protocol") != _RESOURCE_OBSERVER_PROTOCOL
                            or frame.get("nonce") != self.nonce
                            or code not in _ERROR_MESSAGES
                        ):
                            code = "resource_measurement_failed"
                        self.monitor._record_remote_failure(cast(str, code))
                        self.monitor._watchdog.trigger()
                        return
                    self._accept_sample(frame)
                    request_id = int(cast(int, frame.get("request_id", 0)))
                    with self.condition:
                        terminal_sample = self.stop_requested and request_id > 0
                    if terminal_sample:
                        if frame_index != len(frames) - 1 or self.reader.buffer:
                            raise _error("resource_measurement_failed")
                        _require_resource_observer_eof(self.reader)
                    with self.condition:
                        if request_id:
                            self.completed.add(request_id)
                        self.condition.notify_all()
                    if terminal_sample:
                        return
                    if self.monitor._failure_code is not None and not failure_notified:
                        try:
                            self._send(
                                {
                                    "type": "failure_ack",
                                    "protocol": _RESOURCE_OBSERVER_PROTOCOL,
                                    "nonce": self.nonce,
                                },
                            )
                        except EnronCapacityError:
                            pass
                        self.monitor._watchdog.trigger()
                        failure_notified = True
        except _ResourceObserverEOF:
            with self.condition:
                expected_eof = self.stopped
            if not expected_eof:
                self.monitor._record_remote_failure("resource_measurement_failed")
                self.monitor._watchdog.trigger()
        except BaseException:
            self.monitor._record_remote_failure("resource_measurement_failed")
            self.monitor._watchdog.trigger()
        finally:
            with self.condition:
                self.condition.notify_all()

    def _send(self, frame: Mapping[str, Any]) -> None:
        with self.send_lock:
            _send_resource_observer_frame(self.endpoint, frame)

    def _send_final(self, frame: Mapping[str, Any]) -> None:
        with self.send_lock:
            _send_resource_observer_frame(self.endpoint, frame)
            _shutdown_resource_observer_write(self.endpoint)

    def _accept_sample(self, frame: Mapping[str, Any]) -> None:
        _observer_closed(
            frame,
            {
                "type",
                "protocol",
                "nonce",
                "event_sequence",
                "request_id",
                "sample_kind",
                "valid",
                "started_wall_ns",
                "completed_wall_ns",
                "resource_observation_wall_gap_ns",
                "acquisition_duration_ns",
                "rss_duration_ns",
                "filesystem_duration_ns",
                "scheduler_lateness_ns",
                "process_tree_rss_bytes",
                "minimum_free_disk_bytes",
                "output_free_disk_bytes",
                "rss_retry_count",
                "filesystem_retry_count",
                "failure_code",
            },
        )
        event_sequence = _observer_int(frame.get("event_sequence"), minimum=1)
        request_id = _observer_int(frame.get("request_id"), minimum=0)
        started_ns = _observer_int(frame.get("started_wall_ns"), minimum=0)
        completed_ns = _observer_int(frame.get("completed_wall_ns"), minimum=0)
        gap_ns = _observer_int(frame.get("resource_observation_wall_gap_ns"), minimum=0)
        acquisition_ns = _observer_int(frame.get("acquisition_duration_ns"), minimum=0)
        rss_duration_ns = _observer_int(frame.get("rss_duration_ns"), minimum=0)
        filesystem_duration_ns = _observer_int(frame.get("filesystem_duration_ns"), minimum=0)
        scheduler_lateness_ns = _observer_int(frame.get("scheduler_lateness_ns"), minimum=0)
        rss_retries = _observer_int(frame.get("rss_retry_count"), minimum=0)
        filesystem_retries = _observer_int(frame.get("filesystem_retry_count"), minimum=0)
        sample_kind = frame.get("sample_kind")
        valid = frame.get("valid")
        failure_code = frame.get("failure_code")
        with self.condition:
            expected_kind = self.expected.get(request_id) if request_id else None
            request_completed = request_id in self.completed
        if (
            frame.get("type") != "sample"
            or frame.get("protocol") != _RESOURCE_OBSERVER_PROTOCOL
            or frame.get("nonce") != self.nonce
            or event_sequence != self.event_sequence + 1
            or type(valid) is not bool
            or sample_kind not in _RESOURCE_SAMPLE_KINDS
            or (request_id == 0 and sample_kind not in {"startup", "continuous"})
            or (sample_kind == "startup") != (event_sequence == 1 and request_id == 0)
            or (request_id > 0 and (expected_kind != sample_kind or request_completed))
            or completed_ns < started_ns
            or acquisition_ns != completed_ns - started_ns
            or rss_duration_ns + filesystem_duration_ns != acquisition_ns
            or rss_retries >= _RUNTIME_RESOURCE_ACQUISITION_MAX_ATTEMPTS
            or filesystem_retries >= _RUNTIME_RESOURCE_ACQUISITION_MAX_ATTEMPTS
            or (failure_code is not None and failure_code not in _ERROR_MESSAGES)
            or (valid is True and acquisition_ns > MAX_RESOURCE_ACQUISITION_DURATION_NS)
        ):
            raise _error("resource_measurement_failed")
        if self.last_frame_completed_ns is not None and (
            started_ns < self.last_frame_completed_ns or completed_ns < self.last_frame_completed_ns
        ):
            raise _error("clock_invalid")
        expected_gap = 0 if self.last_valid_completed_ns is None else completed_ns - self.last_valid_completed_ns
        if expected_gap < 0 or gap_ns != expected_gap:
            raise _error("clock_invalid")
        if not valid:
            if (
                failure_code is None
                or (
                    acquisition_ns > MAX_RESOURCE_ACQUISITION_DURATION_NS
                    and failure_code != "resource_acquisition_timeout"
                )
                or (
                    acquisition_ns <= MAX_RESOURCE_ACQUISITION_DURATION_NS
                    and failure_code == "resource_acquisition_timeout"
                )
            ):
                raise _error("resource_measurement_failed")
            partial_rss = frame.get("process_tree_rss_bytes")
            partial_minimum = frame.get("minimum_free_disk_bytes")
            trusted_rss = (
                self.monitor.preflight.preflight_process_tree_rss_bytes
                if partial_rss is None
                else _observer_int(partial_rss, minimum=1)
            )
            trusted_minimum = None if partial_minimum is None else _observer_int(partial_minimum, minimum=0)
            self.event_sequence = event_sequence
            self.last_frame_completed_ns = completed_ns
            self.monitor._retain_partial_resource_extrema(
                rss=trusted_rss,
                minimum_free=trusted_minimum,
                acquisition_retries=rss_retries + filesystem_retries,
                acquisition_duration_ns=acquisition_ns,
                now=completed_ns,
                wall_now=completed_ns,
            )
            diagnostic = (
                _resource_gap_failure_diagnostic(
                    phase=None,
                    sample_kind=cast(str, sample_kind),
                    sequence=event_sequence,
                    observed_resource_gap_ns=gap_ns,
                    acquisition_duration_ns=acquisition_ns,
                    rss_duration_ns=rss_duration_ns,
                    filesystem_duration_ns=filesystem_duration_ns,
                    acquisition_retry_count=rss_retries + filesystem_retries,
                    scheduler_lateness_ns=scheduler_lateness_ns,
                )
                if failure_code == "resource_observation_gap"
                else None
            )
            self.monitor._record_remote_failure(cast(str, failure_code), diagnostic=diagnostic)
            return
        rss = _observer_int(frame.get("process_tree_rss_bytes"), minimum=1)
        minimum_free = _observer_int(frame.get("minimum_free_disk_bytes"), minimum=0)
        output_free = _observer_int(frame.get("output_free_disk_bytes"), minimum=0)
        terminal_sample = sample_kind == "terminal"
        expected_failure = _resource_sample_failure_code(
            process_tree_rss_bytes=rss,
            maximum_peak_rss_bytes=self.monitor.preflight.maximum_peak_rss_bytes,
            minimum_free_disk_bytes=minimum_free,
            acquisition_duration_ns=acquisition_ns,
            observation_wall_gap_ns=gap_ns,
            total_runtime_ns=completed_ns - self.monitor.run_started_ns,
            terminal_process_leak=terminal_sample and failure_code == "worker_process_leak",
            fallback_failure_code=(
                "resource_measurement_failed"
                if terminal_sample and failure_code == "resource_measurement_failed"
                else None
            ),
        )
        if failure_code != expected_failure:
            raise _error("resource_measurement_failed")
        self.event_sequence = event_sequence
        self.last_frame_completed_ns = completed_ns
        self.last_valid_completed_ns = completed_ns
        self.monitor._accept_remote_resource_sample(
            kind=cast(str, sample_kind),
            completed_records=None,
            wall_now=completed_ns,
            now=completed_ns,
            rss=rss,
            minimum_free=minimum_free,
            output_free=output_free,
            rss_retries=rss_retries,
            filesystem_retries=filesystem_retries,
            wall_gap=gap_ns,
            acquisition_duration_ns=acquisition_ns,
            rss_duration_ns=rss_duration_ns,
            filesystem_duration_ns=filesystem_duration_ns,
            scheduler_lateness_ns=scheduler_lateness_ns,
            failure_code=cast(str | None, failure_code),
        )


class _ContinuousResourceMonitor:
    """Continuously sample RSS/free disk; checkpoint owned bytes/progress."""

    def __init__(
        self,
        *,
        tree: _PrivateTreeGuard,
        probe: CapacityResourceProbe,
        preflight: _Preflight,
        run_started_ns: int,
        interval_ns: int,
        wall_clock: Callable[[], int],
        resource_observer_socket: socket.socket | None = None,
        resource_observer_nonce: str | None = None,
    ) -> None:
        self.tree = tree
        self.probe = probe
        self.preflight = preflight
        self.run_started_ns = run_started_ns
        self.interval_ns = interval_ns
        self.wall_clock = wall_clock
        if (resource_observer_socket is None) != (resource_observer_nonce is None):
            raise _error("production_identity_invalid")
        self._lock = threading.RLock()
        self._observation_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._stopped = False
        self._current_phase: str | None = None
        self._states: dict[str, _PhaseMeasurements] = {}
        self._failure_code: str | None = None
        self._failure_diagnostic: dict[str, Any] | None = None
        self._global_observations = 0
        self._global_resource_acquisition_retries = 0
        self._global_peak_rss = preflight.preflight_process_tree_rss_bytes
        self._global_minimum_free = preflight.preflight_free_disk_bytes
        self._global_owned_high_water = 0
        self._global_maximum_resource_wall_gap_ns = 0
        self._global_maximum_resource_acquisition_duration_ns = 0
        self._global_last_resource_wall_ns: int | None = None
        self._global_last_probe_ns = run_started_ns
        self._latest_exact_owned = 0
        self._watchdog = _Watchdog(self._current_failure_code)
        self._remote = (
            None
            if resource_observer_socket is None or resource_observer_nonce is None
            else _RemoteResourceObserver(self, resource_observer_socket, resource_observer_nonce)
        )

    def start(self) -> None:
        self._watchdog.install()
        with self._observation_lock:
            owned = self.tree.logical_bytes()
            with self._lock:
                self._latest_exact_owned = owned
                self._global_owned_high_water = max(self._global_owned_high_water, owned)
                self._global_last_resource_wall_ns = None if self._remote is not None else self.wall_clock()
            if self._remote is not None:
                self._remote.start()
                self._remote.force("boundary")
            else:
                self._observe_serialized("boundary", logical_owned=owned)
                thread = threading.Thread(target=self._loop, name="nerb-capacity-resource-monitor", daemon=True)
                self._thread = thread
                thread.start()

    def stop(self) -> None:
        first_error: BaseException | None = None

        def remember(exc: BaseException) -> None:
            nonlocal first_error
            if first_error is None:
                first_error = exc

        try:
            self._stop_once()
        except BaseException as exc:
            remember(exc)
        finally:
            while not self._shutdown_is_settled():
                try:
                    self._stop_once()
                except BaseException as exc:
                    remember(exc)
                    continue
        if first_error is not None:
            if isinstance(first_error, (KeyboardInterrupt, SystemExit, MemoryError, _CapacityAbort)):
                raise first_error
            if isinstance(first_error, EnronCapacityError):
                raise first_error
            raise _error("monitor_shutdown_failed") from None

    def _shutdown_is_settled(self) -> bool:
        remote = getattr(self, "_remote", None)
        return (
            self._stopped
            and self._thread is None
            and (remote is None or (remote.stopped and not remote.thread.is_alive()))
            and not self._watchdog._installed
        )

    def _stop_once(self) -> None:
        first_error: BaseException | None = None

        def remember(exc: BaseException) -> None:
            nonlocal first_error
            if first_error is None:
                first_error = exc

        if self._shutdown_is_settled():
            return
        self._stop.set()
        thread = self._thread
        if thread is not None:
            join_timeout = max(1.0, self.interval_ns / 1_000_000_000 * 4)
            # Cleanup cannot safely race a monitor that still holds tree
            # descriptors or can fire the watchdog.  Do not abandon this
            # join: the public production run is already bounded by its
            # parent worker timeout/recovery path, while a local hard exit
            # would discard authority for sensitive inodes moved outside
            # the stage before that parent can recover them.
            while thread.is_alive():
                try:
                    thread.join(join_timeout)
                except BaseException as exc:
                    remember(exc)
                    continue
                if thread.is_alive():
                    try:
                        self._record_failure("monitor_shutdown_failed")
                    except BaseException as exc:
                        remember(exc)
            self._thread = None
        try:
            remote = getattr(self, "_remote", None)
            if remote is not None:
                remote.stop()
            else:
                self._observe("boundary")
        except BaseException as exc:
            remember(exc)
        finally:
            while self._watchdog._installed:
                try:
                    self._watchdog.close()
                except BaseException as exc:
                    remember(exc)
            self._stopped = True
        if first_error is not None:
            raise first_error

    def begin_phase(self, phase: str, started_ns: int) -> None:
        with self._observation_lock:
            owned = self.tree.logical_bytes()
            with self._lock:
                if phase in self._states or self._current_phase is not None:
                    raise _error("capacity_failed")
                wall_now = self.wall_clock()
                self._states[phase] = _PhaseMeasurements(
                    started_ns=started_ns,
                    started_wall_ns=wall_now,
                    last_owned=owned,
                    owned_high_water=owned,
                    last_progress_wall_ns=wall_now,
                    last_activity_observation_wall_ns=wall_now,
                )
                self._current_phase = phase
                self._global_owned_high_water = max(self._global_owned_high_water, owned)
                self._latest_exact_owned = owned
            self._observe_serialized("boundary", logical_owned=owned)
        self.raise_if_failed()

    def _barrier_remote_before_progress_failure(self, kind: str) -> None:
        remote = getattr(self, "_remote", None)
        if remote is not None:
            remote.force(kind)

    def checkpoint(self, phase: str, completed_records: int) -> None:
        with self._lock:
            self._raise_if_failed_locked()
            if type(completed_records) is not int or completed_records <= 0:
                raise _CapacityAbort("checkpoint_invalid")
        try:
            owned = self.tree.logical_bytes()
        except EnronCapacityError:
            self._record_failure("private_tree_invalid")
            self.raise_if_failed()
            raise _CapacityAbort("private_tree_invalid") from None
        barrier_completed = False
        while True:
            needs_barrier = False
            with self._lock:
                self._raise_if_failed_locked()
                state = self._states.get(phase)
                if state is None or self._current_phase != phase:
                    raise _CapacityAbort("checkpoint_invalid")
                gap = completed_records - state.last_completed
                if gap <= 0:
                    raise _CapacityAbort("checkpoint_invalid")
                if gap > MAX_CHECKPOINT_RECORD_GAP:
                    raise _CapacityAbort("checkpoint_gap")
                if state.checkpoint_count >= MAX_CHECKPOINTS_PER_PHASE:
                    raise _CapacityAbort("checkpoint_limit")
                state.last_owned = owned
                state.owned_high_water = max(state.owned_high_water, owned)
                self._global_owned_high_water = max(self._global_owned_high_water, owned)
                self._latest_exact_owned = owned
                wall_now = self.wall_clock()
                previous_progress_wall = state.last_progress_wall_ns or state.started_wall_ns
                wall_gap = wall_now - previous_progress_wall
                if wall_gap < 0:
                    raise _CapacityAbort("clock_invalid")
                if wall_gap > MAX_PROGRESS_CHECKPOINT_WALL_GAP_NS:
                    if not barrier_completed and getattr(self, "_remote", None) is not None:
                        needs_barrier = True
                    else:
                        self._record_progress_failure(
                            phase,
                            state,
                            origin="checkpoint_call",
                            attempted_kind="checkpoint",
                            wall_now=wall_now,
                            wall_gap=wall_gap,
                        )
                        self._raise_if_failed_locked()
                        raise _CapacityAbort("checkpoint_wall_gap")
                else:
                    self._accept_progress(state, kind="checkpoint", wall_now=wall_now, wall_gap=wall_gap)
                    state.last_activity_observation_wall_ns = wall_now
                    state.checkpoint_count += 1
                    state.last_completed = completed_records
                    state.maximum_checkpoint_gap = max(state.maximum_checkpoint_gap, gap)
                    self._append_progress_signal(
                        state,
                        kind="checkpoint",
                        completed_records=completed_records,
                        wall_now=wall_now,
                        wall_gap=wall_gap,
                    )
            if needs_barrier:
                self._barrier_remote_before_progress_failure("checkpoint")
                barrier_completed = True
                continue
            break
        self._observe("checkpoint", completed_records=completed_records, logical_owned=owned)
        now = _probe_monotonic_ns(self.probe)
        with self._lock:
            state = self._states[phase]
            checkpoints = cast(list[dict[str, int]], state.checkpoints)
            checkpoints.append(
                {
                    "sequence": state.checkpoint_count,
                    "completed_records": completed_records,
                    "elapsed_ns": now - state.started_ns,
                    "wall_elapsed_ns": wall_now - state.started_wall_ns,
                }
            )
        self._enforce_owned(owned)
        self.raise_if_failed()

    def heartbeat(self, phase: str) -> None:
        barrier_completed = False
        while True:
            needs_barrier = False
            with self._lock:
                self._raise_if_failed_locked()
                wall_now = self.wall_clock()
                state = self._states.get(phase)
                if state is None or self._current_phase != phase:
                    raise _CapacityAbort("checkpoint_invalid")
                previous_progress_wall = state.last_progress_wall_ns or state.started_wall_ns
                wall_gap = wall_now - previous_progress_wall
                if wall_gap < 0:
                    raise _CapacityAbort("clock_invalid")
                if wall_gap > MAX_PROGRESS_CHECKPOINT_WALL_GAP_NS:
                    if not barrier_completed and getattr(self, "_remote", None) is not None:
                        needs_barrier = True
                    else:
                        self._record_progress_failure(
                            phase,
                            state,
                            origin="heartbeat_call",
                            attempted_kind="heartbeat",
                            wall_now=wall_now,
                            wall_gap=wall_gap,
                        )
                        self._raise_if_failed_locked()
                        raise _CapacityAbort("checkpoint_wall_gap")
                else:
                    self._accept_progress(state, kind="heartbeat", wall_now=wall_now, wall_gap=wall_gap)
                    self._append_progress_signal(
                        state,
                        kind="heartbeat",
                        completed_records=state.last_completed,
                        wall_now=wall_now,
                        wall_gap=wall_gap,
                    )
                    state.last_activity_observation_wall_ns = wall_now
                    latest_exact_owned = self._latest_exact_owned
            if needs_barrier:
                self._barrier_remote_before_progress_failure("heartbeat")
                barrier_completed = True
                continue
            break
        self._observe(
            "heartbeat",
            completed_records=state.last_completed or None,
            logical_owned=latest_exact_owned,
        )
        self.raise_if_failed()

    def activity(self, phase: str) -> None:
        observe_resources = False
        completed_records = 0
        barrier_completed = False
        while True:
            needs_barrier = False
            with self._lock:
                self._raise_if_failed_locked()
                wall_now = self.wall_clock()
                state = self._states.get(phase)
                if state is None or self._current_phase != phase:
                    raise _CapacityAbort("checkpoint_invalid")
                previous_progress_wall = state.last_progress_wall_ns or state.started_wall_ns
                wall_gap = wall_now - previous_progress_wall
                if wall_gap < 0:
                    raise _CapacityAbort("clock_invalid")
                if wall_gap > MAX_PROGRESS_CHECKPOINT_WALL_GAP_NS:
                    if not barrier_completed and getattr(self, "_remote", None) is not None:
                        needs_barrier = True
                    else:
                        self._record_progress_failure(
                            phase,
                            state,
                            origin="activity_call",
                            attempted_kind="activity",
                            wall_now=wall_now,
                            wall_gap=wall_gap,
                        )
                        self._raise_if_failed_locked()
                        raise _CapacityAbort("checkpoint_wall_gap")
                else:
                    self._accept_progress(state, kind="activity", wall_now=wall_now, wall_gap=wall_gap)
                    self._append_progress_signal(
                        state,
                        kind="activity",
                        completed_records=state.last_completed,
                        wall_now=wall_now,
                        wall_gap=wall_gap,
                    )
                    last_observation = state.last_activity_observation_wall_ns or state.started_wall_ns
                    if wall_now - last_observation >= ACTIVITY_PRIVATE_TREE_VALIDATION_INTERVAL_NS:
                        state.last_activity_observation_wall_ns = wall_now
                        observe_resources = True
                        completed_records = state.last_completed
            if needs_barrier:
                self._barrier_remote_before_progress_failure("activity")
                barrier_completed = True
                continue
            break
        if observe_resources:
            self._observe("activity", completed_records=completed_records or None)
        self.raise_if_failed()

    def finish_phase(self, phase: str, records: int) -> dict[str, Any]:
        with self._observation_lock:
            self._observe_serialized("boundary")
            self.raise_if_failed()
            with self._lock:
                state = self._states.get(phase)
                if state is None or self._current_phase != phase:
                    raise _error("capacity_failed")
                if state.checkpoint_count == 0:
                    raise _error("checkpoint_required")
                if state.last_completed != records:
                    raise _error("checkpoint_required")
                now = _probe_monotonic_ns(self.probe)
                wall_now = self.wall_clock()
                previous_progress_wall = state.last_progress_wall_ns or state.started_wall_ns
                final_wall_gap = wall_now - previous_progress_wall
                if final_wall_gap < 0:
                    raise _error("clock_invalid")
                if final_wall_gap > MAX_PROGRESS_CHECKPOINT_WALL_GAP_NS:
                    self._record_progress_failure(
                        phase,
                        state,
                        origin="phase_finish",
                        attempted_kind="phase_finish",
                        wall_now=wall_now,
                        wall_gap=final_wall_gap,
                    )
                    raise _error("checkpoint_wall_gap", diagnostic=self.failure_diagnostic())
                self._accept_progress(state, kind="phase_finish", wall_now=wall_now, wall_gap=final_wall_gap)
                self._append_progress_signal(
                    state,
                    kind="phase_boundary",
                    completed_records=state.last_completed,
                    wall_now=wall_now,
                    wall_gap=final_wall_gap,
                )
                elapsed_ns = now - state.started_ns
                self._current_phase = None
                return self._phase_snapshot(state, elapsed_ns)

    def observe_transaction_boundary(self, owned: int) -> None:
        with self._lock:
            self._global_owned_high_water = max(self._global_owned_high_water, owned)
            self._latest_exact_owned = owned
            phase = self._current_phase
            if phase is not None:
                state = self._states[phase]
                state.last_owned = owned
                state.owned_high_water = max(state.owned_high_water, owned)
        # Publish the exact transaction size before requesting the independent
        # sample, but let that sample arbitrate every colliding resource limit.
        # Pre-latching owned bytes here would make scheduler order decide
        # whether a higher-priority launcher failure was retained.
        self._observe("boundary", logical_owned=owned)
        self.raise_if_failed()

    def global_snapshot(self) -> dict[str, int]:
        with self._lock:
            return {
                "resource_observation_count": self._global_observations,
                "resource_acquisition_retry_count": self._global_resource_acquisition_retries,
                "peak_process_tree_rss_bytes": self._global_peak_rss,
                "minimum_free_disk_bytes": self._global_minimum_free,
                "owned_disk_high_water_bytes": self._global_owned_high_water,
                "maximum_resource_observation_wall_gap_ns": self._global_maximum_resource_wall_gap_ns,
                "maximum_resource_acquisition_duration_ns": self._global_maximum_resource_acquisition_duration_ns,
            }

    def failure_diagnostic(self) -> dict[str, Any] | None:
        with self._lock:
            return None if self._failure_diagnostic is None else dict(self._failure_diagnostic)

    def _retain_partial_resource_extrema(
        self,
        *,
        rss: int,
        minimum_free: int | None,
        acquisition_retries: int,
        acquisition_duration_ns: int = 0,
        now: int | None = None,
        wall_now: int | None = None,
    ) -> None:
        """Retain valid hard-limit evidence from an intentionally incomplete sample."""

        with self._lock:
            self._global_peak_rss = max(self._global_peak_rss, rss)
            self._global_resource_acquisition_retries += acquisition_retries
            self._global_maximum_resource_acquisition_duration_ns = max(
                self._global_maximum_resource_acquisition_duration_ns,
                acquisition_duration_ns,
            )
            if minimum_free is not None:
                self._global_minimum_free = min(self._global_minimum_free, minimum_free)
            phase = self._current_phase
            if phase is not None:
                state = self._states[phase]
                phase_eligible = (now is None or now >= state.started_ns) and (
                    wall_now is None or wall_now >= state.started_wall_ns
                )
                if not phase_eligible:
                    return
                state.peak_rss = max(state.peak_rss, rss)
                state.resource_acquisition_retry_count += acquisition_retries
                state.maximum_resource_acquisition_duration_ns = max(
                    state.maximum_resource_acquisition_duration_ns,
                    acquisition_duration_ns,
                )
                if minimum_free is not None:
                    state.minimum_free = (
                        minimum_free if state.minimum_free is None else min(state.minimum_free, minimum_free)
                    )

    def raise_if_failed(self) -> None:
        with self._lock:
            self._raise_if_failed_locked()

    def _raise_if_failed_locked(self) -> None:
        if self._failure_code is not None:
            raise _CapacityAbort(self._failure_code)

    def _loop(self) -> None:
        next_deadline_ns = time.monotonic_ns() + self.interval_ns
        while True:
            remaining_ns = max(0, next_deadline_ns - time.monotonic_ns())
            if self._stop.wait(remaining_ns / 1_000_000_000):
                return
            try:
                self._observe("continuous")
            except _CapacityAbort as exc:
                self._record_failure(exc.code)
                return
            except (KeyboardInterrupt, SystemExit, MemoryError):
                self._record_failure("phase_interrupted")
                return
            next_deadline_ns += self.interval_ns
            now_ns = time.monotonic_ns()
            if next_deadline_ns <= now_ns:
                next_deadline_ns = now_ns

    def _observe(
        self,
        kind: str,
        *,
        completed_records: int | None = None,
        logical_owned: int | None = None,
    ) -> None:
        with self._observation_lock:
            self._observe_serialized(kind, completed_records=completed_records, logical_owned=logical_owned)

    def _observe_serialized(
        self,
        kind: str,
        *,
        completed_records: int | None = None,
        logical_owned: int | None = None,
    ) -> None:
        if logical_owned is None:
            try:
                logical_owned = self.tree.logical_bytes()
            except EnronCapacityError as exc:
                self._record_failure(exc.code if exc.code in _ERROR_MESSAGES else "private_tree_invalid")
                return
        with self._lock:
            self._latest_exact_owned = logical_owned
            self._global_owned_high_water = max(self._global_owned_high_water, logical_owned)
        if self._remote is not None:
            self._remote.force(kind)
            return
        try:
            now = _probe_monotonic_ns(self.probe)
            rss, rss_retries = _acquire_runtime_process_tree_rss(self.probe)
            if rss > self.preflight.maximum_peak_rss_bytes:
                self._retain_partial_resource_extrema(
                    rss=rss,
                    minimum_free=None,
                    acquisition_retries=rss_retries,
                )
                self._record_failure("rss_limit")
                return
            minimum_free, output_disk, disk_retries = _sample_runtime_filesystems(self.probe, self.preflight)
            acquisition_retries = rss_retries + disk_retries
        except _RuntimeDiskFloor as exc:
            self._retain_partial_resource_extrema(
                rss=rss,
                minimum_free=exc.minimum_free,
                acquisition_retries=rss_retries + exc.retry_count,
            )
            self._record_failure("runtime_disk_floor")
            return
        except _CapacityAbort:
            raise
        except EnronCapacityError as exc:
            self._record_failure(
                exc.code
                if exc.code
                in {
                    "clock_invalid",
                    "private_tree_invalid",
                    "rss_limit",
                    "runtime_disk_floor",
                    "runtime_filesystem_changed",
                    "rss_acquisition_exhausted",
                    "disk_acquisition_exhausted",
                }
                else "resource_measurement_failed"
            )
            return
        except (KeyboardInterrupt, SystemExit, MemoryError):
            raise
        except BaseException:
            self._record_failure("resource_measurement_failed")
            return
        try:
            wall_now = self.wall_clock()
        except (KeyboardInterrupt, SystemExit, MemoryError):
            raise
        except BaseException:
            self._record_failure("clock_invalid")
            return
        self._accept_resource_sample(
            kind=kind,
            completed_records=completed_records,
            logical_owned=logical_owned,
            now=now,
            wall_now=wall_now,
            rss=rss,
            minimum_free=minimum_free,
            output_free=output_disk.free,
            acquisition_retries=acquisition_retries,
            provided_wall_gap=None,
            acquisition_duration_ns=0,
            rss_duration_ns=0,
            filesystem_duration_ns=0,
            scheduler_lateness_ns=0,
            provided_failure_code=None,
            provided_failure_code_is_authoritative=False,
        )

    def _accept_remote_resource_sample(
        self,
        *,
        kind: str,
        completed_records: int | None,
        wall_now: int,
        now: int,
        rss: int,
        minimum_free: int,
        output_free: int,
        rss_retries: int,
        filesystem_retries: int,
        wall_gap: int,
        acquisition_duration_ns: int,
        rss_duration_ns: int,
        filesystem_duration_ns: int,
        scheduler_lateness_ns: int,
        failure_code: str | None,
    ) -> None:
        with self._lock:
            logical_owned = self._latest_exact_owned
        self._accept_resource_sample(
            kind=kind,
            completed_records=completed_records,
            logical_owned=logical_owned,
            now=now,
            wall_now=wall_now,
            rss=rss,
            minimum_free=minimum_free,
            output_free=output_free,
            acquisition_retries=rss_retries + filesystem_retries,
            provided_wall_gap=wall_gap,
            acquisition_duration_ns=acquisition_duration_ns,
            rss_duration_ns=rss_duration_ns,
            filesystem_duration_ns=filesystem_duration_ns,
            scheduler_lateness_ns=scheduler_lateness_ns,
            provided_failure_code=failure_code,
            provided_failure_code_is_authoritative=True,
        )

    def _accept_resource_sample(
        self,
        *,
        kind: str,
        completed_records: int | None,
        logical_owned: int,
        now: int,
        wall_now: int,
        rss: int,
        minimum_free: int,
        output_free: int,
        acquisition_retries: int,
        provided_wall_gap: int | None,
        acquisition_duration_ns: int,
        rss_duration_ns: int,
        filesystem_duration_ns: int,
        scheduler_lateness_ns: int,
        provided_failure_code: str | None,
        provided_failure_code_is_authoritative: bool,
    ) -> None:
        filesystem_delta = max(0, self.preflight.output_preflight_free_disk_bytes - output_free)
        owned = max(logical_owned, filesystem_delta)
        with self._lock:
            previous_global_wall = self._global_last_resource_wall_ns
            if previous_global_wall is None:
                previous_global_wall = wall_now
            global_resource_wall_gap = wall_now - previous_global_wall
            if (
                now < self.run_started_ns
                or now < self._global_last_probe_ns
                or global_resource_wall_gap < 0
                or (provided_wall_gap is not None and provided_wall_gap != global_resource_wall_gap)
            ):
                self._record_failure("clock_invalid")
                return
            phase = self._current_phase
            phase_state = None if phase is None else self._states[phase]
            phase_eligible = bool(
                phase_state is not None and now >= phase_state.started_ns and wall_now >= phase_state.started_wall_ns
            )
            self._global_last_resource_wall_ns = wall_now
            self._global_last_probe_ns = now
            self._global_observations += 1
            self._global_resource_acquisition_retries += acquisition_retries
            self._global_peak_rss = max(self._global_peak_rss, rss)
            self._global_minimum_free = min(self._global_minimum_free, minimum_free)
            self._global_owned_high_water = max(self._global_owned_high_water, owned)
            self._global_maximum_resource_wall_gap_ns = max(
                self._global_maximum_resource_wall_gap_ns,
                global_resource_wall_gap,
            )
            self._global_maximum_resource_acquisition_duration_ns = max(
                self._global_maximum_resource_acquisition_duration_ns,
                acquisition_duration_ns,
            )
            limit_failure: str | None = None
            if acquisition_duration_ns > MAX_RESOURCE_ACQUISITION_DURATION_NS:
                limit_failure = "resource_acquisition_timeout"
            elif rss > self.preflight.maximum_peak_rss_bytes:
                limit_failure = "rss_limit"
            elif minimum_free < MIN_RUNTIME_FREE_DISK_BYTES:
                limit_failure = "runtime_disk_floor"
            elif owned > MAX_OWNED_DISK_BYTES:
                limit_failure = "owned_disk_limit"
            elif global_resource_wall_gap > MAX_RESOURCE_OBSERVATION_WALL_GAP_NS:
                limit_failure = "resource_observation_gap"
            elif now - self.run_started_ns > MAX_TOTAL_RUNTIME_NS:
                limit_failure = "runtime_limit"
            if (
                provided_failure_code_is_authoritative
                and acquisition_duration_ns <= MAX_RESOURCE_ACQUISITION_DURATION_NS
            ):
                limit_failure = _combine_resource_failure_codes(limit_failure, provided_failure_code)
            if limit_failure == "resource_observation_gap":
                self._record_failure(
                    limit_failure,
                    diagnostic=_resource_gap_failure_diagnostic(
                        phase=phase if phase_eligible else None,
                        sample_kind=kind,
                        sequence=self._global_observations,
                        observed_resource_gap_ns=global_resource_wall_gap,
                        acquisition_duration_ns=acquisition_duration_ns,
                        rss_duration_ns=rss_duration_ns,
                        filesystem_duration_ns=filesystem_duration_ns,
                        acquisition_retry_count=acquisition_retries,
                        scheduler_lateness_ns=scheduler_lateness_ns,
                    ),
                )
            elif limit_failure is not None:
                self._record_failure(limit_failure)
            if phase is not None and phase_state is not None and phase_eligible:
                state = phase_state
                previous_resource_wall = state.last_resource_wall_ns or state.started_wall_ns
                resource_wall_gap = wall_now - previous_resource_wall
                progress_wall_gap = wall_now - (state.last_progress_wall_ns or state.started_wall_ns)
                if resource_wall_gap < 0:
                    self._record_failure("clock_invalid")
                    return
                state.observations += 1
                state.resource_acquisition_retry_count += acquisition_retries
                state.last_resource_wall_ns = wall_now
                state.maximum_resource_wall_gap_ns = max(state.maximum_resource_wall_gap_ns, resource_wall_gap)
                state.maximum_resource_acquisition_duration_ns = max(
                    state.maximum_resource_acquisition_duration_ns,
                    acquisition_duration_ns,
                )
                if progress_wall_gap >= 0:
                    state.maximum_progress_wall_gap_ns = max(state.maximum_progress_wall_gap_ns, progress_wall_gap)
                state.last_owned = owned
                sample = {
                    "sequence": state.observations,
                    "elapsed_ns": now - state.started_ns,
                    "wall_elapsed_ns": wall_now - state.started_wall_ns,
                    "sample_kind": kind,
                    "completed_records": completed_records,
                    "process_tree_rss_bytes": rss,
                    "owned_disk_bytes": owned,
                    "free_disk_bytes": minimum_free,
                    "resource_acquisition_duration_ns": acquisition_duration_ns,
                    "rss_acquisition_duration_ns": rss_duration_ns,
                    "filesystem_acquisition_duration_ns": filesystem_duration_ns,
                    "resource_acquisition_retry_count": acquisition_retries,
                    "scheduler_lateness_ns": scheduler_lateness_ns,
                }
                state.peak_rss = max(state.peak_rss, rss)
                state.minimum_free = (
                    minimum_free if state.minimum_free is None else min(state.minimum_free, minimum_free)
                )
                state.owned_high_water = max(state.owned_high_water, owned)
                state.last_sample = sample
                if state.peak_sample is None or rss >= int(state.peak_sample["process_tree_rss_bytes"]):
                    state.peak_sample = sample
                if state.minimum_free_sample is None or minimum_free <= int(
                    state.minimum_free_sample["free_disk_bytes"]
                ):
                    state.minimum_free_sample = sample
                if state.maximum_wall_gap_sample is None or resource_wall_gap >= int(
                    state.maximum_wall_gap_sample["resource_observation_wall_gap_ns"]
                ):
                    sample["resource_observation_wall_gap_ns"] = resource_wall_gap
                    state.maximum_wall_gap_sample = sample
                else:
                    sample["resource_observation_wall_gap_ns"] = resource_wall_gap
                if state.maximum_acquisition_sample is None or acquisition_duration_ns >= int(
                    state.maximum_acquisition_sample["resource_acquisition_duration_ns"]
                ):
                    state.maximum_acquisition_sample = sample
                if state.owned_peak_sample is None or owned >= int(state.owned_peak_sample["owned_disk_bytes"]):
                    state.owned_peak_sample = sample
                self._retain_sample(state, sample)
                if resource_wall_gap > MAX_RESOURCE_OBSERVATION_WALL_GAP_NS:
                    self._record_failure(
                        "resource_observation_gap",
                        diagnostic=_resource_gap_failure_diagnostic(
                            phase=phase,
                            sample_kind=kind,
                            sequence=state.observations,
                            observed_resource_gap_ns=resource_wall_gap,
                            acquisition_duration_ns=acquisition_duration_ns,
                            rss_duration_ns=rss_duration_ns,
                            filesystem_duration_ns=filesystem_duration_ns,
                            acquisition_retry_count=acquisition_retries,
                            scheduler_lateness_ns=scheduler_lateness_ns,
                        ),
                    )
                if progress_wall_gap > MAX_PROGRESS_CHECKPOINT_WALL_GAP_NS:
                    self._record_progress_failure(
                        phase,
                        state,
                        origin="continuous_observation",
                        attempted_kind="continuous_observation",
                        wall_now=wall_now,
                        wall_gap=progress_wall_gap,
                    )

    def _phase_snapshot(self, state: _PhaseMeasurements, elapsed_ns: int) -> dict[str, Any]:
        retained = list(cast(list[dict[str, Any]], state.samples))
        retained.extend(cast(list[dict[str, Any]], state.cadence_samples))
        for sample in (
            state.first_sample,
            state.peak_sample,
            state.owned_peak_sample,
            state.minimum_free_sample,
            state.maximum_wall_gap_sample,
            state.maximum_acquisition_sample,
            state.last_sample,
        ):
            if sample is not None and all(item["sequence"] != sample["sequence"] for item in retained):
                retained.append(sample)
        retained.sort(key=lambda item: int(item["sequence"]))
        progress_signals = list(cast(list[dict[str, Any]], state.progress_signals))
        progress_signals.extend(cast(list[dict[str, Any]], state.liveness_samples))
        for progress_signal in (state.maximum_progress_signal, state.last_liveness_signal):
            if progress_signal is not None and all(
                item["sequence"] != progress_signal["sequence"] for item in progress_signals
            ):
                progress_signals.append(progress_signal)
        progress_signals.sort(key=lambda item: int(item["sequence"]))
        if len(progress_signals) > MAX_PROGRESS_SIGNALS_PER_PHASE:
            raise _CapacityAbort("checkpoint_limit")
        return {
            "elapsed_ns": elapsed_ns,
            "resource_observation_count": state.observations,
            "resource_acquisition_retry_count": state.resource_acquisition_retry_count,
            "peak_process_tree_rss_bytes": state.peak_rss,
            "owned_disk_high_water_bytes": state.owned_high_water,
            "minimum_free_disk_bytes": 0 if state.minimum_free is None else state.minimum_free,
            "maximum_resource_observation_wall_gap_ns": state.maximum_resource_wall_gap_ns,
            "maximum_resource_acquisition_duration_ns": state.maximum_resource_acquisition_duration_ns,
            "maximum_progress_checkpoint_wall_gap_ns": state.maximum_progress_wall_gap_ns,
            "resource_samples": retained,
            "checkpoint_count": state.checkpoint_count,
            "maximum_checkpoint_gap_records": state.maximum_checkpoint_gap,
            "checkpoint_samples": list(cast(list[dict[str, int]], state.checkpoints)),
            "progress_signal_count": state.progress_signal_count,
            "progress_signals": progress_signals,
        }

    def _accept_progress(self, state: _PhaseMeasurements, *, kind: str, wall_now: int, wall_gap: int) -> None:
        state.maximum_progress_wall_gap_ns = max(state.maximum_progress_wall_gap_ns, wall_gap)
        state.last_progress_wall_ns = wall_now
        state.last_progress_kind = kind

    def _record_progress_failure(
        self,
        phase: str,
        state: _PhaseMeasurements,
        *,
        origin: str,
        attempted_kind: str,
        wall_now: int,
        wall_gap: int,
    ) -> None:
        diagnostic = {
            "phase": phase,
            "origin": origin,
            "last_accepted_progress_kind": state.last_progress_kind,
            "attempted_progress_kind": attempted_kind,
            "last_completed_records": state.last_completed,
            "checkpoint_count": state.checkpoint_count,
            "progress_signal_count": state.progress_signal_count,
            "phase_wall_elapsed_ns": wall_now - state.started_wall_ns,
            "observed_progress_gap_ns": wall_gap,
        }
        self._record_failure("checkpoint_wall_gap", diagnostic=diagnostic)

    def _record_failure_locked(self, code: str, diagnostic: Mapping[str, Any] | None) -> bool:
        if self._failure_code is not None:
            return False
        self._failure_code = code if code in _ERROR_MESSAGES else "resource_measurement_failed"
        validated = _validated_failure_diagnostic(diagnostic)
        if self._failure_code == "checkpoint_wall_gap" and validated is not None:
            self._failure_diagnostic = validated if "origin" in validated else None
        elif self._failure_code == "resource_observation_gap" and validated is not None:
            self._failure_diagnostic = validated if validated.get("diagnostic_kind") else None
        else:
            self._failure_diagnostic = None
        return True

    def _record_failure(self, code: str, *, diagnostic: Mapping[str, Any] | None = None) -> None:
        with self._lock:
            newly_recorded = self._record_failure_locked(code, diagnostic)
        if newly_recorded:
            self._watchdog.trigger()

    def _record_remote_failure(self, code: str, *, diagnostic: Mapping[str, Any] | None = None) -> None:
        with self._lock:
            remote_code = code if code in _ERROR_MESSAGES else "resource_measurement_failed"
            owned_code = "owned_disk_limit" if self._latest_exact_owned > MAX_OWNED_DISK_BYTES else None
            selected_code = _combine_resource_failure_codes(owned_code, remote_code)
            if selected_code is None:
                selected_code = "resource_measurement_failed"
            selected_diagnostic = diagnostic if selected_code == remote_code else None
            newly_recorded = self._record_failure_locked(selected_code, selected_diagnostic)
        if newly_recorded:
            self._watchdog.trigger()

    def _enforce_owned(self, owned: int) -> None:
        if owned > MAX_OWNED_DISK_BYTES:
            self._record_failure("owned_disk_limit")

    def _current_failure_code(self) -> str | None:
        with self._lock:
            return self._failure_code

    def _retain_sample(self, state: _PhaseMeasurements, sample: dict[str, Any]) -> None:
        sequence = int(sample["sequence"])
        if state.first_sample is None:
            state.first_sample = sample
        if sequence & (sequence - 1) == 0:
            cadence = cast(list[dict[str, Any]], state.cadence_samples)
            if len(cadence) < 64:
                cadence.append(sample)
            return
        samples = cast(list[dict[str, Any]], state.samples)
        priorities = cast(list[int], state.sample_priorities)
        priority = int.from_bytes(hashlib.sha256(str(sequence).encode("ascii")).digest()[:8], "big")
        reservoir_capacity = MAX_RESOURCE_SAMPLES_PER_PHASE - 64 - 7
        if len(samples) < reservoir_capacity:
            samples.append(sample)
            priorities.append(priority)
            return
        worst_index = max(range(len(priorities)), key=lambda index: priorities[index])
        if priority < priorities[worst_index]:
            samples[worst_index] = sample
            priorities[worst_index] = priority

    def _append_progress_signal(
        self,
        state: _PhaseMeasurements,
        *,
        kind: str,
        completed_records: int,
        wall_now: int,
        wall_gap: int,
    ) -> None:
        state.progress_signal_count += 1
        signal = {
            "sequence": state.progress_signal_count,
            "kind": kind,
            "completed_records": completed_records,
            "wall_elapsed_ns": wall_now - state.started_wall_ns,
            "progress_wall_gap_ns": wall_gap,
        }
        if state.maximum_progress_signal is None or wall_gap >= int(
            state.maximum_progress_signal["progress_wall_gap_ns"]
        ):
            state.maximum_progress_signal = signal
        if kind not in {"heartbeat", "activity"}:
            signals = cast(list[dict[str, Any]], state.progress_signals)
            signals.append(signal)
            return
        state.last_liveness_signal = signal
        samples = cast(list[dict[str, Any]], state.liveness_samples)
        priorities = cast(list[int], state.liveness_priorities)
        liveness_capacity = MAX_PROGRESS_SIGNALS_PER_PHASE - MAX_CHECKPOINTS_PER_PHASE - 3
        if liveness_capacity <= 0:
            raise _CapacityAbort("checkpoint_limit")
        sequence = state.progress_signal_count
        priority = int.from_bytes(hashlib.sha256(f"{kind}:{sequence}".encode("ascii")).digest()[:8], "big")
        if len(samples) < liveness_capacity:
            samples.append(signal)
            priorities.append(priority)
            return
        worst_index = max(range(len(priorities)), key=lambda index: priorities[index])
        if priority < priorities[worst_index]:
            samples[worst_index] = signal
            priorities[worst_index] = priority


def capacity_policy() -> dict[str, Any]:
    """Return the single current preregistered capacity policy."""

    policy: dict[str, Any] = {
        "schema_version": CAPACITY_POLICY_SCHEMA_VERSION,
        "dataset_id": ENRON_DATASET_ID,
        "dataset_revision": ENRON_DATASET_REVISION,
        "source_rows": ENRON_SOURCE_ROWS,
        "phases": list(CAPACITY_PHASES),
        "max_absolute_rss_bytes": MAX_ABSOLUTE_RSS_BYTES,
        "physical_memory_fraction": {
            "numerator": PHYSICAL_MEMORY_FRACTION_NUMERATOR,
            "denominator": PHYSICAL_MEMORY_FRACTION_DENOMINATOR,
        },
        "peak_rss_fraction_of_effective_cap": {
            "numerator": PEAK_RSS_FRACTION_NUMERATOR,
            "denominator": PEAK_RSS_FRACTION_DENOMINATOR,
        },
        "minimum_preflight_free_disk_bytes": MIN_PREFLIGHT_FREE_DISK_BYTES,
        "maximum_owned_disk_bytes": MAX_OWNED_DISK_BYTES,
        "minimum_runtime_free_disk_bytes": MIN_RUNTIME_FREE_DISK_BYTES,
        "maximum_total_runtime_ns": MAX_TOTAL_RUNTIME_NS,
        "minimum_phase_records_per_second": MIN_PHASE_RECORDS_PER_SECOND,
        "maximum_checkpoint_record_gap": MAX_CHECKPOINT_RECORD_GAP,
        "maximum_checkpoints_per_phase": MAX_CHECKPOINTS_PER_PHASE,
        "maximum_retained_progress_signals_per_phase": MAX_PROGRESS_SIGNALS_PER_PHASE,
        "unbounded_liveness_enforcement_with_bounded_retained_evidence": True,
        "maximum_retained_resource_samples_per_phase": MAX_RESOURCE_SAMPLES_PER_PHASE,
        "production_monitor_interval_ns": PRODUCTION_MONITOR_INTERVAL_NS,
        "maximum_resource_observation_wall_gap_ns": MAX_RESOURCE_OBSERVATION_WALL_GAP_NS,
        "maximum_resource_acquisition_duration_ns": MAX_RESOURCE_ACQUISITION_DURATION_NS,
        "runtime_resource_acquisition_max_attempts": _RUNTIME_RESOURCE_ACQUISITION_MAX_ATTEMPTS,
        "runtime_resource_acquisition_retry_delay_ns": 0,
        "runtime_filesystem_acquisition_order": ["device", "disk", "device"],
        "darwin_process_tree_rss_timeout_ns": int(_DARWIN_PS_TIMEOUT_SECONDS * 1_000_000_000),
        "resource_acquisition_retry_count_required": True,
        "maximum_progress_checkpoint_wall_gap_ns": MAX_PROGRESS_CHECKPOINT_WALL_GAP_NS,
        "activity_record_interval": ACTIVITY_RECORD_INTERVAL,
        "activity_interval_at_minimum_throughput_ns": (
            ACTIVITY_RECORD_INTERVAL * 1_000_000_000 // MIN_PHASE_RECORDS_PER_SECOND
        ),
        "activity_private_tree_validation_interval_ns": ACTIVITY_PRIVATE_TREE_VALIDATION_INTERVAL_NS,
        "resource_observer_protocol": _RESOURCE_OBSERVER_PROTOCOL,
        "resource_observer_role": "launcher_process_observing_complete_execution_tree",
        "resource_observer_workload_gil_independent_required": True,
        "resource_observer_included_in_measured_process_tree": True,
        "production_process_containment": {
            "linux": _LINUX_PROCESS_CONTAINMENT,
            "darwin": _DARWIN_PROCESS_CONTAINMENT,
        },
        "production_process_creation_forbidden": True,
        "production_process_containment_runtime_attested": True,
        "terminal_process_snapshot_includes_rss": True,
        "terminal_audit_never_signals_bare_pid": True,
        "resource_observation_gap_semantics": "completed_valid_sample_to_completed_valid_sample",
        "resource_acquisitions_serialized": True,
        "startup_resource_acquisition_direct_deadline_supervision": True,
        "terminal_resource_acquisition_bounded_by_completion_gap": True,
        "partial_resource_sample_advances_cadence": False,
        "private_tree_scan_in_fast_resource_lane": False,
        "exact_private_tree_validation_at_checkpoints_and_boundaries_required": True,
        "owned_disk_high_water_semantics": "sampled_exact_tree_plus_shared_filesystem_free_space_delta",
        "strict_transient_private_tree_high_water_claimed": False,
        "resource_observer_start_timeout_ns": RESOURCE_OBSERVER_START_TIMEOUT_NS,
        "resource_observer_command_timeout_ns": RESOURCE_OBSERVER_COMMAND_TIMEOUT_NS,
        "production_worker_cleanup_grace_ns": PRODUCTION_WORKER_CLEANUP_GRACE_NS,
        "maximum_resource_observer_frame_bytes": MAX_RESOURCE_OBSERVER_FRAME_BYTES,
        "maximum_capacity_report_bytes": MAX_CAPACITY_REPORT_BYTES,
        "maximum_capacity_report_structural_bound_bytes": _MAX_CAPACITY_REPORT_STRUCTURAL_BOUND_BYTES,
        "maximum_portable_decision_bytes": MAX_PORTABLE_DECISION_BYTES,
        "maximum_portable_attempts": MAX_PORTABLE_ATTEMPTS,
        "reader_phase_environment_policy_sha256": _reader_phase_environment_policy_sha256(),
        "critical_reader_versions": {
            name: version for name, _import_name, _package_init, version in _CRITICAL_READER_DISTRIBUTIONS
        },
        "reader_official_endpoint_sha256": _hash_bytes(_READER_OFFICIAL_ENDPOINT.encode("utf-8")),
        "reader_cache_roots_phase_owned_required": True,
        "reader_ambient_credentials_disabled_required": True,
        "reader_explicit_anonymous_load_required": True,
        "reader_restrictive_umask_required": True,
        "reader_cache_symlinks_disabled_required": True,
        "reader_cache_lock_files_owner_only_required": True,
        "reader_cache_lock_mode": _READER_OWNER_ONLY_CACHE_LOCK_MODE,
        "reader_cache_lock_adapter_sha256": _reader_cache_lock_adapter_sha256(),
        "reader_network_activity_required": True,
        "reader_network_activity_adapter_sha256": _reader_network_activity_adapter_sha256(),
        "processed_bytes_measurement_boundary": _PROCESSED_BYTES_MEASUREMENT_BOUNDARY,
        "processed_bytes_by_phase": {
            "preparation": "prepared_records_artifact_bytes_plus_rejections_artifact_bytes",
            "split": "train_plus_validation_plus_test_role_jsonl_artifact_bytes",
            "build": "development_train_jsonl_artifact_bytes",
            "streaming_validation": "selected_validation_text_utf8_bytes",
            "deep_replay": "development_train_plus_validation_jsonl_artifact_bytes",
        },
        "maximum_retained_private_tombstones": MAX_RETAINED_PRIVATE_TOMBSTONES,
        "maximum_pinned_cleanup_files": _private_io._MAX_PINNED_CLEANUP_FILES,  # noqa: SLF001
        "pinned_cleanup_fd_reserve": _private_io._PINNED_CLEANUP_FD_RESERVE,  # noqa: SLF001
        "nested_phase_cleanup_ownership_required": True,
        "stopped_phase_writer_tree_adoption_required": True,
        "failed_cleanup_retains_payload_empty_private_tombstones": True,
        "private_tombstone_cleanup_is_offline_owner_controlled": True,
        "continuous_process_tree_rss_required": True,
        "continuous_free_disk_required": True,
        "continuous_all_owned_and_evidence_filesystems_required": True,
        "continuous_owned_filesystem_delta_required": True,
        "watchdog_interruption_required": True,
        "append_only_attempt_receipt_required": True,
    }
    return {**policy, "policy_sha256": _canonical_hash(policy)}


def run_enron_capacity(options: EnronCapacityOptions) -> dict[str, Any]:
    """Run production only in a fresh isolated Python worker from clean HEAD."""

    _validate_options(options)
    return _spawn_production_worker(options)


def _stable_bootstrap_directory(path: Path) -> Path:
    try:
        before = path.lstat()
        resolved = path.resolve(strict=True)
        after = path.lstat()
    except OSError:
        raise _error("production_identity_invalid") from None
    if (
        not path.is_absolute()
        or not stat.S_ISDIR(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or resolved != path
        or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
    ):
        raise _error("production_identity_invalid")
    return resolved


def _validated_capacity_bootstrap() -> tuple[Path, tuple[Path, ...], tuple[str, ...], int | None]:
    """Validate the stdlib-only launcher/worker import state without running site hooks."""

    marker = getattr(sys, _BOOTSTRAP_ATTRIBUTE, None)
    if not isinstance(marker, Mapping) or set(marker) != {
        "schema",
        "source_root",
        "dependency_roots",
        "baseline_path",
        "pycache_root",
        "resource_observer_fd",
    }:
        raise _error("production_identity_invalid")
    raw_dependencies = marker.get("dependency_roots")
    raw_baseline = marker.get("baseline_path")
    observer_fd = marker.get("resource_observer_fd")
    if (
        marker.get("schema") != _BOOTSTRAP_SCHEMA
        or not isinstance(marker.get("source_root"), str)
        or not isinstance(marker.get("pycache_root"), str)
        or not isinstance(raw_dependencies, list)
        or not raw_dependencies
        or any(not isinstance(value, str) for value in raw_dependencies)
        or not isinstance(raw_baseline, list)
        or any(not isinstance(value, str) or not value or not Path(value).is_absolute() for value in raw_baseline)
        or (observer_fd is not None and (type(observer_fd) is not int or observer_fd < 3))
        or not sys.flags.isolated
        or not sys.flags.no_site
        or not sys.flags.dont_write_bytecode
        or not sys.dont_write_bytecode
        or sys.pycache_prefix != marker.get("pycache_root")
        or "sitecustomize" in sys.modules
        or "usercustomize" in sys.modules
    ):
        raise _error("production_identity_invalid")

    source_root = _stable_bootstrap_directory(Path(cast(str, marker["source_root"])))
    try:
        _capacity_import_guard.assert_installed(source_root)
    except (ImportError, OSError, RuntimeError, TypeError, ValueError):
        raise _error("production_identity_invalid") from None
    dependencies = tuple(_stable_bootstrap_directory(Path(value)) for value in cast(list[str], raw_dependencies))
    if len(set(dependencies)) != len(dependencies):
        raise _error("production_identity_invalid")
    expected_source = (_git_root() / "src").resolve(strict=True)
    if source_root != expected_source:
        raise _error("production_identity_invalid")

    executable = Path(sys.executable)
    if os.name != "posix" or not executable.is_absolute() or executable.parent.name != "bin":
        raise _error("production_identity_invalid")
    environment = executable.parent.parent
    try:
        config = (environment / "pyvenv.cfg").lstat()
    except OSError:
        raise _error("production_identity_invalid") from None
    if not stat.S_ISREG(config.st_mode) or stat.S_ISLNK(config.st_mode):
        raise _error("production_identity_invalid")
    version = f"python{sys.version_info.major}.{sys.version_info.minor}"
    allowed_dependencies: dict[Path, str] = {}
    for library in ("lib", "lib64"):
        candidate = environment / library / version / "site-packages"
        try:
            candidate.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            raise _error("production_identity_invalid") from None
        try:
            resolved_candidate = candidate.resolve(strict=True)
        except OSError:
            raise _error("production_identity_invalid") from None
        validated = _stable_bootstrap_directory(resolved_candidate)
        allowed_dependencies.setdefault(validated, f"venv/{library}/{version}/site-packages")
    if set(dependencies) != set(allowed_dependencies):
        raise _error("production_identity_invalid")

    pycache_root = _stable_bootstrap_directory(Path(cast(str, marker["pycache_root"])))
    try:
        pycache_info = pycache_root.stat()
    except OSError:
        raise _error("production_identity_invalid") from None
    if pycache_info.st_uid != os.geteuid() or stat.S_IMODE(pycache_info.st_mode) & 0o077:
        raise _error("production_identity_invalid")
    expected_path = [*raw_baseline, *(os.fspath(path) for path in dependencies), os.fspath(source_root)]
    if sys.path != expected_path:
        raise _error("production_identity_invalid")
    layouts = tuple(allowed_dependencies[path] for path in dependencies)
    if observer_fd is not None:
        try:
            observer_info = os.fstat(observer_fd)
        except OSError:
            raise _error("production_identity_invalid") from None
        if not stat.S_ISSOCK(observer_info.st_mode):
            raise _error("production_identity_invalid")
    return source_root, dependencies, layouts, cast(int | None, observer_fd)


class _ResourceObserverEOF(Exception):
    """The private observer channel closed before its protocol completed."""


def _observer_mapping(value: object) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise _error("resource_measurement_failed")
    return cast(Mapping[str, Any], value)


def _observer_closed(value: Mapping[str, Any], fields: set[str]) -> None:
    if set(value) != fields:
        raise _error("resource_measurement_failed")


def _observer_int(value: object, *, minimum: int) -> int:
    if type(value) is not int or value < minimum or value > _MAX_RESOURCE_INTEGER:
        raise _error("resource_measurement_failed")
    return value


class _ResourceObserverFrames:
    """Bounded newline-frame reader for one private socket endpoint."""

    def __init__(self, endpoint: socket.socket) -> None:
        self.endpoint = endpoint
        self.buffer = bytearray()
        self._partial_frame_deadline_ns: int | None = None

    def receive(self, timeout_ns: int) -> list[dict[str, Any]]:
        if type(timeout_ns) is not int or timeout_ns < 0:
            raise _error("resource_measurement_failed")
        deadline_ns = time.monotonic_ns() + timeout_ns
        while True:
            effective_deadline_ns = (
                deadline_ns
                if self._partial_frame_deadline_ns is None
                else min(deadline_ns, self._partial_frame_deadline_ns)
            )
            now_ns = time.monotonic_ns()
            remaining_ns = effective_deadline_ns - now_ns
            if (
                self.buffer
                and self._partial_frame_deadline_ns is not None
                and now_ns >= self._partial_frame_deadline_ns
            ):
                raise _error("resource_measurement_failed")
            try:
                ready, _, _ = select.select([self.endpoint], [], [], max(0, remaining_ns) / 1_000_000_000)
            except (OSError, ValueError):
                raise _error("resource_measurement_failed") from None
            if not ready:
                if (
                    self.buffer
                    and self._partial_frame_deadline_ns is not None
                    and effective_deadline_ns == self._partial_frame_deadline_ns
                ):
                    raise _error("resource_measurement_failed")
                return []
            try:
                payload = self.endpoint.recv(MAX_RESOURCE_OBSERVER_FRAME_BYTES + 1)
            except OSError:
                raise _error("resource_measurement_failed") from None
            if not payload:
                if self.buffer:
                    raise _error("resource_measurement_failed")
                raise _ResourceObserverEOF
            self.buffer.extend(payload)
            if len(self.buffer) > MAX_RESOURCE_OBSERVER_FRAME_BYTES * 2:
                raise _error("resource_measurement_failed")
            frames: list[dict[str, Any]] = []
            while True:
                try:
                    boundary = self.buffer.index(0x0A)
                except ValueError:
                    break
                if boundary <= 0 or boundary >= MAX_RESOURCE_OBSERVER_FRAME_BYTES:
                    raise _error("resource_measurement_failed")
                raw = bytes(self.buffer[:boundary])
                del self.buffer[: boundary + 1]
                try:
                    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
                except (UnicodeError, ValueError):
                    raise _error("resource_measurement_failed") from None
                if not isinstance(value, dict):
                    raise _error("resource_measurement_failed")
                frames.append(value)
            if len(self.buffer) >= MAX_RESOURCE_OBSERVER_FRAME_BYTES:
                raise _error("resource_measurement_failed")
            if self.buffer:
                if self._partial_frame_deadline_ns is None:
                    self._partial_frame_deadline_ns = deadline_ns
            else:
                self._partial_frame_deadline_ns = None
            if frames:
                return frames


def _send_resource_observer_frame(endpoint: socket.socket, frame: Mapping[str, Any]) -> None:
    try:
        payload = _canonical_json_bytes(frame) + b"\n"
        if len(payload) > MAX_RESOURCE_OBSERVER_FRAME_BYTES:
            raise OSError
        endpoint.sendall(payload)
    except (OSError, TypeError, ValueError):
        raise _error("resource_measurement_failed") from None


def _shutdown_resource_observer_write(endpoint: socket.socket) -> None:
    """Half-close one observer endpoint after its final protocol frame."""

    try:
        endpoint.shutdown(socket.SHUT_WR)
    except OSError:
        raise _error("resource_measurement_failed") from None


def _require_resource_observer_eof(reader: _ResourceObserverFrames) -> None:
    """Accept only a clean EOF after the peer's final observer frame."""

    deadline_ns = time.monotonic_ns() + RESOURCE_OBSERVER_COMMAND_TIMEOUT_NS
    while True:
        if reader.buffer:
            raise _error("resource_measurement_failed")
        remaining_ns = deadline_ns - time.monotonic_ns()
        if remaining_ns <= 0:
            raise _error("resource_measurement_failed")
        try:
            frames = reader.receive(remaining_ns)
        except _ResourceObserverEOF:
            return
        if frames or reader.buffer:
            raise _error("resource_measurement_failed")


def _observer_init_preflight(
    frame: Mapping[str, Any],
    *,
    nonce: str,
    options: EnronCapacityOptions,
) -> tuple[_Preflight, int, int]:
    _observer_closed(
        frame,
        {
            "type",
            "protocol",
            "nonce",
            "interval_ns",
            "maximum_gap_ns",
            "run_started_ns",
            "preflight",
        },
    )
    if (
        frame.get("type") != "init"
        or frame.get("protocol") != _RESOURCE_OBSERVER_PROTOCOL
        or frame.get("nonce") != nonce
        or frame.get("interval_ns") != PRODUCTION_MONITOR_INTERVAL_NS
        or frame.get("maximum_gap_ns") != MAX_RESOURCE_OBSERVATION_WALL_GAP_NS
    ):
        raise _error("resource_measurement_failed")
    run_started_ns = _observer_int(frame.get("run_started_ns"), minimum=0)
    raw = _observer_mapping(frame.get("preflight"))
    _observer_closed(
        raw,
        {
            "physical_memory_bytes",
            "effective_rss_cap_bytes",
            "maximum_peak_rss_bytes",
            "preflight_process_tree_rss_bytes",
            "preflight_free_disk_bytes",
            "output_preflight_free_disk_bytes",
            "preexisting_private_tombstone_count",
            "filesystems",
        },
    )
    numeric = {
        key: _observer_int(raw.get(key), minimum=0)
        for key in (
            "physical_memory_bytes",
            "effective_rss_cap_bytes",
            "maximum_peak_rss_bytes",
            "preflight_process_tree_rss_bytes",
            "preflight_free_disk_bytes",
            "output_preflight_free_disk_bytes",
            "preexisting_private_tombstone_count",
        )
    }
    independent_probe = _SystemResourceProbe()
    independent_physical = independent_probe.physical_memory_bytes()
    if type(independent_physical) is not int or independent_physical <= 0:
        raise _error("resource_measurement_failed")
    independent_effective_cap = min(
        MAX_ABSOLUTE_RSS_BYTES,
        independent_physical * PHYSICAL_MEMORY_FRACTION_NUMERATOR // PHYSICAL_MEMORY_FRACTION_DENOMINATOR,
    )
    independent_maximum_peak = independent_effective_cap * PEAK_RSS_FRACTION_NUMERATOR // PEAK_RSS_FRACTION_DENOMINATOR
    if (
        numeric["physical_memory_bytes"] != independent_physical
        or numeric["effective_rss_cap_bytes"] != independent_effective_cap
        or numeric["maximum_peak_rss_bytes"] != independent_maximum_peak
        or not 0 < numeric["preflight_process_tree_rss_bytes"] <= independent_maximum_peak
    ):
        raise _error("resource_measurement_failed")
    raw_filesystems = raw.get("filesystems")
    if not isinstance(raw_filesystems, list) or not 1 <= len(raw_filesystems) <= 2:
        raise _error("resource_measurement_failed")
    try:
        output_path = _absolute_private_path(options.output_dir).parent
        ledger_path = _absolute_private_path(options.attempt_ledger_dir)
    except EnronCapacityError:
        raise _error("resource_measurement_failed") from None
    output_device = independent_probe.filesystem_device(output_path)
    ledger_device = independent_probe.filesystem_device(ledger_path)
    if type(output_device) is not int or type(ledger_device) is not int:
        raise _error("resource_measurement_failed")
    expected_filesystems = (
        {output_device: (output_path, True)}
        if output_device == ledger_device
        else {output_device: (output_path, True), ledger_device: (ledger_path, False)}
    )
    if len(raw_filesystems) != len(expected_filesystems):
        raise _error("resource_measurement_failed")
    filesystems: list[_FilesystemPreflight] = []
    for item in raw_filesystems:
        filesystem = _observer_mapping(item)
        _observer_closed(
            filesystem,
            {"path", "device", "preflight_free_disk_bytes", "includes_output"},
        )
        raw_path = filesystem.get("path")
        if not isinstance(raw_path, str):
            raise _error("resource_measurement_failed")
        try:
            path = _absolute_private_path(Path(raw_path))
        except EnronCapacityError:
            raise _error("resource_measurement_failed") from None
        includes_output = filesystem.get("includes_output")
        if type(includes_output) is not bool:
            raise _error("resource_measurement_failed")
        device = _observer_int(filesystem.get("device"), minimum=0)
        if expected_filesystems.get(device) != (path, includes_output):
            raise _error("resource_measurement_failed")
        filesystems.append(
            _FilesystemPreflight(
                device=device,
                probe_path=path,
                preflight_free_disk_bytes=_observer_int(filesystem.get("preflight_free_disk_bytes"), minimum=0),
                includes_output=includes_output,
            )
        )
    if sum(item.includes_output for item in filesystems) != 1 or len({item.device for item in filesystems}) != len(
        filesystems
    ):
        raise _error("resource_measurement_failed")
    preflight = _Preflight(filesystems=tuple(filesystems), **numeric)
    return preflight, run_started_ns, cast(int, frame["interval_ns"])


@dataclass(frozen=True, slots=True)
class _ResourceAcquisitionCompletion:
    completed_ns: int
    gap_ns: int
    acquisition_duration_ns: int
    rss_duration_ns: int
    filesystem_duration_ns: int
    scheduler_lateness_ns: int
    valid: bool
    failure_code: str | None
    sample_failure_reserved: bool
    external_failure_code: str | None


class _LauncherResourceObserver:
    """Observe the isolated workload from the already-supervising launcher process."""

    def __init__(
        self,
        endpoint: socket.socket,
        *,
        worker_pid: int,
        nonce: str,
        options: EnronCapacityOptions,
    ) -> None:
        self.endpoint = endpoint
        self.worker_pid = worker_pid
        self.nonce = nonce
        self.options = options
        self.thread = threading.Thread(target=self._run, name="nerb-capacity-launcher-resource-observer", daemon=True)
        self.supervisor = threading.Thread(
            target=self._supervise_deadlines,
            name="nerb-capacity-launcher-resource-supervisor",
            daemon=True,
        )
        self.send_lock = threading.Lock()
        self.state_condition = threading.Condition()
        self.supervision_started_ns = time.monotonic_ns()
        self.acquisition_started_ns: int | None = None
        self.pending_publication_completed_ns: int | None = None
        self.last_completed_ns: int | None = None
        self.started = False
        self.terminal_sample_sent = False
        self.stop_acknowledged = False
        self.failure_code: str | None = None
        self.failure_diagnostic: dict[str, Any] | None = None
        self.failure: BaseException | None = None
        self.failure_event = threading.Event()
        self.failure_publication_complete = False
        self.failure_delivery_succeeded = False
        self._finished = threading.Event()

    def start(self) -> None:
        self.supervisor.start()
        try:
            self.thread.start()
        except BaseException:
            self._finished.set()
            with self.state_condition:
                self.state_condition.notify_all()
            self.supervisor.join(RESOURCE_OBSERVER_COMMAND_TIMEOUT_NS / 1_000_000_000)
            raise

    def join(self) -> None:
        if self.thread.ident is not None:
            self.thread.join(RESOURCE_OBSERVER_COMMAND_TIMEOUT_NS / 1_000_000_000)
        if self.thread.is_alive():
            if self._reserve_failure("resource_measurement_failed"):
                self._finish_failure_publication(delivered=False)
            try:
                self.endpoint.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.thread.join(RESOURCE_OBSERVER_COMMAND_TIMEOUT_NS / 1_000_000_000)
        if self.thread.is_alive():
            raise _error("resource_measurement_failed")
        if self.supervisor.ident is not None:
            self.supervisor.join(RESOURCE_OBSERVER_COMMAND_TIMEOUT_NS / 1_000_000_000)
        if self.supervisor.is_alive():
            raise _error("resource_measurement_failed")

    def close(self) -> None:
        try:
            self.endpoint.close()
        except OSError:
            pass

    def _reserve_failure_locked(
        self,
        code: str,
        exc: BaseException | None = None,
        *,
        diagnostic: Mapping[str, Any] | None = None,
    ) -> bool:
        if self.failure_code is not None:
            return False
        safe_code = code if code in _ERROR_MESSAGES else "resource_measurement_failed"
        validated_diagnostic = _validated_resource_failure_diagnostic(diagnostic)
        if safe_code == "resource_observation_gap" and validated_diagnostic is None:
            safe_code = "production_worker_failed"
        if safe_code != "resource_observation_gap":
            validated_diagnostic = None
        self.failure_code = safe_code
        self.failure_diagnostic = validated_diagnostic
        if exc is not None:
            self.failure = exc
        self.failure_event.set()
        self.state_condition.notify_all()
        return True

    def _reserve_failure(self, code: str, exc: BaseException | None = None) -> bool:
        with self.state_condition:
            return self._reserve_failure_locked(code, exc)

    def _finish_failure_publication(self, *, delivered: bool) -> None:
        with self.state_condition:
            self.failure_delivery_succeeded = delivered
            self.failure_publication_complete = True
            self.state_condition.notify_all()

    def _publish_failure(
        self,
        code: str,
        exc: BaseException | None = None,
        *,
        already_delivered: bool = False,
    ) -> bool:
        if not self._reserve_failure(code, exc):
            return False
        self._deliver_reserved_failure(already_delivered=already_delivered)
        return True

    def _deliver_reserved_failure(self, *, already_delivered: bool = False) -> None:
        delivered = already_delivered
        try:
            if not already_delivered:
                self._send(
                    {
                        "type": "observer_failure",
                        "protocol": _RESOURCE_OBSERVER_PROTOCOL,
                        "nonce": self.nonce,
                        "failure_code": self.failure_code,
                    },
                )
                delivered = True
        except BaseException:
            delivered = False
        finally:
            self._finish_failure_publication(delivered=delivered)

    def _complete_resource_acquisition(
        self,
        *,
        started_ns: int,
        previous_completed_ns: int | None,
        run_started_ns: int,
        sample_kind: str,
        sequence: int,
        scheduled_ns: int,
        rss_finished_ns: int,
        rss_retry_count: int,
        filesystem_retry_count: int,
        process_tree_rss_bytes: int | None,
        maximum_peak_rss_bytes: int,
        minimum_free_disk_bytes: int | None,
        output_free_disk_bytes: int | None,
        terminal_process_leak: bool,
        fallback_failure_code: str | None,
    ) -> _ResourceAcquisitionCompletion:
        with self.state_condition:
            completed_ns = time.monotonic_ns()
            gap_ns = 0 if previous_completed_ns is None else completed_ns - previous_completed_ns
            acquisition_duration_ns = completed_ns - started_ns
            rss_duration_ns = rss_finished_ns - started_ns
            filesystem_duration_ns = completed_ns - rss_finished_ns
            scheduler_lateness_ns = max(0, started_ns - scheduled_ns)
            valid = (
                process_tree_rss_bytes is not None
                and minimum_free_disk_bytes is not None
                and output_free_disk_bytes is not None
                and acquisition_duration_ns <= MAX_RESOURCE_ACQUISITION_DURATION_NS
            )
            failure_code: str | None
            if gap_ns < 0 or completed_ns < started_ns or started_ns < run_started_ns:
                valid = False
                failure_code = "clock_invalid"
            else:
                failure_code = _resource_sample_failure_code(
                    process_tree_rss_bytes=process_tree_rss_bytes,
                    maximum_peak_rss_bytes=maximum_peak_rss_bytes,
                    minimum_free_disk_bytes=minimum_free_disk_bytes,
                    acquisition_duration_ns=acquisition_duration_ns,
                    observation_wall_gap_ns=gap_ns,
                    total_runtime_ns=completed_ns - run_started_ns,
                    terminal_process_leak=terminal_process_leak,
                    fallback_failure_code=fallback_failure_code,
                )
                if not valid and failure_code is None:
                    failure_code = "resource_measurement_failed"
            failure_diagnostic: dict[str, Any] | None = None
            if failure_code == "resource_observation_gap":
                try:
                    failure_diagnostic = _resource_gap_failure_diagnostic(
                        phase=None,
                        sample_kind=sample_kind,
                        sequence=sequence,
                        observed_resource_gap_ns=gap_ns,
                        acquisition_duration_ns=acquisition_duration_ns,
                        rss_duration_ns=rss_duration_ns,
                        filesystem_duration_ns=filesystem_duration_ns,
                        acquisition_retry_count=rss_retry_count + filesystem_retry_count,
                        scheduler_lateness_ns=scheduler_lateness_ns,
                    )
                except EnronCapacityError:
                    valid = False
                    failure_code = "production_worker_failed"
            self.acquisition_started_ns = None
            sample_failure_reserved = failure_code is not None and self._reserve_failure_locked(
                failure_code,
                diagnostic=failure_diagnostic,
            )
            external_failure_code = None if sample_failure_reserved else self.failure_code
            if external_failure_code is None:
                self.pending_publication_completed_ns = completed_ns
                if valid:
                    self.last_completed_ns = completed_ns
            self.state_condition.notify_all()
            return _ResourceAcquisitionCompletion(
                completed_ns=completed_ns,
                gap_ns=gap_ns,
                acquisition_duration_ns=acquisition_duration_ns,
                rss_duration_ns=rss_duration_ns,
                filesystem_duration_ns=filesystem_duration_ns,
                scheduler_lateness_ns=scheduler_lateness_ns,
                valid=valid,
                failure_code=failure_code,
                sample_failure_reserved=sample_failure_reserved,
                external_failure_code=external_failure_code,
            )

    def wait_for_failure_publication(self, timeout_ns: int) -> bool:
        deadline_ns = time.monotonic_ns() + timeout_ns
        with self.state_condition:
            while self.failure_event.is_set() and not self.failure_publication_complete:
                remaining_ns = deadline_ns - time.monotonic_ns()
                if remaining_ns <= 0:
                    break
                self.state_condition.wait(remaining_ns / 1_000_000_000)
            return self.failure_publication_complete and self.failure_delivery_succeeded

    def _run(self) -> None:
        try:
            self._run_protocol()
        except _ResourceObserverEOF:
            if not self.stop_acknowledged:
                self._publish_failure("resource_measurement_failed")
        except BaseException as exc:
            safe_code = (
                exc.code
                if isinstance(exc, EnronCapacityError) and exc.code in _ERROR_MESSAGES
                else "resource_measurement_failed"
            )
            self._publish_failure(safe_code, exc)
        finally:
            self._finished.set()
            with self.state_condition:
                self.acquisition_started_ns = None
                self.pending_publication_completed_ns = None
                self.state_condition.notify_all()

    def _send(self, frame: Mapping[str, Any]) -> None:
        with self.send_lock:
            _send_resource_observer_frame(self.endpoint, frame)

    def _supervise_deadlines(self) -> None:
        while not self._finished.is_set():
            failure_code: str | None = None
            failure_reserved = False
            with self.state_condition:
                if self.failure_code is not None:
                    return
                if self.terminal_sample_sent:
                    return
                now_ns = time.monotonic_ns()
                if self.acquisition_started_ns is not None:
                    deadline_ns = self.acquisition_started_ns + MAX_RESOURCE_ACQUISITION_DURATION_NS
                    if now_ns > deadline_ns:
                        failure_code = "resource_acquisition_timeout"
                elif self.pending_publication_completed_ns is not None:
                    deadline_ns = self.pending_publication_completed_ns + MAX_RESOURCE_OBSERVATION_WALL_GAP_NS
                    if now_ns > deadline_ns:
                        failure_code = "resource_measurement_failed"
                elif self.last_completed_ns is not None:
                    deadline_ns = self.last_completed_ns + MAX_RESOURCE_OBSERVATION_WALL_GAP_NS
                    if now_ns > deadline_ns:
                        failure_code = "resource_measurement_failed"
                else:
                    deadline_ns = self.supervision_started_ns + RESOURCE_OBSERVER_START_TIMEOUT_NS
                    if now_ns > deadline_ns:
                        failure_code = "resource_measurement_failed"
                if failure_code is None:
                    remaining_ns = max(1, deadline_ns - now_ns + 1)
                    self.state_condition.wait(min(remaining_ns, 10_000_000) / 1_000_000_000)
                    continue
                failure_reserved = self._reserve_failure_locked(cast(str, failure_code))
            if failure_reserved:
                self._deliver_reserved_failure()
            return

    def _run_protocol(self) -> None:
        reader = _ResourceObserverFrames(self.endpoint)
        init_deadline = time.monotonic_ns() + RESOURCE_OBSERVER_START_TIMEOUT_NS
        init: dict[str, Any] | None = None
        while init is None:
            remaining = init_deadline - time.monotonic_ns()
            if remaining <= 0:
                raise _error("resource_measurement_failed")
            frames = reader.receive(remaining)
            if len(frames) > 1:
                raise _error("resource_measurement_failed")
            if frames:
                init = frames[0]
        preflight, run_started_ns, interval_ns = _observer_init_preflight(
            init,
            nonce=self.nonce,
            options=self.options,
        )
        self.started = True
        with self.state_condition:
            self.state_condition.notify_all()
        probe = _SystemResourceProbe()
        event_sequence = 0
        last_completed_ns: int | None = None
        next_deadline_ns = time.monotonic_ns()
        last_request_id = 0
        worker_peak_rss = preflight.preflight_process_tree_rss_bytes
        failure_latched = False
        failure_acknowledged = False

        def observe(*, sample_kind: str, request_id: int, scheduled_ns: int) -> None:
            nonlocal event_sequence, last_completed_ns, next_deadline_ns, failure_latched
            event_sequence += 1
            started_ns = time.monotonic_ns()
            with self.state_condition:
                self.acquisition_started_ns = started_ns
                self.state_condition.notify_all()
            rss: int | None = None
            minimum_free: int | None = None
            output_free: int | None = None
            rss_retries = 0
            disk_retries = 0
            fallback_failure_code: str | None = None
            terminal_process_leak = False
            try:
                if sample_kind == "terminal":
                    terminal_snapshot = _terminal_process_snapshot(self.worker_pid)
                    if terminal_snapshot is None:
                        raise _error("resource_measurement_failed")
                    rss = terminal_snapshot.worker_tree_rss_bytes
                    if terminal_snapshot.residuals:
                        terminal_process_leak = True
                else:
                    rss, rss_retries = _acquire_runtime_process_tree_rss(probe)
                launcher_peak_rss = _root_process_peak_rss_bytes()
                if type(launcher_peak_rss) is not int or launcher_peak_rss <= 0:
                    raise _error("resource_measurement_failed")
                combined_peak = worker_peak_rss + launcher_peak_rss
                if combined_peak > _MAX_RESOURCE_INTEGER:
                    raise _error("resource_measurement_failed")
                rss = max(rss, combined_peak)
            except EnronCapacityError as exc:
                fallback_failure_code = exc.code if exc.code in _ERROR_MESSAGES else "resource_measurement_failed"
            rss_finished_ns = time.monotonic_ns()
            if fallback_failure_code is None:
                try:
                    minimum_free, output_disk, disk_retries = _sample_runtime_filesystems(probe, preflight)
                    output_free = output_disk.free
                except _RuntimeDiskFloor as exc:
                    minimum_free = exc.minimum_free
                    output_free = None if exc.output_disk is None else exc.output_disk.free
                    disk_retries = exc.retry_count
                except EnronCapacityError as exc:
                    fallback_failure_code = exc.code if exc.code in _ERROR_MESSAGES else "resource_measurement_failed"
            completion = self._complete_resource_acquisition(
                started_ns=started_ns,
                previous_completed_ns=last_completed_ns,
                run_started_ns=run_started_ns,
                sample_kind=sample_kind,
                sequence=event_sequence,
                scheduled_ns=scheduled_ns,
                rss_finished_ns=rss_finished_ns,
                rss_retry_count=rss_retries,
                filesystem_retry_count=disk_retries,
                process_tree_rss_bytes=rss,
                maximum_peak_rss_bytes=preflight.maximum_peak_rss_bytes,
                minimum_free_disk_bytes=minimum_free,
                output_free_disk_bytes=output_free,
                terminal_process_leak=terminal_process_leak,
                fallback_failure_code=fallback_failure_code,
            )
            if completion.external_failure_code is not None:
                raise _error(completion.external_failure_code)
            completed_ns = completion.completed_ns
            gap_ns = completion.gap_ns
            valid = completion.valid
            failure_code = completion.failure_code
            sample_failure_reserved = completion.sample_failure_reserved
            frame = {
                "type": "sample",
                "protocol": _RESOURCE_OBSERVER_PROTOCOL,
                "nonce": self.nonce,
                "event_sequence": event_sequence,
                "request_id": request_id,
                "sample_kind": sample_kind,
                "valid": valid,
                "started_wall_ns": started_ns,
                "completed_wall_ns": completed_ns,
                "resource_observation_wall_gap_ns": gap_ns,
                "acquisition_duration_ns": completion.acquisition_duration_ns,
                "rss_duration_ns": completion.rss_duration_ns,
                "filesystem_duration_ns": completion.filesystem_duration_ns,
                "scheduler_lateness_ns": completion.scheduler_lateness_ns,
                "process_tree_rss_bytes": rss,
                "minimum_free_disk_bytes": minimum_free,
                "output_free_disk_bytes": output_free,
                "rss_retry_count": rss_retries,
                "filesystem_retry_count": disk_retries,
                "failure_code": failure_code,
            }
            if valid:
                last_completed_ns = completed_ns
            try:
                if sample_kind == "terminal":
                    self._send_final(frame)
                else:
                    self._send(frame)
            except BaseException:
                if sample_failure_reserved:
                    self._finish_failure_publication(delivered=False)
                with self.state_condition:
                    self.pending_publication_completed_ns = None
                    self.state_condition.notify_all()
                raise
            if sample_failure_reserved:
                self._finish_failure_publication(delivered=True)
                failure_latched = True
            with self.state_condition:
                self.pending_publication_completed_ns = None
                if sample_kind == "terminal":
                    self.terminal_sample_sent = True
                externally_failed = self.failure_code is not None and not sample_failure_reserved
                external_failure_code = self.failure_code or "resource_measurement_failed"
                self.state_condition.notify_all()
            if externally_failed:
                raise _error(external_failure_code)
            next_deadline_ns = started_ns + interval_ns

        observe(sample_kind="startup", request_id=0, scheduled_ns=next_deadline_ns)
        while True:
            now_ns = time.monotonic_ns()
            wait_until = next_deadline_ns
            frames = reader.receive(max(0, wait_until - now_ns))
            for command_index, command in enumerate(frames):
                command_type = command.get("type")
                if command_type == "failure_ack":
                    _observer_closed(command, {"type", "protocol", "nonce"})
                    if (
                        command.get("protocol") != _RESOURCE_OBSERVER_PROTOCOL
                        or command.get("nonce") != self.nonce
                        or not failure_latched
                        or failure_acknowledged
                    ):
                        raise _error("resource_measurement_failed")
                    failure_acknowledged = True
                    continue
                _observer_closed(
                    command,
                    {"type", "protocol", "nonce", "request_id", "sample_kind", "worker_peak_rss_bytes"},
                )
                request_id = _observer_int(command.get("request_id"), minimum=1)
                reported_worker_peak = _observer_int(command.get("worker_peak_rss_bytes"), minimum=1)
                sample_kind = command.get("sample_kind")
                if (
                    command_type not in {"force", "stop"}
                    or command.get("protocol") != _RESOURCE_OBSERVER_PROTOCOL
                    or command.get("nonce") != self.nonce
                    or request_id <= last_request_id
                    or sample_kind not in {"boundary", "checkpoint", "heartbeat", "activity", "terminal"}
                    or (command_type == "stop") != (sample_kind == "terminal")
                ):
                    raise _error("resource_measurement_failed")
                last_request_id = request_id
                worker_peak_rss = max(worker_peak_rss, reported_worker_peak)
                observe(sample_kind=cast(str, sample_kind), request_id=request_id, scheduled_ns=time.monotonic_ns())
                if command_type == "stop":
                    if command_index != len(frames) - 1 or reader.buffer:
                        raise _error("resource_measurement_failed")
                    _require_resource_observer_eof(reader)
                    with self.state_condition:
                        self.stop_acknowledged = True
                        self.state_condition.notify_all()
                    return
            now_ns = time.monotonic_ns()
            if now_ns >= next_deadline_ns:
                if failure_latched:
                    next_deadline_ns = now_ns + interval_ns
                else:
                    observe(sample_kind="continuous", request_id=0, scheduled_ns=next_deadline_ns)

    def _send_final(self, frame: Mapping[str, Any]) -> None:
        with self.send_lock:
            _send_resource_observer_frame(self.endpoint, frame)
            _shutdown_resource_observer_write(self.endpoint)


def _terminate_worker_process_group(process: subprocess.Popen[bytes]) -> bool:
    """Terminate residual isolated-worker processes and report whether any existed."""

    process_group_id = process.pid
    if type(process_group_id) is not int or process_group_id <= 1 or process_group_id == os.getpgrp():
        raise _error("production_worker_failed")
    group_existed = False
    if process.poll() is None:
        group_existed = True
        try:
            os.killpg(process_group_id, signal.SIGKILL)
        except ProcessLookupError:
            group_existed = False
        except PermissionError:
            pass
        except OSError:
            raise _error("production_worker_failed") from None
        try:
            process.wait(timeout=RESOURCE_OBSERVER_COMMAND_TIMEOUT_NS / 1_000_000_000)
        except (OSError, subprocess.TimeoutExpired):
            raise _error("production_worker_failed") from None
    deadline = time.monotonic_ns() + RESOURCE_OBSERVER_COMMAND_TIMEOUT_NS
    while True:
        try:
            os.killpg(process_group_id, 0)
        except ProcessLookupError:
            break
        except PermissionError:
            group_existed = True
        except OSError:
            raise _error("production_worker_failed") from None
        else:
            group_existed = True
        if time.monotonic_ns() > deadline:
            raise _error("production_worker_failed")
        try:
            os.killpg(process_group_id, signal.SIGKILL)
        except ProcessLookupError:
            break
        except PermissionError:
            pass
        except OSError:
            raise _error("production_worker_failed") from None
        time.sleep(0.01)
    return group_existed


def _request_worker_cooperative_cleanup(
    process: subprocess.Popen[bytes],
    observer: _LauncherResourceObserver,
    *,
    deadline_ns: int,
) -> bool:
    """Ask the live worker watchdog to unwind while its cleanup authority is retained."""

    if process.poll() is not None or time.monotonic_ns() >= deadline_ns:
        return False
    with observer.state_condition:
        watchdog_available = observer.started and not observer.stop_acknowledged
    if not watchdog_available or not hasattr(signal, "SIGUSR1"):
        return False
    if observer.failure_event.is_set():
        publication_wait_ns = min(50_000_000, max(0, deadline_ns - time.monotonic_ns()))
        if publication_wait_ns and observer.wait_for_failure_publication(publication_wait_ns):
            return True
        if time.monotonic_ns() >= deadline_ns:
            return False
    if not observer.failure_event.is_set() and observer._reserve_failure("production_worker_failed"):
        observer._finish_failure_publication(delivered=False)
    try:
        os.kill(process.pid, signal.SIGUSR1)
    except ProcessLookupError:
        return False
    except OSError:
        raise _error("production_worker_failed") from None
    return True


def _wait_for_worker_cleanup_until(process: subprocess.Popen[bytes], deadline_ns: int) -> bool:
    """Wait until one absolute deadline for cooperative worker cleanup and root exit."""

    while process.poll() is None:
        remaining_ns = deadline_ns - time.monotonic_ns()
        if remaining_ns <= 0:
            return False
        time.sleep(min(0.01, remaining_ns / 1_000_000_000))
    return True


def _read_production_worker_response(
    process: subprocess.Popen[bytes],
    request: bytes,
    *,
    timeout_seconds: int,
    observer: _LauncherResourceObserver | None = None,
    cooperative_abort: Callable[[int], bool] | None = None,
) -> bytes:
    """Exchange one bounded worker request/response without unbounded buffering."""

    if process.stdin is None or process.stdout is None or not request or len(request) > 64 * 1024:
        raise _error("production_worker_failed")
    chunks: list[bytes] = []
    total_bytes = 0
    stdin_fd = process.stdin.fileno()
    stdout_fd = process.stdout.fileno()
    request_offset = 0
    stdin_open = True
    stdout_open = True
    root_exit_deadline_ns: int | None = None
    observer_failure_deadline_ns: int | None = None
    deadline_ns = time.monotonic_ns() + timeout_seconds * 1_000_000_000

    def exchange_failure(*, now_ns: int | None = None) -> _ProductionWorkerExchangeFailure:
        nonlocal observer_failure_deadline_ns
        failure_now_ns = time.monotonic_ns() if now_ns is None else now_ns
        if observer_failure_deadline_ns is None and observer is not None and observer.failure_event.is_set():
            observer_failure_deadline_ns = failure_now_ns + PRODUCTION_WORKER_CLEANUP_GRACE_NS
        return _ProductionWorkerExchangeFailure(
            cleanup_deadline_ns=observer_failure_deadline_ns,
            cleanup_grace_consumed=(
                observer_failure_deadline_ns is not None and failure_now_ns >= observer_failure_deadline_ns
            ),
        )

    try:
        os.set_blocking(stdin_fd, False)
        os.set_blocking(stdout_fd, False)
        while stdout_open or process.poll() is None:
            now_ns = time.monotonic_ns()
            if observer is not None and observer.failure_event.is_set() and observer_failure_deadline_ns is None:
                observer_failure_deadline_ns = now_ns + PRODUCTION_WORKER_CLEANUP_GRACE_NS
                publication_wait_ns = min(
                    50_000_000,
                    max(0, observer_failure_deadline_ns - time.monotonic_ns()),
                )
                try:
                    delivered = observer.wait_for_failure_publication(publication_wait_ns)
                    if not delivered and cooperative_abort is not None:
                        cooperative_abort(observer_failure_deadline_ns)
                except (KeyboardInterrupt, SystemExit, MemoryError):
                    raise
                except BaseException:
                    raise exchange_failure() from None
                now_ns = time.monotonic_ns()
            if process.poll() is not None and stdout_open and root_exit_deadline_ns is None:
                root_exit_deadline_ns = now_ns + RESOURCE_OBSERVER_COMMAND_TIMEOUT_NS
            deadlines = [deadline_ns]
            if root_exit_deadline_ns is not None:
                deadlines.append(root_exit_deadline_ns)
            if observer_failure_deadline_ns is not None:
                deadlines.append(observer_failure_deadline_ns)
            effective_deadline_ns = min(deadlines)
            remaining_ns = effective_deadline_ns - now_ns
            if remaining_ns <= 0:
                raise exchange_failure(now_ns=now_ns)
            try:
                readable, writable, _exceptional = select.select(
                    [stdout_fd] if stdout_open else [],
                    [stdin_fd] if stdin_open else [],
                    [],
                    min(0.1, remaining_ns / 1_000_000_000),
                )
            except (OSError, ValueError):
                raise exchange_failure() from None
            if stdin_open and stdin_fd in writable:
                try:
                    written = os.write(stdin_fd, request[request_offset:])
                except OSError as exc:
                    if exc.errno not in {errno.EPIPE, errno.EBADF}:
                        raise exchange_failure() from None
                    written = 0
                    request_offset = len(request)
                if written < 0:
                    raise exchange_failure()
                request_offset += written
                if request_offset == len(request):
                    process.stdin.close()
                    stdin_open = False
            if stdout_open and stdout_fd in readable:
                try:
                    chunk = os.read(stdout_fd, 64 * 1024)
                except OSError:
                    raise exchange_failure() from None
                if not chunk:
                    process.stdout.close()
                    stdout_open = False
                else:
                    total_bytes += len(chunk)
                    if total_bytes > MAX_PRODUCTION_WORKER_RESPONSE_BYTES:
                        raise exchange_failure()
                    chunks.append(chunk)
            if process.poll() is not None and stdin_open:
                process.stdin.close()
                stdin_open = False
        return b"".join(chunks)
    finally:
        if stdin_open:
            try:
                process.stdin.close()
            except OSError:
                pass
        if stdout_open:
            try:
                process.stdout.close()
            except OSError:
                pass


def _spawn_production_worker(options: EnronCapacityOptions) -> dict[str, Any]:
    if not sys.platform.startswith("linux") and sys.platform != "darwin":
        raise _error("production_identity_invalid")
    source_root, dependency_roots, _layouts, observer_fd = _validated_capacity_bootstrap()
    if observer_fd is not None:
        raise _error("production_identity_invalid")
    nonce = secrets.token_hex(32)
    request = {
        "output_dir": os.fspath(_absolute_private_path(options.output_dir)),
        "attempt_ledger_dir": os.fspath(_absolute_private_path(options.attempt_ledger_dir)),
        "workspace_root": None
        if options.workspace_root is None
        else os.fspath(_absolute_private_path(options.workspace_root)),
        "allow_unignored_output": options.allow_unignored_output,
        "nonce": nonce,
        "process_containment": _expected_process_containment_mode(),
    }
    environment = {
        key: value
        for key in ("PATH", "HOME", "LANG", "LC_ALL", "SYSTEMROOT")
        if (value := os.environ.get(key)) is not None
    }
    environment[_PRODUCTION_WORKER_ENV] = nonce
    environment.update(
        {
            "HF_HUB_DISABLE_PROGRESS_BARS": "1",
            "HF_DATASETS_DISABLE_PROGRESS_BARS": "1",
            "TRANSFORMERS_VERBOSITY": "error",
            "TQDM_DISABLE": "1",
            "TOKENIZERS_PARALLELISM": "false",
            "RUST_LOG": "off",
        }
    )
    process: subprocess.Popen[bytes] | None = None
    observer: _LauncherResourceObserver | None = None
    completed_stdout = b""
    residual_worker_group = False
    quiescence_proven = False
    cooperative_signal_sent = False

    def request_cooperative_cleanup(cleanup_deadline_ns: int) -> bool:
        nonlocal cooperative_signal_sent
        if cooperative_signal_sent:
            return True
        if process is None or observer is None:
            return False
        requested = _request_worker_cooperative_cleanup(
            process,
            observer,
            deadline_ns=cleanup_deadline_ns,
        )
        cooperative_signal_sent = cooperative_signal_sent or requested
        return requested

    try:
        with tempfile.TemporaryDirectory(prefix="nerb-capacity-pycache-") as pycache_directory:
            pycache_root = Path(pycache_directory).resolve(strict=True)
            launcher_endpoint, worker_endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            worker_error: BaseException | None = None
            try:
                try:
                    process = subprocess.Popen(
                        [
                            sys.executable,
                            "-I",
                            "-S",
                            "-B",
                            "-X",
                            f"pycache_prefix={pycache_root}",
                            "-c",
                            _PRODUCTION_WORKER_BOOTSTRAP,
                            os.fspath(source_root),
                            str(len(dependency_roots)),
                            *(os.fspath(path) for path in dependency_roots),
                            str(worker_endpoint.fileno()),
                            _PRODUCTION_WORKER_ARGUMENT,
                        ],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                        env=environment,
                        pass_fds=(worker_endpoint.fileno(),),
                        start_new_session=True,
                    )
                    worker_endpoint.close()
                    observer = _LauncherResourceObserver(
                        launcher_endpoint,
                        worker_pid=process.pid,
                        nonce=nonce,
                        options=options,
                    )
                    observer.start()
                    completed_stdout = _read_production_worker_response(
                        process,
                        _canonical_json_bytes(request),
                        timeout_seconds=MAX_TOTAL_RUNTIME_NS // 1_000_000_000 + 300,
                        observer=observer,
                        cooperative_abort=request_cooperative_cleanup,
                    )
                    observer.join()
                except BaseException as exc:
                    worker_error = exc
            finally:
                # Prove that the isolated process group is gone before closing
                # its observer channel or deleting its private bytecode root.
                # Recovery may inspect and wipe sensitive inflight state only
                # after this proof succeeds.
                if process is None:
                    quiescence_proven = True
                else:
                    cleanup_deadline_ns = (
                        worker_error.cleanup_deadline_ns
                        if isinstance(worker_error, _ProductionWorkerExchangeFailure)
                        else None
                    )
                    if worker_error is not None and process.poll() is None:
                        if cleanup_deadline_ns is None:
                            cleanup_deadline_ns = time.monotonic_ns() + PRODUCTION_WORKER_CLEANUP_GRACE_NS
                        if time.monotonic_ns() < cleanup_deadline_ns:
                            cooperative_cleanup_available = False
                            if observer is not None and observer.failure_event.is_set():
                                publication_wait_ns = min(
                                    50_000_000,
                                    max(0, cleanup_deadline_ns - time.monotonic_ns()),
                                )
                                if publication_wait_ns:
                                    cooperative_cleanup_available = observer.wait_for_failure_publication(
                                        publication_wait_ns
                                    )
                            if not cooperative_cleanup_available and time.monotonic_ns() < cleanup_deadline_ns:
                                try:
                                    cooperative_cleanup_available = request_cooperative_cleanup(cleanup_deadline_ns)
                                except BaseException as exc:
                                    if (
                                        isinstance(exc, (KeyboardInterrupt, SystemExit, MemoryError))
                                        or worker_error is None
                                    ):
                                        worker_error = exc
                            if cooperative_cleanup_available and time.monotonic_ns() < cleanup_deadline_ns:
                                try:
                                    _wait_for_worker_cleanup_until(process, cleanup_deadline_ns)
                                except BaseException as exc:
                                    if (
                                        isinstance(exc, (KeyboardInterrupt, SystemExit, MemoryError))
                                        or worker_error is None
                                    ):
                                        worker_error = exc
                    try:
                        residual_worker_group = _terminate_worker_process_group(process)
                    except EnronCapacityError as exc:
                        quiescence_proven = False
                        worker_error = exc
                    else:
                        quiescence_proven = True
                if observer is not None:
                    try:
                        observer.join()
                    except BaseException as exc:
                        if worker_error is None:
                            worker_error = exc
                try:
                    worker_endpoint.close()
                except OSError:
                    pass
                if observer is not None:
                    observer.close()
                else:
                    try:
                        launcher_endpoint.close()
                    except OSError:
                        pass
            if not quiescence_proven:
                raise _error("production_worker_failed")
            if worker_error is not None:
                raise worker_error
    except BaseException as exc:
        if not quiescence_proven:
            raise _error("production_worker_failed") from None
        _recover_worker_inflight(options)
        if isinstance(exc, (KeyboardInterrupt, SystemExit, MemoryError)):
            raise
        raise _error("production_worker_failed") from None
    _recover_worker_inflight(options)
    if (
        process is None
        or process.returncode != 0
        or residual_worker_group
        or len(completed_stdout) > MAX_PRODUCTION_WORKER_RESPONSE_BYTES
    ):
        raise _error("production_worker_failed")
    try:
        response = json.loads(completed_stdout.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeError, ValueError):
        raise _error("production_worker_failed") from None
    if not isinstance(response, Mapping) or set(response) != {"ok", "code", "diagnostic", "report"}:
        raise _error("production_worker_failed")
    if observer is None:
        raise _error("production_worker_failed")
    launcher_code = observer.failure_code
    raw_launcher_diagnostic = observer.failure_diagnostic
    launcher_diagnostic = _validated_resource_failure_diagnostic(raw_launcher_diagnostic)
    if (
        (launcher_code is not None and launcher_code not in _ERROR_MESSAGES)
        or (launcher_code == "resource_observation_gap") != (raw_launcher_diagnostic is not None)
        or (raw_launcher_diagnostic is not None and launcher_diagnostic is None)
    ):
        raise _error("production_worker_failed")
    if response.get("ok") is not True:
        code = response.get("code")
        diagnostic = response.get("diagnostic")
        validated_diagnostic = _validated_failure_diagnostic(diagnostic)
        if (
            response.get("ok") is not False
            or not isinstance(code, str)
            or code not in _ERROR_MESSAGES
            or response.get("report") is not None
            or (code in {"checkpoint_wall_gap", "resource_observation_gap"}) != (diagnostic is not None)
            or (diagnostic is not None and validated_diagnostic is None)
        ):
            raise _error("production_worker_failed")
        selected_code = _combine_resource_failure_codes(code, launcher_code)
        if selected_code is None:
            raise _error("production_worker_failed")
        selected_diagnostic = validated_diagnostic if selected_code == code else launcher_diagnostic
        if selected_code == "resource_observation_gap":
            selected_diagnostic = _validated_resource_failure_diagnostic(selected_diagnostic)
            if selected_diagnostic is None:
                raise _error("production_worker_failed")
        raise _error(selected_code, diagnostic=selected_diagnostic)
    if launcher_code is not None:
        if launcher_code == "resource_observation_gap" and launcher_diagnostic is None:
            raise _error("production_worker_failed")
        raise _error(launcher_code, diagnostic=launcher_diagnostic)
    report = response.get("report")
    if (
        response.get("code") is not None
        or response.get("diagnostic") is not None
        or not isinstance(report, Mapping)
        or not observer.started
        or not observer.stop_acknowledged
    ):
        raise _error("production_worker_failed")
    return dict(report)


def _recover_worker_inflight(options: EnronCapacityOptions) -> None:
    ledger_path = _absolute_private_path(options.attempt_ledger_dir)
    try:
        ledger_path.lstat()
    except FileNotFoundError:
        return
    except OSError:
        raise _error("production_worker_failed") from None
    ledger: _AttemptLedger | None = None
    try:
        ledger = _prepare_attempt_ledger(options)
    except EnronCapacityError:
        raise _error("production_worker_failed") from None
    finally:
        if ledger is not None:
            ledger.close()


def _production_worker_main() -> int:
    global _FRESH_PRODUCTION_WORKER
    response: dict[str, Any]
    observer_endpoint: socket.socket | None = None
    try:
        _source_root, _dependency_roots, _layouts, observer_fd = _validated_capacity_bootstrap()
        if observer_fd is None:
            raise _error("production_identity_invalid")
        observer_endpoint = socket.socket(fileno=observer_fd)
        observer_endpoint.set_inheritable(False)

        def close_observer_in_fork_child() -> None:
            try:
                observer_endpoint.close()
            except OSError:
                pass

        os.register_at_fork(after_in_child=close_observer_in_fork_child)
        _set_production_worker_umask()
        payload = sys.stdin.buffer.read(64 * 1024 + 1)
        request = json.loads(payload.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
        if not isinstance(request, Mapping) or set(request) != {
            "output_dir",
            "attempt_ledger_dir",
            "workspace_root",
            "allow_unignored_output",
            "nonce",
            "process_containment",
        }:
            raise _error("options_invalid")
        nonce = request.get("nonce")
        if (
            not isinstance(nonce, str)
            or not re.fullmatch(r"[0-9a-f]{64}", nonce)
            or os.environ.get(_PRODUCTION_WORKER_ENV) != nonce
        ):
            raise _error("production_identity_invalid")
        process_containment = request.get("process_containment")
        if process_containment != _expected_process_containment_mode():
            raise _error("production_identity_invalid")
        del os.environ[_PRODUCTION_WORKER_ENV]
        workspace = request.get("workspace_root")
        options = EnronCapacityOptions(
            output_dir=Path(cast(str, request["output_dir"])),
            attempt_ledger_dir=Path(cast(str, request["attempt_ledger_dir"])),
            workspace_root=None if workspace is None else Path(cast(str, workspace)),
            allow_unignored_output=cast(bool, request["allow_unignored_output"]),
        )
        _FRESH_PRODUCTION_WORKER = True
        _prepare_production_subprocess_context()

        def install_containment_and_preload() -> None:
            _install_production_process_containment(cast(str, process_containment))
            _preload_production_modules()

        report = _run_capacity_entry(
            options,
            phase_runners=_production_phase_runners(),
            resource_probe=_SystemResourceProbe(),
            production_evidence=True,
            monitor_interval_ns=PRODUCTION_MONITOR_INTERVAL_NS,
            wall_clock=time.monotonic_ns,
            resource_observer_socket=observer_endpoint,
            resource_observer_nonce=nonce,
            process_creation_guard=install_containment_and_preload,
        )
        response = {"ok": True, "code": None, "diagnostic": None, "report": report}
    except BaseException as exc:
        code = (
            exc.code
            if isinstance(exc, EnronCapacityError) and exc.code in _ERROR_MESSAGES
            else "production_worker_failed"
        )
        diagnostic = exc.diagnostic if isinstance(exc, EnronCapacityError) else None
        if (code in {"checkpoint_wall_gap", "resource_observation_gap"}) != (diagnostic is not None):
            code = "production_worker_failed"
            diagnostic = None
        response = {
            "ok": False,
            "code": code,
            "diagnostic": diagnostic,
            "report": None,
        }
    if observer_endpoint is not None:
        try:
            observer_endpoint.close()
        except OSError:
            response = {"ok": False, "code": "production_worker_failed", "diagnostic": None, "report": None}
    sys.stdout.buffer.write(_canonical_json_bytes(response))
    sys.stdout.buffer.flush()
    return 0


def _run_enron_capacity_for_test(
    options: EnronCapacityOptions,
    *,
    phase_runners: Mapping[str, CapacityPhaseRunner],
    resource_probe: CapacityResourceProbe,
    monitor_interval_ns: int = PRODUCTION_MONITOR_INTERVAL_NS,
    wall_clock: Callable[[], int] | None = None,
) -> dict[str, Any]:
    """Private fixture seam; its reports can never verify as production."""

    if type(monitor_interval_ns) is not int or monitor_interval_ns <= 0:
        raise _error("options_invalid")
    return _run_capacity_entry(
        options,
        phase_runners=phase_runners,
        resource_probe=resource_probe,
        production_evidence=False,
        monitor_interval_ns=monitor_interval_ns,
        wall_clock=_deterministic_fixture_wall_clock() if wall_clock is None else wall_clock,
    )


def _deterministic_fixture_wall_clock() -> Callable[[], int]:
    """Return a thread-safe logical wall clock for non-production fixture runs."""

    lock = threading.Lock()
    current = 0

    def read() -> int:
        nonlocal current
        with lock:
            current += 1_000_000
            return current

    return read


def _production_phase_runners() -> dict[str, CapacityPhaseRunner]:
    return {
        "preparation": _run_production_preparation,
        "split": _run_production_split,
        "build": _run_production_build,
        "streaming_validation": _run_production_streaming_validation,
        "deep_replay": _run_production_deep_replay,
    }


def _loaded_reader_modules() -> tuple[str, ...]:
    return tuple(
        sorted(
            name
            for name in sys.modules
            if any(name == prefix or name.startswith(prefix + ".") for prefix in _READER_MODULE_PREFIXES)
        )
    )


def _assert_reader_modules_unloaded() -> None:
    if _loaded_reader_modules():
        raise _error("production_identity_invalid")


def _preload_production_modules() -> None:
    """Import every tracked production-core module under the process fence."""

    _assert_reader_modules_unloaded()
    try:
        for filename in _PRODUCTION_CORE_SOURCE_NAMES:
            importlib.import_module(f"nerb.{filename.removesuffix('.py')}")
    except (ImportError, OSError, RuntimeError, ValueError):
        raise _error("production_identity_invalid") from None
    _assert_reader_modules_unloaded()


def _reassert_production_execution_current(execution: Mapping[str, Any]) -> None:
    """Fail closed if code, locks, native bytes, or runtime identity drift mid-run."""

    if execution.get("production_evidence") is not True:
        return
    git_commit = execution.get("executable_git_commit")
    if not isinstance(git_commit, str) or _GIT_COMMIT_RE.fullmatch(git_commit) is None:
        raise _error("production_identity_invalid")
    containment = execution.get("process_containment")
    if (
        not isinstance(containment, Mapping)
        or containment.get("mode") != _PRODUCTION_PROCESS_CONTAINMENT
        or containment.get("installed_before_workload") is not True
        or containment.get("runtime_attested") is not True
    ):
        raise _error("production_identity_invalid")
    try:
        _capacity_import_guard.assert_installed(Path(__file__).parent.parent)
    except (ImportError, OSError, RuntimeError, TypeError, ValueError):
        raise _error("production_identity_invalid") from None
    if not _PHASE_SCOPED_READER_LOADED:
        _assert_reader_modules_unloaded()
    elif any(import_name not in sys.modules for _name, import_name, _init, _version in _CRITICAL_READER_DISTRIBUTIONS):
        raise _error("production_identity_invalid")
    if (
        execution.get("capacity_implementation_sha256") != _implementation_sha256()
        or execution.get("core_source_sha256") != _core_source_sha256()
        or execution.get("relevant_module_sha256") != _relevant_module_sha256()
        or execution.get("native_extension_sha256") != _native_extension_sha256()
        or execution.get("native_build_source_sha256") != _native_build_source_sha256()
        or execution.get("native_extension_build_source_sha256") != _native_extension_embedded_build_source_sha256()
        or execution.get("reader_lock_sha256") != _reader_lock_sha256()
        or execution.get("extraction_execution_sha256") != _extraction_execution_sha256()
        or execution.get("runtime_environment_sha256") != _canonical_hash(_runtime_environment_identity())
    ):
        raise _error("production_identity_invalid")


@dataclass(frozen=True, slots=True)
class _IntegratedCapacityConfig:
    dataset_id: str = ENRON_DATASET_ID
    dataset_revision: str = ENRON_DATASET_REVISION
    dataset_split: str = "train"
    expected_source_rows: int = ENRON_SOURCE_ROWS
    input_jsonl: Path | None = None
    max_rows: int | None = None
    fixture_mode: bool = False
    enforce_production_runtime: bool = True


@dataclass(frozen=True, slots=True)
class _IntegratedCapacityPaths:
    preparation: Path
    development: Path
    sealed: Path
    bank: Path


def _production_integrated_capacity_config() -> _IntegratedCapacityConfig:
    return _IntegratedCapacityConfig()


def _run_production_preparation(context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
    return _execute_integrated_production_phase(context, "preparation")


def _run_production_split(context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
    return _execute_integrated_production_phase(context, "split")


def _run_production_build(context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
    return _execute_integrated_production_phase(context, "build")


def _run_production_streaming_validation(context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
    return _execute_integrated_production_phase(context, "streaming_validation")


def _run_production_deep_replay(context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
    return _execute_integrated_production_phase(context, "deep_replay")


def _execute_integrated_production_phase(
    context: EnronCapacityPhaseContext,
    expected_phase: str,
) -> EnronCapacityPhaseResult:
    return _execute_integrated_capacity_phase(
        context,
        expected_phase,
        config=_production_integrated_capacity_config(),
    )


def _execute_integrated_capacity_phase(
    context: EnronCapacityPhaseContext,
    expected_phase: str,
    *,
    config: _IntegratedCapacityConfig,
) -> EnronCapacityPhaseResult:
    """Execute one concrete phase through the shared streaming workflow APIs."""

    if context.phase != expected_phase or expected_phase not in CAPACITY_PHASES:
        raise _CapacityAbort("phase_execution_failed")
    if not isinstance(config, _IntegratedCapacityConfig):
        raise _CapacityAbort("phase_execution_failed")
    paths = _integrated_capacity_paths(context)
    runners: dict[
        str,
        Callable[
            [EnronCapacityPhaseContext, _IntegratedCapacityConfig, _IntegratedCapacityPaths], EnronCapacityPhaseResult
        ],
    ] = {
        "preparation": _execute_capacity_preparation,
        "split": _execute_capacity_split,
        "build": _execute_capacity_build,
        "streaming_validation": _execute_capacity_streaming_validation,
        "deep_replay": _execute_capacity_deep_replay,
    }
    return runners[expected_phase](context, config, paths)


def _integrated_capacity_paths(context: EnronCapacityPhaseContext) -> _IntegratedCapacityPaths:
    phases_root = context.work_dir.parent
    if context.work_dir.name != context.phase or phases_root.name != "phases":
        raise _CapacityAbort("owned_root_invalid")
    return _IntegratedCapacityPaths(
        preparation=phases_root / "preparation" / "prepared",
        development=phases_root / "split" / "development",
        sealed=phases_root / "split" / "sealed",
        bank=phases_root / "build" / "bank",
    )


def _execute_capacity_preparation(
    context: EnronCapacityPhaseContext,
    config: _IntegratedCapacityConfig,
    paths: _IntegratedCapacityPaths,
) -> EnronCapacityPhaseResult:
    preparation = importlib.import_module("nerb.enron_preparation")
    datasets_module: Any | None = None
    reader_isolation_before: dict[str, Any] | None = None
    initial_runtime_environment_sha256: str | None = None
    if config.enforce_production_runtime:
        if sys.version_info[:2] != (3, 13) or config.input_jsonl is not None or config.max_rows is not None:
            raise _CapacityAbort("production_identity_invalid")
        distribution_version, file_count, total_bytes, _distribution_sha256 = _datasets_distribution_identity()
        if distribution_version != _PINNED_DATASETS_VERSION or file_count <= 0 or total_bytes <= 0:
            raise _CapacityAbort("production_identity_invalid")
    if config.input_jsonl is None:
        datasets_module, initial_runtime_environment_sha256 = _load_phase_scoped_datasets_reader(context)

    options = preparation.EnronPreparationOptions(
        output_dir=paths.preparation,
        input_jsonl=config.input_jsonl,
        dataset_id=config.dataset_id,
        dataset_revision=config.dataset_revision,
        dataset_split=config.dataset_split,
        max_rows=config.max_rows,
        huggingface_cache_dir=(
            None if config.input_jsonl is not None else Path(context.runtime_environment["HF_DATASETS_CACHE"])
        ),
        huggingface_anonymous=config.input_jsonl is None,
        allow_unignored_output=True,
        progress_callback=context.checkpoint,
        activity_callback=context.activity,
        cleanup_successor=context.cleanup_successor,
    )
    if config.input_jsonl is None and (
        options.huggingface_cache_dir != Path(context.runtime_environment["HF_DATASETS_CACHE"])
        or options.huggingface_anonymous is not True
    ):
        raise _CapacityAbort("production_identity_invalid")
    if datasets_module is None:
        summary = preparation.prepare_enron_source(options)
        reader_isolation = _local_reader_isolation()
    else:
        if initial_runtime_environment_sha256 is None:
            raise _CapacityAbort("production_identity_invalid")
        with _owner_only_reader_cache_locks(context.runtime_environment):
            with _reader_network_activity(context.activity):
                reader_isolation_before = _reader_isolation_snapshot(
                    context,
                    datasets_module,
                    stage="before_source_read",
                )
                if initial_runtime_environment_sha256 != _canonical_hash(_runtime_environment_identity()):
                    raise _CapacityAbort("production_identity_invalid")
                summary = preparation.prepare_enron_source(options)
                reader_isolation_after = _reader_isolation_snapshot(
                    context,
                    datasets_module,
                    stage="after_source_read",
                )
                if initial_runtime_environment_sha256 != _canonical_hash(_runtime_environment_identity()):
                    raise _CapacityAbort("production_identity_invalid")
        isolation_descriptor = {
            "schema": "enron_capacity_remote_reader_isolation",
            "mode": "phase_owned_anonymous_official",
            "before_source_read": reader_isolation_before,
            "after_source_read": reader_isolation_after,
        }
        isolation_sha256 = _canonical_hash(isolation_descriptor)
        if isolation_sha256 != _expected_remote_reader_isolation_sha256():
            raise _CapacityAbort("production_identity_invalid")
        reader_isolation = {
            "mode": "phase_owned_anonymous_official",
            "effective_path_count": len(_READER_EFFECTIVE_PATH_LABELS),
            "cache_roots_phase_owned": True,
            "official_endpoint": True,
            "endpoint_sha256": _hash_bytes(_READER_OFFICIAL_ENDPOINT.encode("utf-8")),
            "ambient_credentials_disabled": True,
            "explicit_cache_dir_argument": True,
            "explicit_anonymous_argument": True,
            "token_files_absent": True,
            "restrictive_umask": True,
            "cache_symlinks_disabled": True,
            "cache_lock_files_owner_only": True,
            "cache_lock_mode": _READER_OWNER_ONLY_CACHE_LOCK_MODE,
            "cache_lock_adapter_sha256": _reader_cache_lock_adapter_sha256(),
            "network_activity_observed": True,
            "network_activity_adapter_sha256": _reader_network_activity_adapter_sha256(),
            "sha256": isolation_sha256,
        }
    verified = preparation.load_enron_preparation_run(
        paths.preparation,
        scratch_dir=context.scratch_dir,
        activity_callback=context.activity,
    )
    profile = _adapter_mapping(verified.get("profile"))
    source = _adapter_mapping(profile.get("source"))
    records = _adapter_mapping(profile.get("records"))
    artifacts = _adapter_mapping(verified.get("artifacts"))
    prepared = _adapter_mapping(artifacts.get("prepared_records"))
    rejections = _adapter_mapping(artifacts.get("rejections"))
    if (
        summary.get("source_records") != config.expected_source_rows
        or source.get("input_records") != config.expected_source_rows
        or source.get("dataset_id") != config.dataset_id
        or source.get("revision") != config.dataset_revision
        or source.get("split") != config.dataset_split
        or (config.input_jsonl is None and source.get("reader_package_version") != _PINNED_DATASETS_VERSION)
        or (config.input_jsonl is None and source.get("reader") != "datasets.load_dataset(streaming=True)")
        or (config.input_jsonl is not None and source.get("reader_package_version") is not None)
    ):
        raise _CapacityAbort("phase_commitment_invalid")
    prepared_records = _adapter_nonnegative_int(records.get("unique_prepared_records"))
    prepared_source_rows = _adapter_nonnegative_int(records.get("prepared_occurrences"))
    rejected_source_rows = _adapter_nonnegative_int(records.get("rejected_records"))
    if prepared_records <= 0 or prepared_source_rows + rejected_source_rows != config.expected_source_rows:
        raise _CapacityAbort("phase_commitment_invalid")
    prepared_bytes = _adapter_nonnegative_int(prepared.get("bytes"))
    rejection_bytes = _adapter_nonnegative_int(rejections.get("bytes"))
    values: dict[str, Any] = {
        "dataset_id": config.dataset_id,
        "dataset_revision": config.dataset_revision,
        "dataset_split": config.dataset_split,
        "source_input_rows": config.expected_source_rows,
        "source_reader": source.get("reader"),
        "source_reader_package_version": source.get("reader_package_version"),
        "source_reader_environment_sha256": _canonical_hash(_reader_environment_identity()),
        "source_reader_isolation_mode": reader_isolation["mode"],
        "source_reader_isolation_sha256": reader_isolation["sha256"],
        "source_reader_effective_path_count": reader_isolation["effective_path_count"],
        "source_reader_cache_roots_phase_owned": reader_isolation["cache_roots_phase_owned"],
        "source_reader_official_endpoint": reader_isolation["official_endpoint"],
        "source_reader_endpoint_sha256": reader_isolation["endpoint_sha256"],
        "source_reader_ambient_credentials_disabled": reader_isolation["ambient_credentials_disabled"],
        "source_reader_explicit_cache_dir": reader_isolation["explicit_cache_dir_argument"],
        "source_reader_explicit_anonymous_load": reader_isolation["explicit_anonymous_argument"],
        "source_reader_token_files_absent": reader_isolation["token_files_absent"],
        "source_reader_restrictive_umask": reader_isolation["restrictive_umask"],
        "source_reader_cache_symlinks_disabled": reader_isolation["cache_symlinks_disabled"],
        "source_reader_cache_lock_files_owner_only": reader_isolation["cache_lock_files_owner_only"],
        "source_reader_cache_lock_mode": reader_isolation["cache_lock_mode"],
        "source_reader_cache_lock_adapter_sha256": reader_isolation["cache_lock_adapter_sha256"],
        "source_reader_network_activity_observed": reader_isolation["network_activity_observed"],
        "source_reader_network_activity_adapter_sha256": reader_isolation["network_activity_adapter_sha256"],
        "source_row_multiset_sha256": source.get("canonical_row_multiset_sha256"),
        "source_conservation_sha256": "",
        "sealed_test_accessed": False,
        "preparation_manifest_sha256": verified.get("manifest_sha256"),
        "prepared_artifact_sha256": prepared.get("sha256"),
        "prepared_artifact_bytes": prepared_bytes,
        "prepared_records": prepared_records,
        "prepared_source_rows": prepared_source_rows,
        "rejection_artifact_sha256": rejections.get("sha256"),
        "rejection_artifact_bytes": rejection_bytes,
        "rejected_source_rows": rejected_source_rows,
    }
    values["source_conservation_sha256"] = _source_conservation_sha256(values)
    commitments = _finalize_phase_commitment("preparation", values)
    return EnronCapacityPhaseResult(
        records=config.expected_source_rows,
        processed_bytes=prepared_bytes + rejection_bytes,
        commitments=commitments,
    )


def _execute_capacity_split(
    context: EnronCapacityPhaseContext,
    config: _IntegratedCapacityConfig,
    paths: _IntegratedCapacityPaths,
) -> EnronCapacityPhaseResult:
    splitting = importlib.import_module("nerb.enron_splitting")
    prior = _adapter_prior_commitment(context, "preparation")
    result = splitting.split_enron_preparation(
        splitting.EnronSplitOptions(
            preparation_run=paths.preparation,
            development_output_dir=paths.development,
            sealed_output_dir=paths.sealed,
            scratch_dir=context.scratch_dir,
            fixture_mode=config.fixture_mode,
            allow_unignored_output=True,
            progress_callback=context.checkpoint,
            activity_callback=context.activity,
            cleanup_successor=context.cleanup_successor,
        )
    )
    verified = splitting.verify_enron_splits(
        paths.development,
        paths.sealed,
        activity_callback=context.activity,
    )
    contract = _adapter_mapping(verified.get("contract_splits"))
    roles = _adapter_mapping(contract.get("roles"))
    role_values: dict[str, Mapping[str, Any]] = {}
    for role in ("train", "validation", "test"):
        value = _adapter_mapping(roles.get(role))
        artifact = _adapter_mapping(value.get("artifact"))
        role_values[role] = {
            "records": _adapter_positive_int(value.get("records")),
            "sha256": artifact.get("sha256"),
            "bytes": _adapter_nonnegative_int(artifact.get("bytes")),
        }
    if (
        result.get("records") != prior.get("prepared_records")
        or verified.get("records") != prior.get("prepared_records")
        or sum(int(role_values[role]["records"]) for role in role_values) != prior.get("prepared_records")
        or result.get("manifest_sha256") != contract.get("manifest_sha256")
        or result.get("policy_sha256") != contract.get("policy_sha256")
        or result.get("fixture_mode") is not config.fixture_mode
        or verified.get("fixture_mode") is not config.fixture_mode
        or verified.get("leakage_groups_crossing") != 0
        or verified.get("test_sealed") is not True
    ):
        raise _CapacityAbort("phase_commitment_invalid")
    access = _sealed_unbound_access(verified)
    values = {
        **_commitment_without_privacy_scan(prior),
        "full_split_manifest_sha256": contract.get("manifest_sha256"),
        "development_manifest_sha256": verified.get("development_manifest_sha256"),
        "split_policy_sha256": contract.get("policy_sha256"),
        "train_artifact_sha256": role_values["train"]["sha256"],
        "train_artifact_bytes": role_values["train"]["bytes"],
        "train_records": role_values["train"]["records"],
        "validation_artifact_sha256": role_values["validation"]["sha256"],
        "validation_artifact_bytes": role_values["validation"]["bytes"],
        "validation_records": role_values["validation"]["records"],
        "test_artifact_sha256": role_values["test"]["sha256"],
        "test_artifact_bytes": role_values["test"]["bytes"],
        "test_records": role_values["test"]["records"],
        "preseal_verification_sha256": verified.get("preseal_verification_sha256"),
        "preseal_access_count": access["access_count"],
        "sealed_state": access["status"],
        "sealed_access_state_sha256": "",
    }
    values["sealed_access_state_sha256"] = _sealed_access_state_sha256(values)
    commitments = _finalize_phase_commitment("split", values)
    return EnronCapacityPhaseResult(
        records=int(prior["prepared_records"]),
        processed_bytes=sum(int(role_values[role]["bytes"]) for role in role_values),
        commitments=commitments,
    )


def _execute_capacity_build(
    context: EnronCapacityPhaseContext,
    config: _IntegratedCapacityConfig,
    paths: _IntegratedCapacityPaths,
) -> EnronCapacityPhaseResult:
    workflow = importlib.import_module("nerb.enron_bank_workflow")
    prior = _adapter_prior_commitment(context, "split")
    _verify_sealed_unbound(paths, prior, context, importlib.import_module("nerb.enron_splitting"))
    try:
        card = workflow.build_enron_intelligence_bank(
            workflow.EnronBankBuildOptions(
                development_run=paths.development,
                output_dir=paths.bank,
                annotation_run=None,
                cmu_catalog_bindings_path=None,
                allow_unignored_output=True,
                progress_callback=context.checkpoint,
                activity_callback=context.activity,
                cleanup_successor=context.cleanup_successor,
            )
        )
    except workflow.EnronBankBuildError as exc:
        failure_code = _BANK_BUILD_FAILURE_CODES.get(str(exc))
        if failure_code is not None:
            raise _CapacityAbort(failure_code) from None
        raise
    _verify_sealed_unbound(paths, prior, context, importlib.import_module("nerb.enron_splitting"))
    source = _adapter_mapping(card.get("source"))
    bank = _adapter_mapping(card.get("bank"))
    stats = _adapter_mapping(bank.get("stats"))
    active_totals = _adapter_mapping(stats.get("active_totals"))
    validation = _adapter_mapping(card.get("validation"))
    builder = _adapter_mapping(card.get("builder"))
    funnel = _adapter_mapping(card.get("candidate_funnel"))
    expected_source = {
        "dataset_id": prior["dataset_id"],
        "dataset_revision": prior["dataset_revision"],
        "dataset_split": prior["dataset_split"],
        "development_manifest_sha256": prior["development_manifest_sha256"],
        "full_split_manifest_sha256": prior["full_split_manifest_sha256"],
        "split_policy_sha256": prior["split_policy_sha256"],
        "preparation_manifest_sha256": prior["preparation_manifest_sha256"],
        "train_artifact_sha256": prior["train_artifact_sha256"],
        "train_records": prior["train_records"],
        "validation_artifact_sha256": prior["validation_artifact_sha256"],
        "validation_records": prior["validation_records"],
        "sealed_test_accessed": False,
    }
    if (
        any(source.get(field) != value for field, value in expected_source.items())
        or card.get("fixture_mode") is not config.fixture_mode
    ):
        raise _CapacityAbort("phase_commitment_invalid")
    values = {
        **_commitment_without_privacy_scan(prior),
        "bank_sha256": bank.get("canonical_sha256"),
        "bank_artifact_sha256": bank.get("artifact_sha256"),
        "bank_canonical_json_bytes": _adapter_positive_int(bank.get("canonical_json_bytes")),
        "bank_card_run_sha256": card.get("run_sha256"),
        "candidate_count": _adapter_positive_int(funnel.get("total_candidates")),
        "candidate_source_sha256": builder.get("candidate_source_sha256"),
        "candidate_ledger_sha256": builder.get("candidate_ledger_sha256"),
        "active_entity_count": _adapter_positive_int(active_totals.get("entities")),
        "active_name_count": _adapter_positive_int(active_totals.get("names")),
        "active_pattern_count": _adapter_positive_int(active_totals.get("patterns")),
        "validation_run_sha256": validation.get("quality_run_sha256"),
        "evaluator_sha256": validation.get("evaluator_sha256"),
        "builder_policy_sha256": builder.get("policy_sha256"),
    }
    commitments = _finalize_phase_commitment("build", values)
    return EnronCapacityPhaseResult(
        records=int(prior["train_records"]),
        processed_bytes=int(prior["train_artifact_bytes"]),
        commitments=commitments,
    )


def _execute_capacity_streaming_validation(
    context: EnronCapacityPhaseContext,
    _config: _IntegratedCapacityConfig,
    paths: _IntegratedCapacityPaths,
) -> EnronCapacityPhaseResult:
    workflow = importlib.import_module("nerb.enron_bank_workflow")
    prior = _adapter_prior_commitment(context, "build")
    summary = workflow._run_enron_streaming_validation(  # noqa: SLF001
        paths.bank,
        development_run=paths.development,
        scratch_root=context.scratch_dir,
        progress_callback=context.checkpoint,
        activity_callback=context.activity,
    )
    if (
        summary.get("validation_records") != prior.get("validation_records")
        or summary.get("bank_sha256") != prior.get("bank_sha256")
        or summary.get("bank_card_run_sha256") != prior.get("bank_card_run_sha256")
        or summary.get("validation_run_sha256") != prior.get("validation_run_sha256")
        or summary.get("evaluator_sha256") != prior.get("evaluator_sha256")
        or summary.get("builder_policy_sha256") != prior.get("builder_policy_sha256")
        or summary.get("development_manifest_sha256") != prior.get("development_manifest_sha256")
        or summary.get("sealed_test_accessed") is not False
    ):
        raise _CapacityAbort("phase_commitment_invalid")
    _verify_sealed_unbound(paths, prior, context, importlib.import_module("nerb.enron_splitting"))
    validation_text_utf8_bytes = _adapter_nonnegative_int(summary.get("validation_text_utf8_bytes"))
    commitments = _finalize_phase_commitment(
        "streaming_validation",
        {
            **_commitment_without_privacy_scan(prior),
            "validation_text_utf8_bytes": validation_text_utf8_bytes,
        },
    )
    return EnronCapacityPhaseResult(
        records=int(prior["validation_records"]),
        processed_bytes=validation_text_utf8_bytes,
        commitments=commitments,
    )


def _execute_capacity_deep_replay(
    context: EnronCapacityPhaseContext,
    _config: _IntegratedCapacityConfig,
    paths: _IntegratedCapacityPaths,
) -> EnronCapacityPhaseResult:
    workflow = importlib.import_module("nerb.enron_bank_workflow")
    prior = _adapter_prior_commitment(context, "streaming_validation")
    replay = workflow.verify_enron_bank_build(
        paths.bank,
        development_run=paths.development,
        scratch_root=context.scratch_dir,
        annotation_run=None,
        progress_callback=context.checkpoint,
        activity_callback=context.activity,
    )
    replay_bank = replay.get("bank_sha256")
    replay_validation = replay.get("selected_validation_run_sha256")
    if (
        replay_bank != prior.get("bank_sha256")
        or replay.get("bank_card_run_sha256") != prior.get("bank_card_run_sha256")
        or replay_validation != prior.get("validation_run_sha256")
        or replay.get("selected_validation_evaluator_sha256") != prior.get("evaluator_sha256")
        or replay.get("builder_policy_sha256") != prior.get("builder_policy_sha256")
        or replay.get("candidate_source_sha256") != prior.get("candidate_source_sha256")
        or replay.get("candidate_ledger_sha256") != prior.get("candidate_ledger_sha256")
        or replay.get("sealed_test_accessed") is not False
    ):
        raise _CapacityAbort("phase_commitment_invalid")
    _verify_sealed_unbound(paths, prior, context, importlib.import_module("nerb.enron_splitting"))
    commitments = _finalize_phase_commitment(
        "deep_replay",
        {
            **_commitment_without_privacy_scan(prior),
            "replay_bank_sha256": replay_bank,
            "replay_validation_run_sha256": replay_validation,
            "replay_equal": True,
        },
    )
    return EnronCapacityPhaseResult(
        records=int(prior["train_records"]) + int(prior["validation_records"]),
        processed_bytes=int(prior["train_artifact_bytes"]) + int(prior["validation_artifact_bytes"]),
        commitments=commitments,
    )


def _adapter_prior_commitment(context: EnronCapacityPhaseContext, expected_phase: str) -> dict[str, Any]:
    prior = context.prior_commitment
    if prior is None or set(prior) != _PHASE_COMMITMENT_FIELDS[expected_phase]:
        raise _CapacityAbort("phase_commitment_invalid")
    return prior


def _adapter_mapping(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise _CapacityAbort("phase_commitment_invalid")
    return value


def _adapter_nonnegative_int(value: Any) -> int:
    if type(value) is not int or value < 0:
        raise _CapacityAbort("phase_commitment_invalid")
    return value


def _adapter_positive_int(value: Any) -> int:
    result = _adapter_nonnegative_int(value)
    if result == 0:
        raise _CapacityAbort("phase_commitment_invalid")
    return result


def _commitment_without_privacy_scan(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: item
        for key, item in value.items()
        if key not in {"privacy_scan_sha256", "privacy_scan_violation_count", "privacy_scanner_source_sha256"}
    }


def _sealed_unbound_access(verification: Mapping[str, Any]) -> Mapping[str, Any]:
    access = _adapter_mapping(verification.get("access"))
    if (
        set(access)
        != {
            "status",
            "access_count",
            "accessed_at",
            "audit_plan_sha256",
            "audit_output_binding_sha256",
        }
        or access.get("status") != "sealed_unbound"
        or access.get("access_count") != 0
        or access.get("accessed_at") is not None
        or access.get("audit_plan_sha256") is not None
        or access.get("audit_output_binding_sha256") is not None
    ):
        raise _CapacityAbort("phase_commitment_invalid")
    return access


def _verify_sealed_unbound(
    paths: _IntegratedCapacityPaths,
    prior: Mapping[str, Any],
    context: EnronCapacityPhaseContext,
    splitting: Any,
) -> None:
    verified = splitting.verify_enron_splits(
        paths.development,
        paths.sealed,
        activity_callback=context.activity,
    )
    access = _sealed_unbound_access(verified)
    if (
        verified.get("manifest_sha256") != prior.get("full_split_manifest_sha256")
        or verified.get("development_manifest_sha256") != prior.get("development_manifest_sha256")
        or verified.get("preseal_verification_sha256") != prior.get("preseal_verification_sha256")
        or access.get("status") != prior.get("sealed_state")
        or access.get("access_count") != prior.get("preseal_access_count")
    ):
        raise _CapacityAbort("phase_commitment_invalid")


def _public_serialization_scanner_source_sha256() -> str:
    contract = importlib.import_module("nerb.enron_contract")
    origin = getattr(contract, "__file__", None)
    if not isinstance(origin, str):
        raise _CapacityAbort("phase_commitment_invalid")
    digest = hashlib.sha256(b"nerb/enron/capacity-public-scanner\0")
    try:
        for label, path in (("contract", Path(origin)), ("capacity", Path(__file__))):
            digest.update(label.encode("ascii") + b"\0" + hashlib.sha256(path.read_bytes()).digest())
    except OSError:
        raise _CapacityAbort("phase_commitment_invalid") from None
    return "sha256:" + digest.hexdigest()


def _public_serialization_is_safe(value: Mapping[str, Any]) -> bool:
    contract = importlib.import_module("nerb.enron_contract")
    scanner = getattr(contract, "_public_serialization_diagnostics", None)
    if not callable(scanner):
        return False
    try:
        diagnostics = scanner(value)
    except (RecursionError, TypeError, ValueError):
        return False
    return isinstance(diagnostics, list) and not diagnostics


def _finalize_phase_commitment(phase: str, values: Mapping[str, Any]) -> dict[str, Any]:
    commitment = {
        **dict(values),
        "privacy_scanner_source_sha256": _public_serialization_scanner_source_sha256(),
        "privacy_scan_violation_count": 0,
        "privacy_scan_sha256": "",
    }
    commitment["privacy_scan_sha256"] = _privacy_scan_sha256(phase, commitment)
    if set(commitment) != _PHASE_COMMITMENT_FIELDS[phase] or not _public_serialization_is_safe(commitment):
        raise _CapacityAbort("phase_commitment_invalid")
    return commitment


def _prepare_capacity_output(options: EnronCapacityOptions) -> tuple[Path, _PinnedDirectory]:
    parent: _PinnedDirectory | None = None
    try:
        final_dir = ensure_private_output_allowed(
            options.output_dir,
            workspace_root=options.workspace_root,
            allow_unignored_output=options.allow_unignored_output,
        )
        parent_fd = _private_io._open_or_create_private_directory(final_dir.parent)  # noqa: SLF001
        os.close(parent_fd)
        parent = _PinnedDirectory(final_dir.parent)
        parent.assert_current(code="private_transaction_failed")
        try:
            os.stat(final_dir.name, dir_fd=parent.fd, follow_symlinks=False)
        except FileNotFoundError:
            return final_dir, parent
        raise _error("private_transaction_failed")
    except EnronCapacityError:
        if parent is not None:
            parent.close()
        raise
    except (EnronPrivateIOError, OSError, TypeError, ValueError):
        if parent is not None:
            parent.close()
        raise _error("private_transaction_failed") from None


def _run_capacity_entry(
    options: EnronCapacityOptions,
    *,
    phase_runners: Mapping[str, CapacityPhaseRunner],
    resource_probe: CapacityResourceProbe,
    production_evidence: bool,
    monitor_interval_ns: int,
    wall_clock: Callable[[], int],
    resource_observer_socket: socket.socket | None = None,
    resource_observer_nonce: str | None = None,
    process_creation_guard: Callable[[], None] | None = None,
) -> dict[str, Any]:
    _validate_options(options)
    runners = _validated_phase_runners(phase_runners)
    ledger = _prepare_attempt_ledger(options)
    metrics = _AttemptMetrics()
    execution: dict[str, Any] | None = None
    report: dict[str, Any] | None = None
    completed_run: _CompletedCapacityRun | None = None
    inflight: _InflightAttempt | None = None
    failure_code: str | None = None
    failure_diagnostic: dict[str, Any] | None = None
    outcome = "passed"
    deferred_finalization_control: KeyboardInterrupt | SystemExit | None = None
    receipt_failure_cleanup_started = False
    cleanup_boundary: _private_io._PrevalidatedCleanupBoundary | None = None  # noqa: SLF001

    def remember_finalization_control(exc: KeyboardInterrupt | SystemExit) -> None:
        nonlocal deferred_finalization_control
        if deferred_finalization_control is None:
            deferred_finalization_control = exc

    def release_cleanup_authority_to_completion(run: PrivateRun) -> None:
        while run.cleanup_authority_retained:
            try:
                run.release_cleanup_authority()
            except (KeyboardInterrupt, SystemExit) as exc:
                remember_finalization_control(exc)

    try:
        try:
            metrics.started_ns = _probe_monotonic_ns(resource_probe)
            try:
                execution = _execution_identity(
                    runners,
                    resource_probe,
                    production_evidence=production_evidence,
                    monitor_interval_ns=monitor_interval_ns,
                )
            except EnronCapacityError:
                raise
            except BaseException:
                raise _error("production_identity_invalid" if production_evidence else "capacity_failed") from None
            final_dir, output_parent = _prepare_capacity_output(options)
            if production_evidence:
                try:
                    cleanup_boundary = _private_io._prevalidate_cleanup_boundary(  # noqa: SLF001
                        final_dir,
                        workspace_root=options.workspace_root,
                        allow_unignored_output=options.allow_unignored_output,
                    )
                except EnronPrivateIOError:
                    output_parent.close()
                    raise _error("private_transaction_failed") from None
            try:
                inflight = _begin_inflight_attempt(
                    ledger,
                    final_dir=final_dir,
                    output_parent=output_parent,
                    execution=execution,
                    production_evidence=production_evidence,
                    started_monotonic_ns=metrics.started_ns,
                )
            except BaseException:
                output_parent.close()
                raise
            completed_run = _execute_capacity_transaction(
                options,
                final_dir=final_dir,
                inflight=inflight,
                runners=runners,
                probe=resource_probe,
                execution=execution,
                monitor_interval_ns=monitor_interval_ns,
                metrics=metrics,
                wall_clock=wall_clock,
                resource_observer_socket=resource_observer_socket,
                resource_observer_nonce=resource_observer_nonce,
                production_evidence=production_evidence,
                process_creation_guard=process_creation_guard,
                cleanup_boundary=cleanup_boundary,
            )
            report = completed_run.report
        except BaseException as exc:
            effective_error = exc
            if inflight is not None:
                recovery_owned_transaction = inflight.transaction_owner is not None
                recovery_error = _recover_inflight_transaction(options, inflight, metrics, effective_error)
                if recovery_error is not None:
                    effective_error = recovery_error
                if recovery_owned_transaction and inflight.transaction_owner is None:
                    completed_run = None
                    report = None
            if isinstance(effective_error, (KeyboardInterrupt, SystemExit, MemoryError)) and isinstance(
                effective_error.__context__, BaseException
            ):
                effective_error = effective_error.__context__
            if isinstance(effective_error, EnronCapacityError) and effective_error.code in _ERROR_MESSAGES:
                failure_code = effective_error.code
                failure_diagnostic = effective_error.diagnostic
            elif isinstance(effective_error, (KeyboardInterrupt, SystemExit)):
                failure_code = "phase_interrupted"
            else:
                failure_code = "capacity_failed"
            outcome = "interrupted" if failure_code == "phase_interrupted" else "failed"
        if failure_code is not None:
            _finish_attempt_metrics(metrics, resource_probe)
        if failure_code == "attempt_ledger_invalid" and inflight is None:
            raise _error(failure_code) from None

        try:
            if completed_run is not None:
                completed_run.pinned.assert_current(code="promotion_failed")
            _append_attempt_receipt(
                ledger,
                inflight=inflight,
                options=options,
                outcome=outcome,
                failure_code=failure_code,
                execution=execution,
                metrics=metrics,
            )
            if completed_run is not None:
                completed_run.pinned.assert_current(code="promotion_failed")
                release_cleanup_authority_to_completion(completed_run.cleanup_owner)
                if inflight is not None:
                    inflight.transaction_owner = None
                    inflight.transaction_pin = None
                    inflight.transaction_tree = None
        except BaseException as exc:
            receipt_failure_cleanup_started = True
            cleanup_failed = False
            if completed_run is not None:
                if inflight is not None and inflight.receipt_appended:
                    if completed_run.cleanup_owner.cleanup_authority_retained:
                        release_cleanup_authority_to_completion(completed_run.cleanup_owner)
                    completed_run.pinned.close()
                else:
                    try:
                        tree_cleanup = _wipe_promoted_capacity_run(
                            completed_run.cleanup_owner,
                            completed_run.pinned,
                            workspace_root=options.workspace_root,
                            allow_unignored_output=options.allow_unignored_output,
                            metrics=metrics,
                        )
                        cleanup_failed = not tree_cleanup[0]
                    except (EnronCapacityError, EnronPrivateIOError):
                        cleanup_failed = True
            if isinstance(exc, EnronCapacityError) and exc.code == "promotion_failed":
                raise _error("promotion_failed") from None
            if isinstance(exc, EnronCapacityError) and exc.code == "attempt_ledger_invalid" and not cleanup_failed:
                raise _error("attempt_ledger_invalid") from None
            raise _error("promotion_failed" if cleanup_failed else "attempt_ledger_write_failed") from None

        if failure_code is not None:
            raise _error(failure_code, diagnostic=failure_diagnostic) from None
        if report is None:
            raise _error("capacity_failed")
        if completed_run is not None:
            completed_run.pinned.close()
        return report
    except BaseException as exc:
        if (
            isinstance(exc, (KeyboardInterrupt, SystemExit, MemoryError))
            and inflight is not None
            and not inflight.receipt_appended
            and not receipt_failure_cleanup_started
            and (inflight.transaction_owner is not None or failure_code is not None)
        ):
            outer_effective_error: BaseException = exc
            if inflight.transaction_owner is not None:
                recovery_error = _recover_inflight_transaction(options, inflight, metrics, outer_effective_error)
                if recovery_error is not None:
                    outer_effective_error = recovery_error
                    failure_code = None
                elif failure_code is None and isinstance(outer_effective_error.__context__, BaseException):
                    outer_effective_error = outer_effective_error.__context__
            completed_run = None
            report = None
            if failure_code is None:
                if (
                    isinstance(outer_effective_error, EnronCapacityError)
                    and outer_effective_error.code in _ERROR_MESSAGES
                ):
                    failure_code = outer_effective_error.code
                    failure_diagnostic = outer_effective_error.diagnostic
                elif isinstance(outer_effective_error, (KeyboardInterrupt, SystemExit)):
                    failure_code = "phase_interrupted"
                else:
                    failure_code = "capacity_failed"
            outcome = "interrupted" if failure_code == "phase_interrupted" else "failed"
            _finish_attempt_metrics(metrics, resource_probe)
            try:
                _append_attempt_receipt(
                    ledger,
                    inflight=inflight,
                    options=options,
                    outcome=outcome,
                    failure_code=failure_code,
                    execution=execution,
                    metrics=metrics,
                )
            except BaseException:
                raise _error("attempt_ledger_write_failed") from None
            raise _error(failure_code, diagnostic=failure_diagnostic) from None
        raise
    finally:
        active_error = sys.exc_info()[1]
        if isinstance(active_error, (KeyboardInterrupt, SystemExit)):
            remember_finalization_control(active_error)
        try:
            if completed_run is not None and completed_run.cleanup_owner.cleanup_authority_retained:
                if inflight is not None and inflight.receipt_appended:
                    release_cleanup_authority_to_completion(completed_run.cleanup_owner)
                else:
                    try:
                        completed_run.cleanup_owner.park_unresolved_cleanup_authority()
                    except (KeyboardInterrupt, SystemExit) as exc:
                        remember_finalization_control(exc)
        finally:
            try:
                while completed_run is not None and not completed_run.pinned.closed:
                    try:
                        completed_run.pinned.close()
                    except (KeyboardInterrupt, SystemExit) as exc:
                        remember_finalization_control(exc)
            finally:
                try:
                    while inflight is not None and not inflight.closed:
                        try:
                            inflight.close()
                        except (KeyboardInterrupt, SystemExit) as exc:
                            remember_finalization_control(exc)
                finally:
                    while not ledger.pinned.closed:
                        try:
                            ledger.close()
                        except (KeyboardInterrupt, SystemExit) as exc:
                            remember_finalization_control(exc)
        if deferred_finalization_control is not None:
            raise deferred_finalization_control


def _private_run_exit_is_settled(private_run: PrivateRun) -> bool:
    return private_run._committed or private_run._cleanup_is_settled()  # noqa: SLF001


@dataclass(slots=True)
class _PrivateRunExitState:
    failure: BaseException | None = None
    control_error: BaseException | None = None

    def remember(self, exc: BaseException) -> None:
        if isinstance(exc, (KeyboardInterrupt, SystemExit, MemoryError)):
            if self.control_error is None:
                self.control_error = exc
        elif self.failure is None:
            self.failure = exc


def _settle_private_run_exit(
    private_run: PrivateRun,
    active_error: BaseException | None,
    state: _PrivateRunExitState,
) -> None:
    """Exit an owned private run without letting one-shot control skip cleanup."""

    exception_info: tuple[object, object, object]
    if active_error is None:
        exception_info = (None, None, None)
    else:
        exception_info = (type(active_error), active_error, active_error.__traceback__)

    try:
        private_run.__exit__(*exception_info)
    except BaseException as exc:
        state.remember(exc)
    finally:
        while not _private_run_exit_is_settled(private_run):
            try:
                private_run.__exit__(*exception_info)
            except BaseException as exc:
                state.remember(exc)
                continue


def _publish_promoted_cleanup_metrics(
    metrics: _AttemptMetrics,
    result: tuple[bool, bool, int],
) -> None:
    _publish_incomplete_promoted_cleanup_metrics(metrics, result)
    metrics.cleanup_evidence = result


def _publish_incomplete_promoted_cleanup_metrics(
    metrics: _AttemptMetrics,
    result: tuple[bool, bool, int],
) -> None:
    """Publish path evidence without overstating an interruptible cleanup."""

    metrics.cleanup_evidence = (False, result[1], result[2])


def _inflight_promoted_identity(inflight: _InflightAttempt) -> tuple[int, int]:
    binding = inflight.stage_binding
    if binding is None:
        raise _error("promotion_failed")
    return cast(int, binding["stage_device"]), cast(int, binding["stage_inode"])


def _publish_private_root_receipt_identity(
    metrics: _AttemptMetrics,
    binding: Mapping[str, Any] | None,
    output_parent: _PinnedDirectory,
) -> None:
    """Carry a durable cleanup-root identity across binding retirement."""

    if binding is None:
        return
    output_parent.assert_current(code="attempt_ledger_invalid")
    identity = cast(int, binding["stage_device"]), cast(int, binding["stage_inode"])
    parent_identity = output_parent.identity.device, output_parent.identity.inode
    existing = (
        metrics.promoted_root_device,
        metrics.promoted_root_inode,
        metrics.promoted_parent_device,
        metrics.promoted_parent_inode,
    )
    expected = (*identity, *parent_identity)
    if any(value is not None and value != expected[index] for index, value in enumerate(existing)):
        raise _error("attempt_ledger_invalid")
    metrics.promoted_root_device, metrics.promoted_root_inode = identity
    metrics.promoted_parent_device, metrics.promoted_parent_inode = parent_identity


def _inflight_cleanup_root_settled(inflight: _InflightAttempt) -> bool:
    """Verify canonical absence or one authenticated empty private tombstone."""

    inflight.output_parent.assert_current(code="promotion_failed")
    stage_name = f".{inflight.output_name}.stage-{inflight.stage_token}"
    expected = None if inflight.stage_binding is None else _inflight_promoted_identity(inflight)
    try:
        complete_name, incomplete_name, scan_valid, bound_names = _recovery_tombstone_names(
            inflight.output_parent.fd,
            inflight.cleanup_intent,
            expected,
            canonical_names=(stage_name, inflight.output_name),
        )
        if not scan_valid or len(bound_names) > 1:
            raise _error("promotion_failed")
        for name in tuple(
            dict.fromkeys(
                item for item in (stage_name, inflight.output_name, complete_name, incomplete_name) if item is not None
            )
        ):
            snapshot = _recovery_entry_snapshot_at(inflight.output_parent.fd, name)
            if snapshot is not None and (
                name in {stage_name, inflight.output_name} or expected is None or snapshot.identity != expected
            ):
                return False
        if not bound_names:
            return True
        name = bound_names[0]
        if expected is None or _PRIVATE_TOMBSTONE_RE.fullmatch(name) is None:
            return False
        snapshot = _recovery_entry_snapshot_at(inflight.output_parent.fd, name)
        candidate: _OwnedDescriptor | None = None
        try:
            candidate = _open_owned_directory_descriptor(name, dir_fd=inflight.output_parent.fd)
            opened = os.fstat(candidate.fd)
            return (
                snapshot is not None
                and snapshot.identity == expected
                and snapshot.is_private_directory
                and (int(opened.st_dev), int(opened.st_ino)) == expected
                and _logical_tree_bytes(candidate.fd, depth=0, entries=[0]) == 0
            )
        finally:
            if candidate is not None:
                candidate.close()
    except EnronCapacityError:
        raise _error("promotion_failed") from None


def _retained_inflight_private_tombstone_count(inflight: _InflightAttempt) -> int:
    """Count the bound run inode only when it remains an empty private tombstone."""

    expected_identity = _inflight_promoted_identity(inflight)
    inflight.output_parent.assert_current(code="promotion_failed")
    stage_name = f".{inflight.output_name}.stage-{inflight.stage_token}"
    try:
        complete_name, incomplete_name, scan_valid, bound_names = _recovery_tombstone_names(
            inflight.output_parent.fd,
            inflight.cleanup_intent,
            expected_identity,
            canonical_names=(stage_name, inflight.output_name),
        )
        if not scan_valid or len(bound_names) > 1:
            raise _error("promotion_failed")
        for name in tuple(
            dict.fromkeys(
                item for item in (stage_name, inflight.output_name, complete_name, incomplete_name) if item is not None
            )
        ):
            snapshot = _recovery_entry_snapshot_at(inflight.output_parent.fd, name)
            if snapshot is not None and snapshot.identity != expected_identity:
                raise _error("promotion_failed")
        if not bound_names:
            return 0
        name = bound_names[0]
        if _PRIVATE_TOMBSTONE_RE.fullmatch(name) is None:
            raise _error("promotion_failed")
        before = _recovery_entry_snapshot_at(inflight.output_parent.fd, name)
        if before is None or before.identity != expected_identity or not before.is_private_directory:
            raise _error("promotion_failed")
        candidate: _OwnedDescriptor | None = None
        try:
            candidate = _open_owned_directory_descriptor(name, dir_fd=inflight.output_parent.fd)
            opened = os.fstat(candidate.fd)
            current = _recovery_entry_snapshot_at(inflight.output_parent.fd, name)
            if (
                (int(opened.st_dev), int(opened.st_ino)) != expected_identity
                or current is None
                or current.identity != expected_identity
                or not current.is_private_directory
                or _logical_tree_bytes(candidate.fd, depth=0, entries=[0]) != 0
            ):
                raise _error("promotion_failed")
        finally:
            if candidate is not None:
                candidate.close()
    except EnronCapacityError:
        raise _error("promotion_failed") from None
    except OSError:
        raise _error("promotion_failed") from None
    return 1


def _recover_inflight_transaction(
    options: EnronCapacityOptions,
    inflight: _InflightAttempt,
    metrics: _AttemptMetrics,
    active_error: BaseException,
) -> BaseException | None:
    """Settle caller-visible transaction ownership after an escaped boundary."""

    owner = inflight.transaction_owner
    if owner is None:
        return None
    reported_cleanup_evidence = metrics.cleanup_evidence
    metrics.cleanup_evidence = (
        False,
        False,
        max(reported_cleanup_evidence[2], 1),
    )
    exit_state = _PrivateRunExitState()
    recovery_error: BaseException | None = None
    recovered = False
    try:
        if not _private_run_exit_is_settled(owner):
            _settle_private_run_exit(owner, active_error, exit_state)
        if exit_state.failure is not None:
            recovery_error = exit_state.failure
        tree = inflight.transaction_tree
        if tree is not None:
            try:
                tree.close()
            except BaseException as exc:
                if recovery_error is None and not isinstance(exc, (KeyboardInterrupt, SystemExit, MemoryError)):
                    recovery_error = exc
        inflight.transaction_tree = None
        if owner.promoted or owner.cleanup_authority_retained:
            if owner.cleanup_authority_retained:
                authority_wiped = owner.wipe_retained_cleanup_authority()
                if not authority_wiped and recovery_error is None:
                    recovery_error = _error("promotion_failed")
            cleanup_root_settled = owner.cleanup_authority_wiped and _inflight_cleanup_root_settled(inflight)
            if cleanup_root_settled:
                sensitive_content_wiped, path_tree_removed, reported_tombstones = reported_cleanup_evidence
                retained_tombstones = max(
                    reported_tombstones,
                    _retained_inflight_private_tombstone_count(inflight),
                )
                if retained_tombstones > 0:
                    path_tree_removed = False
                metrics.cleanup_evidence = (
                    sensitive_content_wiped,
                    path_tree_removed,
                    retained_tombstones,
                )
                cleanup_result_was_published = path_tree_removed is not None
                if not cleanup_result_was_published:
                    sensitive_content_wiped = False
                    path_tree_removed = False
                metrics.cleanup_evidence = (
                    sensitive_content_wiped,
                    path_tree_removed,
                    retained_tombstones,
                )
                recovered = True
                if (
                    not cleanup_result_was_published or metrics.cleanup_evidence[0] is not True
                ) and recovery_error is None:
                    recovery_error = _error("promotion_failed")
            else:
                pin = inflight.transaction_pin
                if pin is None or pin.closed:
                    pin = _open_promoted_capacity_pin(inflight.output_parent.path / inflight.output_name)
                    inflight.transaction_pin = pin
                result = _wipe_promoted_capacity_run(
                    owner,
                    pin,
                    workspace_root=options.workspace_root,
                    allow_unignored_output=options.allow_unignored_output,
                    expected_identity=_inflight_promoted_identity(inflight),
                    metrics=metrics,
                )
                inflight.transaction_pin = None
                _publish_promoted_cleanup_metrics(metrics, result)
                recovered = result[0]
                if not result[0] and recovery_error is None:
                    recovery_error = _error("promotion_failed")
        else:
            owner_cleanup_evidence: _CleanupEvidence = (
                owner.cleanup_sensitive_content_wiped,
                owner.cleanup_path_tree_removed,
                owner.cleanup_tombstone_count,
            )
            if inflight.stage_binding is None:
                retained_tombstones = max(owner_cleanup_evidence[2], 1)
            else:
                retained_tombstones = max(
                    owner_cleanup_evidence[2],
                    _retained_inflight_private_tombstone_count(inflight),
                )
            metrics.cleanup_evidence = (
                False if retained_tombstones > 0 else owner_cleanup_evidence[0],
                False if retained_tombstones > 0 else owner_cleanup_evidence[1],
                retained_tombstones,
            )
            recovered = _private_run_exit_is_settled(owner)
    except BaseException as exc:
        if recovery_error is None:
            recovery_error = exc
    finally:
        if owner.cleanup_authority_wiped and metrics.cleanup_evidence[1] is None:
            metrics.cleanup_evidence = (False, False, metrics.cleanup_evidence[2])
        if recovery_error is not None and owner.cleanup_authority_retained:
            try:
                owner.park_unresolved_cleanup_authority()
            except BaseException as exc:
                if recovery_error is None:
                    recovery_error = exc
        pin = inflight.transaction_pin
        if pin is not None and not pin.closed:
            try:
                pin.close()
            except BaseException as exc:
                if recovery_error is None and not isinstance(exc, (KeyboardInterrupt, SystemExit, MemoryError)):
                    recovery_error = exc
        inflight.transaction_pin = None
        if recovered:
            inflight.transaction_owner = None
    return recovery_error


def _execute_capacity_transaction(
    options: EnronCapacityOptions,
    *,
    final_dir: Path,
    inflight: _InflightAttempt,
    runners: tuple[tuple[str, CapacityPhaseRunner], ...],
    probe: CapacityResourceProbe,
    execution: Mapping[str, Any],
    monitor_interval_ns: int,
    metrics: _AttemptMetrics,
    wall_clock: Callable[[], int],
    resource_observer_socket: socket.socket | None,
    resource_observer_nonce: str | None,
    production_evidence: bool,
    process_creation_guard: Callable[[], None] | None,
    cleanup_boundary: _private_io._PrevalidatedCleanupBoundary | None,  # noqa: SLF001
) -> _CompletedCapacityRun:
    preflight = _resource_preflight(
        final_dir,
        inflight.ledger.pinned.path,
        probe,
        output_parent=inflight.output_parent,
    )
    metrics.peak_process_tree_rss_bytes = preflight.preflight_process_tree_rss_bytes
    metrics.maximum_peak_rss_bytes = preflight.maximum_peak_rss_bytes
    metrics.minimum_free_disk_bytes = preflight.preflight_free_disk_bytes
    metrics.preexisting_private_tombstone_count = preflight.preexisting_private_tombstone_count
    run_started_ns = metrics.started_ns
    if run_started_ns is None:
        raise _error("clock_invalid")

    report: dict[str, Any] | None = None
    tree: _PrivateTreeGuard | None = None
    monitor: _ContinuousResourceMonitor | None = None
    private_run: PrivateRun | None = None
    transaction_error: BaseException | None = None
    exit_state = _PrivateRunExitState()
    promoted = False
    promoted_cleanup_complete = False
    promoted_cleanup_result: tuple[bool, bool, int] | None = None
    promoted_pin: _PinnedDirectory | None = None
    try:
        private_run = PrivateRun(
            final_dir,
            workspace_root=options.workspace_root,
            allow_unignored_output=options.allow_unignored_output,
            stage_token=inflight.stage_token,
            expected_parent_identity=(
                inflight.output_parent.identity.device,
                inflight.output_parent.identity.inode,
            ),
            cleanup_boundary=cleanup_boundary,
        )
        inflight.transaction_owner = private_run
        assert private_run is not None
        private_run.__enter__()
        try:
            inflight.output_parent.assert_current(code="private_transaction_failed")
            _bind_inflight_stage(inflight, private_run.stage_dir)
            _activate_process_creation_guard(
                execution,
                production_evidence=production_evidence,
                process_creation_guard=process_creation_guard,
            )
            _reassert_production_execution_current(execution)
            tree = _PrivateTreeGuard(private_run.stage_dir)
            inflight.transaction_tree = tree
            active_tree = tree
            monitor = _ContinuousResourceMonitor(
                tree=active_tree,
                probe=probe,
                preflight=preflight,
                run_started_ns=run_started_ns,
                interval_ns=monitor_interval_ns,
                wall_clock=wall_clock,
                resource_observer_socket=resource_observer_socket,
                resource_observer_nonce=resource_observer_nonce,
            )
            # The fixture monitor scans the private tree from its background
            # thread and must settle before PrivateRun commits or cleans up.
            # Production's launcher observer owns no private-tree descriptor;
            # exact tree scans stay serialized in this workload process.  It
            # therefore remains live through promotion and is reaped only
            # after the promoted-tree terminal observation.
            if monitor._remote is None:
                private_run.register_cleanup_barrier(monitor.stop, monitor._shutdown_is_settled)
            monitor.start()
            phase_reports: list[dict[str, Any]] = []
            for phase, runner in runners:
                _reassert_production_execution_current(execution)
                work_dir = private_run.ensure_directory(Path("phases") / phase)
                active_tree.register_owned_root(work_dir)
                phase_started_ns = _probe_monotonic_ns(probe)
                monitor.begin_phase(phase, phase_started_ns)

                def checkpoint(completed_records: int, *, current_phase: str = phase) -> None:
                    monitor.checkpoint(current_phase, completed_records)

                def declare_owned_root(path: Path) -> Path:
                    return active_tree.register_owned_root(path if path.is_absolute() else work_dir / path)

                def heartbeat(*, current_phase: str = phase) -> None:
                    monitor.heartbeat(current_phase)

                def activity(*, current_phase: str = phase) -> None:
                    monitor.activity(current_phase)

                runtime_environment, scratch_dir, spool_dir, owned_root_count = _provision_phase_runtime_roots(
                    private_run, active_tree, phase
                )
                context = EnronCapacityPhaseContext(
                    phase,
                    work_dir,
                    checkpoint,
                    declare_owned_root,
                    heartbeat,
                    activity,
                    runtime_environment=runtime_environment,
                    scratch_dir=scratch_dir,
                    spool_dir=spool_dir,
                    owned_root_count=owned_root_count,
                    cleanup_successor=private_run,
                    prior_commitment=(
                        None if not phase_reports else cast(Mapping[str, Any], phase_reports[-1]["commitments"])
                    ),
                )
                with _applied_phase_runtime_environment(runtime_environment):
                    result, runner_failure = _invoke_phase_runner(runner, context)
                _raise_recorded_monitor_failure(monitor)
                if runner_failure is not None:
                    raise _error(runner_failure)
                if result is None:
                    _raise_recorded_monitor_failure(monitor)
                    raise _error("phase_result_invalid")
                try:
                    basic = _validate_phase_result(result)
                except BaseException:
                    _raise_recorded_monitor_failure(monitor)
                    raise
                measurements = monitor.finish_phase(phase, basic.records)
                try:
                    private_run.pin_cleanup_tree(Path("phases") / phase)
                except EnronPrivateIOError:
                    raise _error("private_transaction_failed") from None
                _reassert_production_execution_current(execution)
                phase_report = _phase_report(
                    phase,
                    basic,
                    measurements,
                    owned_root_count=context.owned_root_count,
                    runner_sha256=cast(Mapping[str, str], execution["runner_implementation_sha256"])[phase],
                    executable_git_commit=cast(str, execution["executable_git_commit"]),
                )
                phase_reports.append(phase_report)
                _verify_phase_commitment_chain(
                    phase_reports,
                    require_production_source=bool(execution["production_evidence"]),
                )

            _reassert_production_execution_current(execution)
            pre_report_owned = tree.logical_bytes()
            monitor.observe_transaction_boundary(pre_report_owned)
            report_snapshot = monitor.global_snapshot()
            report_elapsed_ns = _probe_monotonic_ns(probe) - run_started_ns
            report, payload = _capacity_report(
                preflight=preflight,
                execution=execution,
                phase_reports=phase_reports,
                total_elapsed_ns=report_elapsed_ns,
                pre_report_owned_bytes=pre_report_owned,
                monitor_snapshot=report_snapshot,
            )
            _verify_capacity_report(
                report,
                require_production=bool(execution["production_evidence"]),
                current_production_execution=execution if execution["production_evidence"] is True else None,
            )
            metrics.report_sha256 = cast(str, report["run_sha256"])
            _reassert_production_execution_current(execution)
            _write_report_and_fsync(private_run, payload)

            final_staging_owned = tree.logical_bytes()
            if final_staging_owned + len(_COMMIT_PAYLOAD) != report["totals"]["final_owned_disk_bytes"]:
                raise _error("report_invalid")
            monitor.observe_transaction_boundary(final_staging_owned)
            if monitor._remote is None:
                monitor.stop()
                monitor.raise_if_failed()
                snapshot = monitor.global_snapshot()
                _merge_monitor_metrics(metrics, snapshot)

            _reassert_production_execution_current(execution)
            try:
                private_run.commit(
                    retain_cleanup_authority=True,
                    before_promotion=lambda identities: _bind_inflight_cleanup_inventory(inflight, identities),
                )
            except EnronPrivateIOError:
                _raise_recorded_monitor_failure(monitor)
                raise _error("private_transaction_failed") from None
            promoted = True
            tree.rebind(final_dir)
            promoted_pin = _open_promoted_capacity_pin(final_dir)
            inflight.transaction_pin = promoted_pin
            promoted_pin.assert_current(code="promotion_failed")
            metrics.promoted_root_device = promoted_pin.identity.device
            metrics.promoted_root_inode = promoted_pin.identity.inode
            parent_info = os.fstat(promoted_pin.parent_fd)
            metrics.promoted_parent_device = parent_info.st_dev
            metrics.promoted_parent_inode = parent_info.st_ino
            metrics.promoted_name_sha256 = _hash_bytes(promoted_pin.name.encode("utf-8"))
            final_owned = _logical_tree_bytes(promoted_pin.fd, depth=0, entries=[0])
            _post_promotion_enforce(
                probe,
                preflight=preflight,
                run_started_ns=run_started_ns,
                final_owned=final_owned,
                metrics=metrics,
                monitor=monitor,
            )
            if final_owned != report["totals"]["final_owned_disk_bytes"]:
                raise _error("report_invalid")
        except BaseException as exc:
            transaction_error = exc
            if monitor is not None:
                try:
                    monitor.stop()
                except BaseException:
                    pass
                try:
                    _merge_monitor_metrics(metrics, monitor.global_snapshot())
                except BaseException:
                    pass
            raise
        finally:
            _settle_private_run_exit(private_run, transaction_error, exit_state)
            if exit_state.failure is not None:
                raise exit_state.failure
            if transaction_error is None and exit_state.control_error is not None:
                raise exit_state.control_error
        if report is None or promoted_pin is None:
            raise _error("promotion_failed")
        return _CompletedCapacityRun(report=report, pinned=promoted_pin, cleanup_owner=private_run)
    except BaseException as exc:
        effective_error = exit_state.failure if exit_state.failure is not None else exc
        if exit_state.failure is None and isinstance(exc, (KeyboardInterrupt, SystemExit, MemoryError)):
            contextual_error = exc.__context__ if isinstance(exc.__context__, BaseException) else transaction_error
            while isinstance(contextual_error, (KeyboardInterrupt, SystemExit, MemoryError)) and isinstance(
                contextual_error.__context__, BaseException
            ):
                contextual_error = contextual_error.__context__
            if contextual_error is not None:
                effective_error = contextual_error
        if private_run is not None and not _private_run_exit_is_settled(private_run):
            _settle_private_run_exit(private_run, effective_error, exit_state)
        if exit_state.failure is not None:
            effective_error = exit_state.failure
        if private_run is not None:
            metrics.cleanup_evidence = (
                private_run.cleanup_sensitive_content_wiped,
                private_run.cleanup_path_tree_removed,
                private_run.cleanup_tombstone_count,
            )
        if monitor is not None:
            try:
                monitor.stop()
                _merge_monitor_metrics(metrics, monitor.global_snapshot())
            except BaseException:
                pass
        if promoted or (private_run is not None and (private_run.promoted or private_run.cleanup_authority_retained)):
            try:
                if private_run is None:
                    raise _error("promotion_failed")
                if promoted_pin is None:
                    promoted_pin = _open_promoted_capacity_pin(final_dir)
                promoted_cleanup_result = _wipe_promoted_capacity_run(
                    private_run,
                    promoted_pin,
                    workspace_root=options.workspace_root,
                    allow_unignored_output=options.allow_unignored_output,
                    expected_identity=_inflight_promoted_identity(inflight),
                    metrics=metrics,
                )
                promoted_cleanup_complete = True
                promoted = False
                promoted_pin = None
                _publish_promoted_cleanup_metrics(metrics, promoted_cleanup_result)
                if not metrics.cleanup_evidence[0]:
                    raise _error("promotion_failed")
            except EnronCapacityError:
                raise
            except (EnronPrivateIOError, OSError):
                raise _error("promotion_failed") from None
        if isinstance(effective_error, _CapacityAbort):
            raise _error(
                effective_error.code,
                diagnostic=None if monitor is None else monitor.failure_diagnostic(),
            ) from None
        if isinstance(effective_error, EnronCapacityError) and monitor is not None:
            diagnostic = monitor.failure_diagnostic()
            if diagnostic is not None and effective_error.diagnostic is None:
                raise _error(effective_error.code, diagnostic=diagnostic) from None
        raise effective_error
    finally:
        final_error = sys.exc_info()[1]
        tree_close_error: BaseException | None = None
        if tree is not None:
            try:
                tree.close()
            except BaseException as exc:
                tree_close_error = exc
        cleanup_trigger_error = tree_close_error if final_error is None else final_error
        fallback_error: BaseException | None = None
        if promoted_cleanup_result is not None:
            promoted_cleanup_complete = True
            promoted = False
            promoted_pin = None
            _publish_promoted_cleanup_metrics(metrics, promoted_cleanup_result)
        if (
            cleanup_trigger_error is not None
            and not promoted_cleanup_complete
            and private_run is not None
            and (promoted or private_run.promoted or private_run.cleanup_authority_retained)
        ):
            try:
                if promoted_pin is None or promoted_pin.closed:
                    promoted_pin = _open_promoted_capacity_pin(final_dir)
                promoted_cleanup_result = _wipe_promoted_capacity_run(
                    private_run,
                    promoted_pin,
                    workspace_root=options.workspace_root,
                    allow_unignored_output=options.allow_unignored_output,
                    expected_identity=_inflight_promoted_identity(inflight),
                    metrics=metrics,
                )
                promoted_pin = None
                promoted_cleanup_complete = True
                promoted = False
                _publish_promoted_cleanup_metrics(metrics, promoted_cleanup_result)
                if not metrics.cleanup_evidence[0]:
                    raise _error("promotion_failed")
            except BaseException as exc:
                fallback_error = exc
        if fallback_error is not None:
            if isinstance(fallback_error, EnronCapacityError):
                raise fallback_error
            raise _error("promotion_failed") from None
        if tree_close_error is not None and not isinstance(
            tree_close_error, (KeyboardInterrupt, SystemExit, MemoryError)
        ):
            raise tree_close_error
        if isinstance(final_error, (KeyboardInterrupt, SystemExit, MemoryError)):
            preserved_error = exit_state.failure
            if preserved_error is None:
                preserved_error = (
                    final_error.__context__ if isinstance(final_error.__context__, BaseException) else None
                )
            if preserved_error is None:
                preserved_error = transaction_error
            while isinstance(preserved_error, (KeyboardInterrupt, SystemExit, MemoryError)) and isinstance(
                preserved_error.__context__, BaseException
            ):
                preserved_error = preserved_error.__context__
            if preserved_error is not None and preserved_error is not final_error:
                if isinstance(preserved_error, _CapacityAbort):
                    raise _error(
                        preserved_error.code,
                        diagnostic=None if monitor is None else monitor.failure_diagnostic(),
                    ) from None
                raise preserved_error
        if final_error is None and tree_close_error is not None:
            raise tree_close_error


def _invoke_phase_runner(
    runner: CapacityPhaseRunner,
    context: EnronCapacityPhaseContext,
) -> tuple[EnronCapacityPhaseResult | None, str | None]:
    result: EnronCapacityPhaseResult | None = None
    failure: str | None = None
    try:
        result = runner(context)
    except _CapacityAbort as exc:
        failure = exc.code if exc.code in _ERROR_MESSAGES else "phase_execution_failed"
    except BaseException as exc:
        failure = "phase_interrupted" if isinstance(exc, (KeyboardInterrupt, SystemExit)) else "phase_execution_failed"
    return result, failure


def _raise_recorded_monitor_failure(monitor: _ContinuousResourceMonitor) -> None:
    """Translate a stored monitor failure before interpreting a runner response."""

    try:
        monitor.raise_if_failed()
    except _CapacityAbort as exc:
        raise _error(exc.code, diagnostic=monitor.failure_diagnostic()) from None


def _provision_phase_runtime_roots(
    private_run: PrivateRun,
    tree: _PrivateTreeGuard,
    phase: str,
) -> tuple[dict[str, str], Path, Path, int]:
    relative_root = Path("phases") / phase / "runtime"
    roots = {
        name: private_run.ensure_directory(relative_root / name)
        for name in (
            "home",
            "tmp",
            "hf-home",
            "hf-datasets",
            "hf-modules",
            "hf-downloads",
            "hf-extracted",
            "hf-hub",
            "hf-assets",
            "hf-xet",
            "hf-token",
            "transformers",
            "xdg-cache",
            "spool",
            "scratch",
        )
    }
    for path in roots.values():
        tree.register_owned_root(path)
    environment = {
        "HOME": os.fspath(roots["home"]),
        "TMPDIR": os.fspath(roots["tmp"]),
        "TMP": os.fspath(roots["tmp"]),
        "TEMP": os.fspath(roots["tmp"]),
        "HF_HOME": os.fspath(roots["hf-home"]),
        "HF_DATASETS_CACHE": os.fspath(roots["hf-datasets"]),
        "HF_MODULES_CACHE": os.fspath(roots["hf-modules"]),
        "HF_DATASETS_DOWNLOADED_DATASETS_PATH": os.fspath(roots["hf-downloads"]),
        "HF_DATASETS_EXTRACTED_DATASETS_PATH": os.fspath(roots["hf-extracted"]),
        "HUGGINGFACE_HUB_CACHE": os.fspath(roots["hf-hub"]),
        "HF_HUB_CACHE": os.fspath(roots["hf-hub"]),
        "HUGGINGFACE_ASSETS_CACHE": os.fspath(roots["hf-assets"]),
        "HF_ASSETS_CACHE": os.fspath(roots["hf-assets"]),
        "HF_XET_CACHE": os.fspath(roots["hf-xet"]),
        "HF_TOKEN_PATH": os.fspath(roots["hf-token"] / "token"),
        "TRANSFORMERS_CACHE": os.fspath(roots["transformers"]),
        "XDG_CACHE_HOME": os.fspath(roots["xdg-cache"]),
    }
    if set(environment) != _PHASE_RUNTIME_PATH_ENVIRONMENT_KEYS:
        raise _error("production_identity_invalid")
    return environment, roots["scratch"], roots["spool"], 1 + len(roots)


@contextmanager
def _applied_phase_runtime_environment(environment: Mapping[str, str]) -> Iterator[None]:
    if set(environment) != _PHASE_RUNTIME_PATH_ENVIRONMENT_KEYS or any(
        not isinstance(value, str) or not value for value in environment.values()
    ):
        raise _CapacityAbort("production_identity_invalid")
    managed_keys = set(environment) | set(_READER_POLICY_ENVIRONMENT) | set(_READER_CREDENTIAL_ENVIRONMENT_KEYS)
    previous = {key: os.environ.get(key) for key in managed_keys}
    previous_tempdir = tempfile.tempdir
    try:
        os.environ.update(environment)
        os.environ.update(_READER_POLICY_ENVIRONMENT)
        for key in _READER_CREDENTIAL_ENVIRONMENT_KEYS:
            os.environ.pop(key, None)
        tempfile.tempdir = environment["TMPDIR"]
        yield
    finally:
        tempfile.tempdir = previous_tempdir
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _validate_options(options: EnronCapacityOptions) -> None:
    if not isinstance(options, EnronCapacityOptions):
        raise _error("options_invalid")
    if (
        not isinstance(options.output_dir, Path)
        or not isinstance(options.attempt_ledger_dir, Path)
        or (options.workspace_root is not None and not isinstance(options.workspace_root, Path))
        or type(options.allow_unignored_output) is not bool
    ):
        raise _error("options_invalid")
    output = _absolute_private_path(options.output_dir)
    ledger = _absolute_private_path(options.attempt_ledger_dir)
    if output == ledger or _is_within(output, ledger) or _is_within(ledger, output):
        raise _error("options_invalid")


def _validated_phase_runners(
    value: Mapping[str, CapacityPhaseRunner],
) -> tuple[tuple[str, CapacityPhaseRunner], ...]:
    if not isinstance(value, Mapping) or set(value) != set(CAPACITY_PHASES):
        raise _error("options_invalid")
    result: list[tuple[str, CapacityPhaseRunner]] = []
    for phase in CAPACITY_PHASES:
        runner = value.get(phase)
        if not callable(runner):
            raise _error("options_invalid")
        result.append((phase, runner))
    return tuple(result)


def _validate_phase_result(result: EnronCapacityPhaseResult) -> EnronCapacityPhaseResult:
    if (
        not isinstance(result, EnronCapacityPhaseResult)
        or type(result.records) is not int
        or result.records <= 0
        or type(result.processed_bytes) is not int
        or result.processed_bytes < 0
        or not isinstance(result.commitments, Mapping)
    ):
        raise _error("phase_result_invalid")
    return result


_COMMON_COMMITMENT_FIELDS = {
    "dataset_id",
    "dataset_revision",
    "dataset_split",
    "source_input_rows",
    "source_reader",
    "source_reader_package_version",
    "source_reader_environment_sha256",
    "source_reader_isolation_mode",
    "source_reader_isolation_sha256",
    "source_reader_effective_path_count",
    "source_reader_cache_roots_phase_owned",
    "source_reader_official_endpoint",
    "source_reader_endpoint_sha256",
    "source_reader_ambient_credentials_disabled",
    "source_reader_explicit_cache_dir",
    "source_reader_explicit_anonymous_load",
    "source_reader_token_files_absent",
    "source_reader_restrictive_umask",
    "source_reader_cache_symlinks_disabled",
    "source_reader_cache_lock_files_owner_only",
    "source_reader_cache_lock_mode",
    "source_reader_cache_lock_adapter_sha256",
    "source_reader_network_activity_observed",
    "source_reader_network_activity_adapter_sha256",
    "source_row_multiset_sha256",
    "source_conservation_sha256",
    "privacy_scan_sha256",
    "privacy_scan_violation_count",
    "privacy_scanner_source_sha256",
    "sealed_test_accessed",
}
_PREPARATION_COMMITMENT_FIELDS = _COMMON_COMMITMENT_FIELDS | {
    "preparation_manifest_sha256",
    "prepared_artifact_sha256",
    "prepared_artifact_bytes",
    "prepared_records",
    "prepared_source_rows",
    "rejection_artifact_sha256",
    "rejection_artifact_bytes",
    "rejected_source_rows",
}
_SPLIT_COMMITMENT_FIELDS = _PREPARATION_COMMITMENT_FIELDS | {
    "development_manifest_sha256",
    "full_split_manifest_sha256",
    "split_policy_sha256",
    "train_artifact_sha256",
    "train_artifact_bytes",
    "train_records",
    "validation_artifact_sha256",
    "validation_artifact_bytes",
    "validation_records",
    "test_artifact_sha256",
    "test_artifact_bytes",
    "test_records",
    "preseal_verification_sha256",
    "preseal_access_count",
    "sealed_state",
    "sealed_access_state_sha256",
}
_BUILD_COMMITMENT_FIELDS = _SPLIT_COMMITMENT_FIELDS | {
    "bank_sha256",
    "bank_artifact_sha256",
    "bank_canonical_json_bytes",
    "bank_card_run_sha256",
    "candidate_count",
    "candidate_source_sha256",
    "candidate_ledger_sha256",
    "active_entity_count",
    "active_name_count",
    "active_pattern_count",
    "validation_run_sha256",
    "evaluator_sha256",
    "builder_policy_sha256",
}
_STREAMING_COMMITMENT_FIELDS = _BUILD_COMMITMENT_FIELDS | {"validation_text_utf8_bytes"}
_REPLAY_COMMITMENT_FIELDS = _STREAMING_COMMITMENT_FIELDS | {
    "replay_bank_sha256",
    "replay_validation_run_sha256",
    "replay_equal",
}
_PHASE_COMMITMENT_FIELDS = {
    "preparation": _PREPARATION_COMMITMENT_FIELDS,
    "split": _SPLIT_COMMITMENT_FIELDS,
    "build": _BUILD_COMMITMENT_FIELDS,
    "streaming_validation": _STREAMING_COMMITMENT_FIELDS,
    "deep_replay": _REPLAY_COMMITMENT_FIELDS,
}


def _phase_report(
    phase: str,
    result: EnronCapacityPhaseResult,
    measurements: Mapping[str, Any],
    *,
    owned_root_count: int,
    runner_sha256: str,
    executable_git_commit: str,
) -> dict[str, Any]:
    elapsed_ns = _positive_int(measurements.get("elapsed_ns"), "phase elapsed time")
    throughput_milli = result.records * 1_000_000_000_000 // elapsed_ns
    if throughput_milli < MIN_PHASE_RECORDS_PER_SECOND * 1_000:
        raise _error("throughput_limit")
    commitments = dict(result.commitments)
    report = {
        "phase": phase,
        "records": result.records,
        "processed_bytes": result.processed_bytes,
        "commitments": commitments,
        "commitments_sha256": _canonical_hash(commitments),
        "runner_implementation_sha256": runner_sha256,
        "executable_git_commit": executable_git_commit,
        "owned_root_count": owned_root_count,
        "elapsed_ns": elapsed_ns,
        "throughput_milli_records_per_second": throughput_milli,
        **dict(measurements),
    }
    return report


def _verify_phase_commitment_chain(
    phases: Sequence[Mapping[str, Any]],
    *,
    require_production_source: bool = False,
) -> None:
    if not phases or len(phases) > len(CAPACITY_PHASES):
        raise _error("phase_commitment_invalid")
    commitments: list[Mapping[str, Any]] = []
    for expected, phase in zip(CAPACITY_PHASES, phases, strict=False):
        if phase.get("phase") != expected:
            raise _error("phase_commitment_invalid")
        value = _require_mapping(phase.get("commitments"), "phase commitments")
        if set(value) != _PHASE_COMMITMENT_FIELDS[expected]:
            raise _error("phase_commitment_invalid")
        if (
            value.get("dataset_id") != ENRON_DATASET_ID
            or value.get("dataset_revision") != ENRON_DATASET_REVISION
            or value.get("dataset_split") != "train"
            or value.get("source_input_rows") != ENRON_SOURCE_ROWS
            or value.get("sealed_test_accessed") is not False
            or value.get("privacy_scan_violation_count") != 0
        ):
            raise _error("phase_commitment_invalid")
        reader = value.get("source_reader")
        reader_version = value.get("source_reader_package_version")
        if (
            not isinstance(reader, str)
            or not reader
            or len(reader.encode("utf-8")) > 256
            or (reader_version is not None and (not isinstance(reader_version, str) or not reader_version))
        ):
            raise _error("phase_commitment_invalid")
        if require_production_source and (
            reader != "datasets.load_dataset(streaming=True)" or reader_version != _PINNED_DATASETS_VERSION
        ):
            raise _error("phase_commitment_invalid")
        isolation_mode = value.get("source_reader_isolation_mode")
        effective_path_count = value.get("source_reader_effective_path_count")
        isolation_booleans = {
            field: value.get(field)
            for field in (
                "source_reader_cache_roots_phase_owned",
                "source_reader_official_endpoint",
                "source_reader_ambient_credentials_disabled",
                "source_reader_explicit_cache_dir",
                "source_reader_explicit_anonymous_load",
                "source_reader_token_files_absent",
                "source_reader_restrictive_umask",
                "source_reader_cache_symlinks_disabled",
                "source_reader_cache_lock_files_owner_only",
                "source_reader_network_activity_observed",
            )
        }
        cache_lock_mode = value.get("source_reader_cache_lock_mode")
        if (
            isolation_mode not in {"phase_owned_anonymous_official", "local_fixture_no_remote_reader"}
            or type(effective_path_count) is not int
            or effective_path_count < 0
            or any(type(item) is not bool for item in isolation_booleans.values())
            or type(cache_lock_mode) is not int
            or cache_lock_mode < 0
            or cache_lock_mode > 0o777
        ):
            raise _error("phase_commitment_invalid")
        if require_production_source and (
            isolation_mode != "phase_owned_anonymous_official"
            or effective_path_count != len(_READER_EFFECTIVE_PATH_LABELS)
            or any(item is not True for item in isolation_booleans.values())
            or cache_lock_mode != _READER_OWNER_ONLY_CACHE_LOCK_MODE
            or value.get("source_reader_cache_lock_adapter_sha256") != _reader_cache_lock_adapter_sha256()
            or value.get("source_reader_network_activity_adapter_sha256") != _reader_network_activity_adapter_sha256()
            or value.get("source_reader_endpoint_sha256") != _hash_bytes(_READER_OFFICIAL_ENDPOINT.encode("utf-8"))
            or value.get("source_reader_isolation_sha256") != _expected_remote_reader_isolation_sha256()
        ):
            raise _error("phase_commitment_invalid")
        if isolation_mode == "local_fixture_no_remote_reader" and (
            effective_path_count != 0
            or isolation_booleans["source_reader_official_endpoint"] is not False
            or isolation_booleans["source_reader_restrictive_umask"] is not False
            or isolation_booleans["source_reader_cache_lock_files_owner_only"] is not False
            or cache_lock_mode != 0
            or value.get("source_reader_cache_lock_adapter_sha256")
            != _hash_bytes(b"nerb/local-reader-cache-lock-adapter-not-applicable")
            or value.get("source_reader_network_activity_adapter_sha256")
            != _hash_bytes(b"nerb/local-reader-network-activity-adapter-not-applicable")
            or value.get("source_reader_endpoint_sha256") != _hash_bytes(b"local-reader-no-remote-endpoint")
            or value.get("source_reader_isolation_sha256") != _local_reader_isolation()["sha256"]
            or any(
                isolation_booleans[field] is not True
                for field in isolation_booleans
                if field
                not in {
                    "source_reader_official_endpoint",
                    "source_reader_explicit_cache_dir",
                    "source_reader_explicit_anonymous_load",
                    "source_reader_restrictive_umask",
                    "source_reader_cache_lock_files_owner_only",
                    "source_reader_network_activity_observed",
                }
            )
            or isolation_booleans["source_reader_explicit_cache_dir"] is not False
            or isolation_booleans["source_reader_explicit_anonymous_load"] is not False
            or isolation_booleans["source_reader_network_activity_observed"] is not False
        ):
            raise _error("phase_commitment_invalid")
        for field, item in value.items():
            if field.endswith("_sha256") and (not isinstance(item, str) or not _HASH_RE.fullmatch(item)):
                raise _error("phase_commitment_invalid")
        if phase.get("commitments_sha256") != _canonical_hash(value):
            raise _error("phase_commitment_invalid")
        if value.get("privacy_scan_sha256") != _privacy_scan_sha256(expected, value):
            raise _error("phase_commitment_invalid")
        if not _public_serialization_is_safe(value):
            raise _error("phase_commitment_invalid")
        commitments.append(value)

    preparation = commitments[0]
    for field in ("prepared_records", "prepared_source_rows"):
        _positive_int(preparation.get(field), f"commitment {field}")
    _bounded_int(preparation.get("rejected_source_rows"), "commitment rejected rows", minimum=0)
    for field in ("prepared_artifact_bytes", "rejection_artifact_bytes"):
        _bounded_int(preparation.get(field), f"commitment {field}", minimum=0)
    if int(preparation["prepared_source_rows"]) + int(preparation["rejected_source_rows"]) != ENRON_SOURCE_ROWS:
        raise _error("phase_commitment_invalid")
    expected_conservation = _source_conservation_sha256(preparation)
    if preparation["source_conservation_sha256"] != expected_conservation:
        raise _error("phase_commitment_invalid")
    if phases[0].get("records") != ENRON_SOURCE_ROWS or phases[0].get("processed_bytes") != int(
        preparation["prepared_artifact_bytes"]
    ) + int(preparation["rejection_artifact_bytes"]):
        raise _error("phase_commitment_invalid")

    if len(commitments) >= 2:
        split = commitments[1]
        _require_chain_equal(
            preparation,
            split,
            _PREPARATION_COMMITMENT_FIELDS - {"privacy_scan_sha256"},
        )
        for field in ("train_records", "validation_records", "test_records"):
            _positive_int(split.get(field), f"commitment {field}")
        for field in ("train_artifact_bytes", "validation_artifact_bytes", "test_artifact_bytes"):
            _bounded_int(split.get(field), f"commitment {field}", minimum=0)
        if sum(int(split[field]) for field in ("train_records", "validation_records", "test_records")) != int(
            split["prepared_records"]
        ):
            raise _error("phase_commitment_invalid")
        if (
            split.get("preseal_access_count") != 0
            or split.get("sealed_state") != "sealed_unbound"
            or split.get("sealed_access_state_sha256") != _sealed_access_state_sha256(split)
            or phases[1].get("records") != split["prepared_records"]
            or phases[1].get("processed_bytes")
            != sum(
                int(split[field])
                for field in ("train_artifact_bytes", "validation_artifact_bytes", "test_artifact_bytes")
            )
        ):
            raise _error("phase_commitment_invalid")

    if len(commitments) >= 3:
        split = commitments[1]
        build = commitments[2]
        _require_chain_equal(
            split,
            build,
            _SPLIT_COMMITMENT_FIELDS - {"privacy_scan_sha256"},
        )
        for field in (
            "bank_canonical_json_bytes",
            "candidate_count",
            "active_entity_count",
            "active_name_count",
            "active_pattern_count",
        ):
            _positive_int(build.get(field), f"commitment {field}")
        if (
            build.get("preseal_access_count") != 0
            or build.get("sealed_state") != "sealed_unbound"
            or phases[2].get("records") != split["train_records"]
            or phases[2].get("processed_bytes") != split["train_artifact_bytes"]
        ):
            raise _error("phase_commitment_invalid")

    if len(commitments) >= 4:
        split = commitments[1]
        build = commitments[2]
        streaming = commitments[3]
        _require_chain_equal(
            build,
            streaming,
            _BUILD_COMMITMENT_FIELDS - {"privacy_scan_sha256"},
        )
        _bounded_int(streaming.get("validation_text_utf8_bytes"), "commitment validation text bytes", minimum=0)
        if (
            streaming.get("preseal_access_count") != 0
            or streaming.get("sealed_state") != "sealed_unbound"
            or streaming.get("validation_records") != split["validation_records"]
            or phases[3].get("records") != split["validation_records"]
            or phases[3].get("processed_bytes") != streaming["validation_text_utf8_bytes"]
        ):
            raise _error("phase_commitment_invalid")

    if len(commitments) >= 5:
        split = commitments[1]
        streaming = commitments[3]
        replay = commitments[4]
        _require_chain_equal(
            streaming,
            replay,
            _STREAMING_COMMITMENT_FIELDS - {"privacy_scan_sha256"},
        )
        if (
            replay.get("preseal_access_count") != 0
            or replay.get("sealed_state") != "sealed_unbound"
            or replay.get("replay_equal") is not True
            or replay.get("replay_bank_sha256") != replay.get("bank_sha256")
            or replay.get("replay_validation_run_sha256") != replay.get("validation_run_sha256")
            or phases[4].get("records") != int(split["train_records"]) + int(split["validation_records"])
            or phases[4].get("processed_bytes")
            != int(split["train_artifact_bytes"]) + int(split["validation_artifact_bytes"])
        ):
            raise _error("phase_commitment_invalid")


def _source_conservation_sha256(commitment: Mapping[str, Any]) -> str:
    return _canonical_hash(
        {
            "dataset_id": commitment.get("dataset_id"),
            "dataset_revision": commitment.get("dataset_revision"),
            "dataset_split": commitment.get("dataset_split"),
            "source_input_rows": commitment.get("source_input_rows"),
            "source_reader": commitment.get("source_reader"),
            "source_reader_package_version": commitment.get("source_reader_package_version"),
            "source_reader_environment_sha256": commitment.get("source_reader_environment_sha256"),
            "source_row_multiset_sha256": commitment.get("source_row_multiset_sha256"),
            "prepared_records": commitment.get("prepared_records"),
            "prepared_source_rows": commitment.get("prepared_source_rows"),
            "rejected_source_rows": commitment.get("rejected_source_rows"),
            "preparation_manifest_sha256": commitment.get("preparation_manifest_sha256"),
            "prepared_artifact_sha256": commitment.get("prepared_artifact_sha256"),
            "prepared_artifact_bytes": commitment.get("prepared_artifact_bytes"),
            "rejection_artifact_sha256": commitment.get("rejection_artifact_sha256"),
            "rejection_artifact_bytes": commitment.get("rejection_artifact_bytes"),
        }
    )


def _sealed_access_state_sha256(commitment: Mapping[str, Any]) -> str:
    return _canonical_hash(
        {
            "schema": "nerb.enron_capacity.sealed_access_state",
            "source_conservation_sha256": commitment.get("source_conservation_sha256"),
            "preseal_verification_sha256": commitment.get("preseal_verification_sha256"),
            "preseal_access_count": commitment.get("preseal_access_count"),
            "sealed_state": commitment.get("sealed_state"),
            "sealed_test_accessed": commitment.get("sealed_test_accessed"),
        }
    )


def _privacy_scan_sha256(phase: str, commitment: Mapping[str, Any]) -> str:
    projection = {key: value for key, value in commitment.items() if key != "privacy_scan_sha256"}
    return _canonical_hash(
        {
            "schema": "nerb.enron_capacity.aggregate_privacy_scan",
            "phase": phase,
            "violation_count": commitment.get("privacy_scan_violation_count"),
            "closed_aggregate_projection": projection,
        }
    )


def _require_chain_equal(first: Mapping[str, Any], second: Mapping[str, Any], fields: set[str]) -> None:
    if any(first.get(field) != second.get(field) for field in fields):
        raise _error("phase_commitment_invalid")


def _capacity_report(
    *,
    preflight: _Preflight,
    execution: Mapping[str, Any],
    phase_reports: Sequence[Mapping[str, Any]],
    total_elapsed_ns: int,
    pre_report_owned_bytes: int,
    monitor_snapshot: Mapping[str, int],
) -> tuple[dict[str, Any], bytes]:
    privacy_scan_chain = _canonical_hash(
        [cast(Mapping[str, Any], phase["commitments"])["privacy_scan_sha256"] for phase in phase_reports]
    )
    report: dict[str, Any] = {
        "schema_version": CAPACITY_REPORT_SCHEMA_VERSION,
        "artifact_kind": "aggregate_capacity_evidence",
        "evidence_status": "pre_terminal_non_decision",
        "policy": capacity_policy(),
        "execution": dict(execution),
        "environment": {
            "physical_memory_bytes": preflight.physical_memory_bytes,
            "effective_rss_cap_bytes": preflight.effective_rss_cap_bytes,
            "maximum_peak_rss_bytes": preflight.maximum_peak_rss_bytes,
            "preflight_process_tree_rss_bytes": preflight.preflight_process_tree_rss_bytes,
            "preflight_free_disk_bytes": preflight.preflight_free_disk_bytes,
            "output_preflight_free_disk_bytes": preflight.output_preflight_free_disk_bytes,
            "monitored_filesystem_count": len(preflight.filesystems),
            "preexisting_private_tombstone_count": preflight.preexisting_private_tombstone_count,
            "runtime": _runtime_environment_identity(),
        },
        "phases": [dict(item) for item in phase_reports],
        "totals": {
            "source_rows_accounted": ENRON_SOURCE_ROWS,
            "elapsed_ns": total_elapsed_ns,
            "resource_observation_count": int(monitor_snapshot["resource_observation_count"]),
            "resource_acquisition_retry_count": int(monitor_snapshot["resource_acquisition_retry_count"]),
            "maximum_resource_observation_wall_gap_ns": int(
                monitor_snapshot["maximum_resource_observation_wall_gap_ns"]
            ),
            "maximum_resource_acquisition_duration_ns": int(
                monitor_snapshot["maximum_resource_acquisition_duration_ns"]
            ),
            "peak_process_tree_rss_bytes": max(
                preflight.preflight_process_tree_rss_bytes,
                int(monitor_snapshot["peak_process_tree_rss_bytes"]),
            ),
            "pre_report_owned_disk_bytes": pre_report_owned_bytes,
            "report_bytes": 0,
            "final_owned_disk_bytes": 0,
            "owned_disk_high_water_bytes": int(monitor_snapshot["owned_disk_high_water_bytes"]),
            "minimum_free_disk_bytes": min(
                preflight.preflight_free_disk_bytes,
                int(monitor_snapshot["minimum_free_disk_bytes"]),
            ),
        },
        "gates": {
            "source_conservation": True,
            "closed_commitment_chain": True,
            "preseal_access_count_zero": True,
            "sealed_state_unbound": True,
            "sealed_access_state_stable": True,
            "sealed_test_unaccessed": True,
            "replay_equal": True,
            "continuous_resource_monitoring": True,
            "resource_observation_cadence": True,
            "resource_acquisition_duration": True,
            "checkpoint_progress": True,
            "checkpoint_wall_cadence": True,
            "watchdog_interruption_supported": True,
            "process_tree_rss_supported": True,
            "preflight_free_disk": True,
            "private_tombstone_bound": True,
            "peak_rss": True,
            "owned_disk": True,
            "runtime_free_disk": True,
            "total_runtime": True,
            "phase_throughput": True,
            "passed": True,
        },
        "privacy": {
            "aggregate_only": True,
            "paths_included": False,
            "document_ids_included": False,
            "detector_values_included": False,
            "correctness_rows_included": False,
            "sealed_test_accessed": False,
            "sealed_state": "sealed_unbound",
            "sealed_access_state_sha256": phase_reports[-1]["commitments"]["sealed_access_state_sha256"],
            "privacy_scan_chain_sha256": privacy_scan_chain,
            "privacy_scanner_source_sha256": _public_serialization_scanner_source_sha256(),
            "privacy_scan_violation_count": 0,
        },
        "run_sha256": "",
    }
    for _ in range(64):
        report["run_sha256"] = hash_capacity_report(report)
        payload = _pretty_json_bytes(report)
        report_bytes = len(payload)
        final_owned = pre_report_owned_bytes + report_bytes + len(_COMMIT_PAYLOAD)
        totals = cast(dict[str, Any], report["totals"])
        high_water = max(int(totals["owned_disk_high_water_bytes"]), final_owned)
        if (
            totals["report_bytes"] == report_bytes
            and totals["final_owned_disk_bytes"] == final_owned
            and totals["owned_disk_high_water_bytes"] == high_water
        ):
            if report_bytes > MAX_CAPACITY_REPORT_BYTES:
                raise _error("report_invalid")
            if high_water > MAX_OWNED_DISK_BYTES:
                raise _error("owned_disk_limit")
            if not _public_serialization_is_safe(report):
                raise _error("report_invalid")
            return report, payload
        totals["report_bytes"] = report_bytes
        totals["final_owned_disk_bytes"] = final_owned
        totals["owned_disk_high_water_bytes"] = high_water
    raise _error("report_invalid")


def hash_capacity_report(report: Mapping[str, Any]) -> str:
    """Hash one report without its self-referential run field."""

    return _canonical_hash({key: value for key, value in report.items() if key != "run_sha256"})


def verify_capacity_report(report: Mapping[str, Any], *, require_production: bool = True) -> dict[str, Any]:
    """Verify a pre-terminal report; this is never decision evidence by itself."""

    return _verify_capacity_report(report, require_production=require_production)


def _verify_capacity_report(
    report: Mapping[str, Any],
    *,
    require_production: bool,
    current_production_execution: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(report, Mapping):
        raise _error("report_invalid")
    _require_closed(
        report,
        {
            "schema_version",
            "artifact_kind",
            "evidence_status",
            "policy",
            "execution",
            "environment",
            "phases",
            "totals",
            "gates",
            "privacy",
            "run_sha256",
        },
        "report",
    )
    if (
        report.get("schema_version") != CAPACITY_REPORT_SCHEMA_VERSION
        or report.get("artifact_kind") != "aggregate_capacity_evidence"
        or report.get("evidence_status") != "pre_terminal_non_decision"
        or report.get("policy") != capacity_policy()
    ):
        raise _error("report_invalid")
    run_sha256 = report.get("run_sha256")
    if not isinstance(run_sha256, str) or not _HASH_RE.fullmatch(run_sha256):
        raise _error("report_invalid")

    execution = _require_mapping(report.get("execution"), "execution")
    _verify_execution(
        execution,
        require_production=require_production,
        current_production_execution=current_production_execution,
    )
    environment = _require_mapping(report.get("environment"), "environment")
    _verify_environment(environment, require_current=execution.get("production_evidence") is False)
    _verify_process_containment_runtime_binding(execution, environment)
    if execution.get("runtime_environment_sha256") != _canonical_hash(environment["runtime"]):
        raise _error("report_invalid")
    if (
        execution.get("native_extension_sha256") != environment["runtime"]["native_extension_sha256"]
        or execution.get("native_build_source_sha256") != environment["runtime"]["native_build_source_sha256"]
        or execution.get("native_extension_build_source_sha256")
        != environment["runtime"]["native_extension_build_source_sha256"]
    ):
        raise _error("report_invalid")

    raw_phases = report.get("phases")
    if (
        not isinstance(raw_phases, Sequence)
        or isinstance(raw_phases, (str, bytes, bytearray))
        or len(raw_phases) != len(CAPACITY_PHASES)
    ):
        raise _error("report_invalid")
    phases: list[Mapping[str, Any]] = []
    for expected_phase, raw_phase in zip(CAPACITY_PHASES, raw_phases, strict=True):
        phase = _require_mapping(raw_phase, "phase")
        _verify_phase_report(phase, expected_phase, execution)
        phases.append(phase)
    _verify_phase_commitment_chain(
        phases,
        require_production_source=execution.get("production_evidence") is True,
    )
    if phases[-1]["commitments"]["source_reader_environment_sha256"] != _canonical_hash(
        environment["runtime"]["reader_environment"]
    ):
        raise _error("production_identity_invalid")
    if execution.get("production_evidence") is True:
        reader_environment = cast(Mapping[str, Any], environment["runtime"]["reader_environment"])
        bootstrap = cast(Mapping[str, Any], environment["runtime"]["capacity_bootstrap"])
        relevant = cast(Mapping[str, Any], execution["relevant_module_sha256"])
        if (
            not str(environment["runtime"]["python_version"]).startswith("3.13.")
            or bootstrap.get("mode") != "isolated_site_disabled"
            or bootstrap.get("isolated") is not True
            or bootstrap.get("site_disabled") is not True
            or bootstrap.get("bytecode_disabled") is not True
            or bootstrap.get("pth_processing") is not False
            or bootstrap.get("source_root") != "tracked_worktree_src"
            or bootstrap.get("private_pycache_prefix") is not True
            or bootstrap.get("dependency_root_count") not in {1, 2}
            or bootstrap.get("launcher_source_sha256") != relevant.get(_CAPACITY_LAUNCHER_PATH)
            or bootstrap.get("source_import_guard_sha256")
            != cast(Mapping[str, Any], execution["core_source_sha256"]).get("_capacity_bootstrap")
            or reader_environment.get("datasets_version") != _PINNED_DATASETS_VERSION
            or int(cast(int, reader_environment.get("datasets_file_count"))) <= 0
            or int(cast(int, reader_environment.get("datasets_total_bytes"))) <= 0
            or reader_environment.get("critical_reader_distribution_count") != len(_CRITICAL_READER_DISTRIBUTIONS)
            or int(cast(int, reader_environment.get("critical_reader_file_count"))) <= 0
            or int(cast(int, reader_environment.get("critical_reader_total_bytes"))) <= 0
            or reader_environment.get("critical_reader_versions")
            != {name: version for name, _import_name, _package_init, version in _CRITICAL_READER_DISTRIBUTIONS}
        ):
            raise _error("production_identity_invalid")

    totals = _require_mapping(report.get("totals"), "totals")
    _verify_totals(totals, environment, phases)
    gates = _require_mapping(report.get("gates"), "gates")
    expected_gates = _expected_gates(totals, environment, phases)
    if gates != expected_gates or expected_gates["passed"] is not True:
        raise _error("report_invalid")

    privacy = _require_mapping(report.get("privacy"), "privacy")
    expected_privacy = {
        "aggregate_only": True,
        "paths_included": False,
        "document_ids_included": False,
        "detector_values_included": False,
        "correctness_rows_included": False,
        "sealed_test_accessed": False,
        "sealed_state": "sealed_unbound",
        "sealed_access_state_sha256": phases[-1]["commitments"]["sealed_access_state_sha256"],
        "privacy_scan_chain_sha256": _canonical_hash([phase["commitments"]["privacy_scan_sha256"] for phase in phases]),
        "privacy_scanner_source_sha256": phases[-1]["commitments"]["privacy_scanner_source_sha256"],
        "privacy_scan_violation_count": 0,
    }
    if privacy != expected_privacy:
        raise _error("report_invalid")
    if not _public_serialization_is_safe(report):
        raise _error("report_invalid")
    if run_sha256 != hash_capacity_report(report):
        raise _error("report_invalid")
    try:
        payload = _pretty_json_bytes(report)
    except (OverflowError, TypeError, ValueError):
        raise _error("report_invalid") from None
    if len(payload) != totals["report_bytes"] or len(payload) > MAX_CAPACITY_REPORT_BYTES:
        raise _error("report_invalid")
    return dict(report)


def _verify_execution(
    execution: Mapping[str, Any],
    *,
    require_production: bool,
    current_production_execution: Mapping[str, Any] | None = None,
) -> None:
    _require_closed(
        execution,
        {
            "production_evidence",
            "fresh_worker",
            "process_containment",
            "executable_git_commit",
            "git_tree_clean",
            "repository_tree_sha256",
            "capacity_implementation_sha256",
            "core_source_sha256",
            "relevant_module_sha256",
            "native_extension_sha256",
            "native_build_source_sha256",
            "native_extension_build_source_sha256",
            "reader_lock_sha256",
            "extraction_execution_sha256",
            "runtime_environment_sha256",
            "resource_probe_implementation_sha256",
            "runner_implementation_sha256",
            "monitor_interval_ns",
            "report_measurement_boundary",
            "attempt_measurement_boundary",
        },
        "execution",
    )
    production = execution.get("production_evidence")
    if type(production) is not bool or (require_production and production is not True):
        raise _error("report_invalid")
    if current_production_execution is not None and production is not True:
        raise _error("report_invalid")
    containment = _require_mapping(execution.get("process_containment"), "process containment")
    _require_closed(
        containment,
        {"mode", "architecture", "policy_sha256", "installed_before_workload", "runtime_attested"},
        "process containment",
    )
    containment_mode = containment.get("mode")
    containment_architecture = containment.get("architecture")
    containment_sha256 = containment.get("policy_sha256")
    if (
        not isinstance(containment_mode, str)
        or not isinstance(containment_architecture, str)
        or not isinstance(containment_sha256, str)
        or _HASH_RE.fullmatch(containment_sha256) is None
        or type(containment.get("installed_before_workload")) is not bool
        or type(containment.get("runtime_attested")) is not bool
    ):
        raise _error("report_invalid")
    try:
        expected_containment_sha256 = _process_containment_policy_sha256(
            containment_mode,
            containment_architecture,
        )
    except EnronCapacityError:
        raise _error("report_invalid") from None
    if containment_sha256 != expected_containment_sha256:
        raise _error("report_invalid")
    if production:
        if (
            containment_mode not in {_LINUX_PROCESS_CONTAINMENT, _DARWIN_PROCESS_CONTAINMENT}
            or containment.get("installed_before_workload") is not True
            or containment.get("runtime_attested") is not True
        ):
            raise _error("report_invalid")
    elif containment != _process_containment_identity(production=False):
        raise _error("report_invalid")
    git_commit = execution.get("executable_git_commit")
    if not isinstance(git_commit, str) or not _GIT_COMMIT_RE.fullmatch(git_commit):
        raise _error("report_invalid")
    if type(execution.get("git_tree_clean")) is not bool or type(execution.get("fresh_worker")) is not bool:
        raise _error("report_invalid")
    for field in (
        "repository_tree_sha256",
        "capacity_implementation_sha256",
        "native_extension_sha256",
        "native_build_source_sha256",
        "native_extension_build_source_sha256",
        "reader_lock_sha256",
        "extraction_execution_sha256",
        "runtime_environment_sha256",
        "resource_probe_implementation_sha256",
    ):
        value = execution.get(field)
        if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
            raise _error("report_invalid")
    core_sources = _require_mapping(execution.get("core_source_sha256"), "core source identities")
    if set(core_sources) != set(_production_core_source_paths()) or any(
        not isinstance(value, str) or not _HASH_RE.fullmatch(value) for value in core_sources.values()
    ):
        raise _error("report_invalid")
    relevant_modules = _require_mapping(execution.get("relevant_module_sha256"), "relevant module identities")
    if not relevant_modules or any(
        not isinstance(key, str) or not isinstance(value, str) or not _HASH_RE.fullmatch(value)
        for key, value in relevant_modules.items()
    ):
        raise _error("report_invalid")
    runners = _require_mapping(execution.get("runner_implementation_sha256"), "runner identities")
    if set(runners) != set(CAPACITY_PHASES) or any(
        not isinstance(value, str) or not _HASH_RE.fullmatch(value) for value in runners.values()
    ):
        raise _error("report_invalid")
    _positive_int(execution.get("monitor_interval_ns"), "monitor interval")
    if (
        execution.get("report_measurement_boundary") != _REPORT_MEASUREMENT_BOUNDARY
        or execution.get("attempt_measurement_boundary") != _ATTEMPT_MEASUREMENT_BOUNDARY
    ):
        raise _error("report_invalid")
    if production:
        if current_production_execution is None:
            _verify_recorded_production_execution(execution)
        elif (
            not require_production
            or execution != current_production_execution
            or _PRODUCTION_PROCESS_CONTAINMENT != containment_mode
        ):
            raise _error("production_identity_invalid")
    elif execution.get("git_tree_clean") is not False or execution.get("fresh_worker") is not False:
        raise _error("report_invalid")
    elif (
        execution.get("capacity_implementation_sha256") != _implementation_sha256()
        or core_sources != _core_source_sha256()
        or relevant_modules != _relevant_module_sha256()
        or execution.get("repository_tree_sha256") != _repository_tree_sha256(git_commit)
        or execution.get("native_extension_sha256") != _native_extension_sha256()
        or execution.get("native_build_source_sha256") != _native_build_source_sha256()
        or execution.get("native_extension_build_source_sha256")
        != (_native_extension_embedded_build_source_sha256() or _UNAVAILABLE_NATIVE_BUILD_SOURCE_SHA256)
        or execution.get("reader_lock_sha256") != _reader_lock_sha256()
        or execution.get("extraction_execution_sha256") != _extraction_execution_sha256()
        or execution.get("runtime_environment_sha256") != _canonical_hash(_runtime_environment_identity())
    ):
        raise _error("report_invalid")


def _verify_environment(environment: Mapping[str, Any], *, require_current: bool) -> None:
    _require_closed(
        environment,
        {
            "physical_memory_bytes",
            "effective_rss_cap_bytes",
            "maximum_peak_rss_bytes",
            "preflight_process_tree_rss_bytes",
            "preflight_free_disk_bytes",
            "output_preflight_free_disk_bytes",
            "monitored_filesystem_count",
            "preexisting_private_tombstone_count",
            "runtime",
        },
        "environment",
    )
    for field in environment:
        if field == "preexisting_private_tombstone_count":
            _bounded_int(environment[field], f"environment {field}", minimum=0)
        elif field != "runtime":
            _positive_int(environment[field], f"environment {field}")
    runtime = _require_mapping(environment.get("runtime"), "runtime environment")
    _verify_runtime_environment_shape(runtime)
    if require_current and runtime != _runtime_environment_identity():
        raise _error("report_invalid")
    physical = int(environment["physical_memory_bytes"])
    effective = min(
        MAX_ABSOLUTE_RSS_BYTES,
        physical * PHYSICAL_MEMORY_FRACTION_NUMERATOR // PHYSICAL_MEMORY_FRACTION_DENOMINATOR,
    )
    maximum_peak = effective * PEAK_RSS_FRACTION_NUMERATOR // PEAK_RSS_FRACTION_DENOMINATOR
    if (
        environment["effective_rss_cap_bytes"] != effective
        or environment["maximum_peak_rss_bytes"] != maximum_peak
        or int(environment["monitored_filesystem_count"]) not in {1, 2}
        or int(environment["preexisting_private_tombstone_count"]) > MAX_RETAINED_PRIVATE_TOMBSTONES
    ):
        raise _error("report_invalid")


def _verify_process_containment_runtime_binding(
    execution: Mapping[str, Any],
    environment: Mapping[str, Any],
) -> None:
    """Bind a production containment claim to its recorded kernel and architecture."""

    if execution.get("production_evidence") is not True:
        return
    containment = _require_mapping(execution.get("process_containment"), "process containment")
    runtime = _require_mapping(environment.get("runtime"), "runtime environment")
    kernel_system = runtime.get("kernel_system")
    architecture = runtime.get("architecture")
    expected_mode = (
        {
            "Darwin": _DARWIN_PROCESS_CONTAINMENT,
            "Linux": _LINUX_PROCESS_CONTAINMENT,
        }.get(kernel_system)
        if isinstance(kernel_system, str)
        else None
    )
    if (
        expected_mode is None
        or not isinstance(architecture, str)
        or containment.get("mode") != expected_mode
        or containment.get("architecture") != architecture.lower()
    ):
        raise _error("report_invalid")


def _verify_phase_report(
    phase: Mapping[str, Any],
    expected_phase: str,
    execution: Mapping[str, Any],
) -> None:
    _require_closed(
        phase,
        {
            "phase",
            "records",
            "processed_bytes",
            "commitments",
            "commitments_sha256",
            "runner_implementation_sha256",
            "executable_git_commit",
            "owned_root_count",
            "elapsed_ns",
            "throughput_milli_records_per_second",
            "resource_observation_count",
            "resource_acquisition_retry_count",
            "peak_process_tree_rss_bytes",
            "owned_disk_high_water_bytes",
            "minimum_free_disk_bytes",
            "maximum_resource_observation_wall_gap_ns",
            "maximum_resource_acquisition_duration_ns",
            "maximum_progress_checkpoint_wall_gap_ns",
            "resource_samples",
            "checkpoint_count",
            "maximum_checkpoint_gap_records",
            "checkpoint_samples",
            "progress_signal_count",
            "progress_signals",
        },
        "phase",
    )
    if phase.get("phase") != expected_phase:
        raise _error("report_invalid")
    records = _positive_int(phase.get("records"), "phase records")
    _bounded_int(phase.get("processed_bytes"), "phase processed bytes", minimum=0)
    elapsed_ns = _positive_int(phase.get("elapsed_ns"), "phase elapsed time")
    expected_throughput = records * 1_000_000_000_000 // elapsed_ns
    if (
        phase.get("throughput_milli_records_per_second") != expected_throughput
        or expected_throughput < MIN_PHASE_RECORDS_PER_SECOND * 1_000
    ):
        raise _error("report_invalid")
    runners = cast(Mapping[str, Any], execution["runner_implementation_sha256"])
    if (
        phase.get("runner_implementation_sha256") != runners[expected_phase]
        or phase.get("executable_git_commit") != execution["executable_git_commit"]
    ):
        raise _error("report_invalid")
    _positive_int(phase.get("owned_root_count"), "owned root count")
    observation_count = _positive_int(phase.get("resource_observation_count"), "resource observation count")
    acquisition_retry_count = _bounded_int(
        phase.get("resource_acquisition_retry_count"), "resource acquisition retry count", minimum=0
    )
    if acquisition_retry_count > observation_count * 2 * (_RUNTIME_RESOURCE_ACQUISITION_MAX_ATTEMPTS - 1):
        raise _error("report_invalid")
    peak = _positive_int(phase.get("peak_process_tree_rss_bytes"), "phase RSS")
    owned = _bounded_int(phase.get("owned_disk_high_water_bytes"), "phase owned disk", minimum=0)
    minimum_free = _bounded_int(phase.get("minimum_free_disk_bytes"), "phase free disk", minimum=0)
    maximum_resource_wall_gap = _bounded_int(
        phase.get("maximum_resource_observation_wall_gap_ns"), "resource wall gap", minimum=0
    )
    maximum_resource_acquisition_duration = _bounded_int(
        phase.get("maximum_resource_acquisition_duration_ns"), "resource acquisition duration", minimum=0
    )
    maximum_progress_wall_gap = _bounded_int(
        phase.get("maximum_progress_checkpoint_wall_gap_ns"), "progress wall gap", minimum=0
    )

    raw_samples = phase.get("resource_samples")
    if (
        not isinstance(raw_samples, Sequence)
        or isinstance(raw_samples, (str, bytes, bytearray))
        or not 1 <= len(raw_samples) <= MAX_RESOURCE_SAMPLES_PER_PHASE
        or len(raw_samples) > observation_count
    ):
        raise _error("report_invalid")
    samples: list[Mapping[str, Any]] = []
    previous_sequence = 0
    for raw_sample in raw_samples:
        sample = _require_mapping(raw_sample, "resource sample")
        _require_closed(
            sample,
            {
                "sequence",
                "elapsed_ns",
                "wall_elapsed_ns",
                "resource_observation_wall_gap_ns",
                "sample_kind",
                "completed_records",
                "process_tree_rss_bytes",
                "owned_disk_bytes",
                "free_disk_bytes",
                "resource_acquisition_duration_ns",
                "rss_acquisition_duration_ns",
                "filesystem_acquisition_duration_ns",
                "resource_acquisition_retry_count",
                "scheduler_lateness_ns",
            },
            "resource sample",
        )
        sequence = _positive_int(sample.get("sequence"), "resource sample sequence")
        if sequence <= previous_sequence or sequence > observation_count:
            raise _error("report_invalid")
        previous_sequence = sequence
        sample_elapsed = _bounded_int(sample.get("elapsed_ns"), "sample elapsed", minimum=0)
        _bounded_int(sample.get("wall_elapsed_ns"), "sample wall elapsed", minimum=0)
        _bounded_int(sample.get("resource_observation_wall_gap_ns"), "resource wall gap", minimum=0)
        if sample_elapsed > elapsed_ns or sample.get("sample_kind") not in {
            "continuous",
            "checkpoint",
            "heartbeat",
            "activity",
            "boundary",
        }:
            raise _error("report_invalid")
        completed = sample.get("completed_records")
        if completed is not None and (type(completed) is not int or completed <= 0 or completed > records):
            raise _error("report_invalid")
        _positive_int(sample.get("process_tree_rss_bytes"), "sample RSS")
        _bounded_int(sample.get("owned_disk_bytes"), "sample owned disk", minimum=0)
        _bounded_int(sample.get("free_disk_bytes"), "sample free disk", minimum=0)
        acquisition_duration = _bounded_int(
            sample.get("resource_acquisition_duration_ns"), "sample resource acquisition duration", minimum=0
        )
        rss_duration = _bounded_int(
            sample.get("rss_acquisition_duration_ns"), "sample RSS acquisition duration", minimum=0
        )
        filesystem_duration = _bounded_int(
            sample.get("filesystem_acquisition_duration_ns"), "sample filesystem acquisition duration", minimum=0
        )
        sample_retries = _bounded_int(
            sample.get("resource_acquisition_retry_count"), "sample acquisition retry count", minimum=0
        )
        _bounded_int(sample.get("scheduler_lateness_ns"), "sample scheduler lateness", minimum=0)
        if rss_duration + filesystem_duration != acquisition_duration or sample_retries > 2 * (
            _RUNTIME_RESOURCE_ACQUISITION_MAX_ATTEMPTS - 1
        ):
            raise _error("report_invalid")
        samples.append(sample)
    if (
        max(int(item["process_tree_rss_bytes"]) for item in samples) != peak
        or max(int(item["owned_disk_bytes"]) for item in samples) != owned
        or min(int(item["free_disk_bytes"]) for item in samples) != minimum_free
        or max(int(item["resource_observation_wall_gap_ns"]) for item in samples) != maximum_resource_wall_gap
        or max(int(item["resource_acquisition_duration_ns"]) for item in samples)
        != maximum_resource_acquisition_duration
    ):
        raise _error("report_invalid")
    retained_sequences = {int(item["sequence"]) for item in samples}
    cadence_sequences: set[int] = set()
    cadence = 1
    while cadence <= observation_count:
        cadence_sequences.add(cadence)
        cadence *= 2
    if (
        1 not in retained_sequences
        or observation_count not in retained_sequences
        or not cadence_sequences <= retained_sequences
    ):
        raise _error("report_invalid")

    raw_checkpoints = phase.get("checkpoint_samples")
    checkpoint_count = _positive_int(phase.get("checkpoint_count"), "checkpoint count")
    if (
        not isinstance(raw_checkpoints, Sequence)
        or isinstance(raw_checkpoints, (str, bytes, bytearray))
        or len(raw_checkpoints) != checkpoint_count
        or checkpoint_count > MAX_CHECKPOINTS_PER_PHASE
    ):
        raise _error("report_invalid")
    previous_completed = 0
    maximum_gap = 0
    previous_elapsed = -1
    previous_wall_elapsed = 0
    for index, raw_checkpoint in enumerate(raw_checkpoints, start=1):
        checkpoint = _require_mapping(raw_checkpoint, "checkpoint")
        _require_closed(checkpoint, {"sequence", "completed_records", "elapsed_ns", "wall_elapsed_ns"}, "checkpoint")
        if checkpoint.get("sequence") != index:
            raise _error("report_invalid")
        completed = _positive_int(checkpoint.get("completed_records"), "checkpoint records")
        gap = completed - previous_completed
        elapsed = _bounded_int(checkpoint.get("elapsed_ns"), "checkpoint elapsed", minimum=0)
        wall_elapsed = _bounded_int(checkpoint.get("wall_elapsed_ns"), "checkpoint wall elapsed", minimum=0)
        if (
            gap <= 0
            or gap > MAX_CHECKPOINT_RECORD_GAP
            or elapsed < previous_elapsed
            or elapsed > elapsed_ns
            or wall_elapsed < previous_wall_elapsed
        ):
            raise _error("report_invalid")
        maximum_gap = max(maximum_gap, gap)
        previous_completed = completed
        previous_elapsed = elapsed
        previous_wall_elapsed = wall_elapsed

    raw_progress_signals = phase.get("progress_signals")
    progress_signal_count = _positive_int(phase.get("progress_signal_count"), "progress signal count")
    if (
        not isinstance(raw_progress_signals, Sequence)
        or isinstance(raw_progress_signals, (str, bytes, bytearray))
        or not 1 <= len(raw_progress_signals) <= MAX_PROGRESS_SIGNALS_PER_PHASE
        or len(raw_progress_signals) > progress_signal_count
    ):
        raise _error("report_invalid")
    previous_signal_wall = 0
    previous_signal_records = 0
    maximum_signal_wall_gap = 0
    checkpoint_signals: list[tuple[int, int]] = []
    previous_signal_sequence = 0
    for raw_signal in raw_progress_signals:
        progress_signal = _require_mapping(raw_signal, "progress signal")
        _require_closed(
            progress_signal,
            {"sequence", "kind", "completed_records", "wall_elapsed_ns", "progress_wall_gap_ns"},
            "progress signal",
        )
        completed = _bounded_int(progress_signal.get("completed_records"), "progress signal records", minimum=0)
        wall_elapsed = _bounded_int(progress_signal.get("wall_elapsed_ns"), "progress signal wall", minimum=0)
        kind = progress_signal.get("kind")
        sequence = _positive_int(progress_signal.get("sequence"), "progress signal sequence")
        wall_gap = _bounded_int(progress_signal.get("progress_wall_gap_ns"), "progress signal gap", minimum=0)
        if (
            sequence <= previous_signal_sequence
            or sequence > progress_signal_count
            or kind not in {"checkpoint", "heartbeat", "activity", "phase_boundary"}
            or completed < previous_signal_records
            or completed > records
            or wall_elapsed < previous_signal_wall
            or wall_gap > MAX_PROGRESS_CHECKPOINT_WALL_GAP_NS
        ):
            raise _error("report_invalid")
        if kind == "checkpoint":
            checkpoint_signals.append((completed, wall_elapsed))
        maximum_signal_wall_gap = max(maximum_signal_wall_gap, wall_gap)
        previous_signal_wall = wall_elapsed
        previous_signal_records = completed
        previous_signal_sequence = sequence
    if (
        raw_progress_signals[-1]["kind"] != "phase_boundary"
        or raw_progress_signals[-1]["sequence"] != progress_signal_count
        or previous_signal_records != records
        or checkpoint_signals
        != [
            (int(checkpoint["completed_records"]), int(checkpoint["wall_elapsed_ns"]))
            for checkpoint in cast(Sequence[Mapping[str, Any]], raw_checkpoints)
        ]
    ):
        raise _error("report_invalid")
    if (
        previous_completed != records
        or phase.get("maximum_checkpoint_gap_records") != maximum_gap
        or maximum_gap > MAX_CHECKPOINT_RECORD_GAP
        or maximum_resource_wall_gap > MAX_RESOURCE_OBSERVATION_WALL_GAP_NS
        or maximum_resource_acquisition_duration > MAX_RESOURCE_ACQUISITION_DURATION_NS
        or maximum_progress_wall_gap != maximum_signal_wall_gap
        or maximum_progress_wall_gap > MAX_PROGRESS_CHECKPOINT_WALL_GAP_NS
    ):
        raise _error("report_invalid")


def _verify_totals(
    totals: Mapping[str, Any],
    environment: Mapping[str, Any],
    phases: Sequence[Mapping[str, Any]],
) -> None:
    _require_closed(
        totals,
        {
            "source_rows_accounted",
            "elapsed_ns",
            "resource_observation_count",
            "resource_acquisition_retry_count",
            "maximum_resource_observation_wall_gap_ns",
            "maximum_resource_acquisition_duration_ns",
            "peak_process_tree_rss_bytes",
            "pre_report_owned_disk_bytes",
            "report_bytes",
            "final_owned_disk_bytes",
            "owned_disk_high_water_bytes",
            "minimum_free_disk_bytes",
        },
        "totals",
    )
    for field, value in totals.items():
        minimum = (
            1
            if field
            in {
                "elapsed_ns",
                "resource_observation_count",
                "peak_process_tree_rss_bytes",
                "report_bytes",
                "final_owned_disk_bytes",
            }
            else 0
        )
        _bounded_int(value, f"totals {field}", minimum=minimum)
    expected_final_owned = (
        int(totals["pre_report_owned_disk_bytes"]) + int(totals["report_bytes"]) + len(_COMMIT_PAYLOAD)
    )
    phase_observations = sum(int(phase["resource_observation_count"]) for phase in phases)
    phase_acquisition_retries = sum(int(phase["resource_acquisition_retry_count"]) for phase in phases)
    if (
        totals["source_rows_accounted"] != ENRON_SOURCE_ROWS
        or totals["elapsed_ns"] < sum(int(phase["elapsed_ns"]) for phase in phases)
        or totals["resource_observation_count"] < phase_observations
        or totals["resource_acquisition_retry_count"] < phase_acquisition_retries
        or totals["resource_acquisition_retry_count"]
        > int(totals["resource_observation_count"]) * 2 * (_RUNTIME_RESOURCE_ACQUISITION_MAX_ATTEMPTS - 1)
        or int(totals["resource_acquisition_retry_count"]) - phase_acquisition_retries
        > (int(totals["resource_observation_count"]) - phase_observations)
        * 2
        * (_RUNTIME_RESOURCE_ACQUISITION_MAX_ATTEMPTS - 1)
        or totals["maximum_resource_observation_wall_gap_ns"]
        < max(int(phase["maximum_resource_observation_wall_gap_ns"]) for phase in phases)
        or totals["maximum_resource_acquisition_duration_ns"]
        < max(int(phase["maximum_resource_acquisition_duration_ns"]) for phase in phases)
        or totals["peak_process_tree_rss_bytes"]
        < max(
            int(environment["preflight_process_tree_rss_bytes"]),
            *(int(phase["peak_process_tree_rss_bytes"]) for phase in phases),
        )
        or totals["final_owned_disk_bytes"] != expected_final_owned
        or totals["owned_disk_high_water_bytes"]
        < max(
            expected_final_owned,
            int(totals["pre_report_owned_disk_bytes"]),
            *(int(phase["owned_disk_high_water_bytes"]) for phase in phases),
        )
        or totals["minimum_free_disk_bytes"]
        > min(
            int(environment["preflight_free_disk_bytes"]),
            *(int(phase["minimum_free_disk_bytes"]) for phase in phases),
        )
    ):
        raise _error("report_invalid")


def _expected_gates(
    totals: Mapping[str, Any],
    environment: Mapping[str, Any],
    phases: Sequence[Mapping[str, Any]],
) -> dict[str, bool]:
    commitments = [cast(Mapping[str, Any], phase["commitments"]) for phase in phases]
    gates = {
        "source_conservation": totals["source_rows_accounted"] == ENRON_SOURCE_ROWS,
        "closed_commitment_chain": len(phases) == len(CAPACITY_PHASES),
        "preseal_access_count_zero": all(commitment.get("preseal_access_count", 0) == 0 for commitment in commitments),
        "sealed_state_unbound": all(
            commitment.get("sealed_state") == "sealed_unbound" for commitment in commitments[1:]
        ),
        "sealed_access_state_stable": len(
            {commitment.get("sealed_access_state_sha256") for commitment in commitments[1:]}
        )
        == 1,
        "sealed_test_unaccessed": all(commitment["sealed_test_accessed"] is False for commitment in commitments),
        "replay_equal": commitments[-1]["replay_equal"] is True,
        "continuous_resource_monitoring": all(int(phase["resource_observation_count"]) > 0 for phase in phases),
        "resource_observation_cadence": int(totals["maximum_resource_observation_wall_gap_ns"])
        <= MAX_RESOURCE_OBSERVATION_WALL_GAP_NS,
        "resource_acquisition_duration": int(totals["maximum_resource_acquisition_duration_ns"])
        <= MAX_RESOURCE_ACQUISITION_DURATION_NS,
        "checkpoint_progress": all(
            0 < int(phase["maximum_checkpoint_gap_records"]) <= MAX_CHECKPOINT_RECORD_GAP for phase in phases
        ),
        "checkpoint_wall_cadence": all(
            int(phase["maximum_progress_checkpoint_wall_gap_ns"]) <= MAX_PROGRESS_CHECKPOINT_WALL_GAP_NS
            for phase in phases
        ),
        "watchdog_interruption_supported": os.name == "posix" and hasattr(signal, "SIGUSR1"),
        "process_tree_rss_supported": int(totals["peak_process_tree_rss_bytes"]) > 0,
        "preflight_free_disk": int(environment["preflight_free_disk_bytes"]) >= MIN_PREFLIGHT_FREE_DISK_BYTES,
        "private_tombstone_bound": int(environment["preexisting_private_tombstone_count"])
        <= MAX_RETAINED_PRIVATE_TOMBSTONES,
        "peak_rss": int(totals["peak_process_tree_rss_bytes"]) <= int(environment["maximum_peak_rss_bytes"]),
        "owned_disk": int(totals["owned_disk_high_water_bytes"]) <= MAX_OWNED_DISK_BYTES,
        "runtime_free_disk": int(totals["minimum_free_disk_bytes"]) >= MIN_RUNTIME_FREE_DISK_BYTES,
        "total_runtime": int(totals["elapsed_ns"]) <= MAX_TOTAL_RUNTIME_NS,
        "phase_throughput": all(
            int(phase["throughput_milli_records_per_second"]) >= MIN_PHASE_RECORDS_PER_SECOND * 1_000
            for phase in phases
        ),
    }
    gates["passed"] = all(gates.values())
    return gates


def _execution_identity(
    runners: tuple[tuple[str, CapacityPhaseRunner], ...],
    probe: CapacityResourceProbe,
    *,
    production_evidence: bool,
    monitor_interval_ns: int,
) -> dict[str, Any]:
    git_commit = _git_head()
    if production_evidence and git_commit != _PRODUCTION_GIT_COMMIT:
        raise _error("production_identity_invalid")
    runner_hashes = {
        phase: _callable_implementation_sha256(runner, role=f"phase:{phase}", git_commit=git_commit)
        for phase, runner in runners
    }
    execution = {
        "production_evidence": production_evidence,
        "fresh_worker": False,
        "process_containment": _process_containment_identity(production=production_evidence),
        "executable_git_commit": git_commit,
        "git_tree_clean": False,
        "repository_tree_sha256": _repository_tree_sha256(git_commit),
        "capacity_implementation_sha256": _implementation_sha256(),
        "core_source_sha256": _core_source_sha256(),
        "relevant_module_sha256": _relevant_module_sha256(),
        "native_extension_sha256": _native_extension_sha256(),
        "native_build_source_sha256": _native_build_source_sha256(),
        "native_extension_build_source_sha256": (
            _native_extension_embedded_build_source_sha256() or _UNAVAILABLE_NATIVE_BUILD_SOURCE_SHA256
        ),
        "reader_lock_sha256": _reader_lock_sha256(),
        "extraction_execution_sha256": _extraction_execution_sha256(),
        "runtime_environment_sha256": _canonical_hash(_runtime_environment_identity()),
        "resource_probe_implementation_sha256": _callable_implementation_sha256(
            type(probe), role="resource_probe", git_commit=git_commit
        ),
        "runner_implementation_sha256": runner_hashes,
        "monitor_interval_ns": monitor_interval_ns,
        "report_measurement_boundary": _REPORT_MEASUREMENT_BOUNDARY,
        "attempt_measurement_boundary": _ATTEMPT_MEASUREMENT_BOUNDARY,
    }
    if production_evidence:
        expected = _production_execution_identity()
        if execution | {"fresh_worker": True, "git_tree_clean": True} != expected:
            raise _error("production_identity_invalid")
        execution = expected
    return execution


def _production_execution_identity() -> dict[str, Any]:
    if not _FRESH_PRODUCTION_WORKER:
        raise _error("production_identity_invalid")
    _assert_reader_modules_unloaded()
    if _current_process_umask() != 0o077:
        raise _error("production_identity_invalid")
    git_commit = _git_head()
    if git_commit != _PRODUCTION_GIT_COMMIT:
        raise _error("production_identity_invalid")
    runners = _production_phase_runners()
    tracked_callables: list[object] = [*runners.values(), _SystemResourceProbe]
    source_paths = {_callable_source_path(value) for value in tracked_callables}
    source_paths.update(_production_core_source_paths().values())
    _require_globally_clean_checkout(git_commit)
    _require_clean_head_sources(source_paths, git_commit)
    if _root_process_peak_rss_bytes() is None:
        raise _error("production_identity_invalid")
    native_build_source_sha256 = _native_build_source_sha256()
    native_extension_build_source_sha256 = _native_extension_embedded_build_source_sha256()
    if native_extension_build_source_sha256 != native_build_source_sha256:
        raise _error("production_identity_invalid")
    reader_environment = _reader_environment_identity()
    if (
        reader_environment["datasets_version"] != _PINNED_DATASETS_VERSION
        or int(reader_environment["datasets_file_count"]) <= 0
        or int(reader_environment["datasets_total_bytes"]) <= 0
        or reader_environment["critical_reader_distribution_count"] != len(_CRITICAL_READER_DISTRIBUTIONS)
        or int(reader_environment["critical_reader_file_count"]) <= 0
        or int(reader_environment["critical_reader_total_bytes"]) <= 0
        or reader_environment["critical_reader_versions"]
        != {name: version for name, _import_name, _package_init, version in _CRITICAL_READER_DISTRIBUTIONS}
    ):
        raise _error("production_identity_invalid")
    _assert_reader_modules_unloaded()
    identity = {
        "production_evidence": True,
        "fresh_worker": True,
        "process_containment": _process_containment_identity(production=True),
        "executable_git_commit": git_commit,
        "git_tree_clean": True,
        "repository_tree_sha256": _repository_tree_sha256(git_commit),
        "capacity_implementation_sha256": _implementation_sha256(),
        "core_source_sha256": _core_source_sha256(),
        "relevant_module_sha256": _relevant_module_sha256(),
        "native_extension_sha256": _native_extension_sha256(),
        "native_build_source_sha256": native_build_source_sha256,
        "native_extension_build_source_sha256": native_extension_build_source_sha256,
        "reader_lock_sha256": _reader_lock_sha256(),
        "extraction_execution_sha256": _extraction_execution_sha256(),
        "runtime_environment_sha256": _canonical_hash(_runtime_environment_identity()),
        "resource_probe_implementation_sha256": _callable_implementation_sha256(
            _SystemResourceProbe, role="resource_probe", git_commit=git_commit
        ),
        "runner_implementation_sha256": {
            phase: _callable_implementation_sha256(runner, role=f"phase:{phase}", git_commit=git_commit)
            for phase, runner in runners.items()
        },
        "monitor_interval_ns": PRODUCTION_MONITOR_INTERVAL_NS,
        "report_measurement_boundary": _REPORT_MEASUREMENT_BOUNDARY,
        "attempt_measurement_boundary": _ATTEMPT_MEASUREMENT_BOUNDARY,
    }
    _verify_recorded_production_execution(identity)
    return identity


def _verify_recorded_production_execution(execution: Mapping[str, Any]) -> None:
    git_commit = cast(str, execution["executable_git_commit"])
    capacity_source = _git_blob_bytes(git_commit, "src/nerb/enron_capacity.py")
    capacity_sha256 = _hash_bytes(capacity_source)
    if (
        execution.get("fresh_worker") is not True
        or execution.get("git_tree_clean") is not True
        or execution.get("monitor_interval_ns") != PRODUCTION_MONITOR_INTERVAL_NS
        or execution.get("repository_tree_sha256") != _repository_tree_sha256(git_commit)
        or execution.get("capacity_implementation_sha256") != capacity_sha256
        or execution.get("core_source_sha256") != _core_source_sha256_at_commit(git_commit)
        or execution.get("relevant_module_sha256") != _relevant_module_sha256_at_commit(git_commit)
        or execution.get("native_build_source_sha256") != _native_build_source_sha256_at_commit(git_commit)
        or execution.get("native_extension_build_source_sha256") != _native_build_source_sha256_at_commit(git_commit)
        or execution.get("reader_lock_sha256") != _reader_lock_sha256_at_commit(git_commit)
        or execution.get("extraction_execution_sha256") != _extraction_execution_sha256_at_commit(git_commit)
    ):
        raise _error("production_identity_invalid")
    expected_runners = {
        phase: _recorded_callable_sha256(
            role=f"phase:{phase}",
            module="nerb.enron_capacity",
            qualname={
                "preparation": "_run_production_preparation",
                "split": "_run_production_split",
                "build": "_run_production_build",
                "streaming_validation": "_run_production_streaming_validation",
                "deep_replay": "_run_production_deep_replay",
            }[phase],
            source_sha256=capacity_sha256,
            capacity_sha256=capacity_sha256,
            git_commit=git_commit,
        )
        for phase in CAPACITY_PHASES
    }
    expected_probe = _recorded_callable_sha256(
        role="resource_probe",
        module="nerb.enron_capacity",
        qualname="_SystemResourceProbe",
        source_sha256=capacity_sha256,
        capacity_sha256=capacity_sha256,
        git_commit=git_commit,
    )
    if (
        execution.get("runner_implementation_sha256") != expected_runners
        or execution.get("resource_probe_implementation_sha256") != expected_probe
    ):
        raise _error("production_identity_invalid")


def _recorded_callable_sha256(
    *,
    role: str,
    module: str,
    qualname: str,
    source_sha256: str,
    capacity_sha256: str,
    git_commit: str,
) -> str:
    return _canonical_hash(
        {
            "role": role,
            "module": module,
            "qualname": qualname,
            "source_sha256": source_sha256,
            "capacity_implementation_sha256": capacity_sha256,
            "executable_git_commit": git_commit,
        }
    )


def _git_blob_bytes(git_commit: str, relative_path: str) -> bytes:
    root = _git_root()
    try:
        completed = subprocess.run(
            ["git", "-C", os.fspath(root), "show", f"{git_commit}:{relative_path}"],
            check=False,
            capture_output=True,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError):
        raise _error("production_identity_invalid") from None
    if completed.returncode != 0:
        raise _error("production_identity_invalid")
    return completed.stdout


def _core_source_sha256_at_commit(git_commit: str) -> dict[str, str]:
    return {
        name.removesuffix(".py"): _hash_bytes(_git_blob_bytes(git_commit, f"src/nerb/{name}"))
        for name in _PRODUCTION_CORE_SOURCE_NAMES
    }


def _selected_relevant_module_paths(paths: Sequence[str]) -> tuple[str, ...]:
    return tuple(
        sorted(
            path
            for path in paths
            if (path.startswith("src/nerb/") and path.endswith(".py"))
            or (path.startswith("rust/") and path.endswith(".rs"))
            or path
            in {
                "rust/Cargo.toml",
                "rust/Cargo.lock",
                "Cargo.lock",
                "pyproject.toml",
                "uv.lock",
                _CAPACITY_LAUNCHER_PATH,
            }
        )
    )


def _relevant_module_paths_at_commit(git_commit: str) -> tuple[str, ...]:
    root = _git_root()
    try:
        completed = subprocess.run(
            ["git", "-C", os.fspath(root), "ls-tree", "-r", "-z", "--name-only", git_commit],
            check=False,
            capture_output=True,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError):
        raise _error("production_identity_invalid") from None
    if completed.returncode != 0:
        raise _error("production_identity_invalid")
    paths = [item.decode("utf-8") for item in completed.stdout.split(b"\0") if item]
    selected = _selected_relevant_module_paths(paths)
    if not selected:
        raise _error("production_identity_invalid")
    return selected


def _relevant_tracked_worktree_paths() -> tuple[str, ...]:
    if _PRODUCTION_RELEVANT_WORKTREE_PATHS is not None and (
        _FRESH_PRODUCTION_WORKER or _PRODUCTION_PROCESS_CONTAINMENT is not None
    ):
        return _PRODUCTION_RELEVANT_WORKTREE_PATHS
    if _PRODUCTION_PROCESS_CONTAINMENT is not None:
        raise _error("production_identity_invalid")
    root = _git_root()
    try:
        completed = subprocess.run(
            ["git", "-C", os.fspath(root), "ls-files", "-z"],
            check=False,
            capture_output=True,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError):
        raise _error("production_identity_invalid") from None
    if completed.returncode != 0:
        raise _error("production_identity_invalid")
    paths = [item.decode("utf-8") for item in completed.stdout.split(b"\0") if item]
    return _selected_relevant_module_paths(paths)


def _relevant_module_sha256_at_commit(git_commit: str) -> dict[str, str]:
    return {
        path: _hash_bytes(_git_blob_bytes(git_commit, path)) for path in _relevant_module_paths_at_commit(git_commit)
    }


def _extraction_execution_sha256_at_commit(git_commit: str) -> str:
    names = ("engine.py", "engines.py", "extraction.py", "records.py")
    return _canonical_hash({name: _hash_bytes(_git_blob_bytes(git_commit, f"src/nerb/{name}")) for name in names})


def _production_core_source_paths() -> dict[str, Path]:
    root = Path(__file__).parent
    return {name.removesuffix(".py"): root / name for name in _PRODUCTION_CORE_SOURCE_NAMES}


def _core_source_sha256() -> dict[str, str]:
    try:
        return {name: _hash_bytes(path.read_bytes()) for name, path in _production_core_source_paths().items()}
    except OSError:
        raise _error("production_identity_invalid") from None


def _repository_tree_sha256(git_commit: str) -> str:
    root = _git_root()
    try:
        completed = subprocess.run(
            ["git", "-C", os.fspath(root), "ls-tree", "-r", "-z", "--full-tree", git_commit],
            check=False,
            capture_output=True,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError):
        raise _error("production_identity_invalid") from None
    if completed.returncode != 0 or not completed.stdout:
        raise _error("production_identity_invalid")
    return _hash_bytes(completed.stdout)


def _relevant_module_sha256() -> dict[str, str]:
    root = _git_root()
    result: dict[str, str] = {}
    try:
        for relative in _relevant_tracked_worktree_paths():
            path = root / relative
            try:
                info = path.lstat()
            except FileNotFoundError:
                raise OSError from None
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise OSError
            result[relative] = _hash_bytes(path.read_bytes())
    except (OSError, RuntimeError, ValueError):
        raise _error("production_identity_invalid") from None
    if not result:
        raise _error("production_identity_invalid")
    return result


def _native_extension_sha256() -> str:
    try:
        module = importlib.import_module("nerb._engine")
        origin = getattr(module, "__file__", None)
        if not isinstance(origin, str):
            raise OSError
        return _hash_bytes(Path(origin).read_bytes())
    except (ImportError, OSError, TypeError, ValueError):
        raise _error("production_identity_invalid") from None


def _normalized_native_source_bytes(payload: bytes) -> bytes:
    normalized = payload.replace(b"\r\n", b"\n")
    if b"\r" in normalized:
        raise _error("production_identity_invalid")
    return normalized


def _native_build_source_hash(payloads: Mapping[str, bytes]) -> str:
    if set(payloads) != set(_NATIVE_BUILD_SOURCE_FILES):
        raise _error("production_identity_invalid")
    digest = hashlib.sha256(_NATIVE_BUILD_SOURCE_DOMAIN)
    for relative in _NATIVE_BUILD_SOURCE_FILES:
        path_bytes = relative.encode("utf-8")
        payload = _normalized_native_source_bytes(payloads[relative])
        digest.update(len(path_bytes).to_bytes(8, "big"))
        digest.update(path_bytes)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return "sha256:" + digest.hexdigest()


def _native_build_source_sha256() -> str:
    root = _git_root() / "rust"
    try:
        payloads = {relative: (root / relative).read_bytes() for relative in _NATIVE_BUILD_SOURCE_FILES}
    except OSError:
        raise _error("production_identity_invalid") from None
    return _native_build_source_hash(payloads)


def _native_build_source_sha256_at_commit(git_commit: str) -> str:
    return _native_build_source_hash(
        {relative: _git_blob_bytes(git_commit, f"rust/{relative}") for relative in _NATIVE_BUILD_SOURCE_FILES}
    )


def _native_extension_embedded_build_source_sha256() -> str | None:
    try:
        module = importlib.import_module("nerb._engine")
    except ImportError:
        raise _error("production_identity_invalid") from None
    value = getattr(module, "BUILD_SOURCE_SHA256", None)
    if value is None:
        return None
    if not isinstance(value, str) or _HASH_RE.fullmatch(value) is None:
        raise _error("production_identity_invalid")
    return value


def _extraction_execution_sha256() -> str:
    root = Path(__file__).parent
    names = ("engine.py", "engines.py", "extraction.py", "records.py")
    try:
        return _canonical_hash({name: _hash_bytes((root / name).read_bytes()) for name in names})
    except OSError:
        raise _error("production_identity_invalid") from None


def _normalized_distribution_name(value: str) -> str:
    normalized = re.sub(r"[-_.]+", "-", value).lower()
    if not normalized or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,255}", normalized):
        raise _error("production_identity_invalid")
    return normalized


def _installed_distribution_inventory() -> tuple[int, str]:
    inventory: dict[str, str] = {}
    try:
        distributions = tuple(importlib_metadata.distributions())
    except Exception:
        raise _error("production_identity_invalid") from None
    if not 1 <= len(distributions) <= MAX_READER_DISTRIBUTIONS:
        raise _error("production_identity_invalid")
    for distribution in distributions:
        try:
            raw_name = distribution.metadata["Name"]
        except (KeyError, TypeError):
            raise _error("production_identity_invalid") from None
        version = distribution.version
        if (
            not isinstance(raw_name, str)
            or not isinstance(version, str)
            or not version
            or len(version.encode("utf-8")) > 256
            or any(ord(character) < 32 for character in version)
        ):
            raise _error("production_identity_invalid")
        name = _normalized_distribution_name(raw_name)
        if name in inventory:
            raise _error("production_identity_invalid")
        inventory[name] = version
    ordered = [{"name": name, "version": inventory[name]} for name in sorted(inventory)]
    return len(ordered), _canonical_hash({"schema": "python_distribution_inventory", "packages": ordered})


def _hash_regular_distribution_file(path: Path, *, maximum: int) -> tuple[int, str]:
    descriptor: int | None = None
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_size < 0
            or before.st_size > maximum
        ):
            raise OSError
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise OSError
        digest = hashlib.sha256()
        remaining = maximum + 1
        size = 0
        while remaining > 0:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        current = path.lstat()
    except OSError:
        raise _error("production_identity_invalid") from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if (
        size != before.st_size
        or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        != (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns, current.st_ctime_ns)
    ):
        raise _error("production_identity_invalid")
    return size, "sha256:" + digest.hexdigest()


@dataclass(frozen=True, slots=True)
class _ReaderDistributionProvenance:
    version: str | None
    file_count: int
    total_bytes: int
    sha256: str
    package_init: Path | None


def _reader_distribution_provenance(
    distribution_name: str,
    import_name: str,
    package_init_relative: str,
) -> _ReaderDistributionProvenance:
    expected_name = _normalized_distribution_name(distribution_name)
    try:
        distribution = importlib_metadata.distribution(distribution_name)
    except importlib_metadata.PackageNotFoundError:
        return _ReaderDistributionProvenance(
            None,
            0,
            0,
            _hash_bytes(f"{expected_name}-distribution-unavailable".encode("ascii")),
            None,
        )
    try:
        raw_name = distribution.metadata["Name"]
    except (KeyError, TypeError):
        raise _error("production_identity_invalid") from None
    version = distribution.version
    if not isinstance(raw_name, str) or _normalized_distribution_name(raw_name) != expected_name:
        raise _error("production_identity_invalid")
    if not isinstance(version, str) or not version:
        raise _error("production_identity_invalid")
    raw_files = distribution.files
    if raw_files is None:
        raise _error("production_identity_invalid")
    files: list[dict[str, Any]] = []
    seen: set[str] = set()
    total_bytes = 0
    package_init: Path | None = None
    for raw_file in raw_files:
        relative = str(raw_file).replace("\\", "/")
        parts = tuple(part for part in relative.split("/") if part not in {"", "."})
        if relative.endswith(".pyc") or "__pycache__" in parts or ".." in parts:
            continue
        if not parts or relative.startswith("/") or relative in seen:
            raise _error("production_identity_invalid")
        seen.add(relative)
        path = Path(str(distribution.locate_file(raw_file)))
        if relative == package_init_relative:
            package_init = path
        size, sha256 = _hash_regular_distribution_file(path, maximum=MAX_DATASETS_DISTRIBUTION_BYTES)
        total_bytes += size
        if total_bytes > MAX_DATASETS_DISTRIBUTION_BYTES:
            raise _error("production_identity_invalid")
        files.append({"path": relative, "bytes": size, "sha256": sha256})
        if len(files) > MAX_DATASETS_DISTRIBUTION_FILES:
            raise _error("production_identity_invalid")
    files.sort(key=lambda item: cast(str, item["path"]))
    if (
        not files
        or package_init is None
        or not any(str(item["path"]).endswith(".dist-info/METADATA") for item in files)
    ):
        raise _error("production_identity_invalid")
    try:
        specification = importlib_util.find_spec(import_name)
        origin = None if specification is None else specification.origin
        if not isinstance(origin, str) or not os.path.samefile(origin, package_init):
            raise OSError
    except (AttributeError, ImportError, OSError, TypeError, ValueError):
        raise _error("production_identity_invalid") from None
    return _ReaderDistributionProvenance(
        version=version,
        file_count=len(files),
        total_bytes=total_bytes,
        sha256=_canonical_hash(
            {
                "schema": "reader_distribution_file_inventory",
                "name": expected_name,
                "version": version,
                "files": files,
            }
        ),
        package_init=package_init,
    )


def _datasets_distribution_provenance() -> _ReaderDistributionProvenance:
    return _reader_distribution_provenance("datasets", "datasets", "datasets/__init__.py")


def _datasets_distribution_identity() -> tuple[str | None, int, int, str]:
    provenance = _datasets_distribution_provenance()
    return provenance.version, provenance.file_count, provenance.total_bytes, provenance.sha256


def _critical_reader_distribution_identity(
    datasets_provenance: _ReaderDistributionProvenance | None = None,
) -> tuple[int, int, int, dict[str, str | None], str]:
    entries: list[dict[str, Any]] = []
    available_count = 0
    file_count = 0
    total_bytes = 0
    versions: dict[str, str | None] = {}
    for distribution_name, import_name, package_init_relative, expected_version in _CRITICAL_READER_DISTRIBUTIONS:
        provenance = (
            datasets_provenance
            if distribution_name == "datasets" and datasets_provenance is not None
            else _reader_distribution_provenance(distribution_name, import_name, package_init_relative)
        )
        available = provenance.version is not None
        available_count += int(available)
        file_count += provenance.file_count
        total_bytes += provenance.total_bytes
        versions[distribution_name] = provenance.version
        entries.append(
            {
                "name": distribution_name,
                "version": provenance.version,
                "expected_version": expected_version,
                "file_count": provenance.file_count,
                "total_bytes": provenance.total_bytes,
                "distribution_sha256": provenance.sha256,
                "available": available,
            }
        )
    return (
        available_count,
        file_count,
        total_bytes,
        versions,
        _canonical_hash({"schema": "critical_reader_distribution_inventory", "distributions": entries}),
    )


def _reader_environment_identity() -> dict[str, Any]:
    distribution_count, inventory_sha256 = _installed_distribution_inventory()
    datasets_provenance = _datasets_distribution_provenance()
    critical_count, critical_file_count, critical_total_bytes, critical_versions, critical_sha256 = (
        _critical_reader_distribution_identity(datasets_provenance)
    )
    return {
        "installed_distribution_count": distribution_count,
        "installed_distribution_inventory_sha256": inventory_sha256,
        "datasets_version": datasets_provenance.version,
        "datasets_file_count": datasets_provenance.file_count,
        "datasets_total_bytes": datasets_provenance.total_bytes,
        "datasets_distribution_sha256": datasets_provenance.sha256,
        "critical_reader_distribution_count": critical_count,
        "critical_reader_file_count": critical_file_count,
        "critical_reader_total_bytes": critical_total_bytes,
        "critical_reader_versions": critical_versions,
        "critical_reader_distribution_sha256": critical_sha256,
    }


def _reader_phase_environment_policy_sha256() -> str:
    return _canonical_hash(
        {
            "schema": "enron_capacity_reader_phase_environment",
            "path_environment_keys": sorted(_PHASE_RUNTIME_PATH_ENVIRONMENT_KEYS),
            "policy_environment": _READER_POLICY_ENVIRONMENT,
            "removed_credential_environment_keys": sorted(_READER_CREDENTIAL_ENVIRONMENT_KEYS),
            "effective_path_labels": list(_READER_EFFECTIVE_PATH_LABELS),
            "cache_lock_adapter_sha256": _reader_cache_lock_adapter_sha256(),
            "network_activity_adapter_sha256": _reader_network_activity_adapter_sha256(),
        }
    )


def _reader_cache_lock_adapter_sha256() -> str:
    return _canonical_hash(
        {
            "schema": "enron_capacity_reader_cache_lock_adapter",
            "upstream_binding": "huggingface_hub.utils._fixes.FileLock",
            "fallback_binding": "huggingface_hub.utils._fixes.SoftFileLock",
            "upstream_requested_mode": _READER_UPSTREAM_CACHE_LOCK_MODE,
            "effective_mode": _READER_OWNER_ONLY_CACHE_LOCK_MODE,
            "phase_owned_paths_only": True,
            "scope": "remote_preparation_source_consumption",
            "exact_binding_restoration_required": True,
        }
    )


def _reader_network_activity_adapter_sha256() -> str:
    return _canonical_hash(
        {
            "schema": "enron_capacity_reader_network_activity_adapter",
            "upstream_factory": "huggingface_hub.utils._http.default_client_factory",
            "activity_events": ["response_headers", "nonempty_response_chunks"],
            "same_thread": True,
            "request_metadata_captured": False,
            "response_metadata_captured": False,
            "response_bytes_captured": False,
            "tracked_stream_close_success_required": True,
            "tracked_client_close_success_required": True,
            "successful_stream_close_drops_underlying_reference": True,
            "client_descriptor_and_hooks_restored": True,
            "adapter_reference_cycles_cleared": True,
            "any_close_exception_is_terminal": True,
            "cleanup_precedes_factory_restoration": True,
            "exact_factory_and_session_restoration_required": True,
        }
    )


def _current_process_umask() -> int:
    current = os.umask(0o077)
    os.umask(current)
    return current


def _set_production_worker_umask() -> None:
    os.umask(0o077)


def _path_is_absent(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return True
    except OSError:
        raise _CapacityAbort("production_identity_invalid") from None
    return False


def _reader_owned_roots(environment: Mapping[str, str]) -> tuple[Path, ...]:
    roots = {
        Path(environment[key])
        for key in (
            "HOME",
            "TMPDIR",
            "HF_HOME",
            "HF_DATASETS_CACHE",
            "HF_MODULES_CACHE",
            "HF_DATASETS_DOWNLOADED_DATASETS_PATH",
            "HF_DATASETS_EXTRACTED_DATASETS_PATH",
            "HF_HUB_CACHE",
            "HF_ASSETS_CACHE",
            "HF_XET_CACHE",
            "TRANSFORMERS_CACHE",
            "XDG_CACHE_HOME",
        )
    }
    roots.add(Path(environment["HF_TOKEN_PATH"]).parent)
    return tuple(sorted(roots, key=lambda path: os.fspath(path)))


@dataclass(frozen=True, slots=True)
class _ReaderCacheLockAdapter:
    fixes_module: Any
    original_file_lock: Any
    original_soft_file_lock: Any
    file_lock_factory: Callable[..., Any]
    soft_file_lock_factory: Callable[..., Any]
    owned_roots: tuple[Path, ...]


def _reader_cache_lock_path_is_owned(value: object, roots: Sequence[Path]) -> bool:
    try:
        if not isinstance(value, (str, Path)):
            return False
        candidate = Path(value)
        return (
            candidate.is_absolute()
            and os.pardir not in candidate.parts
            and any(_is_within(candidate, root) for root in roots)
        )
    except (OSError, TypeError, ValueError):
        return False


def _reader_cache_lock_adapter_is_active(environment: Mapping[str, str]) -> bool:
    state = _ACTIVE_READER_CACHE_LOCK_ADAPTER
    if state is None:
        return False
    try:
        fixes = importlib.import_module("huggingface_hub.utils._fixes")
        hub_utils = importlib.import_module("huggingface_hub.utils")
        file_download = importlib.import_module("huggingface_hub.file_download")
        filelock = importlib.import_module("filelock")
        weak_file_lock = getattr(fixes, "WeakFileLock")
        weak_file_lock_body = getattr(weak_file_lock, "__wrapped__")
        weak_globals = getattr(weak_file_lock_body, "__globals__")
        expected_roots = _reader_owned_roots(environment)
    except (AttributeError, ImportError, OSError, TypeError, ValueError):
        return False
    return (
        state.fixes_module is fixes
        and state.original_file_lock is getattr(filelock, "FileLock", None)
        and state.original_soft_file_lock is getattr(filelock, "SoftFileLock", None)
        and state.owned_roots == expected_roots
        and getattr(fixes, "FileLock", None) is state.file_lock_factory
        and getattr(fixes, "SoftFileLock", None) is state.soft_file_lock_factory
        and weak_globals.get("FileLock") is state.file_lock_factory
        and weak_globals.get("SoftFileLock") is state.soft_file_lock_factory
        and getattr(hub_utils, "WeakFileLock", None) is weak_file_lock
        and getattr(file_download, "WeakFileLock", None) is weak_file_lock
    )


@contextmanager
def _owner_only_reader_cache_locks(environment: Mapping[str, str]) -> Iterator[None]:
    """Preserve Hub lock semantics while creating phase-owned locks as 0600."""

    global _ACTIVE_READER_CACHE_LOCK_ADAPTER
    if _ACTIVE_READER_CACHE_LOCK_ADAPTER is not None or set(environment) != _PHASE_RUNTIME_PATH_ENVIRONMENT_KEYS:
        raise _CapacityAbort("production_identity_invalid")
    try:
        fixes = importlib.import_module("huggingface_hub.utils._fixes")
        hub_utils = importlib.import_module("huggingface_hub.utils")
        file_download = importlib.import_module("huggingface_hub.file_download")
        filelock = importlib.import_module("filelock")
        original_file_lock = getattr(fixes, "FileLock")
        original_soft_file_lock = getattr(fixes, "SoftFileLock")
        weak_file_lock = getattr(fixes, "WeakFileLock")
        weak_file_lock_body = getattr(weak_file_lock, "__wrapped__")
        weak_globals = getattr(weak_file_lock_body, "__globals__")
        owned_roots = _reader_owned_roots(environment)
    except (AttributeError, ImportError, OSError, TypeError, ValueError):
        raise _CapacityAbort("production_identity_invalid") from None
    if (
        original_file_lock is not getattr(filelock, "FileLock", None)
        or original_soft_file_lock is not getattr(filelock, "SoftFileLock", None)
        or weak_globals.get("FileLock") is not original_file_lock
        or weak_globals.get("SoftFileLock") is not original_soft_file_lock
        or getattr(hub_utils, "WeakFileLock", None) is not weak_file_lock
        or getattr(file_download, "WeakFileLock", None) is not weak_file_lock
        or not owned_roots
    ):
        raise _CapacityAbort("production_identity_invalid")

    def owner_only_file_lock(lock_file: object, *args: object, **kwargs: object) -> Any:
        if (
            args
            or set(kwargs) != {"timeout", "mode"}
            or kwargs.get("mode") != _READER_UPSTREAM_CACHE_LOCK_MODE
            or not _reader_cache_lock_path_is_owned(lock_file, owned_roots)
        ):
            raise _CapacityAbort("production_identity_invalid")
        return original_file_lock(
            lock_file,
            timeout=kwargs["timeout"],
            mode=_READER_OWNER_ONLY_CACHE_LOCK_MODE,
        )

    def owner_only_soft_file_lock(lock_file: object, *args: object, **kwargs: object) -> Any:
        if args or set(kwargs) != {"timeout"} or not _reader_cache_lock_path_is_owned(lock_file, owned_roots):
            raise _CapacityAbort("production_identity_invalid")
        return original_soft_file_lock(
            lock_file,
            timeout=kwargs["timeout"],
            mode=_READER_OWNER_ONLY_CACHE_LOCK_MODE,
        )

    state = _ReaderCacheLockAdapter(
        fixes_module=fixes,
        original_file_lock=original_file_lock,
        original_soft_file_lock=original_soft_file_lock,
        file_lock_factory=owner_only_file_lock,
        soft_file_lock_factory=owner_only_soft_file_lock,
        owned_roots=owned_roots,
    )
    setattr(fixes, "FileLock", owner_only_file_lock)
    setattr(fixes, "SoftFileLock", owner_only_soft_file_lock)
    _ACTIVE_READER_CACHE_LOCK_ADAPTER = state
    if not _reader_cache_lock_adapter_is_active(environment):
        setattr(fixes, "FileLock", original_file_lock)
        setattr(fixes, "SoftFileLock", original_soft_file_lock)
        _ACTIVE_READER_CACHE_LOCK_ADAPTER = None
        raise _CapacityAbort("production_identity_invalid")
    try:
        yield
    finally:
        drifted = not _reader_cache_lock_adapter_is_active(environment)
        setattr(fixes, "FileLock", original_file_lock)
        setattr(fixes, "SoftFileLock", original_soft_file_lock)
        _ACTIVE_READER_CACHE_LOCK_ADAPTER = None
        if (
            drifted
            or getattr(fixes, "FileLock", None) is not original_file_lock
            or getattr(fixes, "SoftFileLock", None) is not original_soft_file_lock
            or weak_globals.get("FileLock") is not original_file_lock
            or weak_globals.get("SoftFileLock") is not original_soft_file_lock
        ):
            raise _CapacityAbort("production_identity_invalid")


@dataclass(slots=True)
class _ReaderNetworkClientClose:
    client: Any
    original_close: Callable[[], None]
    original_close_function: Callable[..., Any]
    close_wrapper: Callable[[], None] | None = None
    close_succeeded: bool = False
    close_failed: bool = False


@dataclass(slots=True)
class _ReaderNetworkActivityAdapter:
    http_module: Any
    original_factory: Callable[[], Any]
    client_factory: Callable[[], Any]
    response_hook: Callable[[Any], None]
    clients: list[Any]
    client_closures: list[_ReaderNetworkClientClose]
    streams: list[Any]
    activity_observed: bool = False
    cleanup_failed: bool = False


def _reader_activity_stream_init(
    wrapper: Any,
    stream: Any,
    pulse: Callable[[], None],
    mark_cleanup_failed: Callable[[], None],
) -> None:
    wrapper._stream = stream
    wrapper._pulse = pulse
    wrapper._mark_cleanup_failed = mark_cleanup_failed
    wrapper._closed = False
    wrapper._close_failed = False


def _reader_activity_stream_iter(wrapper: Any) -> Iterator[bytes]:
    stream = wrapper._stream
    if stream is None:
        return
    for chunk in stream:
        if chunk:
            pulse = wrapper._pulse
            if not callable(pulse):
                raise _CapacityAbort("production_identity_invalid")
            pulse()
        yield chunk


def _reader_activity_stream_close(wrapper: Any) -> None:
    if wrapper._closed:
        return
    stream = wrapper._stream
    if stream is None:
        raise _CapacityAbort("production_identity_invalid")
    try:
        stream.close()
    except BaseException:
        wrapper._close_failed = True
        mark_cleanup_failed = wrapper._mark_cleanup_failed
        if callable(mark_cleanup_failed):
            mark_cleanup_failed()
        raise
    wrapper._closed = True
    wrapper._stream = None
    wrapper._pulse = None
    wrapper._mark_cleanup_failed = None


def _inactive_reader_response_hook(_response: Any) -> None:
    raise _CapacityAbort("production_identity_invalid")


def _reader_network_activity_adapter_is_active() -> bool:
    state = _ACTIVE_READER_NETWORK_ACTIVITY_ADAPTER
    if state is None:
        return False
    try:
        http_module = importlib.import_module("huggingface_hub.utils._http")
        global_client = getattr(http_module, "_GLOBAL_CLIENT")
    except (AttributeError, ImportError):
        return False
    if len(state.clients) != len(state.client_closures):
        return False
    clients_valid = True
    for client, closure in zip(state.clients, state.client_closures, strict=True):
        hooks = getattr(client, "event_hooks", None)
        if (
            closure.client is not client
            or closure.close_wrapper is None
            or getattr(client, "close", None) is not closure.close_wrapper
            or closure.close_failed
            or not isinstance(hooks, dict)
            or set(hooks) != {"request", "response"}
            or hooks["request"] != [getattr(http_module, "hf_request_event_hook", None)]
            or len(hooks["response"]) != 1
            or hooks["response"][0] is not state.response_hook
        ):
            clients_valid = False
            break
        is_closed = bool(getattr(client, "is_closed", True))
        if client is global_client:
            clients_valid = not is_closed and not closure.close_succeeded
        else:
            clients_valid = is_closed and closure.close_succeeded
        if not clients_valid:
            break
    return (
        not state.cleanup_failed
        and state.http_module is http_module
        and getattr(http_module, "_GLOBAL_CLIENT_FACTORY", None) is state.client_factory
        and (global_client is None or any(global_client is client for client in state.clients))
        and all(not bool(getattr(stream, "_close_failed", True)) for stream in state.streams)
        and clients_valid
    )


def _reader_network_activity_observed() -> bool:
    state = _ACTIVE_READER_NETWORK_ACTIVITY_ADAPTER
    return state is not None and state.activity_observed


@contextmanager
def _reader_network_activity(activity: Callable[[], None]) -> Iterator[None]:
    """Translate exact Hub response/chunk I/O into payload-free liveness."""

    global _ACTIVE_READER_NETWORK_ACTIVITY_ADAPTER
    if _ACTIVE_READER_NETWORK_ACTIVITY_ADAPTER is not None or not callable(activity):
        raise _CapacityAbort("production_identity_invalid")
    try:
        hub = importlib.import_module("huggingface_hub")
        http_module = importlib.import_module("huggingface_hub.utils._http")
        httpx = importlib.import_module("httpx")
        original_factory = getattr(http_module, "_GLOBAL_CLIENT_FACTORY")
        default_factory = getattr(http_module, "default_client_factory")
        set_client_factory = getattr(hub, "set_client_factory")
        sync_byte_stream = getattr(httpx, "SyncByteStream")
        client_type = getattr(httpx, "Client")
    except (AttributeError, ImportError, TypeError):
        raise _CapacityAbort("production_identity_invalid") from None
    if (
        original_factory is not default_factory
        or getattr(http_module, "_GLOBAL_CLIENT", None) is not None
        or set_client_factory is not getattr(http_module, "set_client_factory", None)
        or not isinstance(sync_byte_stream, type)
        or not isinstance(client_type, type)
    ):
        raise _CapacityAbort("production_identity_invalid")

    clients: list[Any] = []
    client_closures: list[_ReaderNetworkClientClose] = []
    streams: list[Any] = []
    last_created_client: Any | None = None
    state: _ReaderNetworkActivityAdapter

    def pulse() -> None:
        state.activity_observed = True
        activity()

    def mark_cleanup_failed() -> None:
        state.cleanup_failed = True

    ActivityByteStream = type(
        "_CapacityActivityByteStream",
        (sync_byte_stream,),
        {
            "__init__": _reader_activity_stream_init,
            "__iter__": _reader_activity_stream_iter,
            "close": _reader_activity_stream_close,
        },
    )

    def response_activity(response: Any) -> None:
        stream = getattr(response, "stream", None)
        if not isinstance(stream, sync_byte_stream) or isinstance(stream, ActivityByteStream):
            raise _CapacityAbort("production_identity_invalid")
        wrapped = ActivityByteStream(stream, pulse, mark_cleanup_failed)
        streams.append(wrapped)
        response.stream = wrapped
        try:
            pulse()
        except BaseException:
            try:
                response.close()
            except BaseException:
                state.cleanup_failed = True
            raise

    def client_factory() -> Any:
        nonlocal last_created_client
        client: Any | None = None
        try:
            client = original_factory()
            last_created_client = client
            clients.append(client)
            if isinstance(client, client_type):
                client_namespace = vars(client)
                original_close = getattr(client, "close", None)
                original_close_function = getattr(original_close, "__func__", None)
                if (
                    "close" in client_namespace
                    or not callable(original_close)
                    or getattr(original_close, "__self__", None) is not client
                    or not callable(original_close_function)
                ):
                    raise _CapacityAbort("production_identity_invalid")
                closure = _ReaderNetworkClientClose(
                    client=client,
                    original_close=original_close,
                    original_close_function=original_close_function,
                )
                client_closures.append(closure)

                def tracked_close(*, current: _ReaderNetworkClientClose = closure) -> None:
                    try:
                        current.original_close()
                    except BaseException:
                        current.close_failed = True
                        state.cleanup_failed = True
                        raise
                    current.close_succeeded = True

                closure.close_wrapper = tracked_close
                setattr(client, "close", tracked_close)
            hooks = getattr(client, "event_hooks", None)
            if (
                not isinstance(client, client_type)
                or not isinstance(hooks, dict)
                or set(hooks) != {"request", "response"}
                or len(hooks["request"]) != 1
                or hooks["request"][0] is not getattr(http_module, "hf_request_event_hook", None)
                or hooks["response"]
                or bool(getattr(client, "is_closed", True))
            ):
                raise _CapacityAbort("production_identity_invalid")
            hooks["response"].append(response_activity)
            return client
        except BaseException:
            raise

    state = _ReaderNetworkActivityAdapter(
        http_module=http_module,
        original_factory=original_factory,
        client_factory=client_factory,
        response_hook=response_activity,
        clients=clients,
        client_closures=client_closures,
        streams=streams,
    )
    install_attempted = False
    state_published = False
    primary_error: BaseException | None = None
    deferred_control: KeyboardInterrupt | SystemExit | _CapacityAbort | None = None
    try:
        install_attempted = True
        set_client_factory(client_factory)
        _ACTIVE_READER_NETWORK_ACTIVITY_ADAPTER = state
        state_published = True
        if not _reader_network_activity_adapter_is_active():
            raise _CapacityAbort("production_identity_invalid")
        yield
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        drifted = state_published and not _reader_network_activity_adapter_is_active()
        _ACTIVE_READER_NETWORK_ACTIVITY_ADAPTER = None
        cleanup_failed = drifted or state.cleanup_failed

        for stream in streams:
            if not bool(getattr(stream, "_closed", False)):
                for _attempt in range(3):
                    try:
                        stream.close()
                    except BaseException:
                        cleanup_failed = True
                        continue
                    break
            if bool(getattr(stream, "_close_failed", False)) or not bool(getattr(stream, "_closed", False)):
                cleanup_failed = True

        tracked_clients = [*clients]
        if last_created_client is not None:
            tracked_clients.append(last_created_client)
        current_global_client = getattr(http_module, "_GLOBAL_CLIENT", None)
        if current_global_client is not None:
            tracked_clients.append(current_global_client)
        unique_clients = tuple({id(client): client for client in tracked_clients}.values())
        closure_by_client = {id(closure.client): closure for closure in client_closures}
        for client in unique_clients:
            closure = closure_by_client.get(id(client))
            if closure is None or closure.client is not client or closure.close_wrapper is None:
                cleanup_failed = True
                close = getattr(client, "close", None)
                if callable(close):
                    for _attempt in range(3):
                        try:
                            close()
                        except BaseException:
                            cleanup_failed = True
                            continue
                        break
                continue
            hooks = getattr(client, "event_hooks", None)
            if (
                not isinstance(hooks, dict)
                or set(hooks) != {"request", "response"}
                or hooks.get("request") != [getattr(http_module, "hf_request_event_hook", None)]
                or hooks.get("response") != [state.response_hook]
            ):
                cleanup_failed = True
            if isinstance(hooks, dict):
                hooks.clear()
                hooks.update(
                    {
                        "request": [getattr(http_module, "hf_request_event_hook", None)],
                        "response": [],
                    }
                )
            if getattr(client, "close", None) is not closure.close_wrapper:
                cleanup_failed = True
            if not closure.close_succeeded:
                for _attempt in range(3):
                    try:
                        closure.close_wrapper()
                    except BaseException:
                        cleanup_failed = True
                        continue
                    break
            if closure.close_failed or not closure.close_succeeded or not bool(getattr(client, "is_closed", False)):
                cleanup_failed = True
            try:
                delattr(client, "close")
            except BaseException:
                cleanup_failed = True
            restored_close = getattr(client, "close", None)
            if (
                "close" in vars(client)
                or getattr(restored_close, "__self__", None) is not client
                or getattr(restored_close, "__func__", None) is not closure.original_close_function
            ):
                cleanup_failed = True

        if install_attempted:
            restored = False
            for _attempt in range(3):
                if (
                    getattr(http_module, "_GLOBAL_CLIENT_FACTORY", None) is original_factory
                    and getattr(http_module, "_GLOBAL_CLIENT", None) is None
                ):
                    restored = True
                    break
                try:
                    set_client_factory(original_factory)
                except (KeyboardInterrupt, SystemExit, _CapacityAbort) as exc:
                    if deferred_control is None:
                        deferred_control = exc
                except BaseException:
                    cleanup_failed = True
                    continue
            restored = (
                getattr(http_module, "_GLOBAL_CLIENT_FACTORY", None) is original_factory
                and getattr(http_module, "_GLOBAL_CLIENT", None) is None
            )
            cleanup_failed = cleanup_failed or not restored

        if (
            getattr(http_module, "_GLOBAL_CLIENT_FACTORY", None) is not original_factory
            or getattr(http_module, "_GLOBAL_CLIENT", None) is not None
            or any(
                closure.close_failed
                or not closure.close_succeeded
                or not bool(getattr(closure.client, "is_closed", False))
                for closure in client_closures
            )
            or any(
                bool(getattr(stream, "_close_failed", False)) or not bool(getattr(stream, "_closed", False))
                for stream in streams
            )
            or any(
                "close" in vars(closure.client)
                or getattr(getattr(closure.client, "close", None), "__self__", None) is not closure.client
                or getattr(getattr(closure.client, "close", None), "__func__", None)
                is not closure.original_close_function
                or getattr(closure.client, "event_hooks", {}).get("response") != []
                or getattr(closure.client, "event_hooks", {}).get("request")
                != [getattr(http_module, "hf_request_event_hook", None)]
                for closure in client_closures
            )
        ):
            cleanup_failed = True
        for closure in client_closures:
            closure.close_wrapper = None
        clients.clear()
        client_closures.clear()
        streams.clear()
        state.client_factory = original_factory
        state.response_hook = _inactive_reader_response_hook
        if cleanup_failed:
            raise _CapacityAbort("production_identity_invalid")
        if primary_error is None and deferred_control is not None:
            raise deferred_control


def _expected_reader_effective_paths(environment: Mapping[str, str]) -> dict[str, Path]:
    hf_home = Path(environment["HF_HOME"])
    token_path = Path(environment["HF_TOKEN_PATH"])
    return {
        "datasets_xdg_cache_home": Path(environment["XDG_CACHE_HOME"]),
        "datasets_hf_cache_home": hf_home,
        "datasets_cache": Path(environment["HF_DATASETS_CACHE"]),
        "datasets_modules_cache": Path(environment["HF_MODULES_CACHE"]),
        "datasets_downloads": Path(environment["HF_DATASETS_DOWNLOADED_DATASETS_PATH"]),
        "datasets_extracted": Path(environment["HF_DATASETS_EXTRACTED_DATASETS_PATH"]),
        "hub_home": hf_home,
        "hub_huggingface_cache": Path(environment["HUGGINGFACE_HUB_CACHE"]),
        "hub_huggingface_assets_cache": Path(environment["HUGGINGFACE_ASSETS_CACHE"]),
        "hub_cache": Path(environment["HF_HUB_CACHE"]),
        "hub_assets_cache": Path(environment["HF_ASSETS_CACHE"]),
        "hub_update_marker": hf_home / ".check_for_update_done",
        "hub_agent_harnesses": hf_home / ".agent_harnesses.json",
        "hub_token": token_path,
        "hub_stored_tokens": token_path.parent / "stored_tokens",
        "hub_xet_cache": Path(environment["HF_XET_CACHE"]),
    }


def _reader_isolation_snapshot(
    context: EnronCapacityPhaseContext,
    datasets_module: Any,
    *,
    stage: str,
) -> dict[str, Any]:
    if stage not in {"before_source_read", "after_source_read"}:
        raise _CapacityAbort("production_identity_invalid")
    environment = context.runtime_environment
    if set(environment) != _PHASE_RUNTIME_PATH_ENVIRONMENT_KEYS:
        raise _CapacityAbort("production_identity_invalid")
    if any(os.environ.get(key) != value for key, value in environment.items()):
        raise _CapacityAbort("production_identity_invalid")
    if any(os.environ.get(key) != value for key, value in _READER_POLICY_ENVIRONMENT.items()):
        raise _CapacityAbort("production_identity_invalid")
    if any(key in os.environ for key in _READER_CREDENTIAL_ENVIRONMENT_KEYS):
        raise _CapacityAbort("production_identity_invalid")

    provenance = _datasets_distribution_provenance()
    origin = getattr(datasets_module, "__file__", None)
    if (
        provenance.version != _PINNED_DATASETS_VERSION
        or provenance.package_init is None
        or not isinstance(origin, str)
        or not os.path.samefile(origin, provenance.package_init)
        or getattr(datasets_module, "__version__", None) != provenance.version
        or not callable(getattr(datasets_module, "load_dataset", None))
    ):
        raise _CapacityAbort("production_identity_invalid")

    try:
        for distribution_name, import_name, package_init_relative, expected_version in _CRITICAL_READER_DISTRIBUTIONS:
            module = importlib.import_module(import_name)
            module_provenance = _reader_distribution_provenance(
                distribution_name,
                import_name,
                package_init_relative,
            )
            module_origin = getattr(module, "__file__", None)
            if (
                module_provenance.version != expected_version
                or module_provenance.package_init is None
                or not isinstance(module_origin, str)
                or not os.path.samefile(module_origin, module_provenance.package_init)
                or getattr(module, "__version__", None) != expected_version
            ):
                raise OSError
        datasets_config = importlib.import_module("datasets.config")
        hub_constants = importlib.import_module("huggingface_hub.constants")
        hub_utils = importlib.import_module("huggingface_hub.utils")
        effective = {
            "datasets_xdg_cache_home": Path(datasets_config.XDG_CACHE_HOME),
            "datasets_hf_cache_home": Path(datasets_config.HF_CACHE_HOME),
            "datasets_cache": Path(datasets_config.HF_DATASETS_CACHE),
            "datasets_modules_cache": Path(datasets_config.HF_MODULES_CACHE),
            "datasets_downloads": Path(datasets_config.DOWNLOADED_DATASETS_PATH),
            "datasets_extracted": Path(datasets_config.EXTRACTED_DATASETS_PATH),
            "hub_home": Path(hub_constants.HF_HOME),
            "hub_huggingface_cache": Path(hub_constants.HUGGINGFACE_HUB_CACHE),
            "hub_huggingface_assets_cache": Path(hub_constants.HUGGINGFACE_ASSETS_CACHE),
            "hub_cache": Path(hub_constants.HF_HUB_CACHE),
            "hub_assets_cache": Path(hub_constants.HF_ASSETS_CACHE),
            "hub_update_marker": Path(hub_constants.CHECK_FOR_UPDATE_DONE_PATH),
            "hub_agent_harnesses": Path(hub_constants.AGENT_HARNESSES_PATH),
            "hub_token": Path(hub_constants.HF_TOKEN_PATH),
            "hub_stored_tokens": Path(hub_constants.HF_STORED_TOKENS_PATH),
            "hub_xet_cache": Path(hub_constants.HF_XET_CACHE),
        }
        headers = hub_utils.build_hf_headers(token=None)
    except (AttributeError, ImportError, OSError, TypeError, ValueError):
        raise _CapacityAbort("production_identity_invalid") from None
    expected = _expected_reader_effective_paths(environment)
    if set(effective) != set(_READER_EFFECTIVE_PATH_LABELS) or effective != expected:
        raise _CapacityAbort("production_identity_invalid")

    work_dir = context.work_dir
    roots = _reader_owned_roots(environment)
    try:
        work_root = work_dir.resolve(strict=True)
        for root in roots:
            if (
                root.resolve(strict=True) != root
                or not _is_within(root, work_root)
                or not _safe_private_directory(root.lstat())
            ):
                raise OSError
    except (OSError, RuntimeError, ValueError):
        raise _CapacityAbort("production_identity_invalid") from None
    if any(not any(path == root or _is_within(path, root) for root in roots) for path in effective.values()):
        raise _CapacityAbort("production_identity_invalid")

    token_files_absent = _path_is_absent(effective["hub_token"]) and _path_is_absent(effective["hub_stored_tokens"])
    if (
        datasets_config.HF_ENDPOINT != _READER_OFFICIAL_ENDPOINT
        or hub_constants.ENDPOINT != _READER_OFFICIAL_ENDPOINT
        or datasets_config.HF_DATASETS_OFFLINE is not False
        or datasets_config.HF_HUB_OFFLINE is not False
        or hub_constants.HF_HUB_OFFLINE is not False
        or hub_constants.HF_HUB_DISABLE_IMPLICIT_TOKEN is not True
        or hub_constants.HF_HUB_DISABLE_SYMLINKS is not True
        or hub_constants.HF_HUB_DISABLE_TELEMETRY is not True
        or hub_constants.HF_HUB_DISABLE_XET is not True
        or any(str(key).lower() == "authorization" for key in headers)
        or not token_files_absent
        or _current_process_umask() != 0o077
        or not _reader_cache_lock_adapter_is_active(environment)
        or not _reader_network_activity_adapter_is_active()
    ):
        raise _CapacityAbort("production_identity_invalid")
    if _reader_network_activity_observed() is not (stage == "after_source_read"):
        raise _CapacityAbort("production_identity_invalid")
    return _expected_reader_isolation_snapshot(stage)


def _expected_reader_isolation_snapshot(stage: str) -> dict[str, Any]:
    if stage not in {"before_source_read", "after_source_read"}:
        raise _CapacityAbort("production_identity_invalid")
    return {
        "schema": "enron_capacity_reader_isolation_snapshot",
        "stage": stage,
        "phase_environment_policy_sha256": _reader_phase_environment_policy_sha256(),
        "effective_path_labels": list(_READER_EFFECTIVE_PATH_LABELS),
        "effective_path_count": len(_READER_EFFECTIVE_PATH_LABELS),
        "all_paths_phase_owned": True,
        "official_endpoint_sha256": _hash_bytes(_READER_OFFICIAL_ENDPOINT.encode("utf-8")),
        "official_endpoint": True,
        "offline_disabled": True,
        "ambient_credentials_disabled": True,
        "explicit_cache_dir_argument": True,
        "explicit_anonymous_argument": True,
        "authorization_header_absent": True,
        "token_files_absent": True,
        "restrictive_umask": True,
        "cache_symlinks_disabled": True,
        "cache_lock_files_owner_only": True,
        "cache_lock_mode": _READER_OWNER_ONLY_CACHE_LOCK_MODE,
        "cache_lock_adapter_sha256": _reader_cache_lock_adapter_sha256(),
        "network_activity_observed": stage == "after_source_read",
        "network_activity_adapter_sha256": _reader_network_activity_adapter_sha256(),
    }


def _expected_remote_reader_isolation_sha256() -> str:
    return _canonical_hash(
        {
            "schema": "enron_capacity_remote_reader_isolation",
            "mode": "phase_owned_anonymous_official",
            "before_source_read": _expected_reader_isolation_snapshot("before_source_read"),
            "after_source_read": _expected_reader_isolation_snapshot("after_source_read"),
        }
    )


def _load_phase_scoped_datasets_reader(
    context: EnronCapacityPhaseContext,
) -> tuple[Any, str]:
    global _PHASE_SCOPED_READER_LOADED
    if _PHASE_SCOPED_READER_LOADED or context.phase != "preparation":
        raise _CapacityAbort("production_identity_invalid")
    if _loaded_reader_modules():
        raise _CapacityAbort("production_identity_invalid")
    runtime_environment_sha256 = _canonical_hash(_runtime_environment_identity())
    try:
        datasets_module = importlib.import_module("datasets")
    except ImportError:
        raise _CapacityAbort("production_identity_invalid") from None
    if runtime_environment_sha256 != _canonical_hash(_runtime_environment_identity()):
        raise _CapacityAbort("production_identity_invalid")
    _PHASE_SCOPED_READER_LOADED = True
    return datasets_module, runtime_environment_sha256


def _local_reader_isolation() -> dict[str, Any]:
    descriptor = {
        "schema": "enron_capacity_local_reader_isolation",
        "mode": "local_fixture_no_remote_reader",
        "phase_environment_policy_sha256": _reader_phase_environment_policy_sha256(),
        "effective_path_count": 0,
        "cache_roots_phase_owned": True,
        "official_endpoint": False,
        "endpoint_sha256": _hash_bytes(b"local-reader-no-remote-endpoint"),
        "ambient_credentials_disabled": True,
        "explicit_cache_dir_argument": False,
        "explicit_anonymous_argument": False,
        "token_files_absent": True,
        "restrictive_umask": False,
        "cache_symlinks_disabled": True,
        "cache_lock_files_owner_only": False,
        "cache_lock_mode": 0,
        "cache_lock_adapter_sha256": _hash_bytes(b"nerb/local-reader-cache-lock-adapter-not-applicable"),
        "network_activity_observed": False,
        "network_activity_adapter_sha256": _hash_bytes(b"nerb/local-reader-network-activity-adapter-not-applicable"),
    }
    return {**descriptor, "sha256": _canonical_hash(descriptor)}


def _reader_lock_sha256() -> str:
    root = _git_root()
    try:
        values = {name: _hash_bytes((root / name).read_bytes()) for name in ("pyproject.toml", "uv.lock")}
    except OSError:
        raise _error("production_identity_invalid") from None
    return _canonical_hash({"schema": "enron_capacity_reader_lock", "files": values})


def _reader_lock_sha256_at_commit(git_commit: str) -> str:
    values = {name: _hash_bytes(_git_blob_bytes(git_commit, name)) for name in ("pyproject.toml", "uv.lock")}
    return _canonical_hash({"schema": "enron_capacity_reader_lock", "files": values})


def _capacity_bootstrap_identity() -> dict[str, Any]:
    try:
        _source_root, dependencies, layouts, _observer_fd = _validated_capacity_bootstrap()
        launcher = _git_root() / _CAPACITY_LAUNCHER_PATH
        info = launcher.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise OSError
        launcher_sha256 = _hash_bytes(launcher.read_bytes())
    except (EnronCapacityError, OSError):
        if _FRESH_PRODUCTION_WORKER:
            raise _error("production_identity_invalid") from None
        return {
            "schema": _BOOTSTRAP_SCHEMA,
            "mode": "fixture_process",
            "isolated": False,
            "site_disabled": False,
            "bytecode_disabled": False,
            "pth_processing": False,
            "source_root": "test_process",
            "dependency_root_count": 0,
            "dependency_root_layouts": [],
            "private_pycache_prefix": False,
            "launcher_source_sha256": _hash_bytes(b"nerb/capacity-launcher-unavailable"),
            "source_import_guard_sha256": _hash_bytes(b"nerb/capacity-import-guard-unavailable"),
        }
    try:
        import_guard_sha256 = _hash_bytes((_source_root / "nerb" / "_capacity_bootstrap.py").read_bytes())
    except OSError:
        raise _error("production_identity_invalid") from None
    return {
        "schema": _BOOTSTRAP_SCHEMA,
        "mode": "isolated_site_disabled",
        "isolated": True,
        "site_disabled": True,
        "bytecode_disabled": True,
        "pth_processing": False,
        "source_root": "tracked_worktree_src",
        "dependency_root_count": len(dependencies),
        "dependency_root_layouts": list(layouts),
        "private_pycache_prefix": True,
        "launcher_source_sha256": launcher_sha256,
        "source_import_guard_sha256": import_guard_sha256,
    }


def _runtime_environment_identity() -> dict[str, Any]:
    executable = Path(sys.executable)
    try:
        executable_sha256 = _hash_bytes(executable.read_bytes())
    except OSError:
        raise _error("production_identity_invalid") from None
    logical_cores = os.cpu_count()
    if type(logical_cores) is not int or logical_cores <= 0:
        raise _error("production_identity_invalid")
    embedded_build_source = _native_extension_embedded_build_source_sha256()
    return {
        "os_name": os.name,
        "kernel_system": platform.system(),
        "kernel_release": platform.release(),
        "architecture": platform.machine(),
        "cpu_model": _cpu_model(),
        "logical_cpu_count": logical_cores,
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "python_executable_sha256": executable_sha256,
        "native_extension_sha256": _native_extension_sha256(),
        "native_build_source_sha256": _native_build_source_sha256(),
        "native_extension_build_source_sha256": (embedded_build_source or _UNAVAILABLE_NATIVE_BUILD_SOURCE_SHA256),
        "capacity_bootstrap": _capacity_bootstrap_identity(),
        "reader_environment": _reader_environment_identity(),
        "reader_phase_environment_policy_sha256": _reader_phase_environment_policy_sha256(),
    }


def _verify_runtime_environment_shape(runtime: Mapping[str, Any]) -> None:
    _require_closed(
        runtime,
        {
            "os_name",
            "kernel_system",
            "kernel_release",
            "architecture",
            "cpu_model",
            "logical_cpu_count",
            "python_implementation",
            "python_version",
            "python_executable_sha256",
            "native_extension_sha256",
            "native_build_source_sha256",
            "native_extension_build_source_sha256",
            "capacity_bootstrap",
            "reader_environment",
            "reader_phase_environment_policy_sha256",
        },
        "runtime environment",
    )
    for field in (
        "os_name",
        "kernel_system",
        "kernel_release",
        "architecture",
        "cpu_model",
        "python_implementation",
        "python_version",
    ):
        value = runtime.get(field)
        if (
            not isinstance(value, str)
            or not value
            or len(value.encode("utf-8")) > 256
            or any(ord(character) < 32 for character in value)
        ):
            raise _error("report_invalid")
    _positive_int(runtime.get("logical_cpu_count"), "logical CPU count")
    for field in (
        "python_executable_sha256",
        "native_extension_sha256",
        "native_build_source_sha256",
        "native_extension_build_source_sha256",
        "reader_phase_environment_policy_sha256",
    ):
        value = runtime.get(field)
        if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
            raise _error("report_invalid")
    bootstrap = _require_mapping(runtime.get("capacity_bootstrap"), "capacity bootstrap")
    _require_closed(
        bootstrap,
        {
            "schema",
            "mode",
            "isolated",
            "site_disabled",
            "bytecode_disabled",
            "pth_processing",
            "source_root",
            "dependency_root_count",
            "dependency_root_layouts",
            "private_pycache_prefix",
            "launcher_source_sha256",
            "source_import_guard_sha256",
        },
        "capacity bootstrap",
    )
    if (
        bootstrap.get("schema") != _BOOTSTRAP_SCHEMA
        or bootstrap.get("mode") not in {"isolated_site_disabled", "fixture_process"}
        or not isinstance(bootstrap.get("source_root"), str)
        or type(bootstrap.get("isolated")) is not bool
        or type(bootstrap.get("site_disabled")) is not bool
        or type(bootstrap.get("bytecode_disabled")) is not bool
        or bootstrap.get("pth_processing") is not False
        or type(bootstrap.get("private_pycache_prefix")) is not bool
        or not isinstance(bootstrap.get("launcher_source_sha256"), str)
        or not isinstance(bootstrap.get("source_import_guard_sha256"), str)
        or _HASH_RE.fullmatch(cast(str, bootstrap.get("launcher_source_sha256"))) is None
        or _HASH_RE.fullmatch(cast(str, bootstrap.get("source_import_guard_sha256"))) is None
    ):
        raise _error("report_invalid")
    _bounded_int(bootstrap.get("dependency_root_count"), "dependency root count", minimum=0)
    layouts = bootstrap.get("dependency_root_layouts")
    if (
        not isinstance(layouts, list)
        or len(layouts) != bootstrap.get("dependency_root_count")
        or any(
            not isinstance(value, str) or not re.fullmatch(r"venv/lib(?:64)?/python3\.\d+/site-packages", value)
            for value in layouts
        )
    ):
        raise _error("report_invalid")
    reader = _require_mapping(runtime.get("reader_environment"), "reader environment")
    _require_closed(
        reader,
        {
            "installed_distribution_count",
            "installed_distribution_inventory_sha256",
            "datasets_version",
            "datasets_file_count",
            "datasets_total_bytes",
            "datasets_distribution_sha256",
            "critical_reader_distribution_count",
            "critical_reader_file_count",
            "critical_reader_total_bytes",
            "critical_reader_versions",
            "critical_reader_distribution_sha256",
        },
        "reader environment",
    )
    _positive_int(reader.get("installed_distribution_count"), "installed distribution count")
    _bounded_int(reader.get("datasets_file_count"), "datasets file count", minimum=0)
    _bounded_int(reader.get("datasets_total_bytes"), "datasets total bytes", minimum=0)
    _bounded_int(reader.get("critical_reader_distribution_count"), "critical reader distribution count", minimum=0)
    _bounded_int(reader.get("critical_reader_file_count"), "critical reader file count", minimum=0)
    _bounded_int(reader.get("critical_reader_total_bytes"), "critical reader total bytes", minimum=0)
    for field in (
        "installed_distribution_inventory_sha256",
        "datasets_distribution_sha256",
        "critical_reader_distribution_sha256",
    ):
        item = reader.get(field)
        if not isinstance(item, str) or _HASH_RE.fullmatch(item) is None:
            raise _error("report_invalid")
    datasets_version = reader.get("datasets_version")
    if datasets_version is not None and (not isinstance(datasets_version, str) or not datasets_version):
        raise _error("report_invalid")
    if (datasets_version is None) != (reader.get("datasets_file_count") == 0):
        raise _error("report_invalid")
    versions = _require_mapping(reader.get("critical_reader_versions"), "critical reader versions")
    expected_names = {name for name, _import_name, _package_init, _version in _CRITICAL_READER_DISTRIBUTIONS}
    if set(versions) != expected_names or any(
        version is not None and (not isinstance(version, str) or not version) for version in versions.values()
    ):
        raise _error("report_invalid")
    if runtime.get("reader_phase_environment_policy_sha256") != _reader_phase_environment_policy_sha256():
        raise _error("report_invalid")


def _cpu_model() -> str:
    if _PRODUCTION_CPU_MODEL is not None and (_FRESH_PRODUCTION_WORKER or _PRODUCTION_PROCESS_CONTAINMENT is not None):
        return _PRODUCTION_CPU_MODEL
    if _PRODUCTION_PROCESS_CONTAINMENT is not None:
        raise _error("production_identity_invalid")
    value = platform.processor().strip()
    if not value and sys.platform.startswith("linux"):
        try:
            for line in Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="strict").splitlines():
                if line.lower().startswith("model name") and ":" in line:
                    value = line.split(":", 1)[1].strip()
                    break
        except (OSError, UnicodeError):
            value = ""
    if not value and sys.platform == "darwin":
        try:
            completed = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                check=False,
                capture_output=True,
                text=True,
                timeout=2,
            )
            value = completed.stdout.strip() if completed.returncode == 0 else ""
        except (OSError, subprocess.SubprocessError):
            value = ""
    if not value or len(value.encode("utf-8")) > 256 or any(ord(character) < 32 for character in value):
        raise _error("production_identity_invalid")
    return value


def _git_head() -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", os.fspath(Path(__file__).parent), "rev-parse", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        raise _error("production_identity_invalid") from None
    value = completed.stdout.strip()
    if completed.returncode != 0 or not _GIT_COMMIT_RE.fullmatch(value):
        raise _error("production_identity_invalid")
    return value


def _git_root() -> Path:
    if _PRODUCTION_GIT_ROOT is not None and (_FRESH_PRODUCTION_WORKER or _PRODUCTION_PROCESS_CONTAINMENT is not None):
        return _PRODUCTION_GIT_ROOT
    if _PRODUCTION_PROCESS_CONTAINMENT is not None:
        raise _error("production_identity_invalid")
    try:
        completed = subprocess.run(
            ["git", "-C", os.fspath(Path(__file__).parent), "rev-parse", "--show-toplevel"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        raise _error("production_identity_invalid") from None
    if completed.returncode != 0 or not completed.stdout.strip():
        raise _error("production_identity_invalid")
    return Path(completed.stdout.strip())


def _require_clean_head_sources(paths: set[Path], git_commit: str) -> None:
    root = _git_root()
    for path in paths:
        absolute = _absolute_private_path(path)
        try:
            relative = absolute.relative_to(root)
            working_payload = absolute.read_bytes()
            completed = subprocess.run(
                ["git", "-C", os.fspath(root), "show", f"{git_commit}:{relative.as_posix()}"],
                check=False,
                capture_output=True,
                timeout=10,
            )
        except (OSError, ValueError, subprocess.SubprocessError):
            raise _error("production_identity_invalid") from None
        if completed.returncode != 0 or completed.stdout != working_payload:
            raise _error("production_identity_invalid")
    try:
        status = subprocess.run(
            [
                "git",
                "-C",
                os.fspath(root),
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                "--",
                *(os.fspath(path.relative_to(root)) for path in sorted(paths)),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        raise _error("production_identity_invalid") from None
    if status.returncode != 0 or status.stdout:
        raise _error("production_identity_invalid")


def _require_globally_clean_checkout(git_commit: str) -> None:
    root = _git_root()
    if _git_head() != git_commit:
        raise _error("production_identity_invalid")
    try:
        status = subprocess.run(
            ["git", "-C", os.fspath(root), "status", "--porcelain=v1", "--untracked-files=all"],
            check=False,
            capture_output=True,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError):
        raise _error("production_identity_invalid") from None
    if status.returncode != 0 or status.stdout:
        raise _error("production_identity_invalid")


def _callable_source_path(value: object) -> Path:
    try:
        source = inspect.getsourcefile(cast(Any, value))
    except (TypeError, ValueError):
        source = None
    if source is None:
        raise _error("production_identity_invalid")
    return Path(source)


def _callable_implementation_sha256(value: object, *, role: str, git_commit: str) -> str:
    source_path = _callable_source_path(value)
    try:
        payload = source_path.read_bytes()
        module = cast(Any, value).__module__
        qualname = cast(Any, value).__qualname__
    except (AttributeError, OSError, TypeError, ValueError):
        raise _error("production_identity_invalid") from None
    return _canonical_hash(
        {
            "role": role,
            "module": module,
            "qualname": qualname,
            "source_sha256": _hash_bytes(payload),
            "capacity_implementation_sha256": _implementation_sha256(),
            "executable_git_commit": git_commit,
        }
    )


def _resource_preflight(
    final_dir: Path,
    attempt_ledger_dir: Path,
    probe: CapacityResourceProbe,
    *,
    output_parent: _PinnedDirectory,
) -> _Preflight:
    physical_memory = _probe_physical_memory(probe)
    effective_cap = min(
        MAX_ABSOLUTE_RSS_BYTES,
        physical_memory * PHYSICAL_MEMORY_FRACTION_NUMERATOR // PHYSICAL_MEMORY_FRACTION_DENOMINATOR,
    )
    maximum_peak = effective_cap * PEAK_RSS_FRACTION_NUMERATOR // PEAK_RSS_FRACTION_DENOMINATOR
    if effective_cap <= 0 or maximum_peak <= 0:
        raise _error("preflight_memory")
    process_tree_rss = _probe_process_tree_rss(probe)
    if process_tree_rss > maximum_peak:
        raise _error("preflight_rss_limit")
    output_parent.assert_current(code="private_tree_invalid")
    if output_parent.path != final_dir.parent:
        raise _error("private_tree_invalid")
    tombstone_count = _count_private_tombstones(output_parent.fd)
    output_disk_path = _nearest_existing_directory(final_dir.parent)
    ledger_disk_path = _nearest_existing_directory(attempt_ledger_dir)
    candidates = ((output_disk_path, True), (ledger_disk_path, False))
    grouped: dict[int, list[tuple[Path, bool, CapacityDiskUsage]]] = {}
    for path, includes_output in candidates:
        device = _probe_filesystem_device(probe, path)
        grouped.setdefault(device, []).append((path, includes_output, _probe_disk_usage(probe, path)))
    filesystems: list[_FilesystemPreflight] = []
    output_preflight_free: int | None = None
    disks: list[CapacityDiskUsage] = []
    for device, observations in grouped.items():
        output_observation = next((item for item in observations if item[1]), None)
        selected = output_observation or observations[0]
        group_total = {item[2].total for item in observations}
        if len(group_total) != 1:
            raise _error("preflight_disk")
        minimum_free = min(item[2].free for item in observations)
        filesystems.append(
            _FilesystemPreflight(
                device=device,
                probe_path=selected[0],
                preflight_free_disk_bytes=minimum_free,
                includes_output=output_observation is not None,
            )
        )
        disks.extend(item[2] for item in observations)
        if output_observation is not None:
            output_preflight_free = output_observation[2].free
    filesystems.sort(key=lambda item: (not item.includes_output, item.device))
    if output_preflight_free is None or not filesystems or len(filesystems) > 2:
        raise _error("preflight_disk")
    preflight_free = min(disk.free for disk in disks)
    if preflight_free < MIN_PREFLIGHT_FREE_DISK_BYTES:
        raise _error("preflight_disk_limit")
    return _Preflight(
        physical_memory_bytes=physical_memory,
        effective_rss_cap_bytes=effective_cap,
        maximum_peak_rss_bytes=maximum_peak,
        preflight_process_tree_rss_bytes=process_tree_rss,
        preflight_free_disk_bytes=preflight_free,
        output_preflight_free_disk_bytes=output_preflight_free,
        preexisting_private_tombstone_count=tombstone_count,
        filesystems=tuple(filesystems),
    )


def _count_private_tombstones(parent_fd: int) -> int:
    try:
        names = sorted(name for name in os.listdir(parent_fd) if _PRIVATE_TOMBSTONE_RE.fullmatch(name))
    except OSError:
        raise _error("private_tree_invalid") from None
    if len(names) > MAX_RETAINED_PRIVATE_TOMBSTONES:
        raise _error("private_tree_invalid")
    entries = [0]
    for name in names:
        descriptor: int | None = None
        try:
            before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if not _safe_private_directory(before):
                raise _error("private_tree_invalid")
            flags = (
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(name, flags, dir_fd=parent_fd)
            opened = os.fstat(descriptor)
            if not _same_directory(before, opened) or _logical_tree_bytes(descriptor, depth=0, entries=entries) != 0:
                raise _error("private_tree_invalid")
        except EnronCapacityError:
            raise
        except OSError:
            raise _error("private_tree_invalid") from None
        finally:
            if descriptor is not None:
                os.close(descriptor)
    return len(names)


def _nearest_existing_directory(path: Path) -> Path:
    candidate = path
    while True:
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            parent = candidate.parent
            if parent == candidate:
                raise _error("preflight_disk") from None
            candidate = parent
            continue
        except OSError:
            raise _error("preflight_disk") from None
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise _error("preflight_disk")
        return candidate


def _probe_physical_memory(probe: CapacityResourceProbe) -> int:
    try:
        value = probe.physical_memory_bytes()
    except BaseException:
        value = None
    if type(value) is not int or value <= 0:
        raise _error("preflight_memory")
    return value


def _probe_process_tree_rss(probe: CapacityResourceProbe) -> int:
    try:
        value = probe.process_tree_rss_bytes(os.getpid())
    except BaseException:
        value = None
    if type(value) is not int or value <= 0:
        raise _error("preflight_rss")
    return value


def _probe_disk_usage(probe: CapacityResourceProbe, path: Path) -> CapacityDiskUsage:
    try:
        value = probe.disk_usage(path)
    except BaseException:
        value = None
    if not isinstance(value, CapacityDiskUsage) or any(
        type(item) is not int or item < 0 or item > _MAX_RESOURCE_INTEGER
        for item in (value.total, value.used, value.free)
    ):
        raise _error("preflight_disk")
    if value.total <= 0 or value.used > value.total or value.free > value.total:
        raise _error("preflight_disk")
    return value


def _probe_filesystem_device(probe: CapacityResourceProbe, path: Path) -> int:
    try:
        callback = getattr(probe, "filesystem_device", None)
        if callable(callback):
            value = callback(path)
        else:
            info = path.lstat()
            value = info.st_dev if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) else None
    except BaseException:
        value = None
    if type(value) is not int or value < 0 or value > _MAX_RESOURCE_INTEGER:
        raise _error("preflight_disk")
    return value


def _runtime_probe_error_is_immediate(exc: BaseException) -> bool:
    return isinstance(exc, _CapacityAbort) or (
        isinstance(exc, EnronCapacityError)
        and exc.code
        in {
            "clock_invalid",
            "private_tree_invalid",
            "rss_limit",
            "runtime_disk_floor",
            "runtime_filesystem_changed",
        }
    )


def _acquire_runtime_process_tree_rss(probe: CapacityResourceProbe) -> tuple[int, int]:
    for attempt in range(_RUNTIME_RESOURCE_ACQUISITION_MAX_ATTEMPTS):
        try:
            value = probe.process_tree_rss_bytes(os.getpid())
        except (KeyboardInterrupt, SystemExit, MemoryError):
            raise
        except BaseException as exc:
            if _runtime_probe_error_is_immediate(exc):
                raise
            value = None
        if type(value) is int and value > 0:
            return value, attempt
    raise _error("rss_acquisition_exhausted")


def _acquire_runtime_filesystem_device(probe: CapacityResourceProbe, path: Path) -> int | None:
    try:
        callback = getattr(probe, "filesystem_device", None)
        if callable(callback):
            value = callback(path)
        else:
            info = path.lstat()
            value = info.st_dev if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) else None
    except (KeyboardInterrupt, SystemExit, MemoryError):
        raise
    except BaseException as exc:
        if _runtime_probe_error_is_immediate(exc):
            raise
        return None
    return value if type(value) is int and 0 <= value <= _MAX_RESOURCE_INTEGER else None


def _acquire_runtime_disk_usage(probe: CapacityResourceProbe, path: Path) -> CapacityDiskUsage | None:
    try:
        value = probe.disk_usage(path)
    except (KeyboardInterrupt, SystemExit, MemoryError):
        raise
    except BaseException as exc:
        if _runtime_probe_error_is_immediate(exc):
            raise
        return None
    if not isinstance(value, CapacityDiskUsage) or any(
        type(item) is not int or item < 0 or item > _MAX_RESOURCE_INTEGER
        for item in (value.total, value.used, value.free)
    ):
        return None
    if value.total <= 0 or value.used > value.total or value.free > value.total:
        return None
    return value


def _sample_runtime_filesystems(
    probe: CapacityResourceProbe,
    preflight: _Preflight,
) -> tuple[int, CapacityDiskUsage, int]:
    if not preflight.filesystems or sum(item.includes_output for item in preflight.filesystems) != 1:
        raise _error("resource_measurement_failed")

    minimum_free_across_attempts: int | None = None
    output_disk_across_attempts: CapacityDiskUsage | None = None
    for attempt in range(_RUNTIME_RESOURCE_ACQUISITION_MAX_ATTEMPTS):
        attempt_minimum_free: int | None = None
        attempt_output_disk: CapacityDiskUsage | None = None
        acquired = True
        for filesystem in preflight.filesystems:
            device_before = _acquire_runtime_filesystem_device(probe, filesystem.probe_path)
            if device_before is None:
                acquired = False
                break
            if device_before != filesystem.device:
                raise _error("runtime_filesystem_changed")
            disk = _acquire_runtime_disk_usage(probe, filesystem.probe_path)
            if disk is None:
                acquired = False
                break
            device_after = _acquire_runtime_filesystem_device(probe, filesystem.probe_path)
            if device_after is None:
                acquired = False
                break
            if device_after != filesystem.device:
                raise _error("runtime_filesystem_changed")
            attempt_minimum_free = disk.free if attempt_minimum_free is None else min(attempt_minimum_free, disk.free)
            minimum_free_across_attempts = (
                disk.free if minimum_free_across_attempts is None else min(minimum_free_across_attempts, disk.free)
            )
            if filesystem.includes_output:
                attempt_output_disk = disk
                if output_disk_across_attempts is None or disk.free < output_disk_across_attempts.free:
                    output_disk_across_attempts = disk
            if disk.free < MIN_RUNTIME_FREE_DISK_BYTES:
                raise _RuntimeDiskFloor(minimum_free_across_attempts, output_disk_across_attempts, attempt)
        if acquired and attempt_minimum_free is not None and attempt_output_disk is not None:
            if minimum_free_across_attempts is None or output_disk_across_attempts is None:
                raise _error("resource_measurement_failed")
            return minimum_free_across_attempts, output_disk_across_attempts, attempt
    raise _error("disk_acquisition_exhausted")


def _probe_monotonic_ns(probe: CapacityResourceProbe) -> int:
    try:
        value = probe.monotonic_ns()
    except (KeyboardInterrupt, SystemExit, MemoryError):
        raise
    except BaseException:
        value = None
    if type(value) is not int or value < 0:
        raise _error("clock_invalid")
    return value


def _merge_monitor_metrics(metrics: _AttemptMetrics, snapshot: Mapping[str, int]) -> None:
    peak = int(snapshot["peak_process_tree_rss_bytes"])
    minimum_free = int(snapshot["minimum_free_disk_bytes"])
    metrics.peak_process_tree_rss_bytes = max(metrics.peak_process_tree_rss_bytes or 0, peak)
    metrics.minimum_free_disk_bytes = (
        minimum_free if metrics.minimum_free_disk_bytes is None else min(metrics.minimum_free_disk_bytes, minimum_free)
    )
    metrics.resource_observation_count = max(
        metrics.resource_observation_count or 0,
        int(snapshot["resource_observation_count"]),
    )
    metrics.maximum_resource_observation_wall_gap_ns = max(
        metrics.maximum_resource_observation_wall_gap_ns or 0,
        int(snapshot["maximum_resource_observation_wall_gap_ns"]),
    )


def _post_promotion_enforce(
    probe: CapacityResourceProbe,
    *,
    preflight: _Preflight,
    run_started_ns: int,
    final_owned: int,
    metrics: _AttemptMetrics,
    monitor: _ContinuousResourceMonitor,
) -> None:
    monitor.observe_transaction_boundary(final_owned)
    monitor.stop()
    monitor.raise_if_failed()
    terminal_snapshot = monitor.global_snapshot()
    _merge_monitor_metrics(metrics, terminal_snapshot)
    now = _probe_monotonic_ns(probe)
    if now < run_started_ns:
        raise _error("clock_invalid")
    metrics.elapsed_ns = now - run_started_ns
    metrics.final_owned_disk_bytes = final_owned
    if (metrics.peak_process_tree_rss_bytes or 0) > preflight.maximum_peak_rss_bytes:
        raise _error("rss_limit")
    if (metrics.minimum_free_disk_bytes or 0) < MIN_RUNTIME_FREE_DISK_BYTES:
        raise _error("runtime_disk_floor")
    if (metrics.maximum_resource_observation_wall_gap_ns or 0) > MAX_RESOURCE_OBSERVATION_WALL_GAP_NS:
        raise _error("resource_observation_gap")
    if int(terminal_snapshot["maximum_resource_acquisition_duration_ns"]) > MAX_RESOURCE_ACQUISITION_DURATION_NS:
        raise _error("resource_acquisition_timeout")
    if final_owned > MAX_OWNED_DISK_BYTES:
        raise _error("owned_disk_limit")
    if metrics.elapsed_ns > MAX_TOTAL_RUNTIME_NS:
        raise _error("runtime_limit")


def _finish_attempt_metrics(metrics: _AttemptMetrics, probe: CapacityResourceProbe) -> None:
    if metrics.started_ns is None:
        return
    try:
        now = _probe_monotonic_ns(probe)
    except EnronCapacityError:
        return
    if now >= metrics.started_ns:
        metrics.elapsed_ns = max(metrics.elapsed_ns or 0, now - metrics.started_ns)


def _write_report_and_fsync(private_run: PrivateRun, payload: bytes) -> None:
    try:
        with private_run.open_binary(_REPORT_FILENAME) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except _CapacityAbort:
        raise
    except BaseException:
        raise _error("report_write_failed") from None


class _AttemptLedger:
    def __init__(self, root: Path) -> None:
        self.pinned = _PinnedDirectory(root, create_final=True)

    @property
    def fd(self) -> int:
        return self.pinned.fd

    def assert_current(self) -> None:
        self.pinned.assert_current(code="attempt_ledger_invalid")

    def close(self) -> None:
        self.pinned.close()


def _begin_inflight_attempt(
    ledger: _AttemptLedger,
    *,
    final_dir: Path,
    output_parent: _PinnedDirectory,
    execution: Mapping[str, Any],
    production_evidence: bool,
    started_monotonic_ns: int,
) -> _InflightAttempt:
    descriptor = ledger.fd
    temporary_name: str | None = None
    marker: _OwnedDescriptor | None = None
    marker_name: str | None = None
    try:
        ledger.assert_current()
        output_parent.assert_current(code="private_transaction_failed")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        _recover_ledger_temps_locked(descriptor)
        receipts = _read_attempt_receipts_locked(descriptor)
        inflights = _read_inflight_records_locked(descriptor)
        _validate_attempt_allocations(receipts, inflights)
        if inflights:
            raise _error("attempt_ledger_invalid")
        attempt_sequence = (
            max(
                (int(item["attempt_sequence"]) for item in (*receipts, *(record for _name, record in inflights))),
                default=0,
            )
            + 1
        )
        nonce = secrets.token_hex(32)
        stage_token = nonce[:24]
        marker_name = f".attempt-inflight-{nonce}.json"
        stage_name = f".{final_dir.name}.stage-{stage_token}"
        started_wall_monotonic_ns = time.monotonic_ns()
        record: dict[str, Any] = {
            "schema_version": CAPACITY_INFLIGHT_SCHEMA_VERSION,
            "attempt_sequence": attempt_sequence,
            "attempt_nonce": nonce,
            "owner_pid": os.getpid(),
            "owner_identity_sha256": _canonical_hash(
                {
                    "attempt_nonce": nonce,
                    "owner_pid": os.getpid(),
                    "started_wall_monotonic_ns": started_wall_monotonic_ns,
                    "capacity_implementation_sha256": execution.get("capacity_implementation_sha256"),
                }
            ),
            "started_monotonic_ns": started_monotonic_ns,
            "started_wall_monotonic_ns": started_wall_monotonic_ns,
            "production_evidence": production_evidence,
            "executable_git_commit": execution.get("executable_git_commit"),
            "capacity_implementation_sha256": execution.get("capacity_implementation_sha256"),
            "repository_tree_sha256": execution.get("repository_tree_sha256"),
            "runtime_environment_sha256": execution.get("runtime_environment_sha256"),
            "execution_sha256": _canonical_hash(execution),
            "policy_sha256": capacity_policy()["policy_sha256"],
            "output_parent_device": output_parent.identity.device,
            "output_parent_inode": output_parent.identity.inode,
            "output_name_sha256": _hash_bytes(final_dir.name.encode("utf-8")),
            "stage_token": stage_token,
            "stage_name_sha256": _hash_bytes(stage_name.encode("utf-8")),
        }
        _verify_inflight_record(record, expected_nonce=nonce)
        payload = _pretty_json_bytes(record)
        if len(payload) > MAX_INFLIGHT_RECORD_BYTES:
            raise _error("attempt_ledger_write_failed")
        temporary_name = f".attempt-inflight-stage-{nonce}-{secrets.token_hex(32)}.tmp"
        marker = _write_locked_atomic_file_at(
            descriptor,
            temporary_name=temporary_name,
            final_name=marker_name,
            payload=payload,
        )
        temporary_name = None
        ledger.assert_current()
        attempt = _InflightAttempt(
            ledger=ledger,
            record=record,
            marker_name=marker_name,
            marker=marker,
            output_parent=output_parent,
            output_name=final_dir.name,
        )
        marker = None
        return attempt
    except EnronCapacityError:
        raise
    except BaseException:
        raise _error("attempt_ledger_write_failed") from None
    finally:
        active_error = sys.exc_info()[1]
        cleanup_control = active_error if isinstance(active_error, (KeyboardInterrupt, SystemExit)) else None
        while marker is not None and not marker.closed:
            try:
                marker.close()
            except (KeyboardInterrupt, SystemExit) as exc:
                if cleanup_control is None:
                    cleanup_control = exc
        unlocked = False
        while not unlocked:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                unlocked = True
            except (KeyboardInterrupt, SystemExit) as exc:
                if cleanup_control is None:
                    cleanup_control = exc
            except OSError:
                unlocked = True
        if cleanup_control is not None and cleanup_control is not active_error:
            raise cleanup_control


def _write_locked_atomic_file_at(
    directory_fd: int,
    *,
    temporary_name: str,
    final_name: str,
    payload: bytes,
    durable_commit: bytearray | None = None,
) -> _OwnedDescriptor:
    owner: _OwnedDescriptor | None = None
    descriptor: int | None = None
    staged_identity: tuple[int, int] | None = None
    published = False
    try:
        owner = _open_owned_private_file_descriptor(temporary_name, dir_fd=directory_fd)
        descriptor = owner.fd
        staged_identity = _regular_file_identity(os.fstat(descriptor))
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fsync(descriptor)
        _require_pinned_private_file_at(
            directory_fd,
            temporary_name,
            descriptor,
            staged_identity,
            maximum=max(len(payload), 1),
        )
        _private_io._rename_noreplace_at(directory_fd, temporary_name, directory_fd, final_name)
        published = True
        try:
            _require_pinned_private_file_at(
                directory_fd,
                final_name,
                descriptor,
                staged_identity,
                maximum=max(len(payload), 1),
            )
        except BaseException:
            _restore_mismatched_publication_at(directory_fd, final_name, temporary_name)
            published = False
            raise
        if durable_commit is None:
            os.fsync(directory_fd)
        else:
            if durable_commit != bytearray(1):
                raise ValueError("Durability status must contain one zero byte.")
            fsync_errno = _native_engine._fsync_fd_commit(durable_commit, directory_fd)
            if fsync_errno:
                raise OSError(fsync_errno, os.strerror(fsync_errno))
            if durable_commit != bytearray(b"\x01"):
                raise OSError("Directory fsync returned without committing durability status.")
        try:
            _require_pinned_private_file_at(
                directory_fd,
                final_name,
                descriptor,
                staged_identity,
                maximum=max(len(payload), 1),
            )
        except BaseException:
            _restore_mismatched_publication_at(directory_fd, final_name, temporary_name)
            published = False
            raise
        owner.disarm_private_path_cleanup()
        return owner
    except BaseException as active_error:
        cleanup_control: BaseException | None = None
        if owner is not None:
            if descriptor is None or staged_identity is None:
                cleanup_control = _abort_private_owner_during_unwind(owner)
            else:
                cleanup_names = (final_name, temporary_name) if published else (temporary_name, final_name)
                cleaned = False
                for cleanup_name in cleanup_names:
                    while True:
                        try:
                            _wipe_and_quarantine_private_file_at(
                                directory_fd,
                                cleanup_name,
                                descriptor,
                                staged_identity,
                            )
                            cleaned = True
                            break
                        except (KeyboardInterrupt, SystemExit, MemoryError) as exc:
                            if cleanup_control is None:
                                cleanup_control = exc
                            continue
                        except (EnronCapacityError, EnronPrivateIOError, OSError):
                            break
                    if cleaned:
                        break
                owner.disarm_private_path_cleanup()
                close_control = _close_owned_descriptor_during_unwind(owner)
                if cleanup_control is None:
                    cleanup_control = close_control
        if cleanup_control is not None and not isinstance(
            active_error,
            (KeyboardInterrupt, SystemExit, MemoryError),
        ):
            raise cleanup_control
        raise


def _regular_file_identity(info: os.stat_result) -> tuple[int, int]:
    return int(info.st_dev), int(info.st_ino)


def _require_pinned_private_file_at(
    directory_fd: int,
    name: str,
    descriptor: int,
    expected_identity: tuple[int, int],
    *,
    maximum: int,
) -> os.stat_result:
    try:
        opened = os.fstat(descriptor)
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError:
        raise _error("attempt_ledger_invalid") from None
    owner = os.geteuid() if hasattr(os, "geteuid") else opened.st_uid
    if (
        not stat.S_ISREG(opened.st_mode)
        or stat.S_ISLNK(current.st_mode)
        or opened.st_uid != owner
        or current.st_uid != owner
        or opened.st_nlink != 1
        or current.st_nlink != 1
        or stat.S_IMODE(opened.st_mode) != 0o600
        or stat.S_IMODE(current.st_mode) != 0o600
        or opened.st_size < 0
        or opened.st_size > maximum
        or _regular_file_identity(opened) != expected_identity
        or _regular_file_identity(current) != expected_identity
    ):
        raise _error("attempt_ledger_invalid")
    return opened


def _wipe_and_quarantine_private_file_at(
    directory_fd: int,
    name: str,
    descriptor: int,
    expected_identity: tuple[int, int],
) -> str:
    """Wipe one pinned private inode, then retain it under an authenticated tombstone name."""

    try:
        parent = os.fstat(directory_fd)
        opened = os.fstat(descriptor)
        owner = os.geteuid() if hasattr(os, "geteuid") else opened.st_uid
        if (
            not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != owner
            or stat.S_IMODE(parent.st_mode) != 0o700
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != owner
            or _regular_file_identity(opened) != expected_identity
        ):
            raise OSError
        os.fchmod(descriptor, 0o600)
        os.ftruncate(descriptor, 0)
        os.fsync(descriptor)
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(current.st_mode)
            or stat.S_ISLNK(current.st_mode)
            or current.st_uid != owner
            or current.st_nlink != 1
            or stat.S_IMODE(current.st_mode) != 0o600
            or _regular_file_identity(current) != expected_identity
        ):
            raise OSError
        tombstone_name: str | None = None
        for _ in range(128):
            candidate = f".nerb-cleanup-{secrets.token_hex(24)}"
            try:
                _private_io._rename_noreplace_at(directory_fd, name, directory_fd, candidate)
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
            or tombstone.st_uid != owner
            or tombstone.st_nlink != 1
            or stat.S_IMODE(tombstone.st_mode) != 0o600
            or tombstone.st_size != 0
            or _regular_file_identity(tombstone) != expected_identity
        ):
            _restore_mismatched_quarantine_at(
                directory_fd,
                tombstone_name,
                name,
                _regular_file_identity(tombstone),
            )
            raise OSError
        os.fsync(directory_fd)
        return tombstone_name
    except (EnronPrivateIOError, OSError, ValueError):
        raise _error("attempt_ledger_invalid") from None


def _wipe_authenticated_inflight_descriptor(descriptor: int, expected_identity: tuple[int, int]) -> None:
    """Durably clear one retained inflight inode without trusting its public name."""

    try:
        opened = os.fstat(descriptor)
        owner = os.geteuid() if hasattr(os, "geteuid") else opened.st_uid
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != owner
            or opened.st_nlink != 1
            or _regular_file_identity(opened) != expected_identity
        ):
            raise OSError
        os.fchmod(descriptor, 0o600)
        os.ftruncate(descriptor, 0)
        os.fsync(descriptor)
        cleared = os.fstat(descriptor)
        if (
            not stat.S_ISREG(cleared.st_mode)
            or cleared.st_uid != owner
            or cleared.st_nlink != 1
            or stat.S_IMODE(cleared.st_mode) != 0o600
            or cleared.st_size != 0
            or _regular_file_identity(cleared) != expected_identity
        ):
            raise OSError
    except OSError:
        raise _error("attempt_ledger_invalid") from None


def _preserve_mismatched_retirement_entry_at(
    directory_fd: int,
    temporary_name: str,
    original_name: str,
    expected_identity: tuple[int, int],
) -> bool:
    """Move a raced substitute out of auto-cleanup state without overwriting it."""

    try:
        current = os.stat(temporary_name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError:
        raise _error("attempt_ledger_invalid") from None
    observed_identity = _regular_file_identity(current)
    if observed_identity == expected_identity:
        return False
    try:
        _restore_mismatched_quarantine_at(
            directory_fd,
            temporary_name,
            original_name,
            observed_identity,
        )
    except EnronCapacityError:
        preserved_name: str | None = None
        for _ in range(128):
            candidate = f".attempt-preserved-{secrets.token_hex(32)}.hold"
            try:
                _private_io._rename_noreplace_at(directory_fd, temporary_name, directory_fd, candidate)
            except FileExistsError:
                continue
            preserved_name = candidate
            break
        if preserved_name is None:
            raise
        preserved = os.stat(preserved_name, dir_fd=directory_fd, follow_symlinks=False)
        if _regular_file_identity(preserved) != observed_identity:
            raise _error("attempt_ledger_invalid")
        os.fsync(directory_fd)
        raise _error("attempt_ledger_invalid") from None
    return True


def _retire_inflight_file_at(
    directory_fd: int,
    name: str,
    descriptor: int,
    expected_identity: tuple[int, int],
    *,
    nonce: str,
    kind: str,
) -> str:
    """Move one inflight file out of the live grammar before destructive wiping."""

    temp_specs = {
        "marker": (f".attempt-inflight-stage-{nonce}-", _INFLIGHT_TEMP_RE),
        "stage_binding": (f".attempt-inflight-stage-binding-{nonce}-", _STAGE_BINDING_TEMP_RE),
        "cleanup_inventory": (f".attempt-inflight-cleanup-inventory-{nonce}-", _CLEANUP_INVENTORY_TEMP_RE),
        "cleanup_intent": (f".attempt-inflight-cleanup-intent-{nonce}-", _CLEANUP_INTENT_TEMP_RE),
    }
    if not isinstance(nonce, str) or re.fullmatch(r"[0-9a-f]{64}", nonce) is None or kind not in temp_specs:
        raise _error("attempt_ledger_invalid")
    try:
        opened = _require_pinned_private_file_at(
            directory_fd,
            name,
            descriptor,
            expected_identity,
            maximum=MAX_INFLIGHT_RECORD_BYTES,
        )
        parent = os.fstat(directory_fd)
        owner = os.geteuid() if hasattr(os, "geteuid") else opened.st_uid
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != owner or stat.S_IMODE(parent.st_mode) != 0o700:
            raise OSError
        prefix, temp_pattern = temp_specs[kind]
        temporary_name: str | None = None
        for _ in range(128):
            candidate = f"{prefix}{secrets.token_hex(32)}.tmp"
            if temp_pattern.fullmatch(candidate) is None:
                raise OSError
            try:
                _private_io._rename_noreplace_at(directory_fd, name, directory_fd, candidate)
            except FileExistsError:
                continue
            temporary_name = candidate
            break
        if temporary_name is None:
            raise OSError
        moved = os.stat(temporary_name, dir_fd=directory_fd, follow_symlinks=False)
        moved_mismatch = (
            not stat.S_ISREG(moved.st_mode)
            or stat.S_ISLNK(moved.st_mode)
            or moved.st_uid != owner
            or moved.st_nlink != 1
            or stat.S_IMODE(moved.st_mode) != 0o600
            or _regular_file_identity(moved) != expected_identity
        )
        if moved_mismatch:
            _preserve_mismatched_retirement_entry_at(
                directory_fd,
                temporary_name,
                name,
                expected_identity,
            )
            _wipe_authenticated_inflight_descriptor(descriptor, expected_identity)
            raise OSError
        try:
            os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise OSError
        os.fsync(directory_fd)
        try:
            return _wipe_and_quarantine_private_file_at(
                directory_fd,
                temporary_name,
                descriptor,
                expected_identity,
            )
        except BaseException:
            substituted = _preserve_mismatched_retirement_entry_at(
                directory_fd,
                temporary_name,
                name,
                expected_identity,
            )
            if substituted:
                _wipe_authenticated_inflight_descriptor(descriptor, expected_identity)
            raise
    except (EnronCapacityError, EnronPrivateIOError, OSError, ValueError):
        raise _error("attempt_ledger_invalid") from None


def _restore_mismatched_quarantine_at(
    directory_fd: int,
    quarantine_name: str,
    original_name: str,
    observed_identity: tuple[int, int],
) -> None:
    """Restore a raced substitute to its original name without overwriting another entry."""

    try:
        _private_io._rename_noreplace_at(directory_fd, quarantine_name, directory_fd, original_name)
        restored = os.stat(original_name, dir_fd=directory_fd, follow_symlinks=False)
        if _regular_file_identity(restored) != observed_identity:
            raise OSError
        os.fsync(directory_fd)
    except (EnronPrivateIOError, OSError, ValueError):
        # If the original name was raced back into existence, retaining both
        # entries is safer than overwriting or deleting either one.
        raise _error("attempt_ledger_invalid") from None


def _restore_mismatched_publication_at(
    directory_fd: int,
    published_name: str,
    staging_name: str,
) -> None:
    """Move a raced publication back to its absent staging name without overwriting."""

    try:
        published = os.stat(published_name, dir_fd=directory_fd, follow_symlinks=False)
        observed_identity = _regular_file_identity(published)
        _private_io._rename_noreplace_at(directory_fd, published_name, directory_fd, staging_name)
        restored = os.stat(staging_name, dir_fd=directory_fd, follow_symlinks=False)
        if _regular_file_identity(restored) != observed_identity:
            raise OSError
        os.fsync(directory_fd)
    except (EnronPrivateIOError, OSError, ValueError):
        # If either name was raced again, retain every extant entry and fail.
        raise OSError("Raced publication could not be restored safely.") from None


def _write_atomic_private_file_at(
    directory_fd: int,
    *,
    temporary_name: str,
    final_name: str,
    payload: bytes,
    durable_commit: bytearray | None = None,
) -> None:
    owner: _OwnedDescriptor | None = None
    try:
        owner = _write_locked_atomic_file_at(
            directory_fd,
            temporary_name=temporary_name,
            final_name=final_name,
            payload=payload,
            durable_commit=durable_commit,
        )
        descriptor = owner.fd
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        active_error = sys.exc_info()[1]
        cleanup_control = None if owner is None else _close_owned_descriptor_during_unwind(owner)
        if cleanup_control is not None and not isinstance(
            active_error,
            (KeyboardInterrupt, SystemExit, MemoryError),
        ):
            raise cleanup_control


def _bind_inflight_stage(inflight: _InflightAttempt, stage_dir: Path) -> None:
    descriptor = inflight.ledger.fd
    temporary_name: str | None = None
    try:
        inflight.ledger.assert_current()
        inflight.output_parent.assert_current(code="private_transaction_failed")
        final_name_hash = cast(str, inflight.record["output_name_sha256"])
        expected_stage_name = stage_dir.name
        if (
            _hash_bytes(_output_name_for_stage(expected_stage_name, inflight.stage_token).encode("utf-8"))
            != final_name_hash
            or _hash_bytes(expected_stage_name.encode("utf-8")) != inflight.record["stage_name_sha256"]
        ):
            raise _error("private_transaction_failed")
        info = os.stat(expected_stage_name, dir_fd=inflight.output_parent.fd, follow_symlinks=False)
        if not _safe_private_directory(info):
            raise _error("private_transaction_failed")
        binding = {
            "schema_version": CAPACITY_STAGE_BINDING_SCHEMA_VERSION,
            "attempt_sequence": inflight.record["attempt_sequence"],
            "attempt_nonce_sha256": _hash_bytes(inflight.nonce.encode("ascii")),
            "output_parent_device": inflight.output_parent.identity.device,
            "output_parent_inode": inflight.output_parent.identity.inode,
            "output_name_sha256": inflight.record["output_name_sha256"],
            "stage_name_sha256": inflight.record["stage_name_sha256"],
            "stage_device": int(info.st_dev),
            "stage_inode": int(info.st_ino),
        }
        _verify_stage_binding(binding, inflight.record)
        payload = _pretty_json_bytes(binding)
        if len(payload) > MAX_INFLIGHT_RECORD_BYTES:
            raise _error("attempt_ledger_write_failed")
        temporary_name = f".attempt-inflight-stage-binding-{inflight.nonce}-{secrets.token_hex(32)}.tmp"
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        _write_atomic_private_file_at(
            descriptor,
            temporary_name=temporary_name,
            final_name=inflight.binding_name,
            payload=payload,
        )
        temporary_name = None
        inflight.stage_binding = binding
        inflight.ledger.assert_current()
    except EnronCapacityError:
        raise
    except BaseException:
        raise _error("attempt_ledger_write_failed") from None
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        except OSError:
            pass


def _bind_inflight_cleanup_inventory(
    inflight: _InflightAttempt,
    identities: Sequence[tuple[int, int]],
) -> None:
    """Durably bind the complete registered payload inventory before promotion."""

    descriptor = inflight.ledger.fd
    temporary_name: str | None = None
    try:
        inflight.ledger.assert_current()
        inflight.output_parent.assert_current(code="private_transaction_failed")
        if inflight.stage_binding is None or inflight.cleanup_inventory is not None:
            raise _error("private_transaction_failed")
        normalized = sorted(set(identities))
        if len(normalized) != len(identities) or len(normalized) > _private_io._MAX_PINNED_CLEANUP_FILES:  # noqa: SLF001
            raise _error("private_transaction_failed")
        files = [{"device": device, "inode": inode} for device, inode in normalized]
        binding = inflight.stage_binding
        inventory: dict[str, Any] = {
            "schema_version": CAPACITY_CLEANUP_INVENTORY_SCHEMA_VERSION,
            "attempt_sequence": inflight.record["attempt_sequence"],
            "attempt_nonce_sha256": _hash_bytes(inflight.nonce.encode("ascii")),
            "output_parent_device": inflight.record["output_parent_device"],
            "output_parent_inode": inflight.record["output_parent_inode"],
            "output_name_sha256": inflight.record["output_name_sha256"],
            "stage_name_sha256": inflight.record["stage_name_sha256"],
            "stage_device": binding["stage_device"],
            "stage_inode": binding["stage_inode"],
            "files": files,
            "file_count": len(files),
            "inventory_sha256": "",
        }
        inventory["inventory_sha256"] = _canonical_hash(
            {key: value for key, value in inventory.items() if key != "inventory_sha256"}
        )
        _verify_cleanup_inventory(inventory, inflight.record, binding)
        payload = _pretty_json_bytes(inventory)
        if len(payload) > MAX_INFLIGHT_RECORD_BYTES:
            raise _error("attempt_ledger_write_failed")
        temporary_name = f".attempt-inflight-cleanup-inventory-{inflight.nonce}-{secrets.token_hex(32)}.tmp"
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        _write_atomic_private_file_at(
            descriptor,
            temporary_name=temporary_name,
            final_name=inflight.cleanup_inventory_name,
            payload=payload,
        )
        temporary_name = None
        inflight.cleanup_inventory = inventory
        inflight.ledger.assert_current()
    except EnronCapacityError:
        raise
    except BaseException:
        raise _error("attempt_ledger_write_failed") from None
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        except OSError:
            pass


def _output_name_for_stage(stage_name: str, stage_token: str) -> str:
    suffix = f".stage-{stage_token}"
    if not stage_name.startswith(".") or not stage_name.endswith(suffix):
        raise _error("private_transaction_failed")
    return stage_name[1 : -len(suffix)]


def _prepare_attempt_ledger(options: EnronCapacityOptions) -> _AttemptLedger:
    root = _absolute_private_path(options.attempt_ledger_dir)
    ledger: _AttemptLedger | None = None
    try:
        ledger = _AttemptLedger(root)
        fcntl.flock(ledger.fd, fcntl.LOCK_EX)
        _recover_ledger_temps_locked(ledger.fd)
        _recover_stale_inflight_attempts_locked(ledger, options)
        _read_attempt_receipts_locked(ledger.fd)
        fcntl.flock(ledger.fd, fcntl.LOCK_UN)
    except EnronCapacityError:
        if ledger is not None:
            ledger.close()
        raise
    except BaseException:
        if ledger is not None:
            ledger.close()
        raise _error("attempt_ledger_invalid") from None
    return ledger


def _require_inflight_retirement_headroom_locked(descriptor: int, nonce: str) -> None:
    """Reserve every zero tombstone required to retire one inflight attempt."""

    if not isinstance(nonce, str) or re.fullmatch(r"[0-9a-f]{64}", nonce) is None:
        raise _error("attempt_ledger_invalid")
    try:
        names = os.listdir(descriptor)
    except OSError:
        raise _error("attempt_ledger_invalid") from None
    marker_name = f".attempt-inflight-{nonce}.json"
    if marker_name not in names:
        raise _error("attempt_ledger_invalid")
    pending = 1
    pending += int(f".attempt-inflight-{nonce}.stage.json" in names)
    pending += int(f".attempt-inflight-{nonce}.cleanup.json" in names)
    pending += sum(
        1
        for name in names
        if (match := _CLEANUP_INTENT_NAME_RE.fullmatch(name)) is not None and match.group(1) == nonce
    )
    existing = sum(1 for name in names if _PRIVATE_TOMBSTONE_RE.fullmatch(name))
    if pending <= 0 or existing + pending > MAX_LEDGER_TOMBSTONES:
        raise _error("attempt_ledger_invalid")


def _append_attempt_receipt(
    ledger: _AttemptLedger,
    *,
    inflight: _InflightAttempt | None,
    options: EnronCapacityOptions,
    outcome: str,
    failure_code: str | None,
    execution: Mapping[str, Any] | None,
    metrics: _AttemptMetrics,
) -> dict[str, Any]:
    descriptor = ledger.fd
    receipt: dict[str, Any] | None = None
    durable_commit = bytearray(1)
    try:
        ledger.assert_current()
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        _recover_ledger_temps_locked(descriptor)
        existing = _read_attempt_receipts_locked(descriptor)
        if inflight is None:
            attempt_sequence = _next_attempt_sequence(existing, _read_inflight_records_locked(descriptor))
            attempt_nonce_sha256 = _hash_bytes(secrets.token_hex(32).encode("ascii"))
            identity: Mapping[str, Any] | None = execution
        else:
            _assert_inflight_marker_current(inflight)
            _require_inflight_retirement_headroom_locked(descriptor, inflight.nonce)
            attempt_sequence = int(inflight.record["attempt_sequence"])
            attempt_nonce_sha256 = _hash_bytes(inflight.nonce.encode("ascii"))
            identity = inflight.record
            if outcome != "passed":
                _publish_private_root_receipt_identity(metrics, inflight.stage_binding, inflight.output_parent)
        receipt = _make_attempt_receipt(
            existing,
            attempt_sequence=attempt_sequence,
            attempt_nonce_sha256=attempt_nonce_sha256,
            recovered_from_inflight=False,
            outcome=outcome,
            failure_code=failure_code,
            identity=identity,
            execution=execution,
            metrics=metrics,
        )
        _write_attempt_receipt_locked(descriptor, receipt, durable_commit)
        if inflight is not None:
            if not _reconcile_published_attempt_receipt_locked(
                descriptor,
                inflight,
                receipt,
                durable_commit,
                options=options,
            ):
                raise _error("attempt_ledger_write_failed")
        ledger.assert_current()
        return receipt
    except BaseException as exc:
        if receipt is not None and inflight is not None and not inflight.terminalized:
            try:
                _reconcile_published_attempt_receipt_locked(
                    descriptor,
                    inflight,
                    receipt,
                    durable_commit,
                    options=options,
                )
            except BaseException:
                pass
        if isinstance(exc, EnronCapacityError):
            raise
        raise _error("attempt_ledger_write_failed") from None
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        except OSError:
            pass


def _reconcile_published_attempt_receipt_locked(
    descriptor: int,
    inflight: _InflightAttempt,
    receipt: Mapping[str, Any],
    durable_commit: bytearray,
    *,
    options: EnronCapacityOptions,
) -> bool:
    """Make a durably published receipt authoritative before cleanup can branch."""

    if durable_commit != bytearray(b"\x01"):
        return False
    receipts = _read_attempt_receipts_locked(descriptor)
    if not receipts or receipts[-1] != receipt:
        return False

    def verify_output_boundary() -> None:
        if receipt.get("outcome") == "passed":
            _verify_recovered_promoted_output(
                inflight.output_parent.path / inflight.output_name,
                inflight.output_parent,
                inflight.record,
                receipt,
                inflight.stage_binding,
            )
        else:
            _verify_recovered_failed_output_absent(
                inflight.output_parent.path / inflight.output_name,
                inflight.output_parent,
                inflight.record,
                receipt,
                inflight.stage_binding,
                inflight.cleanup_intent,
                options=options,
            )

    verify_output_boundary()
    inflight.receipt_appended = True
    _remove_inflight_files_locked(inflight, before_marker_retirement=verify_output_boundary)
    inflight.terminalized = True
    return True


def _next_attempt_sequence(
    receipts: Sequence[Mapping[str, Any]],
    inflights: Sequence[tuple[str, Mapping[str, Any]]],
) -> int:
    return (
        max(
            (int(item["attempt_sequence"]) for item in (*receipts, *(record for _name, record in inflights))),
            default=0,
        )
        + 1
    )


def _validate_attempt_allocations(
    receipts: Sequence[Mapping[str, Any]],
    inflights: Sequence[tuple[str, Mapping[str, Any]]],
) -> None:
    terminal_by_sequence = {cast(int, item["attempt_sequence"]): item for item in receipts}
    terminal_by_nonce = {cast(str, item["attempt_nonce_sha256"]): item for item in receipts}
    for _name, record in inflights:
        sequence = cast(int, record["attempt_sequence"])
        nonce = _hash_bytes(cast(str, record["attempt_nonce"]).encode("ascii"))
        sequence_match = terminal_by_sequence.get(sequence)
        nonce_match = terminal_by_nonce.get(nonce)
        if (sequence_match is None) != (nonce_match is None) or (
            sequence_match is not None and sequence_match is not nonce_match
        ):
            raise _error("attempt_ledger_invalid")
    allocated = set(terminal_by_sequence)
    allocated.update(cast(int, record["attempt_sequence"]) for _name, record in inflights)
    if allocated and allocated != set(range(1, max(allocated) + 1)):
        raise _error("attempt_ledger_invalid")


def _make_attempt_receipt(
    existing: Sequence[Mapping[str, Any]],
    *,
    attempt_sequence: int,
    attempt_nonce_sha256: str,
    recovered_from_inflight: bool,
    outcome: str,
    failure_code: str | None,
    identity: Mapping[str, Any] | None,
    execution: Mapping[str, Any] | None,
    metrics: _AttemptMetrics,
) -> dict[str, Any]:
    previous = existing[-1]["attempt_sha256"] if existing else None
    sequence = len(existing) + 1
    git_commit = identity.get("executable_git_commit") if identity is not None else _git_head_or_none()
    implementation = (
        identity.get("capacity_implementation_sha256") if identity is not None else _implementation_sha256()
    )
    production = bool(identity.get("production_evidence")) if identity is not None else False
    execution_sha256 = (
        identity.get("execution_sha256")
        if identity is not None and "execution_sha256" in identity
        else (_canonical_hash(execution) if execution is not None else None)
    )
    sensitive_content_wiped, path_tree_removed, retained_tombstones = metrics.cleanup_evidence
    if outcome != "passed" and (
        sensitive_content_wiped is not True or path_tree_removed is not True or retained_tombstones != 0
    ):
        # Failed and interrupted attempts support a positive durable claim only
        # after complete tree removal with no retained writable tombstone.
        sensitive_content_wiped = False
    receipt: dict[str, Any] = {
        "schema_version": CAPACITY_ATTEMPT_SCHEMA_VERSION,
        "sequence": sequence,
        "attempt_sequence": attempt_sequence,
        "attempt_nonce_sha256": attempt_nonce_sha256,
        "recovered_from_inflight": recovered_from_inflight,
        "outcome": outcome,
        "failure_code": failure_code,
        "production_evidence": production,
        "executable_git_commit": git_commit,
        "capacity_implementation_sha256": implementation,
        "repository_tree_sha256": None if identity is None else identity.get("repository_tree_sha256"),
        "runtime_environment_sha256": None if identity is None else identity.get("runtime_environment_sha256"),
        "execution_sha256": execution_sha256,
        "policy_sha256": capacity_policy()["policy_sha256"],
        "report_sha256": metrics.report_sha256,
        "measurement_boundary": _ATTEMPT_MEASUREMENT_BOUNDARY,
        "elapsed_ns": metrics.elapsed_ns,
        "maximum_peak_rss_bytes": metrics.maximum_peak_rss_bytes,
        "peak_process_tree_rss_bytes": metrics.peak_process_tree_rss_bytes,
        "minimum_free_disk_bytes": metrics.minimum_free_disk_bytes,
        "resource_observation_count": metrics.resource_observation_count,
        "maximum_resource_observation_wall_gap_ns": metrics.maximum_resource_observation_wall_gap_ns,
        "final_owned_disk_bytes": metrics.final_owned_disk_bytes,
        "promoted_root_device": metrics.promoted_root_device,
        "promoted_root_inode": metrics.promoted_root_inode,
        "promoted_parent_device": metrics.promoted_parent_device,
        "promoted_parent_inode": metrics.promoted_parent_inode,
        "promoted_name_sha256": metrics.promoted_name_sha256,
        "preexisting_private_tombstone_count": metrics.preexisting_private_tombstone_count,
        "sensitive_content_wiped": sensitive_content_wiped,
        "path_tree_removed": path_tree_removed,
        "retained_private_tombstone_count": retained_tombstones,
        "previous_attempt_sha256": previous,
        "attempt_sha256": "",
    }
    receipt["attempt_sha256"] = _hash_attempt_receipt(receipt)
    _verify_attempt_receipt(receipt, expected_sequence=sequence, previous_sha256=cast(str | None, previous))
    return receipt


def _write_attempt_receipt_locked(
    descriptor: int,
    receipt: Mapping[str, Any],
    durable_commit: bytearray,
) -> None:
    if receipt.get("sensitive_content_wiped") is True and (
        receipt.get("path_tree_removed") is not True
        or type(receipt.get("retained_private_tombstone_count")) is not int
        or cast(int, receipt["retained_private_tombstone_count"]) != 0
    ):
        raise _error("attempt_ledger_write_failed")
    payload = _pretty_json_bytes(receipt)
    if len(payload) > MAX_ATTEMPT_RECEIPT_BYTES:
        raise _error("attempt_ledger_write_failed")
    sequence = int(receipt["sequence"])
    final_name = f"attempt-{sequence:08d}.json"
    temporary_name = f".attempt-stage-{secrets.token_hex(32)}.tmp"
    _write_atomic_private_file_at(
        descriptor,
        temporary_name=temporary_name,
        final_name=final_name,
        payload=payload,
        durable_commit=durable_commit,
    )


def _assert_inflight_marker_current(inflight: _InflightAttempt) -> None:
    marker_fd = inflight.marker_fd
    if marker_fd is None:
        raise _error("attempt_ledger_invalid")
    try:
        opened = os.fstat(marker_fd)
        current = os.stat(inflight.marker_name, dir_fd=inflight.ledger.fd, follow_symlinks=False)
    except OSError:
        raise _error("attempt_ledger_invalid") from None
    if (
        not stat.S_ISREG(opened.st_mode)
        or stat.S_ISLNK(current.st_mode)
        or opened.st_nlink != 1
        or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
        or not is_owner_only_private_mode(stat.S_IMODE(opened.st_mode))
    ):
        raise _error("attempt_ledger_invalid")
    _assert_inflight_marker_payload(marker_fd, inflight.record)


def _assert_inflight_marker_payload(descriptor: int, expected: Mapping[str, Any]) -> None:
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 0
            or before.st_size > MAX_INFLIGHT_RECORD_BYTES
            or not is_owner_only_private_mode(stat.S_IMODE(before.st_mode))
        ):
            raise OSError
        chunks: list[bytes] = []
        offset = 0
        remaining = MAX_INFLIGHT_RECORD_BYTES + 1
        while remaining > 0:
            chunk = os.pread(descriptor, min(remaining, 1024 * 1024), offset)
            if not chunk:
                break
            chunks.append(chunk)
            offset += len(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(payload) != before.st_size or (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise OSError
        record = _load_closed_json(payload, description="capacity inflight attempt")
        nonce = record.get("attempt_nonce")
        if not isinstance(nonce, str):
            raise OSError
        _verify_inflight_record(record, expected_nonce=nonce)
        if record != expected:
            raise OSError
    except (EnronCapacityError, OSError, TypeError, ValueError):
        raise _error("attempt_ledger_invalid") from None


def _open_pinned_private_file_at(
    directory_fd: int,
    name: str,
    *,
    maximum: int,
) -> tuple[int, bytes, tuple[int, int]]:
    descriptor: int | None = None
    try:
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(name, flags, dir_fd=directory_fd)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        opened = os.fstat(descriptor)
        identity = _regular_file_identity(opened)
        owner = os.geteuid() if hasattr(os, "geteuid") else opened.st_uid
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or before.st_uid != owner
            or opened.st_uid != owner
            or before.st_nlink != 1
            or opened.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or stat.S_IMODE(opened.st_mode) != 0o600
            or before.st_size < 0
            or before.st_size > maximum
            or _regular_file_identity(before) != identity
        ):
            raise OSError
        chunks: list[bytes] = []
        offset = 0
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.pread(descriptor, min(remaining, 1024 * 1024), offset)
            if not chunk:
                break
            chunks.append(chunk)
            offset += len(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        stable_fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        if (
            len(payload) != before.st_size
            or any(getattr(before, field) != getattr(opened, field) for field in stable_fields)
            or any(getattr(opened, field) != getattr(after, field) for field in stable_fields)
            or any(getattr(after, field) != getattr(current, field) for field in stable_fields)
        ):
            raise OSError
        result = descriptor, payload, identity
        descriptor = None
        return result
    except (BlockingIOError, OSError, ValueError):
        raise _error("attempt_ledger_invalid") from None
    finally:
        if descriptor is not None:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(descriptor)


def _remove_inflight_files_locked(
    inflight: _InflightAttempt,
    *,
    before_marker_retirement: Callable[[], None] | None = None,
) -> None:
    names = set(os.listdir(inflight.ledger.fd))
    intent_names = {
        name
        for name in names
        if (match := _CLEANUP_INTENT_NAME_RE.fullmatch(name)) is not None and match.group(1) == inflight.nonce
    }
    if inflight.marker_name not in names:
        if (
            not inflight.receipt_appended
            or inflight.binding_name in names
            or inflight.cleanup_inventory_name in names
            or intent_names
        ):
            raise _error("attempt_ledger_invalid")
        return
    _assert_inflight_marker_current(inflight)
    marker_fd = inflight.marker_fd
    if marker_fd is None:
        raise _error("attempt_ledger_invalid")
    if intent_names:
        if inflight.stage_binding is None:
            raise _error("attempt_ledger_invalid")
        chain = _read_cleanup_intent_chain(
            inflight.ledger.fd,
            inflight.record,
            inflight.stage_binding,
            inflight.cleanup_inventory,
        )
        if inflight.cleanup_intent is not None and chain[-1][1] != inflight.cleanup_intent:
            raise _error("attempt_ledger_invalid")
        for intent_name, expected_intent in reversed(chain):
            intent_fd, payload, intent_identity = _open_pinned_private_file_at(
                inflight.ledger.fd,
                intent_name,
                maximum=MAX_INFLIGHT_RECORD_BYTES,
            )
            try:
                cleanup_intent = _load_closed_json(payload, description="capacity cleanup intent")
                _verify_cleanup_intent(
                    cleanup_intent,
                    inflight.record,
                    inflight.stage_binding,
                    inflight.cleanup_inventory,
                )
                if cleanup_intent != expected_intent:
                    raise _error("attempt_ledger_invalid")
                _retire_inflight_file_at(
                    inflight.ledger.fd,
                    intent_name,
                    intent_fd,
                    intent_identity,
                    nonce=inflight.nonce,
                    kind="cleanup_intent",
                )
            finally:
                try:
                    fcntl.flock(intent_fd, fcntl.LOCK_UN)
                except OSError:
                    pass
                os.close(intent_fd)
    elif inflight.cleanup_intent is not None and not inflight.receipt_appended:
        raise _error("attempt_ledger_invalid")
    if inflight.cleanup_inventory_name in names:
        if inflight.stage_binding is None:
            raise _error("attempt_ledger_invalid")
        inventory_fd, payload, inventory_identity = _open_pinned_private_file_at(
            inflight.ledger.fd,
            inflight.cleanup_inventory_name,
            maximum=MAX_INFLIGHT_RECORD_BYTES,
        )
        try:
            cleanup_inventory = _load_closed_json(payload, description="capacity cleanup inventory")
            _verify_cleanup_inventory(cleanup_inventory, inflight.record, inflight.stage_binding)
            if inflight.cleanup_inventory is not None and cleanup_inventory != inflight.cleanup_inventory:
                raise _error("attempt_ledger_invalid")
            _retire_inflight_file_at(
                inflight.ledger.fd,
                inflight.cleanup_inventory_name,
                inventory_fd,
                inventory_identity,
                nonce=inflight.nonce,
                kind="cleanup_inventory",
            )
        finally:
            try:
                fcntl.flock(inventory_fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(inventory_fd)
    elif inflight.cleanup_inventory is not None and not inflight.receipt_appended:
        raise _error("attempt_ledger_invalid")
    if inflight.binding_name in names:
        binding_fd, payload, binding_identity = _open_pinned_private_file_at(
            inflight.ledger.fd,
            inflight.binding_name,
            maximum=MAX_INFLIGHT_RECORD_BYTES,
        )
        try:
            binding = _load_closed_json(payload, description="capacity stage binding")
            _verify_stage_binding(binding, inflight.record)
            if inflight.stage_binding is not None and binding != inflight.stage_binding:
                raise _error("attempt_ledger_invalid")
            _retire_inflight_file_at(
                inflight.ledger.fd,
                inflight.binding_name,
                binding_fd,
                binding_identity,
                nonce=inflight.nonce,
                kind="stage_binding",
            )
        finally:
            try:
                fcntl.flock(binding_fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(binding_fd)
    elif inflight.stage_binding is not None and not inflight.receipt_appended:
        raise _error("attempt_ledger_invalid")
    if before_marker_retirement is not None:
        before_marker_retirement()
    _retire_inflight_file_at(
        inflight.ledger.fd,
        inflight.marker_name,
        marker_fd,
        _regular_file_identity(os.fstat(marker_fd)),
        nonce=inflight.nonce,
        kind="marker",
    )


def verify_capacity_attempt_ledger(ledger_dir: Path) -> list[dict[str, Any]]:
    """Verify the immutable, privacy-safe aggregate attempt chain."""

    pinned: _PinnedDirectory | None = None
    try:
        pinned = _PinnedDirectory(ledger_dir)
        pinned.assert_current(code="attempt_ledger_invalid")
        fcntl.flock(pinned.fd, fcntl.LOCK_SH)
        receipts = _read_attempt_receipts_locked(pinned.fd)
        if _read_inflight_records_locked(pinned.fd):
            raise _error("attempt_ledger_invalid")
        return receipts
    except EnronCapacityError:
        raise
    except BaseException:
        raise _error("attempt_ledger_invalid") from None
    finally:
        if pinned is not None:
            try:
                fcntl.flock(pinned.fd, fcntl.LOCK_UN)
            except OSError:
                pass
            pinned.close()


def _read_attempt_receipts_locked(descriptor: int) -> list[dict[str, Any]]:
    try:
        _validate_ledger_inventory_locked(descriptor, allow_temps=False)
        names = sorted(name for name in os.listdir(descriptor) if _ATTEMPT_NAME_RE.fullmatch(name))
    except OSError:
        raise _error("attempt_ledger_invalid") from None
    receipts: list[dict[str, Any]] = []
    previous: str | None = None
    attempt_sequences: set[int] = set()
    attempt_nonces: set[str] = set()
    for expected_sequence, name in enumerate(names, start=1):
        match = _ATTEMPT_NAME_RE.fullmatch(name)
        if match is None or int(match.group(1)) != expected_sequence:
            raise _error("attempt_ledger_invalid")
        payload = _read_regular_private_file_at(descriptor, name, maximum=MAX_ATTEMPT_RECEIPT_BYTES)
        receipt = _load_closed_json(payload, description="attempt receipt")
        _verify_attempt_receipt(receipt, expected_sequence=expected_sequence, previous_sha256=previous)
        attempt_sequence = cast(int, receipt["attempt_sequence"])
        attempt_nonce = cast(str, receipt["attempt_nonce_sha256"])
        if (
            attempt_sequence != expected_sequence
            or attempt_sequence in attempt_sequences
            or attempt_nonce in attempt_nonces
        ):
            raise _error("attempt_ledger_invalid")
        attempt_sequences.add(attempt_sequence)
        attempt_nonces.add(attempt_nonce)
        previous = cast(str, receipt["attempt_sha256"])
        receipts.append(receipt)
    return receipts


def _recover_stale_attempt_temps_locked(descriptor: int) -> None:
    names = sorted(name for name in os.listdir(descriptor) if _ATTEMPT_TEMP_RE.fullmatch(name))
    if not names:
        return
    receipts = _read_attempt_receipts_locked_without_temps(descriptor)
    expected_sequence = len(receipts) + 1
    previous = receipts[-1]["attempt_sha256"] if receipts else None
    has_inflight = any(_INFLIGHT_NAME_RE.fullmatch(name) for name in os.listdir(descriptor))
    for name in names:
        stage_fd, payload, identity = _open_pinned_private_file_at(
            descriptor,
            name,
            maximum=MAX_ATTEMPT_RECEIPT_BYTES,
        )
        validation_error: EnronCapacityError | None = None
        try:
            try:
                receipt = _load_closed_json(payload, description="stale attempt receipt")
                _verify_attempt_receipt(receipt, expected_sequence=expected_sequence, previous_sha256=previous)
            except EnronCapacityError as exc:
                validation_error = exc
            _wipe_and_quarantine_private_file_at(descriptor, name, stage_fd, identity)
        finally:
            try:
                fcntl.flock(stage_fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(stage_fd)
        if validation_error is not None and not has_inflight:
            raise validation_error


def _read_attempt_receipts_locked_without_temps(descriptor: int) -> list[dict[str, Any]]:
    _validate_ledger_inventory_locked(descriptor, allow_temps=True)
    names = sorted(name for name in os.listdir(descriptor) if _ATTEMPT_NAME_RE.fullmatch(name))
    receipts: list[dict[str, Any]] = []
    previous: str | None = None
    attempt_sequences: set[int] = set()
    attempt_nonces: set[str] = set()
    for expected_sequence, name in enumerate(names, start=1):
        match = _ATTEMPT_NAME_RE.fullmatch(name)
        if match is None or int(match.group(1)) != expected_sequence:
            raise _error("attempt_ledger_invalid")
        payload = _read_regular_private_file_at(descriptor, name, maximum=MAX_ATTEMPT_RECEIPT_BYTES)
        receipt = _load_closed_json(payload, description="attempt receipt")
        _verify_attempt_receipt(receipt, expected_sequence=expected_sequence, previous_sha256=previous)
        attempt_sequence = cast(int, receipt["attempt_sequence"])
        attempt_nonce = cast(str, receipt["attempt_nonce_sha256"])
        if (
            attempt_sequence != expected_sequence
            or attempt_sequence in attempt_sequences
            or attempt_nonce in attempt_nonces
        ):
            raise _error("attempt_ledger_invalid")
        attempt_sequences.add(attempt_sequence)
        attempt_nonces.add(attempt_nonce)
        previous = cast(str, receipt["attempt_sha256"])
        receipts.append(receipt)
    return receipts


def _validate_ledger_inventory_locked(descriptor: int, *, allow_temps: bool) -> None:
    try:
        names = os.listdir(descriptor)
    except OSError:
        raise _error("attempt_ledger_invalid") from None
    markers = {
        cast(re.Match[str], _INFLIGHT_NAME_RE.fullmatch(name)).group(1)
        for name in names
        if _INFLIGHT_NAME_RE.fullmatch(name)
    }
    tombstones = [name for name in names if _PRIVATE_TOMBSTONE_RE.fullmatch(name)]
    if len(tombstones) > MAX_LEDGER_TOMBSTONES:
        raise _error("attempt_ledger_invalid")
    for name in names:
        binding = _STAGE_BINDING_NAME_RE.fullmatch(name)
        cleanup_inventory = _CLEANUP_INVENTORY_NAME_RE.fullmatch(name)
        cleanup_intent = _CLEANUP_INTENT_NAME_RE.fullmatch(name)
        if (
            _ATTEMPT_NAME_RE.fullmatch(name)
            or _INFLIGHT_NAME_RE.fullmatch(name)
            or (binding is not None and binding.group(1) in markers)
            or (cleanup_inventory is not None and cleanup_inventory.group(1) in markers)
            or (cleanup_intent is not None and cleanup_intent.group(1) in markers)
        ):
            continue
        if _PRIVATE_TOMBSTONE_RE.fullmatch(name):
            tombstone_fd, payload, _identity = _open_pinned_private_file_at(descriptor, name, maximum=0)
            try:
                if payload:
                    raise _error("attempt_ledger_invalid")
            finally:
                try:
                    fcntl.flock(tombstone_fd, fcntl.LOCK_UN)
                except OSError:
                    pass
                os.close(tombstone_fd)
            continue
        if allow_temps and (
            _ATTEMPT_TEMP_RE.fullmatch(name)
            or _INFLIGHT_TEMP_RE.fullmatch(name)
            or _STAGE_BINDING_TEMP_RE.fullmatch(name)
            or _CLEANUP_INVENTORY_TEMP_RE.fullmatch(name)
            or _CLEANUP_INTENT_TEMP_RE.fullmatch(name)
        ):
            continue
        raise _error("attempt_ledger_invalid")


def _verify_inflight_record(record: Mapping[str, Any], *, expected_nonce: str) -> None:
    _require_closed(
        record,
        {
            "schema_version",
            "attempt_sequence",
            "attempt_nonce",
            "owner_pid",
            "owner_identity_sha256",
            "started_monotonic_ns",
            "started_wall_monotonic_ns",
            "production_evidence",
            "executable_git_commit",
            "capacity_implementation_sha256",
            "repository_tree_sha256",
            "runtime_environment_sha256",
            "execution_sha256",
            "policy_sha256",
            "output_parent_device",
            "output_parent_inode",
            "output_name_sha256",
            "stage_token",
            "stage_name_sha256",
        },
        "capacity inflight attempt",
    )
    nonce = record.get("attempt_nonce")
    stage_token = record.get("stage_token")
    if (
        record.get("schema_version") != CAPACITY_INFLIGHT_SCHEMA_VERSION
        or nonce != expected_nonce
        or not isinstance(nonce, str)
        or re.fullmatch(r"[0-9a-f]{64}", nonce) is None
        or not isinstance(stage_token, str)
        or _STAGE_TOKEN_RE.fullmatch(stage_token) is None
        or stage_token != nonce[:24]
        or type(record.get("production_evidence")) is not bool
        or record.get("policy_sha256") != capacity_policy()["policy_sha256"]
    ):
        raise _error("attempt_ledger_invalid")
    for field in (
        "attempt_sequence",
        "owner_pid",
        "started_monotonic_ns",
        "started_wall_monotonic_ns",
        "output_parent_device",
        "output_parent_inode",
    ):
        value = record.get(field)
        minimum = 1 if field in {"attempt_sequence", "owner_pid"} else 0
        if type(value) is not int or int(value) < minimum or int(value) > _MAX_RESOURCE_INTEGER:
            raise _error("attempt_ledger_invalid")
    for field in (
        "owner_identity_sha256",
        "capacity_implementation_sha256",
        "repository_tree_sha256",
        "runtime_environment_sha256",
        "execution_sha256",
        "policy_sha256",
        "output_name_sha256",
        "stage_name_sha256",
    ):
        value = record.get(field)
        if not isinstance(value, str) or _HASH_RE.fullmatch(value) is None:
            raise _error("attempt_ledger_invalid")
    git_commit = record.get("executable_git_commit")
    if git_commit is not None and (not isinstance(git_commit, str) or _GIT_COMMIT_RE.fullmatch(git_commit) is None):
        raise _error("attempt_ledger_invalid")
    expected_owner = _canonical_hash(
        {
            "attempt_nonce": nonce,
            "owner_pid": record["owner_pid"],
            "started_wall_monotonic_ns": record["started_wall_monotonic_ns"],
            "capacity_implementation_sha256": record["capacity_implementation_sha256"],
        }
    )
    if record.get("owner_identity_sha256") != expected_owner:
        raise _error("attempt_ledger_invalid")


def _verify_stage_binding(binding: Mapping[str, Any], inflight: Mapping[str, Any]) -> None:
    _require_closed(
        binding,
        {
            "schema_version",
            "attempt_sequence",
            "attempt_nonce_sha256",
            "output_parent_device",
            "output_parent_inode",
            "output_name_sha256",
            "stage_name_sha256",
            "stage_device",
            "stage_inode",
        },
        "capacity stage binding",
    )
    if (
        binding.get("schema_version") != CAPACITY_STAGE_BINDING_SCHEMA_VERSION
        or binding.get("attempt_sequence") != inflight.get("attempt_sequence")
        or binding.get("attempt_nonce_sha256") != _hash_bytes(cast(str, inflight.get("attempt_nonce")).encode("ascii"))
        or binding.get("output_parent_device") != inflight.get("output_parent_device")
        or binding.get("output_parent_inode") != inflight.get("output_parent_inode")
        or binding.get("output_name_sha256") != inflight.get("output_name_sha256")
        or binding.get("stage_name_sha256") != inflight.get("stage_name_sha256")
    ):
        raise _error("attempt_ledger_invalid")
    for field in ("stage_device", "stage_inode"):
        value = binding.get(field)
        if type(value) is not int or int(value) < 0 or int(value) > _MAX_RESOURCE_INTEGER:
            raise _error("attempt_ledger_invalid")
    nonce_hash = binding.get("attempt_nonce_sha256")
    if not isinstance(nonce_hash, str) or _HASH_RE.fullmatch(nonce_hash) is None:
        raise _error("attempt_ledger_invalid")


def _verify_cleanup_inventory(
    inventory: Mapping[str, Any],
    inflight: Mapping[str, Any],
    binding: Mapping[str, Any],
) -> None:
    _require_closed(
        inventory,
        {
            "schema_version",
            "attempt_sequence",
            "attempt_nonce_sha256",
            "output_parent_device",
            "output_parent_inode",
            "output_name_sha256",
            "stage_name_sha256",
            "stage_device",
            "stage_inode",
            "files",
            "file_count",
            "inventory_sha256",
        },
        "capacity cleanup inventory",
    )
    if (
        inventory.get("schema_version") != CAPACITY_CLEANUP_INVENTORY_SCHEMA_VERSION
        or inventory.get("attempt_sequence") != inflight.get("attempt_sequence")
        or inventory.get("attempt_nonce_sha256")
        != _hash_bytes(cast(str, inflight.get("attempt_nonce")).encode("ascii"))
        or inventory.get("output_parent_device") != inflight.get("output_parent_device")
        or inventory.get("output_parent_inode") != inflight.get("output_parent_inode")
        or inventory.get("output_name_sha256") != inflight.get("output_name_sha256")
        or inventory.get("stage_name_sha256") != inflight.get("stage_name_sha256")
        or inventory.get("stage_device") != binding.get("stage_device")
        or inventory.get("stage_inode") != binding.get("stage_inode")
    ):
        raise _error("attempt_ledger_invalid")
    files = inventory.get("files")
    if not isinstance(files, list) or len(files) > _private_io._MAX_PINNED_CLEANUP_FILES:  # noqa: SLF001
        raise _error("attempt_ledger_invalid")
    normalized: list[tuple[int, int]] = []
    for item in files:
        if not isinstance(item, Mapping):
            raise _error("attempt_ledger_invalid")
        _require_closed(item, {"device", "inode"}, "capacity cleanup inventory file")
        device = item.get("device")
        inode = item.get("inode")
        if (
            type(device) is not int
            or type(inode) is not int
            or device < 0
            or inode < 0
            or device > _MAX_RESOURCE_INTEGER
            or inode > _MAX_RESOURCE_INTEGER
        ):
            raise _error("attempt_ledger_invalid")
        normalized.append((device, inode))
    if (
        normalized != sorted(set(normalized))
        or inventory.get("file_count") != len(normalized)
        or inventory.get("inventory_sha256")
        != _canonical_hash({key: value for key, value in inventory.items() if key != "inventory_sha256"})
    ):
        raise _error("attempt_ledger_invalid")


def _verify_cleanup_intent(
    intent: Mapping[str, Any],
    inflight: Mapping[str, Any],
    binding: Mapping[str, Any],
    inventory: Mapping[str, Any] | None,
) -> None:
    _require_closed(
        intent,
        {
            "schema_version",
            "attempt_sequence",
            "attempt_nonce_sha256",
            "output_parent_device",
            "output_parent_inode",
            "output_name_sha256",
            "stage_name_sha256",
            "stage_device",
            "stage_inode",
            "cleanup_inventory_sha256",
            "generation",
            "previous_intent_sha256",
            "complete_tombstone_name_sha256",
            "incomplete_tombstone_name_sha256",
            "intent_sha256",
        },
        "capacity cleanup intent",
    )
    if (
        intent.get("schema_version") != CAPACITY_CLEANUP_INTENT_SCHEMA_VERSION
        or intent.get("attempt_sequence") != inflight.get("attempt_sequence")
        or intent.get("attempt_nonce_sha256") != _hash_bytes(cast(str, inflight.get("attempt_nonce")).encode("ascii"))
        or intent.get("output_parent_device") != inflight.get("output_parent_device")
        or intent.get("output_parent_inode") != inflight.get("output_parent_inode")
        or intent.get("output_name_sha256") != inflight.get("output_name_sha256")
        or intent.get("stage_name_sha256") != inflight.get("stage_name_sha256")
        or intent.get("stage_device") != binding.get("stage_device")
        or intent.get("stage_inode") != binding.get("stage_inode")
        or intent.get("cleanup_inventory_sha256") != (None if inventory is None else inventory.get("inventory_sha256"))
    ):
        raise _error("attempt_ledger_invalid")
    complete_name_hash = intent.get("complete_tombstone_name_sha256")
    incomplete_name_hash = intent.get("incomplete_tombstone_name_sha256")
    generation = intent.get("generation")
    previous_intent_sha256 = intent.get("previous_intent_sha256")
    if (
        type(generation) is not int
        or generation <= 0
        or generation > _MAX_RESOURCE_INTEGER
        or (
            previous_intent_sha256 is not None
            and (not isinstance(previous_intent_sha256, str) or _HASH_RE.fullmatch(previous_intent_sha256) is None)
        )
        or not isinstance(complete_name_hash, str)
        or _HASH_RE.fullmatch(complete_name_hash) is None
        or not isinstance(incomplete_name_hash, str)
        or _HASH_RE.fullmatch(incomplete_name_hash) is None
        or complete_name_hash == incomplete_name_hash
        or intent.get("intent_sha256")
        != _canonical_hash({key: value for key, value in intent.items() if key != "intent_sha256"})
    ):
        raise _error("attempt_ledger_invalid")


def _read_inflight_records_locked(descriptor: int) -> list[tuple[str, dict[str, Any]]]:
    _validate_ledger_inventory_locked(descriptor, allow_temps=False)
    result: list[tuple[str, dict[str, Any]]] = []
    sequences: set[int] = set()
    names = set(os.listdir(descriptor))
    for name in sorted(names):
        match = _INFLIGHT_NAME_RE.fullmatch(name)
        if match is None:
            continue
        payload = _read_regular_private_file_at(descriptor, name, maximum=MAX_INFLIGHT_RECORD_BYTES)
        record = _load_closed_json(payload, description="capacity inflight attempt")
        _verify_inflight_record(record, expected_nonce=match.group(1))
        sequence = cast(int, record["attempt_sequence"])
        if sequence in sequences:
            raise _error("attempt_ledger_invalid")
        sequences.add(sequence)
        binding_name = f".attempt-inflight-{match.group(1)}.stage.json"
        binding: dict[str, Any] | None = None
        if binding_name in names:
            binding_payload = _read_regular_private_file_at(
                descriptor,
                binding_name,
                maximum=MAX_INFLIGHT_RECORD_BYTES,
            )
            binding = _load_closed_json(binding_payload, description="capacity stage binding")
            _verify_stage_binding(binding, record)
        cleanup_name = f".attempt-inflight-{match.group(1)}.cleanup.json"
        cleanup_inventory: dict[str, Any] | None = None
        if cleanup_name in names:
            if binding is None:
                raise _error("attempt_ledger_invalid")
            cleanup_payload = _read_regular_private_file_at(
                descriptor,
                cleanup_name,
                maximum=MAX_INFLIGHT_RECORD_BYTES,
            )
            cleanup_inventory = _load_closed_json(cleanup_payload, description="capacity cleanup inventory")
            _verify_cleanup_inventory(cleanup_inventory, record, binding)
        _read_cleanup_intent_chain(descriptor, record, binding, cleanup_inventory)
        result.append((name, record))
    return result


def _recover_ledger_temps_locked(descriptor: int) -> None:
    _recover_stale_attempt_temps_locked(descriptor)
    names = sorted(
        name
        for name in os.listdir(descriptor)
        if _INFLIGHT_TEMP_RE.fullmatch(name)
        or _STAGE_BINDING_TEMP_RE.fullmatch(name)
        or _CLEANUP_INVENTORY_TEMP_RE.fullmatch(name)
        or _CLEANUP_INTENT_TEMP_RE.fullmatch(name)
    )
    for name in names:
        stage_fd, _payload, identity = _open_pinned_private_file_at(
            descriptor,
            name,
            maximum=MAX_INFLIGHT_RECORD_BYTES,
        )
        try:
            _wipe_and_quarantine_private_file_at(descriptor, name, stage_fd, identity)
        finally:
            try:
                fcntl.flock(stage_fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(stage_fd)


def _recover_stale_inflight_attempts_locked(ledger: _AttemptLedger, options: EnronCapacityOptions) -> None:
    descriptor = ledger.fd
    try:
        _private_io._retry_unresolved_cleanup_descriptors()  # noqa: SLF001
    except EnronPrivateIOError:
        raise _error("attempt_ledger_invalid") from None
    receipts = _read_attempt_receipts_locked(descriptor)
    inflights = _read_inflight_records_locked(descriptor)
    _validate_attempt_allocations(receipts, inflights)
    for marker_name, record in inflights:
        marker: _OwnedDescriptor | None = None
        output_parent: _PinnedDirectory | None = None
        try:
            marker = _open_owned_existing_private_file_descriptor(marker_name, dir_fd=descriptor)
            marker_fd = marker.fd
            opened = os.fstat(marker_fd)
            current = os.stat(marker_name, dir_fd=descriptor, follow_symlinks=False)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
                or not is_owner_only_private_mode(stat.S_IMODE(opened.st_mode))
            ):
                raise _error("attempt_ledger_invalid")
            try:
                fcntl.flock(marker_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise _error("attempt_ledger_invalid") from None
            _assert_inflight_marker_payload(marker_fd, record)
            final_dir, output_parent = _recovery_output_parent(options, record)
            binding = _read_stage_binding_if_present(descriptor, record)
            cleanup_inventory = _read_cleanup_inventory_if_present(descriptor, record, binding)
            cleanup_intent = _read_cleanup_intent_if_present(
                descriptor,
                record,
                binding,
                cleanup_inventory,
            )
            nonce_sha256 = _hash_bytes(cast(str, record["attempt_nonce"]).encode("ascii"))
            matching = [item for item in receipts if item["attempt_nonce_sha256"] == nonce_sha256]
            if len(matching) > 1:
                raise _error("attempt_ledger_invalid")
            if matching:
                terminal = matching[0]
                if terminal["attempt_sequence"] != record["attempt_sequence"]:
                    raise _error("attempt_ledger_invalid")
                if terminal["outcome"] == "passed" and cleanup_intent is not None:
                    raise _error("attempt_ledger_invalid")
            else:
                cleanup_evidence = _cleanup_recovered_stage(
                    final_dir,
                    output_parent,
                    record,
                    binding,
                    cleanup_inventory,
                    cleanup_intent,
                    attempt_ledger_fd=descriptor,
                    options=options,
                )
                metrics = _AttemptMetrics(
                    started_ns=cast(int, record["started_monotonic_ns"]),
                    elapsed_ns=max(0, time.monotonic_ns() - cast(int, record["started_wall_monotonic_ns"])),
                    cleanup_evidence=cleanup_evidence,
                )
                _publish_private_root_receipt_identity(metrics, binding, output_parent)
                _require_inflight_retirement_headroom_locked(descriptor, cast(str, record["attempt_nonce"]))
                recovered = _make_attempt_receipt(
                    receipts,
                    attempt_sequence=cast(int, record["attempt_sequence"]),
                    attempt_nonce_sha256=nonce_sha256,
                    recovered_from_inflight=True,
                    outcome="interrupted",
                    failure_code="phase_interrupted",
                    identity=record,
                    execution=None,
                    metrics=metrics,
                )
                durable_commit = bytearray(1)
                _write_attempt_receipt_locked(descriptor, recovered, durable_commit)
                if durable_commit != bytearray(b"\x01"):
                    raise _error("attempt_ledger_write_failed")
                receipts.append(recovered)
                terminal = recovered
            cleanup_intent = _read_cleanup_intent_if_present(
                descriptor,
                record,
                binding,
                cleanup_inventory,
            )
            recovered_attempt = _InflightAttempt(
                ledger=ledger,
                record=dict(record),
                marker_name=marker_name,
                marker=marker,
                output_parent=output_parent,
                output_name=final_dir.name,
                stage_binding=None if binding is None else dict(binding),
                cleanup_inventory=None if cleanup_inventory is None else dict(cleanup_inventory),
                cleanup_intent=None if cleanup_intent is None else dict(cleanup_intent),
            )
            marker = None
            output_parent = None
            try:

                def verify_recovered_output_boundary() -> None:
                    if terminal["outcome"] == "passed":
                        _verify_recovered_promoted_output(
                            final_dir,
                            recovered_attempt.output_parent,
                            record,
                            terminal,
                            recovered_attempt.stage_binding,
                        )
                    else:
                        _verify_recovered_failed_output_absent(
                            final_dir,
                            recovered_attempt.output_parent,
                            record,
                            terminal,
                            recovered_attempt.stage_binding,
                            recovered_attempt.cleanup_intent,
                            options=options,
                        )

                verify_recovered_output_boundary()
                _remove_inflight_files_locked(
                    recovered_attempt,
                    before_marker_retirement=verify_recovered_output_boundary,
                )
                recovered_attempt.terminalized = True
            finally:
                recovered_attempt.close()
        finally:
            active_error = sys.exc_info()[1]
            cleanup_control = active_error if isinstance(active_error, (KeyboardInterrupt, SystemExit)) else None
            while marker is not None and not marker.closed:
                try:
                    marker.close()
                except (KeyboardInterrupt, SystemExit) as exc:
                    if cleanup_control is None:
                        cleanup_control = exc
            while output_parent is not None and not output_parent.closed:
                try:
                    output_parent.close()
                except (KeyboardInterrupt, SystemExit) as exc:
                    if cleanup_control is None:
                        cleanup_control = exc
            if cleanup_control is not None and cleanup_control is not active_error:
                raise cleanup_control


def _recovery_output_parent(
    options: EnronCapacityOptions,
    record: Mapping[str, Any],
) -> tuple[Path, _PinnedDirectory]:
    final_dir = _absolute_private_path(options.output_dir)
    if _hash_bytes(final_dir.name.encode("utf-8")) != record.get("output_name_sha256"):
        raise _error("attempt_ledger_invalid")
    expected_stage_name = f".{final_dir.name}.stage-{record.get('stage_token')}"
    if _hash_bytes(expected_stage_name.encode("utf-8")) != record.get("stage_name_sha256"):
        raise _error("attempt_ledger_invalid")
    # Recovery may find the recorded parent after permission drift. Open only
    # its final component through the durable identity binding, restoring that
    # authenticated inode to 0700 before any child is inspected or renamed.
    expected_parent_identity = (
        cast(int, record["output_parent_device"]),
        cast(int, record["output_parent_inode"]),
    )
    parent = _PinnedDirectory(
        final_dir.parent,
        recovery_final_identity=expected_parent_identity,
    )
    if (parent.identity.device, parent.identity.inode) != expected_parent_identity:
        parent.close()
        raise _error("attempt_ledger_invalid")
    return final_dir, parent


def _read_stage_binding_if_present(
    descriptor: int,
    record: Mapping[str, Any],
) -> Mapping[str, Any] | None:
    nonce = cast(str, record["attempt_nonce"])
    name = f".attempt-inflight-{nonce}.stage.json"
    if name not in os.listdir(descriptor):
        return None
    payload = _read_regular_private_file_at(descriptor, name, maximum=MAX_INFLIGHT_RECORD_BYTES)
    binding = _load_closed_json(payload, description="capacity stage binding")
    _verify_stage_binding(binding, record)
    return binding


def _read_cleanup_inventory_if_present(
    descriptor: int,
    record: Mapping[str, Any],
    binding: Mapping[str, Any] | None,
) -> Mapping[str, Any] | None:
    nonce = cast(str, record["attempt_nonce"])
    name = f".attempt-inflight-{nonce}.cleanup.json"
    if name not in os.listdir(descriptor):
        return None
    if binding is None:
        raise _error("attempt_ledger_invalid")
    payload = _read_regular_private_file_at(descriptor, name, maximum=MAX_INFLIGHT_RECORD_BYTES)
    inventory = _load_closed_json(payload, description="capacity cleanup inventory")
    _verify_cleanup_inventory(inventory, record, binding)
    return inventory


def _read_cleanup_intent_chain(
    descriptor: int,
    record: Mapping[str, Any],
    binding: Mapping[str, Any] | None,
    cleanup_inventory: Mapping[str, Any] | None,
) -> list[tuple[str, dict[str, Any]]]:
    nonce = cast(str, record["attempt_nonce"])
    names = sorted(
        name
        for name in os.listdir(descriptor)
        if (match := _CLEANUP_INTENT_NAME_RE.fullmatch(name)) is not None and match.group(1) == nonce
    )
    if not names:
        return []
    if binding is None:
        raise _error("attempt_ledger_invalid")
    if len(names) > MAX_CLEANUP_INTENT_GENERATIONS:
        raise _error("attempt_ledger_invalid")
    chain: list[tuple[str, dict[str, Any]]] = []
    for name in names:
        payload = _read_regular_private_file_at(descriptor, name, maximum=MAX_INFLIGHT_RECORD_BYTES)
        intent = _load_closed_json(payload, description="capacity cleanup intent")
        _verify_cleanup_intent(intent, record, binding, cleanup_inventory)
        chain.append((name, intent))
    chain.sort(key=lambda item: cast(int, item[1]["generation"]))
    previous: str | None = None
    for expected_generation, (_name, intent) in enumerate(chain, start=1):
        if intent["generation"] != expected_generation or intent["previous_intent_sha256"] != previous:
            raise _error("attempt_ledger_invalid")
        previous = cast(str, intent["intent_sha256"])
    return chain


def _read_cleanup_intent_if_present(
    descriptor: int,
    record: Mapping[str, Any],
    binding: Mapping[str, Any] | None,
    cleanup_inventory: Mapping[str, Any] | None,
) -> Mapping[str, Any] | None:
    chain = _read_cleanup_intent_chain(descriptor, record, binding, cleanup_inventory)
    return None if not chain else chain[-1][1]


def _install_cleanup_intent_locked(
    descriptor: int,
    output_parent: _PinnedDirectory,
    record: Mapping[str, Any],
    binding: Mapping[str, Any],
    cleanup_inventory: Mapping[str, Any] | None,
    prior_intent: Mapping[str, Any] | None,
) -> tuple[dict[str, Any], str, str]:
    """Commit unpredictable cleanup names before exposing either name in the output parent."""

    if prior_intent is None:
        generation = 1
        previous_intent_sha256 = None
    else:
        _verify_cleanup_intent(prior_intent, record, binding, cleanup_inventory)
        prior_generation = cast(int, prior_intent["generation"])
        if prior_generation >= MAX_CLEANUP_INTENT_GENERATIONS:
            raise _error("attempt_ledger_invalid")
        generation = prior_generation + 1
        previous_intent_sha256 = cast(str, prior_intent["intent_sha256"])
    parent_info = os.fstat(output_parent.fd)
    owner = os.geteuid() if hasattr(os, "geteuid") else parent_info.st_uid
    if (
        not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != owner
        or (int(parent_info.st_dev), int(parent_info.st_ino))
        != (output_parent.identity.device, output_parent.identity.inode)
    ):
        raise _error("attempt_ledger_invalid")
    complete_name: str | None = None
    incomplete_name: str | None = None
    for _ in range(128):
        candidate_complete = f".nerb-cleanup-{secrets.token_hex(24)}"
        candidate_incomplete = f".nerb-cleanup-{secrets.token_hex(24)}"
        if candidate_complete == candidate_incomplete:
            continue
        collision = False
        for candidate in (candidate_complete, candidate_incomplete):
            try:
                os.stat(candidate, dir_fd=output_parent.fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            except OSError:
                raise _error("attempt_ledger_invalid") from None
            collision = True
            break
        if not collision:
            complete_name = candidate_complete
            incomplete_name = candidate_incomplete
            break
    if complete_name is None or incomplete_name is None:
        raise _error("attempt_ledger_invalid")
    intent: dict[str, Any] = {
        "schema_version": CAPACITY_CLEANUP_INTENT_SCHEMA_VERSION,
        "attempt_sequence": record["attempt_sequence"],
        "attempt_nonce_sha256": _hash_bytes(cast(str, record["attempt_nonce"]).encode("ascii")),
        "output_parent_device": record["output_parent_device"],
        "output_parent_inode": record["output_parent_inode"],
        "output_name_sha256": record["output_name_sha256"],
        "stage_name_sha256": record["stage_name_sha256"],
        "stage_device": binding["stage_device"],
        "stage_inode": binding["stage_inode"],
        "cleanup_inventory_sha256": (None if cleanup_inventory is None else cleanup_inventory["inventory_sha256"]),
        "generation": generation,
        "previous_intent_sha256": previous_intent_sha256,
        "complete_tombstone_name_sha256": _hash_bytes(complete_name.encode("ascii")),
        "incomplete_tombstone_name_sha256": _hash_bytes(incomplete_name.encode("ascii")),
        "intent_sha256": "",
    }
    intent["intent_sha256"] = _canonical_hash({key: value for key, value in intent.items() if key != "intent_sha256"})
    _verify_cleanup_intent(intent, record, binding, cleanup_inventory)
    payload = _pretty_json_bytes(intent)
    if len(payload) > MAX_INFLIGHT_RECORD_BYTES:
        raise _error("attempt_ledger_write_failed")
    nonce = cast(str, record["attempt_nonce"])
    intent_token = secrets.token_hex(32)
    _write_atomic_private_file_at(
        descriptor,
        temporary_name=f".attempt-inflight-cleanup-intent-{nonce}-{intent_token}.tmp",
        final_name=f".attempt-inflight-{nonce}.cleanup-intent-{intent_token}.json",
        payload=payload,
    )
    after = os.fstat(output_parent.fd)
    if (
        not stat.S_ISDIR(after.st_mode)
        or after.st_uid != owner
        or (int(after.st_dev), int(after.st_ino)) != (output_parent.identity.device, output_parent.identity.inode)
    ):
        raise _error("attempt_ledger_invalid")
    return intent, complete_name, incomplete_name


def _entry_identity_at(parent_fd: int, name: str) -> tuple[int, int] | None:
    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError:
        raise _error("attempt_ledger_invalid") from None
    if not _safe_private_directory(info):
        raise _error("attempt_ledger_invalid")
    return int(info.st_dev), int(info.st_ino)


@dataclass(frozen=True, slots=True)
class _RecoveryEntrySnapshot:
    identity: tuple[int, int]
    is_owned_directory: bool
    is_private_directory: bool


def _recovery_entry_snapshot_at(parent_fd: int, name: str) -> _RecoveryEntrySnapshot | None:
    """Classify one recovery name without making policy drift hide a bound inode."""

    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError:
        raise _error("attempt_ledger_invalid") from None
    owner = os.geteuid() if hasattr(os, "geteuid") else info.st_uid
    is_owned_directory = stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_uid == owner
    return _RecoveryEntrySnapshot(
        identity=(int(info.st_dev), int(info.st_ino)),
        is_owned_directory=is_owned_directory,
        is_private_directory=_safe_private_directory(info),
    )


def _recovery_tombstone_names(
    parent_fd: int,
    cleanup_intent: Mapping[str, Any] | None,
    expected_identity: tuple[int, int] | None = None,
    *,
    canonical_names: tuple[str, ...] = (),
) -> tuple[str | None, str | None, bool, tuple[str, ...]]:
    """Stably discover committed names and every parent name bound to the stage inode."""

    complete_hash = None if cleanup_intent is None else cast(str, cleanup_intent["complete_tombstone_name_sha256"])
    incomplete_hash = None if cleanup_intent is None else cast(str, cleanup_intent["incomplete_tombstone_name_sha256"])
    committed_hashes = frozenset(value for value in (complete_hash, incomplete_hash) if value is not None)
    complete_name: str | None = None
    incomplete_name: str | None = None
    bound_names: list[str] = []
    scan_valid = True

    def parent_state() -> tuple[int, int, int, int, int, int, int, int]:
        info = os.fstat(parent_fd)
        owner = os.geteuid() if hasattr(os, "geteuid") else info.st_uid
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner:
            raise OSError
        return (
            int(info.st_dev),
            int(info.st_ino),
            int(info.st_mode),
            int(info.st_uid),
            int(info.st_nlink),
            int(info.st_size),
            int(info.st_mtime_ns),
            int(info.st_ctime_ns),
        )

    before_parent: tuple[int, ...] | None = None
    try:
        before_parent = parent_state()
        with os.scandir(parent_fd) as entries:
            for entry_count, entry in enumerate(entries, start=1):
                if entry_count > MAX_RECOVERY_OUTPUT_PARENT_ENTRIES:
                    scan_valid = False
                    break
                name = entry.name
                tombstone_digest = (
                    _hash_bytes(name.encode("ascii")) if _PRIVATE_TOMBSTONE_RE.fullmatch(name) is not None else None
                )
                committed_name = tombstone_digest in committed_hashes
                possible_bound = False
                if expected_identity is not None:
                    try:
                        possible_bound = int(entry.inode()) == expected_identity[1]
                    except (OSError, TypeError, ValueError):
                        scan_valid = False
                        continue
                if possible_bound or committed_name or name in canonical_names:
                    try:
                        snapshot = _recovery_entry_snapshot_at(parent_fd, name)
                    except EnronCapacityError:
                        scan_valid = False
                        continue
                    if snapshot is None:
                        scan_valid = False
                        continue
                    if expected_identity is not None and snapshot.identity == expected_identity:
                        if len(bound_names) < 2:
                            bound_names.append(name)
                        scan_valid = scan_valid and len(bound_names) == 1
                if tombstone_digest is not None:
                    if complete_hash is not None and tombstone_digest == complete_hash:
                        if complete_name is not None:
                            scan_valid = False
                        else:
                            complete_name = name
                    if incomplete_hash is not None and tombstone_digest == incomplete_hash:
                        if incomplete_name is not None:
                            scan_valid = False
                        else:
                            incomplete_name = name
    except EnronCapacityError:
        scan_valid = False
    except OSError:
        scan_valid = False
    try:
        scan_valid = scan_valid and before_parent is not None and parent_state() == before_parent
    except OSError:
        scan_valid = False
    return complete_name, incomplete_name, scan_valid, tuple(bound_names)


def _cleanup_recovered_stage(
    final_dir: Path,
    output_parent: _PinnedDirectory,
    record: Mapping[str, Any],
    binding: Mapping[str, Any] | None,
    cleanup_inventory: Mapping[str, Any] | None,
    cleanup_intent: Mapping[str, Any] | None,
    *,
    attempt_ledger_fd: int,
    options: EnronCapacityOptions,
) -> tuple[bool | None, bool | None, int]:
    stage_name = f".{final_dir.name}.stage-{record['stage_token']}"
    expected = None if binding is None else (cast(int, binding["stage_device"]), cast(int, binding["stage_inode"]))
    (
        complete_tombstone_name,
        incomplete_tombstone_name,
        tombstone_inventory_valid,
        bound_tombstone_names,
    ) = _recovery_tombstone_names(
        output_parent.fd,
        cleanup_intent,
        expected,
        canonical_names=(stage_name, final_dir.name),
    )
    published_tombstone_names = tuple(
        name for name in (complete_tombstone_name, incomplete_tombstone_name) if name is not None
    )
    if binding is None:
        stage_identity = _entry_identity_at(output_parent.fd, stage_name)
        final_identity = _entry_identity_at(output_parent.fd, final_dir.name)
        if cleanup_inventory is not None or cleanup_intent is not None:
            raise _error("attempt_ledger_invalid")
        if final_identity is not None:
            raise _error("attempt_ledger_invalid")
        if stage_identity is not None:
            return _remove_empty_unbound_stage(
                output_parent,
                stage_name,
                expected_identity=stage_identity,
                options=options,
            )
        return None, None, 0
    expected_identity = cast(tuple[int, int], expected)
    expected_files = (
        set()
        if cleanup_inventory is None
        else {
            (cast(int, item["device"]), cast(int, item["inode"]))
            for item in cast(Sequence[Mapping[str, Any]], cleanup_inventory["files"])
        }
    )
    tracked_names = tuple(
        dict.fromkeys(
            (
                stage_name,
                final_dir.name,
                *published_tombstone_names,
                *bound_tombstone_names,
            )
        )
    )
    observed: list[tuple[str, _RecoveryEntrySnapshot]] = []
    observation_failed = False
    for name in tracked_names:
        try:
            snapshot = _recovery_entry_snapshot_at(output_parent.fd, name)
        except EnronCapacityError:
            observation_failed = True
            continue
        if snapshot is not None:
            observed.append((name, snapshot))
    matching = [
        (name, snapshot) for name, snapshot in observed if snapshot.identity == expected and snapshot.is_owned_directory
    ]
    policy_invalid = (
        not tombstone_inventory_valid
        or observation_failed
        or len(matching) > 1
        or any(snapshot.identity != expected or not snapshot.is_private_directory for _name, snapshot in observed)
    )
    if matching:
        candidate: _OwnedDescriptor | None = None
        try:
            candidate_name, _snapshot = matching[0]
            candidate_is_canonical = candidate_name in {stage_name, final_dir.name}
            candidate_is_private_tombstone = _PRIVATE_TOMBSTONE_RE.fullmatch(candidate_name) is not None
            candidate_is_committed_tombstone = candidate_name in published_tombstone_names
            candidate = _open_owned_recovery_directory_descriptor(
                candidate_name,
                dir_fd=output_parent.fd,
                expected_identity=expected_identity,
            )
            candidate_info = os.fstat(candidate.fd)
            owner = os.geteuid() if hasattr(os, "geteuid") else candidate_info.st_uid
            if (
                not stat.S_ISDIR(candidate_info.st_mode)
                or stat.S_ISLNK(candidate_info.st_mode)
                or candidate_info.st_uid != owner
                or (candidate_info.st_dev, candidate_info.st_ino) != expected_identity
            ):
                raise _error("attempt_ledger_invalid")
            policy_invalid = policy_invalid or not _safe_private_directory(candidate_info)
            if not candidate_is_canonical:
                # A valid uncommitted tombstone with no intent, or the exact
                # tombstone committed by the current intent, can terminalize.
                # Every other relabel is policy-invalid, but the authenticated
                # inode is still wiped before that violation is reported.
                removed = _private_io._wipe_and_quarantine_pinned_private_directory(  # noqa: SLF001
                    candidate.fd,
                    output_parent.fd,
                    output_parent.path,
                    candidate_name,
                    expected_identity,
                    workspace_root=options.workspace_root,
                    allow_unignored_output=options.allow_unignored_output,
                    quarantine=False,
                    maximum_tree_depth=_private_io._MAX_PRIVATE_TREE_DEPTH,  # noqa: SLF001
                    maximum_tree_entries=_private_io._MAX_PRIVATE_TREE_ENTRIES,  # noqa: SLF001
                )
                selected_tombstone_name = candidate_name
                policy_invalid = policy_invalid or removed[1] is not False or removed[2] != 0
                policy_invalid = (
                    policy_invalid
                    or not candidate_is_private_tombstone
                    or (cleanup_intent is not None and not candidate_is_committed_tombstone)
                )
            else:
                # Cleanup intent generations never authorize an arbitrary
                # source name. A canonical stage/final root may commit a new
                # unpredictable destination and then move only that pinned
                # inode into the committed namespace.
                cleanup_intent, complete_name, incomplete_name = _install_cleanup_intent_locked(
                    attempt_ledger_fd,
                    output_parent,
                    record,
                    binding,
                    cleanup_inventory,
                    cleanup_intent,
                )
                complete_tombstone_name = complete_name
                incomplete_tombstone_name = incomplete_name
                tracked_names = tuple(
                    dict.fromkeys(
                        (
                            stage_name,
                            final_dir.name,
                            *published_tombstone_names,
                            complete_tombstone_name,
                            incomplete_tombstone_name,
                            *bound_tombstone_names,
                        )
                    )
                )
                if cleanup_inventory is None:
                    removed = _private_io._wipe_and_quarantine_pinned_private_directory(  # noqa: SLF001
                        candidate.fd,
                        output_parent.fd,
                        output_parent.path,
                        candidate_name,
                        expected_identity,
                        workspace_root=options.workspace_root,
                        allow_unignored_output=options.allow_unignored_output,
                        quarantine=True,
                        quarantine_name=complete_tombstone_name,
                        maximum_tree_depth=_private_io._MAX_PRIVATE_TREE_DEPTH,  # noqa: SLF001
                        maximum_tree_entries=_private_io._MAX_PRIVATE_TREE_ENTRIES,  # noqa: SLF001
                    )
                    selected_tombstone_name = complete_tombstone_name
                else:
                    removed = _private_io._wipe_and_quarantine_pinned_private_directory_with_inventory(  # noqa: SLF001
                        candidate.fd,
                        output_parent.fd,
                        output_parent.path,
                        candidate_name,
                        expected_identity,
                        expected_files,
                        workspace_root=options.workspace_root,
                        allow_unignored_output=options.allow_unignored_output,
                        quarantine=True,
                        complete_quarantine_name=complete_tombstone_name,
                        incomplete_quarantine_name=incomplete_tombstone_name,
                        allow_complete_quarantine=cleanup_intent["generation"] == 1,
                    )
                    selected_tombstone_name = complete_tombstone_name if removed[0] else incomplete_tombstone_name
                policy_invalid = policy_invalid or removed[1] is not False or removed[2] != 1
            for name in tracked_names:
                try:
                    snapshot = _recovery_entry_snapshot_at(output_parent.fd, name)
                except EnronCapacityError:
                    policy_invalid = True
                    continue
                if name == selected_tombstone_name:
                    policy_invalid = policy_invalid or (
                        snapshot is None or snapshot.identity != expected_identity or not snapshot.is_private_directory
                    )
                else:
                    policy_invalid = policy_invalid or snapshot is not None
            _post_complete, _post_incomplete, post_scan_valid, post_bound_names = _recovery_tombstone_names(
                output_parent.fd,
                cleanup_intent,
                expected_identity,
                canonical_names=(stage_name, final_dir.name),
            )
            policy_invalid = policy_invalid or not post_scan_valid or post_bound_names != (selected_tombstone_name,)
            if policy_invalid:
                raise _error("attempt_ledger_invalid")
            candidate.close()
            candidate = None
            # Crash recovery retains a writable tombstone after this helper
            # returns. Its empty state cannot be held through the separate
            # durable receipt commit, so recovery must not publish positive
            # wipe evidence even when this call completed every cleanup step.
            return False, False, 1
        except EnronCapacityError:
            raise
        except EnronPrivateIOError:
            raise _error("attempt_ledger_invalid") from None
        except OSError:
            raise _error("attempt_ledger_invalid") from None
        finally:
            if candidate is not None:
                candidate.close()
    if policy_invalid:
        raise _error("attempt_ledger_invalid")
    if cleanup_intent is not None:
        # A durable intent with neither its committed tombstone nor the bound
        # source name is evidence of an external rename, not a clean absence.
        raise _error("attempt_ledger_invalid")
    # A durable stage binding remains authoritative even if its inode was
    # renamed outside every bounded recovery name. Do not terminalize and
    # discard the only durable identity needed for a later owner-controlled
    # recovery.
    raise _error("attempt_ledger_invalid")


def _remove_empty_unbound_stage(
    output_parent: _PinnedDirectory,
    name: str,
    *,
    expected_identity: tuple[int, int],
    options: EnronCapacityOptions,
) -> tuple[bool, bool, int]:
    candidate: _PinnedDirectory | None = None
    try:
        candidate = _PinnedDirectory(output_parent.path / name)
        output_parent.assert_current(code="attempt_ledger_invalid")
        try:
            with os.scandir(candidate.fd) as entries:
                has_entry = next(entries, None) is not None
        except OSError:
            raise _error("attempt_ledger_invalid") from None
        if (candidate.identity.device, candidate.identity.inode) != expected_identity or has_entry:
            raise _error("attempt_ledger_invalid")
        candidate.assert_current(code="attempt_ledger_invalid")
        removed = _remove_pinned_directory(
            candidate,
            workspace_root=options.workspace_root,
            allow_unignored_output=options.allow_unignored_output,
            maximum_tree_depth=_private_io._MAX_PRIVATE_TREE_DEPTH,  # noqa: SLF001
            maximum_tree_entries=_private_io._MAX_PRIVATE_TREE_ENTRIES,  # noqa: SLF001
        )
        return False, removed[1], removed[2]
    except EnronCapacityError:
        raise
    except OSError:
        raise _error("attempt_ledger_invalid") from None
    finally:
        if candidate is not None:
            candidate.close()


def _remove_recovery_directory(
    output_parent: _PinnedDirectory,
    name: str,
    *,
    expected_identity: tuple[int, int] | None,
    options: EnronCapacityOptions,
) -> tuple[bool, bool, int]:
    candidate = _PinnedDirectory(output_parent.path / name)
    try:
        if expected_identity is not None and (candidate.identity.device, candidate.identity.inode) != expected_identity:
            raise _error("attempt_ledger_invalid")
        removed = _remove_pinned_directory(
            candidate,
            workspace_root=options.workspace_root,
            allow_unignored_output=options.allow_unignored_output,
            maximum_tree_depth=_private_io._MAX_PRIVATE_TREE_DEPTH,  # noqa: SLF001
            maximum_tree_entries=_private_io._MAX_PRIVATE_TREE_ENTRIES,  # noqa: SLF001
        )
        return False, removed[1], removed[2]
    except EnronCapacityError:
        candidate.close()
        raise _error("attempt_ledger_invalid") from None


def _verify_recovered_promoted_output(
    final_dir: Path,
    output_parent: _PinnedDirectory,
    record: Mapping[str, Any],
    receipt: Mapping[str, Any],
    binding: Mapping[str, Any] | None,
) -> None:
    if _entry_identity_at(output_parent.fd, f".{final_dir.name}.stage-{record['stage_token']}") is not None:
        raise _error("attempt_ledger_invalid")
    final_identity = _entry_identity_at(output_parent.fd, final_dir.name)
    expected = (
        (cast(int, receipt["promoted_root_device"]), cast(int, receipt["promoted_root_inode"]))
        if binding is None
        else (cast(int, binding["stage_device"]), cast(int, binding["stage_inode"]))
    )
    if (
        final_identity != expected
        or receipt.get("promoted_root_device") != expected[0]
        or receipt.get("promoted_root_inode") != expected[1]
        or receipt.get("promoted_parent_device") != output_parent.identity.device
        or receipt.get("promoted_parent_inode") != output_parent.identity.inode
        or receipt.get("promoted_name_sha256") != _hash_bytes(final_dir.name.encode("utf-8"))
    ):
        raise _error("attempt_ledger_invalid")


def _verify_recovered_failed_output_absent(
    final_dir: Path,
    output_parent: _PinnedDirectory,
    record: Mapping[str, Any],
    receipt: Mapping[str, Any],
    binding: Mapping[str, Any] | None,
    cleanup_intent: Mapping[str, Any] | None,
    *,
    options: EnronCapacityOptions,
) -> None:
    """Re-wipe and verify the exact failed-attempt root before retirement."""

    output_parent.assert_current(code="attempt_ledger_invalid")
    stage_name = f".{final_dir.name}.stage-{record['stage_token']}"
    receipt_identity_values = receipt.get("promoted_root_device"), receipt.get("promoted_root_inode")
    receipt_parent_values = receipt.get("promoted_parent_device"), receipt.get("promoted_parent_inode")
    receipt_identity_valid = all(type(value) is int and value >= 0 for value in receipt_identity_values)
    receipt_parent_valid = all(type(value) is int and value >= 0 for value in receipt_parent_values)
    receipt_identity = cast(tuple[int, int], receipt_identity_values) if receipt_identity_valid else None
    binding_identity = (
        None if binding is None else (cast(int, binding["stage_device"]), cast(int, binding["stage_inode"]))
    )
    policy_invalid = (
        receipt_identity_valid != receipt_parent_valid
        or (receipt_identity is None and receipt_identity_values != (None, None))
        or (not receipt_parent_valid and receipt_parent_values != (None, None))
        or (
            receipt_parent_valid
            and receipt_parent_values != (output_parent.identity.device, output_parent.identity.inode)
        )
        or (binding_identity is not None and receipt_identity != binding_identity)
    )
    expected_identity = binding_identity if binding_identity is not None else receipt_identity
    complete_name, incomplete_name, scan_valid, bound_names = _recovery_tombstone_names(
        output_parent.fd,
        cleanup_intent,
        expected_identity,
        canonical_names=(stage_name, final_dir.name),
    )
    policy_invalid = policy_invalid or not scan_valid or len(bound_names) > 1
    tracked_names = tuple(
        dict.fromkeys(name for name in (stage_name, final_dir.name, complete_name, incomplete_name) if name is not None)
    )
    for name in tracked_names:
        try:
            snapshot = _recovery_entry_snapshot_at(output_parent.fd, name)
        except EnronCapacityError:
            policy_invalid = True
            continue
        if snapshot is None:
            continue
        if name in {stage_name, final_dir.name}:
            policy_invalid = True
        elif expected_identity is None or snapshot.identity != expected_identity:
            policy_invalid = True
    if expected_identity is None:
        if policy_invalid:
            raise _error("attempt_ledger_invalid")
        return
    if not bound_names:
        if (
            policy_invalid
            or receipt.get("path_tree_removed") is not True
            or receipt.get("retained_private_tombstone_count") != 0
        ):
            raise _error("attempt_ledger_invalid")
        return

    candidate_name = bound_names[0]
    candidate: _OwnedDescriptor | None = None
    try:
        try:
            initial = _recovery_entry_snapshot_at(output_parent.fd, candidate_name)
        except EnronCapacityError:
            initial = None
            policy_invalid = True
        if initial is None or initial.identity != expected_identity or not initial.is_owned_directory:
            raise _error("attempt_ledger_invalid")
        policy_invalid = policy_invalid or not initial.is_private_directory
        policy_invalid = policy_invalid or _PRIVATE_TOMBSTONE_RE.fullmatch(candidate_name) is None
        policy_invalid = policy_invalid or (
            receipt.get("sensitive_content_wiped") is not False
            or receipt.get("path_tree_removed") is not False
            or receipt.get("retained_private_tombstone_count") != 1
        )
        candidate = _open_owned_recovery_directory_descriptor(
            candidate_name,
            dir_fd=output_parent.fd,
            expected_identity=expected_identity,
        )
        opened = os.fstat(candidate.fd)
        owner = os.geteuid() if hasattr(os, "geteuid") else opened.st_uid
        if (
            not stat.S_ISDIR(opened.st_mode)
            or stat.S_ISLNK(opened.st_mode)
            or opened.st_uid != owner
            or (int(opened.st_dev), int(opened.st_ino)) != expected_identity
        ):
            raise _error("attempt_ledger_invalid")
        removed = _private_io._wipe_and_quarantine_pinned_private_directory(  # noqa: SLF001
            candidate.fd,
            output_parent.fd,
            output_parent.path,
            candidate_name,
            expected_identity,
            workspace_root=options.workspace_root,
            allow_unignored_output=options.allow_unignored_output,
            quarantine=False,
            maximum_tree_depth=_private_io._MAX_PRIVATE_TREE_DEPTH,  # noqa: SLF001
            maximum_tree_entries=_private_io._MAX_PRIVATE_TREE_ENTRIES,  # noqa: SLF001
        )
        policy_invalid = policy_invalid or removed != (True, False, 0)
        post_complete, post_incomplete, post_scan_valid, post_bound_names = _recovery_tombstone_names(
            output_parent.fd,
            cleanup_intent,
            expected_identity,
            canonical_names=(stage_name, final_dir.name),
        )
        policy_invalid = policy_invalid or not post_scan_valid or post_bound_names != (candidate_name,)
        post_tracked_names = tuple(
            dict.fromkeys(
                name for name in (stage_name, final_dir.name, post_complete, post_incomplete) if name is not None
            )
        )
        for name in post_tracked_names:
            try:
                snapshot = _recovery_entry_snapshot_at(output_parent.fd, name)
            except EnronCapacityError:
                policy_invalid = True
                continue
            if snapshot is None:
                continue
            if name in {stage_name, final_dir.name} or snapshot.identity != expected_identity:
                policy_invalid = True
        try:
            final_snapshot = _recovery_entry_snapshot_at(output_parent.fd, candidate_name)
            payload_bytes = _logical_tree_bytes(candidate.fd, depth=0, entries=[0])
        except EnronCapacityError:
            final_snapshot = None
            payload_bytes = -1
        policy_invalid = policy_invalid or (
            final_snapshot is None
            or final_snapshot.identity != expected_identity
            or not final_snapshot.is_private_directory
            or payload_bytes != 0
        )
        if policy_invalid:
            raise _error("attempt_ledger_invalid")
    except EnronCapacityError:
        raise
    except (EnronPrivateIOError, OSError):
        raise _error("attempt_ledger_invalid") from None
    finally:
        if candidate is not None:
            candidate.close()


def _verify_attempt_receipt(
    receipt: Mapping[str, Any],
    *,
    expected_sequence: int,
    previous_sha256: str | None,
) -> None:
    _require_closed(
        receipt,
        {
            "schema_version",
            "sequence",
            "attempt_sequence",
            "attempt_nonce_sha256",
            "recovered_from_inflight",
            "outcome",
            "failure_code",
            "production_evidence",
            "executable_git_commit",
            "capacity_implementation_sha256",
            "repository_tree_sha256",
            "runtime_environment_sha256",
            "execution_sha256",
            "policy_sha256",
            "report_sha256",
            "measurement_boundary",
            "elapsed_ns",
            "maximum_peak_rss_bytes",
            "peak_process_tree_rss_bytes",
            "minimum_free_disk_bytes",
            "resource_observation_count",
            "maximum_resource_observation_wall_gap_ns",
            "final_owned_disk_bytes",
            "promoted_root_device",
            "promoted_root_inode",
            "promoted_parent_device",
            "promoted_parent_inode",
            "promoted_name_sha256",
            "preexisting_private_tombstone_count",
            "sensitive_content_wiped",
            "path_tree_removed",
            "retained_private_tombstone_count",
            "previous_attempt_sha256",
            "attempt_sha256",
        },
        "attempt receipt",
    )
    if (
        receipt.get("schema_version") != CAPACITY_ATTEMPT_SCHEMA_VERSION
        or receipt.get("sequence") != expected_sequence
        or receipt.get("previous_attempt_sha256") != previous_sha256
        or receipt.get("measurement_boundary") != _ATTEMPT_MEASUREMENT_BOUNDARY
        or type(receipt.get("production_evidence")) is not bool
        or type(receipt.get("recovered_from_inflight")) is not bool
        or type(receipt.get("attempt_sequence")) is not int
        or int(receipt["attempt_sequence"]) <= 0
    ):
        raise _error("attempt_ledger_invalid")
    for field in (
        "attempt_nonce_sha256",
        "capacity_implementation_sha256",
        "policy_sha256",
        "attempt_sha256",
    ):
        value = receipt.get(field)
        if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
            raise _error("attempt_ledger_invalid")
    git_commit = receipt.get("executable_git_commit")
    if git_commit is not None and (not isinstance(git_commit, str) or not _GIT_COMMIT_RE.fullmatch(git_commit)):
        raise _error("attempt_ledger_invalid")
    report_sha = receipt.get("report_sha256")
    if report_sha is not None and (not isinstance(report_sha, str) or not _HASH_RE.fullmatch(report_sha)):
        raise _error("attempt_ledger_invalid")
    for field in (
        "elapsed_ns",
        "maximum_peak_rss_bytes",
        "peak_process_tree_rss_bytes",
        "minimum_free_disk_bytes",
        "resource_observation_count",
        "maximum_resource_observation_wall_gap_ns",
        "final_owned_disk_bytes",
        "promoted_root_device",
        "promoted_root_inode",
        "promoted_parent_device",
        "promoted_parent_inode",
        "preexisting_private_tombstone_count",
    ):
        value = receipt.get(field)
        if value is not None and (type(value) is not int or value < 0):
            raise _error("attempt_ledger_invalid")
    private_root_identity = tuple(
        receipt.get(field)
        for field in (
            "promoted_root_device",
            "promoted_root_inode",
            "promoted_parent_device",
            "promoted_parent_inode",
        )
    )
    if any(value is None for value in private_root_identity) and any(
        value is not None for value in private_root_identity
    ):
        raise _error("attempt_ledger_invalid")
    for field in ("sensitive_content_wiped", "path_tree_removed"):
        if receipt.get(field) is not None and type(receipt[field]) is not bool:
            raise _error("attempt_ledger_invalid")
    retained_tombstones = receipt.get("retained_private_tombstone_count")
    if (
        type(retained_tombstones) is not int
        or retained_tombstones < 0
        or retained_tombstones > MAX_RETAINED_PRIVATE_TOMBSTONES
        or (retained_tombstones > 0 and receipt.get("path_tree_removed") is not False)
        or (receipt.get("path_tree_removed") is True and retained_tombstones != 0)
    ):
        raise _error("attempt_ledger_invalid")
    preexisting_tombstones = receipt.get("preexisting_private_tombstone_count")
    if preexisting_tombstones is not None and preexisting_tombstones > MAX_RETAINED_PRIVATE_TOMBSTONES:
        raise _error("attempt_ledger_invalid")
    outcome = receipt.get("outcome")
    failure_code = receipt.get("failure_code")
    if outcome == "passed":
        if (
            failure_code is not None
            or report_sha is None
            or receipt.get("elapsed_ns") is None
            or receipt.get("maximum_peak_rss_bytes") is None
            or receipt.get("peak_process_tree_rss_bytes") is None
            or receipt.get("minimum_free_disk_bytes") is None
            or receipt.get("resource_observation_count") is None
            or receipt.get("maximum_resource_observation_wall_gap_ns") is None
            or receipt.get("final_owned_disk_bytes") is None
            or receipt.get("promoted_root_device") is None
            or receipt.get("promoted_root_inode") is None
            or receipt.get("promoted_parent_device") is None
            or receipt.get("promoted_parent_inode") is None
            or receipt.get("promoted_name_sha256") is None
            or receipt.get("preexisting_private_tombstone_count") is None
            or receipt.get("sensitive_content_wiped") is not None
            or receipt.get("path_tree_removed") is not None
            or retained_tombstones != 0
            or int(receipt["elapsed_ns"]) > MAX_TOTAL_RUNTIME_NS
            or int(receipt["maximum_peak_rss_bytes"]) > MAX_ABSOLUTE_RSS_BYTES
            or int(receipt["peak_process_tree_rss_bytes"]) > int(receipt["maximum_peak_rss_bytes"])
            or int(receipt["minimum_free_disk_bytes"]) < MIN_RUNTIME_FREE_DISK_BYTES
            or int(receipt["resource_observation_count"]) <= 0
            or int(receipt["maximum_resource_observation_wall_gap_ns"]) > MAX_RESOURCE_OBSERVATION_WALL_GAP_NS
            or int(receipt["final_owned_disk_bytes"]) > MAX_OWNED_DISK_BYTES
        ):
            raise _error("attempt_ledger_invalid")
    elif outcome in {"failed", "interrupted"}:
        if not isinstance(failure_code, str) or failure_code not in _ERROR_MESSAGES:
            raise _error("attempt_ledger_invalid")
        if outcome == "interrupted" and failure_code != "phase_interrupted":
            raise _error("attempt_ledger_invalid")
    else:
        raise _error("attempt_ledger_invalid")
    if receipt.get("recovered_from_inflight") is True and (
        outcome != "interrupted" or failure_code != "phase_interrupted" or report_sha is not None
    ):
        raise _error("attempt_ledger_invalid")
    if receipt.get("production_evidence") is True and git_commit is None:
        raise _error("attempt_ledger_invalid")
    for field in ("repository_tree_sha256", "runtime_environment_sha256", "execution_sha256"):
        value = receipt.get(field)
        if value is not None and (not isinstance(value, str) or not _HASH_RE.fullmatch(value)):
            raise _error("attempt_ledger_invalid")
    promoted_name = receipt.get("promoted_name_sha256")
    if promoted_name is not None and (not isinstance(promoted_name, str) or not _HASH_RE.fullmatch(promoted_name)):
        raise _error("attempt_ledger_invalid")
    if outcome == "passed" and any(
        receipt.get(field) is None
        for field in ("repository_tree_sha256", "runtime_environment_sha256", "execution_sha256")
    ):
        raise _error("attempt_ledger_invalid")
    if receipt.get("attempt_sha256") != _hash_attempt_receipt(receipt):
        raise _error("attempt_ledger_invalid")


def _hash_attempt_receipt(receipt: Mapping[str, Any]) -> str:
    return _canonical_hash({key: value for key, value in receipt.items() if key != "attempt_sha256"})


def _git_head_or_none() -> str | None:
    try:
        return _git_head()
    except EnronCapacityError:
        return None


def _remove_pinned_directory(
    pinned: _PinnedDirectory,
    *,
    workspace_root: Path | None,
    allow_unignored_output: bool,
    cleanup_boundary: _private_io._PrevalidatedCleanupBoundary | None = None,  # noqa: SLF001
    effective_workspace_root: Path | None = None,
    maximum_tree_depth: int | None = None,
    maximum_tree_entries: int | None = None,
    cleanup_result_observer: Callable[[tuple[bool, bool, int]], None] | None = None,
) -> tuple[bool, bool, int]:
    try:
        result = _private_io._wipe_and_quarantine_pinned_private_directory(  # noqa: SLF001
            pinned.fd,
            pinned.parent_fd,
            pinned.path.parent,
            pinned.name,
            (pinned.identity.device, pinned.identity.inode),
            workspace_root=workspace_root,
            allow_unignored_output=allow_unignored_output,
            cleanup_boundary=cleanup_boundary,
            effective_workspace_root=effective_workspace_root,
            maximum_tree_depth=maximum_tree_depth,
            maximum_tree_entries=maximum_tree_entries,
        )
        if cleanup_result_observer is not None:
            cleanup_result_observer(result)
        return result
    except EnronCapacityError:
        raise
    except EnronPrivateIOError:
        raise _error("promotion_failed") from None
    except OSError:
        raise _error("promotion_failed") from None
    finally:
        pinned.close()


def verify_capacity_run(
    run_dir: Path,
    attempt_ledger_dir: Path,
    *,
    require_production: bool = True,
) -> dict[str, Any]:
    """Verify terminal decision evidence from one pinned run and ledger."""

    return verify_capacity_decision(
        run_dir,
        attempt_ledger_dir,
        require_production=require_production,
    )


def _evidence_state(info: os.stat_result) -> tuple[int, int, int, int, int, int, int, int, int]:
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_mode),
        int(info.st_uid),
        int(info.st_gid),
        int(info.st_nlink),
        int(info.st_size),
        int(info.st_mtime_ns),
        int(info.st_ctime_ns),
    )


def _read_pinned_evidence_bytes(descriptor: int, *, maximum: int) -> bytes:
    chunks: list[bytes] = []
    offset = 0
    remaining = maximum + 1
    while remaining > 0:
        chunk = os.pread(descriptor, min(remaining, 1024 * 1024), offset)
        if not chunk:
            break
        chunks.append(chunk)
        offset += len(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


@dataclass(slots=True)
class _DecisionEvidenceFile:
    directory_fd: int
    name: str
    payload: bytes
    state: tuple[int, int, int, int, int, int, int, int, int]
    descriptor: int | None

    def assert_current(self, *, code: str) -> None:
        descriptor = self.descriptor
        close_after = descriptor is None
        try:
            if descriptor is None:
                descriptor = os.open(
                    self.name,
                    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=self.directory_fd,
                )
            opened_before = os.fstat(descriptor)
            current_before = os.stat(self.name, dir_fd=self.directory_fd, follow_symlinks=False)
            if _evidence_state(opened_before) != self.state or _evidence_state(current_before) != self.state:
                raise OSError
            payload = _read_pinned_evidence_bytes(descriptor, maximum=len(self.payload))
            opened_after = os.fstat(descriptor)
            current_after = os.stat(self.name, dir_fd=self.directory_fd, follow_symlinks=False)
            if (
                payload != self.payload
                or _evidence_state(opened_after) != self.state
                or _evidence_state(current_after) != self.state
            ):
                raise OSError
        except OSError:
            raise _error(code) from None
        finally:
            if close_after and descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def close(self) -> None:
        if self.descriptor is None:
            return
        try:
            os.close(self.descriptor)
        except OSError:
            pass
        self.descriptor = None


@dataclass(slots=True)
class _PinnedDecisionSources:
    report: _DecisionEvidenceFile
    marker: _DecisionEvidenceFile
    receipts: tuple[_DecisionEvidenceFile, ...]
    ledger_inventory: tuple[str, ...]
    run_directory_state: tuple[int, int, int, int, int, int, int, int, int]
    ledger_directory_state: tuple[int, int, int, int, int, int, int, int, int]

    def assert_current(self, run: _PinnedDirectory, ledger: _PinnedDirectory, *, code: str) -> None:
        try:
            run.assert_current(code=code)
            ledger.assert_current(code=code)
            if (
                _evidence_state(os.fstat(run.fd)) != self.run_directory_state
                or _evidence_state(os.fstat(ledger.fd)) != self.ledger_directory_state
            ):
                raise OSError
            self.report.assert_current(code=code)
            self.marker.assert_current(code=code)
            for receipt in self.receipts:
                receipt.assert_current(code=code)
            if tuple(sorted(os.listdir(ledger.fd))) != self.ledger_inventory:
                raise OSError
            _validate_ledger_inventory_locked(ledger.fd, allow_temps=False)
            if (
                _evidence_state(os.fstat(run.fd)) != self.run_directory_state
                or _evidence_state(os.fstat(ledger.fd)) != self.ledger_directory_state
            ):
                raise OSError
            run.assert_current(code=code)
            ledger.assert_current(code=code)
        except EnronCapacityError as exc:
            if exc.code == code:
                raise
            raise _error(code) from None
        except OSError:
            raise _error(code) from None

    def close(self) -> None:
        self.report.close()
        self.marker.close()
        for receipt in self.receipts:
            receipt.close()


def _pin_decision_evidence_file(
    directory_fd: int,
    name: str,
    *,
    maximum: int,
    retain_descriptor: bool,
    code: str,
) -> _DecisionEvidenceFile:
    descriptor: int | None = None
    descriptor_transferred = False
    try:
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        owner = os.geteuid() if hasattr(os, "geteuid") else before.st_uid
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_uid != owner
            or before.st_nlink != 1
            or before.st_size < 0
            or before.st_size > maximum
            or not is_owner_only_private_mode(stat.S_IMODE(before.st_mode))
        ):
            raise OSError
        descriptor = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
        opened_before = os.fstat(descriptor)
        current_before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        state = _evidence_state(before)
        if _evidence_state(opened_before) != state or _evidence_state(current_before) != state:
            raise OSError
        payload = _read_pinned_evidence_bytes(descriptor, maximum=maximum)
        opened_after = os.fstat(descriptor)
        current_after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            len(payload) != before.st_size
            or _evidence_state(opened_after) != state
            or _evidence_state(current_after) != state
        ):
            raise OSError
        snapshot = _DecisionEvidenceFile(
            directory_fd=directory_fd,
            name=name,
            payload=payload,
            state=state,
            descriptor=descriptor if retain_descriptor else None,
        )
        if not retain_descriptor:
            os.close(descriptor)
            descriptor = None
        else:
            descriptor_transferred = True
        return snapshot
    except OSError:
        raise _error(code) from None
    finally:
        if descriptor is not None and not descriptor_transferred:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _pin_capacity_decision_sources(
    run: _PinnedDirectory,
    ledger: _PinnedDirectory,
) -> tuple[_PinnedDecisionSources, list[dict[str, Any]], int]:
    snapshots: list[_DecisionEvidenceFile] = []
    try:
        run_directory_state = _evidence_state(os.fstat(run.fd))
        ledger_directory_state = _evidence_state(os.fstat(ledger.fd))
        report = _pin_decision_evidence_file(
            run.fd,
            _REPORT_FILENAME,
            maximum=MAX_CAPACITY_REPORT_BYTES,
            retain_descriptor=True,
            code="decision_invalid",
        )
        snapshots.append(report)
        marker = _pin_decision_evidence_file(
            run.fd,
            _COMMIT_FILENAME,
            maximum=1024,
            retain_descriptor=True,
            code="decision_invalid",
        )
        snapshots.append(marker)

        _validate_ledger_inventory_locked(ledger.fd, allow_temps=False)
        ledger_inventory = tuple(sorted(os.listdir(ledger.fd)))
        if any(_INFLIGHT_NAME_RE.fullmatch(name) for name in ledger_inventory):
            raise _error("decision_invalid")
        receipt_names = tuple(name for name in ledger_inventory if _ATTEMPT_NAME_RE.fullmatch(name))
        if not 1 <= len(receipt_names) <= MAX_PORTABLE_ATTEMPTS:
            raise _error("decision_invalid")

        receipts: list[dict[str, Any]] = []
        receipt_snapshots: list[_DecisionEvidenceFile] = []
        previous: str | None = None
        attempt_sequences: set[int] = set()
        attempt_nonces: set[str] = set()
        for expected_sequence, name in enumerate(receipt_names, start=1):
            match = _ATTEMPT_NAME_RE.fullmatch(name)
            if match is None or int(match.group(1)) != expected_sequence:
                raise _error("decision_invalid")
            receipt_snapshot = _pin_decision_evidence_file(
                ledger.fd,
                name,
                maximum=MAX_ATTEMPT_RECEIPT_BYTES,
                retain_descriptor=expected_sequence == len(receipt_names),
                code="decision_invalid",
            )
            snapshots.append(receipt_snapshot)
            receipt_snapshots.append(receipt_snapshot)
            receipt = _load_closed_json(receipt_snapshot.payload, description="attempt receipt")
            _verify_attempt_receipt(receipt, expected_sequence=expected_sequence, previous_sha256=previous)
            attempt_sequence = cast(int, receipt["attempt_sequence"])
            attempt_nonce = cast(str, receipt["attempt_nonce_sha256"])
            if (
                attempt_sequence != expected_sequence
                or attempt_sequence in attempt_sequences
                or attempt_nonce in attempt_nonces
            ):
                raise _error("decision_invalid")
            attempt_sequences.add(attempt_sequence)
            attempt_nonces.add(attempt_nonce)
            previous = cast(str, receipt["attempt_sha256"])
            receipts.append(receipt)

        actual_owned_bytes = _logical_tree_bytes(run.fd, depth=0, entries=[0])
        sources = _PinnedDecisionSources(
            report=report,
            marker=marker,
            receipts=tuple(receipt_snapshots),
            ledger_inventory=ledger_inventory,
            run_directory_state=run_directory_state,
            ledger_directory_state=ledger_directory_state,
        )
        sources.assert_current(run, ledger, code="decision_invalid")
        return sources, receipts, actual_owned_bytes
    except EnronCapacityError as exc:
        for snapshot in snapshots:
            snapshot.close()
        if exc.code == "decision_invalid":
            raise
        raise _error("decision_invalid") from None
    except OSError:
        for snapshot in snapshots:
            snapshot.close()
        raise _error("decision_invalid") from None
    except BaseException:
        for snapshot in snapshots:
            snapshot.close()
        raise


def _verify_pinned_capacity_decision(
    run: _PinnedDirectory,
    ledger: _PinnedDirectory,
    *,
    require_production: bool,
) -> tuple[dict[str, Any], _PinnedDecisionSources]:
    sources: _PinnedDecisionSources | None = None
    try:
        sources, receipts, actual_owned_bytes = _pin_capacity_decision_sources(run, ledger)
        if sources.marker.payload != _COMMIT_PAYLOAD:
            raise _error("decision_invalid")
        report = _load_closed_json(sources.report.payload, description="capacity report")
        verified = _verify_capacity_report(report, require_production=require_production)
        if actual_owned_bytes != verified["totals"]["final_owned_disk_bytes"]:
            raise _error("decision_invalid")

        matching = [
            receipt
            for receipt in receipts
            if receipt["outcome"] == "passed" and receipt["report_sha256"] == verified["run_sha256"]
        ]
        if len(matching) != 1 or matching[0] is not receipts[-1]:
            raise _error("decision_invalid")
        terminal = matching[0]
        execution = cast(Mapping[str, Any], verified["execution"])
        environment = cast(Mapping[str, Any], verified["environment"])
        totals = cast(Mapping[str, Any], verified["totals"])
        if (
            terminal["production_evidence"] is not execution["production_evidence"]
            or terminal["policy_sha256"] != verified["policy"]["policy_sha256"]
            or terminal["executable_git_commit"] != execution["executable_git_commit"]
            or terminal["capacity_implementation_sha256"] != execution["capacity_implementation_sha256"]
            or terminal["repository_tree_sha256"] != execution["repository_tree_sha256"]
            or terminal["runtime_environment_sha256"] != execution["runtime_environment_sha256"]
            or terminal["execution_sha256"] != _canonical_hash(execution)
            or terminal["measurement_boundary"] != execution["attempt_measurement_boundary"]
            or terminal["final_owned_disk_bytes"] != actual_owned_bytes
            or terminal["promoted_root_device"] != run.identity.device
            or terminal["promoted_root_inode"] != run.identity.inode
            or terminal["promoted_parent_device"] != os.fstat(run.parent_fd).st_dev
            or terminal["promoted_parent_inode"] != os.fstat(run.parent_fd).st_ino
            or terminal["promoted_name_sha256"] != _hash_bytes(run.name.encode("utf-8"))
            or int(terminal["elapsed_ns"]) < int(totals["elapsed_ns"])
            or int(terminal["elapsed_ns"]) > MAX_TOTAL_RUNTIME_NS
            or terminal["maximum_peak_rss_bytes"] != environment["maximum_peak_rss_bytes"]
            or int(terminal["peak_process_tree_rss_bytes"]) < int(totals["peak_process_tree_rss_bytes"])
            or int(terminal["peak_process_tree_rss_bytes"]) > int(terminal["maximum_peak_rss_bytes"])
            or int(terminal["minimum_free_disk_bytes"]) > int(totals["minimum_free_disk_bytes"])
            or int(terminal["minimum_free_disk_bytes"]) < MIN_RUNTIME_FREE_DISK_BYTES
            or int(terminal["resource_observation_count"]) <= int(totals["resource_observation_count"])
            or int(terminal["maximum_resource_observation_wall_gap_ns"])
            < int(totals["maximum_resource_observation_wall_gap_ns"])
            or int(terminal["maximum_resource_observation_wall_gap_ns"]) > MAX_RESOURCE_OBSERVATION_WALL_GAP_NS
        ):
            raise _error("decision_invalid")
        decision = {
            "artifact_kind": "aggregate_capacity_decision_evidence",
            "report": verified,
            "attempt_chain": [dict(receipt) for receipt in receipts],
            "terminal_attempt": dict(terminal),
            "decision_sha256": "",
        }
        decision["decision_sha256"] = _canonical_hash(
            {key: value for key, value in decision.items() if key != "decision_sha256"}
        )
        sources.assert_current(run, ledger, code="decision_invalid")
        return decision, sources
    except EnronCapacityError as exc:
        if sources is not None:
            sources.close()
        if exc.code == "decision_invalid":
            raise
        raise _error("decision_invalid") from None
    except BaseException:
        if sources is not None:
            sources.close()
        raise


def verify_capacity_decision(
    run_dir: Path,
    attempt_ledger_dir: Path,
    *,
    require_production: bool = True,
) -> dict[str, Any]:
    """Require a uniquely matching passed terminal receipt for a pinned run."""

    run: _PinnedDirectory | None = None
    ledger: _PinnedDirectory | None = None
    sources: _PinnedDecisionSources | None = None
    ledger_locked = False
    try:
        run = _PinnedDirectory(run_dir)
        run.assert_current(code="decision_invalid")
        ledger = _PinnedDirectory(attempt_ledger_dir)
        ledger.assert_current(code="decision_invalid")
        fcntl.flock(ledger.fd, fcntl.LOCK_SH)
        ledger_locked = True
        decision, sources = _verify_pinned_capacity_decision(
            run,
            ledger,
            require_production=require_production,
        )
        return decision
    except EnronCapacityError as exc:
        if exc.code == "decision_invalid":
            raise
        raise _error("decision_invalid") from None
    except (OSError, RuntimeError, ValueError):
        raise _error("decision_invalid") from None
    finally:
        if sources is not None:
            sources.close()
        if ledger is not None:
            if ledger_locked:
                try:
                    fcntl.flock(ledger.fd, fcntl.LOCK_UN)
                except OSError:
                    pass
            ledger.close()
        if run is not None:
            run.close()


def export_capacity_decision(
    run_dir: Path,
    attempt_ledger_dir: Path,
    output_path: Path,
    *,
    require_production: bool = True,
) -> dict[str, Any]:
    """Export one fully verified aggregate decision as a path-free portable artifact."""

    if require_production:
        _require_globally_clean_checkout(_git_head())
    try:
        target, output_parent_identity = _canonical_public_output_path(output_path)
        roots = (_absolute_private_path(run_dir), _absolute_private_path(attempt_ledger_dir))
        resolved_roots = tuple(root.resolve(strict=True) for root in roots)
    except (AttributeError, OSError, RuntimeError, ValueError):
        raise _error("portable_write_failed") from None
    if any(
        target == root or _is_within(target, root) or _is_within(root, target) for root in (*roots, *resolved_roots)
    ):
        raise _error("portable_write_failed")
    run_pin: _PinnedDirectory | None = None
    ledger_pin: _PinnedDirectory | None = None
    sources: _PinnedDecisionSources | None = None
    ledger_locked = False
    try:
        run_pin = _PinnedDirectory(roots[0])
        ledger_pin = _PinnedDirectory(roots[1])
        run_pin.assert_current(code="portable_write_failed")
        ledger_pin.assert_current(code="portable_write_failed")
        fcntl.flock(ledger_pin.fd, fcntl.LOCK_SH)
        ledger_locked = True
        decision, sources = _verify_pinned_capacity_decision(
            run_pin,
            ledger_pin,
            require_production=require_production,
        )
        forbidden_identities = {
            (run_pin.identity.device, run_pin.identity.inode),
            (ledger_pin.identity.device, ledger_pin.identity.inode),
        }
        verified, payload = _build_portable_capacity_decision(
            decision,
            require_production=require_production,
        )
        pinned_sources = sources
        pinned_run = run_pin
        pinned_ledger = ledger_pin
        _write_new_public_artifact(
            target,
            payload,
            expected_parent_identity=output_parent_identity,
            forbidden_directory_identities=forbidden_identities,
            publication_guard=lambda: pinned_sources.assert_current(
                pinned_run,
                pinned_ledger,
                code="portable_write_failed",
            ),
        )
        return verified
    finally:
        if sources is not None:
            sources.close()
        if ledger_pin is not None:
            if ledger_locked:
                try:
                    fcntl.flock(ledger_pin.fd, fcntl.LOCK_UN)
                except OSError:
                    pass
            ledger_pin.close()
        if run_pin is not None:
            run_pin.close()


def _build_portable_capacity_decision(
    decision: Mapping[str, Any],
    *,
    require_production: bool,
) -> tuple[dict[str, Any], bytes]:
    report = cast(Mapping[str, Any], decision["report"])
    attempts = cast(Sequence[Mapping[str, Any]], decision["attempt_chain"])
    terminal = cast(Mapping[str, Any], decision["terminal_attempt"])
    if not 1 <= len(attempts) <= MAX_PORTABLE_ATTEMPTS:
        raise _error("portable_decision_invalid")
    attestation = _portable_capacity_attestation(report, attempts, terminal)
    privacy: dict[str, Any] = {
        "aggregate_only": True,
        "private_paths_included": False,
        "private_payloads_included": False,
        "correctness_rows_included": False,
        "privacy_scanner_source_sha256": _public_serialization_scanner_source_sha256(),
        "privacy_scan_violation_count": 0,
        "privacy_sha256": "",
    }
    privacy["privacy_sha256"] = _canonical_hash(
        {key: value for key, value in privacy.items() if key != "privacy_sha256"}
    )
    artifact: dict[str, Any] = {
        "schema_version": CAPACITY_PORTABLE_DECISION_SCHEMA_VERSION,
        "artifact_kind": "aggregate_capacity_portable_decision",
        "report": dict(report),
        "attempt_chain": [dict(receipt) for receipt in attempts],
        "terminal_attempt": dict(terminal),
        "attestation": attestation,
        "verification_scope": _portable_verification_scope(),
        "privacy": privacy,
        "decision_sha256": "",
    }
    artifact["decision_sha256"] = _canonical_hash(
        {key: value for key, value in artifact.items() if key != "decision_sha256"}
    )
    if not _public_serialization_is_safe(artifact):
        raise _error("portable_decision_invalid")
    verified = _verify_portable_capacity_decision(artifact, require_production=require_production)
    payload = _pretty_json_bytes(verified)
    if len(payload) > MAX_PORTABLE_DECISION_BYTES:
        raise _error("portable_decision_invalid")
    return verified, payload


def verify_portable_capacity_decision(
    artifact_path: Path,
    *,
    require_production: bool = True,
) -> dict[str, Any]:
    """Verify an exported decision in a clean clone with the measured commit available."""

    try:
        if require_production:
            _require_globally_clean_checkout(_git_head())
        payload = _read_regular_public_artifact(artifact_path, maximum=MAX_PORTABLE_DECISION_BYTES)
        artifact = _load_closed_json(payload, description="portable capacity decision")
        return _verify_portable_capacity_decision(artifact, require_production=require_production)
    except EnronCapacityError as exc:
        if exc.code == "portable_decision_invalid":
            raise
        raise _error("portable_decision_invalid") from None
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _error("portable_decision_invalid") from None


def _verify_portable_capacity_decision(
    artifact: Mapping[str, Any],
    *,
    require_production: bool,
) -> dict[str, Any]:
    _require_closed(
        artifact,
        {
            "schema_version",
            "artifact_kind",
            "report",
            "attempt_chain",
            "terminal_attempt",
            "attestation",
            "verification_scope",
            "privacy",
            "decision_sha256",
        },
        "portable capacity decision",
    )
    if (
        artifact.get("schema_version") != CAPACITY_PORTABLE_DECISION_SCHEMA_VERSION
        or artifact.get("artifact_kind") != "aggregate_capacity_portable_decision"
    ):
        raise _error("portable_decision_invalid")
    report = _require_mapping(artifact.get("report"), "portable report")
    verified_report = _verify_capacity_report(report, require_production=require_production)
    raw_attempts = artifact.get("attempt_chain")
    if (
        not isinstance(raw_attempts, Sequence)
        or isinstance(raw_attempts, (str, bytes, bytearray))
        or not 1 <= len(raw_attempts) <= MAX_PORTABLE_ATTEMPTS
    ):
        raise _error("portable_decision_invalid")
    attempts: list[dict[str, Any]] = []
    previous: str | None = None
    nonces: set[str] = set()
    for sequence, raw_receipt in enumerate(raw_attempts, start=1):
        receipt = _require_mapping(raw_receipt, "portable attempt receipt")
        _verify_attempt_receipt(receipt, expected_sequence=sequence, previous_sha256=previous)
        if receipt.get("attempt_sequence") != sequence:
            raise _error("portable_decision_invalid")
        nonce = cast(str, receipt["attempt_nonce_sha256"])
        if nonce in nonces:
            raise _error("portable_decision_invalid")
        nonces.add(nonce)
        previous = cast(str, receipt["attempt_sha256"])
        attempts.append(dict(receipt))
    terminal = _require_mapping(artifact.get("terminal_attempt"), "portable terminal attempt")
    matching = [
        receipt
        for receipt in attempts
        if receipt["outcome"] == "passed" and receipt["report_sha256"] == verified_report["run_sha256"]
    ]
    if terminal != attempts[-1] or len(matching) != 1 or matching[0] != terminal:
        raise _error("portable_decision_invalid")
    _verify_portable_terminal(verified_report, terminal)
    attestation = _require_mapping(artifact.get("attestation"), "portable attestation")
    expected_attestation = _portable_capacity_attestation(verified_report, attempts, terminal)
    if attestation != expected_attestation:
        raise _error("portable_decision_invalid")
    if artifact.get("verification_scope") != _portable_verification_scope():
        raise _error("portable_decision_invalid")
    privacy = _require_mapping(artifact.get("privacy"), "portable privacy")
    expected_privacy = {
        "aggregate_only": True,
        "private_paths_included": False,
        "private_payloads_included": False,
        "correctness_rows_included": False,
        "privacy_scanner_source_sha256": verified_report["privacy"]["privacy_scanner_source_sha256"],
        "privacy_scan_violation_count": 0,
        "privacy_sha256": "",
    }
    expected_privacy["privacy_sha256"] = _canonical_hash(
        {key: value for key, value in expected_privacy.items() if key != "privacy_sha256"}
    )
    if privacy != expected_privacy or not _public_serialization_is_safe(artifact):
        raise _error("portable_decision_invalid")
    decision_sha256 = artifact.get("decision_sha256")
    if (
        not isinstance(decision_sha256, str)
        or _HASH_RE.fullmatch(decision_sha256) is None
        or decision_sha256
        != _canonical_hash({key: value for key, value in artifact.items() if key != "decision_sha256"})
    ):
        raise _error("portable_decision_invalid")
    return dict(artifact)


def _verify_portable_terminal(report: Mapping[str, Any], terminal: Mapping[str, Any]) -> None:
    execution = cast(Mapping[str, Any], report["execution"])
    environment = cast(Mapping[str, Any], report["environment"])
    totals = cast(Mapping[str, Any], report["totals"])
    if (
        terminal.get("outcome") != "passed"
        or terminal.get("failure_code") is not None
        or terminal.get("report_sha256") != report.get("run_sha256")
        or terminal.get("production_evidence") is not execution.get("production_evidence")
        or terminal.get("policy_sha256") != report["policy"]["policy_sha256"]
        or terminal.get("executable_git_commit") != execution.get("executable_git_commit")
        or terminal.get("capacity_implementation_sha256") != execution.get("capacity_implementation_sha256")
        or terminal.get("repository_tree_sha256") != execution.get("repository_tree_sha256")
        or terminal.get("runtime_environment_sha256") != execution.get("runtime_environment_sha256")
        or terminal.get("execution_sha256") != _canonical_hash(execution)
        or terminal.get("measurement_boundary") != execution.get("attempt_measurement_boundary")
        or terminal.get("final_owned_disk_bytes") != totals.get("final_owned_disk_bytes")
        or int(cast(int, terminal.get("elapsed_ns"))) < int(totals["elapsed_ns"])
        or terminal.get("maximum_peak_rss_bytes") != environment.get("maximum_peak_rss_bytes")
        or int(cast(int, terminal.get("peak_process_tree_rss_bytes"))) < int(totals["peak_process_tree_rss_bytes"])
        or int(cast(int, terminal.get("minimum_free_disk_bytes"))) > int(totals["minimum_free_disk_bytes"])
        or int(cast(int, terminal.get("resource_observation_count"))) <= int(totals["resource_observation_count"])
        or int(cast(int, terminal.get("maximum_resource_observation_wall_gap_ns")))
        < int(totals["maximum_resource_observation_wall_gap_ns"])
    ):
        raise _error("portable_decision_invalid")


def _portable_capacity_attestation(
    report: Mapping[str, Any],
    attempts: Sequence[Mapping[str, Any]],
    terminal: Mapping[str, Any],
) -> dict[str, Any]:
    execution = _require_mapping(report.get("execution"), "portable execution")
    git_commit = execution.get("executable_git_commit")
    if not isinstance(git_commit, str) or _GIT_COMMIT_RE.fullmatch(git_commit) is None:
        raise _error("portable_decision_invalid")
    commit_sources = _relevant_module_sha256_at_commit(git_commit)
    attestation: dict[str, Any] = {
        "kind": "clean_clone_source_and_hash_chain_verification",
        "executable_git_commit": git_commit,
        "commit_object_sha256": _git_commit_object_sha256(git_commit),
        "root_tree_object_id": _git_commit_root_tree(git_commit),
        "repository_tree_sha256": _repository_tree_sha256(git_commit),
        "measured_source_inventory_sha256": _canonical_hash(execution["relevant_module_sha256"]),
        "commit_source_inventory_sha256": _canonical_hash(commit_sources),
        "native_binary_sha256": execution["native_extension_sha256"],
        "native_build_source_sha256": _native_build_source_sha256_at_commit(git_commit),
        "native_extension_build_source_sha256": execution["native_extension_build_source_sha256"],
        "reader_lock_sha256": _reader_lock_sha256_at_commit(git_commit),
        "reader_environment_sha256": _canonical_hash(report["environment"]["runtime"]["reader_environment"]),
        "report_sha256": report["run_sha256"],
        "attempt_chain_sha256": _canonical_hash(list(attempts)),
        "terminal_attempt_sha256": terminal["attempt_sha256"],
        "sha256": "",
    }
    attestation["sha256"] = _canonical_hash({key: value for key, value in attestation.items() if key != "sha256"})
    return attestation


def _portable_verification_scope() -> dict[str, Any]:
    scope: dict[str, Any] = {
        "verified": [
            "closed_report_arithmetic_and_hashes",
            "full_attempt_receipt_hash_chain_and_terminal_cross_bindings",
            "git_commit_object_root_tree_and_recorded_source_blobs_from_clone",
            "reader_lock_and_native_build_source_commitments",
        ],
        "not_independently_attested": [
            "original_private_payload_bytes",
            "original_promoted_inode_or_private_filesystem_identity",
            "original_runtime_timing_rss_or_disk_observations",
            "failed_attempt_cleanup_fields_or_durable_wipe_state",
            "recorded_native_binary_bytes_or_reproducible_binary_build",
            "observed_runtime_reader_distribution_file_bytes",
            "lower_http_dependency_file_bytes_beyond_critical_reader_set",
        ],
        "prerequisite": (
            "trusted_access_controlled_host_with_measured_git_commit_complete_history_and_fresh_uv_managed_install_"
            "from_checked_in_lock"
        ),
        "sha256": "",
    }
    scope["sha256"] = _canonical_hash({key: value for key, value in scope.items() if key != "sha256"})
    return scope


def _git_commit_object_sha256(git_commit: str) -> str:
    root = _git_root()
    try:
        object_type = subprocess.run(
            ["git", "-C", os.fspath(root), "cat-file", "-t", git_commit],
            check=False,
            capture_output=True,
            timeout=20,
        )
        resolved = subprocess.run(
            ["git", "-C", os.fspath(root), "rev-parse", "--verify", f"{git_commit}^{{commit}}"],
            check=False,
            capture_output=True,
            timeout=20,
        )
        payload = subprocess.run(
            ["git", "-C", os.fspath(root), "cat-file", "commit", git_commit],
            check=False,
            capture_output=True,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError):
        raise _error("portable_decision_invalid") from None
    if (
        object_type.returncode != 0
        or object_type.stdout != b"commit\n"
        or resolved.returncode != 0
        or resolved.stdout.strip() != git_commit.encode("ascii")
        or payload.returncode != 0
        or not payload.stdout
        or hashlib.sha1(b"commit " + str(len(payload.stdout)).encode("ascii") + b"\0" + payload.stdout).hexdigest()
        != git_commit
    ):
        raise _error("portable_decision_invalid")
    return _hash_bytes(payload.stdout)


def _git_commit_root_tree(git_commit: str) -> str:
    root = _git_root()
    try:
        completed = subprocess.run(
            ["git", "-C", os.fspath(root), "rev-parse", "--verify", f"{git_commit}^{{tree}}"],
            check=False,
            capture_output=True,
            timeout=20,
        )
        payload = subprocess.run(
            ["git", "-C", os.fspath(root), "cat-file", "commit", git_commit],
            check=False,
            capture_output=True,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError):
        raise _error("portable_decision_invalid") from None
    tree = completed.stdout.strip()
    first_line = payload.stdout.splitlines()[0] if payload.stdout else b""
    if (
        completed.returncode != 0
        or payload.returncode != 0
        or not re.fullmatch(rb"[0-9a-f]{40}", tree)
        or first_line != b"tree " + tree
    ):
        raise _error("portable_decision_invalid")
    return tree.decode("ascii")


def _canonical_public_output_path(path: Path) -> tuple[Path, tuple[int, int]]:
    if not isinstance(path, Path) or any(part == os.pardir for part in path.parts) or not path.name:
        raise _error("portable_write_failed")
    target = path.expanduser()
    if not target.is_absolute():
        target = Path.cwd() / target
    try:
        parent = target.parent.resolve(strict=True)
        info = parent.lstat()
    except (OSError, RuntimeError, ValueError):
        raise _error("portable_write_failed") from None
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise _error("portable_write_failed")
    return parent / target.name, (int(info.st_dev), int(info.st_ino))


def _require_public_output_parent_current(
    parent: Path,
    directory_fd: int,
    expected_identity: tuple[int, int],
) -> None:
    opened = os.fstat(directory_fd)
    current = parent.lstat()
    if (
        not stat.S_ISDIR(opened.st_mode)
        or not stat.S_ISDIR(current.st_mode)
        or stat.S_ISLNK(current.st_mode)
        or (int(opened.st_dev), int(opened.st_ino)) != expected_identity
        or (int(current.st_dev), int(current.st_ino)) != expected_identity
    ):
        raise OSError


def _directory_has_forbidden_ancestor(
    directory_fd: int,
    forbidden: set[tuple[int, int]],
) -> bool:
    current: int | None = None
    try:
        current = os.dup(directory_fd)
        for _depth in range(MAX_PRIVATE_TREE_DEPTH + 2):
            info = os.fstat(current)
            identity = (int(info.st_dev), int(info.st_ino))
            if identity in forbidden:
                return True
            parent = os.open(
                "..",
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=current,
            )
            parent_info = os.fstat(parent)
            if (parent_info.st_dev, parent_info.st_ino) == identity:
                os.close(parent)
                return False
            os.close(current)
            current = parent
        raise OSError
    except OSError:
        raise _error("portable_write_failed") from None
    finally:
        if current is not None:
            try:
                os.close(current)
            except OSError:
                pass


def _write_new_public_artifact(
    path: Path,
    payload: bytes,
    *,
    expected_parent_identity: tuple[int, int] | None = None,
    forbidden_directory_identities: set[tuple[int, int]] | None = None,
    publication_guard: Callable[[], None] | None = None,
) -> None:
    target, observed_parent_identity = _canonical_public_output_path(path)
    if expected_parent_identity is None:
        expected_parent_identity = observed_parent_identity
    elif (
        not isinstance(expected_parent_identity, tuple)
        or len(expected_parent_identity) != 2
        or any(type(value) is not int or value < 0 for value in expected_parent_identity)
        or target != path
        or observed_parent_identity != expected_parent_identity
    ):
        raise _error("portable_write_failed")
    parent = target.parent
    temporary = f".{target.name}.stage-{secrets.token_hex(24)}"
    directory_fd: int | None = None
    descriptor: int | None = None
    staged_identity: tuple[int, int] | None = None
    try:
        directory_fd = os.open(
            parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        _require_public_output_parent_current(parent, directory_fd, expected_parent_identity)
        forbidden = forbidden_directory_identities or set()
        if forbidden and _directory_has_forbidden_ancestor(directory_fd, forbidden):
            raise OSError
        _require_public_output_parent_current(parent, directory_fd, expected_parent_identity)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
        os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError
            view = view[written:]
        os.fsync(descriptor)
        staged = os.fstat(descriptor)
        staged_identity = (int(staged.st_dev), int(staged.st_ino))
        if forbidden and _directory_has_forbidden_ancestor(directory_fd, forbidden):
            raise OSError
        _require_pinned_public_file_at(directory_fd, temporary, descriptor, staged_identity, len(payload))
        _require_public_output_parent_current(parent, directory_fd, expected_parent_identity)
        _private_io._rename_noreplace_at(directory_fd, temporary, directory_fd, target.name)
        try:
            _require_pinned_public_file_at(directory_fd, target.name, descriptor, staged_identity, len(payload))
            _require_public_output_parent_current(parent, directory_fd, expected_parent_identity)
            os.fsync(directory_fd)
            _require_public_output_parent_current(parent, directory_fd, expected_parent_identity)
            if publication_guard is not None:
                publication_guard()
                _require_public_output_parent_current(parent, directory_fd, expected_parent_identity)
            # Conditional on the guard and final checks succeeding, this is
            # the no-replace publication's explicit linearization point.
            _require_pinned_public_file_at(directory_fd, target.name, descriptor, staged_identity, len(payload))
            _require_public_output_parent_current(parent, directory_fd, expected_parent_identity)
            if publication_guard is not None:
                publication_guard()
                _require_public_output_parent_current(parent, directory_fd, expected_parent_identity)
            _require_pinned_public_file_at(directory_fd, target.name, descriptor, staged_identity, len(payload))
            _require_public_output_parent_current(parent, directory_fd, expected_parent_identity)
        except BaseException:
            _restore_mismatched_publication_at(directory_fd, target.name, temporary)
            raise
    except (EnronPrivateIOError, FileExistsError, OSError, RuntimeError, ValueError):
        raise _error("portable_write_failed") from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if directory_fd is not None:
            try:
                os.close(directory_fd)
            except OSError:
                pass


def _require_pinned_public_file_at(
    directory_fd: int,
    name: str,
    descriptor: int,
    expected_identity: tuple[int, int],
    expected_size: int,
) -> None:
    opened = os.fstat(descriptor)
    current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    owner = os.geteuid() if hasattr(os, "geteuid") else opened.st_uid
    if (
        not stat.S_ISREG(opened.st_mode)
        or stat.S_ISLNK(current.st_mode)
        or opened.st_uid != owner
        or current.st_uid != owner
        or opened.st_nlink != 1
        or current.st_nlink != 1
        or stat.S_IMODE(opened.st_mode) != 0o600
        or stat.S_IMODE(current.st_mode) != 0o600
        or opened.st_size != expected_size
        or current.st_size != expected_size
        or _regular_file_identity(opened) != expected_identity
        or _regular_file_identity(current) != expected_identity
    ):
        raise OSError


def _read_regular_public_artifact(path: Path, *, maximum: int) -> bytes:
    descriptor: int | None = None
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 0
            or before.st_size > maximum
            or stat.S_IMODE(before.st_mode) & 0o022
        ):
            raise OSError
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise OSError
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        current = path.lstat()
    except (OSError, RuntimeError, ValueError):
        raise _error("portable_decision_invalid") from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
    payload = b"".join(chunks)
    if (
        len(payload) > maximum
        or len(payload) != before.st_size
        or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        != (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns, current.st_ctime_ns)
    ):
        raise _error("portable_decision_invalid")
    return payload


def _absolute_private_path(path: Path) -> Path:
    if not isinstance(path, Path) or any(part == os.pardir for part in path.parts):
        raise _error("options_invalid")
    try:
        expanded = path.expanduser()
        return expanded if expanded.is_absolute() else Path.cwd() / expanded
    except (OSError, RuntimeError, ValueError):
        raise _error("options_invalid") from None


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _read_regular_private_file(path: Path, *, maximum: int) -> bytes:
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 0
            or before.st_size > maximum
            or not is_owner_only_private_mode(stat.S_IMODE(before.st_mode))
        ):
            raise _error("report_invalid")
        with open_private_binary_input(path) as handle:
            opened = os.fstat(handle.fileno())
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise _error("report_invalid")
            payload = handle.read(maximum + 1)
            after = os.fstat(handle.fileno())
        current = path.lstat()
    except EnronCapacityError:
        raise
    except (EnronPrivateIOError, OSError):
        raise _error("report_invalid") from None
    if (
        len(payload) > maximum
        or len(payload) != before.st_size
        or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        != (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns, current.st_ctime_ns)
    ):
        raise _error("report_invalid")
    return payload


def _read_regular_private_file_at(directory_fd: int, name: str, *, maximum: int) -> bytes:
    descriptor: int | None = None
    try:
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 0
            or before.st_size > maximum
            or not is_owner_only_private_mode(stat.S_IMODE(before.st_mode))
        ):
            raise _error("report_invalid")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(name, flags, dir_fd=directory_fd)
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise _error("report_invalid")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except EnronCapacityError:
        raise
    except OSError:
        raise _error("report_invalid") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if (
        len(payload) > maximum
        or len(payload) != before.st_size
        or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        != (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns, current.st_ctime_ns)
    ):
        raise _error("report_invalid")
    return payload


def _load_closed_json(payload: bytes, *, description: str) -> dict[str, Any]:
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
            parse_float=_reject_float,
            parse_int=_parse_bounded_int,
        )
    except (OverflowError, RecursionError, TypeError, UnicodeError, ValueError):
        raise _error("report_invalid") from None
    if not isinstance(value, dict) or payload != _pretty_json_bytes(value):
        raise _error("report_invalid")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> Any:
    raise ValueError("non-finite constant")


def _reject_float(_value: str) -> Any:
    raise ValueError("floating-point value")


def _parse_bounded_int(value: str) -> int:
    digits = value.lstrip("-")
    if len(digits) > _MAX_JSON_INTEGER_DIGITS:
        raise ValueError("integer too large")
    return int(value)


def _require_mapping(value: Any, _description: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise _error("report_invalid")
    return cast(Mapping[str, Any], value)


def _require_closed(value: Mapping[str, Any], fields: set[str], _description: str) -> None:
    if set(value) != fields:
        raise _error("report_invalid")


def _bounded_int(value: Any, _description: str, *, minimum: int) -> int:
    if type(value) is not int or value < minimum:
        raise _error("report_invalid")
    return value


def _positive_int(value: Any, description: str) -> int:
    return _bounded_int(value, description, minimum=1)


def _implementation_sha256() -> str:
    try:
        payload = Path(__file__).read_bytes()
    except OSError:
        raise _error("production_identity_invalid") from None
    return _hash_bytes(payload)


def _canonical_hash(value: Any) -> str:
    try:
        payload = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (OverflowError, TypeError, UnicodeError, ValueError):
        raise _error("report_invalid") from None
    return _hash_bytes(payload)


def _hash_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _pretty_json_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n"


def _canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


if __name__ == "__main__":
    if sys.argv != [sys.argv[0], _PRODUCTION_WORKER_ARGUMENT]:
        raise SystemExit(2)
    raise SystemExit(_production_worker_main())

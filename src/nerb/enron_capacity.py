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
import shutil
import signal
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
MAX_PROGRESS_CHECKPOINT_WALL_GAP_NS = 30_000_000_000
MAX_CAPACITY_REPORT_BYTES = 4 * 1024 * 1024
MAX_ATTEMPT_RECEIPT_BYTES = 64 * 1024
MAX_INFLIGHT_RECORD_BYTES = 16 * 1024
MAX_PRIVATE_TREE_ENTRIES = 1_000_000
MAX_PRIVATE_TREE_DEPTH = 64
MAX_RETAINED_PRIVATE_TOMBSTONES = 1_024
MAX_PORTABLE_DECISION_BYTES = 16 * 1024 * 1024
MAX_PORTABLE_ATTEMPTS = 1_024
MAX_LEDGER_TOMBSTONES = 4 * MAX_PORTABLE_ATTEMPTS
MAX_READER_DISTRIBUTIONS = 4_096
MAX_DATASETS_DISTRIBUTION_FILES = 16_384
MAX_DATASETS_DISTRIBUTION_BYTES = 512 * 1024 * 1024

_REPORT_FILENAME = "capacity-report.json"
_COMMIT_FILENAME = "COMMITTED"
_COMMIT_PAYLOAD = b"nerb.enron.private-run.v2\n"
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
_BOOTSTRAP_ATTRIBUTE = "_nerb_capacity_bootstrap"
_BOOTSTRAP_SCHEMA = "nerb.enron_capacity.bootstrap.v1"
_CAPACITY_LAUNCHER_PATH = "scripts/run_enron_capacity.py"
_PRODUCTION_WORKER_BOOTSTRAP = (
    "import importlib.machinery,importlib.util,os,sys;"
    "source=sys.argv.pop(1);count=int(sys.argv.pop(1));"
    "roots=[sys.argv.pop(1) for _ in range(count)];"
    "baseline=list(sys.path);"
    "path=os.path.join(source,'nerb','_capacity_bootstrap.py');"
    "loader=importlib.machinery.SourceFileLoader('_nerb_capacity_bootstrap_impl',path);"
    "spec=importlib.util.spec_from_file_location('_nerb_capacity_bootstrap_impl',path,loader=loader);"
    "module=importlib.util.module_from_spec(spec);sys.modules['_nerb_capacity_bootstrap_impl']=module;"
    "loader.exec_module(module);module.install(source);"
    "sys.path[:]=[*baseline,*roots,source];"
    "setattr(sys,'_nerb_capacity_bootstrap',"
    "{'schema':'nerb.enron_capacity.bootstrap.v1','source_root':source,'dependency_roots':roots,"
    "'baseline_path':baseline,'pycache_root':sys.pycache_prefix});"
    "sys.exit(module.run(source) "
    "if sys.argv==[sys.argv[0],'--nerb-capacity-production-worker'] else 2)"
)
_FRESH_PRODUCTION_WORKER = False
_PHASE_SCOPED_READER_LOADED = False
_PRODUCTION_CORE_SOURCE_NAMES = (
    "_capacity_bootstrap.py",
    "engine.py",
    "engines.py",
    "enron_bank_builder.py",
    "enron_bank_workflow.py",
    "enron_capacity.py",
    "enron_preparation.py",
    "enron_private_io.py",
    "enron_quality.py",
    "enron_splitting.py",
)
_READER_MODULE_PREFIXES = ("datasets", "huggingface_hub", "fsspec", "pyarrow", "transformers")
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
    ("fsspec", "fsspec", "fsspec/__init__.py", "2026.4.0"),
    ("pyarrow", "pyarrow", "pyarrow/__init__.py", "25.0.0"),
)
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
    "phase_interrupted": "Capacity phase was interrupted safely.",
    "phase_result_invalid": "Capacity phase returned an invalid closed result.",
    "phase_commitment_invalid": "Capacity phase commitment chain is invalid.",
    "checkpoint_required": "Capacity phase omitted required progress checkpoints.",
    "checkpoint_gap": "Capacity phase checkpoint progress exceeds the frozen gap.",
    "checkpoint_invalid": "Capacity phase checkpoint progress is invalid.",
    "checkpoint_limit": "Capacity phase exceeds its checkpoint limit.",
    "checkpoint_wall_gap": "Capacity phase progress-checkpoint wall gap exceeds the frozen limit.",
    "resource_observation_gap": "Capacity resource-observation wall gap exceeds the frozen limit.",
    "watchdog_unsupported": "Capacity watchdog interruption is unsupported.",
    "rss_limit": "Capacity process-tree RSS exceeds the frozen limit.",
    "runtime_disk_floor": "Capacity filesystem free space fell below the frozen abort floor.",
    "owned_disk_limit": "Capacity owned-disk use exceeds the frozen limit.",
    "runtime_limit": "Capacity runtime exceeds the frozen limit.",
    "throughput_limit": "Capacity phase throughput is below the frozen minimum.",
    "resource_measurement_failed": "Capacity continuous resource measurement failed safely.",
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
    "portable_decision_invalid": "Portable capacity decision evidence is invalid.",
    "portable_write_failed": "Portable capacity decision evidence could not be written safely.",
}


class EnronCapacityError(RuntimeError):
    """Raised when full-source capacity cannot be proved safely."""

    def __init__(self, message: str = _ERROR_MESSAGES["capacity_failed"], *, code: str = "capacity_failed") -> None:
        super().__init__(message)
        self.code = code


class _CapacityAbort(BaseException):
    """Internal payload-free phase abort that a checkpoint may raise."""

    def __init__(self, code: str) -> None:
        self.code = code if code in _ERROR_MESSAGES else "capacity_failed"


def _error(code: str) -> EnronCapacityError:
    safe_code = code if code in _ERROR_MESSAGES else "capacity_failed"
    return EnronCapacityError(_ERROR_MESSAGES[safe_code], code=safe_code)


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

    def declare_owned_root(self, path: Path) -> Path:
        """Register an additional existing root inside the transaction."""

        registered = self._declare_owned_root(path)
        self._owned_root_count += 1
        return registered


CapacityPhaseRunner = Callable[[EnronCapacityPhaseContext], EnronCapacityPhaseResult]


class _SystemResourceProbe:
    def physical_memory_bytes(self) -> int | None:
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
            current = _darwin_process_tree_rss_bytes(root_pid)
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
            ["ps", "-axo", "pid=,ppid=,rss="],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    parents: dict[int, int] = {}
    rss_by_pid: dict[int, int] = {}
    try:
        for line in completed.stdout.splitlines():
            fields = line.split()
            if len(fields) != 3:
                return None
            pid, parent, rss_kib = (int(value) for value in fields)
            if pid <= 0 or parent < 0 or rss_kib < 0:
                return None
            parents[pid] = parent
            rss_by_pid[pid] = rss_kib
    except ValueError:
        return None
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
    return sum(rss_by_pid[pid] for pid in descendants) * 1024


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

    def __init__(self, path: Path, *, create_final: bool = False) -> None:
        self.path = _absolute_private_path(path)
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
                descriptor = _open_owned_directory_descriptor(name, dir_fd=parent_fd)
                info = os.fstat(descriptor.fd)
                before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if not _same_directory(before, info):
                    descriptor.close()
                    raise OSError
                if final:
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
            if not _safe_private_directory(os.fstat(self.fd)):
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
    if depth > MAX_PRIVATE_TREE_DEPTH:
        raise _error("private_tree_invalid")
    try:
        names = sorted(os.listdir(directory_fd))
    except OSError:
        raise _error("private_tree_invalid") from None
    total = 0
    for name in names:
        entries[0] += 1
        if entries[0] > MAX_PRIVATE_TREE_ENTRIES:
            raise _error("private_tree_invalid")
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
    sensitive_content_wiped: bool | None = None
    path_tree_removed: bool | None = None
    retained_private_tombstone_count: int = 0


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


@dataclass(slots=True)
class _PhaseMeasurements:
    started_ns: int
    started_wall_ns: int
    observations: int = 0
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
    last_sample: dict[str, Any] | None = None
    last_resource_wall_ns: int | None = None
    last_progress_wall_ns: int | None = None
    maximum_resource_wall_gap_ns: int = 0
    maximum_progress_wall_gap_ns: int = 0
    checkpoints: list[dict[str, int]] | None = None
    progress_signals: list[dict[str, Any]] | None = None
    heartbeat_samples: list[dict[str, Any]] | None = None
    heartbeat_priorities: list[int] | None = None
    progress_signal_count: int = 0
    maximum_progress_signal: dict[str, Any] | None = None
    last_heartbeat_signal: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        self.samples = []
        self.sample_priorities = []
        self.cadence_samples = []
        self.checkpoints = []
        self.progress_signals = []
        self.heartbeat_samples = []
        self.heartbeat_priorities = []


class _Watchdog:
    def __init__(self, failure_code: Callable[[], str | None]) -> None:
        self._failure_code = failure_code
        self._previous: Any = None
        self._installed = False

    def install(self) -> None:
        if (
            os.name != "posix"
            or threading.current_thread() is not threading.main_thread()
            or not hasattr(signal, "SIGUSR1")
        ):
            raise _error("watchdog_unsupported")
        try:
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
        code = self._failure_code()
        if code is not None:
            raise _CapacityAbort(code)


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
    ) -> None:
        self.tree = tree
        self.probe = probe
        self.preflight = preflight
        self.run_started_ns = run_started_ns
        self.interval_ns = interval_ns
        self.wall_clock = wall_clock
        self._lock = threading.RLock()
        self._observation_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._stopped = False
        self._current_phase: str | None = None
        self._states: dict[str, _PhaseMeasurements] = {}
        self._failure_code: str | None = None
        self._global_observations = 0
        self._global_peak_rss = preflight.preflight_process_tree_rss_bytes
        self._global_minimum_free = preflight.preflight_free_disk_bytes
        self._global_owned_high_water = 0
        self._global_maximum_resource_wall_gap_ns = 0
        self._global_last_resource_wall_ns: int | None = None
        self._global_last_probe_ns = run_started_ns
        self._watchdog = _Watchdog(self._current_failure_code)

    def start(self) -> None:
        self._watchdog.install()
        with self._lock:
            self._global_last_resource_wall_ns = self.wall_clock()
        self._observe("boundary")
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
            raise first_error

    def _shutdown_is_settled(self) -> bool:
        return self._stopped and self._thread is None and not self._watchdog._installed

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
                        self._record_failure("resource_measurement_failed")
                    except BaseException as exc:
                        remember(exc)
            self._thread = None
        try:
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
            )
            self._current_phase = phase
            self._global_owned_high_water = max(self._global_owned_high_water, owned)
        self._observe("boundary")
        self.raise_if_failed()

    def checkpoint(self, phase: str, completed_records: int) -> None:
        if type(completed_records) is not int or completed_records <= 0:
            raise _CapacityAbort("checkpoint_invalid")
        try:
            owned = self.tree.logical_bytes()
        except EnronCapacityError:
            self._record_failure("private_tree_invalid")
            raise _CapacityAbort("private_tree_invalid") from None
        with self._lock:
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
            wall_now = self.wall_clock()
            previous_progress_wall = state.last_progress_wall_ns or state.started_wall_ns
            wall_gap = wall_now - previous_progress_wall
            if wall_gap < 0:
                raise _CapacityAbort("clock_invalid")
            state.maximum_progress_wall_gap_ns = max(state.maximum_progress_wall_gap_ns, wall_gap)
            state.last_progress_wall_ns = wall_now
            if wall_gap > MAX_PROGRESS_CHECKPOINT_WALL_GAP_NS:
                self._record_failure("checkpoint_wall_gap")
                raise _CapacityAbort("checkpoint_wall_gap")
            state.checkpoint_count += 1
            state.last_completed = completed_records
            state.maximum_checkpoint_gap = max(state.maximum_checkpoint_gap, gap)
            state.last_owned = owned
            state.owned_high_water = max(state.owned_high_water, owned)
            self._global_owned_high_water = max(self._global_owned_high_water, owned)
            self._append_progress_signal(
                state,
                kind="checkpoint",
                completed_records=completed_records,
                wall_now=wall_now,
                wall_gap=wall_gap,
            )
        self._observe("checkpoint", completed_records=completed_records)
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
        with self._lock:
            wall_now = self.wall_clock()
            state = self._states.get(phase)
            if state is None or self._current_phase != phase:
                raise _CapacityAbort("checkpoint_invalid")
            previous_progress_wall = state.last_progress_wall_ns or state.started_wall_ns
            wall_gap = wall_now - previous_progress_wall
            if wall_gap < 0:
                raise _CapacityAbort("clock_invalid")
            state.maximum_progress_wall_gap_ns = max(state.maximum_progress_wall_gap_ns, wall_gap)
            state.last_progress_wall_ns = wall_now
            self._append_progress_signal(
                state,
                kind="heartbeat",
                completed_records=state.last_completed,
                wall_now=wall_now,
                wall_gap=wall_gap,
            )
            if wall_gap > MAX_PROGRESS_CHECKPOINT_WALL_GAP_NS:
                self._record_failure("checkpoint_wall_gap")
                raise _CapacityAbort("checkpoint_wall_gap")
        self._observe("heartbeat", completed_records=state.last_completed or None)
        self.raise_if_failed()

    def finish_phase(self, phase: str, records: int) -> dict[str, Any]:
        self._observe("boundary")
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
            if final_wall_gap < 0 or final_wall_gap > MAX_PROGRESS_CHECKPOINT_WALL_GAP_NS:
                raise _error("checkpoint_wall_gap")
            state.maximum_progress_wall_gap_ns = max(state.maximum_progress_wall_gap_ns, final_wall_gap)
            state.last_progress_wall_ns = wall_now
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
            phase = self._current_phase
            if phase is not None:
                state = self._states[phase]
                state.last_owned = owned
                state.owned_high_water = max(state.owned_high_water, owned)
        self._enforce_owned(owned)
        self._observe("boundary")
        self.raise_if_failed()

    def global_snapshot(self) -> dict[str, int]:
        with self._lock:
            return {
                "resource_observation_count": self._global_observations,
                "peak_process_tree_rss_bytes": self._global_peak_rss,
                "minimum_free_disk_bytes": self._global_minimum_free,
                "owned_disk_high_water_bytes": self._global_owned_high_water,
                "maximum_resource_observation_wall_gap_ns": self._global_maximum_resource_wall_gap_ns,
            }

    def raise_if_failed(self) -> None:
        with self._lock:
            code = self._failure_code
        if code is not None:
            raise _CapacityAbort(code)

    def _loop(self) -> None:
        interval = self.interval_ns / 1_000_000_000
        while not self._stop.wait(interval):
            self._observe("continuous")

    def _observe(self, kind: str, *, completed_records: int | None = None) -> None:
        with self._observation_lock:
            self._observe_serialized(kind, completed_records=completed_records)

    def _observe_serialized(self, kind: str, *, completed_records: int | None = None) -> None:
        try:
            logical_owned = self.tree.logical_bytes()
            now = _probe_monotonic_ns(self.probe)
            rss = _probe_process_tree_rss(self.probe)
            minimum_free, output_disk = _sample_runtime_filesystems(self.probe, self.preflight)
        except _CapacityAbort:
            raise
        except EnronCapacityError as exc:
            self._record_failure(
                exc.code
                if exc.code in {"runtime_filesystem_changed", "runtime_disk_floor"}
                else "resource_measurement_failed"
            )
            return
        except BaseException:
            self._record_failure("resource_measurement_failed")
            return
        filesystem_delta = max(0, self.preflight.output_preflight_free_disk_bytes - output_disk.free)
        owned = max(logical_owned, filesystem_delta)
        with self._lock:
            try:
                wall_now = self.wall_clock()
            except BaseException:
                self._record_failure("clock_invalid")
                return
            previous_global_wall = self._global_last_resource_wall_ns
            if previous_global_wall is None:
                previous_global_wall = wall_now
            global_resource_wall_gap = wall_now - previous_global_wall
            if now < self.run_started_ns or now < self._global_last_probe_ns or global_resource_wall_gap < 0:
                self._record_failure("clock_invalid")
                return
            self._global_last_resource_wall_ns = wall_now
            self._global_last_probe_ns = now
            self._global_observations += 1
            self._global_peak_rss = max(self._global_peak_rss, rss)
            self._global_minimum_free = min(self._global_minimum_free, minimum_free)
            self._global_owned_high_water = max(self._global_owned_high_water, owned)
            self._global_maximum_resource_wall_gap_ns = max(
                self._global_maximum_resource_wall_gap_ns,
                global_resource_wall_gap,
            )
            if global_resource_wall_gap > MAX_RESOURCE_OBSERVATION_WALL_GAP_NS:
                self._record_failure("resource_observation_gap")
            phase = self._current_phase
            if phase is not None:
                state = self._states[phase]
                if now < state.started_ns:
                    self._record_failure("clock_invalid")
                    return
                state.observations += 1
                previous_resource_wall = state.last_resource_wall_ns or state.started_wall_ns
                resource_wall_gap = wall_now - previous_resource_wall
                progress_wall_gap = wall_now - (state.last_progress_wall_ns or state.started_wall_ns)
                if resource_wall_gap < 0 or progress_wall_gap < 0:
                    self._record_failure("clock_invalid")
                    return
                state.last_resource_wall_ns = wall_now
                state.maximum_resource_wall_gap_ns = max(state.maximum_resource_wall_gap_ns, resource_wall_gap)
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
                if state.owned_peak_sample is None or owned >= int(state.owned_peak_sample["owned_disk_bytes"]):
                    state.owned_peak_sample = sample
                self._retain_sample(state, sample)
                if resource_wall_gap > MAX_RESOURCE_OBSERVATION_WALL_GAP_NS:
                    self._record_failure("resource_observation_gap")
                if progress_wall_gap > MAX_PROGRESS_CHECKPOINT_WALL_GAP_NS:
                    self._record_failure("checkpoint_wall_gap")
            if rss > self.preflight.maximum_peak_rss_bytes:
                self._record_failure("rss_limit")
            if minimum_free < MIN_RUNTIME_FREE_DISK_BYTES:
                self._record_failure("runtime_disk_floor")
            if owned > MAX_OWNED_DISK_BYTES:
                self._record_failure("owned_disk_limit")
            if now - self.run_started_ns > MAX_TOTAL_RUNTIME_NS:
                self._record_failure("runtime_limit")

    def _phase_snapshot(self, state: _PhaseMeasurements, elapsed_ns: int) -> dict[str, Any]:
        retained = list(cast(list[dict[str, Any]], state.samples))
        retained.extend(cast(list[dict[str, Any]], state.cadence_samples))
        for sample in (
            state.first_sample,
            state.peak_sample,
            state.owned_peak_sample,
            state.minimum_free_sample,
            state.maximum_wall_gap_sample,
            state.last_sample,
        ):
            if sample is not None and all(item["sequence"] != sample["sequence"] for item in retained):
                retained.append(sample)
        retained.sort(key=lambda item: int(item["sequence"]))
        progress_signals = list(cast(list[dict[str, Any]], state.progress_signals))
        progress_signals.extend(cast(list[dict[str, Any]], state.heartbeat_samples))
        for progress_signal in (state.maximum_progress_signal, state.last_heartbeat_signal):
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
            "peak_process_tree_rss_bytes": state.peak_rss,
            "owned_disk_high_water_bytes": state.owned_high_water,
            "minimum_free_disk_bytes": 0 if state.minimum_free is None else state.minimum_free,
            "maximum_resource_observation_wall_gap_ns": state.maximum_resource_wall_gap_ns,
            "maximum_progress_checkpoint_wall_gap_ns": state.maximum_progress_wall_gap_ns,
            "resource_samples": retained,
            "checkpoint_count": state.checkpoint_count,
            "maximum_checkpoint_gap_records": state.maximum_checkpoint_gap,
            "checkpoint_samples": list(cast(list[dict[str, int]], state.checkpoints)),
            "progress_signal_count": state.progress_signal_count,
            "progress_signals": progress_signals,
        }

    def _record_failure(self, code: str) -> None:
        newly_recorded = False
        with self._lock:
            if self._failure_code is None:
                self._failure_code = code if code in _ERROR_MESSAGES else "resource_measurement_failed"
                newly_recorded = True
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
        reservoir_capacity = MAX_RESOURCE_SAMPLES_PER_PHASE - 64 - 6
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
        if kind != "heartbeat":
            signals = cast(list[dict[str, Any]], state.progress_signals)
            signals.append(signal)
            return
        state.last_heartbeat_signal = signal
        samples = cast(list[dict[str, Any]], state.heartbeat_samples)
        priorities = cast(list[int], state.heartbeat_priorities)
        heartbeat_capacity = MAX_PROGRESS_SIGNALS_PER_PHASE - MAX_CHECKPOINTS_PER_PHASE - 3
        if heartbeat_capacity <= 0:
            raise _CapacityAbort("checkpoint_limit")
        sequence = state.progress_signal_count
        priority = int.from_bytes(hashlib.sha256(f"heartbeat:{sequence}".encode("ascii")).digest()[:8], "big")
        if len(samples) < heartbeat_capacity:
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
        "unbounded_heartbeat_enforcement_with_bounded_retained_evidence": True,
        "maximum_retained_resource_samples_per_phase": MAX_RESOURCE_SAMPLES_PER_PHASE,
        "production_monitor_interval_ns": PRODUCTION_MONITOR_INTERVAL_NS,
        "maximum_resource_observation_wall_gap_ns": MAX_RESOURCE_OBSERVATION_WALL_GAP_NS,
        "maximum_progress_checkpoint_wall_gap_ns": MAX_PROGRESS_CHECKPOINT_WALL_GAP_NS,
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


def _validated_capacity_bootstrap() -> tuple[Path, tuple[Path, ...], tuple[str, ...]]:
    """Validate the stdlib-only launcher/worker import state without running site hooks."""

    marker = getattr(sys, _BOOTSTRAP_ATTRIBUTE, None)
    if not isinstance(marker, Mapping) or set(marker) != {
        "schema",
        "source_root",
        "dependency_roots",
        "baseline_path",
        "pycache_root",
    }:
        raise _error("production_identity_invalid")
    raw_dependencies = marker.get("dependency_roots")
    raw_baseline = marker.get("baseline_path")
    if (
        marker.get("schema") != _BOOTSTRAP_SCHEMA
        or not isinstance(marker.get("source_root"), str)
        or not isinstance(marker.get("pycache_root"), str)
        or not isinstance(raw_dependencies, list)
        or not raw_dependencies
        or any(not isinstance(value, str) for value in raw_dependencies)
        or not isinstance(raw_baseline, list)
        or any(not isinstance(value, str) or not value or not Path(value).is_absolute() for value in raw_baseline)
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
    return source_root, dependencies, layouts


def _spawn_production_worker(options: EnronCapacityOptions) -> dict[str, Any]:
    source_root, dependency_roots, _layouts = _validated_capacity_bootstrap()
    nonce = secrets.token_hex(32)
    request = {
        "output_dir": os.fspath(_absolute_private_path(options.output_dir)),
        "attempt_ledger_dir": os.fspath(_absolute_private_path(options.attempt_ledger_dir)),
        "workspace_root": None
        if options.workspace_root is None
        else os.fspath(_absolute_private_path(options.workspace_root)),
        "allow_unignored_output": options.allow_unignored_output,
        "nonce": nonce,
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
    try:
        with tempfile.TemporaryDirectory(prefix="nerb-capacity-pycache-") as pycache_directory:
            pycache_root = Path(pycache_directory).resolve(strict=True)
            completed = subprocess.run(
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
                    _PRODUCTION_WORKER_ARGUMENT,
                ],
                input=_canonical_json_bytes(request),
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=environment,
                timeout=MAX_TOTAL_RUNTIME_NS // 1_000_000_000 + 300,
            )
    except (OSError, subprocess.SubprocessError):
        _recover_worker_inflight(options)
        raise _error("production_worker_failed") from None
    _recover_worker_inflight(options)
    if completed.returncode != 0 or len(completed.stdout) > MAX_CAPACITY_REPORT_BYTES + 64 * 1024:
        raise _error("production_worker_failed")
    try:
        response = json.loads(completed.stdout.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeError, ValueError):
        raise _error("production_worker_failed") from None
    if not isinstance(response, Mapping) or set(response) != {"ok", "code", "report"}:
        raise _error("production_worker_failed")
    if response.get("ok") is not True:
        code = response.get("code")
        raise _error(code if isinstance(code, str) else "production_worker_failed")
    report = response.get("report")
    if response.get("code") is not None or not isinstance(report, Mapping):
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
    try:
        _validated_capacity_bootstrap()
        _set_production_worker_umask()
        payload = sys.stdin.buffer.read(64 * 1024 + 1)
        request = json.loads(payload.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
        if not isinstance(request, Mapping) or set(request) != {
            "output_dir",
            "attempt_ledger_dir",
            "workspace_root",
            "allow_unignored_output",
            "nonce",
        }:
            raise _error("options_invalid")
        nonce = request.get("nonce")
        if (
            not isinstance(nonce, str)
            or not re.fullmatch(r"[0-9a-f]{64}", nonce)
            or os.environ.get(_PRODUCTION_WORKER_ENV) != nonce
        ):
            raise _error("production_identity_invalid")
        workspace = request.get("workspace_root")
        options = EnronCapacityOptions(
            output_dir=Path(cast(str, request["output_dir"])),
            attempt_ledger_dir=Path(cast(str, request["attempt_ledger_dir"])),
            workspace_root=None if workspace is None else Path(cast(str, workspace)),
            allow_unignored_output=cast(bool, request["allow_unignored_output"]),
        )
        _FRESH_PRODUCTION_WORKER = True
        _preload_production_modules()
        report = _run_capacity_entry(
            options,
            phase_runners=_production_phase_runners(),
            resource_probe=_SystemResourceProbe(),
            production_evidence=True,
            monitor_interval_ns=PRODUCTION_MONITOR_INTERVAL_NS,
            wall_clock=time.monotonic_ns,
        )
        response = {"ok": True, "code": None, "report": report}
    except BaseException as exc:
        code = (
            exc.code
            if isinstance(exc, EnronCapacityError) and exc.code in _ERROR_MESSAGES
            else "production_worker_failed"
        )
        response = {"ok": False, "code": code, "report": None}
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
    """Import every tracked production-core module before identity capture."""

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
    try:
        _capacity_import_guard.assert_installed(Path(__file__).parent.parent)
    except (ImportError, OSError, RuntimeError, TypeError, ValueError):
        raise _error("production_identity_invalid") from None
    if not _PHASE_SCOPED_READER_LOADED:
        _assert_reader_modules_unloaded()
    elif any(import_name not in sys.modules for _name, import_name, _init, _version in _CRITICAL_READER_DISTRIBUTIONS):
        raise _error("production_identity_invalid")
    _require_globally_clean_checkout(git_commit)
    if (
        _git_head() != git_commit
        or execution.get("capacity_implementation_sha256") != _implementation_sha256()
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
        datasets_module, reader_isolation_before, initial_runtime_environment_sha256 = (
            _load_phase_scoped_datasets_reader(context)
        )

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
        activity_callback=context.heartbeat,
        cleanup_successor=context.cleanup_successor,
    )
    if config.input_jsonl is None and (
        options.huggingface_cache_dir != Path(context.runtime_environment["HF_DATASETS_CACHE"])
        or options.huggingface_anonymous is not True
    ):
        raise _CapacityAbort("production_identity_invalid")
    summary = preparation.prepare_enron_source(options)
    if datasets_module is None:
        reader_isolation = _local_reader_isolation()
    else:
        if reader_isolation_before is None or initial_runtime_environment_sha256 is None:
            raise _CapacityAbort("production_identity_invalid")
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
            "sha256": isolation_sha256,
        }
    verified = preparation.load_enron_preparation_run(
        paths.preparation,
        scratch_dir=context.scratch_dir,
        activity_callback=context.heartbeat,
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
            activity_callback=context.heartbeat,
            cleanup_successor=context.cleanup_successor,
        )
    )
    verified = splitting.verify_enron_splits(
        paths.development,
        paths.sealed,
        activity_callback=context.heartbeat,
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
    card = workflow.build_enron_intelligence_bank(
        workflow.EnronBankBuildOptions(
            development_run=paths.development,
            output_dir=paths.bank,
            annotation_run=None,
            cmu_catalog_bindings_path=None,
            allow_unignored_output=True,
            progress_callback=context.checkpoint,
            activity_callback=context.heartbeat,
            cleanup_successor=context.cleanup_successor,
        )
    )
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
        activity_callback=context.heartbeat,
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
        activity_callback=context.heartbeat,
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
        access.get("status") != "sealed_unbound"
        or access.get("access_count") != 0
        or access.get("accessed_at") is not None
        or access.get("aggregate_sha256") is not None
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
        activity_callback=context.heartbeat,
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
    outcome = "passed"
    deferred_finalization_control: KeyboardInterrupt | SystemExit | None = None
    receipt_failure_cleanup_started = False

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
                        )
                        cleanup_failed = not tree_cleanup[0]
                    except (EnronCapacityError, EnronPrivateIOError):
                        cleanup_failed = True
            if isinstance(exc, EnronCapacityError) and exc.code == "promotion_failed":
                raise _error("promotion_failed") from None
            raise _error("promotion_failed" if cleanup_failed else "attempt_ledger_write_failed") from None

        if failure_code is not None:
            raise _error(failure_code) from None
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
                    outcome=outcome,
                    failure_code=failure_code,
                    execution=execution,
                    metrics=metrics,
                )
            except BaseException:
                raise _error("attempt_ledger_write_failed") from None
            raise _error(failure_code) from None
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
    metrics.sensitive_content_wiped = result[0]
    metrics.path_tree_removed = result[1]
    metrics.retained_private_tombstone_count = result[2]


def _inflight_promoted_identity(inflight: _InflightAttempt) -> tuple[int, int]:
    binding = inflight.stage_binding
    if binding is None:
        raise _error("promotion_failed")
    return cast(int, binding["stage_device"]), cast(int, binding["stage_inode"])


def _inflight_output_absent(inflight: _InflightAttempt) -> bool:
    inflight.output_parent.assert_current(code="promotion_failed")
    try:
        os.stat(inflight.output_name, dir_fd=inflight.output_parent.fd, follow_symlinks=False)
    except FileNotFoundError:
        return True
    except OSError:
        raise _error("promotion_failed") from None
    return False


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
                metrics.sensitive_content_wiped = authority_wiped
                if not authority_wiped and recovery_error is None:
                    recovery_error = _error("promotion_failed")
            if owner.cleanup_authority_wiped and _inflight_output_absent(inflight):
                cleanup_result_was_published = metrics.path_tree_removed is not None
                metrics.sensitive_content_wiped = True
                if not cleanup_result_was_published:
                    metrics.path_tree_removed = False
                recovered = True
                if not cleanup_result_was_published and recovery_error is None:
                    recovery_error = _error("promotion_failed")
            else:
                pin = inflight.transaction_pin
                if pin is None or pin.closed:
                    pin = _PinnedDirectory(inflight.output_parent.path / inflight.output_name)
                    inflight.transaction_pin = pin
                result = _wipe_promoted_capacity_run(
                    owner,
                    pin,
                    workspace_root=options.workspace_root,
                    allow_unignored_output=options.allow_unignored_output,
                    expected_identity=_inflight_promoted_identity(inflight),
                )
                inflight.transaction_pin = None
                _publish_promoted_cleanup_metrics(metrics, result)
                recovered = result[0]
                if not result[0] and recovery_error is None:
                    recovery_error = _error("promotion_failed")
        else:
            metrics.sensitive_content_wiped = owner.cleanup_sensitive_content_wiped
            metrics.path_tree_removed = owner.cleanup_path_tree_removed
            metrics.retained_private_tombstone_count = owner.cleanup_tombstone_count
            recovered = _private_run_exit_is_settled(owner)
    except BaseException as exc:
        if recovery_error is None:
            recovery_error = exc
    finally:
        if owner.cleanup_authority_wiped:
            metrics.sensitive_content_wiped = True
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
        )
        inflight.transaction_owner = private_run
        assert private_run is not None
        private_run.__enter__()
        try:
            inflight.output_parent.assert_current(code="private_transaction_failed")
            _bind_inflight_stage(inflight, private_run.stage_dir)
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
            )
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

                runtime_environment, scratch_dir, spool_dir, owned_root_count = _provision_phase_runtime_roots(
                    private_run, active_tree, phase
                )
                context = EnronCapacityPhaseContext(
                    phase,
                    work_dir,
                    checkpoint,
                    declare_owned_root,
                    heartbeat,
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
                if runner_failure is not None:
                    raise _error(runner_failure)
                if result is None:
                    raise _error("phase_result_invalid")
                basic = _validate_phase_result(result)
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
            _verify_capacity_report(report, require_production=bool(execution["production_evidence"]))
            metrics.report_sha256 = cast(str, report["run_sha256"])
            _reassert_production_execution_current(execution)
            _write_report_and_fsync(private_run, payload)

            final_staging_owned = tree.logical_bytes()
            if final_staging_owned + len(_COMMIT_PAYLOAD) != report["totals"]["final_owned_disk_bytes"]:
                raise _error("report_invalid")
            monitor.observe_transaction_boundary(final_staging_owned)
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
                raise _error("private_transaction_failed") from None
            promoted = True
            tree.rebind(final_dir)
            promoted_pin = _PinnedDirectory(final_dir)
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
            metrics.sensitive_content_wiped = private_run.cleanup_sensitive_content_wiped
            metrics.path_tree_removed = private_run.cleanup_path_tree_removed
            metrics.retained_private_tombstone_count = private_run.cleanup_tombstone_count
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
                    promoted_pin = _PinnedDirectory(final_dir)
                promoted_cleanup_result = _wipe_promoted_capacity_run(
                    private_run,
                    promoted_pin,
                    workspace_root=options.workspace_root,
                    allow_unignored_output=options.allow_unignored_output,
                    expected_identity=_inflight_promoted_identity(inflight),
                )
                promoted_cleanup_complete = True
                promoted = False
                promoted_pin = None
                _publish_promoted_cleanup_metrics(metrics, promoted_cleanup_result)
                if not metrics.sensitive_content_wiped:
                    raise _error("promotion_failed")
            except EnronCapacityError:
                raise
            except (EnronPrivateIOError, OSError):
                raise _error("promotion_failed") from None
        if isinstance(effective_error, _CapacityAbort):
            raise _error(effective_error.code) from None
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
                    promoted_pin = _PinnedDirectory(final_dir)
                promoted_cleanup_result = _wipe_promoted_capacity_run(
                    private_run,
                    promoted_pin,
                    workspace_root=options.workspace_root,
                    allow_unignored_output=options.allow_unignored_output,
                    expected_identity=_inflight_promoted_identity(inflight),
                )
                promoted_pin = None
                promoted_cleanup_complete = True
                promoted = False
                _publish_promoted_cleanup_metrics(metrics, promoted_cleanup_result)
                if not metrics.sensitive_content_wiped:
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
                    raise _error(preserved_error.code) from None
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
            )
        }
        if (
            isolation_mode not in {"phase_owned_anonymous_official", "local_fixture_no_remote_reader"}
            or type(effective_path_count) is not int
            or effective_path_count < 0
            or any(type(item) is not bool for item in isolation_booleans.values())
        ):
            raise _error("phase_commitment_invalid")
        if require_production_source and (
            isolation_mode != "phase_owned_anonymous_official"
            or effective_path_count != len(_READER_EFFECTIVE_PATH_LABELS)
            or any(item is not True for item in isolation_booleans.values())
            or value.get("source_reader_endpoint_sha256") != _hash_bytes(_READER_OFFICIAL_ENDPOINT.encode("utf-8"))
            or value.get("source_reader_isolation_sha256") != _expected_remote_reader_isolation_sha256()
        ):
            raise _error("phase_commitment_invalid")
        if isolation_mode == "local_fixture_no_remote_reader" and (
            effective_path_count != 0
            or isolation_booleans["source_reader_official_endpoint"] is not False
            or isolation_booleans["source_reader_restrictive_umask"] is not False
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
                }
            )
            or isolation_booleans["source_reader_explicit_cache_dir"] is not False
            or isolation_booleans["source_reader_explicit_anonymous_load"] is not False
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
            "maximum_resource_observation_wall_gap_ns": int(
                monitor_snapshot["maximum_resource_observation_wall_gap_ns"]
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


def _verify_capacity_report(report: Mapping[str, Any], *, require_production: bool) -> dict[str, Any]:
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
    _verify_execution(execution, require_production=require_production)
    environment = _require_mapping(report.get("environment"), "environment")
    _verify_environment(environment, require_current=execution.get("production_evidence") is False)
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


def _verify_execution(execution: Mapping[str, Any], *, require_production: bool) -> None:
    _require_closed(
        execution,
        {
            "production_evidence",
            "fresh_worker",
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
        _verify_recorded_production_execution(execution)
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
            "peak_process_tree_rss_bytes",
            "owned_disk_high_water_bytes",
            "minimum_free_disk_bytes",
            "maximum_resource_observation_wall_gap_ns",
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
    peak = _positive_int(phase.get("peak_process_tree_rss_bytes"), "phase RSS")
    owned = _bounded_int(phase.get("owned_disk_high_water_bytes"), "phase owned disk", minimum=0)
    minimum_free = _bounded_int(phase.get("minimum_free_disk_bytes"), "phase free disk", minimum=0)
    maximum_resource_wall_gap = _bounded_int(
        phase.get("maximum_resource_observation_wall_gap_ns"), "resource wall gap", minimum=0
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
            "boundary",
        }:
            raise _error("report_invalid")
        completed = sample.get("completed_records")
        if completed is not None and (type(completed) is not int or completed <= 0 or completed > records):
            raise _error("report_invalid")
        _positive_int(sample.get("process_tree_rss_bytes"), "sample RSS")
        _bounded_int(sample.get("owned_disk_bytes"), "sample owned disk", minimum=0)
        _bounded_int(sample.get("free_disk_bytes"), "sample free disk", minimum=0)
        samples.append(sample)
    if (
        max(int(item["process_tree_rss_bytes"]) for item in samples) != peak
        or max(int(item["owned_disk_bytes"]) for item in samples) != owned
        or min(int(item["free_disk_bytes"]) for item in samples) != minimum_free
        or max(int(item["resource_observation_wall_gap_ns"]) for item in samples) != maximum_resource_wall_gap
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
            or kind not in {"checkpoint", "heartbeat", "phase_boundary"}
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
            "maximum_resource_observation_wall_gap_ns",
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
    if (
        totals["source_rows_accounted"] != ENRON_SOURCE_ROWS
        or totals["elapsed_ns"] < sum(int(phase["elapsed_ns"]) for phase in phases)
        or totals["resource_observation_count"] < sum(int(phase["resource_observation_count"]) for phase in phases)
        or totals["maximum_resource_observation_wall_gap_ns"]
        < max(int(phase["maximum_resource_observation_wall_gap_ns"]) for phase in phases)
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
    runner_hashes = {
        phase: _callable_implementation_sha256(runner, role=f"phase:{phase}", git_commit=git_commit)
        for phase, runner in runners
    }
    execution = {
        "production_evidence": production_evidence,
        "fresh_worker": False,
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
    return {
        "production_evidence": True,
        "fresh_worker": True,
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
                continue
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
    ):
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
) -> tuple[Any, dict[str, Any], str]:
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
    before = _reader_isolation_snapshot(context, datasets_module, stage="before_source_read")
    if runtime_environment_sha256 != _canonical_hash(_runtime_environment_identity()):
        raise _CapacityAbort("production_identity_invalid")
    _PHASE_SCOPED_READER_LOADED = True
    return datasets_module, before, runtime_environment_sha256


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
        _source_root, dependencies, layouts = _validated_capacity_bootstrap()
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


def _sample_runtime_filesystems(
    probe: CapacityResourceProbe,
    preflight: _Preflight,
) -> tuple[int, CapacityDiskUsage]:
    minimum_free: int | None = None
    output_disk: CapacityDiskUsage | None = None
    for filesystem in preflight.filesystems:
        if _probe_filesystem_device(probe, filesystem.probe_path) != filesystem.device:
            raise _error("runtime_filesystem_changed")
        disk = _probe_disk_usage(probe, filesystem.probe_path)
        minimum_free = disk.free if minimum_free is None else min(minimum_free, disk.free)
        if filesystem.includes_output:
            if output_disk is not None:
                raise _error("runtime_filesystem_changed")
            output_disk = disk
    if minimum_free is None or output_disk is None:
        raise _error("resource_measurement_failed")
    return minimum_free, output_disk


def _probe_monotonic_ns(probe: CapacityResourceProbe) -> int:
    try:
        value = probe.monotonic_ns()
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
    _merge_monitor_metrics(metrics, monitor.global_snapshot())
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


def _append_attempt_receipt(
    ledger: _AttemptLedger,
    *,
    inflight: _InflightAttempt | None,
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
            attempt_sequence = int(inflight.record["attempt_sequence"])
            attempt_nonce_sha256 = _hash_bytes(inflight.nonce.encode("ascii"))
            identity = inflight.record
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
) -> bool:
    """Make a durably published receipt authoritative before cleanup can branch."""

    if durable_commit != bytearray(b"\x01"):
        return False
    receipts = _read_attempt_receipts_locked(descriptor)
    if not receipts or receipts[-1] != receipt:
        return False
    if receipt.get("outcome") == "passed":
        _verify_recovered_promoted_output(
            inflight.output_parent.path / inflight.output_name,
            inflight.output_parent,
            inflight.record,
            receipt,
            inflight.stage_binding,
        )
    else:
        _assert_owned_attempt_output_absent(inflight)
    inflight.receipt_appended = True
    _remove_inflight_files_locked(inflight)
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
        "sensitive_content_wiped": metrics.sensitive_content_wiped,
        "path_tree_removed": metrics.path_tree_removed,
        "retained_private_tombstone_count": metrics.retained_private_tombstone_count,
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


def _remove_inflight_files_locked(inflight: _InflightAttempt) -> None:
    names = set(os.listdir(inflight.ledger.fd))
    if inflight.marker_name not in names:
        if not inflight.receipt_appended or inflight.binding_name in names or inflight.cleanup_inventory_name in names:
            raise _error("attempt_ledger_invalid")
        return
    _assert_inflight_marker_current(inflight)
    marker_fd = inflight.marker_fd
    if marker_fd is None:
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
            _wipe_and_quarantine_private_file_at(
                inflight.ledger.fd,
                inflight.cleanup_inventory_name,
                inventory_fd,
                inventory_identity,
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
            _wipe_and_quarantine_private_file_at(
                inflight.ledger.fd,
                inflight.binding_name,
                binding_fd,
                binding_identity,
            )
        finally:
            try:
                fcntl.flock(binding_fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(binding_fd)
    elif inflight.stage_binding is not None and not inflight.receipt_appended:
        raise _error("attempt_ledger_invalid")
    _wipe_and_quarantine_private_file_at(
        inflight.ledger.fd,
        inflight.marker_name,
        marker_fd,
        _regular_file_identity(os.fstat(marker_fd)),
    )


def _assert_owned_attempt_output_absent(inflight: _InflightAttempt) -> None:
    inflight.output_parent.assert_current(code="attempt_ledger_invalid")
    stage_name = f".{inflight.output_name}.stage-{inflight.stage_token}"
    expected = (
        None
        if inflight.stage_binding is None
        else (
            cast(int, inflight.stage_binding["stage_device"]),
            cast(int, inflight.stage_binding["stage_inode"]),
        )
    )
    for name in (stage_name, inflight.output_name):
        try:
            info = os.stat(name, dir_fd=inflight.output_parent.fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError:
            raise _error("attempt_ledger_invalid") from None
        identity = int(info.st_dev), int(info.st_ino)
        if (expected is None and name == stage_name) or identity == expected:
            raise _error("attempt_ledger_invalid")


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
        if (
            _ATTEMPT_NAME_RE.fullmatch(name)
            or _INFLIGHT_NAME_RE.fullmatch(name)
            or (binding is not None and binding.group(1) in markers)
            or (cleanup_inventory is not None and cleanup_inventory.group(1) in markers)
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
            nonce_sha256 = _hash_bytes(cast(str, record["attempt_nonce"]).encode("ascii"))
            matching = [item for item in receipts if item["attempt_nonce_sha256"] == nonce_sha256]
            if len(matching) > 1:
                raise _error("attempt_ledger_invalid")
            if matching:
                terminal = matching[0]
                if terminal["attempt_sequence"] != record["attempt_sequence"]:
                    raise _error("attempt_ledger_invalid")
                if terminal["outcome"] == "passed":
                    _verify_recovered_promoted_output(final_dir, output_parent, record, terminal, binding)
                else:
                    _cleanup_recovered_stage(
                        final_dir,
                        output_parent,
                        record,
                        binding,
                        cleanup_inventory,
                        options=options,
                    )
            else:
                cleanup_evidence = _cleanup_recovered_stage(
                    final_dir,
                    output_parent,
                    record,
                    binding,
                    cleanup_inventory,
                    options=options,
                )
                metrics = _AttemptMetrics(
                    started_ns=cast(int, record["started_monotonic_ns"]),
                    elapsed_ns=max(0, time.monotonic_ns() - cast(int, record["started_wall_monotonic_ns"])),
                    sensitive_content_wiped=cleanup_evidence[0],
                    path_tree_removed=cleanup_evidence[1],
                    retained_private_tombstone_count=cleanup_evidence[2],
                )
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
            recovered_attempt = _InflightAttempt(
                ledger=ledger,
                record=dict(record),
                marker_name=marker_name,
                marker=marker,
                output_parent=output_parent,
                output_name=final_dir.name,
                stage_binding=None if binding is None else dict(binding),
                cleanup_inventory=None if cleanup_inventory is None else dict(cleanup_inventory),
            )
            marker = None
            output_parent = None
            try:
                _remove_inflight_files_locked(recovered_attempt)
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
    parent = _PinnedDirectory(final_dir.parent)
    if parent.identity.device != record.get("output_parent_device") or parent.identity.inode != record.get(
        "output_parent_inode"
    ):
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


def _cleanup_recovered_stage(
    final_dir: Path,
    output_parent: _PinnedDirectory,
    record: Mapping[str, Any],
    binding: Mapping[str, Any] | None,
    cleanup_inventory: Mapping[str, Any] | None,
    *,
    options: EnronCapacityOptions,
) -> tuple[bool | None, bool | None, int]:
    output_parent.assert_current(code="attempt_ledger_invalid")
    stage_name = f".{final_dir.name}.stage-{record['stage_token']}"
    stage_identity = _entry_identity_at(output_parent.fd, stage_name)
    final_identity = _entry_identity_at(output_parent.fd, final_dir.name)
    expected = None if binding is None else (cast(int, binding["stage_device"]), cast(int, binding["stage_inode"]))
    if binding is None:
        if cleanup_inventory is not None:
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
    matching = [
        name
        for name, identity in ((stage_name, stage_identity), (final_dir.name, final_identity))
        if identity == expected
    ]
    if (stage_identity is not None and stage_identity != expected) or (
        final_identity is not None and final_identity != expected
    ):
        raise _error("attempt_ledger_invalid")
    if len(matching) > 1:
        raise _error("attempt_ledger_invalid")
    if matching:
        candidate: _PinnedDirectory | None = None
        try:
            candidate = _PinnedDirectory(output_parent.path / matching[0])
            output_parent.assert_current(code="attempt_ledger_invalid")
            if (candidate.identity.device, candidate.identity.inode) != expected:
                raise _error("attempt_ledger_invalid")
            expected_files = (
                set()
                if cleanup_inventory is None
                else {
                    (cast(int, item["device"]), cast(int, item["inode"]))
                    for item in cast(Sequence[Mapping[str, Any]], cleanup_inventory["files"])
                }
            )
            removed = _private_io._wipe_and_quarantine_pinned_private_directory_with_inventory(  # noqa: SLF001
                candidate.fd,
                candidate.parent_fd,
                candidate.path.parent,
                candidate.name,
                (candidate.identity.device, candidate.identity.inode),
                expected_files,
                workspace_root=options.workspace_root,
                allow_unignored_output=options.allow_unignored_output,
            )
            candidate.close()
            candidate = None
            return removed[0] and cleanup_inventory is not None, removed[1], removed[2]
        except EnronCapacityError:
            raise
        except EnronPrivateIOError:
            raise _error("attempt_ledger_invalid") from None
        finally:
            if candidate is not None:
                candidate.close()
    if cleanup_inventory is not None:
        return False, None, 0
    return None, None, 0


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
        if (candidate.identity.device, candidate.identity.inode) != expected_identity or os.listdir(candidate.fd):
            raise _error("attempt_ledger_invalid")
        candidate.assert_current(code="attempt_ledger_invalid")
        return _remove_pinned_directory(
            candidate,
            workspace_root=options.workspace_root,
            allow_unignored_output=options.allow_unignored_output,
        )
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
        output_parent.assert_current(code="attempt_ledger_invalid")
        if expected_identity is not None and (candidate.identity.device, candidate.identity.inode) != expected_identity:
            raise _error("attempt_ledger_invalid")
        return _remove_pinned_directory(
            candidate,
            workspace_root=options.workspace_root,
            allow_unignored_output=options.allow_unignored_output,
        )
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
        or receipt.get("policy_sha256") != capacity_policy()["policy_sha256"]
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
) -> tuple[bool, bool, int]:
    try:
        pinned.assert_current(code="promotion_failed")
        return _private_io._wipe_and_quarantine_pinned_private_directory(  # noqa: SLF001
            pinned.fd,
            pinned.parent_fd,
            pinned.path.parent,
            pinned.name,
            (pinned.identity.device, pinned.identity.inode),
            workspace_root=workspace_root,
            allow_unignored_output=allow_unignored_output,
        )
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

#!/usr/bin/env python3
"""Run a same-host synthetic soak of the production resource observer protocol.

The public process is the launcher.  It starts an isolated worker using the
same launcher/worker resource-observer classes as a production capacity run,
but the worker uses only generated data in an owner-only temporary tree.

The default duration is the required thirty-minute soak.  Shorter durations
are useful smoke checks, but the emitted report never labels them
decision-grade.  Output is deliberately aggregate-only: no samples, process
identifiers, source values, hostnames, usernames, or filesystem paths are
serialized.

PyArrow is optional because it is not a core dependency.  Its absence is
reported as a coverage limitation.  Observer CPU overhead is exact per-thread
CPU time for the protocol and deadline-supervisor threads.  Memory is only a
conservative launcher-process high-water bound; Python does not expose
per-thread allocation high-water marks.
"""

from __future__ import annotations

import argparse
import ctypes
import gc
import json
import math
import os
import secrets
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, NoReturn

from nerb import Bank, enron_capacity

_DEFAULT_DURATION_SECONDS = 1_800.0
_INJECTED_STALL_NS = 501_000_000
_EXPECTED_INTERVAL_NS = 100_000_000
_EXPECTED_LIMIT_NS = 500_000_000
_MAX_WORKER_RESULT_BYTES = 64 * 1024
_MIN_LARGE_TREE_REGULAR_ENTRIES = 10_000
_LARGE_TREE_DIRECTORIES = 100
_LARGE_TREE_FILES_PER_DIRECTORY = 100
_PHASE = "preparation"


def _safe_error_code(exc: BaseException) -> str:
    code = getattr(exc, "code", None)
    if isinstance(code, str) and code and len(code) <= 80 and code.replace("_", "").isalnum():
        return code
    return "soak_failed"


def _write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    try:
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("result channel closed")
            view = view[written:]
    finally:
        view.release()


def _read_bounded(fd: int) -> bytes:
    result = bytearray()
    while chunk := os.read(fd, 8_192):
        result.extend(chunk)
        if len(result) > _MAX_WORKER_RESULT_BYTES:
            raise RuntimeError("worker result exceeded aggregate bound")
    return bytes(result)


def _build_preflight(output_parent: Path, ledger_dir: Path) -> enron_capacity._Preflight:
    probe = enron_capacity._SystemResourceProbe()
    physical = probe.physical_memory_bytes()
    rss = probe.process_tree_rss_bytes(os.getpid())
    if not isinstance(physical, int) or physical <= 0 or not isinstance(rss, int) or rss <= 0:
        raise RuntimeError("resource probe unavailable")
    effective = min(
        enron_capacity.MAX_ABSOLUTE_RSS_BYTES,
        physical
        * enron_capacity.PHYSICAL_MEMORY_FRACTION_NUMERATOR
        // enron_capacity.PHYSICAL_MEMORY_FRACTION_DENOMINATOR,
    )
    maximum_peak = (
        effective * enron_capacity.PEAK_RSS_FRACTION_NUMERATOR // enron_capacity.PEAK_RSS_FRACTION_DENOMINATOR
    )
    observations: list[tuple[Path, bool, int, int]] = []
    for path, includes_output in ((output_parent, True), (ledger_dir, False)):
        device = probe.filesystem_device(path)
        usage = probe.disk_usage(path)
        if not isinstance(device, int) or usage is None:
            raise RuntimeError("filesystem probe unavailable")
        observations.append((path, includes_output, device, usage.free))
    output = observations[0]
    ledger = observations[1]
    if output[2] == ledger[2]:
        filesystems = (
            enron_capacity._FilesystemPreflight(
                device=output[2],
                probe_path=output[0],
                preflight_free_disk_bytes=min(output[3], ledger[3]),
                includes_output=True,
            ),
        )
    else:
        filesystems = (
            enron_capacity._FilesystemPreflight(
                device=output[2],
                probe_path=output[0],
                preflight_free_disk_bytes=output[3],
                includes_output=True,
            ),
            enron_capacity._FilesystemPreflight(
                device=ledger[2],
                probe_path=ledger[0],
                preflight_free_disk_bytes=ledger[3],
                includes_output=False,
            ),
        )
    return enron_capacity._Preflight(
        physical_memory_bytes=physical,
        effective_rss_cap_bytes=effective,
        maximum_peak_rss_bytes=maximum_peak,
        preflight_process_tree_rss_bytes=rss,
        preflight_free_disk_bytes=min(item[3] for item in observations),
        output_preflight_free_disk_bytes=output[3],
        preexisting_private_tombstone_count=0,
        filesystems=filesystems,
    )


def _owner_only_directory(path: Path) -> None:
    path.mkdir(mode=0o700)
    path.chmod(0o700)


def _seed_large_owner_only_tree(root: Path) -> tuple[Path, int]:
    seed_root = root / "large-seed"
    _owner_only_directory(seed_root)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    seeded = 0
    payload = b"synthetic-observer-entry\n"
    for directory_index in range(_LARGE_TREE_DIRECTORIES):
        directory = seed_root / f"partition-{directory_index:03d}"
        _owner_only_directory(directory)
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0))
        try:
            for file_index in range(_LARGE_TREE_FILES_PER_DIRECTORY):
                descriptor = os.open(f"entry-{file_index:03d}.bin", flags, 0o600, dir_fd=directory_fd)
                try:
                    _write_all(descriptor, payload)
                    os.fchmod(descriptor, 0o600)
                finally:
                    os.close(descriptor)
                seeded += 1
        finally:
            os.close(directory_fd)
    if seeded < _MIN_LARGE_TREE_REGULAR_ENTRIES:
        raise RuntimeError("large synthetic tree was undersized")
    return seed_root, seeded


def _owner_only_regular_entry_count(root: Path) -> int:
    owner = os.geteuid() if hasattr(os, "geteuid") else root.stat().st_uid
    pending = [root]
    regular_entries = 0
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                info = entry.stat(follow_symlinks=False)
                mode = stat.S_IMODE(info.st_mode)
                if info.st_uid != owner or not enron_capacity.is_owner_only_private_mode(mode):
                    raise RuntimeError("synthetic tree permissions changed")
                if stat.S_ISDIR(info.st_mode):
                    pending.append(Path(entry.path))
                elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    regular_entries += 1
                else:
                    raise RuntimeError("synthetic tree entry changed type")
    return regular_entries


def _replace_synthetic_file(root: Path, iteration: int) -> None:
    segment = root / "segments" / f"{iteration % 8:02d}"
    target = segment / f"block-{iteration % 32:02d}.bin"
    staged = segment / f".next-{iteration % 32:02d}.bin"
    payload = bytes([iteration % 251]) * (4_096 + (iteration % 16) * 257)
    with staged.open("wb") as handle:
        handle.write(payload)
        handle.flush()
    staged.chmod(0o600)
    os.replace(staged, target)


def _open_sqlite_workload(root: Path) -> sqlite3.Connection:
    database = root / "synthetic.sqlite3"
    connection = sqlite3.connect(database)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
    connection.execute("CREATE TABLE observations (sequence INTEGER PRIMARY KEY, bucket INTEGER, payload TEXT)")
    connection.commit()
    database.chmod(0o600)
    return connection


def _run_sqlite_batch(connection: sqlite3.Connection, iteration: int) -> None:
    start = iteration * 16
    connection.executemany(
        "INSERT INTO observations(sequence, bucket, payload) VALUES (?, ?, ?)",
        ((start + offset, (start + offset) % 97, f"synthetic-{(start + offset) % 1_000:04d}") for offset in range(16)),
    )
    retained_from = max(0, start - 4_096)
    connection.execute("DELETE FROM observations WHERE sequence < ?", (retained_from,))
    connection.execute(
        "SELECT bucket, COUNT(*) FROM observations WHERE sequence >= ? GROUP BY bucket ORDER BY bucket",
        (retained_from,),
    ).fetchall()
    connection.commit()


class _ArrowWorkload:
    def __init__(self, root: Path) -> None:
        self.available = False
        self._compute: Any = None
        self._table: Any = None
        try:
            import pyarrow as pa
            import pyarrow.compute as pc
            import pyarrow.ipc as ipc

            self._compute = pc
            self._table = pa.table(
                {
                    "sequence": list(range(4_096)),
                    "bucket": [index % 127 for index in range(4_096)],
                    "label": [f"synthetic-{index % 64:02d}" for index in range(4_096)],
                }
            )
            destination = root / "synthetic.arrow"
            with pa.OSFile(os.fspath(destination), "wb") as sink, ipc.new_file(sink, self._table.schema) as writer:
                writer.write_table(self._table)
            destination.chmod(0o600)
            self.available = True
        except (ImportError, OSError, RuntimeError, TypeError, ValueError):
            self._compute = None
            self._table = None

    def run(self) -> bool:
        if not self.available:
            return False
        self._compute.sum(self._table["bucket"])
        self._compute.value_counts(self._table["label"])
        return True


class _NativeWorkload:
    def __init__(self) -> None:
        self.available = False
        self._bank: Bank | None = None
        self._document = b""
        try:
            self._bank = Bank.from_source_bytes(
                b'{"TOKEN":{"Synthetic":"SYNTH-[0-9]{6}","_flags":["IGNORECASE"]}}',
                format_hint="json",
                use_cache=False,
            )
            unit = b"generated text SYNTH-000042 with neutral padding\n"
            self._document = unit * max(1, 64 * 1_024 // len(unit))
            if not self._bank.scan_bytes(self._document, max_matches=4_096):
                raise RuntimeError("native workload returned no records")
            self.available = True
        except (ImportError, RuntimeError, TypeError, ValueError):
            self._bank = None
            self._document = b""

    def run(self) -> bool:
        if self._bank is None:
            return False
        return bool(self._bank.scan_bytes(self._document, max_matches=4_096))


_GRANDCHILD_CODE = "import time;data=bytearray(4*1024*1024);data[::4096]=bytes(len(data[::4096]));time.sleep(0.18)"
_CHILD_CODE = (
    "import subprocess,sys,time;"
    "data=bytearray(4*1024*1024);"
    "data[::4096]=bytes(len(data[::4096]));"
    "child=subprocess.Popen([sys.executable,'-I','-c',sys.argv[1]],"
    "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);"
    "time.sleep(0.08);"
    "code=child.wait();"
    "raise SystemExit(code)"
)


def _run_descendant_churn() -> None:
    process = subprocess.Popen(
        [sys.executable, "-I", "-c", _CHILD_CODE, _GRANDCHILD_CODE],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )
    try:
        if process.wait(timeout=5) != 0:
            raise RuntimeError("synthetic descendant failed")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def _gil_holding_usleep() -> Any:
    function = ctypes.PyDLL(None).usleep
    function.argtypes = (ctypes.c_uint,)
    function.restype = ctypes.c_int
    return function


def _synchronize_remote_observer(monitor: enron_capacity._ContinuousResourceMonitor) -> None:
    remote = monitor._remote
    if remote is None:
        raise RuntimeError("remote observer unavailable")
    remote.force("boundary")


class _SoakMonitor(enron_capacity._ContinuousResourceMonitor):
    """Production monitor that retains only the aggregate name of a failing stage."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.failure_origin: str | None = None
        self.failure_condition: str | None = None
        super().__init__(*args, **kwargs)

    def _record_failure(self, code: str, *, diagnostic: Mapping[str, Any] | None = None) -> None:
        if self._failure_code is None:
            self.failure_origin = sys._getframe(1).f_code.co_name
        super()._record_failure(code, diagnostic=diagnostic)

    def _accept_remote_resource_sample(self, **sample: Any) -> None:
        wall_now = int(sample["wall_now"])
        now = int(sample["now"])
        provided_gap = int(sample["wall_gap"])
        with self._lock:
            previous_global = self._global_last_resource_wall_ns
            expected_gap = 0 if previous_global is None else wall_now - previous_global
            if now < self.run_started_ns:
                condition = "sample_before_run"
            elif now < self._global_last_probe_ns:
                condition = "sample_before_previous_probe"
            elif expected_gap < 0:
                condition = "negative_global_gap"
            elif provided_gap != expected_gap:
                condition = "global_gap_mismatch"
            else:
                phase = self._current_phase
                state = None if phase is None else self._states[phase]
                if state is not None and now < state.started_ns:
                    condition = "sample_before_phase"
                elif state is not None and wall_now < (state.last_resource_wall_ns or state.started_wall_ns):
                    condition = "negative_phase_resource_gap"
                elif state is not None and wall_now < (state.last_progress_wall_ns or state.started_wall_ns):
                    condition = "negative_phase_progress_gap"
                else:
                    condition = None
        prior_failure = self._failure_code
        super()._accept_remote_resource_sample(**sample)
        if prior_failure is None and self._failure_code == "clock_invalid":
            self.failure_condition = condition or "unclassified_clock_condition"


def _positive_worker(
    endpoint: socket.socket,
    *,
    duration_seconds: float,
    nonce: str,
    tree_root: Path,
    output_parent: Path,
    ledger_dir: Path,
) -> dict[str, Any]:
    segments = tree_root / "segments"
    _owner_only_directory(segments)
    for index in range(8):
        _owner_only_directory(segments / f"{index:02d}")
    seed_root, seeded_regular_entries = _seed_large_owner_only_tree(tree_root)

    guard = enron_capacity._PrivateTreeGuard(tree_root)
    monitor = _SoakMonitor(
        tree=guard,
        probe=enron_capacity._SystemResourceProbe(),
        preflight=_build_preflight(output_parent, ledger_dir),
        run_started_ns=time.monotonic_ns(),
        interval_ns=enron_capacity.PRODUCTION_MONITOR_INTERVAL_NS,
        wall_clock=time.monotonic_ns,
        resource_observer_socket=endpoint,
        resource_observer_nonce=nonce,
    )
    connection: sqlite3.Connection | None = None
    monitor_started = False
    workload_started_ns = 0
    result: dict[str, Any] | None = None
    first_error: BaseException | None = None
    failure_stage = "workload_setup"
    try:
        connection = _open_sqlite_workload(tree_root)
        arrow = _ArrowWorkload(tree_root)
        native = _NativeWorkload()
        usleep = _gil_holding_usleep()
        failure_stage = "monitor_start"
        monitor.start()
        monitor_started = True
        phase_started_ns = time.monotonic_ns()
        failure_stage = "phase_start"
        monitor.begin_phase(_PHASE, phase_started_ns)

        workload_started_ns = time.monotonic_ns()
        deadline_ns = workload_started_ns + math.ceil(duration_seconds * 1_000_000_000)
        checkpoint_interval_ns = max(2_000_000_000, math.ceil(duration_seconds * 1_000_000_000 / 900))
        next_checkpoint_ns = workload_started_ns
        next_activity_ns = workload_started_ns
        next_churn_ns = workload_started_ns
        next_gil_hold_ns = workload_started_ns
        iteration = 0
        last_checkpoint_records = 0
        arrow_batches = 0
        native_scans = 0
        descendant_churn_cycles = 0
        gil_holds = 0

        while iteration == 0 or time.monotonic_ns() < deadline_ns:
            iteration += 1
            failure_stage = "tree_mutation"
            _replace_synthetic_file(tree_root, iteration)
            failure_stage = "sqlite_workload"
            _run_sqlite_batch(connection, iteration)
            failure_stage = "columnar_workload"
            if arrow.run():
                arrow_batches += 1
            failure_stage = "native_workload"
            if native.run():
                native_scans += 1

            now_ns = time.monotonic_ns()
            if now_ns >= next_churn_ns:
                failure_stage = "descendant_churn"
                _run_descendant_churn()
                descendant_churn_cycles += 1
                next_churn_ns = now_ns + 5_000_000_000
            if now_ns >= next_gil_hold_ns:
                failure_stage = "held_gil_interval"
                # This exceeds the 500 ms observation-gap gate.  A passing
                # global gap distribution therefore proves that launcher
                # samples completed while the worker could not run Python.
                if usleep(850_000) != 0:
                    raise RuntimeError("C-held-GIL interval failed")
                gil_holds += 1
                next_gil_hold_ns = now_ns + 3_000_000_000

            now_ns = time.monotonic_ns()
            activity_due = now_ns >= next_activity_ns
            checkpoint_due = now_ns >= next_checkpoint_ns
            if activity_due or checkpoint_due:
                # A C-held GIL interval can leave older continuous frames queued
                # for the worker receiver.  Drain them before publishing a
                # newer progress timestamp; checkpoint/activity own any exact
                # tree scan their policy requires.
                failure_stage = "progress_synchronization"
                _synchronize_remote_observer(monitor)
            if activity_due:
                failure_stage = "activity_signal"
                monitor.activity(_PHASE)
                next_activity_ns = now_ns + 1_000_000_000
            if checkpoint_due:
                failure_stage = "checkpoint"
                monitor.checkpoint(_PHASE, iteration)
                last_checkpoint_records = iteration
                next_checkpoint_ns = now_ns + checkpoint_interval_ns
            time.sleep(0.02)

        connection.commit()
        connection.close()
        connection = None
        if last_checkpoint_records != iteration:
            failure_stage = "final_progress_synchronization"
            _synchronize_remote_observer(monitor)
            failure_stage = "final_checkpoint"
            monitor.checkpoint(_PHASE, iteration)
        failure_stage = "phase_finish"
        monitor.finish_phase(_PHASE, iteration)
        failure_stage = "monitor_stop"
        monitor.stop()
        monitor_started = False
        monitor.raise_if_failed()
        failure_stage = "terminal_tree_count"
        retained_seed_regular_entries = _owner_only_regular_entry_count(seed_root)
        terminal_regular_entries = _owner_only_regular_entry_count(tree_root)
        elapsed_ns = time.monotonic_ns() - workload_started_ns
        result = {
            "ok": True,
            "workload_elapsed_ns": elapsed_ns,
            "workload_iterations": iteration,
            "workloads": {
                "owner_only_tree_mutations": iteration,
                "owner_only_tree_seeded_regular_entries": seeded_regular_entries,
                "owner_only_tree_retained_seed_regular_entries": retained_seed_regular_entries,
                "owner_only_tree_terminal_regular_entries": terminal_regular_entries,
                "sqlite_transactions": iteration,
                "pyarrow_available": arrow.available,
                "pyarrow_batches": arrow_batches,
                "native_rust_available": native.available,
                "native_rust_scans": native_scans,
                "c_held_gil_intervals": gil_holds,
                "descendant_churn_cycles": descendant_churn_cycles,
            },
            "resource_snapshot": monitor.global_snapshot(),
        }
    except BaseException as exc:
        first_error = exc
    finally:
        if connection is not None:
            try:
                connection.close()
            except BaseException as exc:
                first_error = first_error or exc
        if monitor_started:
            try:
                monitor.stop()
            except BaseException as exc:
                first_error = first_error or exc
        try:
            guard.close()
        except BaseException as exc:
            first_error = first_error or exc
    if first_error is not None:
        return {
            "ok": False,
            "error_code": _safe_error_code(first_error),
            "failure_stage": failure_stage,
            "failure_origin": monitor.failure_origin,
            "failure_condition": monitor.failure_condition,
        }
    if result is None:
        return {"ok": False, "error_code": "soak_failed"}
    return result


def _stall_worker(
    endpoint: socket.socket,
    *,
    nonce: str,
    tree_root: Path,
    output_parent: Path,
    ledger_dir: Path,
) -> dict[str, Any]:
    guard = enron_capacity._PrivateTreeGuard(tree_root)
    monitor = enron_capacity._ContinuousResourceMonitor(
        tree=guard,
        probe=enron_capacity._SystemResourceProbe(),
        preflight=_build_preflight(output_parent, ledger_dir),
        run_started_ns=time.monotonic_ns(),
        interval_ns=enron_capacity.PRODUCTION_MONITOR_INTERVAL_NS,
        wall_clock=time.monotonic_ns,
        resource_observer_socket=endpoint,
        resource_observer_nonce=nonce,
    )
    observed_code = "missing_failure"
    try:
        monitor.start()
    except BaseException as exc:
        observed_code = _safe_error_code(exc)
    finally:
        try:
            monitor.stop()
        except BaseException as exc:
            if observed_code == "missing_failure":
                observed_code = _safe_error_code(exc)
        guard.close()
    return {
        "ok": False,
        "error_code": observed_code,
    }


def _worker_main(arguments: Sequence[str]) -> NoReturn:
    if len(arguments) != 7:
        raise SystemExit(2)
    os.umask(0o077)
    mode, observer_raw, result_raw, duration_raw, nonce, tree_raw, output_raw = arguments
    observer_fd = int(observer_raw)
    result_fd = int(result_raw)
    duration_seconds = float(duration_raw)
    tree_root = Path(tree_raw)
    output_parent = Path(output_raw)
    ledger_dir = output_parent.parent / "ledger"
    endpoint = socket.socket(fileno=observer_fd)
    result: dict[str, Any]
    try:
        if mode == "positive":
            result = _positive_worker(
                endpoint,
                duration_seconds=duration_seconds,
                nonce=nonce,
                tree_root=tree_root,
                output_parent=output_parent,
                ledger_dir=ledger_dir,
            )
        elif mode == "stall":
            result = _stall_worker(
                endpoint,
                nonce=nonce,
                tree_root=tree_root,
                output_parent=output_parent,
                ledger_dir=ledger_dir,
            )
        else:
            result = {"ok": False, "error_code": "worker_mode_invalid"}
    except BaseException as exc:
        result = {"ok": False, "error_code": _safe_error_code(exc)}
    finally:
        endpoint.close()
    payload = json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    try:
        _write_all(result_fd, payload)
    finally:
        os.close(result_fd)
    raise SystemExit(0 if result.get("ok") is True else 1)


class _MeasuredLauncherObserver(enron_capacity._LauncherResourceObserver):
    """Production observer with aggregate-only timing and thread-CPU accounting."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.acquisition_durations_ns: list[int] = []
        self.completion_gaps_ns: list[int] = []
        self.scheduler_lateness_ns: list[int] = []
        self.valid_sample_count = 0
        self.invalid_sample_count = 0
        self.protocol_thread_cpu_ns = 0
        self.supervisor_thread_cpu_ns = 0
        self._metrics_lock = threading.Lock()
        super().__init__(*args, **kwargs)

    def _send(self, frame: Mapping[str, Any]) -> None:
        if frame.get("type") == "sample":
            with self._metrics_lock:
                if frame.get("valid") is True:
                    self.valid_sample_count += 1
                    self.acquisition_durations_ns.append(int(frame["acquisition_duration_ns"]))
                    self.scheduler_lateness_ns.append(int(frame["scheduler_lateness_ns"]))
                    if int(frame["event_sequence"]) > 1:
                        self.completion_gaps_ns.append(int(frame["resource_observation_wall_gap_ns"]))
                else:
                    self.invalid_sample_count += 1
        super()._send(frame)

    def _run(self) -> None:
        started_ns = time.thread_time_ns()
        try:
            super()._run()
        finally:
            self.protocol_thread_cpu_ns = time.thread_time_ns() - started_ns

    def _supervise_deadlines(self) -> None:
        started_ns = time.thread_time_ns()
        try:
            super()._supervise_deadlines()
        finally:
            self.supervisor_thread_cpu_ns = time.thread_time_ns() - started_ns

    def aggregate_metrics(self, wall_elapsed_ns: int) -> dict[str, Any]:
        with self._metrics_lock:
            acquisitions = tuple(self.acquisition_durations_ns)
            gaps = tuple(self.completion_gaps_ns)
            lateness = tuple(self.scheduler_lateness_ns)
            valid_count = self.valid_sample_count
            invalid_count = self.invalid_sample_count
        cpu_ns = self.protocol_thread_cpu_ns + self.supervisor_thread_cpu_ns
        return {
            "valid_sample_count": valid_count,
            "invalid_sample_count": invalid_count,
            "percentile_method": "nearest_rank",
            "acquisition_duration_ns": _percentiles(acquisitions),
            "completion_to_completion_gap_ns": _percentiles(gaps),
            "scheduler_lateness_ns": _percentiles(lateness),
            "observer_thread_cpu_ns": cpu_ns,
            "observer_thread_cpu_fraction": round(cpu_ns / max(1, wall_elapsed_ns), 8),
        }


def _percentiles(values: Sequence[int]) -> dict[str, int | None]:
    ordered = sorted(values)

    def nearest_rank(percentile: float) -> int | None:
        if not ordered:
            return None
        return ordered[max(0, math.ceil(percentile * len(ordered)) - 1)]

    return {
        "count": len(ordered),
        "p50": nearest_rank(0.50),
        "p95": nearest_rank(0.95),
        "p99": nearest_rank(0.99),
        "max": ordered[-1] if ordered else None,
    }


def _process_group_gone(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return True
    except OSError:
        return False
    return False


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    # The session leader may crash while a child or grandchild remains in its
    # isolated process group.  Group cleanup must not depend on leader liveness.
    if not _process_group_gone(process.pid):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if process.poll() is None:
        process.wait(timeout=5)
    deadline = time.monotonic() + 5.0
    while not _process_group_gone(process.pid) and time.monotonic() < deadline:
        time.sleep(0.01)


def _run_case(
    *,
    mode: str,
    duration_seconds: float,
    case_root: Path,
) -> dict[str, Any]:
    tree_root = case_root / "tree"
    output_parent = case_root / "output"
    ledger_dir = case_root / "ledger"
    for path in (tree_root, output_parent, ledger_dir):
        _owner_only_directory(path)

    worker_endpoint, launcher_endpoint = socket.socketpair()
    result_read_fd, result_write_fd = os.pipe()
    nonce = secrets.token_hex(32)
    process: subprocess.Popen[bytes] | None = None
    observer: _MeasuredLauncherObserver | None = None
    observer_started_ns = 0
    observer_elapsed_ns = 0
    worker_result: dict[str, Any] = {"ok": False, "error_code": "worker_result_missing"}
    timed_out = False
    observer_join_error: str | None = None
    try:
        process = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-B",
                os.fspath(Path(__file__).resolve()),
                "--worker",
                mode,
                str(worker_endpoint.fileno()),
                str(result_write_fd),
                repr(duration_seconds),
                nonce,
                os.fspath(tree_root),
                os.fspath(output_parent),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            pass_fds=(worker_endpoint.fileno(), result_write_fd),
            start_new_session=True,
        )
        worker_endpoint.close()
        os.close(result_write_fd)
        result_write_fd = -1
        observer = _MeasuredLauncherObserver(
            launcher_endpoint,
            worker_pid=process.pid,
            nonce=nonce,
            options=enron_capacity.EnronCapacityOptions(
                output_dir=output_parent / "report.json",
                attempt_ledger_dir=ledger_dir,
            ),
        )
        observer_started_ns = time.monotonic_ns()
        observer.start()
        try:
            process.wait(timeout=duration_seconds + 30.0)
        except subprocess.TimeoutExpired:
            timed_out = True
            _terminate_process_group(process)
        try:
            observer.join()
        except BaseException as exc:
            observer_join_error = _safe_error_code(exc)
        observer_elapsed_ns = time.monotonic_ns() - observer_started_ns
        payload = _read_bounded(result_read_fd)
        if payload:
            decoded = json.loads(payload)
            if isinstance(decoded, dict):
                worker_result = decoded
    finally:
        if process is not None:
            _terminate_process_group(process)
        if observer is not None:
            observer.close()
        else:
            launcher_endpoint.close()
        worker_endpoint.close()
        if result_write_fd >= 0:
            os.close(result_write_fd)
        os.close(result_read_fd)

    group_gone = process is not None and _process_group_gone(process.pid)

    metrics = (
        {
            "valid_sample_count": 0,
            "invalid_sample_count": 0,
            "percentile_method": "nearest_rank",
            "acquisition_duration_ns": _percentiles(()),
            "completion_to_completion_gap_ns": _percentiles(()),
            "scheduler_lateness_ns": _percentiles(()),
            "observer_thread_cpu_ns": 0,
            "observer_thread_cpu_fraction": 0.0,
        }
        if observer is None
        else observer.aggregate_metrics(observer_elapsed_ns)
    )
    return {
        "worker_result": worker_result,
        "worker_return_code": None if process is None else process.returncode,
        "worker_process_group_gone": group_gone,
        "timed_out": timed_out,
        "observer_failure_code": None if observer is None else observer.failure_code,
        "observer_join_error": observer_join_error,
        "observer_wall_elapsed_ns": observer_elapsed_ns,
        "observer_metrics": metrics,
    }


def _open_descriptor_set() -> set[int] | None:
    for directory in ("/proc/self/fd", "/dev/fd"):
        try:
            names = os.listdir(directory)
        except OSError:
            continue
        descriptors: set[int] = set()
        for name in names:
            if not name.isdigit():
                continue
            descriptor = int(name)
            try:
                os.fstat(descriptor)
            except OSError:
                continue
            descriptors.add(descriptor)
        return descriptors
    return None


def _policy_is_exact() -> bool:
    return (
        enron_capacity.PRODUCTION_MONITOR_INTERVAL_NS == _EXPECTED_INTERVAL_NS
        and enron_capacity.MAX_RESOURCE_OBSERVATION_WALL_GAP_NS == _EXPECTED_LIMIT_NS
        and enron_capacity.MAX_RESOURCE_ACQUISITION_DURATION_NS == _EXPECTED_LIMIT_NS
    )


def _positive_case_passed(case: Mapping[str, Any]) -> bool:
    worker = case["worker_result"]
    metrics = case["observer_metrics"]
    acquisition = metrics["acquisition_duration_ns"]
    gaps = metrics["completion_to_completion_gap_ns"]
    workloads = worker.get("workloads", {}) if isinstance(worker, dict) else {}
    return bool(
        isinstance(worker, dict)
        and worker.get("ok") is True
        and case["worker_return_code"] == 0
        and case["worker_process_group_gone"] is True
        and case["timed_out"] is False
        and case["observer_failure_code"] is None
        and case["observer_join_error"] is None
        and metrics["valid_sample_count"] >= 3
        and metrics["invalid_sample_count"] == 0
        and acquisition["max"] is not None
        and acquisition["max"] <= _EXPECTED_LIMIT_NS
        and gaps["max"] is not None
        and gaps["max"] <= _EXPECTED_LIMIT_NS
        and workloads.get("owner_only_tree_mutations", 0) > 0
        and workloads.get("owner_only_tree_seeded_regular_entries", 0) >= _MIN_LARGE_TREE_REGULAR_ENTRIES
        and workloads.get("owner_only_tree_retained_seed_regular_entries", 0)
        == workloads.get("owner_only_tree_seeded_regular_entries", -1)
        and workloads.get("owner_only_tree_terminal_regular_entries", 0)
        >= workloads.get("owner_only_tree_seeded_regular_entries", _MIN_LARGE_TREE_REGULAR_ENTRIES)
        and workloads.get("sqlite_transactions", 0) > 0
        and workloads.get("native_rust_scans", 0) > 0
        and workloads.get("c_held_gil_intervals", 0) > 0
        and workloads.get("descendant_churn_cycles", 0) > 0
    )


def _stall_case_passed(case: Mapping[str, Any], injected_calls: int, observed_stall_ns: int) -> bool:
    worker = case["worker_result"]
    return bool(
        injected_calls == 1
        and observed_stall_ns >= _INJECTED_STALL_NS
        and isinstance(worker, dict)
        and worker.get("ok") is False
        and worker.get("error_code") == "resource_acquisition_timeout"
        and case["worker_return_code"] != 0
        and case["worker_process_group_gone"] is True
        and case["timed_out"] is False
        and case["observer_failure_code"] == "resource_acquisition_timeout"
        and case["observer_join_error"] is None
    )


def _public_report(duration_seconds: float) -> tuple[dict[str, Any], str]:
    if os.name != "posix" or not (sys.platform.startswith("linux") or sys.platform == "darwin"):
        raise RuntimeError("same-host observer soak is unsupported on this platform")
    if not _policy_is_exact():
        raise RuntimeError("resource observer policy constants changed")

    descriptors_before = _open_descriptor_set()
    scratch_path = ""
    positive: dict[str, Any]
    stall: dict[str, Any]
    stall_calls = 0
    stall_elapsed_ns = 0
    with tempfile.TemporaryDirectory(prefix="nerb-resource-observer-soak-") as scratch_raw:
        scratch_path = scratch_raw
        scratch_root = Path(scratch_raw)
        scratch_root.chmod(0o700)
        positive_root = scratch_root / "positive"
        stall_root = scratch_root / "stall"
        _owner_only_directory(positive_root)
        _owner_only_directory(stall_root)
        positive = _run_case(mode="positive", duration_seconds=duration_seconds, case_root=positive_root)
        positive_launcher_peak = enron_capacity._root_process_peak_rss_bytes()

        original_acquire = enron_capacity._acquire_runtime_process_tree_rss
        stall_lock = threading.Lock()

        def stalled_acquire(probe: enron_capacity.CapacityResourceProbe) -> tuple[int, int]:
            nonlocal stall_calls, stall_elapsed_ns
            with stall_lock:
                inject = stall_calls == 0
                if inject:
                    stall_calls += 1
            if inject:
                started_ns = time.monotonic_ns()
                time.sleep(_INJECTED_STALL_NS / 1_000_000_000)
                stall_elapsed_ns = time.monotonic_ns() - started_ns
            return original_acquire(probe)

        setattr(enron_capacity, "_acquire_runtime_process_tree_rss", stalled_acquire)
        try:
            stall = _run_case(mode="stall", duration_seconds=0.1, case_root=stall_root)
        finally:
            setattr(enron_capacity, "_acquire_runtime_process_tree_rss", original_acquire)

    scratch_removed = bool(scratch_path) and not Path(scratch_path).exists()
    gc.collect()
    descriptors_after = _open_descriptor_set()
    descriptor_check_available = descriptors_before is not None and descriptors_after is not None
    descriptors_clean = descriptor_check_available and descriptors_before == descriptors_after

    positive_passed = _positive_case_passed(positive)
    stall_passed = _stall_case_passed(stall, stall_calls, stall_elapsed_ns)
    worker = positive["worker_result"]
    snapshot = worker.get("resource_snapshot", {}) if isinstance(worker, dict) else {}
    workloads = worker.get("workloads", {}) if isinstance(worker, dict) else {}
    workload_elapsed_ns = int(worker.get("workload_elapsed_ns", 0)) if isinstance(worker, dict) else 0
    iterations = int(worker.get("workload_iterations", 0)) if isinstance(worker, dict) else 0
    limitations = [
        "The workload is synthetic and does not establish production-data representativeness.",
        "Sampling cannot prove capture of every sub-interval RSS or filesystem transient.",
        "Observer CPU uses exact observer-thread CPU time; memory is a launcher-process high-water bound.",
    ]
    if not workloads.get("pyarrow_available", False):
        limitations.append("PyArrow was unavailable, so columnar workload coverage is absent.")
    if duration_seconds < _DEFAULT_DURATION_SECONDS:
        limitations.append("This shortened run is a smoke check, not the required thirty-minute same-host soak.")

    overall_ok = bool(positive_passed and stall_passed and scratch_removed and descriptors_clean)
    completed_required_duration = duration_seconds >= _DEFAULT_DURATION_SECONDS and workload_elapsed_ns >= int(
        _DEFAULT_DURATION_SECONDS * 1_000_000_000
    )
    report: dict[str, Any] = {
        "report_type": "nerb.resource_observer_soak",
        "ok": overall_ok,
        "decision_grade": overall_ok and completed_required_duration,
        "same_host": True,
        "requested_duration_seconds": duration_seconds,
        "completed_required_duration": completed_required_duration,
        "policy": {
            "production_monitor_interval_ns": enron_capacity.PRODUCTION_MONITOR_INTERVAL_NS,
            "maximum_resource_observation_wall_gap_ns": enron_capacity.MAX_RESOURCE_OBSERVATION_WALL_GAP_NS,
            "maximum_resource_acquisition_duration_ns": enron_capacity.MAX_RESOURCE_ACQUISITION_DURATION_NS,
            "exact_expected_constants_verified": _policy_is_exact(),
        },
        "positive_soak": {
            "passed": positive_passed,
            "workload_elapsed_ns": workload_elapsed_ns,
            "workload_iterations": iterations,
            "workload_iterations_per_second": round(iterations * 1_000_000_000 / max(1, workload_elapsed_ns), 3),
            "workloads": workloads,
            "observer": positive["observer_metrics"],
            "resource_snapshot": snapshot,
            "launcher_process_peak_rss_bytes": positive_launcher_peak,
        },
        "fail_closed_injection": {
            "passed": stall_passed,
            "injected_stall_ns": _INJECTED_STALL_NS,
            "observed_stall_ns": stall_elapsed_ns,
            "injection_count": stall_calls,
            "expected_failure_code": "resource_acquisition_timeout",
            "observed_failure_code": stall["observer_failure_code"],
            "observer": stall["observer_metrics"],
        },
        "cleanup": {
            "worker_process_groups_gone": bool(
                positive["worker_process_group_gone"] and stall["worker_process_group_gone"]
            ),
            "descriptor_check_available": descriptor_check_available,
            "open_descriptor_count_before": 0 if descriptors_before is None else len(descriptors_before),
            "open_descriptor_count_after": 0 if descriptors_after is None else len(descriptors_after),
            "descriptor_leak_free": descriptors_clean,
            "scratch_removed": scratch_removed,
        },
        "limitations": limitations,
    }
    serialized = json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    if scratch_path in serialized:
        raise RuntimeError("aggregate report contained an internal path")
    return report, serialized


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the same-host synthetic resource-observer soak.")
    parser.add_argument(
        "--duration-seconds",
        type=float,
        default=_DEFAULT_DURATION_SECONDS,
        help="positive soak duration; default: 1800 seconds",
    )
    return parser


def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1] == "--worker":
        _worker_main(sys.argv[2:])
    arguments = _parser().parse_args()
    duration_seconds = arguments.duration_seconds
    if not math.isfinite(duration_seconds) or duration_seconds <= 0:
        _parser().error("--duration-seconds must be finite and greater than zero")

    previous_umask = os.umask(0o077)
    try:
        report, serialized = _public_report(duration_seconds)
    except BaseException as exc:
        report = {
            "report_type": "nerb.resource_observer_soak",
            "ok": False,
            "decision_grade": False,
            "error_code": _safe_error_code(exc),
            "policy_constants_verified": _policy_is_exact(),
        }
        serialized = json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    finally:
        os.umask(previous_umask)
    print(serialized)
    return 0 if report.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())

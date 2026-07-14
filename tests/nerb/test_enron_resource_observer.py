from __future__ import annotations

import errno
import hashlib
import importlib
import importlib.util
import json
import os
import runpy
import select
import signal
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Generator
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from nerb import enron_capacity
from nerb.enron_capacity import CapacityDiskUsage, EnronCapacityError, EnronCapacityOptions

_GIB = 1024**3
_MIB = 1024**2
_NONCE = "a" * 64

_GIL_HOLD_WORKER = r"""
import ctypes
import json
import os
import socket
import sys
import time
from pathlib import Path

from nerb import enron_capacity


class _SyntheticPrivateTree:
    def logical_bytes(self):
        return 0


def _build_preflight(output_parent, ledger_dir):
    probe = enron_capacity._SystemResourceProbe()
    physical = probe.physical_memory_bytes()
    rss = probe.process_tree_rss_bytes(os.getpid())
    if not isinstance(physical, int) or physical <= 0 or not isinstance(rss, int) or rss <= 0:
        raise RuntimeError("unavailable resource probe")
    effective = min(
        enron_capacity.MAX_ABSOLUTE_RSS_BYTES,
        physical
        * enron_capacity.PHYSICAL_MEMORY_FRACTION_NUMERATOR
        // enron_capacity.PHYSICAL_MEMORY_FRACTION_DENOMINATOR,
    )
    maximum_peak = (
        effective
        * enron_capacity.PEAK_RSS_FRACTION_NUMERATOR
        // enron_capacity.PEAK_RSS_FRACTION_DENOMINATOR
    )
    observations = []
    for path, includes_output in ((output_parent, True), (ledger_dir, False)):
        device = probe.filesystem_device(path)
        usage = probe.disk_usage(path)
        if not isinstance(device, int) or usage is None:
            raise RuntimeError("unavailable filesystem probe")
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


endpoint = socket.socket(fileno=int(sys.argv[1]))
status_fd = int(sys.argv[2])
output_parent = Path(sys.argv[3])
ledger_dir = Path(sys.argv[4])
nonce = sys.argv[5]
monitor = enron_capacity._ContinuousResourceMonitor(
    tree=_SyntheticPrivateTree(),
    probe=enron_capacity._SystemResourceProbe(),
    preflight=_build_preflight(output_parent, ledger_dir),
    run_started_ns=time.monotonic_ns(),
    interval_ns=enron_capacity.PRODUCTION_MONITOR_INTERVAL_NS,
    wall_clock=time.monotonic_ns,
    resource_observer_socket=endpoint,
    resource_observer_nonce=nonce,
)
try:
    sys.setswitchinterval(10.0)
    monitor.start()
    os.write(status_fd, b"R")
    usleep = ctypes.PyDLL(None).usleep
    usleep.argtypes = (ctypes.c_uint,)
    usleep.restype = ctypes.c_int
    hold_started_ns = time.monotonic_ns()
    if usleep(850_000) != 0:
        raise RuntimeError("usleep failed")
    hold_finished_ns = time.monotonic_ns()
    phase_started_ns = time.monotonic_ns()
    monitor.begin_phase("preparation", phase_started_ns)
    progress_hold_started_ns = time.monotonic_ns()
    if usleep(850_000) != 0:
        raise RuntimeError("usleep failed")
    progress_hold_finished_ns = time.monotonic_ns()
    monitor.activity("preparation")
    monitor.checkpoint("preparation", 1)
    phase_snapshot = monitor.finish_phase("preparation", 1)
    monitor.stop()
    monitor.raise_if_failed()
    os.write(status_fd, b"D")
    result = {
        "hold_started_ns": hold_started_ns,
        "hold_finished_ns": hold_finished_ns,
        "progress_hold_started_ns": progress_hold_started_ns,
        "progress_hold_finished_ns": progress_hold_finished_ns,
        "phase_snapshot": phase_snapshot,
        "snapshot": monitor.global_snapshot(),
    }
    os.write(status_fd, b"J" + json.dumps(result, sort_keys=True).encode("ascii") + b"\n")
except BaseException as exc:
    try:
        monitor.stop()
    except BaseException:
        pass
    os.write(status_fd, ("E" + type(exc).__name__ + "\n").encode("ascii", errors="replace"))
    raise
finally:
    endpoint.close()
    os.close(status_fd)
"""


class _StaticTree:
    def logical_bytes(self) -> int:
        return 0


class _UnusedProbe:
    """The remote-acceptance seam must not reacquire resources in the worker."""


def _preflight(path: Path, *, baseline_rss: int = 64 * _MIB) -> enron_capacity._Preflight:
    return enron_capacity._Preflight(
        physical_memory_bytes=16 * _GIB,
        effective_rss_cap_bytes=8 * _GIB,
        maximum_peak_rss_bytes=6 * _GIB,
        preflight_process_tree_rss_bytes=baseline_rss,
        preflight_free_disk_bytes=30 * _GIB,
        output_preflight_free_disk_bytes=30 * _GIB,
        preexisting_private_tombstone_count=0,
        filesystems=(
            enron_capacity._FilesystemPreflight(
                device=path.stat().st_dev,
                probe_path=path,
                preflight_free_disk_bytes=30 * _GIB,
                includes_output=True,
            ),
        ),
    )


@dataclass
class _RemoteHarness:
    monitor: enron_capacity._ContinuousResourceMonitor
    remote: enron_capacity._RemoteResourceObserver
    worker_endpoint: socket.socket
    launcher_endpoint: socket.socket

    def close(self) -> None:
        self.worker_endpoint.close()
        self.launcher_endpoint.close()


@pytest.fixture
def remote_harness(tmp_path: Path) -> Generator[_RemoteHarness, None, None]:
    worker_endpoint, launcher_endpoint = socket.socketpair()
    monitor = enron_capacity._ContinuousResourceMonitor(
        tree=cast(Any, _StaticTree()),
        probe=cast(Any, _UnusedProbe()),
        preflight=_preflight(tmp_path),
        run_started_ns=1,
        interval_ns=enron_capacity.PRODUCTION_MONITOR_INTERVAL_NS,
        wall_clock=lambda: 1,
    )
    harness = _RemoteHarness(
        monitor=monitor,
        remote=enron_capacity._RemoteResourceObserver(monitor, worker_endpoint, _NONCE),
        worker_endpoint=worker_endpoint,
        launcher_endpoint=launcher_endpoint,
    )
    try:
        yield harness
    finally:
        harness.close()


def _sample(
    *,
    sequence: int,
    completed_ns: int,
    gap_ns: int,
    acquisition_ns: int = 0,
    kind: str = "continuous",
    valid: bool = True,
    failure_code: str | None = None,
    nonce: str = _NONCE,
    process_tree_rss_bytes: int | None = 64 * _MIB,
    minimum_free_disk_bytes: int | None = 30 * _GIB,
    output_free_disk_bytes: int | None = 30 * _GIB,
) -> dict[str, Any]:
    return {
        "type": "sample",
        "protocol": enron_capacity._RESOURCE_OBSERVER_PROTOCOL,
        "nonce": nonce,
        "event_sequence": sequence,
        "request_id": 0,
        "sample_kind": kind,
        "valid": valid,
        "started_wall_ns": completed_ns - acquisition_ns,
        "completed_wall_ns": completed_ns,
        "resource_observation_wall_gap_ns": gap_ns,
        "acquisition_duration_ns": acquisition_ns,
        "rss_duration_ns": acquisition_ns,
        "filesystem_duration_ns": 0,
        "scheduler_lateness_ns": 0,
        "process_tree_rss_bytes": process_tree_rss_bytes,
        "minimum_free_disk_bytes": minimum_free_disk_bytes,
        "output_free_disk_bytes": output_free_disk_bytes,
        "rss_retry_count": 0,
        "filesystem_retry_count": 0,
        "failure_code": failure_code,
    }


def _wait_until(predicate: Callable[[], bool], *, timeout: float = 1.0) -> bool:
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        time.sleep(0.001)
    return predicate()


def _send_fragmented_frame(
    endpoint: socket.socket,
    reader: enron_capacity._ResourceObserverFrames,
    frame: dict[str, Any],
) -> None:
    payload = enron_capacity._canonical_json_bytes(frame) + b"\n"
    boundary = max(1, len(payload) // 2)
    first = payload[:boundary]
    endpoint.sendall(first)
    assert _wait_until(lambda: bytes(reader.buffer) == first)
    endpoint.sendall(payload[boundary:])


def _accept_startup(harness: _RemoteHarness, *, completed_ns: int = 1_000_000_001) -> int:
    harness.remote._accept_sample(
        _sample(sequence=1, completed_ns=completed_ns, gap_ns=0, kind="startup"),
    )
    return completed_ns


def _start_remote_phase(
    harness: _RemoteHarness,
    *,
    started_ns: int,
) -> enron_capacity._PhaseMeasurements:
    state = enron_capacity._PhaseMeasurements(
        started_ns=started_ns,
        started_wall_ns=started_ns,
        last_progress_wall_ns=started_ns,
        last_activity_observation_wall_ns=started_ns,
    )
    harness.monitor._states["preparation"] = state
    harness.monitor._current_phase = "preparation"
    return state


def test_observer_frames_are_canonical_closed_and_bounded() -> None:
    sender, receiver = socket.socketpair()
    try:
        reader = enron_capacity._ResourceObserverFrames(receiver)
        enron_capacity._send_resource_observer_frame(sender, {"second": 2, "first": 1})
        assert reader.receive(1_000_000_000) == [{"first": 1, "second": 2}]

        with pytest.raises(EnronCapacityError) as oversized:
            enron_capacity._send_resource_observer_frame(
                sender,
                {"payload": "x" * enron_capacity.MAX_RESOURCE_OBSERVER_FRAME_BYTES},
            )
        assert oversized.value.code == "resource_measurement_failed"
    finally:
        sender.close()
        receiver.close()


def test_terminal_eof_helper_accepts_only_a_clean_half_close() -> None:
    sender, receiver = socket.socketpair()
    try:
        reader = enron_capacity._ResourceObserverFrames(receiver)
        sender.shutdown(socket.SHUT_WR)

        enron_capacity._require_resource_observer_eof(reader)
    finally:
        sender.close()
        receiver.close()


@pytest.mark.parametrize("trailing", [b"{", b'{"late":true}\n'])
def test_terminal_eof_helper_rejects_later_partial_or_complete_frames(trailing: bytes) -> None:
    sender, receiver = socket.socketpair()
    try:
        reader = enron_capacity._ResourceObserverFrames(receiver)
        sender.sendall(trailing)
        sender.shutdown(socket.SHUT_WR)

        with pytest.raises(EnronCapacityError) as raised:
            enron_capacity._require_resource_observer_eof(reader)
        assert raised.value.code == "resource_measurement_failed"
    finally:
        sender.close()
        receiver.close()


@pytest.mark.parametrize(
    "payload",
    [
        b'{"duplicate":1,"duplicate":2}\n',
        b"x" * enron_capacity.MAX_RESOURCE_OBSERVER_FRAME_BYTES,
        b"\n",
    ],
)
def test_observer_frame_reader_fails_closed_on_noncanonical_or_unbounded_input(payload: bytes) -> None:
    sender, receiver = socket.socketpair()
    try:
        sender.sendall(payload)
        with pytest.raises(EnronCapacityError) as raised:
            enron_capacity._ResourceObserverFrames(receiver).receive(1_000_000_000)
        assert raised.value.code == "resource_measurement_failed"
    finally:
        sender.close()
        receiver.close()


def test_observer_frame_reader_rejects_eof_with_an_unterminated_frame() -> None:
    sender, receiver = socket.socketpair()
    reader = enron_capacity._ResourceObserverFrames(receiver)
    try:
        sender.sendall(b'{"incomplete":true}')
        sender.close()
        with pytest.raises(EnronCapacityError) as raised:
            reader.receive(1_000_000_000)
        assert raised.value.code == "resource_measurement_failed"
    finally:
        sender.close()
        receiver.close()


def test_observer_frame_reader_uses_one_absolute_deadline_across_fragments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FragmentEndpoint:
        def recv(self, _maximum_bytes: int) -> bytes:
            return b"{"

    endpoint = FragmentEndpoint()
    waits: list[float] = []
    clock = iter((100, 200, 300))

    def select_once_then_timeout(
        readable: list[object],
        _writable: list[object],
        _exceptional: list[object],
        timeout: float,
    ) -> tuple[list[object], list[object], list[object]]:
        waits.append(timeout)
        return (readable, [], []) if len(waits) == 1 else ([], [], [])

    monkeypatch.setattr(enron_capacity.time, "monotonic_ns", lambda: next(clock))
    monkeypatch.setattr(enron_capacity.select, "select", select_once_then_timeout)
    reader = enron_capacity._ResourceObserverFrames(cast(Any, endpoint))

    with pytest.raises(EnronCapacityError) as raised:
        reader.receive(1_000)
    assert raised.value.code == "resource_measurement_failed"
    assert reader.buffer == b"{"
    assert reader._partial_frame_deadline_ns == 1_100
    assert waits == [900 / 1_000_000_000, 800 / 1_000_000_000]


def test_observer_frame_reader_does_not_renew_a_partial_deadline_after_returning_a_frame(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class CompleteThenPartialEndpoint:
        def recv(self, _maximum_bytes: int) -> bytes:
            return b'{"complete":true}\n{'

    endpoint = CompleteThenPartialEndpoint()
    select_calls = 0
    clock = iter((100, 200, 300, 1_100))

    def select_ready(
        readable: list[object],
        _writable: list[object],
        _exceptional: list[object],
        _timeout: float,
    ) -> tuple[list[object], list[object], list[object]]:
        nonlocal select_calls
        select_calls += 1
        return readable, [], []

    monkeypatch.setattr(enron_capacity.time, "monotonic_ns", lambda: next(clock))
    monkeypatch.setattr(enron_capacity.select, "select", select_ready)
    reader = enron_capacity._ResourceObserverFrames(cast(Any, endpoint))

    assert reader.receive(1_000) == [{"complete": True}]
    assert reader.buffer == b"{"
    assert reader._partial_frame_deadline_ns == 1_100

    with pytest.raises(EnronCapacityError) as raised:
        reader.receive(10_000)
    assert raised.value.code == "resource_measurement_failed"
    assert select_calls == 1


@pytest.mark.parametrize(
    ("sample_kind", "request_id"),
    [("continuous", 0), ("boundary", 1)],
    ids=["continuous", "forced-boundary"],
)
def test_remote_observer_accepts_fragmented_startup_and_followup_samples(
    remote_harness: _RemoteHarness,
    sample_kind: str,
    request_id: int,
) -> None:
    receiver = threading.Thread(target=remote_harness.remote._loop)
    receiver.start()
    try:
        startup_completed = 1_000_000_001
        _send_fragmented_frame(
            remote_harness.launcher_endpoint,
            remote_harness.remote.reader,
            _sample(sequence=1, completed_ns=startup_completed, gap_ns=0, kind="startup"),
        )
        assert _wait_until(lambda: remote_harness.remote.event_sequence == 1)
        assert remote_harness.monitor._failure_code is None

        followup = _sample(
            sequence=2,
            completed_ns=startup_completed + 1,
            gap_ns=1,
            kind=sample_kind,
        )
        followup["request_id"] = request_id
        if request_id:
            with remote_harness.remote.condition:
                remote_harness.remote.expected[request_id] = sample_kind
        _send_fragmented_frame(
            remote_harness.launcher_endpoint,
            remote_harness.remote.reader,
            followup,
        )
        assert _wait_until(
            lambda: (
                remote_harness.remote.event_sequence == 2
                and (not request_id or request_id in remote_harness.remote.completed)
            )
        )
        assert remote_harness.remote.completed == ({request_id} if request_id else set())
        assert remote_harness.monitor._failure_code is None
    finally:
        with remote_harness.remote.condition:
            remote_harness.remote.stopped = True
            remote_harness.remote.condition.notify_all()
        remote_harness.launcher_endpoint.shutdown(socket.SHUT_WR)
        receiver.join(1)
    assert not receiver.is_alive()


def test_remote_observer_accepts_a_fragmented_observer_failure(remote_harness: _RemoteHarness) -> None:
    receiver = threading.Thread(target=remote_harness.remote._loop)
    receiver.start()
    failure: dict[str, Any] = {
        "type": "observer_failure",
        "protocol": enron_capacity._RESOURCE_OBSERVER_PROTOCOL,
        "nonce": _NONCE,
        "failure_code": "runtime_disk_floor",
    }
    try:
        _send_fragmented_frame(
            remote_harness.launcher_endpoint,
            remote_harness.remote.reader,
            failure,
        )
        receiver.join(1)
    finally:
        if receiver.is_alive():
            with remote_harness.remote.condition:
                remote_harness.remote.stopped = True
                remote_harness.remote.condition.notify_all()
            remote_harness.launcher_endpoint.shutdown(socket.SHUT_WR)
            receiver.join(1)
    assert not receiver.is_alive()
    assert remote_harness.monitor._failure_code == "runtime_disk_floor"


def test_queued_pre_phase_sample_is_global_only(remote_harness: _RemoteHarness) -> None:
    startup_completed = _accept_startup(remote_harness)
    state = _start_remote_phase(remote_harness, started_ns=startup_completed + 100)

    remote_harness.remote._accept_sample(
        _sample(
            sequence=2,
            completed_ns=startup_completed + 50,
            gap_ns=50,
            process_tree_rss_bytes=128 * _MIB,
            minimum_free_disk_bytes=20 * _GIB,
        ),
    )

    assert remote_harness.remote.last_valid_completed_ns == startup_completed + 50
    assert remote_harness.monitor._global_observations == 2
    assert remote_harness.monitor._global_peak_rss == 128 * _MIB
    assert remote_harness.monitor._global_minimum_free == 20 * _GIB
    assert state.observations == 0
    assert state.peak_rss == 0
    assert state.minimum_free is None
    assert state.last_resource_wall_ns is None
    assert remote_harness.monitor._failure_code is None


def test_queued_in_phase_sample_older_than_progress_retains_resource_extrema(
    remote_harness: _RemoteHarness,
) -> None:
    startup_completed = _accept_startup(remote_harness)
    state = _start_remote_phase(remote_harness, started_ns=startup_completed)
    remote_harness.remote._accept_sample(
        _sample(
            sequence=2,
            completed_ns=startup_completed + 10,
            gap_ns=10,
            process_tree_rss_bytes=80 * _MIB,
            minimum_free_disk_bytes=25 * _GIB,
        ),
    )
    remote_harness.monitor._accept_progress(
        state,
        kind="activity",
        wall_now=startup_completed + 30,
        wall_gap=20,
    )

    remote_harness.remote._accept_sample(
        _sample(
            sequence=3,
            completed_ns=startup_completed + 20,
            gap_ns=10,
            process_tree_rss_bytes=128 * _MIB,
            minimum_free_disk_bytes=20 * _GIB,
        ),
    )

    assert remote_harness.monitor._global_observations == 3
    assert state.observations == 2
    assert state.last_resource_wall_ns == startup_completed + 20
    assert state.peak_rss == 128 * _MIB
    assert state.minimum_free == 20 * _GIB
    assert state.maximum_resource_wall_gap_ns == 10
    assert state.maximum_progress_wall_gap_ns == 20
    assert remote_harness.monitor._failure_code is None


def test_remote_resource_completion_clock_regression_fails_closed(remote_harness: _RemoteHarness) -> None:
    startup_completed = _accept_startup(remote_harness)

    with pytest.raises(EnronCapacityError) as raised:
        remote_harness.remote._accept_sample(
            _sample(
                sequence=2,
                completed_ns=startup_completed - 1,
                gap_ns=0,
            ),
        )

    assert raised.value.code == "clock_invalid"
    assert remote_harness.remote.event_sequence == 1
    assert remote_harness.remote.last_valid_completed_ns == startup_completed
    assert remote_harness.monitor._global_observations == 1


def test_invalid_frame_completion_orders_the_next_acquisition_start(remote_harness: _RemoteHarness) -> None:
    startup_completed = _accept_startup(remote_harness, completed_ns=100)
    remote_harness.remote._accept_sample(
        _sample(
            sequence=2,
            completed_ns=200,
            gap_ns=100,
            acquisition_ns=10,
            valid=False,
            failure_code="rss_acquisition_exhausted",
        ),
    )

    with pytest.raises(EnronCapacityError) as raised:
        remote_harness.remote._accept_sample(
            _sample(
                sequence=3,
                completed_ns=250,
                gap_ns=150,
                acquisition_ns=100,
            ),
        )

    assert raised.value.code == "clock_invalid"
    assert remote_harness.remote.event_sequence == 2
    assert remote_harness.remote.last_frame_completed_ns == 200
    assert remote_harness.remote.last_valid_completed_ns == startup_completed


def test_phase_resource_clock_regression_still_fails_closed(remote_harness: _RemoteHarness) -> None:
    startup_completed = _accept_startup(remote_harness)
    state = _start_remote_phase(remote_harness, started_ns=startup_completed)
    state.last_resource_wall_ns = startup_completed + 20

    remote_harness.monitor._accept_remote_resource_sample(
        kind="continuous",
        completed_records=None,
        wall_now=startup_completed + 10,
        now=startup_completed + 10,
        rss=64 * _MIB,
        minimum_free=30 * _GIB,
        output_free=30 * _GIB,
        rss_retries=0,
        filesystem_retries=0,
        wall_gap=10,
        acquisition_duration_ns=0,
        rss_duration_ns=0,
        filesystem_duration_ns=0,
        scheduler_lateness_ns=0,
        failure_code=None,
    )

    assert remote_harness.monitor._global_observations == 2
    assert state.observations == 0
    assert remote_harness.monitor._failure_code == "clock_invalid"


def test_worker_owned_disk_precedes_launcher_gap_without_losing_extrema(remote_harness: _RemoteHarness) -> None:
    startup_completed = _accept_startup(remote_harness)
    state = _start_remote_phase(remote_harness, started_ns=startup_completed)
    owned = enron_capacity.MAX_OWNED_DISK_BYTES + 1
    gap = enron_capacity.MAX_RESOURCE_OBSERVATION_WALL_GAP_NS + 1
    remote_harness.monitor._latest_exact_owned = owned

    remote_harness.remote._accept_sample(
        _sample(
            sequence=2,
            completed_ns=startup_completed + gap,
            gap_ns=gap,
            acquisition_ns=1,
            failure_code="resource_observation_gap",
        ),
    )

    assert remote_harness.monitor._failure_code == "owned_disk_limit"
    assert remote_harness.monitor.failure_diagnostic() is None
    assert remote_harness.monitor._global_observations == 2
    assert remote_harness.monitor._global_owned_high_water == owned
    assert remote_harness.monitor._global_maximum_resource_wall_gap_ns == gap
    assert state.observations == 1
    assert state.owned_high_water == owned
    assert state.maximum_resource_wall_gap_ns == gap
    assert state.last_sample is not None
    assert state.last_sample["owned_disk_bytes"] == owned
    assert state.last_sample["resource_observation_wall_gap_ns"] == gap


@pytest.mark.parametrize(
    ("launcher_code", "acquisition_ns", "rss", "minimum_free", "expected_code"),
    [
        ("resource_measurement_failed", 0, None, None, "owned_disk_limit"),
        ("rss_acquisition_exhausted", 0, None, None, "owned_disk_limit"),
        ("disk_acquisition_exhausted", 0, 64 * _MIB, None, "owned_disk_limit"),
        (
            "resource_acquisition_timeout",
            enron_capacity.MAX_RESOURCE_ACQUISITION_DURATION_NS + 1,
            64 * _MIB,
            30 * _GIB,
            "resource_acquisition_timeout",
        ),
        ("rss_limit", 0, 6 * _GIB + 1, 30 * _GIB, "rss_limit"),
        (
            "runtime_disk_floor",
            0,
            64 * _MIB,
            enron_capacity.MIN_RUNTIME_FREE_DISK_BYTES - 1,
            "runtime_disk_floor",
        ),
    ],
)
def test_transaction_boundary_atomically_arbitrates_exact_owned_with_invalid_launcher_sample(
    remote_harness: _RemoteHarness,
    launcher_code: str,
    acquisition_ns: int,
    rss: int | None,
    minimum_free: int | None,
    expected_code: str,
) -> None:
    monitor = remote_harness.monitor
    startup_completed = _accept_startup(remote_harness)
    owned = enron_capacity.MAX_OWNED_DISK_BYTES + 1

    class InvalidSampleRemote:
        def force(self, kind: str) -> None:
            assert kind == "boundary"
            remote_harness.remote._accept_sample(
                _sample(
                    sequence=2,
                    completed_ns=startup_completed + acquisition_ns,
                    gap_ns=acquisition_ns,
                    acquisition_ns=acquisition_ns,
                    valid=False,
                    failure_code=launcher_code,
                    process_tree_rss_bytes=rss,
                    minimum_free_disk_bytes=minimum_free,
                    output_free_disk_bytes=None,
                )
            )
            monitor.raise_if_failed()

    monitor._remote = cast(Any, InvalidSampleRemote())

    with pytest.raises(enron_capacity._CapacityAbort) as raised:
        monitor.observe_transaction_boundary(owned)

    assert raised.value.code == expected_code
    assert monitor._failure_code == expected_code
    assert monitor._latest_exact_owned == owned
    assert monitor._global_owned_high_water == owned


@pytest.mark.parametrize(
    ("failure_code", "acquisition_ns", "rss", "minimum_free"),
    [
        (
            "resource_acquisition_timeout",
            enron_capacity.MAX_RESOURCE_ACQUISITION_DURATION_NS + 1,
            64 * _MIB,
            30 * _GIB,
        ),
        ("rss_limit", 0, 6 * _GIB + 1, 30 * _GIB),
        ("runtime_disk_floor", 0, 64 * _MIB, enron_capacity.MIN_RUNTIME_FREE_DISK_BYTES - 1),
    ],
)
@pytest.mark.parametrize("receiver_first", [False, True], ids=["worker-first", "receiver-first"])
def test_transaction_boundary_arbitrates_owned_with_higher_priority_launcher_failure(
    remote_harness: _RemoteHarness,
    failure_code: str,
    acquisition_ns: int,
    rss: int,
    minimum_free: int,
    receiver_first: bool,
) -> None:
    monitor = remote_harness.monitor
    state = _start_remote_phase(remote_harness, started_ns=1)
    owned = enron_capacity.MAX_OWNED_DISK_BYTES + 1
    force_calls: list[str] = []

    def deliver_launcher_sample() -> None:
        monitor._accept_remote_resource_sample(
            kind="continuous",
            completed_records=None,
            wall_now=2,
            now=2,
            rss=rss,
            minimum_free=minimum_free,
            output_free=30 * _GIB,
            rss_retries=0,
            filesystem_retries=0,
            wall_gap=0,
            acquisition_duration_ns=acquisition_ns,
            rss_duration_ns=acquisition_ns,
            filesystem_duration_ns=0,
            scheduler_lateness_ns=0,
            failure_code=failure_code,
        )

    class CollidingFailureRemote:
        def force(self, kind: str) -> None:
            force_calls.append(kind)
            if not receiver_first:
                deliver_launcher_sample()
            monitor.raise_if_failed()

    if receiver_first:
        deliver_launcher_sample()
    monitor._remote = cast(Any, CollidingFailureRemote())

    with pytest.raises(enron_capacity._CapacityAbort) as raised:
        monitor.observe_transaction_boundary(owned)

    assert raised.value.code == failure_code
    assert force_calls == ["boundary"]
    assert monitor._failure_code == failure_code
    assert monitor.failure_diagnostic() is None
    assert monitor._latest_exact_owned == owned
    assert monitor._global_owned_high_water == owned
    assert state.last_owned == owned
    assert state.owned_high_water == owned
    assert state.observations == 1


@pytest.mark.parametrize(
    ("failure_code", "rss", "minimum_free"),
    [
        ("rss_limit", 6 * _GIB + 1, 30 * _GIB),
        ("runtime_disk_floor", 64 * _MIB, enron_capacity.MIN_RUNTIME_FREE_DISK_BYTES - 1),
    ],
)
@pytest.mark.parametrize("callback_kind", ["checkpoint", "heartbeat", "activity"])
@pytest.mark.parametrize("receiver_first", [False, True])
def test_progress_failure_barrier_preserves_queued_resource_failure_precedence(
    remote_harness: _RemoteHarness,
    failure_code: str,
    rss: int,
    minimum_free: int,
    callback_kind: str,
    receiver_first: bool,
) -> None:
    monitor = remote_harness.monitor
    state = _start_remote_phase(remote_harness, started_ns=1)
    monitor.wall_clock = lambda: enron_capacity.MAX_PROGRESS_CHECKPOINT_WALL_GAP_NS + 2
    force_calls: list[str] = []

    def deliver_queued_sample() -> None:
        monitor._accept_remote_resource_sample(
            kind="continuous",
            completed_records=None,
            wall_now=2,
            now=2,
            rss=rss,
            minimum_free=minimum_free,
            output_free=30 * _GIB,
            rss_retries=0,
            filesystem_retries=0,
            wall_gap=0,
            acquisition_duration_ns=0,
            rss_duration_ns=0,
            filesystem_duration_ns=0,
            scheduler_lateness_ns=0,
            failure_code=failure_code,
        )

    class QueuedFailureRemote:
        def force(self, kind: str) -> None:
            force_calls.append(kind)
            deliver_queued_sample()
            monitor.raise_if_failed()

    monitor._remote = cast(Any, QueuedFailureRemote())
    if receiver_first:
        deliver_queued_sample()

    with pytest.raises(enron_capacity._CapacityAbort) as raised:
        if callback_kind == "checkpoint":
            monitor.checkpoint("preparation", 1)
        elif callback_kind == "heartbeat":
            monitor.heartbeat("preparation")
        else:
            monitor.activity("preparation")

    assert raised.value.code == failure_code
    assert force_calls == ([] if receiver_first else [callback_kind])
    assert monitor._failure_code == failure_code
    assert monitor.failure_diagnostic() is None
    assert state.progress_signal_count == 0
    assert state.checkpoint_count == 0
    assert state.observations == 1


def test_checkpoint_progress_failure_barrier_publishes_exact_owned_high_water(
    remote_harness: _RemoteHarness,
) -> None:
    monitor = remote_harness.monitor
    state = _start_remote_phase(remote_harness, started_ns=1)
    owned = enron_capacity.MAX_OWNED_DISK_BYTES + 1
    monitor.tree = cast(Any, type("ExactOwnedTree", (), {"logical_bytes": lambda _self: owned})())
    monitor.wall_clock = lambda: enron_capacity.MAX_PROGRESS_CHECKPOINT_WALL_GAP_NS + 2
    force_calls: list[str] = []

    class OwnedFailureRemote:
        def force(self, kind: str) -> None:
            force_calls.append(kind)
            monitor._accept_remote_resource_sample(
                kind=kind,
                completed_records=None,
                wall_now=2,
                now=2,
                rss=64 * _MIB,
                minimum_free=30 * _GIB,
                output_free=30 * _GIB,
                rss_retries=0,
                filesystem_retries=0,
                wall_gap=0,
                acquisition_duration_ns=0,
                rss_duration_ns=0,
                filesystem_duration_ns=0,
                scheduler_lateness_ns=0,
                failure_code=None,
            )
            monitor.raise_if_failed()

    monitor._remote = cast(Any, OwnedFailureRemote())

    with pytest.raises(enron_capacity._CapacityAbort) as raised:
        monitor.checkpoint("preparation", 1)

    assert raised.value.code == "owned_disk_limit"
    assert force_calls == ["checkpoint"]
    assert monitor._latest_exact_owned == owned
    assert monitor._global_owned_high_water == owned
    assert state.owned_high_water == owned
    assert state.observations == 1
    assert state.last_sample is not None
    assert state.last_sample["owned_disk_bytes"] == owned
    assert state.progress_signal_count == 0
    assert state.checkpoint_count == 0


@pytest.mark.parametrize("mutation", ["duplicate_sequence", "duplicate_startup", "wrong_nonce", "extra_field"])
def test_remote_observer_rejects_duplicate_startup_sequence_nonce_and_open_frames(
    remote_harness: _RemoteHarness,
    mutation: str,
) -> None:
    completed_ns = _accept_startup(remote_harness)
    candidate = _sample(
        sequence=2,
        completed_ns=completed_ns + 1,
        gap_ns=1,
    )
    if mutation == "duplicate_sequence":
        candidate["event_sequence"] = 1
    elif mutation == "duplicate_startup":
        candidate["sample_kind"] = "startup"
    elif mutation == "wrong_nonce":
        candidate["nonce"] = "b" * 64
    else:
        candidate["private_path"] = "/synthetic/must-not-be-accepted"

    with pytest.raises(EnronCapacityError) as raised:
        remote_harness.remote._accept_sample(candidate)
    assert raised.value.code == "resource_measurement_failed"
    assert remote_harness.remote.event_sequence == 1
    assert remote_harness.remote.last_valid_completed_ns == completed_ns


def test_remote_observer_rejects_a_replayed_completed_forced_request(
    remote_harness: _RemoteHarness,
) -> None:
    first_completed = _accept_startup(remote_harness)
    first = _sample(
        sequence=2,
        completed_ns=first_completed + 1,
        gap_ns=1,
        kind="boundary",
    )
    first["request_id"] = 1
    replay = _sample(
        sequence=3,
        completed_ns=first_completed + 2,
        gap_ns=1,
        kind="boundary",
    )
    replay["request_id"] = 1
    remote_harness.remote.expected[1] = "boundary"
    remote_harness.launcher_endpoint.sendall(
        enron_capacity._canonical_json_bytes(first) + b"\n" + enron_capacity._canonical_json_bytes(replay) + b"\n"
    )

    remote_harness.remote._loop()

    assert remote_harness.monitor._failure_code == "resource_measurement_failed"
    assert remote_harness.remote.completed == {1}
    assert remote_harness.remote.event_sequence == 2
    assert remote_harness.monitor._global_observations == 2


@pytest.mark.parametrize(
    ("acquisition_ns", "failure_code"),
    [
        (499_000_000, None),
        (enron_capacity.MAX_RESOURCE_ACQUISITION_DURATION_NS, None),
        (enron_capacity.MAX_RESOURCE_ACQUISITION_DURATION_NS + 1, "resource_acquisition_timeout"),
        (501_000_000, "resource_acquisition_timeout"),
    ],
)
def test_remote_acceptance_enforces_the_exact_acquisition_deadline_in_shared_state(
    remote_harness: _RemoteHarness,
    acquisition_ns: int,
    failure_code: str | None,
) -> None:
    first_completed = _accept_startup(remote_harness)
    second_completed = first_completed + acquisition_ns
    valid = acquisition_ns <= enron_capacity.MAX_RESOURCE_ACQUISITION_DURATION_NS
    remote_harness.remote._accept_sample(
        _sample(
            sequence=2,
            completed_ns=second_completed,
            gap_ns=acquisition_ns,
            acquisition_ns=acquisition_ns,
            valid=valid,
            failure_code=failure_code,
        ),
    )

    assert remote_harness.remote.last_valid_completed_ns == (second_completed if valid else first_completed)
    assert remote_harness.monitor._global_observations == (2 if valid else 1)
    assert remote_harness.monitor._global_maximum_resource_acquisition_duration_ns == acquisition_ns
    assert remote_harness.monitor._failure_code == failure_code


@pytest.mark.parametrize(
    ("gap_ns", "failure_code"),
    [
        (499_000_000, None),
        (enron_capacity.MAX_RESOURCE_OBSERVATION_WALL_GAP_NS, None),
        (enron_capacity.MAX_RESOURCE_OBSERVATION_WALL_GAP_NS + 1, "resource_observation_gap"),
    ],
)
def test_remote_acceptance_enforces_the_exact_completion_gap_independently_of_acquisition(
    remote_harness: _RemoteHarness,
    gap_ns: int,
    failure_code: str | None,
) -> None:
    first_completed = _accept_startup(remote_harness)
    remote_harness.remote._accept_sample(
        _sample(
            sequence=2,
            completed_ns=first_completed + gap_ns,
            gap_ns=gap_ns,
            acquisition_ns=1,
            failure_code=failure_code,
        ),
    )

    assert remote_harness.remote.last_valid_completed_ns == first_completed + gap_ns
    assert remote_harness.monitor._global_observations == 2
    assert remote_harness.monitor._global_maximum_resource_wall_gap_ns == gap_ns
    assert remote_harness.monitor._failure_code == failure_code


@pytest.mark.parametrize(
    ("acquisition_ns", "rss", "minimum_free", "valid", "expected"),
    [
        (
            enron_capacity.MAX_RESOURCE_ACQUISITION_DURATION_NS + 1,
            6 * _GIB + 1,
            enron_capacity.MIN_RUNTIME_FREE_DISK_BYTES - 1,
            False,
            "resource_acquisition_timeout",
        ),
        (1, 6 * _GIB + 1, enron_capacity.MIN_RUNTIME_FREE_DISK_BYTES - 1, True, "rss_limit"),
        (1, 64 * _MIB, enron_capacity.MIN_RUNTIME_FREE_DISK_BYTES - 1, True, "runtime_disk_floor"),
    ],
)
def test_remote_resource_failure_precedence_is_explicit(
    remote_harness: _RemoteHarness,
    acquisition_ns: int,
    rss: int,
    minimum_free: int,
    valid: bool,
    expected: str,
) -> None:
    first_completed = _accept_startup(remote_harness)
    remote_harness.remote._accept_sample(
        _sample(
            sequence=2,
            completed_ns=first_completed + acquisition_ns,
            gap_ns=acquisition_ns,
            acquisition_ns=acquisition_ns,
            valid=valid,
            failure_code=expected,
            process_tree_rss_bytes=rss,
            minimum_free_disk_bytes=minimum_free,
        ),
    )

    assert remote_harness.monitor._failure_code == expected


def test_remote_rejects_non_timeout_code_for_an_over_deadline_invalid_sample(
    remote_harness: _RemoteHarness,
) -> None:
    first_completed = _accept_startup(remote_harness)
    acquisition_ns = enron_capacity.MAX_RESOURCE_ACQUISITION_DURATION_NS + 1

    with pytest.raises(EnronCapacityError) as raised:
        remote_harness.remote._accept_sample(
            _sample(
                sequence=2,
                completed_ns=first_completed + acquisition_ns,
                gap_ns=acquisition_ns,
                acquisition_ns=acquisition_ns,
                valid=False,
                failure_code="rss_limit",
                process_tree_rss_bytes=6 * _GIB + 1,
            ),
        )

    assert raised.value.code == "resource_measurement_failed"


@pytest.mark.parametrize(
    (
        "expected",
        "rss",
        "minimum_free",
        "started_ns",
        "previous_completed_ns",
        "run_started_ns",
        "completed_ns",
    ),
    [
        ("rss_limit", 6 * _GIB + 1, 30 * _GIB, 999, None, 1, 1_000),
        (
            "runtime_disk_floor",
            64 * _MIB,
            enron_capacity.MIN_RUNTIME_FREE_DISK_BYTES - 1,
            999,
            None,
            1,
            1_000,
        ),
        (
            "resource_acquisition_timeout",
            64 * _MIB,
            30 * _GIB,
            1_000,
            None,
            1,
            1_000 + enron_capacity.MAX_RESOURCE_ACQUISITION_DURATION_NS + 1,
        ),
        (
            "resource_observation_gap",
            64 * _MIB,
            30 * _GIB,
            999_999_999,
            1_000_000_000 - enron_capacity.MAX_RESOURCE_OBSERVATION_WALL_GAP_NS - 1,
            1,
            1_000_000_000,
        ),
        (
            "runtime_limit",
            64 * _MIB,
            30 * _GIB,
            enron_capacity.MAX_TOTAL_RUNTIME_NS + 99,
            enron_capacity.MAX_TOTAL_RUNTIME_NS + 99,
            1,
            enron_capacity.MAX_TOTAL_RUNTIME_NS + 100,
        ),
    ],
)
def test_launcher_terminal_leak_collision_uses_shared_resource_precedence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    expected: str,
    rss: int,
    minimum_free: int,
    started_ns: int,
    previous_completed_ns: int | None,
    run_started_ns: int,
    completed_ns: int,
) -> None:
    worker_endpoint, launcher_endpoint = socket.socketpair()
    observer = enron_capacity._LauncherResourceObserver(
        launcher_endpoint,
        worker_pid=os.getpid(),
        nonce=_NONCE,
        options=EnronCapacityOptions(
            output_dir=tmp_path / "output" / "report.json",
            attempt_ledger_dir=tmp_path / "attempts",
        ),
    )
    observer.acquisition_started_ns = started_ns
    monkeypatch.setattr(enron_capacity.time, "monotonic_ns", lambda: completed_ns)
    try:
        completion = observer._complete_resource_acquisition(
            started_ns=started_ns,
            previous_completed_ns=previous_completed_ns,
            run_started_ns=run_started_ns,
            sample_kind="terminal",
            sequence=1,
            scheduled_ns=started_ns,
            rss_finished_ns=started_ns,
            rss_retry_count=0,
            filesystem_retry_count=0,
            process_tree_rss_bytes=rss,
            maximum_peak_rss_bytes=6 * _GIB,
            minimum_free_disk_bytes=minimum_free,
            output_free_disk_bytes=30 * _GIB,
            terminal_process_leak=True,
            fallback_failure_code=None,
        )

        assert completion.valid is (expected != "resource_acquisition_timeout")
        assert completion.failure_code == expected
        assert completion.sample_failure_reserved is True
        assert completion.external_failure_code is None
        assert observer.failure_code == expected
    finally:
        worker_endpoint.close()
        launcher_endpoint.close()


def test_partial_invalid_sample_retains_extrema_without_advancing_valid_cadence(
    remote_harness: _RemoteHarness,
) -> None:
    first_completed = _accept_startup(remote_harness)
    partial_completed = first_completed + 100
    remote_harness.remote._accept_sample(
        _sample(
            sequence=2,
            completed_ns=partial_completed,
            gap_ns=100,
            valid=False,
            failure_code="rss_acquisition_exhausted",
            process_tree_rss_bytes=128 * _MIB,
            minimum_free_disk_bytes=None,
            output_free_disk_bytes=None,
        ),
    )

    assert remote_harness.remote.event_sequence == 2
    assert remote_harness.remote.last_valid_completed_ns == first_completed
    assert remote_harness.monitor._global_observations == 1
    assert remote_harness.monitor._global_peak_rss == 128 * _MIB

    final_completed = first_completed + 250
    remote_harness.remote._accept_sample(
        _sample(
            sequence=3,
            completed_ns=final_completed,
            gap_ns=250,
        ),
    )
    assert remote_harness.remote.last_valid_completed_ns == final_completed
    assert remote_harness.monitor._global_observations == 2
    assert remote_harness.monitor._global_maximum_resource_wall_gap_ns == 250
    assert remote_harness.monitor._failure_code == "rss_acquisition_exhausted"


def test_remote_rejects_trailing_partial_bytes_after_terminal_sample(
    remote_harness: _RemoteHarness,
) -> None:
    terminal = _sample(sequence=1, completed_ns=1_000_000_001, gap_ns=0, kind="terminal")
    terminal["request_id"] = 1
    remote_harness.remote.started = True
    remote_harness.remote.stop_requested = True
    remote_harness.remote.expected[1] = "terminal"
    remote_harness.launcher_endpoint.sendall(enron_capacity._canonical_json_bytes(terminal) + b"\n{")

    remote_harness.remote._loop()

    assert remote_harness.monitor._failure_code == "resource_measurement_failed"
    assert remote_harness.remote.event_sequence == 1


def test_remote_terminal_request_is_completed_only_after_peer_eof(remote_harness: _RemoteHarness) -> None:
    terminal = _sample(sequence=1, completed_ns=1_000_000_001, gap_ns=0, kind="terminal")
    terminal["request_id"] = 1
    remote_harness.remote.started = True
    remote_harness.remote.stop_requested = True
    remote_harness.remote.expected[1] = "terminal"
    receiver = threading.Thread(target=remote_harness.remote._loop)
    receiver.start()
    try:
        _send_fragmented_frame(
            remote_harness.launcher_endpoint,
            remote_harness.remote.reader,
            terminal,
        )
        deadline = time.monotonic() + 1
        while remote_harness.remote.event_sequence == 0 and time.monotonic() < deadline:
            time.sleep(0.001)
        assert remote_harness.remote.event_sequence == 1
        assert 1 not in remote_harness.remote.completed

        remote_harness.launcher_endpoint.shutdown(socket.SHUT_WR)
        receiver.join(1)
        assert not receiver.is_alive()
        assert remote_harness.remote.completed == {1}
        assert remote_harness.monitor._failure_code is None
    finally:
        if receiver.is_alive():
            remote_harness.launcher_endpoint.shutdown(socket.SHUT_WR)
            receiver.join(1)


class _AdvancingCondition:
    def __init__(self, clock: list[int]) -> None:
        self.clock = clock
        self.waits: list[float] = []

    def __enter__(self) -> _AdvancingCondition:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def wait(self, seconds: float) -> None:
        self.waits.append(seconds)
        self.clock[0] += 1

    def notify_all(self) -> None:
        return None


class _StoppingCondition(_AdvancingCondition):
    def __init__(self, clock: list[int], finished: threading.Event) -> None:
        super().__init__(clock)
        self.finished = finished

    def wait(self, seconds: float) -> None:
        self.waits.append(seconds)
        self.finished.set()


def test_launcher_supervisor_allows_the_exact_acquisition_deadline_and_fails_at_plus_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started_ns = 100
    deadline_ns = started_ns + enron_capacity.MAX_RESOURCE_ACQUISITION_DURATION_NS
    clock = [deadline_ns]
    condition = _AdvancingCondition(clock)
    sent: list[dict[str, Any]] = []
    observer = enron_capacity._LauncherResourceObserver.__new__(enron_capacity._LauncherResourceObserver)
    observer._finished = threading.Event()
    observer.state_condition = cast(Any, condition)
    observer.failure_code = None
    observer.acquisition_started_ns = started_ns
    observer.pending_publication_completed_ns = None
    observer.last_completed_ns = None
    observer.supervision_started_ns = 0
    observer.terminal_sample_sent = False
    observer.nonce = _NONCE
    observer.failure_event = threading.Event()
    observer.failure_publication_complete = False
    observer.failure_delivery_succeeded = False
    observer.failure = None
    observer._send = lambda frame: sent.append(dict(frame))
    monkeypatch.setattr(enron_capacity.time, "monotonic_ns", lambda: clock[0])

    observer._supervise_deadlines()

    assert condition.waits == [1 / 1_000_000_000]
    assert clock[0] == deadline_ns + 1
    assert observer.failure_code == "resource_acquisition_timeout"
    assert sent == [
        {
            "type": "observer_failure",
            "protocol": enron_capacity._RESOURCE_OBSERVER_PROTOCOL,
            "nonce": observer.nonce,
            "failure_code": "resource_acquisition_timeout",
        }
    ]


@pytest.mark.parametrize("gap_delta_ns", [0, 1], ids=["exact-gap", "gap-plus-one"])
@pytest.mark.parametrize("supervisor_first", [False, True])
def test_active_acquisition_defers_completion_gap_arbitration_to_completed_sample(
    monkeypatch: pytest.MonkeyPatch,
    gap_delta_ns: int,
    supervisor_first: bool,
) -> None:
    previous_completed_ns = 100
    started_ns = previous_completed_ns + 100_000_000
    completed_ns = previous_completed_ns + enron_capacity.MAX_RESOURCE_OBSERVATION_WALL_GAP_NS + gap_delta_ns
    clock = [completed_ns]
    finished = threading.Event()
    condition = _StoppingCondition(clock, finished)
    observer = enron_capacity._LauncherResourceObserver.__new__(enron_capacity._LauncherResourceObserver)
    observer._finished = finished
    observer.state_condition = cast(Any, condition)
    observer.failure_code = None
    observer.acquisition_started_ns = started_ns
    observer.pending_publication_completed_ns = None
    observer.last_completed_ns = previous_completed_ns
    observer.supervision_started_ns = 0
    observer.terminal_sample_sent = False
    observer.nonce = _NONCE
    observer.failure_event = threading.Event()
    observer.failure_publication_complete = False
    observer.failure_delivery_succeeded = False
    observer.failure = None
    observer._send = lambda _frame: None
    monkeypatch.setattr(enron_capacity.time, "monotonic_ns", lambda: clock[0])

    if supervisor_first:
        observer._supervise_deadlines()
        assert observer.failure_code is None
        assert condition.waits
        finished.clear()

    completion = observer._complete_resource_acquisition(
        started_ns=started_ns,
        previous_completed_ns=previous_completed_ns,
        run_started_ns=1,
        sample_kind="continuous",
        sequence=1,
        scheduled_ns=started_ns,
        rss_finished_ns=started_ns,
        rss_retry_count=0,
        filesystem_retry_count=0,
        process_tree_rss_bytes=64 * _MIB,
        maximum_peak_rss_bytes=6 * _GIB,
        minimum_free_disk_bytes=30 * _GIB,
        output_free_disk_bytes=30 * _GIB,
        terminal_process_leak=False,
        fallback_failure_code=None,
    )

    if not supervisor_first:
        observer._supervise_deadlines()

    expected = "resource_observation_gap" if gap_delta_ns else None
    assert completion.valid is True
    assert completion.failure_code == expected
    assert completion.sample_failure_reserved is (expected is not None)
    assert completion.external_failure_code is None
    assert observer.failure_code == expected


def test_launcher_resource_gap_failure_publishes_code_and_diagnostic_atomically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker_endpoint, launcher_endpoint = socket.socketpair()
    observer = enron_capacity._LauncherResourceObserver(
        launcher_endpoint,
        worker_pid=os.getpid(),
        nonce=_NONCE,
        options=EnronCapacityOptions(
            output_dir=tmp_path / "output" / "report.json",
            attempt_ledger_dir=tmp_path / "attempts",
        ),
    )
    previous_completed_ns = 1_000
    started_ns = previous_completed_ns + 100_000_000
    completed_ns = previous_completed_ns + enron_capacity.MAX_RESOURCE_OBSERVATION_WALL_GAP_NS + 1
    rss_finished_ns = started_ns + 7
    scheduled_ns = started_ns - 3
    witnessed: list[tuple[str | None, dict[str, Any] | None]] = []

    def await_failure() -> None:
        assert observer.failure_event.wait(1)
        with observer.state_condition:
            diagnostic = None if observer.failure_diagnostic is None else dict(observer.failure_diagnostic)
            witnessed.append((observer.failure_code, diagnostic))

    waiter = threading.Thread(target=await_failure)
    monkeypatch.setattr(enron_capacity.time, "monotonic_ns", lambda: completed_ns)
    try:
        waiter.start()
        completion = observer._complete_resource_acquisition(
            started_ns=started_ns,
            previous_completed_ns=previous_completed_ns,
            run_started_ns=1,
            sample_kind="continuous",
            sequence=17,
            scheduled_ns=scheduled_ns,
            rss_finished_ns=rss_finished_ns,
            rss_retry_count=1,
            filesystem_retry_count=1,
            process_tree_rss_bytes=64 * _MIB,
            maximum_peak_rss_bytes=6 * _GIB,
            minimum_free_disk_bytes=30 * _GIB,
            output_free_disk_bytes=30 * _GIB,
            terminal_process_leak=False,
            fallback_failure_code=None,
        )
        waiter.join(1)

        expected_diagnostic = {
            "diagnostic_kind": "resource_observation_gap",
            "phase": None,
            "sample_kind": "continuous",
            "sequence": 17,
            "observed_resource_gap_ns": enron_capacity.MAX_RESOURCE_OBSERVATION_WALL_GAP_NS + 1,
            "maximum_resource_gap_ns": enron_capacity.MAX_RESOURCE_OBSERVATION_WALL_GAP_NS,
            "acquisition_duration_ns": completed_ns - started_ns,
            "rss_duration_ns": rss_finished_ns - started_ns,
            "filesystem_duration_ns": completed_ns - rss_finished_ns,
            "acquisition_retry_count": 2,
            "scheduler_lateness_ns": 3,
        }
        assert not waiter.is_alive()
        assert completion.failure_code == "resource_observation_gap"
        assert completion.sample_failure_reserved is True
        assert witnessed == [("resource_observation_gap", expected_diagnostic)]
        assert enron_capacity._validated_resource_failure_diagnostic(expected_diagnostic) == expected_diagnostic
    finally:
        if waiter.is_alive():
            observer.failure_event.set()
            waiter.join(1)
        worker_endpoint.close()
        launcher_endpoint.close()


def test_launcher_supervisor_treats_blocked_publication_as_protocol_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    completed_ns = 100
    deadline_ns = completed_ns + enron_capacity.MAX_RESOURCE_OBSERVATION_WALL_GAP_NS
    clock = [deadline_ns]
    condition = _AdvancingCondition(clock)
    sent: list[dict[str, Any]] = []
    observer = enron_capacity._LauncherResourceObserver.__new__(enron_capacity._LauncherResourceObserver)
    observer._finished = threading.Event()
    observer.state_condition = cast(Any, condition)
    observer.failure_code = None
    observer.acquisition_started_ns = None
    observer.pending_publication_completed_ns = completed_ns
    observer.last_completed_ns = completed_ns
    observer.supervision_started_ns = 0
    observer.terminal_sample_sent = False
    observer.nonce = _NONCE
    observer.failure_event = threading.Event()
    observer.failure_publication_complete = False
    observer.failure_delivery_succeeded = False
    observer.failure = None
    observer._send = lambda frame: sent.append(dict(frame))
    monkeypatch.setattr(enron_capacity.time, "monotonic_ns", lambda: clock[0])

    observer._supervise_deadlines()

    assert condition.waits == [1 / 1_000_000_000]
    assert observer.failure_code == "resource_measurement_failed"
    assert sent[0]["failure_code"] == "resource_measurement_failed"


@pytest.mark.parametrize("resource_failure", ["rss_limit", "runtime_disk_floor"])
@pytest.mark.parametrize("supervisor_first", [False, True])
def test_launcher_acquisition_completion_and_supervisor_share_one_ordered_transition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    resource_failure: str,
    supervisor_first: bool,
) -> None:
    worker_endpoint, launcher_endpoint = socket.socketpair()
    observer = enron_capacity._LauncherResourceObserver(
        launcher_endpoint,
        worker_pid=os.getpid(),
        nonce=_NONCE,
        options=EnronCapacityOptions(
            output_dir=tmp_path / "output" / "report.json",
            attempt_ledger_dir=tmp_path / "attempts",
        ),
    )
    started_ns = 100
    completed_ns = started_ns + enron_capacity.MAX_RESOURCE_ACQUISITION_DURATION_NS + 1
    observer.supervision_started_ns = 0
    observer.acquisition_started_ns = started_ns
    sent: list[dict[str, Any]] = []
    observer._send = lambda frame: sent.append(dict(frame))  # ty: ignore[invalid-assignment]
    monkeypatch.setattr(enron_capacity.time, "monotonic_ns", lambda: completed_ns)
    rss = 6 * _GIB + 1 if resource_failure == "rss_limit" else 64 * _MIB
    minimum_free = (
        enron_capacity.MIN_RUNTIME_FREE_DISK_BYTES - 1 if resource_failure == "runtime_disk_floor" else 30 * _GIB
    )
    try:
        if supervisor_first:
            observer._supervise_deadlines()
        completion = observer._complete_resource_acquisition(
            started_ns=started_ns,
            previous_completed_ns=None,
            run_started_ns=1,
            sample_kind="continuous",
            sequence=1,
            scheduled_ns=started_ns,
            rss_finished_ns=started_ns,
            rss_retry_count=0,
            filesystem_retry_count=0,
            process_tree_rss_bytes=rss,
            maximum_peak_rss_bytes=6 * _GIB,
            minimum_free_disk_bytes=minimum_free,
            output_free_disk_bytes=30 * _GIB,
            terminal_process_leak=False,
            fallback_failure_code=None,
        )
        if not supervisor_first:
            observer._supervise_deadlines()

        assert completion.valid is False
        assert completion.failure_code == "resource_acquisition_timeout"
        if supervisor_first:
            assert completion.sample_failure_reserved is False
            assert completion.external_failure_code == "resource_acquisition_timeout"
            assert observer.failure_code == "resource_acquisition_timeout"
            assert sent[0]["failure_code"] == "resource_acquisition_timeout"
        else:
            assert completion.sample_failure_reserved is True
            assert completion.external_failure_code is None
            assert observer.failure_code == "resource_acquisition_timeout"
            assert sent == []
    finally:
        worker_endpoint.close()
        launcher_endpoint.close()


def test_watchdog_delivers_at_most_one_abort_for_duplicate_signals() -> None:
    calls = 0

    def failure_code() -> str:
        nonlocal calls
        calls += 1
        return "rss_limit"

    watchdog = enron_capacity._Watchdog(failure_code)
    with pytest.raises(enron_capacity._CapacityAbort) as raised:
        watchdog._handle(0, None)
    assert raised.value.code == "rss_limit"

    watchdog._handle(0, None)
    assert calls == 1


def test_launcher_failure_latch_preserves_the_first_publication_across_threads(tmp_path: Path) -> None:
    worker_endpoint, launcher_endpoint = socket.socketpair()
    observer = enron_capacity._LauncherResourceObserver(
        launcher_endpoint,
        worker_pid=os.getpid(),
        nonce=_NONCE,
        options=EnronCapacityOptions(
            output_dir=tmp_path / "output" / "report.json",
            attempt_ledger_dir=tmp_path / "attempts",
        ),
    )
    publication_entered = threading.Event()
    publication_release = threading.Event()
    frames: list[dict[str, Any]] = []
    outcomes: list[bool] = []

    def blocking_send(frame: Any) -> None:
        frames.append(dict(frame))
        publication_entered.set()
        assert publication_release.wait(2)

    observer._send = blocking_send  # ty: ignore[invalid-assignment]
    first = threading.Thread(target=lambda: outcomes.append(observer._publish_failure("rss_limit")))
    second = threading.Thread(target=lambda: outcomes.append(observer._publish_failure("runtime_disk_floor")))
    try:
        first.start()
        assert publication_entered.wait(2)
        second.start()
        second.join(2)
        assert not second.is_alive()
        publication_release.set()
        first.join(2)
        assert not first.is_alive()

        assert sorted(outcomes) == [False, True]
        assert observer.failure_code == "rss_limit"
        assert observer.failure_event.is_set()
        assert observer.failure_publication_complete is True
        assert observer.failure_delivery_succeeded is True
        assert len(frames) == 1
        assert frames[0]["failure_code"] == "rss_limit"
    finally:
        publication_release.set()
        first.join(2)
        second.join(2)
        worker_endpoint.close()
        launcher_endpoint.close()


class _ScriptedFrames:
    commands: list[list[dict[str, Any]]] = []
    trailing = b""

    def __init__(self, _endpoint: socket.socket) -> None:
        self._commands = iter(self.commands)
        self.buffer = bytearray(self.trailing)

    def receive(self, _timeout_ns: int) -> list[dict[str, Any]]:
        try:
            return next(self._commands)
        except StopIteration:
            raise enron_capacity._ResourceObserverEOF from None


def _run_synthetic_launcher_protocol(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    descendants: tuple[int, ...],
    process_group_members: tuple[int, ...] = (),
    command_type: str = "stop",
    sample_kind: str = "terminal",
    trailing: bytes = b"",
) -> tuple[enron_capacity._LauncherResourceObserver, list[dict[str, Any]], list[int]]:
    preflight = _preflight(tmp_path, baseline_rss=250)
    _ScriptedFrames.commands = [
        [{}],
        [
            {
                "type": command_type,
                "protocol": enron_capacity._RESOURCE_OBSERVER_PROTOCOL,
                "nonce": _NONCE,
                "request_id": 1,
                "sample_kind": sample_kind,
                "worker_peak_rss_bytes": 400,
            }
        ],
    ]
    _ScriptedFrames.trailing = trailing
    clock = iter(range(100, 10_000, 10))
    killed: list[int] = []
    monkeypatch.setattr(enron_capacity, "_ResourceObserverFrames", _ScriptedFrames)
    monkeypatch.setattr(
        enron_capacity,
        "_observer_init_preflight",
        lambda _frame, *, nonce, options: (preflight, 1, enron_capacity.PRODUCTION_MONITOR_INTERVAL_NS),
    )
    monkeypatch.setattr(enron_capacity, "_SystemResourceProbe", lambda: object())
    monkeypatch.setattr(enron_capacity, "_acquire_runtime_process_tree_rss", lambda _probe: (100, 0))
    monkeypatch.setattr(enron_capacity, "_root_process_peak_rss_bytes", lambda: 75)
    monkeypatch.setattr(
        enron_capacity,
        "_sample_runtime_filesystems",
        lambda _probe, _preflight: (
            30 * _GIB,
            CapacityDiskUsage(total=100 * _GIB, used=70 * _GIB, free=30 * _GIB),
            0,
        ),
    )
    residuals = tuple(sorted(set(descendants) | set(process_group_members)))
    monkeypatch.setattr(
        enron_capacity,
        "_terminal_process_snapshot",
        lambda _pid: enron_capacity._TerminalProcessSnapshot(
            worker_tree_rss_bytes=100,
            residuals=tuple((pid, f"identity-{pid}") for pid in residuals),
        ),
    )
    monkeypatch.setattr(enron_capacity.os, "kill", lambda pid, _signal: killed.append(pid))
    monkeypatch.setattr(enron_capacity.time, "monotonic_ns", lambda: next(clock))

    worker_endpoint, launcher_endpoint = socket.socketpair()
    observer = enron_capacity._LauncherResourceObserver(
        launcher_endpoint,
        worker_pid=777,
        nonce=_NONCE,
        options=EnronCapacityOptions(
            output_dir=tmp_path / "output" / "report.json",
            attempt_ledger_dir=tmp_path / "attempts",
        ),
    )
    frames: list[dict[str, Any]] = []
    monkeypatch.setattr(observer, "_send", lambda frame: frames.append(dict(frame)))
    monkeypatch.setattr(observer, "_send_final", lambda frame: frames.append(dict(frame)))
    try:
        observer._run_protocol()
    finally:
        _ScriptedFrames.trailing = b""
        worker_endpoint.close()
        launcher_endpoint.close()
    return observer, frames, killed


def test_launcher_combines_worker_and_launcher_root_peaks_with_the_live_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observer, frames, killed = _run_synthetic_launcher_protocol(monkeypatch, tmp_path, descendants=())

    samples = [frame for frame in frames if frame["type"] == "sample"]
    assert [sample["process_tree_rss_bytes"] for sample in samples] == [325, 475]
    assert [sample["sample_kind"] for sample in samples] == ["startup", "terminal"]
    assert all(sample["failure_code"] is None for sample in samples)
    assert observer.stop_acknowledged is True
    assert observer.failure_code is None
    assert killed == []


@pytest.mark.parametrize(
    ("descendants", "process_group_members"),
    [((901, 902), ()), ((), (901, 902)), ((901,), (901, 902))],
)
def test_launcher_terminal_sample_fails_closed_without_signaling_a_bare_residual_pid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    descendants: tuple[int, ...],
    process_group_members: tuple[int, ...],
) -> None:
    observer, frames, killed = _run_synthetic_launcher_protocol(
        monkeypatch,
        tmp_path,
        descendants=descendants,
        process_group_members=process_group_members,
    )

    terminal = [frame for frame in frames if frame.get("sample_kind") == "terminal"]
    assert len(terminal) == 1
    assert terminal[0]["valid"] is True
    assert terminal[0]["failure_code"] == "worker_process_leak"
    assert killed == []
    assert observer.failure_code == "worker_process_leak"
    assert observer.stop_acknowledged is True


@pytest.mark.parametrize(
    ("command_type", "sample_kind"),
    [("force", "terminal"), ("stop", "boundary")],
)
def test_launcher_rejects_mismatched_terminal_command_kinds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command_type: str,
    sample_kind: str,
) -> None:
    with pytest.raises(EnronCapacityError) as raised:
        _run_synthetic_launcher_protocol(
            monkeypatch,
            tmp_path,
            descendants=(),
            command_type=command_type,
            sample_kind=sample_kind,
        )
    assert raised.value.code == "resource_measurement_failed"


def test_launcher_rejects_trailing_partial_bytes_after_terminal_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(EnronCapacityError) as raised:
        _run_synthetic_launcher_protocol(monkeypatch, tmp_path, descendants=(), trailing=b"{")
    assert raised.value.code == "resource_measurement_failed"


@pytest.mark.skipif(os.name != "posix", reason="descriptor inheritance is a POSIX assertion")
def test_observer_endpoint_is_cloexec_unless_explicitly_passed_to_worker() -> None:
    parent_endpoint, worker_endpoint = socket.socketpair()
    try:
        worker_fd = worker_endpoint.fileno()
        assert os.get_inheritable(parent_endpoint.fileno()) is False
        assert os.get_inheritable(worker_fd) is False
        child = (
            "import os,socket,stat,sys;fd=int(sys.argv[1]);"
            "info=None;"
            "\ntry: info=os.fstat(fd)"
            "\nexcept OSError: sys.exit(42)"
            "\nif not stat.S_ISSOCK(info.st_mode): sys.exit(43)"
            "\nsocket.socket(fileno=fd).sendall(b'inherited')"
        )
        closed = subprocess.run(
            [sys.executable, "-I", "-c", child, str(worker_fd)],
            check=False,
        )
        assert closed.returncode == 42

        inherited = subprocess.run(
            [sys.executable, "-I", "-c", child, str(worker_fd)],
            check=False,
            pass_fds=(worker_fd,),
        )
        assert inherited.returncode == 0
        parent_endpoint.settimeout(1)
        assert parent_endpoint.recv(64) == b"inherited"
    finally:
        parent_endpoint.close()
        worker_endpoint.close()


@pytest.mark.skipif(
    not (sys.platform.startswith("linux") or sys.platform == "darwin"),
    reason="the production process-tree probe supports Linux and macOS",
)
def test_launcher_sampler_backlog_survives_phase_and_progress_callbacks_while_worker_gil_is_held(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_parent = tmp_path / "output"
    ledger_dir = tmp_path / "attempts"
    output_parent.mkdir(mode=0o700)
    ledger_dir.mkdir(mode=0o700)
    options = EnronCapacityOptions(
        output_dir=output_parent / "report.json",
        attempt_ledger_dir=ledger_dir,
    )
    worker_endpoint, launcher_endpoint = socket.socketpair()
    status_read_fd, status_write_fd = os.pipe()
    process: subprocess.Popen[bytes] | None = None
    observer: enron_capacity._LauncherResourceObserver | None = None
    observer_joined = False
    captured_samples: list[dict[str, Any]] = []

    def read_status_marker(timeout_seconds: float) -> bytes:
        ready, _, _ = select.select([status_read_fd], [], [], timeout_seconds)
        if not ready:
            pytest.fail("synthetic worker status timed out")
        marker = os.read(status_read_fd, 1)
        if not marker:
            pytest.fail("synthetic worker closed its status channel")
        return marker

    try:
        process = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-c",
                _GIL_HOLD_WORKER,
                str(worker_endpoint.fileno()),
                str(status_write_fd),
                os.fspath(output_parent),
                os.fspath(ledger_dir),
                _NONCE,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            pass_fds=(worker_endpoint.fileno(), status_write_fd),
            start_new_session=True,
        )
        worker_endpoint.close()
        os.close(status_write_fd)
        status_write_fd = -1

        observer = enron_capacity._LauncherResourceObserver(
            launcher_endpoint,
            worker_pid=process.pid,
            nonce=_NONCE,
            options=options,
        )
        original_send = observer._send

        def capture_sample(frame: Any) -> None:
            if isinstance(frame, dict) and frame.get("type") == "sample":
                captured_samples.append(dict(frame))
            original_send(frame)

        monkeypatch.setattr(observer, "_send", capture_sample)
        observer.start()

        assert read_status_marker(10) == b"R"
        assert read_status_marker(10) == b"D"
        _, stderr = process.communicate(timeout=10)
        observer.join()
        observer_joined = True

        outcome_chunks: list[bytes] = []
        while chunk := os.read(status_read_fd, 4096):
            outcome_chunks.append(chunk)
        outcome = b"".join(outcome_chunks)
        assert process.returncode == 0, stderr.decode("utf-8", errors="replace")
        assert outcome.startswith(b"J"), outcome.decode("ascii", errors="replace")
        result = cast(dict[str, Any], json.loads(outcome[1:]))
        hold_started_ns = int(result["hold_started_ns"])
        hold_finished_ns = int(result["hold_finished_ns"])
        progress_hold_started_ns = int(result["progress_hold_started_ns"])
        progress_hold_finished_ns = int(result["progress_hold_finished_ns"])
        phase_snapshot = cast(dict[str, int], result["phase_snapshot"])
        snapshot = cast(dict[str, int], result["snapshot"])
        samples_during_hold = [
            sample
            for sample in captured_samples
            if sample.get("sample_kind") == "continuous"
            and hold_started_ns <= int(sample["completed_wall_ns"]) <= hold_finished_ns
        ]

        assert hold_finished_ns - hold_started_ns >= 800_000_000
        assert progress_hold_finished_ns - progress_hold_started_ns >= 800_000_000
        assert len(samples_during_hold) >= 3
        assert (
            int(samples_during_hold[-1]["completed_wall_ns"]) - int(samples_during_hold[0]["completed_wall_ns"])
            >= 2 * enron_capacity.PRODUCTION_MONITOR_INTERVAL_NS
        )
        assert snapshot["resource_observation_count"] >= len(samples_during_hold) + 3
        assert (
            snapshot["maximum_resource_observation_wall_gap_ns"] <= enron_capacity.MAX_RESOURCE_OBSERVATION_WALL_GAP_NS
        )
        assert (
            snapshot["maximum_resource_acquisition_duration_ns"] <= enron_capacity.MAX_RESOURCE_ACQUISITION_DURATION_NS
        )
        assert phase_snapshot["resource_observation_count"] >= 3
        assert phase_snapshot["checkpoint_count"] == 1
        assert phase_snapshot["progress_signal_count"] == 3
        assert observer.started is True
        assert observer.stop_acknowledged is True
        assert observer.failure_code is None
        assert observer.failure is None
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
        if observer is not None:
            if not observer_joined:
                try:
                    observer.join()
                except EnronCapacityError:
                    pass
            observer.close()
        else:
            launcher_endpoint.close()
        worker_endpoint.close()
        if status_write_fd >= 0:
            os.close(status_write_fd)
        os.close(status_read_fd)


class _ShutdownEndpoint:
    def __init__(self) -> None:
        self.shutdown_calls: list[int] = []

    def shutdown(self, how: int) -> None:
        self.shutdown_calls.append(how)


class _ReceiverThread:
    def __init__(self, *, dies_on_join: bool) -> None:
        self.alive = True
        self.dies_on_join = dies_on_join
        self.join_calls: list[float] = []

    def is_alive(self) -> bool:
        return self.alive

    def join(self, timeout: float) -> None:
        self.join_calls.append(timeout)
        if self.dies_on_join:
            self.alive = False


class _FailureRecorder:
    def __init__(self) -> None:
        self.failures: list[str] = []

    def _record_failure(self, code: str) -> None:
        self.failures.append(code)

    def _record_remote_failure(self, code: str) -> None:
        self._record_failure(code)


@pytest.mark.parametrize("after_native_start", [False, True], ids=["thread-start-raises", "post-start-interruption"])
def test_remote_start_interruption_leaves_monitor_shutdown_settled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    after_native_start: bool,
) -> None:
    worker_endpoint, launcher_endpoint = socket.socketpair()
    monitor = enron_capacity._ContinuousResourceMonitor(
        tree=cast(Any, _StaticTree()),
        probe=cast(Any, _UnusedProbe()),
        preflight=_preflight(tmp_path),
        run_started_ns=1,
        interval_ns=enron_capacity.PRODUCTION_MONITOR_INTERVAL_NS,
        wall_clock=lambda: 1,
        resource_observer_socket=worker_endpoint,
        resource_observer_nonce=_NONCE,
    )
    remote = monitor._remote
    assert remote is not None
    native_start = remote.thread.start

    def interrupted_start() -> None:
        if after_native_start:
            native_start()
            raise KeyboardInterrupt
        raise RuntimeError("injected receiver thread start failure")

    monkeypatch.setattr(remote.thread, "start", interrupted_start)
    expected_error = KeyboardInterrupt if after_native_start else RuntimeError
    try:
        with pytest.raises(expected_error):
            remote.start()
        monitor._stop_once()
        assert remote.stopped is True
        assert not remote.thread.is_alive()
        assert monitor._shutdown_is_settled() is True
    finally:
        with remote.condition:
            remote.stopped = True
            remote.condition.notify_all()
        try:
            worker_endpoint.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        if remote.thread.is_alive():
            remote.thread.join(1)
        worker_endpoint.close()
        launcher_endpoint.close()


@pytest.mark.parametrize("dies_on_join", [True, False])
def test_remote_shutdown_requires_the_receiver_thread_to_be_dead(dies_on_join: bool) -> None:
    endpoint = _ShutdownEndpoint()
    receiver = _ReceiverThread(dies_on_join=dies_on_join)
    monitor = _FailureRecorder()
    remote = enron_capacity._RemoteResourceObserver.__new__(enron_capacity._RemoteResourceObserver)
    remote.started = True
    remote.stopped = True
    remote.thread = cast(Any, receiver)
    remote.endpoint = cast(Any, endpoint)
    remote.monitor = cast(Any, monitor)
    remote.condition = threading.Condition()

    if dies_on_join:
        remote.stop()
        assert monitor.failures == []
    else:
        with pytest.raises(EnronCapacityError) as raised:
            remote.stop()
        assert raised.value.code == "resource_measurement_failed"
        assert monitor.failures == ["resource_measurement_failed"]
    assert endpoint.shutdown_calls == [socket.SHUT_RDWR]
    assert receiver.join_calls == [enron_capacity.RESOURCE_OBSERVER_COMMAND_TIMEOUT_NS / 1_000_000_000]


@pytest.mark.parametrize(
    ("stdout", "expected"),
    [
        (
            "100 1 100 10 Mon Jul 13 12:00:00 2026\n"
            "101 100 100 5 Mon Jul 13 12:00:01 2026\n"
            "102 101 102 6 Mon Jul 13 12:00:02 2026\n"
            "200 1 200 7 Mon Jul 13 12:00:03 2026\n",
            (101, 102),
        ),
        ("101 100 100 5 Mon Jul 13 12:00:01 2026\n", None),
        ("100 1 100 malformed Mon Jul 13 12:00:00 2026\n", None),
    ],
)
def test_terminal_process_snapshot_is_transitive_and_fails_closed_on_incomplete_tables(
    stdout: str,
    expected: tuple[int, ...] | None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(enron_capacity.sys, "platform", "darwin")
    monkeypatch.setattr(
        enron_capacity,
        "_darwin_process_table",
        lambda: enron_capacity._parse_darwin_process_table(stdout),
    )

    snapshot = enron_capacity._terminal_process_snapshot(100)

    assert (None if snapshot is None else tuple(pid for pid, _identity in snapshot.residuals)) == expected
    if snapshot is not None:
        assert snapshot.worker_tree_rss_bytes == 21 * 1024


@pytest.mark.parametrize(
    ("stdout", "expected"),
    [
        (
            "100 1 100 10 Mon Jul 13 12:00:00 2026\n"
            "101 1 100 5 Mon Jul 13 12:00:01 2026\n"
            "102 1 102 6 Mon Jul 13 12:00:02 2026\n",
            (101,),
        ),
        (
            "100 1 99 10 Mon Jul 13 12:00:00 2026\n101 1 100 5 Mon Jul 13 12:00:01 2026\n",
            None,
        ),
        ("100 1 100 10 Mon Jul 13 12:00:00 2026\n101 malformed\n", None),
        ("101 1 100 5 Mon Jul 13 12:00:01 2026\n", None),
    ],
)
def test_terminal_process_snapshot_includes_group_members_and_requires_the_group_leader(
    stdout: str,
    expected: tuple[int, ...] | None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(enron_capacity.sys, "platform", "darwin")
    monkeypatch.setattr(
        enron_capacity,
        "_darwin_process_table",
        lambda: enron_capacity._parse_darwin_process_table(stdout),
    )

    snapshot = enron_capacity._terminal_process_snapshot(100)

    assert (None if snapshot is None else tuple(pid for pid, _identity in snapshot.residuals)) == expected
    if expected == (101,):
        assert snapshot is not None
        assert snapshot.worker_tree_rss_bytes == 15 * 1024


def test_linux_terminal_snapshot_ignores_non_ascii_commands_and_unrelated_kernel_processes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proc_root = tmp_path / "proc"
    for pid, parent_pid, process_group_id, command in (
        (2, 0, 0, b"kernel-\xff-task"),
        (100, 1, 100, b"worker"),
        (101, 1, 100, b"reparented-member"),
        (102, 1, 102, b"unrelated"),
    ):
        process_root = proc_root / str(pid)
        process_root.mkdir(parents=True)
        fields = [
            b"S",
            str(parent_pid).encode("ascii"),
            str(process_group_id).encode("ascii"),
            *([b"0"] * 16),
            str(1_000 + pid).encode("ascii"),
            b"0",
            b"2",
        ]
        (process_root / "stat").write_bytes(
            str(pid).encode("ascii") + b" (" + command + b") " + b" ".join(fields) + b"\n"
        )
    real_path = Path

    def test_path(value: str) -> Path:
        return proc_root if value == "/proc" else real_path(value)

    monkeypatch.setattr(enron_capacity.sys, "platform", "linux")
    monkeypatch.setattr(enron_capacity, "Path", test_path)

    assert enron_capacity._terminal_residual_process_pids(100) == (101,)


def test_process_creation_guard_records_only_an_attested_matching_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mode = enron_capacity._expected_process_containment_mode()
    execution = {"process_containment": {"mode": mode}}

    def install() -> None:
        monkeypatch.setattr(enron_capacity, "_PRODUCTION_PROCESS_CONTAINMENT", mode)

    enron_capacity._activate_process_creation_guard(
        execution,
        production_evidence=True,
        process_creation_guard=install,
    )

    monkeypatch.setattr(enron_capacity, "_PRODUCTION_PROCESS_CONTAINMENT", None)
    with pytest.raises(EnronCapacityError) as raised:
        enron_capacity._activate_process_creation_guard(
            execution,
            production_evidence=True,
            process_creation_guard=lambda: None,
        )
    assert raised.value.code == "production_identity_invalid"


def test_fresh_worker_containment_rechecks_the_cached_clean_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mode = enron_capacity._expected_process_containment_mode()
    commit = "a" * 40
    observed: list[str] = []
    monkeypatch.setattr(enron_capacity, "_FRESH_PRODUCTION_WORKER", True)
    monkeypatch.setattr(enron_capacity, "_PRODUCTION_GIT_COMMIT", commit)
    monkeypatch.setattr(enron_capacity, "_PRODUCTION_GIT_ROOT", tmp_path)
    monkeypatch.setattr(enron_capacity, "_PRODUCTION_RELEVANT_WORKTREE_PATHS", ("src/nerb/example.py",))
    monkeypatch.setattr(enron_capacity, "_PRODUCTION_CPU_MODEL", "synthetic-cpu")
    monkeypatch.setattr(enron_capacity, "_PRODUCTION_PHYSICAL_MEMORY_BYTES", 1)

    def reject(value: str) -> None:
        observed.append(value)
        raise enron_capacity._error("production_identity_invalid")

    monkeypatch.setattr(enron_capacity, "_require_globally_clean_checkout", reject)

    with pytest.raises(EnronCapacityError) as raised:
        enron_capacity._install_production_process_containment(mode)
    assert raised.value.code == "production_identity_invalid"
    assert observed == [commit]
    assert enron_capacity._PRODUCTION_PROCESS_CONTAINMENT is None


def test_linux_seccomp_filter_rejects_native_and_x32_process_creation() -> None:
    instructions, _program = enron_capacity._linux_process_creation_filter("x86_64")

    def evaluate(syscall_number: int, *, first_argument: int = 0) -> int:
        accumulator = 0
        index = 0
        while index < len(instructions):
            instruction = instructions[index]
            if instruction.code == 0x20:
                accumulator = {0: syscall_number, 4: 0xC000003E, 16: first_argument}[instruction.k]
                index += 1
            elif instruction.code == 0x15:
                index += 1 + (instruction.jt if accumulator == instruction.k else instruction.jf)
            elif instruction.code == 0x35:
                index += 1 + (instruction.jt if accumulator >= instruction.k else instruction.jf)
            elif instruction.code == 0x54:
                accumulator &= instruction.k
                index += 1
            elif instruction.code == 0x06:
                return int(instruction.k)
            else:
                raise AssertionError(f"unexpected BPF instruction {instruction.code:#x}")
        raise AssertionError("BPF program did not return")

    denied = 0x00050000 | errno.EPERM
    assert evaluate(57) == denied
    assert evaluate(58) == denied
    assert evaluate(56) == denied
    assert evaluate(0x40000000 | 57) == denied
    assert evaluate(0x40000000 | 56) == denied
    assert evaluate(56, first_argument=0x00010000) == 0x7FFF0000
    assert evaluate(39) == 0x7FFF0000


@pytest.mark.skipif(
    not (sys.platform.startswith("linux") or sys.platform == "darwin"),
    reason="production containment is supported on Linux and macOS",
)
@pytest.mark.skipif(
    importlib.util.find_spec("pyarrow") is None,
    reason="PyArrow is not installed in the local environment",
)
def test_production_process_containment_denies_processes_and_allows_threads() -> None:
    script = (
        "import json,os,sqlite3,tempfile;from pathlib import Path;"
        "from nerb import Bank,enron_capacity as c;import nerb.enron_preparation as prep;"
        "tmp=tempfile.TemporaryDirectory();final=Path(tmp.name).resolve()/'run';token='a'*24;"
        "scratch=Path(tmp.name).resolve()/'scratch';scratch.mkdir(mode=0o700);"
        "c.ensure_private_output_allowed(final);"
        "boundary=c._private_io._prevalidate_cleanup_boundary("
        "final,workspace_root=None,allow_unignored_output=False);"
        "run=c.PrivateRun(final,stage_token=token,cleanup_boundary=boundary);run.__enter__();"
        "mode=c._expected_process_containment_mode();"
        "c._FRESH_PRODUCTION_WORKER=True;c._prepare_production_subprocess_context();"
        "c._require_globally_clean_checkout=lambda _commit:None;"
        "c._install_production_process_containment(mode);"
        "probe=c._SystemResourceProbe();assert probe.physical_memory_bytes()>0;"
        "assert probe.process_tree_rss_bytes(os.getpid())>0;"
        "c._private_io.subprocess.run=lambda *_a,**_k:(_ for _ in ()).throw(AssertionError('spawn attempted'));"
        "handle=run.open_text('synthetic.txt');handle.write('synthetic');handle.close();"
        "failure=RuntimeError('synthetic');run.__exit__(RuntimeError,failure,None);"
        "scratch_context=prep._verification_scratch_directory(scratch);"
        "scratch_file=scratch_context.__enter__();os.write(scratch_file.descriptor,b'synthetic');"
        "scratch_context.__exit__(None,None,None);"
        "db=sqlite3.connect(':memory:');db.execute('create table t (v integer)');"
        "db.execute('insert into t values (1)');db.commit();db.close();"
        'bank=Bank.from_source_bytes(b\'{"TOKEN":{"Synthetic":"SYNTH-[0-9]{6}"}}\','
        "format_hint='json',use_cache=False);assert bank.scan_bytes(b'SYNTH-000042');"
        "import pyarrow as pa,pyarrow.compute as pc;"
        "assert pc.sum(pa.array([1,2,3])).as_py()==6;"
        "print(json.dumps({'installed':c._PRODUCTION_PROCESS_CONTAINMENT,'libraries':True,'mode':mode}))"
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-c", script],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        start_new_session=True,
    )

    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result == {
        "installed": enron_capacity._expected_process_containment_mode(),
        "libraries": True,
        "mode": result["installed"],
    }


@pytest.mark.skipif(os.name != "posix", reason="worker process-group membership requires POSIX")
def test_terminal_process_snapshot_detects_a_reparented_double_fork_member() -> None:
    status_read, status_write = os.pipe()
    worker = (
        "import os,sys,time;fd=int(sys.argv[1]);child=os.fork();"
        "\nif child==0:"
        "\n grandchild=os.fork()"
        "\n if grandchild==0: os.write(fd,(str(os.getpid())+'\\n').encode());time.sleep(60);os._exit(0)"
        "\n os._exit(0)"
        "\nos.waitpid(child,0);time.sleep(60)"
    )
    process = subprocess.Popen(
        [sys.executable, "-I", "-c", worker, str(status_write)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        pass_fds=(status_write,),
        start_new_session=True,
    )
    os.close(status_write)
    try:
        ready, _, _ = select.select([status_read], [], [], 5)
        assert ready
        raw_pid = b""
        while not raw_pid.endswith(b"\n"):
            raw_pid += os.read(status_read, 32)
        orphan_pid = int(raw_pid)
        deadline = time.monotonic() + 5
        residuals: tuple[int, ...] | None = None
        while time.monotonic() < deadline:
            residuals = enron_capacity._terminal_residual_process_pids(process.pid)
            if residuals is not None and orphan_pid in residuals:
                break
            time.sleep(0.01)
        assert orphan_pid in cast(tuple[int, ...], residuals)
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)
        os.close(status_read)


def _valid_soak_gate_case(
    *,
    acquisition_ns: int = 1,
    completion_gap_ns: int = 1,
    pyarrow_available: bool = True,
    pyarrow_batches: int = 1,
) -> dict[str, Any]:
    return {
        "worker_result": {
            "ok": True,
            "resource_snapshot": {
                "resource_observation_count": 3,
                "maximum_resource_acquisition_duration_ns": acquisition_ns,
                "maximum_resource_observation_wall_gap_ns": completion_gap_ns,
            },
            "workloads": {
                "owner_only_tree_mutations": 1,
                "owner_only_tree_seeded_regular_entries": 10_000,
                "owner_only_tree_retained_seed_regular_entries": 10_000,
                "owner_only_tree_terminal_regular_entries": 10_001,
                "sqlite_transactions": 1,
                "pyarrow_available": pyarrow_available,
                "pyarrow_batches": pyarrow_batches,
                "native_rust_scans": 1,
                "c_held_gil_intervals": 1,
                "descendant_churn_cycles": 1,
            },
        },
        "worker_return_code": 0,
        "worker_process_group_gone": True,
        "timed_out": False,
        "observer_failure_code": None,
        "observer_join_error": None,
        "observer_metrics": {
            "valid_sample_count": 3,
            "invalid_sample_count": 0,
            "acquisition_duration_ns": {"max": acquisition_ns},
            "completion_to_completion_gap_ns": {"max": completion_gap_ns},
        },
    }


@pytest.mark.parametrize(
    ("pyarrow_available", "pyarrow_batches", "expected"),
    [(True, 1, True), (False, 1, False), (True, 0, False)],
)
def test_decision_grade_soak_gate_requires_exercised_pyarrow(
    pyarrow_available: bool,
    pyarrow_batches: int,
    expected: bool,
) -> None:
    script = runpy.run_path(
        os.fspath(Path(__file__).parents[2] / "scripts" / "soak_enron_resource_observer.py"),
    )
    case = _valid_soak_gate_case(
        pyarrow_available=pyarrow_available,
        pyarrow_batches=pyarrow_batches,
    )

    assert script["_positive_case_passed"](case) is expected


def test_decision_grade_soak_environment_requires_exact_python_and_pyarrow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = runpy.run_path(
        os.fspath(Path(__file__).parents[2] / "scripts" / "soak_enron_resource_observer.py"),
    )

    provenance = {
        "version": "25.0.0",
        "distribution_file_count": 3,
        "distribution_total_bytes": 100,
        "distribution_sha256": "sha256:" + "a" * 64,
        "distribution_root_bound": True,
        "import_origin_bound": False,
        "module_version_matches_distribution": False,
    }
    monkeypatch.setitem(
        script["_runtime_environment_identity"].__globals__,
        "_pyarrow_provenance_identity",
        lambda: dict(provenance),
    )
    exact = script["_runtime_environment_identity"]()
    assert exact["python_major"] == sys.version_info.major
    assert exact["python_minor"] == sys.version_info.minor
    assert exact["pyarrow_version"] == "25.0.0"
    assert exact["launcher_environment_verified"] is (sys.version_info[:2] == (3, 13))

    provenance["version"] = "24.0.0"
    mismatched = script["_runtime_environment_identity"]()
    assert mismatched["pyarrow_version"] == "24.0.0"
    assert mismatched["launcher_environment_verified"] is False


def test_soak_pyarrow_provenance_binds_exact_distribution_files_and_module_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = runpy.run_path(
        os.fspath(Path(__file__).parents[2] / "scripts" / "soak_enron_resource_observer.py"),
    )
    source_root = tmp_path / "repository" / "src"
    dependency_root = tmp_path / "venv" / "site-packages"
    pyarrow_root = dependency_root / "pyarrow"
    pyarrow_root.mkdir(parents=True)
    module_paths = tuple(pyarrow_root / name for name in ("__init__.py", "compute.py", "ipc.py"))
    for index, path in enumerate(module_paths):
        path.write_text(f"MODULE = {index}\n", encoding="utf-8")

    class FakeDistribution:
        version = "25.0.0"
        files = tuple(Path("pyarrow") / path.name for path in module_paths)

        def locate_file(self, relative: Path) -> Path:
            return dependency_root / relative

    provenance_sha256 = "sha256:" + "a" * 64
    monkeypatch.setattr(
        script["enron_capacity"],
        "_reader_distribution_provenance",
        lambda *_args: enron_capacity._ReaderDistributionProvenance(
            version="25.0.0",
            file_count=3,
            total_bytes=sum(path.stat().st_size for path in module_paths),
            sha256=provenance_sha256,
            package_init=module_paths[0],
        ),
    )
    monkeypatch.setattr(
        script["enron_capacity"],
        "_validated_capacity_bootstrap",
        lambda: (source_root, (dependency_root,), (), None),
    )
    monkeypatch.setattr(script["importlib"].metadata, "distribution", lambda _name: FakeDistribution())

    pyarrow_module = SimpleNamespace(__file__=os.fspath(module_paths[0]), __version__="25.0.0")
    compute_module = SimpleNamespace(__file__=os.fspath(module_paths[1]))
    ipc_module = SimpleNamespace(__file__=os.fspath(module_paths[2]))

    exact = script["_pyarrow_provenance_identity"](
        imported_modules=(pyarrow_module, compute_module, ipc_module),
    )
    assert exact == {
        "version": "25.0.0",
        "distribution_file_count": 3,
        "distribution_total_bytes": sum(path.stat().st_size for path in module_paths),
        "distribution_sha256": provenance_sha256,
        "distribution_root_bound": True,
        "import_origin_bound": True,
        "module_version_matches_distribution": True,
    }

    shadow = tmp_path / "shadow-compute.py"
    shadow.write_bytes(module_paths[1].read_bytes())
    compute_module.__file__ = os.fspath(shadow)
    wrong_origin = script["_pyarrow_provenance_identity"](
        imported_modules=(pyarrow_module, compute_module, ipc_module),
    )
    assert wrong_origin["import_origin_bound"] is False
    assert wrong_origin["module_version_matches_distribution"] is True

    compute_module.__file__ = os.fspath(module_paths[1])
    pyarrow_module.__version__ = "24.0.0"
    wrong_version = script["_pyarrow_provenance_identity"](
        imported_modules=(pyarrow_module, compute_module, ipc_module),
    )
    assert wrong_version["import_origin_bound"] is True
    assert wrong_version["module_version_matches_distribution"] is False


def test_soak_worker_pyarrow_bindings_preserve_independent_diagnostics() -> None:
    script = runpy.run_path(
        os.fspath(Path(__file__).parents[2] / "scripts" / "soak_enron_resource_observer.py"),
    )
    environment = {
        "pyarrow_version": "25.0.0",
        "pyarrow_distribution_file_count": 3,
        "pyarrow_distribution_total_bytes": 100,
        "pyarrow_distribution_sha256": "sha256:" + "a" * 64,
    }
    provenance = {
        "version": "25.0.0",
        "distribution_file_count": 3,
        "distribution_total_bytes": 100,
        "distribution_sha256": "sha256:" + "a" * 64,
        "distribution_root_bound": True,
        "import_origin_bound": True,
        "module_version_matches_distribution": True,
    }
    case = {"worker_result": {"pyarrow_provenance": provenance}}
    bindings = script["_worker_pyarrow_bindings"]

    assert bindings(case, environment) == (True, True)
    provenance["import_origin_bound"] = False
    assert bindings(case, environment) == (False, True)
    provenance["import_origin_bound"] = True
    provenance["module_version_matches_distribution"] = False
    assert bindings(case, environment) == (True, False)
    provenance["module_version_matches_distribution"] = True
    provenance["distribution_sha256"] = "sha256:" + "b" * 64
    assert bindings(case, environment) == (False, False)
    provenance["unexpected"] = True
    assert bindings(case, environment) == (False, False)


def test_soak_worker_command_uses_the_closed_shared_launcher_shape(tmp_path: Path) -> None:
    script_path = Path(__file__).parents[2] / "scripts" / "soak_enron_resource_observer.py"
    script = runpy.run_path(os.fspath(script_path))
    tree_root = (tmp_path / "tree").resolve()
    output_parent = (tmp_path / "output").resolve()

    command = script["_worker_command"](
        mode="positive",
        observer_fd=7,
        result_fd=8,
        duration_seconds=0.25,
        nonce=_NONCE,
        tree_root=tree_root,
        output_parent=output_parent,
    )

    assert command == [
        sys.executable,
        "-I",
        "-S",
        "-B",
        os.fspath(script_path.parent / "run_enron_capacity.py"),
        "resource-observer-soak",
        "--worker",
        "positive",
        "7",
        "8",
        "0.25",
        _NONCE,
        os.fspath(tree_root),
        os.fspath(output_parent),
    ]


def test_soak_worker_dispatch_and_result_protocol_reject_malformed_inputs(tmp_path: Path) -> None:
    script = runpy.run_path(
        os.fspath(Path(__file__).parents[2] / "scripts" / "soak_enron_resource_observer.py"),
    )
    worker_endpoint, launcher_endpoint = socket.socketpair()
    result_read, result_write = os.pipe()
    try:
        invalid_arguments = [
            "unknown-role",
            str(worker_endpoint.fileno()),
            str(result_write),
            "0.1",
            _NONCE,
            os.fspath(tmp_path.resolve()),
            os.fspath(tmp_path.resolve()),
        ]
        with pytest.raises(SystemExit) as raised:
            script["_worker_main"](invalid_arguments)
        assert raised.value.code == 2
    finally:
        worker_endpoint.close()
        launcher_endpoint.close()
        os.close(result_read)
        os.close(result_write)

    with pytest.raises(ValueError, match="duplicate worker result key"):
        json.loads('{"ok":true,"ok":false}', object_pairs_hook=script["_reject_duplicate_pairs"])

    bootstrap = {
        "isolated": True,
        "site_disabled": True,
        "bytecode_disabled": True,
        "site_hooks_absent": True,
        "private_fresh_pycache": True,
        "source_root_validated": True,
        "dependency_roots_validated": True,
        "source_import_guard_validated": True,
        "dependency_root_count": 1,
        "dependency_root_layouts_sha256": "sha256:" + "a" * 64,
        "bootstrap_launcher_sha256": "sha256:" + "b" * 64,
        "source_import_guard_sha256": "sha256:" + "c" * 64,
        "exact": True,
    }
    provenance = {
        "version": "25.0.0",
        "distribution_file_count": 3,
        "distribution_total_bytes": 100,
        "distribution_sha256": "sha256:" + "d" * 64,
        "distribution_root_bound": True,
        "import_origin_bound": True,
        "module_version_matches_distribution": True,
    }
    result = {
        "ok": True,
        "worker_role": "positive",
        "protocol_nonce_sha256": "sha256:" + hashlib.sha256(_NONCE.encode("ascii")).hexdigest(),
        "runtime_source_identity": {},
        "runtime_source_stable": True,
        "runtime_bootstrap_identity": bootstrap,
        "runtime_bootstrap_stable": True,
        "workload_elapsed_ns": 1,
        "workload_iterations": 1,
        "workloads": {},
        "pyarrow_provenance": provenance,
        "resource_snapshot": {},
    }
    validate = script["_validated_worker_result"]
    assert validate(result, mode="positive", nonce=_NONCE) == result

    malformed_provenance = json.loads(json.dumps(result))
    malformed_provenance["pyarrow_provenance"]["unexpected"] = True
    assert validate(malformed_provenance, mode="positive", nonce=_NONCE) is None

    malformed_bootstrap = json.loads(json.dumps(result))
    malformed_bootstrap["runtime_bootstrap_identity"].pop("source_import_guard_sha256")
    assert validate(malformed_bootstrap, mode="positive", nonce=_NONCE) is None


@pytest.mark.parametrize(
    ("require_decision_grade", "expected_exit"),
    [(False, 0), (True, 1)],
)
def test_soak_cli_can_require_decision_grade_without_changing_smoke_exit_behavior(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    require_decision_grade: bool,
    expected_exit: int,
) -> None:
    script = runpy.run_path(
        os.fspath(Path(__file__).parents[2] / "scripts" / "soak_enron_resource_observer.py"),
    )
    script_globals = script["main"].__globals__
    serialized = '{"decision_grade":false,"ok":true}'
    monkeypatch.setitem(
        script_globals,
        "_public_report",
        lambda _duration: ({"ok": True, "decision_grade": False}, serialized),
    )
    monkeypatch.setitem(script_globals, "_runtime_bootstrap_identity", lambda: {"exact": True})
    arguments = ["soak_enron_resource_observer.py", "--duration-seconds", "0.1"]
    if require_decision_grade:
        arguments.append("--require-decision-grade")
    monkeypatch.setattr(script_globals["sys"], "argv", arguments)

    assert script["main"]() == expected_exit
    assert capsys.readouterr().out.strip() == serialized


def test_soak_cli_fails_fast_before_a_required_decision_run_without_the_shared_bootstrap(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    script = runpy.run_path(
        os.fspath(Path(__file__).parents[2] / "scripts" / "soak_enron_resource_observer.py"),
    )
    globals_ = script["main"].__globals__
    monkeypatch.setitem(globals_, "_runtime_bootstrap_identity", lambda: {"exact": False})
    monkeypatch.setitem(
        globals_,
        "_public_report",
        lambda _duration: pytest.fail("a direct required-decision invocation must fail before the workload"),
    )
    monkeypatch.setattr(globals_["sys"], "argv", ["soak_enron_resource_observer.py", "--require-decision-grade"])

    assert script["main"]() == 1
    report = json.loads(capsys.readouterr().out)
    assert report == {
        "decision_grade": False,
        "error_code": "bootstrap_required",
        "ok": False,
        "policy_constants_verified": True,
        "report_type": "nerb.resource_observer_soak",
    }


@pytest.mark.parametrize(
    ("acquisition_ns", "completion_gap_ns", "hard_gate_passed", "headroom_passed"),
    [
        (250_000_000, 400_000_000, True, True),
        (250_000_001, 400_000_000, True, False),
        (250_000_000, 400_000_001, True, False),
        (500_000_000, 500_000_000, True, False),
        (500_000_001, 1, False, False),
        (1, 500_000_001, False, False),
    ],
)
def test_decision_grade_headroom_is_stricter_than_the_unchanged_hard_gate(
    acquisition_ns: int,
    completion_gap_ns: int,
    hard_gate_passed: bool,
    headroom_passed: bool,
) -> None:
    script = runpy.run_path(
        os.fspath(Path(__file__).parents[2] / "scripts" / "soak_enron_resource_observer.py"),
    )
    case = _valid_soak_gate_case(
        acquisition_ns=acquisition_ns,
        completion_gap_ns=completion_gap_ns,
    )

    assert script["_positive_case_passed"](case) is hard_gate_passed
    assert script["_decision_headroom_passed"](case) is headroom_passed


def test_soak_metrics_include_the_terminal_frame_in_all_aggregates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = runpy.run_path(
        os.fspath(Path(__file__).parents[2] / "scripts" / "soak_enron_resource_observer.py"),
    )
    measured_observer = script["_MeasuredLauncherObserver"]
    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(
        enron_capacity._LauncherResourceObserver,
        "_send",
        lambda _self, frame: sent.append(dict(frame)),
    )
    monkeypatch.setattr(
        enron_capacity._LauncherResourceObserver,
        "_send_final",
        lambda _self, frame: sent.append(dict(frame)),
    )
    worker_endpoint, launcher_endpoint = socket.socketpair()
    observer = measured_observer(
        launcher_endpoint,
        worker_pid=os.getpid(),
        nonce=_NONCE,
        options=EnronCapacityOptions(
            output_dir=tmp_path / "output" / "report.json",
            attempt_ledger_dir=tmp_path / "attempts",
        ),
    )
    try:
        observer._send(
            {
                "type": "sample",
                "valid": True,
                "event_sequence": 1,
                "acquisition_duration_ns": 10,
                "resource_observation_wall_gap_ns": 0,
                "scheduler_lateness_ns": 1,
            }
        )
        observer._send_final(
            {
                "type": "sample",
                "valid": True,
                "event_sequence": 2,
                "acquisition_duration_ns": 99,
                "resource_observation_wall_gap_ns": 88,
                "scheduler_lateness_ns": 77,
            }
        )
        metrics = observer.aggregate_metrics(1_000)
    finally:
        observer.close()
        worker_endpoint.close()

    assert len(sent) == 2
    assert metrics["valid_sample_count"] == 2
    assert metrics["acquisition_duration_ns"] == {"count": 2, "p50": 10, "p95": 99, "p99": 99, "max": 99}
    assert metrics["completion_to_completion_gap_ns"] == {
        "count": 1,
        "p50": 88,
        "p95": 88,
        "p99": 88,
        "max": 88,
    }
    assert metrics["scheduler_lateness_ns"]["max"] == 77


def test_soak_source_identity_compares_runtime_bytes_to_head_even_when_status_claims_clean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = runpy.run_path(
        os.fspath(Path(__file__).parents[2] / "scripts" / "soak_enron_resource_observer.py"),
    )
    repository_root = Path(__file__).parents[2].resolve()
    commit = "a" * 40
    tree = "b" * 40

    def fake_run(command: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[Any]:
        arguments = command[1:]
        if arguments[-2:] == ["rev-parse", "--show-toplevel"]:
            stdout: str | bytes = os.fspath(repository_root)
        elif arguments == ["rev-parse", "HEAD"]:
            stdout = commit
        elif arguments == ["rev-parse", "HEAD^{tree}"]:
            stdout = tree
        elif arguments == ["status", "--porcelain=v1", "--untracked-files=all"]:
            stdout = ""
        elif arguments[0] == "show":
            stdout = b"bytes-that-were-not-executed"
        else:
            raise AssertionError(arguments)
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr=b"")

    monkeypatch.setattr(script["subprocess"], "run", fake_run)

    identity = script["_source_identity"]()

    assert identity["worktree_clean"] is True
    assert identity["head_blobs_match"] is False
    assert identity["reader_lock_matches_head"] is False


def test_soak_source_identity_rejects_a_different_imported_capacity_module(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = runpy.run_path(
        os.fspath(Path(__file__).parents[2] / "scripts" / "soak_enron_resource_observer.py"),
    )
    monkeypatch.setattr(script["enron_capacity"], "__file__", os.fspath(tmp_path / "other.py"))

    with pytest.raises(RuntimeError, match="runtime source path mismatch"):
        script["_source_identity"]()


def test_soak_source_inventory_is_closed_and_import_order_independent() -> None:
    script = runpy.run_path(
        os.fspath(Path(__file__).parents[2] / "scripts" / "soak_enron_resource_observer.py"),
    )
    repository_root = Path(__file__).parents[2].resolve()
    expected_paths = {path.resolve(strict=True) for path in (repository_root / "src" / "nerb").rglob("*.py")}

    before_paths = script["_runtime_nerb_source_paths"](repository_root)
    before_hashes = script["_runtime_source_hashes"]()
    importlib.import_module("nerb.enron_performance")
    importlib.import_module("nerb.enron_splitting")
    after_paths = script["_runtime_nerb_source_paths"](repository_root)
    after_hashes = script["_runtime_source_hashes"]()

    assert set(before_paths.values()) == expected_paths
    assert after_paths == before_paths
    assert before_hashes["nerb_source_file_count"] == len(expected_paths)
    assert after_hashes == before_hashes


def test_soak_source_inventory_still_rejects_loaded_shadow_modules(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = runpy.run_path(
        os.fspath(Path(__file__).parents[2] / "scripts" / "soak_enron_resource_observer.py"),
    )
    repository_root = Path(__file__).parents[2].resolve()
    shadow = tmp_path / "shadow.py"
    shadow.write_text("VALUE = 1\n", encoding="utf-8")
    monkeypatch.setitem(sys.modules, "nerb.shadow_source", SimpleNamespace(__file__=os.fspath(shadow)))

    with pytest.raises(RuntimeError, match="runtime source path mismatch"):
        script["_runtime_nerb_source_paths"](repository_root)


def test_soak_source_reader_binds_the_opened_inode_to_the_observed_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = runpy.run_path(
        os.fspath(Path(__file__).parents[2] / "scripts" / "soak_enron_resource_observer.py"),
    )
    source = tmp_path / "source.py"
    substitute = tmp_path / "substitute.py"
    source.write_bytes(b"expected source\n")
    substitute.write_bytes(b"different source\n")
    source.chmod(0o600)
    substitute.chmod(0o600)
    real_open = os.open

    def substitute_open(path: str | bytes | os.PathLike[str] | os.PathLike[bytes], flags: int) -> int:
        if os.fsdecode(path) == os.fspath(source):
            return real_open(substitute, flags)
        return real_open(path, flags)

    monkeypatch.setattr(script["os"], "open", substitute_open)

    with pytest.raises(RuntimeError, match="runtime source unavailable"):
        script["_read_stable_regular_bytes"](source)


def test_soak_worker_source_binding_rejects_a_stale_native_extension() -> None:
    script = runpy.run_path(
        os.fspath(Path(__file__).parents[2] / "scripts" / "soak_enron_resource_observer.py"),
    )
    source_identity = {
        "capacity_implementation_sha256": "sha256:" + "a" * 64,
        "soak_implementation_sha256": "sha256:" + "b" * 64,
        "bootstrap_launcher_sha256": "sha256:" + "e" * 64,
        "source_import_guard_sha256": "sha256:" + "f" * 64,
        "nerb_source_file_count": 21,
        "nerb_source_inventory_sha256": "sha256:" + "1" * 64,
        "native_extension_sha256": "sha256:" + "c" * 64,
        "native_build_source_sha256": "sha256:" + "d" * 64,
        "native_extension_build_source_sha256": "sha256:" + "d" * 64,
    }
    case = {
        "worker_result": {
            "runtime_source_stable": True,
            "runtime_source_identity": dict(source_identity),
        }
    }
    assert script["_worker_source_is_bound"](case, source_identity) is True

    case["worker_result"]["runtime_source_identity"]["native_extension_sha256"] = "sha256:" + "e" * 64
    assert script["_worker_source_is_bound"](case, source_identity) is False


def test_soak_aggregate_privacy_guard_enforces_closed_schema_and_leaf_formats() -> None:
    script = runpy.run_path(
        os.fspath(Path(__file__).parents[2] / "scripts" / "soak_enron_resource_observer.py"),
    )
    assert_privacy = script["_assert_aggregate_report_privacy"]
    report, _serialized = script["_public_report"](0.01)
    assert_privacy(report)
    assert report["ok"] is True
    assert report["positive_soak"]["passed"] is True
    assert report["positive_soak"]["workload_iterations"] > 0
    assert report["positive_soak"]["workloads"]["c_held_gil_intervals"] > 0
    assert report["policy"]["source_provenance_boundary"] == "trusted_quiescent_worktree_observation"
    assert report["policy"]["decision_grade_maximum_resource_acquisition_duration_ns"] == 250_000_000
    assert report["policy"]["decision_grade_maximum_resource_observation_wall_gap_ns"] == 400_000_000
    assert report["environment"]["exact_expected_versions_verified"] is False
    assert report["bootstrap"]["launcher"]["exact"] is False
    assert report["bootstrap"]["positive_worker"]["exact"] is True
    assert report["bootstrap"]["fail_closed_worker"]["exact"] is True
    assert report["bootstrap"]["all_exact"] is False
    assert report["source_identity"]["reader_lock_matches_head"] is True
    observer = report["positive_soak"]["observer"]
    expected_headroom = bool(
        observer["acquisition_duration_ns"]["max"] <= 250_000_000
        and observer["completion_to_completion_gap_ns"]["max"] <= 400_000_000
    )
    assert report["positive_soak"]["decision_headroom_passed"] is expected_headroom

    for private_payload in (
        {"pid": 123},
        {"output_dir": "relative/private.json"},
        {"host": f"node={socket.gethostname()}"},
        {"user": f"owner={os.environ.get('USER', 'private-user')}"},
        {"worker_process": os.getpid()},
        {"match": "private@example.test"},
    ):
        tampered = json.loads(json.dumps(report))
        tampered.update(private_payload)
        with pytest.raises(RuntimeError, match="aggregate report contained"):
            assert_privacy(tampered)

    tampered = json.loads(json.dumps(report))
    tampered["platform"]["architecture"] = socket.gethostname()
    with pytest.raises(RuntimeError, match="aggregate report contained"):
        assert_privacy(tampered)

    tampered = json.loads(json.dumps(report))
    tampered["limitations"].append("private@example.test")
    with pytest.raises(RuntimeError, match="aggregate report contained"):
        assert_privacy(tampered)

    tampered = json.loads(json.dumps(report))
    tampered["policy"]["source_provenance_boundary"] = "executed_source_bytes"
    with pytest.raises(RuntimeError, match="aggregate report contained"):
        assert_privacy(tampered)

    tampered = json.loads(json.dumps(report))
    tampered["policy"]["decision_grade_maximum_resource_acquisition_duration_ns"] += 1
    with pytest.raises(RuntimeError, match="aggregate report contained"):
        assert_privacy(tampered)

    tampered = json.loads(json.dumps(report))
    tampered["positive_soak"]["decision_headroom_passed"] = not expected_headroom
    with pytest.raises(RuntimeError, match="aggregate report contained"):
        assert_privacy(tampered)


@pytest.mark.skipif(os.name != "posix", reason="worker supervision requires POSIX process groups")
def test_observer_failure_bounds_parent_wait_without_immediate_sigkill(monkeypatch: pytest.MonkeyPatch) -> None:
    class FailedObserver:
        def __init__(self) -> None:
            self.failure_event = threading.Event()
            self.failure_event.set()

        def wait_for_failure_publication(self, _timeout_ns: int) -> bool:
            return True

    monkeypatch.setattr(enron_capacity, "PRODUCTION_WORKER_CLEANUP_GRACE_NS", 50_000_000)
    process = subprocess.Popen(
        [sys.executable, "-I", "-c", "import time;time.sleep(60)"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    cooperative_calls: list[bool] = []
    started = time.monotonic()
    try:
        with pytest.raises(enron_capacity._ProductionWorkerExchangeFailure) as raised:
            enron_capacity._read_production_worker_response(
                process,
                b"{}",
                timeout_seconds=5,
                observer=cast(Any, FailedObserver()),
                cooperative_abort=lambda _deadline_ns: cooperative_calls.append(True) is None,
            )
        assert raised.value.cleanup_grace_consumed is True
        assert raised.value.cleanup_deadline_ns is not None
        assert time.monotonic_ns() >= raised.value.cleanup_deadline_ns
        assert time.monotonic() - started < 1
        assert cooperative_calls == []
        assert process.poll() is None
        assert enron_capacity._terminate_worker_process_group(process) is True
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


@pytest.mark.skipif(os.name != "posix", reason="worker supervision requires POSIX signals")
def test_worker_cooperative_cleanup_signal_precedes_group_escalation() -> None:
    class Observer:
        def __init__(self) -> None:
            self.state_condition = threading.Condition()
            self.started = True
            self.stop_acknowledged = False
            self.failure_event = threading.Event()

        def _reserve_failure(self, _code: str) -> bool:
            self.failure_event.set()
            return True

        def _finish_failure_publication(self, *, delivered: bool) -> None:
            assert delivered is False

        def wait_for_failure_publication(self, _timeout_ns: int) -> bool:
            return False

    status_read, status_write = os.pipe()
    worker = (
        "import os,signal,sys;fd=int(sys.argv[1]);"
        "signal.signal(signal.SIGUSR1,lambda *_:(os.write(fd,b'C'),sys.exit(0)));"
        "os.write(fd,b'R');signal.pause()"
    )
    process = subprocess.Popen(
        [sys.executable, "-I", "-c", worker, str(status_write)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        pass_fds=(status_write,),
        start_new_session=True,
    )
    os.close(status_write)
    observer = cast(Any, Observer())
    try:
        ready, _, _ = select.select([status_read], [], [], 5)
        assert ready and os.read(status_read, 1) == b"R"
        cleanup_deadline_ns = time.monotonic_ns() + 2_000_000_000
        assert (
            enron_capacity._request_worker_cooperative_cleanup(
                process,
                observer,
                deadline_ns=cleanup_deadline_ns,
            )
            is True
        )
        assert enron_capacity._wait_for_worker_cleanup_until(process, cleanup_deadline_ns) is True
        assert os.read(status_read, 1) == b"C"
        assert process.returncode == 0
        assert enron_capacity._terminate_worker_process_group(process) is False
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        os.close(status_read)


def test_expired_cleanup_deadline_skips_publication_signal_and_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    class LiveProcess:
        pid = 123

        def poll(self) -> None:
            return None

    class Observer:
        def __init__(self) -> None:
            self.state_condition = threading.Condition()
            self.started = True
            self.stop_acknowledged = False
            self.failure_event = threading.Event()
            self.failure_event.set()
            self.publication_waits: list[int] = []

        def wait_for_failure_publication(self, timeout_ns: int) -> bool:
            self.publication_waits.append(timeout_ns)
            return False

    observer = Observer()
    signals: list[tuple[int, int]] = []
    monkeypatch.setattr(enron_capacity.time, "monotonic_ns", lambda: 100)
    monkeypatch.setattr(enron_capacity.os, "kill", lambda pid, signum: signals.append((pid, signum)))

    assert (
        enron_capacity._request_worker_cooperative_cleanup(
            cast(Any, LiveProcess()),
            cast(Any, observer),
            deadline_ns=100,
        )
        is False
    )
    assert observer.publication_waits == []
    assert signals == []


def test_cleanup_wait_consumes_an_absolute_deadline_without_restarting_it(monkeypatch: pytest.MonkeyPatch) -> None:
    class LiveProcess:
        def poll(self) -> None:
            return None

    sleeps: list[float] = []
    monkeypatch.setattr(enron_capacity.time, "monotonic_ns", lambda: 151)
    monkeypatch.setattr(enron_capacity.time, "sleep", lambda seconds: sleeps.append(seconds))

    assert enron_capacity._wait_for_worker_cleanup_until(cast(Any, LiveProcess()), 150) is False
    assert sleeps == []


@pytest.mark.skipif(os.name != "posix", reason="worker supervision requires POSIX process groups")
def test_bounded_worker_exchange_round_trips_and_leaves_no_process_group() -> None:
    process = subprocess.Popen(
        [sys.executable, "-I", "-c", "import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    request = b'{"bounded":true}'
    try:
        assert enron_capacity._read_production_worker_response(process, request, timeout_seconds=5) == request
        assert process.returncode == 0
        assert enron_capacity._terminate_worker_process_group(process) is False
    finally:
        if process.poll() is None:
            os.killpg(process.pid, 9)
            process.wait(timeout=5)


@pytest.mark.skipif(os.name != "posix", reason="worker supervision requires POSIX process groups")
def test_bounded_worker_exchange_kills_output_overflow_without_buffering_it() -> None:
    process = subprocess.Popen(
        [
            sys.executable,
            "-I",
            "-c",
            (
                "import os;"
                f"remaining={enron_capacity.MAX_PRODUCTION_WORKER_RESPONSE_BYTES + 1};"
                "chunk=b'x'*65536;"
                "\nwhile remaining:"
                "\n payload=chunk[:remaining];os.write(1,payload);remaining-=len(payload)"
            ),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        with pytest.raises(EnronCapacityError) as raised:
            enron_capacity._read_production_worker_response(process, b"{}", timeout_seconds=5)
        assert raised.value.code == "production_worker_failed"
        enron_capacity._terminate_worker_process_group(process)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, 9)
            process.wait(timeout=5)


@pytest.mark.skipif(os.name != "posix", reason="worker supervision requires POSIX process groups")
def test_bounded_worker_exchange_rejects_a_descendant_holding_stdout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(enron_capacity, "RESOURCE_OBSERVER_COMMAND_TIMEOUT_NS", 50_000_000)
    process = subprocess.Popen(
        [
            sys.executable,
            "-I",
            "-c",
            (
                "import subprocess,sys;"
                "subprocess.Popen([sys.executable,'-I','-c','import time;time.sleep(60)']);"
                "sys.stdout.write('{}');sys.stdout.flush()"
            ),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        with pytest.raises(EnronCapacityError) as raised:
            enron_capacity._read_production_worker_response(process, b"{}", timeout_seconds=5)
        assert raised.value.code == "production_worker_failed"
        assert enron_capacity._terminate_worker_process_group(process) is True
    finally:
        if process.poll() is None:
            os.killpg(process.pid, 9)
            process.wait(timeout=5)

from __future__ import annotations

import json
import os
import select
import signal
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Generator
from dataclasses import dataclass
from pathlib import Path
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
    monitor.start()
    os.write(status_fd, b"R")
    usleep = ctypes.PyDLL(None).usleep
    usleep.argtypes = (ctypes.c_uint,)
    usleep.restype = ctypes.c_int
    hold_started_ns = time.monotonic_ns()
    if usleep(850_000) != 0:
        raise RuntimeError("usleep failed")
    hold_finished_ns = time.monotonic_ns()
    os.write(status_fd, b"D")
    monitor.stop()
    monitor.raise_if_failed()
    result = {
        "hold_started_ns": hold_started_ns,
        "hold_finished_ns": hold_finished_ns,
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


def _accept_startup(harness: _RemoteHarness, *, completed_ns: int = 1_000_000_001) -> int:
    harness.remote._accept_sample(
        _sample(sequence=1, completed_ns=completed_ns, gap_ns=0, kind="startup"),
    )
    return completed_ns


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
        assert reader.receive(1_000_000_000) == []
        sender.close()
        with pytest.raises(EnronCapacityError) as raised:
            reader.receive(1_000_000_000)
        assert raised.value.code == "resource_measurement_failed"
    finally:
        sender.close()
        receiver.close()


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
    remote_harness.remote._accept_sample(
        _sample(
            sequence=2,
            completed_ns=second_completed,
            gap_ns=acquisition_ns,
            acquisition_ns=acquisition_ns,
            failure_code=failure_code,
        ),
    )

    assert remote_harness.remote.last_valid_completed_ns == second_completed
    assert remote_harness.monitor._global_observations == 2
    assert remote_harness.monitor._global_maximum_resource_acquisition_duration_ns == acquisition_ns
    assert remote_harness.monitor._failure_code == failure_code


@pytest.mark.parametrize(
    ("rss", "minimum_free", "expected"),
    [
        (6 * _GIB + 1, enron_capacity.MIN_RUNTIME_FREE_DISK_BYTES - 1, "rss_limit"),
        (64 * _MIB, enron_capacity.MIN_RUNTIME_FREE_DISK_BYTES - 1, "runtime_disk_floor"),
        (64 * _MIB, 30 * _GIB, "resource_acquisition_timeout"),
    ],
)
def test_remote_resource_failure_precedence_is_explicit(
    remote_harness: _RemoteHarness,
    rss: int,
    minimum_free: int,
    expected: str,
) -> None:
    first_completed = _accept_startup(remote_harness)
    acquisition_ns = enron_capacity.MAX_RESOURCE_ACQUISITION_DURATION_NS + 1
    remote_harness.remote._accept_sample(
        _sample(
            sequence=2,
            completed_ns=first_completed + acquisition_ns,
            gap_ns=acquisition_ns,
            acquisition_ns=acquisition_ns,
            failure_code=expected,
            process_tree_rss_bytes=rss,
            minimum_free_disk_bytes=minimum_free,
        ),
    )

    assert remote_harness.monitor._failure_code == expected


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
        remote_harness.launcher_endpoint.sendall(enron_capacity._canonical_json_bytes(terminal) + b"\n")
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
    monkeypatch.setattr(enron_capacity, "_worker_descendant_pids", lambda _pid: descendants)
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


def test_launcher_terminal_sample_fails_closed_and_kills_reported_descendants(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observer, frames, killed = _run_synthetic_launcher_protocol(
        monkeypatch,
        tmp_path,
        descendants=(901, 902),
    )

    terminal = [frame for frame in frames if frame.get("sample_kind") == "terminal"]
    assert len(terminal) == 1
    assert terminal[0]["valid"] is True
    assert terminal[0]["failure_code"] == "worker_process_leak"
    assert killed == [902, 901]
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
def test_launcher_sampler_progresses_while_worker_gil_is_held(
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
        assert read_status_marker(3) == b"D"
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
        snapshot = cast(dict[str, int], result["snapshot"])
        samples_during_hold = [
            sample
            for sample in captured_samples
            if sample.get("sample_kind") == "continuous"
            and hold_started_ns <= int(sample["completed_wall_ns"]) <= hold_finished_ns
        ]

        assert hold_finished_ns - hold_started_ns >= 800_000_000
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
        ("100 1\n101 100\n102 101\n200 1\n", (101, 102)),
        ("101 100\n", None),
        ("100 1\n101 malformed\n", None),
    ],
)
def test_descendant_helper_is_transitive_and_fails_closed_on_incomplete_process_tables(
    stdout: str,
    expected: tuple[int, ...] | None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr="")
    monkeypatch.setattr(enron_capacity.sys, "platform", "darwin")
    monkeypatch.setattr(enron_capacity.subprocess, "run", lambda *_args, **_kwargs: completed)

    assert enron_capacity._worker_descendant_pids(100) == expected


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

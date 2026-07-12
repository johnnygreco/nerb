from __future__ import annotations

import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any, cast

import pytest

import nerb.enron_performance as performance_module
from nerb.enron_performance import EnronPerformanceError

_WORKLOAD_SHA256 = "sha256:" + "a" * 64
_REQUEST = {"nonce": "safe-nonce", "workload_sha256": _WORKLOAD_SHA256}


def _result_child(*, pid_offset: int = 0) -> str:
    return f"""
import json
import os
import sys

request = json.load(sys.stdin)
result = {{
    "schema_version": "{performance_module.RESULT_SCHEMA_VERSION}",
    "nonce": request["nonce"],
    "workload_sha256": request["workload_sha256"],
    "pid": os.getpid() + {pid_offset},
    "status": "ok",
    "error_code": None,
    "elapsed_ns": 1,
    "peak_rss_bytes": None,
    "peak_rss_status": "unsupported_platform",
    "record_count": 0,
    "correctness_sha256": "{_WORKLOAD_SHA256}",
}}
sys.stderr.write("discarded-private-diagnostic")
json.dump(result, sys.stdout)
sys.stdout.flush()
"""


def _session_result_child(*, pid_offset: int = 0) -> str:
    return f"""
import json
import os
import sys

for line in sys.stdin:
    request = json.loads(line)
    result = {{
        "schema_version": "{performance_module.RESULT_SCHEMA_VERSION}",
        "nonce": request["nonce"],
        "workload_sha256": request["workload_sha256"],
        "pid": os.getpid() + {pid_offset},
        "status": "ok",
        "error_code": None,
        "elapsed_ns": 1,
        "peak_rss_bytes": None,
        "peak_rss_status": "unsupported_platform",
        "record_count": 0,
        "correctness_sha256": "{_WORKLOAD_SHA256}",
    }}
    print(json.dumps(result), flush=True)
"""


def _replace_child(
    monkeypatch: pytest.MonkeyPatch,
    source: str,
) -> tuple[list[subprocess.Popen[bytes]], list[Mapping[str, Any]]]:
    real_popen = subprocess.Popen
    children: list[subprocess.Popen[bytes]] = []
    invocations: list[Mapping[str, Any]] = []

    def launch(_command: Sequence[str], **kwargs: Any) -> subprocess.Popen[bytes]:
        invocations.append(dict(kwargs))
        child = cast(Any, real_popen([sys.executable, "-c", source], **kwargs))
        children.append(child)
        return child

    monkeypatch.setattr(performance_module.subprocess, "Popen", launch)
    return children, invocations


@pytest.mark.parametrize(
    "runner",
    [performance_module._run_worker_once, performance_module._run_source_build_once],
)
def test_fresh_worker_uses_bounded_pipes_and_binds_the_child_pid(
    monkeypatch: pytest.MonkeyPatch,
    runner: Callable[..., dict[str, Any]],
) -> None:
    children, invocations = _replace_child(monkeypatch, _result_child())

    result = runner(_REQUEST, timeout_seconds=5)

    assert result["pid"] == children[0].pid
    assert children[0].returncode == 0
    assert invocations == [
        {
            "stdin": subprocess.PIPE,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.DEVNULL,
        }
    ]


@pytest.mark.parametrize(
    "runner",
    [performance_module._run_worker_once, performance_module._run_source_build_once],
)
def test_fresh_worker_rejects_a_result_from_a_different_pid(
    monkeypatch: pytest.MonkeyPatch,
    runner: Callable[..., dict[str, Any]],
) -> None:
    children, _invocations = _replace_child(monkeypatch, _result_child(pid_offset=1))

    with pytest.raises(EnronPerformanceError, match="process identity protocol"):
        runner(_REQUEST, timeout_seconds=5)

    assert children[0].returncode == 0


def test_fresh_worker_kills_and_reaps_on_the_first_byte_past_the_output_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = f"""
import os
import sys
import time

sys.stdin.buffer.read()
os.write(sys.stdout.fileno(), b"x" * ({performance_module.MAX_WORKER_OUTPUT_BYTES} + 1))
time.sleep(30)
"""
    children, _invocations = _replace_child(monkeypatch, source)
    started = time.monotonic()

    with pytest.raises(EnronPerformanceError, match="output exceeded its fixed bound"):
        performance_module._run_worker_once(_REQUEST, timeout_seconds=10)

    assert time.monotonic() - started < 3
    assert children[0].returncode is not None


def test_fresh_worker_timeout_kills_and_reaps_a_silent_child(monkeypatch: pytest.MonkeyPatch) -> None:
    children, _invocations = _replace_child(monkeypatch, "import time; time.sleep(30)")

    with pytest.raises(EnronPerformanceError, match="did not complete within its fixed boundary"):
        performance_module._run_worker_once(_REQUEST, timeout_seconds=0.1)

    assert children[0].returncode is not None


def test_fresh_worker_rejects_an_oversized_request_before_process_creation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_value = "not-for-an-error-message"

    def forbidden_popen(*_args: Any, **_kwargs: Any) -> subprocess.Popen[bytes]:
        raise AssertionError("process creation must not occur")

    monkeypatch.setattr(performance_module.subprocess, "Popen", forbidden_popen)
    request = {
        **_REQUEST,
        "padding": private_value * performance_module.DEFAULT_MAX_REQUEST_BYTES,
    }

    with pytest.raises(EnronPerformanceError) as captured:
        performance_module._run_worker_once(request, timeout_seconds=5)

    assert str(captured.value) == "Performance worker request exceeded its fixed bound."
    assert private_value not in str(captured.value)


def test_reusable_worker_uses_bounded_protocol_and_binds_child_pid(monkeypatch: pytest.MonkeyPatch) -> None:
    children, _invocations = _replace_child(monkeypatch, _session_result_child())

    with performance_module._WorkerSession(timeout_seconds=5) as session:
        result = session.request(_REQUEST)

    assert result["pid"] == children[0].pid
    assert children[0].returncode == 0


def test_reusable_worker_rejects_pid_mismatch_and_reaps(monkeypatch: pytest.MonkeyPatch) -> None:
    children, _invocations = _replace_child(monkeypatch, _session_result_child(pid_offset=1))
    session = performance_module._WorkerSession(timeout_seconds=5)

    with pytest.raises(EnronPerformanceError, match="process identity protocol"):
        session.request(_REQUEST)

    assert children[0].returncode is not None


def test_reusable_worker_partial_line_timeout_is_bounded_and_reaped(monkeypatch: pytest.MonkeyPatch) -> None:
    source = """
import os
import sys
import time

sys.stdin.buffer.readline()
os.write(sys.stdout.fileno(), b"{")
time.sleep(30)
"""
    children, _invocations = _replace_child(monkeypatch, source)
    session = performance_module._WorkerSession(timeout_seconds=0.1)
    started = time.monotonic()

    with pytest.raises(EnronPerformanceError, match="timed out"):
        session.request(_REQUEST)

    assert time.monotonic() - started < 3
    assert children[0].returncode is not None


def test_reusable_worker_output_overflow_and_oversized_request_reap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    overflow_source = f"""
import os
import sys
import time

sys.stdin.buffer.readline()
os.write(sys.stdout.fileno(), b"x" * ({performance_module.MAX_WORKER_OUTPUT_BYTES} + 1))
time.sleep(30)
"""
    children, _invocations = _replace_child(monkeypatch, overflow_source)
    session = performance_module._WorkerSession(timeout_seconds=5)
    with pytest.raises(EnronPerformanceError, match="output exceeded"):
        session.request(_REQUEST)
    assert children[0].returncode is not None

    monkeypatch.undo()
    children, _invocations = _replace_child(monkeypatch, "import time; time.sleep(30)")
    session = performance_module._WorkerSession(timeout_seconds=5)
    oversized = {**_REQUEST, "padding": "x" * performance_module.DEFAULT_MAX_REQUEST_BYTES}
    with pytest.raises(EnronPerformanceError, match="request exceeded"):
        session.request(oversized)
    assert children[0].returncode is not None

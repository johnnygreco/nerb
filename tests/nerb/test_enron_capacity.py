from __future__ import annotations

import copy
import errno
import gc
import hashlib
import importlib.util
import inspect
import json
import os
import py_compile
import re
import shutil
import signal
import stat
import subprocess
import sys
import textwrap
import threading
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest

from nerb import enron_capacity
from nerb.enron_capacity import (
    CAPACITY_PHASES,
    ENRON_DATASET_ID,
    ENRON_DATASET_REVISION,
    ENRON_SOURCE_ROWS,
    CapacityDiskUsage,
    EnronCapacityError,
    EnronCapacityOptions,
    EnronCapacityPhaseContext,
    EnronCapacityPhaseResult,
    export_capacity_decision,
    hash_capacity_report,
    run_enron_capacity,
    verify_capacity_attempt_ledger,
    verify_capacity_report,
    verify_capacity_run,
    verify_portable_capacity_decision,
)

_GIB = 1024**3
_MIB = 1024**2
_PREPARED_RECORDS = 500_000
_PREPARED_SOURCE_ROWS = 510_000
_REJECTED_SOURCE_ROWS = 7_401
_TRAIN_RECORDS = 400_000
_VALIDATION_RECORDS = 50_000
_TEST_RECORDS = 50_000
_PREPARED_BYTES = 16 * _MIB
_REJECTION_BYTES = _MIB
_TRAIN_BYTES = 12 * _MIB
_VALIDATION_BYTES = 2 * _MIB
_TEST_BYTES = 2 * _MIB
_VALIDATION_TEXT_BYTES = 1_500_000
_ALLOWED_ZERO_PAYLOAD_TOMBSTONE_FILES = {
    "records.sqlite3",
    "split.sqlite3",
    "mining-snapshot.sqlite3",
    "mining-rebuild.sqlite3",
}


class _Probe:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.physical: int | None = 16 * _GIB
        self.rss: int | None = 64 * _MIB
        self.total = 100 * _GIB
        self.used = 10 * _GIB
        self.free = 30 * _GIB
        self.now_ns = 1
        self.disk_paths: set[Path] = set()
        self.free_by_path: dict[Path, int] = {}
        self.device_by_path: dict[Path, int] = {}

    def physical_memory_bytes(self) -> int | None:
        with self._lock:
            return self.physical

    def process_tree_rss_bytes(self, root_pid: int) -> int | None:
        assert root_pid == os.getpid()
        with self._lock:
            return self.rss

    def disk_usage(self, path: Path) -> CapacityDiskUsage | None:
        assert path.is_absolute()
        with self._lock:
            self.disk_paths.add(path)
            free = self.free_by_path.get(path, self.free)
            return CapacityDiskUsage(total=self.total, used=self.total - free, free=free)

    def filesystem_device(self, path: Path) -> int | None:
        assert path.is_absolute()
        with self._lock:
            return self.device_by_path.get(path, path.stat().st_dev)

    def monotonic_ns(self) -> int:
        with self._lock:
            return self.now_ns

    def advance_ns(self, nanoseconds: int) -> None:
        with self._lock:
            self.now_ns += nanoseconds

    def set_rss(self, value: int) -> None:
        with self._lock:
            self.rss = value

    def set_free(self, value: int) -> None:
        with self._lock:
            self.free = value

    def set_path_free(self, path: Path, value: int) -> None:
        with self._lock:
            self.free_by_path[path] = value

    def set_path_device(self, path: Path, value: int) -> None:
        with self._lock:
            self.device_by_path[path] = value


def _hash(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def _canonical_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return "sha256:" + hashlib.sha256(payload).hexdigest()


_FIXTURE_READER_ENV_SHA256 = _canonical_hash(enron_capacity._reader_environment_identity())


def _commitments() -> dict[str, dict[str, Any]]:
    common: dict[str, Any] = {
        "dataset_id": ENRON_DATASET_ID,
        "dataset_revision": ENRON_DATASET_REVISION,
        "dataset_split": "train",
        "source_input_rows": ENRON_SOURCE_ROWS,
        "source_reader": "fixture.reader",
        "source_reader_package_version": None,
        "source_reader_environment_sha256": _FIXTURE_READER_ENV_SHA256,
        "source_reader_isolation_mode": "local_fixture_no_remote_reader",
        "source_reader_isolation_sha256": enron_capacity._local_reader_isolation()["sha256"],
        "source_reader_effective_path_count": 0,
        "source_reader_cache_roots_phase_owned": True,
        "source_reader_official_endpoint": False,
        "source_reader_endpoint_sha256": _hash("local-reader-no-remote-endpoint"),
        "source_reader_ambient_credentials_disabled": True,
        "source_reader_explicit_cache_dir": False,
        "source_reader_explicit_anonymous_load": False,
        "source_reader_token_files_absent": True,
        "source_reader_restrictive_umask": False,
        "source_reader_cache_symlinks_disabled": True,
        "source_row_multiset_sha256": _hash("source-row-multiset"),
        "source_conservation_sha256": "",
        "sealed_test_accessed": False,
    }
    preparation_values = {
        **common,
        "preparation_manifest_sha256": _hash("preparation-manifest"),
        "prepared_artifact_sha256": _hash("prepared-artifact"),
        "prepared_artifact_bytes": _PREPARED_BYTES,
        "prepared_records": _PREPARED_RECORDS,
        "prepared_source_rows": _PREPARED_SOURCE_ROWS,
        "rejection_artifact_sha256": _hash("rejection-artifact"),
        "rejection_artifact_bytes": _REJECTION_BYTES,
        "rejected_source_rows": _REJECTED_SOURCE_ROWS,
    }
    preparation_values["source_conservation_sha256"] = enron_capacity._source_conservation_sha256(preparation_values)
    preparation = enron_capacity._finalize_phase_commitment("preparation", preparation_values)
    split_values = {
        **enron_capacity._commitment_without_privacy_scan(preparation),
        "full_split_manifest_sha256": _hash("full-split-manifest"),
        "development_manifest_sha256": _hash("development-manifest"),
        "split_policy_sha256": _hash("split-policy"),
        "train_artifact_sha256": _hash("train-artifact"),
        "train_artifact_bytes": _TRAIN_BYTES,
        "train_records": _TRAIN_RECORDS,
        "validation_artifact_sha256": _hash("validation-artifact"),
        "validation_artifact_bytes": _VALIDATION_BYTES,
        "validation_records": _VALIDATION_RECORDS,
        "test_artifact_sha256": _hash("test-artifact"),
        "test_artifact_bytes": _TEST_BYTES,
        "test_records": _TEST_RECORDS,
        "preseal_verification_sha256": _hash("preseal-verification"),
        "preseal_access_count": 0,
        "sealed_state": "sealed_unbound",
        "sealed_access_state_sha256": "",
    }
    split_values["sealed_access_state_sha256"] = enron_capacity._sealed_access_state_sha256(split_values)
    split = enron_capacity._finalize_phase_commitment("split", split_values)
    build_values = {
        **enron_capacity._commitment_without_privacy_scan(split),
        "bank_sha256": _hash("bank"),
        "bank_artifact_sha256": _hash("bank-artifact"),
        "bank_canonical_json_bytes": _MIB,
        "bank_card_run_sha256": _hash("bank-card-run"),
        "candidate_count": 25_000,
        "candidate_source_sha256": _hash("candidate-source"),
        "candidate_ledger_sha256": _hash("candidate-ledger"),
        "active_entity_count": 4,
        "active_name_count": 25_000,
        "active_pattern_count": 25_000,
        "validation_run_sha256": _hash("validation-run"),
        "evaluator_sha256": _hash("evaluator"),
        "builder_policy_sha256": _hash("builder-policy"),
    }
    build = enron_capacity._finalize_phase_commitment("build", build_values)
    streaming = enron_capacity._finalize_phase_commitment(
        "streaming_validation",
        {
            **enron_capacity._commitment_without_privacy_scan(build),
            "validation_text_utf8_bytes": _VALIDATION_TEXT_BYTES,
        },
    )
    replay_values = {
        **enron_capacity._commitment_without_privacy_scan(streaming),
        "replay_bank_sha256": build["bank_sha256"],
        "replay_validation_run_sha256": streaming["validation_run_sha256"],
        "replay_equal": True,
    }
    replay = enron_capacity._finalize_phase_commitment("deep_replay", replay_values)
    results = {
        "preparation": preparation,
        "split": split,
        "build": build,
        "streaming_validation": streaming,
        "deep_replay": replay,
    }
    return results


def _phase_records(phase: str) -> int:
    return {
        "preparation": ENRON_SOURCE_ROWS,
        "split": _PREPARED_RECORDS,
        "build": _TRAIN_RECORDS,
        "streaming_validation": _VALIDATION_RECORDS,
        "deep_replay": _TRAIN_RECORDS + _VALIDATION_RECORDS,
    }[phase]


def _phase_processed_bytes(phase: str) -> int:
    return {
        "preparation": _PREPARED_BYTES + _REJECTION_BYTES,
        "split": _TRAIN_BYTES + _VALIDATION_BYTES + _TEST_BYTES,
        "build": _TRAIN_BYTES,
        "streaming_validation": _VALIDATION_TEXT_BYTES,
        "deep_replay": _TRAIN_BYTES + _VALIDATION_BYTES,
    }[phase]


def _result(phase: str, *, commitments: Mapping[str, Any] | None = None) -> EnronCapacityPhaseResult:
    return EnronCapacityPhaseResult(
        records=_phase_records(phase),
        processed_bytes=_phase_processed_bytes(phase),
        commitments=dict(_commitments()[phase] if commitments is None else commitments),
    )


def _checkpoint_all(context: EnronCapacityPhaseContext, probe: _Probe, records: int, *, slow: bool = False) -> None:
    completed = 0
    while completed < records:
        next_completed = min(records, completed + enron_capacity.MAX_CHECKPOINT_RECORD_GAP)
        increment = next_completed - completed
        denominator = 99 if slow else 1_000
        probe.advance_ns(max(1, increment * 1_000_000_000 // denominator))
        completed = next_completed
        context.checkpoint(completed)


def _successful_runners(
    probe: _Probe,
    replacements: Mapping[str, Callable[[EnronCapacityPhaseContext], EnronCapacityPhaseResult]] | None = None,
) -> dict[str, Callable[[EnronCapacityPhaseContext], EnronCapacityPhaseResult]]:
    runners: dict[str, Callable[[EnronCapacityPhaseContext], EnronCapacityPhaseResult]] = {}
    for phase in CAPACITY_PHASES:

        def runner(context: EnronCapacityPhaseContext, *, phase: str = phase) -> EnronCapacityPhaseResult:
            assert context.phase == phase
            assert context.work_dir.is_dir()
            _checkpoint_all(context, probe, _phase_records(phase))
            return _result(phase)

        runners[phase] = runner
    runners.update(replacements or {})
    return runners


def _options(tmp_path: Path, name: str = "capacity-run", *, ledger: str = "attempts") -> EnronCapacityOptions:
    return EnronCapacityOptions(
        output_dir=tmp_path / name,
        attempt_ledger_dir=tmp_path / ledger,
        allow_unignored_output=True,
    )


def _run(
    tmp_path: Path,
    probe: _Probe | None = None,
    *,
    name: str = "capacity-run",
    ledger: str = "attempts",
    replacements: Mapping[str, Callable[[EnronCapacityPhaseContext], EnronCapacityPhaseResult]] | None = None,
    monitor_interval_ns: int = enron_capacity.PRODUCTION_MONITOR_INTERVAL_NS,
    wall_clock: Callable[[], int] | None = None,
) -> tuple[dict[str, Any], _Probe]:
    actual_probe = _Probe() if probe is None else probe
    report = enron_capacity._run_enron_capacity_for_test(
        _options(tmp_path, name, ledger=ledger),
        phase_runners=_successful_runners(actual_probe, replacements),
        resource_probe=actual_probe,
        monitor_interval_ns=monitor_interval_ns,
        wall_clock=wall_clock,
    )
    return report, actual_probe


def _assert_no_stage(tmp_path: Path, name: str) -> None:
    assert not list(tmp_path.glob(f".{name}.stage-*"))


def _assert_attempt_ledger_files(ledger: Path) -> None:
    for path in ledger.iterdir():
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode)
        assert not stat.S_ISLNK(info.st_mode)
        assert info.st_uid == os.geteuid()
        assert info.st_nlink == 1
        assert stat.S_IMODE(info.st_mode) == 0o600
        if enron_capacity._PRIVATE_TOMBSTONE_RE.fullmatch(path.name):
            assert info.st_size == 0
        else:
            assert enron_capacity._ATTEMPT_NAME_RE.fullmatch(path.name)


def _process_descriptor_inventory() -> dict[int, tuple[int, int, int]]:
    for inventory_path in (Path(f"/proc/{os.getpid()}/fd"), Path("/dev/fd")):
        try:
            names = os.listdir(inventory_path)
        except OSError:
            continue
        inventory: dict[int, tuple[int, int, int]] = {}
        for name in names:
            try:
                descriptor = int(name)
                info = os.fstat(descriptor)
            except (OSError, ValueError):
                continue
            inventory[descriptor] = (int(info.st_dev), int(info.st_ino), stat.S_IFMT(info.st_mode))
        return inventory
    raise AssertionError("The capacity cleanup regression requires a process descriptor inventory.")


def _start_crashing_capacity_attempt(
    tmp_path: Path, *, name: str = "crash-run"
) -> tuple[subprocess.Popen[bytes], Path]:
    output = tmp_path / name
    ledger = tmp_path / "attempts"
    ready = tmp_path / f"{name}.ready"
    worker = tmp_path / f"{name}-worker.py"
    worker.write_text(
        textwrap.dedent(
            """
            import os
            import sys
            import time
            from pathlib import Path

            from nerb import enron_capacity as capacity
            from nerb.enron_capacity import CapacityDiskUsage, EnronCapacityOptions

            class Probe:
                def physical_memory_bytes(self):
                    return 16 * 1024**3

                def process_tree_rss_bytes(self, root_pid):
                    return 64 * 1024**2

                def disk_usage(self, path):
                    return CapacityDiskUsage(total=100 * 1024**3, used=10 * 1024**3, free=90 * 1024**3)

                def filesystem_device(self, path):
                    return path.stat().st_dev

                def monotonic_ns(self):
                    return time.monotonic_ns()

            ready = Path(sys.argv[3])

            def hang(_context):
                ready.write_text("ready", encoding="utf-8")
                ready.chmod(0o600)
                while True:
                    time.sleep(1)

            runners = {phase: hang for phase in capacity.CAPACITY_PHASES}
            capacity._run_enron_capacity_for_test(
                EnronCapacityOptions(
                    output_dir=Path(sys.argv[1]),
                    attempt_ledger_dir=Path(sys.argv[2]),
                    allow_unignored_output=True,
                ),
                phase_runners=runners,
                resource_probe=Probe(),
            )
            """
        ),
        encoding="utf-8",
    )
    process = subprocess.Popen(
        [sys.executable, str(worker), str(output), str(ledger), str(ready)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not ready.exists() and process.poll() is None:
        time.sleep(0.02)
    assert process.poll() is None
    assert ready.read_text(encoding="utf-8") == "ready"
    return process, ready


def _start_terminal_crash_attempt(
    tmp_path: Path,
    *,
    crash_point: str,
) -> tuple[subprocess.Popen[bytes], EnronCapacityOptions, Path]:
    name = f"terminal-{crash_point}"
    options = _options(tmp_path, name)
    ready = tmp_path / f"{name}.ready"
    worker = tmp_path / f"{name}-worker.py"
    fixture = tmp_path / f"{name}-fixture.json"
    fixture.write_text(
        json.dumps(
            {
                "commitments": _commitments(),
                "records": {phase: _phase_records(phase) for phase in CAPACITY_PHASES},
                "processed_bytes": {phase: _phase_processed_bytes(phase) for phase in CAPACITY_PHASES},
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    worker.write_text(
        textwrap.dedent(
            """
            import json
            import os
            import signal
            import sys
            import time
            from pathlib import Path

            from nerb import enron_capacity as capacity
            from nerb.enron_capacity import (
                CapacityDiskUsage,
                EnronCapacityOptions,
                EnronCapacityPhaseResult,
            )

            class Probe:
                def physical_memory_bytes(self):
                    return 16 * 1024**3

                def process_tree_rss_bytes(self, root_pid):
                    return 64 * 1024**2

                def disk_usage(self, path):
                    return CapacityDiskUsage(total=100 * 1024**3, used=10 * 1024**3, free=90 * 1024**3)

                def filesystem_device(self, path):
                    return path.stat().st_dev

                def monotonic_ns(self):
                    return time.monotonic_ns()

            fixture = json.loads(Path(sys.argv[4]).read_text(encoding="utf-8"))
            ready = Path(sys.argv[5])
            crash_point = sys.argv[6]

            def announce_and_kill():
                ready.write_text("ready", encoding="utf-8")
                ready.chmod(0o600)
                os.kill(os.getpid(), signal.SIGKILL)

            if crash_point in {"post_promotion", "post_promotion_payload"}:
                original = capacity._post_promotion_enforce
                def crash_after_promotion(*args, **kwargs):
                    original(*args, **kwargs)
                    announce_and_kill()
                capacity._post_promotion_enforce = crash_after_promotion
            elif crash_point == "pre_binding":
                def crash_before_binding(*args, **kwargs):
                    announce_and_kill()
                capacity._bind_inflight_stage = crash_before_binding
            elif crash_point == "after_receipt":
                original = capacity._remove_inflight_files_locked
                def crash_after_receipt(*args, **kwargs):
                    announce_and_kill()
                capacity._remove_inflight_files_locked = crash_after_receipt
            else:
                raise RuntimeError("invalid crash point")

            def run_phase(context):
                records = fixture["records"][context.phase]
                completed = 0
                while completed < records:
                    completed = min(records, completed + capacity.MAX_CHECKPOINT_RECORD_GAP)
                    context.checkpoint(completed)
                if crash_point == "post_promotion_payload" and context.phase == "preparation":
                    payload = context.work_dir / "crash-secret.bin"
                    payload.write_bytes(b"private crash recovery payload")
                    payload.chmod(0o600)
                return EnronCapacityPhaseResult(
                    records=records,
                    processed_bytes=fixture["processed_bytes"][context.phase],
                    commitments=fixture["commitments"][context.phase],
                )

            capacity._run_enron_capacity_for_test(
                EnronCapacityOptions(
                    output_dir=Path(sys.argv[1]),
                    attempt_ledger_dir=Path(sys.argv[2]),
                    allow_unignored_output=True,
                ),
                phase_runners={phase: run_phase for phase in capacity.CAPACITY_PHASES},
                resource_probe=Probe(),
            )
            """
        ),
        encoding="utf-8",
    )
    process = subprocess.Popen(
        [
            sys.executable,
            str(worker),
            str(options.output_dir),
            str(options.attempt_ledger_dir),
            str(tmp_path),
            str(fixture),
            str(ready),
            crash_point,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline and not ready.exists() and process.poll() is None:
        time.sleep(0.02)
    assert ready.read_text(encoding="utf-8") == "ready"
    assert process.wait(timeout=5) == -signal.SIGKILL
    return process, options, ready


def _rehash_report(report: dict[str, Any]) -> None:
    report["run_sha256"] = hash_capacity_report(report)


def test_public_entry_is_noninjectable_and_fixture_cannot_verify_as_production(tmp_path: Path) -> None:
    assert list(inspect.signature(run_enron_capacity).parameters) == ["options"]
    report, _probe = _run(tmp_path)

    assert report["execution"]["production_evidence"] is False
    assert report["execution"]["git_tree_clean"] is False
    with pytest.raises(EnronCapacityError):
        verify_capacity_report(report)
    assert verify_capacity_report(report, require_production=False) == report
    decision = verify_capacity_run(
        tmp_path / "capacity-run",
        tmp_path / "attempts",
        require_production=False,
    )
    assert decision["report"] == report
    assert decision["terminal_attempt"]["report_sha256"] == report["run_sha256"]

    relabeled = copy.deepcopy(report)
    relabeled["execution"]["production_evidence"] = True
    relabeled["execution"]["git_tree_clean"] = True
    _rehash_report(relabeled)
    with pytest.raises(EnronCapacityError):
        verify_capacity_report(relabeled)


def test_same_five_adapters_complete_a_private_synthetic_capacity_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_rows = 60
    dataset_id = "synthetic/enron-capacity"
    dataset_revision = "fixture-2026"
    source = tmp_path / "synthetic-source.jsonl"

    def source_row(index: int) -> dict[str, Any]:
        sender = (
            "Alice Alpha <alice.alpha@example.invalid>" if index % 2 == 0 else "Bob Beta <bob.beta@example.invalid>"
        )
        recipient = (
            "Bob Beta <bob.beta@example.invalid>" if index % 2 == 0 else "Alice Alpha <alice.alpha@example.invalid>"
        )
        month = index // 28 + 1
        day = index % 28 + 1
        return {
            "message_id": f"<synthetic-{index:03d}@messages.invalid>",
            "subject": f"Unique synthetic capacity subject {index:03d}",
            "from": sender,
            "to": [recipient, "Service Desk <service.desk@example.invalid>"],
            "cc": [],
            "bcc": [],
            "date": f"2001-{month:02d}-{day:02d}T12:00:00Z",
            "body": f"Synthetic capacity body marker {index:03d} with bounded fixture content.",
            "file_name": f"maildir/owner-{index % 6}/inbox/{index}",
        }

    source.write_text(
        "".join(json.dumps(source_row(index), separators=(",", ":")) + "\n" for index in range(source_rows)),
        encoding="utf-8",
    )
    source.chmod(0o600)
    monkeypatch.setattr(enron_capacity, "ENRON_DATASET_ID", dataset_id)
    monkeypatch.setattr(enron_capacity, "ENRON_DATASET_REVISION", dataset_revision)
    monkeypatch.setattr(enron_capacity, "ENRON_SOURCE_ROWS", source_rows)

    config = enron_capacity._IntegratedCapacityConfig(
        dataset_id=dataset_id,
        dataset_revision=dataset_revision,
        expected_source_rows=source_rows,
        input_jsonl=source,
        max_rows=source_rows,
        fixture_mode=True,
        enforce_production_runtime=False,
    )
    sealed_guard_active = False
    splitting = __import__("nerb.enron_splitting", fromlist=["open_private_binary_input"])
    original_private_open = splitting.open_private_binary_input

    def reject_postsplit_test_open(path: Path, *args: Any, **kwargs: Any) -> Any:
        if sealed_guard_active and Path(path).name == "test.jsonl":
            pytest.fail("downstream adapter opened sealed test content")
        return original_private_open(path, *args, **kwargs)

    monkeypatch.setattr(splitting, "open_private_binary_input", reject_postsplit_test_open)

    def run_phase(context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
        nonlocal sealed_guard_active
        result = enron_capacity._execute_integrated_capacity_phase(
            context,
            context.phase,
            config=config,
        )
        if context.phase == "split":
            sealed_guard_active = True
        return result

    class TickingProbe(_Probe):
        def monotonic_ns(self) -> int:
            with self._lock:
                self.now_ns += 10_000
                return self.now_ns

    options = _options(tmp_path, "synthetic-capacity")
    report = enron_capacity._run_enron_capacity_for_test(
        options,
        phase_runners={phase: run_phase for phase in CAPACITY_PHASES},
        resource_probe=TickingProbe(),
        monitor_interval_ns=enron_capacity.PRODUCTION_MONITOR_INTERVAL_NS,
    )

    assert verify_capacity_report(report, require_production=False) == report
    assert report["totals"]["source_rows_accounted"] == source_rows
    preparation, split, build, streaming, replay = report["phases"]
    assert preparation["processed_bytes"] == (
        preparation["commitments"]["prepared_artifact_bytes"] + preparation["commitments"]["rejection_artifact_bytes"]
    )
    assert split["processed_bytes"] == sum(
        split["commitments"][field]
        for field in ("train_artifact_bytes", "validation_artifact_bytes", "test_artifact_bytes")
    )
    assert build["processed_bytes"] == split["commitments"]["train_artifact_bytes"]
    assert streaming["processed_bytes"] == streaming["commitments"]["validation_text_utf8_bytes"]
    assert replay["processed_bytes"] == (
        split["commitments"]["train_artifact_bytes"] + split["commitments"]["validation_artifact_bytes"]
    )
    assert build["commitments"]["active_pattern_count"] > 0
    assert replay["commitments"]["replay_equal"] is True
    assert report["gates"]["sealed_test_unaccessed"] is True
    expected_tombstones = {
        "preparation": {"scratch": 1, "tmp": 1},
        "split": {"scratch": 3},
        "build": {"tmp": 1},
        "streaming_validation": {"scratch": 1},
        "deep_replay": {"scratch": 1},
    }
    for phase in CAPACITY_PHASES:
        runtime = options.output_dir / "phases" / phase / "runtime"
        for owned_root in runtime.iterdir():
            retained = tuple(owned_root.iterdir())
            assert len(retained) == expected_tombstones.get(phase, {}).get(owned_root.name, 0)
            for tombstone in retained:
                assert enron_capacity._PRIVATE_TOMBSTONE_RE.fullmatch(tombstone.name)
                for path in (tombstone, *tombstone.rglob("*")):
                    info = path.lstat()
                    assert not stat.S_ISLNK(info.st_mode)
                    assert info.st_uid == os.geteuid()
                    assert stat.S_IMODE(info.st_mode) & 0o077 == 0
                    if stat.S_ISREG(info.st_mode):
                        assert info.st_size == 0
                        assert (
                            path.name in _ALLOWED_ZERO_PAYLOAD_TOMBSTONE_FILES
                            or enron_capacity._PRIVATE_TOMBSTONE_RE.fullmatch(path.name)
                        )
                    else:
                        assert stat.S_ISDIR(info.st_mode)
    public_payload = json.dumps(report, sort_keys=True)
    assert "synthetic-000@messages.invalid" not in public_payload
    assert os.fspath(tmp_path) not in public_payload
    monkeypatch.setattr(
        enron_capacity,
        "_native_build_source_sha256_at_commit",
        lambda _commit: report["execution"]["native_build_source_sha256"],
    )
    portable = export_capacity_decision(
        options.output_dir,
        options.attempt_ledger_dir,
        tmp_path / "synthetic-portable.json",
        require_production=False,
    )
    portable_payload = json.dumps(portable, sort_keys=True)
    assert "synthetic-000@messages.invalid" not in portable_payload
    assert os.fspath(tmp_path) not in portable_payload
    assert options.output_dir.name not in portable_payload


def test_portable_export_binds_full_attempt_chain_and_rejects_tamper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe = _Probe()

    def fail_preparation(_context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
        raise RuntimeError("private fixture payload")

    with pytest.raises(EnronCapacityError):
        _run(
            tmp_path,
            probe,
            name="portable-run",
            replacements={"preparation": fail_preparation},
        )
    report, _ = _run(tmp_path, _Probe(), name="portable-run")
    monkeypatch.setattr(
        enron_capacity,
        "_native_build_source_sha256_at_commit",
        lambda _commit: report["execution"]["native_build_source_sha256"],
    )
    output = tmp_path / "portable-decision.json"
    artifact = export_capacity_decision(
        tmp_path / "portable-run",
        tmp_path / "attempts",
        output,
        require_production=False,
    )

    assert len(artifact["attempt_chain"]) == 2
    assert artifact["attempt_chain"][0]["outcome"] == "failed"
    assert artifact["terminal_attempt"] == artifact["attempt_chain"][-1]
    assert artifact["terminal_attempt"]["report_sha256"] == report["run_sha256"]
    assert artifact["attestation"]["kind"] == "clean_clone_source_and_hash_chain_verification"
    assert (
        "recorded_native_binary_bytes_or_reproducible_binary_build"
        in artifact["verification_scope"]["not_independently_attested"]
    )
    assert "trusted_access_controlled_host" in artifact["verification_scope"]["prerequisite"]
    assert "fresh_uv_managed_install" in artifact["verification_scope"]["prerequisite"]
    assert artifact["attestation"]["native_binary_sha256"] == report["execution"]["native_extension_sha256"]
    assert verify_portable_capacity_decision(output, require_production=False) == artifact

    tampered = copy.deepcopy(artifact)
    tampered["attempt_chain"][0]["failure_code"] = "phase_interrupted"
    tampered_path = tmp_path / "tampered-portable.json"
    tampered_path.write_text(json.dumps(tampered, sort_keys=True), encoding="utf-8")
    tampered_path.chmod(0o600)
    with pytest.raises(EnronCapacityError, match="Portable capacity"):
        verify_portable_capacity_decision(tampered_path, require_production=False)

    gapped = copy.deepcopy(artifact)
    gapped["attempt_chain"][1]["attempt_sequence"] = 3
    gapped["attempt_chain"][1]["attempt_sha256"] = enron_capacity._hash_attempt_receipt(gapped["attempt_chain"][1])
    with pytest.raises(EnronCapacityError, match="Portable capacity"):
        enron_capacity._verify_portable_capacity_decision(gapped, require_production=False)


def test_portable_export_linearizes_before_a_cooperating_attempt_can_append(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report, _ = _run(tmp_path, name="export-linearization-run")
    run_dir = tmp_path / "export-linearization-run"
    ledger_dir = tmp_path / "attempts"
    output = tmp_path / "linearized-portable.json"
    monkeypatch.setattr(
        enron_capacity,
        "_native_build_source_sha256_at_commit",
        lambda _commit: report["execution"]["native_build_source_sha256"],
    )

    published = threading.Event()
    release_publication = threading.Event()
    append_lock_requested = threading.Event()
    append_lock_acquired = threading.Event()
    real_rename = enron_capacity._private_io._rename_noreplace_at
    real_flock = enron_capacity.fcntl.flock

    def pause_after_publication(
        source_directory_fd: int,
        source_name: str,
        destination_directory_fd: int,
        destination_name: str,
    ) -> None:
        real_rename(source_directory_fd, source_name, destination_directory_fd, destination_name)
        if destination_name == output.name:
            published.set()
            if not release_publication.wait(timeout=5):
                raise RuntimeError("test publication release timed out")

    def observe_attempt_lock(descriptor: int, operation: int) -> None:
        if (
            threading.current_thread().name == "racing-attempt"
            and operation & enron_capacity.fcntl.LOCK_EX
            and not operation & enron_capacity.fcntl.LOCK_NB
            and not append_lock_requested.is_set()
        ):
            append_lock_requested.set()
            real_flock(descriptor, operation)
            append_lock_acquired.set()
            return
        real_flock(descriptor, operation)

    monkeypatch.setattr(enron_capacity._private_io, "_rename_noreplace_at", pause_after_publication)
    monkeypatch.setattr(enron_capacity.fcntl, "flock", observe_attempt_lock)
    exported: list[dict[str, Any]] = []
    export_errors: list[BaseException] = []
    attempt_errors: list[BaseException] = []

    def export_worker() -> None:
        try:
            exported.append(export_capacity_decision(run_dir, ledger_dir, output, require_production=False))
        except BaseException as exc:
            export_errors.append(exc)

    def attempt_worker() -> None:
        try:
            _run(tmp_path, name="after-export")
        except BaseException as exc:
            attempt_errors.append(exc)

    exporter = threading.Thread(target=export_worker, name="paused-export")
    attempt = threading.Thread(target=attempt_worker, name="racing-attempt")
    exporter.start()
    try:
        assert published.wait(timeout=15), "export did not reach its publication point"
        assert output.exists()
        attempt.start()
        assert append_lock_requested.wait(timeout=15), "new attempt did not request the ledger lock"
        assert not append_lock_acquired.wait(timeout=0.1), "new attempt passed the export's shared ledger lock"
    finally:
        release_publication.set()
    exporter.join(timeout=20)
    attempt.join(timeout=20)

    assert not exporter.is_alive()
    assert not attempt.is_alive()
    assert export_errors == []
    assert len(attempt_errors) == 1
    assert isinstance(attempt_errors[0], EnronCapacityError)
    assert attempt_errors[0].code == "watchdog_unsupported"
    assert append_lock_acquired.is_set()
    assert len(exported) == 1
    assert len(exported[0]["attempt_chain"]) == 1
    assert len(verify_capacity_attempt_ledger(ledger_dir)) == 2
    assert verify_portable_capacity_decision(output, require_production=False) == exported[0]


@pytest.mark.parametrize(
    ("relative_root", "evidence_name"),
    (
        ("run", "capacity-report.json"),
        ("run", "COMMITTED"),
        ("ledger", "attempt-00000001.json"),
    ),
)
def test_portable_export_rolls_back_after_same_inode_evidence_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative_root: str,
    evidence_name: str,
) -> None:
    report, _ = _run(tmp_path, name="mutated-export-run")
    run_dir = tmp_path / "mutated-export-run"
    ledger_dir = tmp_path / "attempts"
    output = tmp_path / "mutation-portable.json"
    evidence_root = run_dir if relative_root == "run" else ledger_dir
    evidence_path = evidence_root / evidence_name
    monkeypatch.setattr(
        enron_capacity,
        "_native_build_source_sha256_at_commit",
        lambda _commit: report["execution"]["native_build_source_sha256"],
    )

    published = threading.Event()
    release_publication = threading.Event()
    real_rename = enron_capacity._private_io._rename_noreplace_at

    def pause_after_publication(
        source_directory_fd: int,
        source_name: str,
        destination_directory_fd: int,
        destination_name: str,
    ) -> None:
        real_rename(source_directory_fd, source_name, destination_directory_fd, destination_name)
        if destination_name == output.name:
            published.set()
            if not release_publication.wait(timeout=5):
                raise RuntimeError("test publication release timed out")

    monkeypatch.setattr(enron_capacity._private_io, "_rename_noreplace_at", pause_after_publication)
    errors: list[BaseException] = []

    def export_worker() -> None:
        try:
            export_capacity_decision(run_dir, ledger_dir, output, require_production=False)
        except BaseException as exc:
            errors.append(exc)

    exporter = threading.Thread(target=export_worker)
    exporter.start()
    try:
        assert published.wait(timeout=15), "export did not publish before the evidence mutation"
        identity_before = (evidence_path.stat().st_dev, evidence_path.stat().st_ino)
        descriptor = os.open(
            evidence_path,
            os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            original = os.pread(descriptor, 1, 0)
            replacement = b"X" if original != b"X" else b"Y"
            assert os.pwrite(descriptor, replacement, 0) == 1
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        identity_after = (evidence_path.stat().st_dev, evidence_path.stat().st_ino)
        assert identity_after == identity_before
    finally:
        release_publication.set()
    exporter.join(timeout=20)

    assert not exporter.is_alive()
    assert len(errors) == 1
    assert isinstance(errors[0], EnronCapacityError)
    assert errors[0].code == "portable_write_failed"
    assert not output.exists()
    retained_stages = tuple(tmp_path.glob(f".{output.name}.stage-*"))
    assert len(retained_stages) == 1
    assert retained_stages[0].stat().st_size > 0


def test_portable_commit_verification_requires_missing_history_then_passes_after_fetch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path(
        subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    )
    parent = subprocess.run(
        ["git", "-C", os.fspath(root), "rev-parse", "HEAD^"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    shallow = tmp_path / "shallow"
    subprocess.run(
        ["git", "clone", "--quiet", "--depth", "1", f"file://{root}", os.fspath(shallow)],
        check=True,
    )
    monkeypatch.setattr(enron_capacity, "_git_root", lambda: shallow)

    with pytest.raises(EnronCapacityError, match="Portable capacity"):
        enron_capacity._git_commit_object_sha256(parent)

    subprocess.run(
        ["git", "-C", os.fspath(shallow), "fetch", "--quiet", "--unshallow"],
        check=True,
    )
    assert enron_capacity._git_commit_object_sha256(parent).startswith("sha256:")


def test_portable_export_rejects_output_parent_swap_before_writer_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report, _ = _run(tmp_path, name="parent-swap-export-run")
    run_dir = tmp_path / "parent-swap-export-run"
    ledger_dir = tmp_path / "attempts"
    output_parent = tmp_path / "public-output"
    moved_parent = tmp_path / "moved-public-output"
    output_parent.mkdir()
    output = output_parent / "decision.json"
    substitute = b"unrelated replacement target"
    monkeypatch.setattr(
        enron_capacity,
        "_native_build_source_sha256_at_commit",
        lambda _commit: report["execution"]["native_build_source_sha256"],
    )
    real_writer = enron_capacity._write_new_public_artifact
    swapped = False

    def swap_before_open(path: Path, payload: bytes, **kwargs: Any) -> None:
        nonlocal swapped
        swapped = True
        output_parent.rename(moved_parent)
        output_parent.mkdir()
        output.write_bytes(substitute)
        output.chmod(0o600)
        real_writer(path, payload, **kwargs)

    monkeypatch.setattr(enron_capacity, "_write_new_public_artifact", swap_before_open)
    with pytest.raises(EnronCapacityError) as raised:
        export_capacity_decision(run_dir, ledger_dir, output, require_production=False)

    assert raised.value.code == "portable_write_failed"
    assert swapped is True
    assert output.read_bytes() == substitute
    assert not tuple(moved_parent.iterdir())
    assert not tuple(output_parent.glob(f".{output.name}.stage-*"))


def test_public_writer_rolls_back_through_opened_parent_after_postpublication_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_parent = tmp_path / "writer-output"
    moved_parent = tmp_path / "moved-writer-output"
    output_parent.mkdir()
    output = output_parent / "decision.json"
    payload = b'{"aggregate":true}\n'
    substitute = b"unrelated replacement target"
    real_rename = enron_capacity._private_io._rename_noreplace_at
    swapped = False

    def swap_parent_after_publication(
        source_directory_fd: int,
        source_name: str,
        destination_directory_fd: int,
        destination_name: str,
    ) -> None:
        nonlocal swapped
        real_rename(source_directory_fd, source_name, destination_directory_fd, destination_name)
        if destination_name == output.name and not swapped:
            swapped = True
            output_parent.rename(moved_parent)
            output_parent.mkdir()
            output.write_bytes(substitute)
            output.chmod(0o600)

    monkeypatch.setattr(enron_capacity._private_io, "_rename_noreplace_at", swap_parent_after_publication)
    with pytest.raises(EnronCapacityError) as raised:
        enron_capacity._write_new_public_artifact(output, payload)

    assert raised.value.code == "portable_write_failed"
    assert swapped is True
    assert output.read_bytes() == substitute
    assert not (moved_parent / output.name).exists()
    retained = tuple(moved_parent.glob(f".{output.name}.stage-*"))
    assert len(retained) == 1
    assert retained[0].read_bytes() == payload
    assert not tuple(output_parent.glob(f".{output.name}.stage-*"))


def test_portable_output_failure_or_substitution_never_deletes_published_or_staged_inodes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b'{"aggregate":true}\n'
    fsync_output = tmp_path / "fsync-output.json"
    original_fsync = os.fsync
    fsync_calls = 0

    def fail_directory_fsync(descriptor: int) -> None:
        nonlocal fsync_calls
        fsync_calls += 1
        if fsync_calls == 2:
            raise OSError("directory fsync failure")
        original_fsync(descriptor)

    monkeypatch.setattr(enron_capacity.os, "fsync", fail_directory_fsync)
    with pytest.raises(EnronCapacityError, match="could not be written"):
        enron_capacity._write_new_public_artifact(fsync_output, payload)
    assert not fsync_output.exists()
    fsync_stages = tuple(tmp_path.glob(".fsync-output.json.stage-*"))
    assert len(fsync_stages) == 1
    assert fsync_stages[0].read_bytes() == payload

    monkeypatch.setattr(enron_capacity.os, "fsync", original_fsync)
    substituted_output = tmp_path / "substituted-output.json"
    moved_output = tmp_path / "published-by-writer.json"
    original_rename = enron_capacity._private_io._rename_noreplace_at

    def substitute_after_rename(
        source_directory_fd: int,
        source_name: str,
        destination_directory_fd: int,
        destination_name: str,
    ) -> None:
        original_rename(source_directory_fd, source_name, destination_directory_fd, destination_name)
        if destination_name == substituted_output.name:
            substituted_output.rename(moved_output)
            substituted_output.write_bytes(b"unrelated")
            substituted_output.chmod(0o600)

    monkeypatch.setattr(enron_capacity._private_io, "_rename_noreplace_at", substitute_after_rename)
    with pytest.raises(EnronCapacityError, match="could not be written"):
        enron_capacity._write_new_public_artifact(substituted_output, payload)
    assert not substituted_output.exists()
    assert moved_output.read_bytes() == payload
    substituted_stages = tuple(tmp_path.glob(".substituted-output.json.stage-*"))
    assert len(substituted_stages) == 1
    assert substituted_stages[0].read_bytes() == b"unrelated"

    temp_swap_output = tmp_path / "temp-swap-output.json"
    preserved_stage = tmp_path / "preserved-writer-stage.json"

    def substitute_temporary_before_rename(
        source_directory_fd: int,
        temporary_name: str,
        destination_directory_fd: int,
        destination_name: str,
    ) -> None:
        if destination_name == temp_swap_output.name:
            os.rename(
                temporary_name,
                preserved_stage.name,
                src_dir_fd=source_directory_fd,
                dst_dir_fd=source_directory_fd,
            )
            substitute_fd = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=source_directory_fd,
            )
            try:
                os.write(substitute_fd, b"unrelated-temp")
            finally:
                os.close(substitute_fd)
        original_rename(
            source_directory_fd,
            temporary_name,
            destination_directory_fd,
            destination_name,
        )

    monkeypatch.setattr(enron_capacity._private_io, "_rename_noreplace_at", substitute_temporary_before_rename)
    with pytest.raises(EnronCapacityError, match="could not be written"):
        enron_capacity._write_new_public_artifact(temp_swap_output, payload)
    assert not temp_swap_output.exists()
    assert preserved_stage.read_bytes() == payload
    retained_temps = tuple(tmp_path.glob(".temp-swap-output.json.stage-*"))
    assert len(retained_temps) == 1
    assert retained_temps[0].read_bytes() == b"unrelated-temp"


@pytest.mark.parametrize("swap_point", ["before", "after"])
def test_private_atomic_writer_detects_publication_swaps_without_deleting_substitutes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    swap_point: str,
) -> None:
    ledger = tmp_path / "private-writer"
    ledger.mkdir(mode=0o700)
    directory_fd = os.open(ledger, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    temporary_name = ".attempt-stage-" + "a" * 64 + ".tmp"
    final_name = "attempt-00000001.json"
    moved_name = f"moved-authentic-{swap_point}"
    substitute = b"unrelated-substitute"
    real_rename = enron_capacity._private_io._rename_noreplace_at

    def swap_around_rename(
        source_directory_fd: int,
        source_name: str,
        destination_directory_fd: int,
        destination_name: str,
    ) -> None:
        if destination_name == final_name and swap_point == "before":
            os.rename(source_name, moved_name, src_dir_fd=source_directory_fd, dst_dir_fd=source_directory_fd)
            substitute_fd = os.open(
                source_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=source_directory_fd,
            )
            try:
                os.write(substitute_fd, substitute)
            finally:
                os.close(substitute_fd)
        real_rename(source_directory_fd, source_name, destination_directory_fd, destination_name)
        if destination_name == final_name and swap_point == "after":
            os.rename(
                destination_name,
                moved_name,
                src_dir_fd=destination_directory_fd,
                dst_dir_fd=destination_directory_fd,
            )
            substitute_fd = os.open(
                destination_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=destination_directory_fd,
            )
            try:
                os.write(substitute_fd, substitute)
            finally:
                os.close(substitute_fd)

    monkeypatch.setattr(enron_capacity._private_io, "_rename_noreplace_at", swap_around_rename)
    try:
        with pytest.raises(EnronCapacityError):
            enron_capacity._write_locked_atomic_file_at(
                directory_fd,
                temporary_name=temporary_name,
                final_name=final_name,
                payload=b"authentic-private-receipt",
            )
    finally:
        os.close(directory_fd)

    assert not (ledger / final_name).exists()
    assert (ledger / temporary_name).read_bytes() == substitute
    assert (ledger / moved_name).read_bytes() == b""


@pytest.mark.parametrize("entry_kind", ["binding", "marker"])
def test_inflight_removal_swaps_preserve_substitutes_and_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    entry_kind: str,
) -> None:
    ledger = enron_capacity._AttemptLedger(tmp_path / "attempts")
    output_parent = enron_capacity._PinnedDirectory(tmp_path)
    execution = {
        "executable_git_commit": None,
        "capacity_implementation_sha256": _hash("implementation"),
        "repository_tree_sha256": _hash("repository"),
        "runtime_environment_sha256": _hash("runtime"),
    }
    inflight = enron_capacity._begin_inflight_attempt(
        ledger,
        final_dir=tmp_path / "capacity-run",
        output_parent=output_parent,
        execution=execution,
        production_evidence=False,
        started_monotonic_ns=1,
    )
    stage = tmp_path / f".capacity-run.stage-{inflight.stage_token}"
    stage.mkdir(mode=0o700)
    enron_capacity._bind_inflight_stage(inflight, stage)
    target_name = inflight.binding_name if entry_kind == "binding" else inflight.marker_name
    substitute = b"unrelated-ledger-substitute"
    moved_name = f"moved-{entry_kind}"
    real_cleanup = enron_capacity._wipe_and_quarantine_private_file_at

    def swap_before_cleanup(
        directory_fd: int,
        name: str,
        descriptor: int,
        expected_identity: tuple[int, int],
    ) -> str:
        if name == target_name:
            os.rename(name, moved_name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            substitute_fd = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=directory_fd,
            )
            try:
                os.write(substitute_fd, substitute)
            finally:
                os.close(substitute_fd)
        return real_cleanup(directory_fd, name, descriptor, expected_identity)

    monkeypatch.setattr(enron_capacity, "_wipe_and_quarantine_private_file_at", swap_before_cleanup)
    try:
        with pytest.raises(EnronCapacityError):
            enron_capacity._remove_inflight_files_locked(inflight)
    finally:
        inflight.close()
        ledger.close()

    assert (tmp_path / "attempts" / target_name).read_bytes() == substitute
    assert (tmp_path / "attempts" / moved_name).read_bytes() == b""


def test_stale_ledger_temp_swap_is_preserved_and_blocks_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = enron_capacity._AttemptLedger(tmp_path / "attempts")
    temporary_name = ".attempt-inflight-stage-" + "a" * 64 + "-" + "b" * 64 + ".tmp"
    stage = tmp_path / "attempts" / temporary_name
    stage.write_bytes(b"partial-private-ledger-state")
    stage.chmod(0o600)
    substitute = b"unrelated-stale-substitute"
    moved_name = "moved-stale-authentic"
    real_cleanup = enron_capacity._wipe_and_quarantine_private_file_at

    def swap_before_cleanup(
        directory_fd: int,
        name: str,
        descriptor: int,
        expected_identity: tuple[int, int],
    ) -> str:
        if name == temporary_name:
            os.rename(name, moved_name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            substitute_fd = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=directory_fd,
            )
            try:
                os.write(substitute_fd, substitute)
            finally:
                os.close(substitute_fd)
        return real_cleanup(directory_fd, name, descriptor, expected_identity)

    monkeypatch.setattr(enron_capacity, "_wipe_and_quarantine_private_file_at", swap_before_cleanup)
    try:
        with pytest.raises(EnronCapacityError):
            enron_capacity._recover_ledger_temps_locked(ledger.fd)
    finally:
        ledger.close()

    assert stage.read_bytes() == substitute
    assert (tmp_path / "attempts" / moved_name).read_bytes() == b""


def test_capacity_quarantine_rename_race_restores_the_substitute_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = tmp_path / "attempts"
    ledger.mkdir(mode=0o700)
    source = ledger / "private-stage"
    source.write_bytes(b"authentic-private-payload")
    source.chmod(0o600)
    moved = ledger / "moved-authentic"
    substitute = b"preserve-this-substitute"
    directory_fd = os.open(ledger, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    descriptor = os.open(source.name, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
    identity = enron_capacity._regular_file_identity(os.fstat(descriptor))
    real_rename = enron_capacity._private_io._rename_noreplace_at
    swapped = False

    def swap_inside_quarantine_rename(
        source_directory_fd: int,
        source_name: str,
        destination_directory_fd: int,
        destination_name: str,
    ) -> None:
        nonlocal swapped
        if source_name == source.name and destination_name.startswith(".nerb-cleanup-") and not swapped:
            swapped = True
            os.rename(source_name, moved.name, src_dir_fd=source_directory_fd, dst_dir_fd=source_directory_fd)
            substitute_fd = os.open(
                source_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=source_directory_fd,
            )
            try:
                os.write(substitute_fd, substitute)
            finally:
                os.close(substitute_fd)
        real_rename(source_directory_fd, source_name, destination_directory_fd, destination_name)

    monkeypatch.setattr(enron_capacity._private_io, "_rename_noreplace_at", swap_inside_quarantine_rename)
    try:
        with pytest.raises(EnronCapacityError):
            enron_capacity._wipe_and_quarantine_private_file_at(
                directory_fd,
                source.name,
                descriptor,
                identity,
            )
    finally:
        os.close(descriptor)
        os.close(directory_fd)

    assert source.read_bytes() == substitute
    assert moved.read_bytes() == b""
    assert not tuple(ledger.glob(".nerb-cleanup-*"))


def test_portable_export_cannot_write_into_or_alias_private_evidence_roots(tmp_path: Path) -> None:
    report, _ = _run(tmp_path, name="excluded-export-run")
    run_dir = tmp_path / "excluded-export-run"
    ledger_dir = tmp_path / "attempts"
    alias = tmp_path / "run-alias"
    alias.symlink_to(run_dir, target_is_directory=True)

    for output in (run_dir / "portable.json", ledger_dir / "portable.json", alias / "portable.json"):
        with pytest.raises(EnronCapacityError, match="could not be written"):
            export_capacity_decision(run_dir, ledger_dir, output, require_production=False)

    assert verify_capacity_report(report, require_production=False) == report
    assert verify_capacity_attempt_ledger(ledger_dir)[-1]["report_sha256"] == report["run_sha256"]


def test_portable_export_closes_private_pins_when_private_verification_is_interrupted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _run(tmp_path, name="interrupted-export-run")
    run_dir = tmp_path / "interrupted-export-run"
    ledger_dir = tmp_path / "attempts"
    output = tmp_path / "interrupted-portable.json"
    closed: list[Path] = []
    original_close = enron_capacity._PinnedDirectory.close

    def interrupt_verification(*_args: Any, **_kwargs: Any) -> None:
        def tracked_close(directory: enron_capacity._PinnedDirectory) -> None:
            closed.append(directory.path)
            original_close(directory)

        monkeypatch.setattr(enron_capacity._PinnedDirectory, "close", tracked_close)
        raise KeyboardInterrupt

    monkeypatch.setattr(enron_capacity, "_verify_pinned_capacity_decision", interrupt_verification)
    with pytest.raises(KeyboardInterrupt):
        export_capacity_decision(run_dir, ledger_dir, output, require_production=False)

    assert closed == [ledger_dir.resolve(), run_dir.resolve()]
    assert not output.exists()


def test_portable_verifier_preserves_control_flow_exceptions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        enron_capacity,
        "_read_regular_public_artifact",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    with pytest.raises(KeyboardInterrupt):
        verify_portable_capacity_decision(tmp_path / "unused.json", require_production=False)


def test_public_production_dispatcher_fails_closed_without_isolated_tracked_launcher(tmp_path: Path) -> None:
    with pytest.raises(EnronCapacityError) as raised:
        run_enron_capacity(_options(tmp_path))

    assert raised.value.code == "production_identity_invalid"
    assert not (tmp_path / "capacity-run").exists()
    assert not (tmp_path / "attempts").exists()


def test_successful_report_has_five_closed_chained_phases_and_durable_receipt(tmp_path: Path) -> None:
    report, probe = _run(tmp_path)

    assert [phase["phase"] for phase in report["phases"]] == list(CAPACITY_PHASES)
    assert report["totals"]["source_rows_accounted"] == ENRON_SOURCE_ROWS
    assert report["gates"]["passed"] is True
    assert report["phases"][1]["commitments"]["preseal_access_count"] == 0
    assert report["phases"][1]["commitments"]["sealed_state"] == "sealed_unbound"
    assert report["gates"]["sealed_state_unbound"] is True
    assert report["phases"][3]["commitments"]["validation_run_sha256"] == _hash("validation-run")
    assert report["phases"][4]["commitments"]["replay_validation_run_sha256"] == _hash("validation-run")
    assert report["policy"]["processed_bytes_measurement_boundary"].startswith("deterministic_logical")
    assert report["phases"][4]["commitments"]["replay_equal"] is True
    assert all(phase["commitments"]["sealed_test_accessed"] is False for phase in report["phases"])
    assert report["execution"]["report_measurement_boundary"] == enron_capacity._REPORT_MEASUREMENT_BOUNDARY
    assert report["execution"]["attempt_measurement_boundary"] == enron_capacity._ATTEMPT_MEASUREMENT_BOUNDARY
    assert set(report["execution"]["core_source_sha256"]) == {
        name.removesuffix(".py") for name in enron_capacity._PRODUCTION_CORE_SOURCE_NAMES
    }
    assert tmp_path in probe.disk_paths
    assert tmp_path / "attempts" in probe.disk_paths

    receipts = verify_capacity_attempt_ledger(tmp_path / "attempts")
    assert len(receipts) == 1
    assert receipts[0]["outcome"] == "passed"
    assert receipts[0]["report_sha256"] == report["run_sha256"]
    assert receipts[0]["final_owned_disk_bytes"] == report["totals"]["final_owned_disk_bytes"]
    assert report["environment"]["preexisting_private_tombstone_count"] == 0
    assert receipts[0]["preexisting_private_tombstone_count"] == 0
    assert receipts[0]["sensitive_content_wiped"] is None
    assert receipts[0]["path_tree_removed"] is None
    assert receipts[0]["retained_private_tombstone_count"] == 0
    serialized = json.dumps({"report": report, "receipts": receipts}, sort_keys=True)
    assert os.fspath(tmp_path) not in serialized
    assert "@" not in serialized


def test_policy_freezes_streaming_monitoring_checkpoint_and_attempt_gates() -> None:
    policy = enron_capacity.capacity_policy()

    assert policy["dataset_id"] == ENRON_DATASET_ID
    assert policy["dataset_revision"] == ENRON_DATASET_REVISION
    assert policy["source_rows"] == 517_401
    assert policy["phases"] == list(CAPACITY_PHASES)
    assert policy["maximum_checkpoint_record_gap"] == 10_000
    assert policy["production_monitor_interval_ns"] == 100_000_000
    assert policy["continuous_process_tree_rss_required"] is True
    assert policy["continuous_free_disk_required"] is True
    assert policy["append_only_attempt_receipt_required"] is True
    assert policy["failed_cleanup_retains_payload_empty_private_tombstones"] is True
    assert policy["maximum_pinned_cleanup_files"] == 128
    assert policy["pinned_cleanup_fd_reserve"] == 72
    assert policy["nested_phase_cleanup_ownership_required"] is True
    assert policy["stopped_phase_writer_tree_adoption_required"] is True


def test_linux_process_tree_rss_enumerates_children_of_every_thread(tmp_path: Path) -> None:
    proc_root = tmp_path / "proc"

    def write_process(pid: int, rss_kib: int, task_children: Mapping[int, tuple[int, ...]]) -> None:
        process = proc_root / str(pid)
        process.mkdir(parents=True)
        (process / "status").write_text(f"Name:\tfixture\nVmRSS:\t{rss_kib} kB\n", encoding="ascii")
        for tid, children in task_children.items():
            task = process / "task" / str(tid)
            task.mkdir(parents=True)
            (task / "children").write_text(" ".join(str(child) for child in children), encoding="ascii")

    write_process(100, 100, {100: (200,), 101: (300,)})
    write_process(200, 20, {200: ()})
    write_process(300, 30, {300: (400,)})
    write_process(400, 40, {400: ()})

    assert enron_capacity._linux_process_tree_rss_bytes(100, proc_root=proc_root) == 190 * 1024


@pytest.mark.parametrize(("platform_name", "scale"), [("linux", 1024), ("darwin", 1)])
def test_root_process_peak_rss_combines_self_and_reaped_children_with_platform_units(
    monkeypatch: pytest.MonkeyPatch,
    platform_name: str,
    scale: int,
) -> None:
    class Usage:
        def __init__(self, value: int) -> None:
            self.ru_maxrss = value

    def usage(kind: int) -> Usage:
        assert kind in {enron_capacity.resource.RUSAGE_SELF, enron_capacity.resource.RUSAGE_CHILDREN}
        return Usage(3 if kind == enron_capacity.resource.RUSAGE_SELF else 5)

    monkeypatch.setattr(enron_capacity.sys, "platform", platform_name)
    monkeypatch.setattr(enron_capacity.resource, "getrusage", usage)

    assert enron_capacity._root_process_peak_rss_bytes() == 8 * scale


@pytest.mark.parametrize(("self_rss", "child_rss"), [(0, 1), (1, -1)])
def test_root_process_peak_rss_rejects_invalid_kernel_values(
    monkeypatch: pytest.MonkeyPatch,
    self_rss: int,
    child_rss: int,
) -> None:
    class Usage:
        def __init__(self, value: int) -> None:
            self.ru_maxrss = value

    monkeypatch.setattr(
        enron_capacity.resource,
        "getrusage",
        lambda kind: Usage(self_rss if kind == enron_capacity.resource.RUSAGE_SELF else child_rss),
    )

    assert enron_capacity._root_process_peak_rss_bytes() is None


@pytest.mark.parametrize(
    ("current", "kernel_bound", "expected"),
    [(100, 200, 200), (300, 200, 300), (100, None, 100), (None, 200, None)],
)
def test_system_resource_probe_uses_maximum_of_live_tree_and_kernel_bound(
    monkeypatch: pytest.MonkeyPatch,
    current: int | None,
    kernel_bound: int | None,
    expected: int | None,
) -> None:
    monkeypatch.setattr(enron_capacity.sys, "platform", "linux")
    monkeypatch.setattr(enron_capacity, "_linux_process_tree_rss_bytes", lambda _pid: current)
    monkeypatch.setattr(enron_capacity, "_root_process_peak_rss_bytes", lambda: kernel_bound)

    assert enron_capacity._SystemResourceProbe().process_tree_rss_bytes(123) == expected


@pytest.mark.parametrize(
    ("attribute", "value", "code"),
    [
        ("physical", None, "preflight_memory"),
        ("rss", None, "preflight_rss"),
        ("free", 25 * _GIB - 1, "preflight_disk_limit"),
    ],
)
def test_preflight_failure_is_cleaned_and_durably_receipted(
    tmp_path: Path,
    attribute: str,
    value: int | None,
    code: str,
) -> None:
    probe = _Probe()
    setattr(probe, attribute, value)

    with pytest.raises(EnronCapacityError) as raised:
        enron_capacity._run_enron_capacity_for_test(
            _options(tmp_path),
            phase_runners=_successful_runners(probe),
            resource_probe=probe,
        )

    assert raised.value.code == code
    assert not (tmp_path / "capacity-run").exists()
    receipts = verify_capacity_attempt_ledger(tmp_path / "attempts")
    assert receipts[-1]["outcome"] == "failed"
    assert receipts[-1]["failure_code"] == code


def test_continuous_monitor_catches_short_rss_and_free_disk_spikes_without_checkpoint(
    tmp_path: Path,
) -> None:
    rss_probe = _Probe()

    def rss_spike(context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
        rss_probe.set_rss(6 * _GIB + 1)
        time.sleep(0.25)
        rss_probe.set_rss(64 * _MIB)
        _checkpoint_all(context, rss_probe, _phase_records("split"))
        return _result("split")

    with pytest.raises(EnronCapacityError) as rss_error:
        _run(tmp_path, rss_probe, name="rss-spike", replacements={"split": rss_spike})
    assert rss_error.value.code == "rss_limit"
    assert not (tmp_path / "rss-spike").exists()

    disk_probe = _Probe()

    def disk_spike(context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
        disk_probe.set_free(5 * _GIB - 1)
        time.sleep(0.25)
        disk_probe.set_free(30 * _GIB)
        _checkpoint_all(context, disk_probe, _phase_records("build"))
        return _result("build")

    with pytest.raises(EnronCapacityError) as disk_error:
        _run(tmp_path, disk_probe, name="disk-spike", replacements={"build": disk_spike})
    assert disk_error.value.code == "runtime_disk_floor"
    assert not (tmp_path / "disk-spike").exists()


def test_distinct_attempt_ledger_filesystem_is_sampled_continuously_without_inflating_owned_bytes(
    tmp_path: Path,
) -> None:
    probe = _Probe()
    output_root = tmp_path
    ledger_root = tmp_path / "attempts"
    probe.set_path_device(output_root, 101)
    probe.set_path_device(ledger_root, 202)
    probe.set_path_free(output_root, 30 * _GIB)
    probe.set_path_free(ledger_root, 28 * _GIB)

    def lower_ledger_free_space(context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
        probe.set_path_free(ledger_root, 27 * _GIB)
        _checkpoint_all(context, probe, _phase_records("build"))
        return _result("build")

    report, _ = _run(tmp_path, probe, replacements={"build": lower_ledger_free_space})

    assert report["environment"]["monitored_filesystem_count"] == 2
    assert report["totals"]["minimum_free_disk_bytes"] == 27 * _GIB
    assert report["totals"]["owned_disk_high_water_bytes"] < _MIB
    assert os.fspath(tmp_path) not in json.dumps(report, sort_keys=True)


def test_distinct_attempt_ledger_filesystem_runtime_floor_and_identity_tamper_fail_closed(
    tmp_path: Path,
) -> None:
    ledger_root = tmp_path / "attempts"
    disk_probe = _Probe()
    disk_probe.set_path_device(tmp_path, 101)
    disk_probe.set_path_device(ledger_root, 202)

    def drop_ledger(context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
        disk_probe.set_path_free(ledger_root, 5 * _GIB - 1)
        try:
            time.sleep(0.25)
        finally:
            disk_probe.set_path_free(ledger_root, 30 * _GIB)
        _checkpoint_all(context, disk_probe, _phase_records("split"))
        return _result("split")

    with pytest.raises(EnronCapacityError) as disk_error:
        _run(tmp_path, disk_probe, name="ledger-disk-drop", replacements={"split": drop_ledger})
    assert disk_error.value.code == "runtime_disk_floor"

    identity_probe = _Probe()
    second_ledger = tmp_path / "second-attempts"
    identity_probe.set_path_device(tmp_path, 301)
    identity_probe.set_path_device(second_ledger, 302)

    def swap_identity(context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
        identity_probe.set_path_device(second_ledger, 999)
        try:
            time.sleep(0.25)
        finally:
            identity_probe.set_path_device(second_ledger, 302)
        _checkpoint_all(context, identity_probe, _phase_records("split"))
        return _result("split")

    with pytest.raises(EnronCapacityError) as identity_error:
        _run(
            tmp_path,
            identity_probe,
            name="ledger-identity-swap",
            ledger="second-attempts",
            replacements={"split": swap_identity},
        )
    assert identity_error.value.code == "runtime_filesystem_changed"


def test_post_promotion_gate_resamples_distinct_attempt_ledger_filesystem(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe = _Probe()
    ledger_root = tmp_path / "attempts"
    probe.set_path_device(tmp_path, 101)
    probe.set_path_device(ledger_root, 202)
    original = enron_capacity._post_promotion_enforce

    def drop_before_post_promotion(*args: Any, **kwargs: Any) -> None:
        probe.set_path_free(ledger_root, 5 * _GIB - 1)
        original(*args, **kwargs)

    monkeypatch.setattr(enron_capacity, "_post_promotion_enforce", drop_before_post_promotion)

    with pytest.raises(EnronCapacityError) as raised:
        _run(tmp_path, probe, name="post-promotion-ledger-drop")

    assert raised.value.code == "runtime_disk_floor"
    assert not (tmp_path / "post-promotion-ledger-drop").exists()


def test_continuous_monitor_catches_deleted_owned_disk_spike_between_checkpoints(tmp_path: Path) -> None:
    probe = _Probe()

    def owned_spike(context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
        path = context.work_dir / "transient"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.ftruncate(descriptor, 20 * _GIB + 1)
        finally:
            os.close(descriptor)
        time.sleep(0.25)
        path.unlink()
        _checkpoint_all(context, probe, _phase_records("preparation"))
        return _result("preparation")

    with pytest.raises(EnronCapacityError) as raised:
        _run(tmp_path, probe, replacements={"preparation": owned_spike})
    assert raised.value.code == "owned_disk_limit"
    assert not (tmp_path / "capacity-run").exists()


def test_owned_disk_high_water_survives_successful_temporary_file_deletion(tmp_path: Path) -> None:
    probe = _Probe()

    def temporary(context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
        path = context.work_dir / "bounded-temporary"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.ftruncate(descriptor, _MIB)
        finally:
            os.close(descriptor)
        probe.advance_ns(10_000 * 1_000_000)
        context.checkpoint(10_000)
        path.unlink()
        completed = 10_000
        while completed < ENRON_SOURCE_ROWS:
            next_completed = min(ENRON_SOURCE_ROWS, completed + 10_000)
            probe.advance_ns((next_completed - completed) * 1_000_000)
            completed = next_completed
            context.checkpoint(completed)
        return _result("preparation")

    report, _ = _run(tmp_path, probe, replacements={"preparation": temporary})

    assert report["phases"][0]["owned_disk_high_water_bytes"] >= _MIB
    assert report["totals"]["owned_disk_high_water_bytes"] >= _MIB
    assert verify_capacity_report(report, require_production=False) == report


def test_missing_gapped_and_incomplete_progress_checkpoints_fail_closed(tmp_path: Path) -> None:
    no_checkpoint_probe = _Probe()

    def no_checkpoint(_context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
        no_checkpoint_probe.advance_ns(1_000_000_000)
        return _result("streaming_validation")

    with pytest.raises(EnronCapacityError) as omitted:
        _run(tmp_path, no_checkpoint_probe, name="omitted", replacements={"streaming_validation": no_checkpoint})
    assert omitted.value.code == "checkpoint_required"

    gap_probe = _Probe()

    def gap(context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
        gap_probe.advance_ns(1_000_000)
        context.checkpoint(10_001)
        return _result("build")

    with pytest.raises(EnronCapacityError) as gapped:
        _run(tmp_path, gap_probe, name="gapped", replacements={"build": gap})
    assert gapped.value.code == "checkpoint_gap"

    incomplete_probe = _Probe()

    def incomplete(context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
        incomplete_probe.advance_ns(1_000_000)
        context.checkpoint(10_000)
        return _result("build")

    with pytest.raises(EnronCapacityError) as incomplete_error:
        _run(tmp_path, incomplete_probe, name="incomplete", replacements={"build": incomplete})
    assert incomplete_error.value.code == "checkpoint_required"


def test_external_owned_root_and_phase_substitution_are_rejected(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    probe = _Probe()

    def external(context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
        context.declare_owned_root(outside)
        raise AssertionError("unreachable")

    with pytest.raises(EnronCapacityError) as external_error:
        _run(tmp_path, probe, name="external-root", replacements={"split": external})
    assert external_error.value.code == "owned_root_invalid"
    assert outside.is_dir()

    substitution_probe = _Probe()

    def substitute(context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
        moved = context.work_dir.with_name(context.work_dir.name + "-moved")
        context.work_dir.rename(moved)
        context.work_dir.symlink_to(moved, target_is_directory=True)
        time.sleep(0.01)
        context.checkpoint(1)
        return _result("preparation")

    with pytest.raises(EnronCapacityError):
        _run(tmp_path, substitution_probe, name="substitution", replacements={"preparation": substitute})
    assert not (tmp_path / "substitution").exists()
    assert outside.is_dir()


@pytest.mark.parametrize(
    ("exception_factory", "expected_code", "expected_outcome"),
    [
        (lambda: ValueError("private/value@example.test"), "phase_execution_failed", "failed"),
        (lambda: EnronCapacityError("private/value@example.test"), "phase_execution_failed", "failed"),
        (lambda: SystemExit("private/value@example.test"), "phase_interrupted", "interrupted"),
        (lambda: KeyboardInterrupt("private/value@example.test"), "phase_interrupted", "interrupted"),
    ],
)
def test_every_runner_exception_payload_is_sanitized_and_attempt_chain_is_append_only(
    tmp_path: Path,
    exception_factory: Callable[[], BaseException],
    expected_code: str,
    expected_outcome: str,
) -> None:
    probe = _Probe()
    name = (
        f"failure-{len(verify_capacity_attempt_ledger(tmp_path / 'attempts'))}"
        if (tmp_path / "attempts").exists()
        else "failure-0"
    )

    def fail(_context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
        raise exception_factory()

    with pytest.raises(EnronCapacityError) as raised:
        _run(tmp_path, probe, name=name, replacements={"build": fail})

    assert raised.value.code == expected_code
    assert "private/value" not in str(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert not (tmp_path / name).exists()
    _assert_no_stage(tmp_path, name)
    receipts = verify_capacity_attempt_ledger(tmp_path / "attempts")
    assert receipts[-1]["outcome"] == expected_outcome
    assert receipts[-1]["failure_code"] == expected_code
    assert receipts[-1]["sensitive_content_wiped"] is True
    assert receipts[-1]["path_tree_removed"] is False
    assert receipts[-1]["retained_private_tombstone_count"] == 1
    assert "private/value" not in json.dumps(receipts)
    assert [item["sequence"] for item in receipts] == list(range(1, len(receipts) + 1))
    for previous, current in zip(receipts, receipts[1:], strict=False):
        assert current["previous_attempt_sha256"] == previous["attempt_sha256"]


def test_repeated_failed_attempts_append_without_rewriting_prior_receipts(tmp_path: Path) -> None:
    first_payload: bytes | None = None
    for index in range(2):
        probe = _Probe()

        def fail(_context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
            raise ValueError("private-attempt-payload")

        with pytest.raises(EnronCapacityError):
            _run(tmp_path, probe, name=f"failed-{index}", replacements={"build": fail})
        first_path = tmp_path / "attempts" / "attempt-00000001.json"
        if first_payload is None:
            first_payload = first_path.read_bytes()
        else:
            assert first_path.read_bytes() == first_payload

    receipts = verify_capacity_attempt_ledger(tmp_path / "attempts")
    assert len(receipts) == 2
    assert receipts[1]["previous_attempt_sha256"] == receipts[0]["attempt_sha256"]
    assert [item["preexisting_private_tombstone_count"] for item in receipts] == [0, 1]
    assert [item["retained_private_tombstone_count"] for item in receipts] == [1, 1]
    assert len(list(tmp_path.glob(".nerb-cleanup-*"))) == 2
    assert "private-attempt-payload" not in json.dumps(receipts)


def test_retry_counts_payload_empty_tombstones_without_treating_them_as_active_stages(tmp_path: Path) -> None:
    probe = _Probe()

    def fail(_context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
        raise ValueError("private")

    with pytest.raises(EnronCapacityError):
        _run(tmp_path, probe, name="failed", replacements={"build": fail})
    tombstone = next(tmp_path.glob(".nerb-cleanup-*"))

    report, _probe = _run(tmp_path, name="retry")

    assert report["environment"]["preexisting_private_tombstone_count"] == 1
    receipts = verify_capacity_attempt_ledger(tmp_path / "attempts")
    assert [receipt["preexisting_private_tombstone_count"] for receipt in receipts] == [0, 1]
    assert [receipt["outcome"] for receipt in receipts] == ["failed", "passed"]
    assert tombstone.is_dir()
    assert not list(tmp_path.glob(".retry.stage-*"))


def test_private_tombstone_accumulation_is_bounded_before_phase_execution(tmp_path: Path) -> None:
    for index in range(enron_capacity.MAX_RETAINED_PRIVATE_TOMBSTONES + 1):
        (tmp_path / f".nerb-cleanup-{index:048x}").mkdir(mode=0o700)

    with pytest.raises(EnronCapacityError) as raised:
        _run(tmp_path)

    assert raised.value.code == "private_tree_invalid"
    assert not (tmp_path / "capacity-run").exists()
    _assert_no_stage(tmp_path, "capacity-run")
    receipt = verify_capacity_attempt_ledger(tmp_path / "attempts")[-1]
    assert receipt["outcome"] == "failed"
    assert receipt["failure_code"] == "private_tree_invalid"
    assert receipt["retained_private_tombstone_count"] == 0


def test_outer_capacity_cleanup_owns_child_outputs_and_stopped_writer_cache_through_later_failure(
    tmp_path: Path,
) -> None:
    probe = _Probe()
    parked_child = tmp_path / "parked-child-secret.txt"
    parked_cache = tmp_path / "parked-reader-cache.bin"

    def preparation(context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
        assert context.cleanup_successor is not None
        _checkpoint_all(context, probe, _phase_records("preparation"))
        with enron_capacity.PrivateRun(
            context.work_dir / "prepared",
            allow_unignored_output=True,
        ) as child:
            with child.open_text("secret.txt") as handle:
                handle.write("nested phase private payload")
            child.commit(cleanup_successor=context.cleanup_successor)
        # Move the committed child payload before the phase runner returns, so
        # the phase-boundary tree walk cannot discover it. Only descriptor
        # ownership transferred at child commit can wipe this inode later.
        (context.work_dir / "prepared" / "secret.txt").replace(parked_child)
        runtime = context.work_dir / "reader-runtime"
        runtime.mkdir(mode=0o700)
        cache = runtime / "source-cache.bin"
        cache.write_bytes(b"stopped third-party private cache")
        cache.chmod(0o600)
        return _result("preparation")

    def later_failure(context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
        preparation_root = context.work_dir.parent / "preparation"
        (preparation_root / "reader-runtime" / "source-cache.bin").replace(parked_cache)
        raise RuntimeError("injected later phase failure")

    with pytest.raises(EnronCapacityError) as raised:
        enron_capacity._run_enron_capacity_for_test(
            _options(tmp_path, "successor-run"),
            phase_runners=_successful_runners(
                probe,
                {"preparation": preparation, "split": later_failure},
            ),
            resource_probe=probe,
        )

    assert raised.value.code == "phase_execution_failed"
    assert parked_child.read_bytes() == b""
    assert parked_cache.read_bytes() == b""
    receipt = verify_capacity_attempt_ledger(tmp_path / "attempts")[-1]
    assert receipt["sensitive_content_wiped"] is True


def test_post_promotion_failure_wipes_registered_child_moved_out_of_promoted_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe = _Probe()
    output = tmp_path / "post-promotion-move"
    parked = tmp_path / "parked-post-promotion-secret.bin"

    def preparation(context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
        _checkpoint_all(context, probe, _phase_records("preparation"))
        payload = context.work_dir / "third-party-secret.bin"
        payload.write_bytes(b"private payload retained through terminal receipt")
        payload.chmod(0o600)
        return _result("preparation")

    original_enforce = enron_capacity._post_promotion_enforce

    def move_then_fail(*args: Any, **kwargs: Any) -> None:
        original_enforce(*args, **kwargs)
        (output / "phases" / "preparation" / "third-party-secret.bin").replace(parked)
        raise RuntimeError("injected post-promotion failure")

    monkeypatch.setattr(enron_capacity, "_post_promotion_enforce", move_then_fail)
    with pytest.raises(EnronCapacityError) as raised:
        enron_capacity._run_enron_capacity_for_test(
            _options(tmp_path, output.name),
            phase_runners=_successful_runners(probe, {"preparation": preparation}),
            resource_probe=probe,
        )

    assert raised.value.code == "capacity_failed"
    assert parked.read_bytes() == b""
    assert not output.exists()
    receipt = verify_capacity_attempt_ledger(tmp_path / "attempts")[-1]
    assert receipt["outcome"] == "failed"
    assert receipt["sensitive_content_wiped"] is True


def test_report_write_and_atomic_promotion_are_inside_enforced_attempt_accounting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_probe = _Probe()
    original_write = enron_capacity._write_report_and_fsync

    def slow_write(private_run: Any, payload: bytes) -> None:
        original_write(private_run, payload)
        report_probe.advance_ns(enron_capacity.MAX_TOTAL_RUNTIME_NS + 1)

    monkeypatch.setattr(enron_capacity, "_write_report_and_fsync", slow_write)
    with pytest.raises(EnronCapacityError) as report_error:
        _run(tmp_path, report_probe, name="slow-report")
    assert report_error.value.code == "runtime_limit"
    assert not (tmp_path / "slow-report").exists()
    assert verify_capacity_attempt_ledger(tmp_path / "attempts")[-1]["elapsed_ns"] > enron_capacity.MAX_TOTAL_RUNTIME_NS

    monkeypatch.setattr(enron_capacity, "_write_report_and_fsync", original_write)
    promotion_probe = _Probe()
    original_commit = enron_capacity.PrivateRun.commit

    def slow_commit(private_run: Any, *args: Any, **kwargs: Any) -> Path:
        result = original_commit(private_run, *args, **kwargs)
        promotion_probe.advance_ns(enron_capacity.MAX_TOTAL_RUNTIME_NS + 1)
        return result

    monkeypatch.setattr(enron_capacity.PrivateRun, "commit", slow_commit)
    with pytest.raises(EnronCapacityError) as promotion_error:
        _run(tmp_path, promotion_probe, name="slow-promotion")
    assert promotion_error.value.code == "runtime_limit"
    assert not (tmp_path / "slow-promotion").exists()
    assert verify_capacity_attempt_ledger(tmp_path / "attempts")[-1]["elapsed_ns"] > enron_capacity.MAX_TOTAL_RUNTIME_NS


@pytest.mark.parametrize("blocked_boundary", ["report", "promotion"])
def test_terminal_resource_observation_gap_is_enforced_outside_phases(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    blocked_boundary: str,
) -> None:
    probe = _Probe()
    wall_now = 1
    monkeypatch.setattr(enron_capacity.time, "monotonic_ns", lambda: wall_now)
    if blocked_boundary == "report":
        original_write = enron_capacity._write_report_and_fsync

        def block_report(private_run: Any, payload: bytes) -> None:
            nonlocal wall_now
            original_write(private_run, payload)
            wall_now += enron_capacity.MAX_RESOURCE_OBSERVATION_WALL_GAP_NS + 1

        monkeypatch.setattr(enron_capacity, "_write_report_and_fsync", block_report)
    else:
        original_commit = enron_capacity.PrivateRun.commit

        def block_promotion(private_run: Any, *args: Any, **kwargs: Any) -> Path:
            nonlocal wall_now
            promoted = original_commit(private_run, *args, **kwargs)
            wall_now += enron_capacity.MAX_RESOURCE_OBSERVATION_WALL_GAP_NS + 1
            return promoted

        monkeypatch.setattr(enron_capacity.PrivateRun, "commit", block_promotion)

    name = f"blocked-{blocked_boundary}"
    with pytest.raises(EnronCapacityError) as raised:
        _run(
            tmp_path,
            probe,
            name=name,
            monitor_interval_ns=1_000_000_000,
            wall_clock=enron_capacity.time.monotonic_ns,
        )

    assert raised.value.code == "resource_observation_gap"
    assert not (tmp_path / name).exists()
    receipt = verify_capacity_attempt_ledger(tmp_path / "attempts")[-1]
    assert receipt["failure_code"] == "resource_observation_gap"
    assert receipt["resource_observation_count"] > 0
    assert receipt["maximum_resource_observation_wall_gap_ns"] > enron_capacity.MAX_RESOURCE_OBSERVATION_WALL_GAP_NS


def test_terminal_resource_envelope_strictly_contains_pre_report_observations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe = _Probe()
    wall_now = 1
    post_report_free = 20 * _GIB
    post_promotion_rss = 256 * _MIB
    monkeypatch.setattr(enron_capacity.time, "monotonic_ns", lambda: wall_now)
    original_write = enron_capacity._write_report_and_fsync
    original_commit = enron_capacity.PrivateRun.commit

    def advance_after_report(private_run: Any, payload: bytes) -> None:
        nonlocal wall_now
        original_write(private_run, payload)
        wall_now += enron_capacity.MAX_RESOURCE_OBSERVATION_WALL_GAP_NS // 4
        probe.set_free(post_report_free)

    def advance_after_promotion(private_run: Any, *args: Any, **kwargs: Any) -> Path:
        nonlocal wall_now
        promoted = original_commit(private_run, *args, **kwargs)
        wall_now += enron_capacity.MAX_RESOURCE_OBSERVATION_WALL_GAP_NS // 4
        probe.set_rss(post_promotion_rss)
        return promoted

    monkeypatch.setattr(enron_capacity, "_write_report_and_fsync", advance_after_report)
    monkeypatch.setattr(enron_capacity.PrivateRun, "commit", advance_after_promotion)

    report, _ = _run(
        tmp_path,
        probe,
        monitor_interval_ns=1_000_000_000,
        wall_clock=enron_capacity.time.monotonic_ns,
    )
    terminal = verify_capacity_attempt_ledger(tmp_path / "attempts")[-1]
    totals = report["totals"]

    assert terminal["resource_observation_count"] > totals["resource_observation_count"]
    assert (
        totals["maximum_resource_observation_wall_gap_ns"]
        <= terminal["maximum_resource_observation_wall_gap_ns"]
        <= enron_capacity.MAX_RESOURCE_OBSERVATION_WALL_GAP_NS
    )
    assert terminal["peak_process_tree_rss_bytes"] == post_promotion_rss
    assert terminal["peak_process_tree_rss_bytes"] > totals["peak_process_tree_rss_bytes"]
    assert terminal["minimum_free_disk_bytes"] == post_report_free
    assert terminal["minimum_free_disk_bytes"] < totals["minimum_free_disk_bytes"]
    assert terminal["elapsed_ns"] >= totals["elapsed_ns"]
    verified = verify_capacity_run(tmp_path / "capacity-run", tmp_path / "attempts", require_production=False)
    assert verified["terminal_attempt"] == terminal


def test_verifier_rejects_rehashed_commitment_identity_privacy_and_replay_tampering(tmp_path: Path) -> None:
    report, _probe = _run(tmp_path)

    chain = copy.deepcopy(report)
    chain["phases"][3]["commitments"]["bank_sha256"] = _hash("different-bank")
    chain["phases"][3]["commitments_sha256"] = _canonical_hash(chain["phases"][3]["commitments"])
    _rehash_report(chain)
    with pytest.raises(EnronCapacityError):
        verify_capacity_report(chain, require_production=False)

    identity = copy.deepcopy(report)
    identity["execution"]["core_source_sha256"]["engine"] = _hash("different-engine")
    _rehash_report(identity)
    with pytest.raises(EnronCapacityError):
        verify_capacity_report(identity, require_production=False)

    replay = copy.deepcopy(report)
    replay["phases"][4]["commitments"]["replay_equal"] = False
    replay["phases"][4]["commitments_sha256"] = _canonical_hash(replay["phases"][4]["commitments"])
    _rehash_report(replay)
    with pytest.raises(EnronCapacityError):
        verify_capacity_report(replay, require_production=False)

    evidence_bound = copy.deepcopy(report)
    evidence_bound["phases"][1]["commitments"]["sealed_state"] = "EVIDENCE_BOUND"
    evidence_bound["phases"][1]["commitments_sha256"] = _canonical_hash(evidence_bound["phases"][1]["commitments"])
    _rehash_report(evidence_bound)
    with pytest.raises(EnronCapacityError):
        verify_capacity_report(evidence_bound, require_production=False)

    private = copy.deepcopy(report)
    private["phases"][0]["private_path"] = "/private/source"
    _rehash_report(private)
    with pytest.raises(EnronCapacityError):
        verify_capacity_report(private, require_production=False)


def test_attempt_ledger_tampering_and_report_symlink_substitution_fail_closed(tmp_path: Path) -> None:
    report, _probe = _run(tmp_path)
    receipt_path = tmp_path / "attempts" / "attempt-00000001.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["outcome"] = "failed"
    receipt_path.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    with pytest.raises(EnronCapacityError):
        verify_capacity_attempt_ledger(tmp_path / "attempts")

    root = tmp_path / "capacity-run"
    report_path = root / "capacity-report.json"
    outside = tmp_path / "outside-report.json"
    outside.write_text(json.dumps(report), encoding="utf-8")
    report_path.unlink()
    report_path.symlink_to(outside)
    with pytest.raises(EnronCapacityError):
        verify_capacity_run(root, tmp_path / "attempts", require_production=False)


def test_wrong_source_conservation_and_rehashed_arbitrary_aggregate_cannot_promote(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe = _Probe()
    bad = _commitments()["preparation"]
    bad["prepared_source_rows"] -= 1
    bad["source_conservation_sha256"] = _hash("attacker-chosen-conservation")
    monitors: list[enron_capacity._ContinuousResourceMonitor] = []
    monitor_threads: list[threading.Thread] = []
    stop_events: list[InterruptedStopEvent] = []
    cleanup_states: list[tuple[bool, bool, bool, bool]] = []
    original_start = enron_capacity._ContinuousResourceMonitor.start
    original_clear = enron_capacity._private_io._clear_pinned_private_directory
    stop_code = enron_capacity._ContinuousResourceMonitor.stop.__code__
    trace_injected = False

    class InterruptedStopEvent(threading.Event):
        def __init__(self, inner: threading.Event) -> None:
            super().__init__()
            self.inner = inner
            self.set_calls = 0

        def set(self) -> None:
            self.set_calls += 1
            if self.set_calls == 1:
                raise KeyboardInterrupt
            self.inner.set()

        def wait(self, timeout: float | None = None) -> bool:
            return self.inner.wait(timeout)

    def capture_start(monitor: enron_capacity._ContinuousResourceMonitor) -> None:
        original_start(monitor)
        thread = monitor._thread
        assert thread is not None
        stop_event = InterruptedStopEvent(monitor._stop)
        monitor._stop = stop_event
        monitor_threads.append(thread)
        stop_events.append(stop_event)
        monitors.append(monitor)

    def capture_cleanup(_directory_fd: int, directory_path: Path) -> bool:
        if monitors and not cleanup_states:
            monitor = monitors[-1]
            cleanup_states.append(
                (
                    monitor._thread is None,
                    not monitor_threads[-1].is_alive(),
                    not monitor._watchdog._installed,
                    monitor._stopped,
                )
            )
        return original_clear(_directory_fd, directory_path)

    def interrupt_stop_entry(frame: Any, event: str, _arg: Any) -> Any:
        nonlocal trace_injected
        if not trace_injected and event == "line" and frame.f_code is stop_code:
            trace_injected = True
            sys.settrace(None)
            raise KeyboardInterrupt
        return interrupt_stop_entry

    monkeypatch.setattr(enron_capacity._ContinuousResourceMonitor, "start", capture_start)
    monkeypatch.setattr(enron_capacity._private_io, "_clear_pinned_private_directory", capture_cleanup)

    def truncated(context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
        _checkpoint_all(context, probe, ENRON_SOURCE_ROWS)
        return _result("preparation", commitments=bad)

    sys.settrace(interrupt_stop_entry)
    try:
        with pytest.raises(EnronCapacityError) as raised:
            _run(tmp_path, probe, replacements={"preparation": truncated})
    finally:
        sys.settrace(None)
    assert trace_injected is True
    assert raised.value.code == "phase_commitment_invalid"
    assert not (tmp_path / "capacity-run").exists()
    assert [event.set_calls for event in stop_events] == [2]
    assert cleanup_states == [(True, True, True, True)]
    receipt = verify_capacity_attempt_ledger(tmp_path / "attempts")[-1]
    assert receipt["outcome"] == "failed"
    assert receipt["failure_code"] == "phase_commitment_invalid"
    assert receipt["sensitive_content_wiped"] is True
    assert receipt["retained_private_tombstone_count"] == 1
    tombstone = next(tmp_path.glob(".nerb-cleanup-*"))
    for path in (tombstone, *tombstone.rglob("*")):
        info = path.lstat()
        assert not stat.S_ISLNK(info.st_mode)
        if stat.S_ISREG(info.st_mode):
            assert info.st_size == 0


def test_private_run_exit_entry_interruption_retries_cleanup_before_failure_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe = _Probe()
    bad = _commitments()["preparation"]
    bad["prepared_source_rows"] -= 1
    bad["source_conservation_sha256"] = _hash("invalid-conservation")
    runs: list[enron_capacity.PrivateRun] = []
    original_enter = enron_capacity.PrivateRun.__enter__
    exit_code = enron_capacity.PrivateRun.__exit__.__code__
    trace_injected = False

    def capture_enter(run: enron_capacity.PrivateRun) -> enron_capacity.PrivateRun:
        entered = original_enter(run)
        runs.append(entered)
        return entered

    def interrupt_exit_entry(frame: Any, event: str, _arg: Any) -> Any:
        nonlocal trace_injected
        if not trace_injected and event == "line" and frame.f_code is exit_code:
            trace_injected = True
            sys.settrace(None)
            raise KeyboardInterrupt("private exit interrupted")
        return interrupt_exit_entry

    monkeypatch.setattr(enron_capacity.PrivateRun, "__enter__", capture_enter)

    def truncated(context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
        _checkpoint_all(context, probe, ENRON_SOURCE_ROWS)
        return _result("preparation", commitments=bad)

    sys.settrace(interrupt_exit_entry)
    try:
        with pytest.raises(EnronCapacityError) as raised:
            _run(tmp_path, probe, replacements={"preparation": truncated})
    finally:
        sys.settrace(None)

    assert trace_injected is True
    assert raised.value.code == "phase_commitment_invalid"
    assert len(runs) == 1
    run = runs[0]
    assert run._cleanup_is_settled() is True  # noqa: SLF001
    assert run.cleanup_sensitive_content_wiped is True
    assert not (tmp_path / "capacity-run").exists()
    _assert_no_stage(tmp_path, "capacity-run")
    receipt = verify_capacity_attempt_ledger(tmp_path / "attempts")[-1]
    assert receipt["outcome"] == "failed"
    assert receipt["failure_code"] == "phase_commitment_invalid"
    assert receipt["sensitive_content_wiped"] is True
    assert receipt["retained_private_tombstone_count"] == 1
    tombstone = next(tmp_path.glob(".nerb-cleanup-*"))
    for path in (tombstone, *tombstone.rglob("*")):
        if stat.S_ISREG(path.lstat().st_mode):
            assert path.stat().st_size == 0


def test_private_run_exit_boundary_entry_interruption_falls_back_before_failure_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe = _Probe()
    bad = _commitments()["preparation"]
    bad["prepared_source_rows"] -= 1
    bad["source_conservation_sha256"] = _hash("invalid-boundary-conservation")
    runs: list[enron_capacity.PrivateRun] = []
    original_enter = enron_capacity.PrivateRun.__enter__
    source_lines, source_start = inspect.getsourcelines(enron_capacity._execute_capacity_transaction)
    boundary_line = next(
        source_start + offset
        for offset, line in enumerate(source_lines)
        if "_settle_private_run_exit(private_run, transaction_error, exit_state)" in line
    )
    trace_injected = False

    def capture_enter(run: enron_capacity.PrivateRun) -> enron_capacity.PrivateRun:
        entered = original_enter(run)
        runs.append(entered)
        return entered

    def interrupt_exit_boundary(frame: Any, event: str, _arg: Any) -> Any:
        nonlocal trace_injected
        if (
            not trace_injected
            and event == "line"
            and frame.f_code is enron_capacity._execute_capacity_transaction.__code__
            and frame.f_lineno == boundary_line
        ):
            trace_injected = True
            sys.settrace(None)
            raise KeyboardInterrupt("private exit boundary interrupted")
        return interrupt_exit_boundary

    monkeypatch.setattr(enron_capacity.PrivateRun, "__enter__", capture_enter)

    def truncated(context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
        _checkpoint_all(context, probe, ENRON_SOURCE_ROWS)
        return _result("preparation", commitments=bad)

    sys.settrace(interrupt_exit_boundary)
    try:
        with pytest.raises(EnronCapacityError) as raised:
            _run(tmp_path, probe, replacements={"preparation": truncated})
    finally:
        sys.settrace(None)

    assert trace_injected is True
    assert raised.value.code == "phase_commitment_invalid"
    assert len(runs) == 1
    run = runs[0]
    assert run._cleanup_is_settled() is True  # noqa: SLF001
    assert run.cleanup_sensitive_content_wiped is True
    assert not (tmp_path / "capacity-run").exists()
    _assert_no_stage(tmp_path, "capacity-run")
    receipt = verify_capacity_attempt_ledger(tmp_path / "attempts")[-1]
    assert receipt["outcome"] == "failed"
    assert receipt["failure_code"] == "phase_commitment_invalid"
    assert receipt["sensitive_content_wiped"] is True
    assert receipt["retained_private_tombstone_count"] == 1


@pytest.mark.parametrize("interruption", ["post_helper", "post_record", "pre_record"])
def test_private_run_exit_failure_survives_post_settlement_control_interruption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    interruption: str,
) -> None:
    probe = _Probe()
    bad = _commitments()["preparation"]
    bad["prepared_source_rows"] -= 1
    bad["source_conservation_sha256"] = _hash("invalid-exit-failure-conservation")
    runs: list[enron_capacity.PrivateRun] = []
    original_enter = enron_capacity.PrivateRun.__enter__
    original_exit = enron_capacity.PrivateRun.__exit__
    original_remember = enron_capacity._PrivateRunExitState.remember
    exit_failed = False
    source_lines, source_start = inspect.getsourcelines(enron_capacity._execute_capacity_transaction)
    post_settlement_line = next(
        source_start + offset
        for offset, line in enumerate(source_lines)
        if "if exit_state.failure is not None:" in line
    )
    remember_lines, remember_start = inspect.getsourcelines(original_remember)
    pre_record_line = next(
        remember_start + offset for offset, line in enumerate(remember_lines) if "elif self.failure is None:" in line
    )
    trace_injected = False

    def capture_enter(run: enron_capacity.PrivateRun) -> enron_capacity.PrivateRun:
        entered = original_enter(run)
        runs.append(entered)
        return entered

    def settle_then_fail(
        run: enron_capacity.PrivateRun,
        exc_type: object,
        exc: object,
        traceback: object,
    ) -> None:
        nonlocal exit_failed
        original_exit(run, exc_type, exc, traceback)
        if not exit_failed:
            exit_failed = True
            raise enron_capacity.EnronPrivateIOError("injected private exit failure")

    def interrupt_post_settlement(frame: Any, event: str, _arg: Any) -> Any:
        nonlocal trace_injected
        if not trace_injected and event == "line":
            if (
                interruption == "post_helper"
                and frame.f_code is enron_capacity._execute_capacity_transaction.__code__
                and frame.f_lineno == post_settlement_line
            ):
                trace_injected = True
                sys.settrace(None)
                raise KeyboardInterrupt("post-settlement boundary interrupted")
            if (
                interruption == "pre_record"
                and frame.f_code is original_remember.__code__
                and frame.f_lineno == pre_record_line
            ):
                trace_injected = True
                sys.settrace(None)
                raise KeyboardInterrupt("pre-record exit state interrupted")
        return interrupt_post_settlement

    def remember_then_interrupt(state: Any, exc: BaseException) -> None:
        nonlocal trace_injected
        original_remember(state, exc)
        if (
            interruption == "post_record"
            and not trace_injected
            and not isinstance(exc, (KeyboardInterrupt, SystemExit, MemoryError))
        ):
            trace_injected = True
            raise KeyboardInterrupt("post-record exit state interrupted")

    monkeypatch.setattr(enron_capacity.PrivateRun, "__enter__", capture_enter)
    monkeypatch.setattr(enron_capacity.PrivateRun, "__exit__", settle_then_fail)
    if interruption == "post_record":
        monkeypatch.setattr(enron_capacity._PrivateRunExitState, "remember", remember_then_interrupt)

    def truncated(context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
        _checkpoint_all(context, probe, ENRON_SOURCE_ROWS)
        return _result("preparation", commitments=bad)

    if interruption in {"post_helper", "pre_record"}:
        sys.settrace(interrupt_post_settlement)
    try:
        with pytest.raises(EnronCapacityError) as raised:
            _run(tmp_path, probe, replacements={"preparation": truncated})
    finally:
        sys.settrace(None)

    assert trace_injected is True
    assert exit_failed is True
    assert raised.value.code == "capacity_failed"
    assert len(runs) == 1
    run = runs[0]
    assert run._cleanup_is_settled() is True  # noqa: SLF001
    assert run.cleanup_sensitive_content_wiped is True
    assert not (tmp_path / "capacity-run").exists()
    _assert_no_stage(tmp_path, "capacity-run")
    receipt = verify_capacity_attempt_ledger(tmp_path / "attempts")[-1]
    assert receipt["outcome"] == "failed"
    assert receipt["failure_code"] == "capacity_failed"
    assert receipt["sensitive_content_wiped"] is True


@pytest.mark.parametrize(
    "interruption",
    [
        "outer_handler",
        "promoted_wipe_entry",
        "after_authority_wipe",
        "after_promoted_wipe_return",
        "cleanup_metrics_publication",
        "tree_close_settled",
        "final_fallback_entry",
    ],
)
def test_post_promotion_control_uses_final_cleanup_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    interruption: str,
) -> None:
    source_lines, source_start = inspect.getsourcelines(enron_capacity._execute_capacity_transaction)
    outer_handler_line = next(
        source_start + offset
        for offset, line in enumerate(source_lines)
        if "effective_error = exit_state.failure if exit_state.failure is not None else exc" in line
    )
    wipe_lines, wipe_start = inspect.getsourcelines(enron_capacity._wipe_promoted_capacity_run)
    wipe_entry_line = next(
        wipe_start + offset for offset, line in enumerate(wipe_lines) if "authority_wiped = False" in line
    )
    after_authority_wipe_line = next(
        wipe_start + offset
        for offset, line in enumerate(wipe_lines)
        if "tree_cleanup = _remove_pinned_directory(" in line
    )
    after_promoted_wipe_return_line = next(
        source_start + offset for offset, line in enumerate(source_lines) if "promoted_cleanup_complete = True" in line
    )
    cleanup_metrics_publication_line = next(
        source_start + offset
        for offset, line in enumerate(source_lines)
        if "_publish_promoted_cleanup_metrics(metrics, promoted_cleanup_result)" in line
    )
    final_fallback_entry_line = next(
        source_start + offset for offset, line in enumerate(source_lines) if "final_error = sys.exc_info()[1]" in line
    )
    trace_injected = False
    original_tree_close = enron_capacity._PrivateTreeGuard.close

    def fail_after_promotion(*_args: Any, **_kwargs: Any) -> None:
        raise enron_capacity._error("runtime_disk_floor")

    def interrupt_recovery(frame: Any, event: str, _arg: Any) -> Any:
        nonlocal trace_injected
        if not trace_injected and event == "line":
            if (
                interruption == "outer_handler"
                and frame.f_code is enron_capacity._execute_capacity_transaction.__code__
                and frame.f_lineno == outer_handler_line
            ):
                trace_injected = True
                sys.settrace(None)
                raise KeyboardInterrupt("outer recovery interrupted")
            if (
                interruption == "promoted_wipe_entry"
                and frame.f_code is enron_capacity._wipe_promoted_capacity_run.__code__
                and frame.f_lineno == wipe_entry_line
            ):
                trace_injected = True
                sys.settrace(None)
                raise KeyboardInterrupt("promoted wipe interrupted")
            if (
                interruption == "after_authority_wipe"
                and frame.f_code is enron_capacity._wipe_promoted_capacity_run.__code__
                and frame.f_lineno == after_authority_wipe_line
            ):
                trace_injected = True
                sys.settrace(None)
                raise KeyboardInterrupt("promoted tree removal interrupted")
            if (
                interruption == "after_promoted_wipe_return"
                and frame.f_code is enron_capacity._execute_capacity_transaction.__code__
                and frame.f_lineno == after_promoted_wipe_return_line
            ):
                trace_injected = True
                sys.settrace(None)
                raise KeyboardInterrupt("promoted cleanup publication interrupted")
            if (
                interruption == "cleanup_metrics_publication"
                and frame.f_code is enron_capacity._execute_capacity_transaction.__code__
                and frame.f_lineno == cleanup_metrics_publication_line
            ):
                trace_injected = True
                sys.settrace(None)
                raise KeyboardInterrupt("promoted cleanup metrics interrupted")
            if (
                interruption == "final_fallback_entry"
                and frame.f_code is enron_capacity._execute_capacity_transaction.__code__
                and frame.f_lineno == final_fallback_entry_line
            ):
                trace_injected = True
                sys.settrace(None)
                raise KeyboardInterrupt("final fallback entry interrupted")
        return interrupt_recovery

    def close_then_interrupt(tree: Any) -> None:
        nonlocal trace_injected
        original_tree_close(tree)
        if not trace_injected:
            trace_injected = True
            raise KeyboardInterrupt("private tree close interrupted")

    monkeypatch.setattr(enron_capacity, "_post_promotion_enforce", fail_after_promotion)
    if interruption == "tree_close_settled":
        monkeypatch.setattr(enron_capacity._PrivateTreeGuard, "close", close_then_interrupt)
    else:
        sys.settrace(interrupt_recovery)
    try:
        with pytest.raises(EnronCapacityError) as raised:
            _run(tmp_path)
    finally:
        sys.settrace(None)

    assert trace_injected is True
    assert raised.value.code == "runtime_disk_floor"
    assert not (tmp_path / "capacity-run").exists()
    receipt = verify_capacity_attempt_ledger(tmp_path / "attempts")[-1]
    assert receipt["outcome"] == "failed"
    assert receipt["failure_code"] == "runtime_disk_floor"
    assert receipt["sensitive_content_wiped"] is True


def test_success_tree_close_control_wipes_promoted_run_before_interrupt_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_tree_close = enron_capacity._PrivateTreeGuard.close
    interrupted = False

    def close_then_interrupt(tree: Any) -> None:
        nonlocal interrupted
        original_tree_close(tree)
        if not interrupted:
            interrupted = True
            raise KeyboardInterrupt("successful tree close interrupted")

    monkeypatch.setattr(enron_capacity._PrivateTreeGuard, "close", close_then_interrupt)
    with pytest.raises(EnronCapacityError) as raised:
        _run(tmp_path)

    assert interrupted is True
    assert raised.value.code == "phase_interrupted"
    assert not (tmp_path / "capacity-run").exists()
    receipt = verify_capacity_attempt_ledger(tmp_path / "attempts")[-1]
    assert receipt["outcome"] == "interrupted"
    assert receipt["failure_code"] == "phase_interrupted"
    assert receipt["sensitive_content_wiped"] is True


def test_success_final_fallback_entry_control_uses_caller_owned_recovery(
    tmp_path: Path,
) -> None:
    source_lines, source_start = inspect.getsourcelines(enron_capacity._execute_capacity_transaction)
    final_entry_line = next(
        source_start + offset for offset, line in enumerate(source_lines) if "final_error = sys.exc_info()[1]" in line
    )
    trace_injected = False

    def interrupt_final_entry(frame: Any, event: str, _arg: Any) -> Any:
        nonlocal trace_injected
        if (
            not trace_injected
            and event == "line"
            and frame.f_code is enron_capacity._execute_capacity_transaction.__code__
            and frame.f_lineno == final_entry_line
        ):
            trace_injected = True
            sys.settrace(None)
            raise KeyboardInterrupt("final transaction cleanup interrupted")
        return interrupt_final_entry

    sys.settrace(interrupt_final_entry)
    try:
        with pytest.raises(EnronCapacityError) as raised:
            _run(tmp_path)
    finally:
        sys.settrace(None)

    assert trace_injected is True
    assert raised.value.code == "phase_interrupted"
    assert not (tmp_path / "capacity-run").exists()
    receipt = verify_capacity_attempt_ledger(tmp_path / "attempts")[-1]
    assert receipt["outcome"] == "interrupted"
    assert receipt["failure_code"] == "phase_interrupted"
    assert receipt["sensitive_content_wiped"] is True


def test_post_return_control_invalidates_recovered_completed_run_before_receipt(
    tmp_path: Path,
) -> None:
    source_lines, source_start = inspect.getsourcelines(enron_capacity._run_capacity_entry)
    post_return_line = next(
        source_start + offset for offset, line in enumerate(source_lines) if "report = completed_run.report" in line
    )
    trace_injected = False

    def interrupt_post_return(frame: Any, event: str, _arg: Any) -> Any:
        nonlocal trace_injected
        if (
            not trace_injected
            and event == "line"
            and frame.f_code is enron_capacity._run_capacity_entry.__code__
            and frame.f_lineno == post_return_line
        ):
            trace_injected = True
            sys.settrace(None)
            raise KeyboardInterrupt("post-return handoff interrupted")
        return interrupt_post_return

    sys.settrace(interrupt_post_return)
    try:
        with pytest.raises(EnronCapacityError) as raised:
            _run(tmp_path)
    finally:
        sys.settrace(None)

    assert trace_injected is True
    assert raised.value.code == "phase_interrupted"
    assert not (tmp_path / "capacity-run").exists()
    receipts = verify_capacity_attempt_ledger(tmp_path / "attempts")
    assert len(receipts) == 1
    assert receipts[0]["outcome"] == "interrupted"
    assert receipts[0]["failure_code"] == "phase_interrupted"
    assert receipts[0]["sensitive_content_wiped"] is True


def test_pre_receipt_control_uses_outer_caller_recovery_boundary(
    tmp_path: Path,
) -> None:
    source_lines, source_start = inspect.getsourcelines(enron_capacity._run_capacity_entry)
    pre_receipt_line = next(
        source_start + offset for offset, line in enumerate(source_lines) if "if failure_code is not None:" in line
    )
    trace_injected = False

    def interrupt_pre_receipt(frame: Any, event: str, _arg: Any) -> Any:
        nonlocal trace_injected
        if (
            not trace_injected
            and event == "line"
            and frame.f_code is enron_capacity._run_capacity_entry.__code__
            and frame.f_lineno == pre_receipt_line
        ):
            trace_injected = True
            sys.settrace(None)
            raise KeyboardInterrupt("pre-receipt handoff interrupted")
        return interrupt_pre_receipt

    sys.settrace(interrupt_pre_receipt)
    try:
        with pytest.raises(EnronCapacityError) as raised:
            _run(tmp_path)
    finally:
        sys.settrace(None)

    assert trace_injected is True
    assert raised.value.code == "phase_interrupted"
    assert not (tmp_path / "capacity-run").exists()
    receipts = verify_capacity_attempt_ledger(tmp_path / "attempts")
    assert len(receipts) == 1
    assert receipts[0]["outcome"] == "interrupted"
    assert receipts[0]["failure_code"] == "phase_interrupted"
    assert receipts[0]["sensitive_content_wiped"] is True


def test_failed_transaction_pre_receipt_control_preserves_semantic_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_lines, source_start = inspect.getsourcelines(enron_capacity._run_capacity_entry)
    pre_receipt_line = next(
        source_start + offset for offset, line in enumerate(source_lines) if "if failure_code is not None:" in line
    )
    trace_injected = False

    def fail_commitment_chain(*_args: Any, **_kwargs: Any) -> None:
        raise enron_capacity._CapacityAbort("phase_commitment_invalid")  # noqa: SLF001

    def interrupt_pre_receipt(frame: Any, event: str, _arg: Any) -> Any:
        nonlocal trace_injected
        if (
            not trace_injected
            and event == "line"
            and frame.f_code is enron_capacity._run_capacity_entry.__code__
            and frame.f_lineno == pre_receipt_line
        ):
            trace_injected = True
            sys.settrace(None)
            raise KeyboardInterrupt("failed transaction pre-receipt handoff interrupted")
        return interrupt_pre_receipt

    monkeypatch.setattr(enron_capacity, "_verify_phase_commitment_chain", fail_commitment_chain)
    sys.settrace(interrupt_pre_receipt)
    try:
        with pytest.raises(EnronCapacityError) as raised:
            _run(tmp_path)
    finally:
        sys.settrace(None)

    assert trace_injected is True
    assert raised.value.code == "phase_commitment_invalid"
    assert not (tmp_path / "capacity-run").exists()
    receipts = verify_capacity_attempt_ledger(tmp_path / "attempts")
    assert len(receipts) == 1
    assert receipts[0]["outcome"] == "failed"
    assert receipts[0]["failure_code"] == "phase_commitment_invalid"
    assert receipts[0]["sensitive_content_wiped"] is True


@pytest.mark.parametrize("reuse_kind", ["different_inode", "same_inode"])
@pytest.mark.parametrize("handoff", ["stage", "parent"])
def test_commit_descriptor_handoff_control_leaks_no_owner_descriptors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    handoff: str,
    reuse_kind: str,
) -> None:
    original_commit = enron_capacity.PrivateRun.commit
    original_native_close = enron_capacity._private_io._native_engine._close_fd_once  # noqa: SLF001
    close_injected = False
    sentinel_path = tmp_path / f"{handoff}-descriptor-sentinel"
    sentinel_path.write_bytes(b"sentinel")
    before_descriptors = _process_descriptor_inventory()
    target_descriptor: int | None = None
    same_inode_path: Path | None = None
    sentinel_descriptor: int | None = None
    sentinel_descriptors: list[int] = []

    def capture_commit_target(
        run: Any,
        *args: Any,
        **kwargs: Any,
    ) -> Path:
        nonlocal same_inode_path, target_descriptor
        target_descriptor = getattr(run, f"_{handoff}_fd")
        same_inode_path = run.final_dir if handoff == "stage" else run.final_dir.parent
        return original_commit(run, *args, **kwargs)

    def close_then_reuse(attempted: bytearray, descriptor: int) -> int:
        nonlocal close_injected, sentinel_descriptor
        close_errno = original_native_close(attempted, descriptor)
        if not close_injected and descriptor == target_descriptor:
            close_injected = True
            assert attempted == bytearray(b"\x01")
            assert same_inode_path is not None
            if reuse_kind == "same_inode":
                source_descriptor = os.open(same_inode_path, os.O_RDONLY | os.O_DIRECTORY)
            else:
                source_descriptor = os.open(sentinel_path, os.O_RDONLY)
            sentinel_descriptors.append(source_descriptor)
            if source_descriptor != descriptor:
                os.dup2(source_descriptor, descriptor)
                sentinel_descriptors.append(descriptor)
            sentinel_descriptor = descriptor
            raise KeyboardInterrupt("commit descriptor handoff interrupted")
        return close_errno

    monkeypatch.setattr(enron_capacity.PrivateRun, "commit", capture_commit_target)
    monkeypatch.setattr(enron_capacity._private_io._native_engine, "_close_fd_once", close_then_reuse)  # noqa: SLF001
    try:
        with pytest.raises(EnronCapacityError):
            _run(tmp_path)
        assert close_injected is True
        assert sentinel_descriptor is not None
        assert os.fstat(sentinel_descriptor)
    finally:
        monkeypatch.setattr(enron_capacity._private_io._native_engine, "_close_fd_once", original_native_close)  # noqa: SLF001
        for descriptor in dict.fromkeys(sentinel_descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass
    assert not (tmp_path / "capacity-run").exists()
    assert _process_descriptor_inventory() == before_descriptors
    receipt = verify_capacity_attempt_ledger(tmp_path / "attempts")[-1]
    assert receipt["sensitive_content_wiped"] is True


def test_post_commit_substitute_is_preserved_while_bound_payload_is_wiped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "capacity-run"
    moved = tmp_path / "moved-capacity-run"
    sentinel = output / "unrelated"
    original_commit = enron_capacity.PrivateRun.commit

    def substitute_after_commit(run: Any, *args: Any, **kwargs: Any) -> Path:
        original_commit(run, *args, **kwargs)
        output.rename(moved)
        output.mkdir(mode=0o700)
        sentinel.write_text("preserve", encoding="utf-8")
        sentinel.chmod(0o600)
        raise KeyboardInterrupt("post-commit substitute interruption")

    monkeypatch.setattr(enron_capacity.PrivateRun, "commit", substitute_after_commit)
    with pytest.raises(EnronCapacityError) as raised:
        _run(tmp_path)

    assert raised.value.code == "promotion_failed"
    assert sentinel.read_text(encoding="utf-8") == "preserve"
    assert (moved / "capacity-report.json").read_bytes() == b""
    receipt = verify_capacity_attempt_ledger(tmp_path / "attempts")[-1]
    assert receipt["failure_code"] == "promotion_failed"
    assert receipt["sensitive_content_wiped"] is True


def test_post_commit_moved_output_wipes_payload_before_path_recovery_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "capacity-run"
    moved = tmp_path / "moved-capacity-run"
    original_commit = enron_capacity.PrivateRun.commit

    def move_after_commit(run: Any, *args: Any, **kwargs: Any) -> Path:
        original_commit(run, *args, **kwargs)
        output.rename(moved)
        raise KeyboardInterrupt("post-commit moved output interruption")

    monkeypatch.setattr(enron_capacity.PrivateRun, "commit", move_after_commit)
    with pytest.raises(EnronCapacityError) as raised:
        _run(tmp_path)

    assert raised.value.code == "promotion_failed"
    assert not output.exists()
    assert (moved / "capacity-report.json").read_bytes() == b""
    receipt = verify_capacity_attempt_ledger(tmp_path / "attempts")[-1]
    assert receipt["failure_code"] == "promotion_failed"
    assert receipt["sensitive_content_wiped"] is True


def test_failed_moved_output_wipe_parks_authority_for_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "capacity-run"
    moved = tmp_path / "moved-capacity-run"
    original_commit = enron_capacity.PrivateRun.commit
    original_wipe = enron_capacity._private_io._wipe_authenticated_cleanup_descriptor
    fail_wipe = True

    def move_after_commit(run: Any, *args: Any, **kwargs: Any) -> Path:
        original_commit(run, *args, **kwargs)
        output.rename(moved)
        raise KeyboardInterrupt("post-commit failed moved wipe")

    def conditional_wipe(identity: tuple[int, int], descriptor: int) -> bool:
        if fail_wipe:
            return False
        return original_wipe(identity, descriptor)

    monkeypatch.setattr(enron_capacity.PrivateRun, "commit", move_after_commit)
    monkeypatch.setattr(enron_capacity._private_io, "_wipe_authenticated_cleanup_descriptor", conditional_wipe)
    with pytest.raises(EnronCapacityError) as raised:
        _run(tmp_path)

    assert raised.value.code == "promotion_failed"
    receipt = verify_capacity_attempt_ledger(tmp_path / "attempts")[-1]
    assert receipt["sensitive_content_wiped"] is False
    assert (moved / "capacity-report.json").stat().st_size > 0
    assert enron_capacity._private_io._UNRESOLVED_CLEANUP_FDS  # noqa: SLF001

    fail_wipe = False
    enron_capacity._private_io._retry_unresolved_cleanup_descriptors()  # noqa: SLF001
    assert (moved / "capacity-report.json").read_bytes() == b""
    assert not enron_capacity._private_io._UNRESOLVED_CLEANUP_FDS  # noqa: SLF001


def test_target_created_during_run_is_preserved_and_capacity_stage_is_removed(tmp_path: Path) -> None:
    probe = _Probe()
    target = tmp_path / "capacity-run"

    def substitute_target(context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
        _checkpoint_all(context, probe, _phase_records("deep_replay"))
        target.mkdir(mode=0o700)
        marker = target / "owner"
        marker.write_text("unrelated", encoding="utf-8")
        marker.chmod(0o600)
        return _result("deep_replay")

    with pytest.raises(EnronCapacityError):
        _run(tmp_path, probe, replacements={"deep_replay": substitute_target})
    assert (target / "owner").read_text(encoding="utf-8") == "unrelated"
    _assert_no_stage(tmp_path, "capacity-run")


def test_decision_verification_requires_unique_terminal_receipt_and_original_promoted_inode(tmp_path: Path) -> None:
    report, _probe = _run(tmp_path)
    run = tmp_path / "capacity-run"
    ledger = tmp_path / "attempts"
    assert verify_capacity_run(run, ledger, require_production=False)["report"] == report

    empty_ledger = tmp_path / "empty-attempts"
    empty_ledger.mkdir(mode=0o700)
    with pytest.raises(EnronCapacityError) as detached:
        verify_capacity_run(run, empty_ledger, require_production=False)
    assert detached.value.code == "decision_invalid"

    copied = tmp_path / "copied-capacity-run"
    shutil.copytree(run, copied)
    with pytest.raises(EnronCapacityError) as copied_error:
        verify_capacity_run(copied, ledger, require_production=False)
    assert copied_error.value.code == "decision_invalid"

    first = verify_capacity_attempt_ledger(ledger)[0]
    duplicate = copy.deepcopy(first)
    duplicate["sequence"] = 2
    duplicate["attempt_sequence"] = 2
    duplicate["attempt_nonce_sha256"] = _hash("duplicate-terminal-attempt")
    duplicate["previous_attempt_sha256"] = first["attempt_sha256"]
    duplicate["attempt_sha256"] = ""
    duplicate["attempt_sha256"] = enron_capacity._hash_attempt_receipt(duplicate)
    duplicate_path = ledger / "attempt-00000002.json"
    duplicate_path.write_bytes(enron_capacity._pretty_json_bytes(duplicate))
    duplicate_path.chmod(0o600)
    assert len(verify_capacity_attempt_ledger(ledger)) == 2
    with pytest.raises(EnronCapacityError) as duplicate_error:
        verify_capacity_run(run, ledger, require_production=False)
    assert duplicate_error.value.code == "decision_invalid"

    duplicate["attempt_sequence"] = 3
    duplicate["attempt_sha256"] = enron_capacity._hash_attempt_receipt(duplicate)
    duplicate_path.write_bytes(enron_capacity._pretty_json_bytes(duplicate))
    duplicate_path.chmod(0o600)
    with pytest.raises(EnronCapacityError):
        verify_capacity_attempt_ledger(ledger)


def test_ledger_no_follow_walk_rejects_symlink_component(tmp_path: Path) -> None:
    real = tmp_path / "real-ledger-parent"
    real.mkdir(mode=0o700)
    linked = tmp_path / "linked-ledger-parent"
    linked.symlink_to(real, target_is_directory=True)
    probe = _Probe()
    options = EnronCapacityOptions(
        output_dir=tmp_path / "capacity-run",
        attempt_ledger_dir=linked / "attempts",
        allow_unignored_output=True,
    )

    with pytest.raises(EnronCapacityError) as raised:
        enron_capacity._run_enron_capacity_for_test(
            options,
            phase_runners=_successful_runners(probe),
            resource_probe=probe,
        )

    assert raised.value.code == "attempt_ledger_invalid"
    assert not (real / "attempts").exists()
    assert not options.output_dir.exists()


@pytest.mark.parametrize(
    ("purpose", "create_final"),
    [
        ("run-verification", False),
        ("attempt-ledger", True),
        ("output-parent", False),
        ("portable-verification", False),
    ],
)
def test_existing_directory_pins_never_repair_unsafe_modes_or_touch_sentinels(
    tmp_path: Path,
    purpose: str,
    create_final: bool,
) -> None:
    target = tmp_path / purpose
    target.mkdir(mode=0o700)
    sentinel = target / "unrelated-sentinel"
    sentinel.write_text("preserve", encoding="utf-8")
    sentinel.chmod(0o600)
    target.chmod(0o755)

    with pytest.raises(EnronCapacityError):
        enron_capacity._PinnedDirectory(target, create_final=create_final)

    assert stat.S_IMODE(target.stat().st_mode) == 0o755
    assert sentinel.read_text(encoding="utf-8") == "preserve"
    assert stat.S_IMODE(sentinel.stat().st_mode) == 0o600


def test_run_ledger_output_parent_and_portable_read_paths_do_not_mutate_existing_directories(
    tmp_path: Path,
) -> None:
    run = tmp_path / "existing-run"
    ledger = tmp_path / "existing-ledger"
    output_parent = tmp_path / "existing-output-parent"
    roots = (run, ledger, output_parent)
    for root in roots:
        root.mkdir(mode=0o700)
        sentinel = root / "sentinel"
        sentinel.write_text(root.name, encoding="utf-8")
        sentinel.chmod(0o600)
        root.chmod(0o755)

    with pytest.raises(EnronCapacityError):
        verify_capacity_run(run, ledger, require_production=False)
    with pytest.raises(EnronCapacityError):
        verify_capacity_attempt_ledger(ledger)
    with pytest.raises(EnronCapacityError):
        enron_capacity._prepare_capacity_output(
            EnronCapacityOptions(
                output_dir=output_parent / "new-run",
                attempt_ledger_dir=ledger,
                allow_unignored_output=True,
            )
        )
    with pytest.raises(EnronCapacityError):
        export_capacity_decision(run, ledger, tmp_path / "portable.json", require_production=False)

    for root in roots:
        assert stat.S_IMODE(root.stat().st_mode) == 0o755
        assert (root / "sentinel").read_text(encoding="utf-8") == root.name


def test_attempt_allocation_sequences_must_be_contiguous_even_before_terminalization() -> None:
    terminal = {"attempt_sequence": 1, "attempt_nonce_sha256": _hash("terminal-nonce")}
    inflight = {"attempt_sequence": 3, "attempt_nonce": "a" * 64}

    with pytest.raises(EnronCapacityError):
        enron_capacity._validate_attempt_allocations([terminal], [("inflight", inflight)])


def test_overlapping_failed_attempt_is_rejected_while_the_live_marker_is_locked(tmp_path: Path) -> None:
    entered_preflight = threading.Event()
    release_preflight = threading.Event()
    errors: dict[int, str] = {}
    lock = threading.Lock()

    class BlockingPreflightProbe(_Probe):
        def physical_memory_bytes(self) -> int | None:
            entered_preflight.set()
            if not release_preflight.wait(timeout=5):
                raise RuntimeError("test preflight release timed out")
            return None

    def attempt(index: int, probe: _Probe) -> None:
        try:
            enron_capacity._run_enron_capacity_for_test(
                _options(tmp_path, f"failed-{index}"),
                phase_runners=_successful_runners(probe),
                resource_probe=probe,
            )
        except EnronCapacityError as exc:
            with lock:
                errors[index] = exc.code

    first = threading.Thread(target=attempt, args=(0, BlockingPreflightProbe()))
    second_probe = _Probe()
    second_probe.physical = None
    second = threading.Thread(target=attempt, args=(1, second_probe))
    first.start()
    try:
        assert entered_preflight.wait(timeout=5), "first attempt did not reach preflight with its marker live"
        second.start()
        second.join(timeout=10)
        assert not second.is_alive()
    finally:
        release_preflight.set()
    first.join(timeout=10)

    assert not first.is_alive()
    assert errors == {0: "preflight_memory", 1: "attempt_ledger_invalid"}
    receipts = verify_capacity_attempt_ledger(tmp_path / "attempts")
    assert [receipt["sequence"] for receipt in receipts] == [1]
    assert [receipt["attempt_sequence"] for receipt in receipts] == [1]
    assert receipts[0]["failure_code"] == "preflight_memory"
    assert receipts[0]["recovered_from_inflight"] is False
    _assert_attempt_ledger_files(tmp_path / "attempts")


def test_nonoverlapping_preflight_failures_each_append_a_terminal_receipt(tmp_path: Path) -> None:
    for index in range(2):
        probe = _Probe()
        probe.physical = None
        with pytest.raises(EnronCapacityError) as raised:
            enron_capacity._run_enron_capacity_for_test(
                _options(tmp_path, f"failed-{index}"),
                phase_runners=_successful_runners(probe),
                resource_probe=probe,
            )
        assert raised.value.code == "preflight_memory"

    receipts = verify_capacity_attempt_ledger(tmp_path / "attempts")
    assert [receipt["sequence"] for receipt in receipts] == [1, 2]
    assert [receipt["attempt_sequence"] for receipt in receipts] == [1, 2]
    assert [receipt["failure_code"] for receipt in receipts] == ["preflight_memory", "preflight_memory"]
    _assert_attempt_ledger_files(tmp_path / "attempts")


def test_stale_complete_atomic_attempt_temp_is_recovered_before_append(tmp_path: Path) -> None:
    _run(tmp_path)
    ledger = tmp_path / "attempts"
    first = verify_capacity_attempt_ledger(ledger)[0]
    stale = copy.deepcopy(first)
    stale.update(
        {
            "sequence": 2,
            "attempt_sequence": 2,
            "attempt_nonce_sha256": _hash("stale-complete-attempt"),
            "outcome": "failed",
            "failure_code": "capacity_failed",
            "previous_attempt_sha256": first["attempt_sha256"],
            "attempt_sha256": "",
        }
    )
    stale["attempt_sha256"] = enron_capacity._hash_attempt_receipt(stale)
    temporary = ledger / (".attempt-stage-" + "a" * 64 + ".tmp")
    temporary.write_bytes(enron_capacity._pretty_json_bytes(stale))
    temporary.chmod(0o600)

    probe = _Probe()
    probe.physical = None
    with pytest.raises(EnronCapacityError, match="physical-memory"):
        enron_capacity._run_enron_capacity_for_test(
            _options(tmp_path, "failed-after-stale"),
            phase_runners=_successful_runners(probe),
            resource_probe=probe,
        )

    assert not temporary.exists()
    receipts = verify_capacity_attempt_ledger(ledger)
    assert len(receipts) == 2
    assert receipts[-1]["failure_code"] == "preflight_memory"


def test_sigkill_after_stage_is_recovered_once_and_exact_stage_is_cleaned(tmp_path: Path) -> None:
    process, _ready = _start_crashing_capacity_attempt(tmp_path)
    ledger = tmp_path / "attempts"
    inflight_payloads = [
        path.read_text(encoding="utf-8")
        for path in ledger.glob(".attempt-inflight-*.json")
        if not path.name.endswith(".stage.json")
    ]
    binding_payloads = [path.read_text(encoding="utf-8") for path in ledger.glob(".attempt-inflight-*.stage.json")]
    assert len(inflight_payloads) == len(binding_payloads) == 1
    assert os.fspath(tmp_path) not in "".join(inflight_payloads + binding_payloads)
    assert len(list(tmp_path.glob(".crash-run.stage-*"))) == 1

    os.kill(process.pid, signal.SIGKILL)
    assert process.wait(timeout=5) == -signal.SIGKILL

    report, _probe = _run(tmp_path, name="crash-run")
    receipts = verify_capacity_attempt_ledger(ledger)
    assert report["gates"]["passed"] is True
    assert [(item["sequence"], item["attempt_sequence"], item["outcome"]) for item in receipts] == [
        (1, 1, "interrupted"),
        (2, 2, "passed"),
    ]
    assert receipts[0]["recovered_from_inflight"] is True
    assert receipts[0]["failure_code"] == "phase_interrupted"
    assert receipts[0]["sensitive_content_wiped"] is False
    assert receipts[0]["path_tree_removed"] is False
    assert receipts[0]["retained_private_tombstone_count"] == 1
    assert receipts[1]["recovered_from_inflight"] is False
    assert not list(tmp_path.glob(".crash-run.stage-*"))
    _assert_attempt_ledger_files(ledger)

    enron_capacity._recover_worker_inflight(_options(tmp_path, "crash-run"))
    assert verify_capacity_attempt_ledger(ledger) == receipts


def test_parent_timeout_recovery_terminalizes_crashed_attempt_without_starting_a_successor(tmp_path: Path) -> None:
    process, _ready = _start_crashing_capacity_attempt(tmp_path, name="timeout-run")
    with pytest.raises(subprocess.TimeoutExpired):
        process.wait(timeout=0.05)
    process.kill()
    process.wait(timeout=5)

    options = _options(tmp_path, "timeout-run")
    enron_capacity._recover_worker_inflight(options)
    receipts = verify_capacity_attempt_ledger(tmp_path / "attempts")
    assert len(receipts) == 1
    assert receipts[0]["outcome"] == "interrupted"
    assert receipts[0]["recovered_from_inflight"] is True
    assert receipts[0]["sensitive_content_wiped"] is False
    assert receipts[0]["path_tree_removed"] is False
    assert receipts[0]["retained_private_tombstone_count"] == 1
    assert not options.output_dir.exists()
    _assert_no_stage(tmp_path, "timeout-run")
    _assert_attempt_ledger_files(options.attempt_ledger_dir)

    enron_capacity._recover_worker_inflight(options)
    assert verify_capacity_attempt_ledger(tmp_path / "attempts") == receipts


def test_live_inflight_owner_cannot_be_stolen_by_recovery(tmp_path: Path) -> None:
    process, _ready = _start_crashing_capacity_attempt(tmp_path, name="live-owner")
    options = _options(tmp_path, "live-owner")
    try:
        with pytest.raises(EnronCapacityError) as recovery_error:
            enron_capacity._recover_worker_inflight(options)
        assert recovery_error.value.code == "production_worker_failed"
        with pytest.raises(EnronCapacityError) as successor_error:
            _run(tmp_path, name="live-owner")
        assert successor_error.value.code == "attempt_ledger_invalid"
        with pytest.raises(EnronCapacityError, match="attempt ledger"):
            verify_capacity_attempt_ledger(options.attempt_ledger_dir)
        assert not list(options.attempt_ledger_dir.glob("attempt-*.json"))
        assert len(list(tmp_path.glob(".live-owner.stage-*"))) == 1
        assert process.poll() is None
    finally:
        process.kill()
        process.wait(timeout=5)

    enron_capacity._recover_worker_inflight(options)
    receipts = verify_capacity_attempt_ledger(options.attempt_ledger_dir)
    assert len(receipts) == 1
    assert receipts[0]["recovered_from_inflight"] is True


def test_crash_before_stage_binding_cleans_only_the_authentic_empty_stage(tmp_path: Path) -> None:
    _process, options, _ready = _start_terminal_crash_attempt(tmp_path, crash_point="pre_binding")
    assert len(list(tmp_path.glob(f".{options.output_dir.name}.stage-*"))) == 1
    assert not list(options.attempt_ledger_dir.glob(".attempt-inflight-*.stage.json"))

    enron_capacity._recover_worker_inflight(options)

    receipts = verify_capacity_attempt_ledger(options.attempt_ledger_dir)
    assert len(receipts) == 1
    assert receipts[0]["outcome"] == "interrupted"
    assert receipts[0]["recovered_from_inflight"] is True
    assert receipts[0]["sensitive_content_wiped"] is True
    assert receipts[0]["path_tree_removed"] is False
    assert receipts[0]["retained_private_tombstone_count"] == 1
    assert not options.output_dir.exists()
    _assert_no_stage(tmp_path, options.output_dir.name)


def test_unbound_stage_substitution_is_preserved_and_blocks_recovery(tmp_path: Path) -> None:
    _process, options, _ready = _start_terminal_crash_attempt(tmp_path, crash_point="pre_binding")
    original = next(tmp_path.glob(f".{options.output_dir.name}.stage-*"))
    moved = tmp_path / "moved-unbound-stage"
    original.rename(moved)
    original.mkdir(mode=0o700)
    sentinel = original / "preserve"
    sentinel.write_text("unrelated", encoding="utf-8")
    sentinel.chmod(0o600)

    with pytest.raises(EnronCapacityError) as raised:
        enron_capacity._recover_worker_inflight(options)

    assert raised.value.code == "production_worker_failed"
    assert sentinel.read_text(encoding="utf-8") == "unrelated"
    assert moved.is_dir()
    assert [
        path
        for path in options.attempt_ledger_dir.glob(".attempt-inflight-*.json")
        if not path.name.endswith(".stage.json")
    ]


def test_capacity_recovery_rolls_back_an_empty_root_swap_without_deleting_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _process, options, _ready = _start_terminal_crash_attempt(tmp_path, crash_point="pre_binding")
    stage = next(tmp_path.glob(f".{options.output_dir.name}.stage-*"))
    moved = tmp_path / "moved-empty-capacity-stage"
    real_quarantine = enron_capacity._private_io._rename_cleanup_entry_at
    swapped = False

    def swap_empty_root(
        parent_fd: int,
        parent_path: Path,
        source_name: str,
        destination_name: str,
    ) -> None:
        nonlocal swapped
        if source_name == stage.name and destination_name.startswith(".nerb-cleanup-") and not swapped:
            swapped = True
            stage.rename(moved)
            stage.mkdir(mode=0o700)
        real_quarantine(parent_fd, parent_path, source_name, destination_name)

    monkeypatch.setattr(enron_capacity._private_io, "_rename_cleanup_entry_at", swap_empty_root)
    with pytest.raises(EnronCapacityError) as raised:
        enron_capacity._recover_worker_inflight(options)

    assert raised.value.code == "production_worker_failed"
    assert stage.is_dir() and not list(stage.iterdir())
    assert moved.is_dir() and not list(moved.iterdir())
    assert [
        path
        for path in options.attempt_ledger_dir.glob(".attempt-inflight-*.json")
        if not path.name.endswith(".stage.json")
    ]


def test_capacity_recovery_retains_empty_file_shells_and_never_calls_name_delete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process, _ready = _start_crashing_capacity_attempt(tmp_path, name="file-swap")
    process.kill()
    process.wait(timeout=5)
    stage = next(tmp_path.glob(".file-swap.stage-*"))
    source = stage / "secret.txt"
    source.write_text("private", encoding="utf-8")
    source.chmod(0o600)
    real_ftruncate = enron_capacity._private_io.os.ftruncate
    swapped = False
    delete_calls: list[str] = []

    def truncate_then_swap(descriptor: int, length: int) -> None:
        nonlocal swapped
        real_ftruncate(descriptor, length)
        if not swapped:
            swapped = True
            source.rename(stage / "moved-authentic.txt")
            source.write_bytes(b"")
            source.chmod(0o600)

    def forbidden_delete(_parent_fd: int, _parent_path: Path, name: str) -> None:
        delete_calls.append(name)
        raise AssertionError("capacity cleanup must retain wiped tombstones")

    monkeypatch.setattr(enron_capacity._private_io.os, "ftruncate", truncate_then_swap)
    monkeypatch.setattr(enron_capacity._private_io, "_unlink_at", forbidden_delete)
    monkeypatch.setattr(enron_capacity._private_io, "_rmdir_at", forbidden_delete)

    options = _options(tmp_path, "file-swap")
    enron_capacity._recover_worker_inflight(options)

    tombstone = next(tmp_path.glob(".nerb-cleanup-*"))
    assert (tombstone / "secret.txt").read_bytes() == b""
    assert (tombstone / "moved-authentic.txt").read_bytes() == b""
    assert delete_calls == []
    receipt = verify_capacity_attempt_ledger(options.attempt_ledger_dir)[0]
    assert receipt["sensitive_content_wiped"] is False
    assert receipt["path_tree_removed"] is False
    assert receipt["retained_private_tombstone_count"] == 1


def test_capacity_recovery_retains_both_empty_directory_shells_after_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process, _ready = _start_crashing_capacity_attempt(tmp_path, name="directory-swap")
    process.kill()
    process.wait(timeout=5)
    stage = next(tmp_path.glob(".directory-swap.stage-*"))
    child = stage / "swap-child"
    child.mkdir(mode=0o700)
    secret = child / "secret.txt"
    secret.write_text("private", encoding="utf-8")
    secret.chmod(0o600)
    real_clear = enron_capacity._private_io._clear_pinned_private_directory
    swapped = False

    def clear_then_swap(directory_fd: int, directory_path: Path) -> bool:
        nonlocal swapped
        cleared = real_clear(directory_fd, directory_path)
        if directory_path.name == child.name and not swapped:
            swapped = True
            child.rename(stage / "moved-child")
            child.mkdir(mode=0o700)
        return cleared

    monkeypatch.setattr(enron_capacity._private_io, "_clear_pinned_private_directory", clear_then_swap)
    options = _options(tmp_path, "directory-swap")

    enron_capacity._recover_worker_inflight(options)

    tombstone = next(tmp_path.glob(".nerb-cleanup-*"))
    assert (tombstone / "swap-child").is_dir()
    assert not list((tombstone / "swap-child").iterdir())
    assert (tombstone / "moved-child" / "secret.txt").read_bytes() == b""
    receipt = verify_capacity_attempt_ledger(options.attempt_ledger_dir)[0]
    assert receipt["retained_private_tombstone_count"] == 1


def test_stale_stage_substitution_is_rejected_and_never_deleted(tmp_path: Path) -> None:
    process, _ready = _start_crashing_capacity_attempt(tmp_path, name="substituted-crash")
    process.kill()
    process.wait(timeout=5)
    original = next(tmp_path.glob(".substituted-crash.stage-*"))
    moved = tmp_path / "moved-original-stage"
    original.rename(moved)
    original.mkdir(mode=0o700)
    sentinel = original / "preserve"
    sentinel.write_text("unrelated", encoding="utf-8")
    sentinel.chmod(0o600)

    with pytest.raises(EnronCapacityError) as raised:
        enron_capacity._recover_worker_inflight(_options(tmp_path, "substituted-crash"))

    assert raised.value.code == "production_worker_failed"
    assert sentinel.read_text(encoding="utf-8") == "unrelated"
    assert moved.is_dir()
    assert [
        path
        for path in (tmp_path / "attempts").glob(".attempt-inflight-*.json")
        if not path.name.endswith(".stage.json")
    ]


def test_crash_after_promotion_before_receipt_removes_bound_output_and_records_one_interruption(tmp_path: Path) -> None:
    _process, options, _ready = _start_terminal_crash_attempt(tmp_path, crash_point="post_promotion")
    assert options.output_dir.is_dir()
    with pytest.raises(EnronCapacityError, match="attempt ledger"):
        verify_capacity_attempt_ledger(options.attempt_ledger_dir)
    assert not list(options.attempt_ledger_dir.glob("attempt-*.json"))

    enron_capacity._recover_worker_inflight(options)

    receipts = verify_capacity_attempt_ledger(options.attempt_ledger_dir)
    assert len(receipts) == 1
    assert receipts[0]["outcome"] == "interrupted"
    assert receipts[0]["recovered_from_inflight"] is True
    assert receipts[0]["sensitive_content_wiped"] is True
    assert receipts[0]["path_tree_removed"] is False
    assert receipts[0]["retained_private_tombstone_count"] == 1
    assert not options.output_dir.exists()
    _assert_no_stage(tmp_path, options.output_dir.name)


def test_crash_recovery_reports_false_when_inventory_child_moved_after_process_death(tmp_path: Path) -> None:
    _process, options, _ready = _start_terminal_crash_attempt(tmp_path, crash_point="post_promotion_payload")
    source = options.output_dir / "phases" / "preparation" / "crash-secret.bin"
    parked = tmp_path / "parked-crash-secret.bin"
    expected = source.read_bytes()
    source.replace(parked)

    enron_capacity._recover_worker_inflight(options)

    receipts = verify_capacity_attempt_ledger(options.attempt_ledger_dir)
    assert len(receipts) == 1
    assert receipts[0]["outcome"] == "interrupted"
    assert receipts[0]["recovered_from_inflight"] is True
    assert receipts[0]["sensitive_content_wiped"] is False
    assert parked.read_bytes() == expected
    assert not options.output_dir.exists()
    _assert_no_stage(tmp_path, options.output_dir.name)


def test_crash_recovery_retained_inventory_fd_wipes_child_moved_after_authentication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _process, options, _ready = _start_terminal_crash_attempt(tmp_path, crash_point="post_promotion_payload")
    source = options.output_dir / "phases" / "preparation" / "crash-secret.bin"
    parked = tmp_path / "parked-after-recovery-authentication.bin"
    original_wipe = enron_capacity._private_io._wipe_authenticated_cleanup_descriptor
    moved = False

    def move_then_wipe(identity: tuple[int, int], descriptor: int) -> bool:
        nonlocal moved
        if not moved:
            moved = True
            source.replace(parked)
        return original_wipe(identity, descriptor)

    monkeypatch.setattr(
        enron_capacity._private_io,
        "_wipe_authenticated_cleanup_descriptor",
        move_then_wipe,
    )
    enron_capacity._recover_worker_inflight(options)

    receipt = verify_capacity_attempt_ledger(options.attempt_ledger_dir)[0]
    assert moved is True
    assert receipt["outcome"] == "interrupted"
    assert receipt["sensitive_content_wiped"] is True
    assert parked.read_bytes() == b""
    assert not options.output_dir.exists()


def test_crash_recovery_parks_failed_moved_inventory_until_later_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _process, options, _ready = _start_terminal_crash_attempt(tmp_path, crash_point="post_promotion_payload")
    source = options.output_dir / "phases" / "preparation" / "crash-secret.bin"
    parked = tmp_path / "parked-after-failed-recovery-wipe.bin"
    expected = source.read_bytes()
    original_wipe = enron_capacity._private_io._wipe_authenticated_cleanup_descriptor
    fail_wipe = True
    moved = False

    def move_then_maybe_fail(identity: tuple[int, int], descriptor: int) -> bool:
        nonlocal moved
        if not moved:
            moved = True
            source.replace(parked)
        if fail_wipe:
            return False
        return original_wipe(identity, descriptor)

    monkeypatch.setattr(
        enron_capacity._private_io,
        "_wipe_authenticated_cleanup_descriptor",
        move_then_maybe_fail,
    )
    try:
        with pytest.raises(EnronCapacityError) as blocked:
            enron_capacity._recover_worker_inflight(options)
        assert blocked.value.code == "production_worker_failed"
        assert parked.read_bytes() == expected
        assert not list(options.attempt_ledger_dir.glob("attempt-*.json"))
        assert list(options.attempt_ledger_dir.glob(".attempt-inflight-*.json"))
        assert len(enron_capacity._private_io._UNRESOLVED_CLEANUP_FDS) == 1  # noqa: SLF001

        fail_wipe = False
        enron_capacity._recover_worker_inflight(options)

        receipts = verify_capacity_attempt_ledger(options.attempt_ledger_dir)
        assert len(receipts) == 1
        assert receipts[0]["outcome"] == "interrupted"
        assert receipts[0]["sensitive_content_wiped"] is False
        assert parked.read_bytes() == b""
        assert not list(options.attempt_ledger_dir.glob(".attempt-inflight-*.json"))
        assert not enron_capacity._private_io._UNRESOLVED_CLEANUP_FDS  # noqa: SLF001
    finally:
        fail_wipe = False
        enron_capacity._private_io._retry_unresolved_cleanup_descriptors()  # noqa: SLF001


@pytest.mark.parametrize("control_error", [KeyboardInterrupt, SystemExit])
def test_crash_inventory_helper_return_interruption_keeps_map_owned_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    control_error: type[BaseException],
) -> None:
    _process, options, _ready = _start_terminal_crash_attempt(tmp_path, crash_point="post_promotion_payload")
    source = options.output_dir / "phases" / "preparation" / "crash-secret.bin"
    parked = tmp_path / "parked-after-inventory-helper-return.bin"
    expected = source.read_bytes()
    real_open_cleanup = enron_capacity._private_io._open_cleanup_descriptor_at
    interrupted = False

    def open_then_interrupt(
        directory_fd: int,
        directory_path: Path,
        name: str,
        flags: int,
        *,
        expected_identity: tuple[int, int],
        target: dict[tuple[int, int], int],
    ) -> None:
        nonlocal interrupted
        real_open_cleanup(
            directory_fd,
            directory_path,
            name,
            flags,
            expected_identity=expected_identity,
            target=target,
        )
        if name == source.name and not interrupted:
            interrupted = True
            source.replace(parked)
            raise control_error("injected crash inventory helper return interruption")

    monkeypatch.setattr(enron_capacity._private_io, "_open_cleanup_descriptor_at", open_then_interrupt)
    with pytest.raises(EnronCapacityError) as interrupted_recovery:
        enron_capacity._recover_worker_inflight(options)

    assert interrupted_recovery.value.code == "production_worker_failed"
    assert interrupted
    assert parked.read_bytes() == expected
    assert not list(options.attempt_ledger_dir.glob("attempt-*.json"))
    assert list(options.attempt_ledger_dir.glob(".attempt-inflight-*.json"))
    assert enron_capacity._private_io._UNRESOLVED_CLEANUP_FDS  # noqa: SLF001
    assert enron_capacity._private_io._LIVE_CLEANUP_FDS == len(  # noqa: SLF001
        enron_capacity._private_io._UNRESOLVED_CLEANUP_FDS  # noqa: SLF001
    )
    monkeypatch.setattr(enron_capacity._private_io, "_open_cleanup_descriptor_at", real_open_cleanup)

    enron_capacity._recover_worker_inflight(options)

    receipt = verify_capacity_attempt_ledger(options.attempt_ledger_dir)[0]
    assert receipt["outcome"] == "interrupted"
    assert receipt["sensitive_content_wiped"] is False
    assert parked.read_bytes() == b""
    assert not enron_capacity._private_io._UNRESOLVED_CLEANUP_FDS  # noqa: SLF001
    assert enron_capacity._private_io._LIVE_CLEANUP_FDS == 0  # noqa: SLF001


@pytest.mark.parametrize("control_error", [KeyboardInterrupt, SystemExit])
def test_crash_inventory_line_interruption_after_durable_retention_keeps_global_authority(
    tmp_path: Path,
    control_error: type[BaseException],
) -> None:
    _process, options, _ready = _start_terminal_crash_attempt(tmp_path, crash_point="post_promotion_payload")
    source = options.output_dir / "phases" / "preparation" / "crash-secret.bin"
    parked = tmp_path / "parked-after-inventory-retention-line.bin"
    expected = source.read_bytes()
    source_info = source.stat()
    source_identity = int(source_info.st_dev), int(source_info.st_ino)
    collector_code = enron_capacity._private_io._collect_cleanup_inventory_descriptors.__code__
    interrupted = False

    def interrupt_after_durable_retention(frame: Any, event: str, _argument: Any) -> Any:
        nonlocal interrupted
        if (
            frame.f_code is collector_code
            and event == "line"
            and not interrupted
            and source_identity in enron_capacity._private_io._UNRESOLVED_CLEANUP_FDS  # noqa: SLF001
            and frame.f_locals.get("retained_descriptor")
            == enron_capacity._private_io._UNRESOLVED_CLEANUP_FDS.get(source_identity)  # noqa: SLF001
        ):
            interrupted = True
            source.replace(parked)
            raise control_error("injected crash inventory durable-retention line interruption")
        return interrupt_after_durable_retention

    sys.settrace(interrupt_after_durable_retention)
    try:
        with pytest.raises(EnronCapacityError) as interrupted_recovery:
            enron_capacity._recover_worker_inflight(options)
    finally:
        sys.settrace(None)

    assert interrupted_recovery.value.code == "production_worker_failed"
    assert interrupted
    assert parked.read_bytes() == expected
    assert source_identity in enron_capacity._private_io._UNRESOLVED_CLEANUP_FDS  # noqa: SLF001
    assert enron_capacity._private_io._LIVE_CLEANUP_FDS == len(  # noqa: SLF001
        enron_capacity._private_io._UNRESOLVED_CLEANUP_FDS  # noqa: SLF001
    )
    assert not list(options.attempt_ledger_dir.glob("attempt-*.json"))
    assert list(options.attempt_ledger_dir.glob(".attempt-inflight-*.json"))

    enron_capacity._recover_worker_inflight(options)

    receipt = verify_capacity_attempt_ledger(options.attempt_ledger_dir)[0]
    assert receipt["outcome"] == "interrupted"
    assert receipt["sensitive_content_wiped"] is False
    assert parked.read_bytes() == b""
    assert not enron_capacity._private_io._UNRESOLVED_CLEANUP_FDS  # noqa: SLF001
    assert enron_capacity._private_io._LIVE_CLEANUP_FDS == 0  # noqa: SLF001


def test_crash_after_receipt_before_inflight_removal_preserves_exactly_one_passed_decision(tmp_path: Path) -> None:
    _process, options, _ready = _start_terminal_crash_attempt(tmp_path, crash_point="after_receipt")
    before_payload = (options.attempt_ledger_dir / "attempt-00000001.json").read_bytes()
    before = json.loads(before_payload)
    assert before["outcome"] == "passed"
    with pytest.raises(EnronCapacityError, match="attempt ledger"):
        verify_capacity_attempt_ledger(options.attempt_ledger_dir)
    assert options.output_dir.is_dir()

    enron_capacity._recover_worker_inflight(options)

    after = verify_capacity_attempt_ledger(options.attempt_ledger_dir)
    assert after == [before]
    assert (options.attempt_ledger_dir / "attempt-00000001.json").read_bytes() == before_payload
    assert (
        verify_capacity_run(options.output_dir, options.attempt_ledger_dir, require_production=False)[
            "terminal_attempt"
        ]
        == before
    )
    _assert_attempt_ledger_files(options.attempt_ledger_dir)


def test_crash_after_durable_binding_removal_recovers_from_marker_and_terminal_receipt(tmp_path: Path) -> None:
    _process, options, _ready = _start_terminal_crash_attempt(tmp_path, crash_point="after_receipt")
    before = json.loads((options.attempt_ledger_dir / "attempt-00000001.json").read_bytes())
    binding = next(options.attempt_ledger_dir.glob(".attempt-inflight-*.stage.json"))
    cleanup_inventory = next(options.attempt_ledger_dir.glob(".attempt-inflight-*.cleanup.json"))
    binding.unlink()
    cleanup_inventory.unlink()
    ledger_fd = os.open(options.attempt_ledger_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(ledger_fd)
    finally:
        os.close(ledger_fd)

    enron_capacity._recover_worker_inflight(options)

    assert verify_capacity_attempt_ledger(options.attempt_ledger_dir) == [before]
    assert options.output_dir.is_dir()
    _assert_attempt_ledger_files(options.attempt_ledger_dir)


def test_receipt_cleanup_error_preserves_passed_output_for_same_process_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_remove = enron_capacity._remove_inflight_files_locked
    original_park = enron_capacity.PrivateRun.park_unresolved_cleanup_authority
    park_calls = 0

    def fail_after_receipt(_inflight: Any) -> None:
        raise OSError("injected cleanup failure")

    def reject_parking_after_receipt(_run: Any) -> None:
        nonlocal park_calls
        park_calls += 1
        raise AssertionError("durable receipt cleanup must release, not park")

    monkeypatch.setattr(enron_capacity, "_remove_inflight_files_locked", fail_after_receipt)
    monkeypatch.setattr(enron_capacity.PrivateRun, "park_unresolved_cleanup_authority", reject_parking_after_receipt)
    with pytest.raises(EnronCapacityError) as raised:
        _run(tmp_path)
    assert raised.value.code == "attempt_ledger_write_failed"
    options = _options(tmp_path, "capacity-run")
    assert options.output_dir.is_dir()
    assert (options.attempt_ledger_dir / "attempt-00000001.json").is_file()
    assert park_calls == 0
    assert not enron_capacity._private_io._UNRESOLVED_CLEANUP_FDS  # noqa: SLF001
    assert enron_capacity._private_io._LIVE_CLEANUP_FDS == 0  # noqa: SLF001
    monkeypatch.setattr(enron_capacity, "_remove_inflight_files_locked", original_remove)
    monkeypatch.setattr(enron_capacity.PrivateRun, "park_unresolved_cleanup_authority", original_park)

    enron_capacity._recover_worker_inflight(options)

    receipts = verify_capacity_attempt_ledger(options.attempt_ledger_dir)
    assert len(receipts) == 1
    assert receipts[0]["outcome"] == "passed"
    assert options.output_dir.is_dir()
    _assert_attempt_ledger_files(options.attempt_ledger_dir)


@pytest.mark.parametrize("control_error", [KeyboardInterrupt, SystemExit])
def test_receipt_postpublication_control_reconciles_passed_terminal_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    control_error: type[BaseException],
) -> None:
    original_write = enron_capacity._write_attempt_receipt_locked
    interrupted = False

    def write_then_interrupt(
        descriptor: int,
        receipt: Mapping[str, Any],
        durable_commit: bytearray,
    ) -> None:
        nonlocal interrupted
        original_write(descriptor, receipt, durable_commit)
        if not interrupted:
            interrupted = True
            raise control_error("injected receipt postpublication control")

    monkeypatch.setattr(enron_capacity, "_write_attempt_receipt_locked", write_then_interrupt)
    with pytest.raises(EnronCapacityError) as raised:
        _run(tmp_path)

    assert raised.value.code == "attempt_ledger_write_failed"
    assert interrupted is True
    options = _options(tmp_path, "capacity-run")
    receipts = verify_capacity_attempt_ledger(options.attempt_ledger_dir)
    assert len(receipts) == 1
    assert receipts[0]["outcome"] == "passed"
    assert options.output_dir.is_dir()
    assert (
        verify_capacity_run(options.output_dir, options.attempt_ledger_dir, require_production=False)[
            "terminal_attempt"
        ]
        == receipts[0]
    )
    _assert_attempt_ledger_files(options.attempt_ledger_dir)


def test_visible_receipt_without_directory_durability_cannot_retain_private_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_wipe = enron_capacity._wipe_and_quarantine_private_file_at
    fsync_failed = False

    def fail_directory_fsync(committed: bytearray, _descriptor: int) -> int:
        nonlocal fsync_failed
        assert committed == bytearray(1)
        fsync_failed = True
        return errno.EIO

    def leave_receipt_visible(
        directory_fd: int,
        name: str,
        descriptor: int,
        expected_identity: tuple[int, int],
    ) -> None:
        if name == "attempt-00000001.json" or name.startswith(".attempt-stage-"):
            raise OSError(errno.EROFS, os.strerror(errno.EROFS))
        original_wipe(directory_fd, name, descriptor, expected_identity)

    monkeypatch.setattr(enron_capacity._native_engine, "_fsync_fd_commit", fail_directory_fsync)
    monkeypatch.setattr(enron_capacity, "_wipe_and_quarantine_private_file_at", leave_receipt_visible)

    with pytest.raises(EnronCapacityError) as raised:
        _run(tmp_path)

    assert raised.value.code == "attempt_ledger_write_failed"
    assert fsync_failed is True
    options = _options(tmp_path, "capacity-run")
    assert not options.output_dir.exists()
    assert (options.attempt_ledger_dir / "attempt-00000001.json").is_file()
    assert list(options.attempt_ledger_dir.glob(".attempt-inflight-*.json"))
    with pytest.raises(EnronCapacityError) as invalid:
        verify_capacity_attempt_ledger(options.attempt_ledger_dir)
    assert invalid.value.code == "attempt_ledger_invalid"


@pytest.mark.parametrize("control_error", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("release_interruptions", [1, 3])
def test_post_receipt_control_is_deferred_until_every_capacity_descriptor_is_settled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    control_error: type[BaseException],
    release_interruptions: int,
) -> None:
    original_execute = enron_capacity._execute_capacity_transaction
    original_append = enron_capacity._append_attempt_receipt
    original_release = enron_capacity.PrivateRun.release_cleanup_authority
    captured: dict[str, Any] = {}
    armed = False
    release_calls = 0
    first_control: BaseException | None = None

    def capture_completed(*args: Any, **kwargs: Any) -> Any:
        completed = original_execute(*args, **kwargs)
        captured["completed"] = completed
        return completed

    def arm_after_receipt(*args: Any, **kwargs: Any) -> None:
        nonlocal armed
        inflight = kwargs["inflight"]
        captured["inflight"] = inflight
        captured["marker_fd"] = inflight.marker_fd
        original_append(*args, **kwargs)
        assert inflight.receipt_appended is True
        armed = True

    def interrupt_release(run: Any) -> None:
        nonlocal first_control, release_calls
        if armed:
            release_calls += 1
            if release_calls <= release_interruptions:
                injected = control_error("injected post-receipt cleanup control")
                if first_control is None:
                    first_control = injected
                raise injected
        original_release(run)

    monkeypatch.setattr(enron_capacity, "_execute_capacity_transaction", capture_completed)
    monkeypatch.setattr(enron_capacity, "_append_attempt_receipt", arm_after_receipt)
    monkeypatch.setattr(enron_capacity.PrivateRun, "release_cleanup_authority", interrupt_release)
    before_descriptors = _process_descriptor_inventory()

    with pytest.raises(control_error, match="post-receipt cleanup control") as raised:
        _run(tmp_path)

    assert first_control is not None
    assert raised.value is first_control
    assert release_calls == release_interruptions + 1
    marker_fd = captured["marker_fd"]
    assert isinstance(marker_fd, int)
    with pytest.raises(OSError) as marker_closed:
        os.fstat(marker_fd)
    assert marker_closed.value.errno == errno.EBADF
    completed = captured["completed"]
    inflight = captured["inflight"]
    assert completed.cleanup_owner.cleanup_authority_retained is False
    assert completed.pinned.closed is True
    assert inflight.closed is True
    assert inflight.ledger.pinned.closed is True
    assert not enron_capacity._private_io._UNRESOLVED_CLEANUP_FDS  # noqa: SLF001
    assert enron_capacity._private_io._LIVE_CLEANUP_FDS == 0  # noqa: SLF001
    gc.collect()
    assert _process_descriptor_inventory() == before_descriptors

    options = _options(tmp_path)
    decision = verify_capacity_run(options.output_dir, options.attempt_ledger_dir, require_production=False)
    assert decision["report"] == completed.report
    assert decision["terminal_attempt"]["outcome"] == "passed"
    _assert_attempt_ledger_files(options.attempt_ledger_dir)


@pytest.mark.parametrize("control_error", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("close_interruptions", [1, 3])
@pytest.mark.parametrize("close_target", ["completed_pin", "inflight", "ledger_pin"])
def test_post_receipt_finalizer_retries_control_before_each_close_delegates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    control_error: type[BaseException],
    close_interruptions: int,
    close_target: str,
) -> None:
    original_execute = enron_capacity._execute_capacity_transaction
    original_append = enron_capacity._append_attempt_receipt
    original_pinned_close = enron_capacity._PinnedDirectory.close
    original_inflight_close = enron_capacity._InflightAttempt.close
    captured: dict[str, Any] = {}
    armed = False
    close_calls = 0
    first_control: BaseException | None = None

    def capture_completed(*args: Any, **kwargs: Any) -> Any:
        completed = original_execute(*args, **kwargs)
        captured["completed"] = completed
        return completed

    def arm_after_receipt(*args: Any, **kwargs: Any) -> None:
        nonlocal armed
        inflight = kwargs["inflight"]
        captured["inflight"] = inflight
        captured["marker_fd"] = inflight.marker_fd
        original_append(*args, **kwargs)
        assert inflight.receipt_appended is True
        armed = True

    def maybe_interrupt() -> None:
        nonlocal close_calls, first_control
        close_calls += 1
        if close_calls <= close_interruptions:
            injected = control_error(f"injected {close_target} pre-delegation control")
            if first_control is None:
                first_control = injected
            raise injected

    def interrupt_pinned_close(pinned: Any) -> None:
        if armed:
            completed_target = captured["completed"].pinned
            ledger_target = captured["inflight"].ledger.pinned
            if (close_target == "completed_pin" and pinned is completed_target) or (
                close_target == "ledger_pin" and pinned is ledger_target
            ):
                maybe_interrupt()
        original_pinned_close(pinned)

    def interrupt_inflight_close(inflight: Any) -> None:
        if armed and close_target == "inflight" and inflight is captured["inflight"]:
            maybe_interrupt()
        original_inflight_close(inflight)

    monkeypatch.setattr(enron_capacity, "_execute_capacity_transaction", capture_completed)
    monkeypatch.setattr(enron_capacity, "_append_attempt_receipt", arm_after_receipt)
    monkeypatch.setattr(enron_capacity._PinnedDirectory, "close", interrupt_pinned_close)
    monkeypatch.setattr(enron_capacity._InflightAttempt, "close", interrupt_inflight_close)
    before_descriptors = _process_descriptor_inventory()

    with pytest.raises(control_error, match="pre-delegation control") as raised:
        _run(tmp_path)

    assert first_control is not None
    assert raised.value is first_control
    assert close_calls == close_interruptions + 1
    marker_fd = captured["marker_fd"]
    assert isinstance(marker_fd, int)
    with pytest.raises(OSError) as marker_closed:
        os.fstat(marker_fd)
    assert marker_closed.value.errno == errno.EBADF
    completed = captured["completed"]
    inflight = captured["inflight"]
    assert completed.cleanup_owner.cleanup_authority_retained is False
    assert completed.pinned.closed is True
    assert inflight.closed is True
    assert inflight.ledger.pinned.closed is True
    assert not enron_capacity._private_io._UNRESOLVED_CLEANUP_FDS  # noqa: SLF001
    assert enron_capacity._private_io._LIVE_CLEANUP_FDS == 0  # noqa: SLF001
    gc.collect()
    assert _process_descriptor_inventory() == before_descriptors

    options = _options(tmp_path)
    decision = verify_capacity_run(options.output_dir, options.attempt_ledger_dir, require_production=False)
    assert decision["report"] == completed.report
    assert decision["terminal_attempt"]["outcome"] == "passed"
    _assert_attempt_ledger_files(options.attempt_ledger_dir)


@pytest.mark.parametrize("control_error", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("ownership_target", ["component", "base", "marker"])
@pytest.mark.parametrize("reuse_kind", ["different_inode", "same_inode"])
def test_capacity_close_never_closes_a_reused_descriptor_after_post_close_control(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    control_error: type[BaseException],
    ownership_target: str,
    reuse_kind: str,
) -> None:
    original_execute = enron_capacity._execute_capacity_transaction
    original_append = enron_capacity._append_attempt_receipt
    captured: dict[str, Any] = {}
    armed = False
    injected = False
    first_control: BaseException | None = None
    sentinel_fds: list[int] = []
    sentinel_path = tmp_path / "sentinel.bin"
    sentinel_path.write_bytes(b"sentinel")
    close_source, close_start = inspect.getsourcelines(enron_capacity._close_owned_descriptor_to_completion)
    all_return_lines = {
        close_start + index for index, line in enumerate(close_source) if line.strip() == "return first_error"
    }
    successful_return_lines = {max(all_return_lines)}

    def capture_completed(*args: Any, **kwargs: Any) -> Any:
        completed = original_execute(*args, **kwargs)
        captured["completed"] = completed
        captured["component_fd"] = completed.pinned._components[-1].fd
        assert completed.pinned._base is not None
        captured["base_fd"] = completed.pinned._base.fd
        return completed

    def arm_after_receipt(*args: Any, **kwargs: Any) -> None:
        nonlocal armed
        inflight = kwargs["inflight"]
        captured["inflight"] = inflight
        captured["marker_fd"] = inflight.marker_fd
        original_append(*args, **kwargs)
        assert inflight.receipt_appended is True
        if reuse_kind == "same_inode":
            target_fd = captured[f"{ownership_target}_fd"]
            same_inode_source_fd = os.dup(target_fd)
            captured["same_inode_source_fd"] = same_inode_source_fd
            sentinel_fds.append(same_inode_source_fd)
        armed = True
        sys.settrace(trace_close_return)

    def trace_close_return(frame: Any, event: str, _argument: Any) -> Any:
        nonlocal first_control, injected
        if (
            event != "line"
            or frame.f_code is not enron_capacity._close_owned_descriptor_to_completion.__code__
            or frame.f_lineno not in successful_return_lines
        ):
            return trace_close_return
        descriptor = frame.f_locals["descriptor"]
        target_fd = captured.get(f"{ownership_target}_fd")
        if armed and not injected and descriptor == target_fd:
            injected = True
            sys.settrace(None)
            if reuse_kind == "same_inode":
                source_fd = captured["same_inode_source_fd"]
                os.dup2(source_fd, descriptor)
                sentinel_fds.append(descriptor)
            else:
                source_fd = os.open(sentinel_path, os.O_RDONLY)
                sentinel_fds.append(source_fd)
                if source_fd != descriptor:
                    os.dup2(source_fd, descriptor)
                    sentinel_fds.append(descriptor)
            reopened = os.fstat(descriptor)
            captured["replacement_identity"] = (
                int(reopened.st_dev),
                int(reopened.st_ino),
                stat.S_IFMT(reopened.st_mode),
            )
            first_control = control_error(f"injected {ownership_target} post-close reuse control")
            raise first_control
        return trace_close_return

    monkeypatch.setattr(enron_capacity, "_execute_capacity_transaction", capture_completed)
    monkeypatch.setattr(enron_capacity, "_append_attempt_receipt", arm_after_receipt)
    before_descriptors = _process_descriptor_inventory()

    try:
        with pytest.raises(control_error, match="post-close reuse control") as raised:
            _run(tmp_path)

        assert injected is True
        assert first_control is not None
        assert raised.value is first_control
        target_fd = captured[f"{ownership_target}_fd"]
        assert isinstance(target_fd, int)
        target_info = os.fstat(target_fd)
        assert (
            int(target_info.st_dev),
            int(target_info.st_ino),
            stat.S_IFMT(target_info.st_mode),
        ) == captured["replacement_identity"]
        completed = captured["completed"]
        inflight = captured["inflight"]
        assert completed.cleanup_owner.cleanup_authority_retained is False
        assert completed.pinned.closed is True
        assert inflight.closed is True
        assert inflight.ledger.pinned.closed is True
        assert not enron_capacity._private_io._UNRESOLVED_CLEANUP_FDS  # noqa: SLF001
        assert enron_capacity._private_io._LIVE_CLEANUP_FDS == 0  # noqa: SLF001
    finally:
        sys.settrace(None)
        for descriptor in dict.fromkeys(sentinel_fds):
            try:
                os.close(descriptor)
            except OSError:
                pass

    gc.collect()
    assert _process_descriptor_inventory() == before_descriptors
    options = _options(tmp_path)
    decision = verify_capacity_run(options.output_dir, options.attempt_ledger_dir, require_production=False)
    assert decision["report"] == captured["completed"].report
    assert decision["terminal_attempt"]["outcome"] == "passed"
    _assert_attempt_ledger_files(options.attempt_ledger_dir)


@pytest.mark.parametrize("control_error", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("ownership_target", ["component", "base", "marker"])
def test_native_close_commit_retries_control_before_the_syscall_is_entered(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    control_error: type[BaseException],
    ownership_target: str,
) -> None:
    original_execute = enron_capacity._execute_capacity_transaction
    original_append = enron_capacity._append_attempt_receipt
    captured: dict[str, Any] = {}
    armed = False
    injected = False
    first_control: BaseException | None = None
    close_source, close_start = inspect.getsourcelines(enron_capacity._close_owned_descriptor_to_completion)
    native_call_lines = {
        close_start + index
        for index, line in enumerate(close_source)
        if "close_errno = _native_engine._close_fd_once" in line
    }
    assert len(native_call_lines) == 1

    def capture_completed(*args: Any, **kwargs: Any) -> Any:
        completed = original_execute(*args, **kwargs)
        captured["completed"] = completed
        captured["component_fd"] = completed.pinned._components[-1].fd
        assert completed.pinned._base is not None
        captured["base_fd"] = completed.pinned._base.fd
        return completed

    def arm_after_receipt(*args: Any, **kwargs: Any) -> None:
        nonlocal armed
        inflight = kwargs["inflight"]
        captured["inflight"] = inflight
        captured["marker_fd"] = inflight.marker_fd
        original_append(*args, **kwargs)
        assert inflight.receipt_appended is True
        armed = True
        sys.settrace(trace_pre_native_close)

    def trace_pre_native_close(frame: Any, event: str, _argument: Any) -> Any:
        nonlocal first_control, injected
        if (
            event == "line"
            and frame.f_code is enron_capacity._close_owned_descriptor_to_completion.__code__
            and frame.f_lineno in native_call_lines
            and armed
            and not injected
            and frame.f_locals["descriptor"] == captured[f"{ownership_target}_fd"]
        ):
            injected = True
            sys.settrace(None)
            first_control = control_error(f"injected {ownership_target} pre-native-close control")
            raise first_control
        return trace_pre_native_close

    monkeypatch.setattr(enron_capacity, "_execute_capacity_transaction", capture_completed)
    monkeypatch.setattr(enron_capacity, "_append_attempt_receipt", arm_after_receipt)
    before_descriptors = _process_descriptor_inventory()
    try:
        with pytest.raises(control_error, match="pre-native-close control") as raised:
            _run(tmp_path)
    finally:
        sys.settrace(None)

    assert injected is True
    assert first_control is not None
    assert raised.value is first_control
    target_fd = captured[f"{ownership_target}_fd"]
    with pytest.raises(OSError) as target_closed:
        os.fstat(target_fd)
    assert target_closed.value.errno == errno.EBADF
    completed = captured["completed"]
    inflight = captured["inflight"]
    assert completed.cleanup_owner.cleanup_authority_retained is False
    assert completed.pinned.closed is True
    assert inflight.closed is True
    assert inflight.ledger.pinned.closed is True
    gc.collect()
    assert _process_descriptor_inventory() == before_descriptors
    options = _options(tmp_path)
    decision = verify_capacity_run(options.output_dir, options.attempt_ledger_dir, require_production=False)
    assert decision["report"] == completed.report
    assert decision["terminal_attempt"]["outcome"] == "passed"


@pytest.mark.parametrize("control_error", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("open_target", ["base", "component"])
def test_pinned_directory_native_open_status_closes_post_open_control(
    tmp_path: Path,
    control_error: type[BaseException],
    open_target: str,
) -> None:
    open_source, open_start = inspect.getsourcelines(enron_capacity._open_owned_directory_descriptor)
    post_open_lines = {
        open_start + index for index, line in enumerate(open_source) if line.strip() == "if not owner.closed:"
    }
    post_open_lines = {min(post_open_lines)}
    injected = False
    opened_descriptor: int | None = None
    before_descriptors = _process_descriptor_inventory()

    def trace_post_native_open(frame: Any, event: str, _argument: Any) -> Any:
        nonlocal injected, opened_descriptor
        target_call = (open_target == "base" and frame.f_locals.get("dir_fd") is None) or (
            open_target == "component" and frame.f_locals.get("dir_fd") is not None
        )
        if (
            event == "line"
            and frame.f_code is enron_capacity._open_owned_directory_descriptor.__code__
            and frame.f_lineno in post_open_lines
            and target_call
            and not injected
        ):
            injected = True
            opened_descriptor = frame.f_locals["owner"].fd
            assert opened_descriptor >= 0
            sys.settrace(None)
            raise control_error(f"injected {open_target} post-native-open control")
        return trace_post_native_open

    try:
        sys.settrace(trace_post_native_open)
        with pytest.raises(EnronCapacityError):
            enron_capacity._PinnedDirectory(tmp_path)
    finally:
        sys.settrace(None)

    assert injected is True
    assert opened_descriptor is not None
    with pytest.raises(OSError) as opened_closed:
        os.fstat(opened_descriptor)
    assert opened_closed.value.errno == errno.EBADF
    gc.collect()
    assert _process_descriptor_inventory() == before_descriptors


@pytest.mark.parametrize("control_error", [KeyboardInterrupt, SystemExit])
def test_private_file_native_open_status_cleans_post_open_control(
    tmp_path: Path,
    control_error: type[BaseException],
) -> None:
    open_source, open_start = inspect.getsourcelines(enron_capacity._open_owned_private_file_descriptor)
    post_open_lines = {
        open_start + index for index, line in enumerate(open_source) if line.strip() == "if not owner.closed:"
    }
    post_open_lines = {min(post_open_lines)}
    temporary_name = "private-open.tmp"
    directory_fd = os.open(tmp_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    injected = False
    opened_descriptor: int | None = None
    before_descriptors = _process_descriptor_inventory()

    def trace_post_native_open(frame: Any, event: str, _argument: Any) -> Any:
        nonlocal injected, opened_descriptor
        if (
            event == "line"
            and frame.f_code is enron_capacity._open_owned_private_file_descriptor.__code__
            and frame.f_lineno in post_open_lines
            and not injected
        ):
            injected = True
            opened_descriptor = frame.f_locals["owner"].fd
            assert opened_descriptor >= 0
            sys.settrace(None)
            raise control_error("injected private-file post-native-open control")
        return trace_post_native_open

    try:
        try:
            sys.settrace(trace_post_native_open)
            with pytest.raises(control_error, match="private-file post-native-open control") as raised:
                enron_capacity._open_owned_private_file_descriptor(temporary_name, dir_fd=directory_fd)
        finally:
            sys.settrace(None)

        assert injected is True
        assert isinstance(raised.value, control_error)
        assert opened_descriptor is not None
        with pytest.raises(OSError) as opened_closed:
            os.fstat(opened_descriptor)
        assert opened_closed.value.errno == errno.EBADF
        gc.collect()
        assert _process_descriptor_inventory() == before_descriptors
        assert not (tmp_path / temporary_name).exists()
        tombstones = list(tmp_path.glob(".nerb-cleanup-*"))
        assert len(tombstones) == 1
        assert tombstones[0].stat().st_size == 0
    finally:
        os.close(directory_fd)


@pytest.mark.parametrize("control_error", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("open_kind", ["directory", "private", "existing"])
def test_native_open_preserves_first_control_when_later_identity_check_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    control_error: type[BaseException],
    open_kind: str,
) -> None:
    directory_fd = os.open(tmp_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    existing = tmp_path / "existing.json"
    existing.write_bytes(b"existing")
    existing.chmod(0o600)
    if open_kind == "directory":
        native_name = "_open_directory_fd_once"
    elif open_kind == "private":
        native_name = "_open_private_file_fd_once"
    else:
        native_name = "_open_existing_private_file_fd_once"
    original_native_open = getattr(enron_capacity._native_engine, native_name)
    original_fstat = os.fstat
    first_control = control_error(f"injected {open_kind} first control")
    open_calls = 0
    identity_failed = False
    before_descriptors = _process_descriptor_inventory()

    def interrupt_then_open(*args: Any) -> int:
        nonlocal open_calls
        open_calls += 1
        if open_calls == 1:
            raise first_control
        return original_native_open(*args)

    def fail_first_identity_check(descriptor: int) -> os.stat_result:
        nonlocal identity_failed
        if not identity_failed:
            identity_failed = True
            raise OSError(errno.EIO, "injected later identity failure")
        return original_fstat(descriptor)

    monkeypatch.setattr(enron_capacity._native_engine, native_name, interrupt_then_open)
    monkeypatch.setattr(enron_capacity.os, "fstat", fail_first_identity_check)
    try:
        with pytest.raises(control_error, match="first control") as raised:
            if open_kind == "directory":
                enron_capacity._open_owned_directory_descriptor(os.fspath(tmp_path))
            elif open_kind == "private":
                enron_capacity._open_owned_private_file_descriptor("first-control.tmp", dir_fd=directory_fd)
            else:
                enron_capacity._open_owned_existing_private_file_descriptor(existing.name, dir_fd=directory_fd)

        assert raised.value is first_control
        assert open_calls == 2
        assert identity_failed is True
        gc.collect()
        assert _process_descriptor_inventory() == before_descriptors
        assert not (tmp_path / "first-control.tmp").exists()
        assert existing.read_bytes() == b"existing"
    finally:
        os.close(directory_fd)


@pytest.mark.parametrize("control_error", [KeyboardInterrupt, SystemExit])
def test_private_tree_guard_construction_closes_post_open_control(
    tmp_path: Path,
    control_error: type[BaseException],
) -> None:
    init_source, init_start = inspect.getsourcelines(enron_capacity._PrivateTreeGuard.__init__)
    post_open_lines = {
        init_start + index
        for index, line in enumerate(init_source)
        if line.strip() == "after = os.fstat(self._owner.fd)"
    }
    assert len(post_open_lines) == 1
    injected = False
    opened_descriptor: int | None = None
    before_descriptors = _process_descriptor_inventory()

    def trace_post_guard_open(frame: Any, event: str, _argument: Any) -> Any:
        nonlocal injected, opened_descriptor
        if (
            event == "line"
            and frame.f_code is enron_capacity._PrivateTreeGuard.__init__.__code__
            and frame.f_lineno in post_open_lines
            and not injected
        ):
            injected = True
            opened_descriptor = frame.f_locals["self"]._owner.fd
            assert opened_descriptor >= 0
            sys.settrace(None)
            raise control_error("injected private-tree post-open control")
        return trace_post_guard_open

    try:
        sys.settrace(trace_post_guard_open)
        with pytest.raises(control_error, match="private-tree post-open control") as raised:
            enron_capacity._PrivateTreeGuard(tmp_path)
    finally:
        sys.settrace(None)

    assert injected is True
    assert isinstance(raised.value, control_error)
    assert opened_descriptor is not None
    gc.collect()
    with pytest.raises(OSError) as opened_closed:
        os.fstat(opened_descriptor)
    assert opened_closed.value.errno == errno.EBADF
    assert _process_descriptor_inventory() == before_descriptors


@pytest.mark.parametrize("control_error", [KeyboardInterrupt, SystemExit])
def test_private_tree_logical_scan_closes_post_open_control(
    tmp_path: Path,
    control_error: type[BaseException],
) -> None:
    guard = enron_capacity._PrivateTreeGuard(tmp_path)
    logical_source, logical_start = inspect.getsourcelines(enron_capacity._PrivateTreeGuard.logical_bytes)
    post_open_lines = {
        logical_start + index
        for index, line in enumerate(logical_source)
        if line.strip() == "opened = os.fstat(scan.fd)"
    }
    assert len(post_open_lines) == 1
    injected = False
    opened_descriptor: int | None = None
    before_descriptors = _process_descriptor_inventory()

    def trace_post_scan_open(frame: Any, event: str, _argument: Any) -> Any:
        nonlocal injected, opened_descriptor
        if (
            event == "line"
            and frame.f_code is enron_capacity._PrivateTreeGuard.logical_bytes.__code__
            and frame.f_lineno in post_open_lines
            and not injected
        ):
            injected = True
            opened_descriptor = frame.f_locals["scan"].fd
            assert opened_descriptor >= 0
            sys.settrace(None)
            raise control_error("injected logical-scan post-open control")
        return trace_post_scan_open

    try:
        try:
            sys.settrace(trace_post_scan_open)
            with pytest.raises(control_error, match="logical-scan post-open control") as raised:
                guard.logical_bytes()
        finally:
            sys.settrace(None)

        assert injected is True
        assert isinstance(raised.value, control_error)
        assert opened_descriptor is not None
        gc.collect()
        with pytest.raises(OSError) as opened_closed:
            os.fstat(opened_descriptor)
        assert opened_closed.value.errno == errno.EBADF
        assert _process_descriptor_inventory() == before_descriptors
        guard.assert_current()
    finally:
        guard.close()


@pytest.mark.parametrize("control_error", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("helper_name", ["locked", "atomic"])
def test_private_file_publication_transfer_closes_post_publish_control(
    tmp_path: Path,
    control_error: type[BaseException],
    helper_name: str,
) -> None:
    if helper_name == "locked":
        helper = enron_capacity._write_locked_atomic_file_at
        helper_source, helper_start = inspect.getsourcelines(helper)
        transfer_lines = {
            helper_start + index for index, line in enumerate(helper_source) if line.strip() == "return owner"
        }
    else:
        helper = enron_capacity._write_atomic_private_file_at
        helper_source, helper_start = inspect.getsourcelines(helper)
        transfer_lines = {
            helper_start + index for index, line in enumerate(helper_source) if line.strip() == "descriptor = owner.fd"
        }
    assert len(transfer_lines) == 1
    temporary_name = f"{helper_name}.tmp"
    final_name = f"{helper_name}.json"
    payload = b'{"private":"pii@example.com"}\n'
    directory_fd = os.open(tmp_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    injected = False
    opened_descriptor: int | None = None
    before_descriptors = _process_descriptor_inventory()

    def trace_transfer(frame: Any, event: str, _argument: Any) -> Any:
        nonlocal injected, opened_descriptor
        if event == "line" and frame.f_code is helper.__code__ and frame.f_lineno in transfer_lines and not injected:
            injected = True
            opened_descriptor = frame.f_locals["owner"].fd
            assert opened_descriptor >= 0
            sys.settrace(None)
            raise control_error(f"injected {helper_name} publication-transfer control")
        return trace_transfer

    try:
        try:
            sys.settrace(trace_transfer)
            with pytest.raises(control_error, match="publication-transfer control") as raised:
                helper(
                    directory_fd,
                    temporary_name=temporary_name,
                    final_name=final_name,
                    payload=payload,
                )
        finally:
            sys.settrace(None)

        assert injected is True
        assert isinstance(raised.value, control_error)
        assert opened_descriptor is not None
        gc.collect()
        with pytest.raises(OSError) as opened_closed:
            os.fstat(opened_descriptor)
        assert opened_closed.value.errno == errno.EBADF
        assert _process_descriptor_inventory() == before_descriptors
        assert not (tmp_path / temporary_name).exists()
        if helper_name == "atomic":
            assert (tmp_path / final_name).read_bytes() == payload
        else:
            assert not (tmp_path / final_name).exists()
            tombstones = list(tmp_path.glob(".nerb-cleanup-*"))
            assert len(tombstones) == 1
            assert tombstones[0].stat().st_size == 0
    finally:
        os.close(directory_fd)


def test_owned_descriptor_rejects_raw_descriptor_transfer(tmp_path: Path) -> None:
    descriptor = os.open(tmp_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    constructor: Any = enron_capacity._OwnedDescriptor
    try:
        with pytest.raises(TypeError):
            constructor(descriptor)
        os.fstat(descriptor)
    finally:
        os.close(descriptor)


@pytest.mark.parametrize("control_error", [KeyboardInterrupt, SystemExit])
def test_locked_publication_cleans_interrupt_between_rename_and_state_commit(
    tmp_path: Path,
    control_error: type[BaseException],
) -> None:
    helper = enron_capacity._write_locked_atomic_file_at
    helper_source, helper_start = inspect.getsourcelines(helper)
    post_rename_lines = {
        helper_start + index for index, line in enumerate(helper_source) if line.strip() == "published = True"
    }
    assert len(post_rename_lines) == 1
    temporary_name = "rename-state.tmp"
    final_name = "rename-state.json"
    payload = b'{"private":"pii@example.com"}\n'
    directory_fd = os.open(tmp_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    injected = False
    before_descriptors = _process_descriptor_inventory()

    def trace_post_rename(frame: Any, event: str, _argument: Any) -> Any:
        nonlocal injected
        if event == "line" and frame.f_code is helper.__code__ and frame.f_lineno in post_rename_lines and not injected:
            injected = True
            sys.settrace(None)
            raise control_error("injected rename-state control")
        return trace_post_rename

    try:
        try:
            sys.settrace(trace_post_rename)
            with pytest.raises(control_error, match="rename-state control") as raised:
                helper(
                    directory_fd,
                    temporary_name=temporary_name,
                    final_name=final_name,
                    payload=payload,
                )
        finally:
            sys.settrace(None)

        assert injected is True
        assert isinstance(raised.value, control_error)
        gc.collect()
        assert _process_descriptor_inventory() == before_descriptors
        assert not (tmp_path / temporary_name).exists()
        assert not (tmp_path / final_name).exists()
        tombstones = list(tmp_path.glob(".nerb-cleanup-*"))
        assert len(tombstones) == 1
        assert tombstones[0].stat().st_size == 0
    finally:
        os.close(directory_fd)


@pytest.mark.parametrize("control_error", [KeyboardInterrupt, SystemExit])
def test_private_tree_cleanup_rethrows_control_after_descriptor_is_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    control_error: type[BaseException],
) -> None:
    guard = enron_capacity._PrivateTreeGuard(tmp_path)
    assert guard._owner is not None
    descriptor = guard._owner.fd
    original_close = enron_capacity._OwnedDescriptor.close
    injected = False

    def close_then_interrupt(owner: Any) -> None:
        nonlocal injected
        original_close(owner)
        if not injected and owner.closed:
            injected = True
            raise control_error("injected settled-close control")

    monkeypatch.setattr(enron_capacity._OwnedDescriptor, "close", close_then_interrupt)
    with pytest.raises(control_error, match="settled-close control") as raised:
        guard.close()

    assert injected is True
    assert isinstance(raised.value, control_error)
    assert guard._owner is None
    with pytest.raises(OSError) as descriptor_closed:
        os.fstat(descriptor)
    assert descriptor_closed.value.errno == errno.EBADF


def test_owned_descriptor_close_does_not_depend_on_python_fstat(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = enron_capacity._open_owned_directory_descriptor(os.fspath(tmp_path))
    descriptor = owner.fd
    original_fstat = os.fstat

    def fail_fstat(_descriptor: int) -> os.stat_result:
        raise OSError(errno.EIO, "injected persistent fstat failure")

    monkeypatch.setattr(enron_capacity.os, "fstat", fail_fstat)
    owner.close()

    with pytest.raises(OSError) as descriptor_closed:
        original_fstat(descriptor)
    assert descriptor_closed.value.errno == errno.EBADF


@pytest.mark.parametrize("control_error", [KeyboardInterrupt, SystemExit])
def test_begin_inflight_defers_local_close_control_until_marker_close_and_ledger_unlock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    control_error: type[BaseException],
) -> None:
    probe = _Probe()
    options = _options(tmp_path)
    before_descriptors = _process_descriptor_inventory()
    ledger = enron_capacity._prepare_attempt_ledger(options)
    final_dir, output_parent = enron_capacity._prepare_capacity_output(options)
    runners = enron_capacity._validated_phase_runners(_successful_runners(probe))
    execution = enron_capacity._execution_identity(
        runners,
        probe,
        production_evidence=False,
        monitor_interval_ns=enron_capacity.PRODUCTION_MONITOR_INTERVAL_NS,
    )
    original_assert = enron_capacity._AttemptLedger.assert_current
    original_close = enron_capacity._close_owned_descriptor_to_completion
    assert_calls = 0
    returned_control = False
    injected = control_error("injected local marker close control")

    def fail_after_marker_write(actual: Any) -> None:
        nonlocal assert_calls
        original_assert(actual)
        if actual is ledger:
            assert_calls += 1
            if assert_calls == 2:
                raise ValueError("force local marker cleanup")

    def return_control_after_marker_close(
        descriptor: int,
        expected: Any,
        attempted: bytearray,
    ) -> BaseException | None:
        nonlocal returned_control
        close_error = original_close(descriptor, expected, attempted)
        if not returned_control and expected[2] == stat.S_IFREG:
            returned_control = True
            return injected
        return close_error

    monkeypatch.setattr(enron_capacity._AttemptLedger, "assert_current", fail_after_marker_write)
    monkeypatch.setattr(enron_capacity, "_close_owned_descriptor_to_completion", return_control_after_marker_close)
    try:
        with pytest.raises(control_error, match="local marker close control") as raised:
            enron_capacity._begin_inflight_attempt(
                ledger,
                final_dir=final_dir,
                output_parent=output_parent,
                execution=execution,
                production_evidence=False,
                started_monotonic_ns=1,
            )

        assert raised.value is injected
        assert returned_control is True
        competing_fd = os.open(
            options.attempt_ledger_dir,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            enron_capacity.fcntl.flock(
                competing_fd,
                enron_capacity.fcntl.LOCK_EX | enron_capacity.fcntl.LOCK_NB,
            )
            enron_capacity.fcntl.flock(competing_fd, enron_capacity.fcntl.LOCK_UN)
        finally:
            os.close(competing_fd)
    finally:
        output_parent.close()
        ledger.close()

    gc.collect()
    assert _process_descriptor_inventory() == before_descriptors


@pytest.mark.parametrize("control_error", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("interrupt_after_publication", [False, True])
def test_no_receipt_capacity_cleanup_publication_survives_control_and_gc(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    control_error: type[BaseException],
    interrupt_after_publication: bool,
) -> None:
    probe = _Probe()
    output = tmp_path / "no-receipt-run"
    moved = tmp_path / "moved-no-receipt-private.bin"
    real_wipe = enron_capacity._private_io._wipe_authenticated_cleanup_descriptor
    real_publish = enron_capacity._private_io._publish_unresolved_cleanup_descriptors
    fail_wipe = True
    interruptions = 0

    def preparation(context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
        _checkpoint_all(context, probe, _phase_records("preparation"))
        payload = context.work_dir / "private.bin"
        payload.write_bytes(b"private no-receipt payload")
        payload.chmod(0o600)
        return _result("preparation")

    def fail_before_receipt(*_args: Any, **_kwargs: Any) -> None:
        (output / "phases" / "preparation" / "private.bin").replace(moved)
        raise OSError("injected receipt failure")

    def injected_wipe(identity: tuple[int, int], descriptor: int) -> bool:
        if fail_wipe:
            return False
        return real_wipe(identity, descriptor)

    def interrupt_publication(descriptors: dict[tuple[int, ...], int]) -> None:
        nonlocal interruptions
        if interruptions < 2:
            interruptions += 1
            if interrupt_after_publication:
                real_publish(descriptors)
            raise control_error("injected capacity cleanup publication interruption")
        real_publish(descriptors)

    monkeypatch.setattr(enron_capacity, "_append_attempt_receipt", fail_before_receipt)
    monkeypatch.setattr(enron_capacity._private_io, "_wipe_authenticated_cleanup_descriptor", injected_wipe)
    monkeypatch.setattr(enron_capacity._private_io, "_publish_unresolved_cleanup_descriptors", interrupt_publication)
    try:
        with pytest.raises(control_error, match="capacity cleanup publication interruption"):
            _run(tmp_path, probe, name=output.name, replacements={"preparation": preparation})
        assert interruptions == (1 if interrupt_after_publication else 2)
        gc.collect()
        assert moved.read_bytes() == b"private no-receipt payload"
        assert enron_capacity._private_io._UNRESOLVED_CLEANUP_FDS  # noqa: SLF001

        blocked = tmp_path / "blocked-private-run"
        with pytest.raises(enron_capacity.EnronPrivateIOError, match="blocks a new private transaction"):
            with enron_capacity.PrivateRun(blocked):
                pass
        fail_wipe = False
        monkeypatch.setattr(enron_capacity._private_io, "_publish_unresolved_cleanup_descriptors", real_publish)
        retry = tmp_path / "retry-private-run"
        with enron_capacity.PrivateRun(retry) as retry_run:
            retry_run.commit()
        assert moved.read_bytes() == b""
        assert not enron_capacity._private_io._UNRESOLVED_CLEANUP_FDS  # noqa: SLF001
        assert enron_capacity._private_io._LIVE_CLEANUP_FDS == 0  # noqa: SLF001
    finally:
        fail_wipe = False
        monkeypatch.setattr(enron_capacity._private_io, "_publish_unresolved_cleanup_descriptors", real_publish)
        enron_capacity._private_io._retry_unresolved_cleanup_descriptors()  # noqa: SLF001


def test_ledger_and_promoted_directory_swaps_never_write_or_delete_substitutes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_append = enron_capacity._append_attempt_receipt
    ledger = tmp_path / "attempts"
    moved_ledger = tmp_path / "attempts-moved"
    replacement_ledger = tmp_path / "attempts"

    def swap_ledger(*args: Any, **kwargs: Any) -> dict[str, Any]:
        ledger.rename(moved_ledger)
        replacement_ledger.mkdir(mode=0o700)
        return original_append(*args, **kwargs)

    monkeypatch.setattr(enron_capacity, "_append_attempt_receipt", swap_ledger)
    with pytest.raises(EnronCapacityError) as ledger_error:
        _run(tmp_path, name="ledger-swap-run")
    assert ledger_error.value.code == "attempt_ledger_write_failed"
    assert list(replacement_ledger.iterdir()) == []
    assert not (tmp_path / "ledger-swap-run").exists()

    monkeypatch.setattr(enron_capacity, "_append_attempt_receipt", original_append)
    output = tmp_path / "output-swap-run"
    moved_output = tmp_path / "output-swap-run-moved"
    replacement_marker = output / "unrelated"

    def swap_output(*args: Any, **kwargs: Any) -> dict[str, Any]:
        output.rename(moved_output)
        output.mkdir(mode=0o700)
        replacement_marker.write_text("preserve", encoding="utf-8")
        replacement_marker.chmod(0o600)
        return original_append(*args, **kwargs)

    monkeypatch.setattr(enron_capacity, "_append_attempt_receipt", swap_output)
    with pytest.raises(EnronCapacityError) as output_error:
        _run(tmp_path, name="output-swap-run", ledger="second-ledger")
    assert output_error.value.code == "promotion_failed"
    assert replacement_marker.read_text(encoding="utf-8") == "preserve"
    assert moved_output.is_dir()
    with pytest.raises(EnronCapacityError):
        verify_capacity_run(moved_output, tmp_path / "second-ledger", require_production=False)


def test_watchdog_interrupts_resource_and_progress_wall_gap_at_production_interval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert enron_capacity.PRODUCTION_MONITOR_INTERVAL_NS == 100_000_000
    resource_probe = _Probe()
    monkeypatch.setattr(enron_capacity, "MAX_RESOURCE_OBSERVATION_WALL_GAP_NS", 50_000_000)

    def block_resource(_context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
        time.sleep(1)
        return _result("split")

    started = time.monotonic()
    with pytest.raises(EnronCapacityError) as resource_error:
        _run(
            tmp_path,
            resource_probe,
            name="resource-gap",
            replacements={"split": block_resource},
            wall_clock=time.monotonic_ns,
        )
    assert resource_error.value.code == "resource_observation_gap"
    assert time.monotonic() - started < 0.8

    monkeypatch.setattr(enron_capacity, "MAX_RESOURCE_OBSERVATION_WALL_GAP_NS", 500_000_000)
    monkeypatch.setattr(enron_capacity, "MAX_PROGRESS_CHECKPOINT_WALL_GAP_NS", 50_000_000)
    progress_probe = _Probe()

    def block_progress(_context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
        time.sleep(1)
        return _result("build")

    started = time.monotonic()
    with pytest.raises(EnronCapacityError) as progress_error:
        _run(
            tmp_path,
            progress_probe,
            name="progress-gap",
            ledger="progress-attempts",
            replacements={"build": block_progress},
            wall_clock=time.monotonic_ns,
        )
    assert progress_error.value.code == "checkpoint_wall_gap"
    assert time.monotonic() - started < 0.8


def test_private_tree_guard_registration_and_scanning_are_thread_safe(tmp_path: Path) -> None:
    root = tmp_path / "guarded-tree"
    root.mkdir(mode=0o700)
    guard = enron_capacity._PrivateTreeGuard(root)
    stop = threading.Event()
    errors: list[BaseException] = []

    def scan() -> None:
        while not stop.is_set():
            try:
                guard.logical_bytes()
            except BaseException as exc:
                errors.append(exc)
                return
            time.sleep(0.0001)

    scanner = threading.Thread(target=scan)
    scanner.start()
    try:
        for index in range(64):
            child = root / f"owned-{index:03d}"
            child.mkdir(mode=0o700)
            assert guard.register_owned_root(child) == child
    finally:
        stop.set()
        scanner.join(timeout=5)
        guard.close()

    assert not scanner.is_alive()
    assert errors == []


def test_private_tree_guard_concurrent_scans_use_independent_directory_offsets(tmp_path: Path) -> None:
    root = tmp_path / "static-guarded-tree"
    root.mkdir(mode=0o700)
    expected_bytes = 1_000
    for index in range(expected_bytes):
        path = root / f"payload-{index:04d}"
        path.write_bytes(b"x")
        path.chmod(0o600)
    guard = enron_capacity._PrivateTreeGuard(root)
    barrier = threading.Barrier(5)
    results: list[int] = []
    errors: list[BaseException] = []

    def scan() -> None:
        try:
            barrier.wait(timeout=5)
            for _ in range(4):
                results.append(guard.logical_bytes())
        except BaseException as exc:
            errors.append(exc)

    scanners = [threading.Thread(target=scan) for _ in range(4)]
    for scanner in scanners:
        scanner.start()
    barrier.wait(timeout=5)
    for scanner in scanners:
        scanner.join(timeout=10)
    guard.close()

    assert all(not scanner.is_alive() for scanner in scanners)
    assert errors == []
    assert results == [expected_bytes] * 16


def test_concurrent_heartbeats_serialize_wall_clock_reads_with_progress_state() -> None:
    first_clock_entered = threading.Event()
    release_first_clock = threading.Event()
    second_clock_called = threading.Event()
    second_lock_attempted = threading.Event()
    clock_lock = threading.Lock()
    clock_calls = 0

    def ordered_clock() -> int:
        nonlocal clock_calls
        with clock_lock:
            clock_calls += 1
            call = clock_calls
        if call == 1:
            first_clock_entered.set()
            if not release_first_clock.wait(timeout=5):
                raise AssertionError("first clock call was not released")
        else:
            second_clock_called.set()
        return call * 100

    class ObservedRLock:
        def __init__(self) -> None:
            self._inner = threading.RLock()

        def __enter__(self) -> ObservedRLock:
            if threading.current_thread().name == "second-heartbeat":
                second_lock_attempted.set()
            self._inner.acquire()
            return self

        def __exit__(self, *_args: Any) -> None:
            self._inner.release()

    monitor = enron_capacity._ContinuousResourceMonitor.__new__(enron_capacity._ContinuousResourceMonitor)
    monitor.wall_clock = ordered_clock
    monitor._lock = ObservedRLock()
    monitor._states = {
        "phase": enron_capacity._PhaseMeasurements(started_ns=0, started_wall_ns=0),
    }
    monitor._current_phase = "phase"
    monitor._failure_code = None
    monitor._observe = lambda _kind, **_kwargs: None
    errors: list[BaseException] = []

    def heartbeat() -> None:
        try:
            monitor.heartbeat("phase")
        except BaseException as exc:
            errors.append(exc)

    first = threading.Thread(target=heartbeat, name="first-heartbeat")
    second = threading.Thread(target=heartbeat, name="second-heartbeat")
    first.start()
    try:
        assert first_clock_entered.wait(timeout=5)
        second.start()
        assert second_lock_attempted.wait(timeout=5)
        assert not second_clock_called.is_set()
    finally:
        release_first_clock.set()
        first.join(timeout=5)
        if second.ident is not None:
            second.join(timeout=5)

    assert not first.is_alive()
    assert not second.is_alive()
    assert errors == []
    assert clock_calls == 2
    assert second_clock_called.is_set()
    assert monitor._states["phase"].last_progress_wall_ns == 200


def test_monitor_stop_restores_watchdog_and_is_idempotent_after_observation_error() -> None:
    class Watchdog:
        def __init__(self) -> None:
            self._installed = True
            self.close_calls = 0

        def close(self) -> None:
            self.close_calls += 1
            self._installed = False

    watchdog = Watchdog()
    monitor = enron_capacity._ContinuousResourceMonitor.__new__(enron_capacity._ContinuousResourceMonitor)
    monitor.interval_ns = enron_capacity.PRODUCTION_MONITOR_INTERVAL_NS
    monitor._stop = threading.Event()
    monitor._thread = None
    monitor._stopped = False
    monitor._watchdog = watchdog
    observations = 0

    def interrupted_observation(_kind: str) -> None:
        nonlocal observations
        observations += 1
        raise RuntimeError("boundary observation interrupted")

    monitor._observe = interrupted_observation

    with pytest.raises(RuntimeError, match="boundary observation interrupted"):
        monitor.stop()
    assert monitor._stopped is True
    assert watchdog._installed is False
    assert watchdog.close_calls == 1
    assert observations == 1

    monitor.stop()
    assert watchdog.close_calls == 1
    assert observations == 1


@pytest.mark.skipif(
    os.name != "posix" or not hasattr(signal, "SIGUSR1"),
    reason="POSIX watchdog assertion",
)
def test_watchdog_install_interruption_restores_handler_before_private_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_signal = signal.signal
    original_handler = signal.getsignal(signal.SIGUSR1)

    class EqualHandler:
        def __call__(self, _signum: int, _frame: Any) -> None:
            return None

        def __eq__(self, _other: object) -> bool:
            return callable(_other)

    previous = EqualHandler()
    real_signal(signal.SIGUSR1, previous)
    assert signal.getsignal(signal.SIGUSR1) is previous
    interrupted = False
    restoration_attempts = 0
    cleanup_handlers: list[Any] = []
    original_clear = enron_capacity._private_io._clear_pinned_private_directory

    def interrupt_after_install(signum: int, handler: Any) -> Any:
        nonlocal interrupted, restoration_attempts
        if signum == signal.SIGUSR1 and not interrupted:
            real_signal(signum, handler)
            interrupted = True
            raise KeyboardInterrupt("watchdog install interrupted")
        restoration_attempts += 1
        if restoration_attempts == 1:
            raise OSError("watchdog restoration interrupted")
        return real_signal(signum, handler)

    def observe_cleanup(directory_fd: int, directory_path: Path) -> bool:
        cleanup_handlers.append(signal.getsignal(signal.SIGUSR1))
        return original_clear(directory_fd, directory_path)

    try:
        monkeypatch.setattr(enron_capacity.signal, "signal", interrupt_after_install)
        monkeypatch.setattr(enron_capacity._private_io, "_clear_pinned_private_directory", observe_cleanup)
        with pytest.raises(EnronCapacityError) as raised:
            _run(tmp_path)

        assert interrupted is True
        assert restoration_attempts == 2
        assert raised.value.code == "phase_interrupted"
        assert signal.getsignal(signal.SIGUSR1) is previous
        assert cleanup_handlers and all(handler is previous for handler in cleanup_handlers)
        assert not (tmp_path / "capacity-run").exists()
        _assert_no_stage(tmp_path, "capacity-run")
        receipt = verify_capacity_attempt_ledger(tmp_path / "attempts")[-1]
        assert receipt["sensitive_content_wiped"] is True
        assert receipt["retained_private_tombstone_count"] == 1
    finally:
        real_signal(signal.SIGUSR1, original_handler)


def test_legitimate_non_record_heartbeats_do_not_inflate_record_progress(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Four 40 ms finalization segments would exceed this gate without
    # heartbeats, while leaving enough scheduler/filesystem margin for the
    # phase-boundary resource observation itself.
    test_wall_gap_ns = 120_000_000
    monkeypatch.setattr(enron_capacity, "MAX_RESOURCE_OBSERVATION_WALL_GAP_NS", 30_000_000_000)
    monkeypatch.setattr(enron_capacity, "MAX_PROGRESS_CHECKPOINT_WALL_GAP_NS", test_wall_gap_ns)
    probe = _Probe()

    def finalization(context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
        _checkpoint_all(context, probe, _VALIDATION_RECORDS)
        for _ in range(4):
            time.sleep(0.04)
            context.heartbeat()
        return _result("streaming_validation")

    report, _ = _run(
        tmp_path,
        probe,
        replacements={"streaming_validation": finalization},
        wall_clock=time.monotonic_ns,
    )
    phase = report["phases"][3]
    assert phase["checkpoint_samples"][-1]["completed_records"] == _VALIDATION_RECORDS
    assert sum(signal["kind"] == "heartbeat" for signal in phase["progress_signals"]) == 4
    assert all(
        signal["completed_records"] == _VALIDATION_RECORDS
        for signal in phase["progress_signals"]
        if signal["kind"] == "heartbeat"
    )
    assert phase["maximum_progress_checkpoint_wall_gap_ns"] <= test_wall_gap_ns


def test_heartbeat_enforcement_is_unbounded_while_report_evidence_is_deterministically_bounded(
    tmp_path: Path,
) -> None:
    probe = _Probe()
    heartbeat_count = enron_capacity.MAX_PROGRESS_SIGNALS_PER_PHASE + 257

    def many_heartbeats(context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
        _checkpoint_all(context, probe, _VALIDATION_RECORDS)
        for _ in range(heartbeat_count):
            context.heartbeat()
        return _result("streaming_validation")

    report, _ = _run(
        tmp_path,
        probe,
        replacements={"streaming_validation": many_heartbeats},
    )
    phase = report["phases"][3]
    assert phase["progress_signal_count"] == phase["checkpoint_count"] + heartbeat_count + 1
    assert len(phase["progress_signals"]) <= enron_capacity.MAX_PROGRESS_SIGNALS_PER_PHASE
    assert phase["progress_signal_count"] > len(phase["progress_signals"])
    assert phase["progress_signals"][-1]["kind"] == "phase_boundary"
    assert phase["progress_signals"][-1]["sequence"] == phase["progress_signal_count"]
    assert (
        max(signal["progress_wall_gap_ns"] for signal in phase["progress_signals"])
        == phase["maximum_progress_checkpoint_wall_gap_ns"]
    )
    assert len(json.dumps(report, sort_keys=True).encode("utf-8")) < enron_capacity.MAX_CAPACITY_REPORT_BYTES


def test_continuous_owned_scan_tolerates_legitimate_atomic_create_delete_races(tmp_path: Path) -> None:
    probe = _Probe()

    def preparation(context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
        _checkpoint_all(context, probe, ENRON_SOURCE_ROWS)
        stop = threading.Event()

        def churn() -> None:
            index = 0
            while not stop.is_set():
                path = context.scratch_dir / f"atomic-{index % 8}"
                try:
                    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                except FileExistsError:
                    continue
                try:
                    os.write(descriptor, b"bounded")
                finally:
                    os.close(descriptor)
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
                index += 1

        worker = threading.Thread(target=churn)
        worker.start()
        try:
            for _ in range(5):
                time.sleep(0.06)
                context.heartbeat()
        finally:
            stop.set()
            worker.join(timeout=2)
        assert not worker.is_alive()
        return _result("preparation")

    report, _ = _run(tmp_path, probe, replacements={"preparation": preparation})
    assert verify_capacity_report(report, require_production=False) == report


def test_phase_runtime_roots_environment_identity_disk_delta_and_report_bound(tmp_path: Path) -> None:
    probe = _Probe()
    original_home = os.environ.get("HOME")

    def preparation(context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
        assert context.scratch_dir.is_relative_to(context.work_dir)
        assert context.spool_dir.is_relative_to(context.work_dir)
        assert all(Path(value).is_relative_to(context.work_dir) for value in context.runtime_environment.values())
        assert os.environ["TMPDIR"] == context.runtime_environment["TMPDIR"]
        assert os.environ["HOME"] == context.runtime_environment["HOME"]
        assert len(set(context.runtime_environment.values())) == len(context.runtime_environment) - 4
        assert context.runtime_environment["TMPDIR"] == context.runtime_environment["TMP"]
        assert context.runtime_environment["TMP"] == context.runtime_environment["TEMP"]
        assert context.runtime_environment["HUGGINGFACE_HUB_CACHE"] == context.runtime_environment["HF_HUB_CACHE"]
        assert context.runtime_environment["HUGGINGFACE_ASSETS_CACHE"] == context.runtime_environment["HF_ASSETS_CACHE"]
        probe.set_free(30 * _GIB - 2 * _MIB)
        _checkpoint_all(context, probe, ENRON_SOURCE_ROWS)
        return _result("preparation")

    report, _ = _run(tmp_path, probe, replacements={"preparation": preparation})

    assert report["phases"][0]["owned_root_count"] == 16
    assert os.environ.get("HOME") == original_home
    assert report["totals"]["owned_disk_high_water_bytes"] >= 2 * _MIB
    assert all(len(phase["resource_samples"]) <= 256 for phase in report["phases"])
    assert report["totals"]["report_bytes"] < enron_capacity._MAX_CAPACITY_REPORT_STRUCTURAL_BOUND_BYTES
    assert enron_capacity._MAX_CAPACITY_REPORT_STRUCTURAL_BOUND_BYTES < 4 * _MIB
    runtime = report["environment"]["runtime"]
    assert runtime["logical_cpu_count"] > 0
    assert runtime["native_extension_sha256"] == report["execution"]["native_extension_sha256"]
    assert runtime["native_build_source_sha256"] == report["execution"]["native_build_source_sha256"]
    assert runtime["reader_environment"]["installed_distribution_count"] > 0
    assert report["execution"]["runtime_environment_sha256"] == _canonical_hash(runtime)
    assert report["execution"]["repository_tree_sha256"].startswith("sha256:")


def test_privacy_scan_is_recomputed_from_closed_projection_and_violation_count(tmp_path: Path) -> None:
    probe = _Probe()
    invalid = _commitments()["build"]
    invalid["privacy_scan_violation_count"] = 1
    invalid["privacy_scan_sha256"] = enron_capacity._privacy_scan_sha256("build", invalid)

    def violating(context: EnronCapacityPhaseContext) -> EnronCapacityPhaseResult:
        _checkpoint_all(context, probe, _TRAIN_RECORDS)
        return _result("build", commitments=invalid)

    with pytest.raises(EnronCapacityError) as raised:
        _run(tmp_path, probe, replacements={"build": violating})
    assert raised.value.code == "phase_commitment_invalid"


def test_worker_discards_benign_dependency_stderr_and_validates_only_canonical_stdout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, Any] = {}
    monkeypatch.setattr(enron_capacity, "_git_root", lambda: Path.cwd())
    monkeypatch.setattr(
        enron_capacity,
        "_validated_capacity_bootstrap",
        lambda: (Path.cwd() / "src", (), ()),
    )

    def fake_run(*args: Any, **kwargs: Any) -> Any:
        observed["command"] = args[0]
        observed.update(kwargs)
        response = {"ok": False, "code": "production_identity_invalid", "report": None}
        return subprocess.CompletedProcess(
            args[0], 0, stdout=enron_capacity._canonical_json_bytes(response), stderr=b"benign"
        )

    monkeypatch.setattr(enron_capacity.subprocess, "run", fake_run)
    with pytest.raises(EnronCapacityError) as raised:
        enron_capacity._spawn_production_worker(_options(tmp_path))

    assert raised.value.code == "production_identity_invalid"
    assert observed["stderr"] is subprocess.DEVNULL
    assert observed["env"]["HF_HUB_DISABLE_PROGRESS_BARS"] == "1"
    assert observed["env"]["TQDM_DISABLE"] == "1"
    assert "PYTHONHASHSEED" not in observed["env"]
    assert observed["command"][1:4] == ["-I", "-S", "-B"]


@pytest.mark.parametrize(
    "invalidation_mode",
    [py_compile.PycInvalidationMode.TIMESTAMP, py_compile.PycInvalidationMode.UNCHECKED_HASH],
    ids=["timestamp", "unchecked-hash"],
)
def test_worker_ignores_valid_divergent_colocated_bytecode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invalidation_mode: py_compile.PycInvalidationMode,
) -> None:
    repository = tmp_path / "repository"
    source_root = repository / "src"
    package = source_root / "nerb"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    module = package / "enron_capacity.py"
    source_payload = (
        'import json\nprint(json.dumps({"ok":False,"code":"options_invalid","report":None},'
        'sort_keys=True,separators=(",",":")))\n'
    )
    divergent_payload = source_payload.replace("options_invalid", "capacity_failed")
    assert len(source_payload.encode("utf-8")) == len(divergent_payload.encode("utf-8"))
    module.write_text(source_payload, encoding="utf-8")

    divergent = repository / "divergent.py"
    divergent.write_text(divergent_payload, encoding="utf-8")
    source_stat = module.stat()
    os.utime(divergent, ns=(source_stat.st_atime_ns, source_stat.st_mtime_ns))
    divergent_stat = divergent.stat()
    assert divergent_stat.st_size == source_stat.st_size
    assert int(divergent_stat.st_mtime) == int(source_stat.st_mtime)
    pyc_path = Path(importlib.util.cache_from_source(os.fspath(module)))
    pyc_path.parent.mkdir()
    py_compile.compile(
        os.fspath(divergent),
        cfile=os.fspath(pyc_path),
        dfile=os.fspath(module),
        doraise=True,
        invalidation_mode=invalidation_mode,
    )
    dependency_root = repository / "dependency-root"
    dependency_root.mkdir()
    hostile_marker = repository / "hostile-site-hook-ran"
    hostile_statement = f"import pathlib; pathlib.Path({os.fspath(hostile_marker)!r}).write_text('ran')\n"
    (dependency_root / "hostile.pth").write_text(hostile_statement, encoding="utf-8")
    (dependency_root / "sitecustomize.py").write_text(hostile_statement, encoding="utf-8")

    control = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            "-c",
            enron_capacity._PRODUCTION_WORKER_BOOTSTRAP,
            os.fspath(source_root),
            "1",
            os.fspath(dependency_root),
            enron_capacity._PRODUCTION_WORKER_ARGUMENT,
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )
    assert json.loads(control.stdout)["code"] == "capacity_failed"
    assert not hostile_marker.exists()

    monkeypatch.setattr(enron_capacity, "_git_root", lambda: repository)
    monkeypatch.setattr(
        enron_capacity,
        "_validated_capacity_bootstrap",
        lambda: (source_root, (), ()),
    )
    with pytest.raises(EnronCapacityError) as raised:
        enron_capacity._spawn_production_worker(_options(tmp_path, f"isolated-{invalidation_mode.name.lower()}"))
    assert raised.value.code == "options_invalid"


@pytest.mark.parametrize(
    "invalidation_mode",
    [py_compile.PycInvalidationMode.TIMESTAMP, py_compile.PycInvalidationMode.UNCHECKED_HASH],
    ids=["timestamp", "unchecked-hash"],
)
def test_tracked_launcher_ignores_site_hooks_and_valid_parent_bytecode(
    tmp_path: Path,
    invalidation_mode: py_compile.PycInvalidationMode,
) -> None:
    repository = tmp_path / "repository"
    scripts = repository / "scripts"
    package = repository / "src" / "nerb"
    scripts.mkdir(parents=True)
    package.mkdir(parents=True)
    shutil.copy2(Path.cwd() / "scripts" / "run_enron_capacity.py", scripts / "run_enron_capacity.py")
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "enron_capacity.py").write_text("", encoding="utf-8")
    cli = package / "cli.py"
    source_payload = textwrap.dedent(
        """
        import json
        import os
        import sys

        def main():
            print(json.dumps({
                "result": "safe",
                "command": sys.argv[1],
                "isolated": bool(sys.flags.isolated),
                "no_site": bool(sys.flags.no_site),
                "no_bytecode": bool(sys.flags.dont_write_bytecode),
                "sitecustomize_loaded": "sitecustomize" in sys.modules,
                "hostile_marker_exists": os.path.exists(os.environ["HOSTILE_MARKER"]),
                "pycache_prefix": sys.pycache_prefix is not None,
            }, sort_keys=True))
        """
    )
    divergent_payload = source_payload.replace('"safe"', '"evil"')
    assert len(source_payload.encode("utf-8")) == len(divergent_payload.encode("utf-8"))
    cli.write_text(source_payload, encoding="utf-8")
    divergent = repository / "divergent_cli.py"
    divergent.write_text(divergent_payload, encoding="utf-8")
    source_stat = cli.stat()
    os.utime(divergent, ns=(source_stat.st_atime_ns, source_stat.st_mtime_ns))
    pyc_path = Path(importlib.util.cache_from_source(os.fspath(cli)))
    pyc_path.parent.mkdir()
    py_compile.compile(
        os.fspath(divergent),
        cfile=os.fspath(pyc_path),
        dfile=os.fspath(cli),
        doraise=True,
        invalidation_mode=invalidation_mode,
    )

    environment = tmp_path / "venv"
    binary = environment / "bin" / "python"
    dependency_root = environment / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
    binary.parent.mkdir(parents=True)
    dependency_root.mkdir(parents=True)
    (environment / "lib64").symlink_to("lib", target_is_directory=True)
    binary.symlink_to(Path(sys.executable))
    (environment / "pyvenv.cfg").write_text(f"home = {sys.base_prefix}\n", encoding="utf-8")
    hostile_marker = tmp_path / "hostile-hook-ran"
    hostile_statement = f"import pathlib; pathlib.Path({os.fspath(hostile_marker)!r}).write_text('ran')\n"
    (dependency_root / "hostile.pth").write_text(hostile_statement, encoding="utf-8")
    (dependency_root / "sitecustomize.py").write_text(hostile_statement, encoding="utf-8")

    completed = subprocess.run(
        [
            os.fspath(binary),
            "-I",
            "-S",
            "-B",
            os.fspath(scripts / "run_enron_capacity.py"),
            "verify-enron-capacity",
        ],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "HOSTILE_MARKER": os.fspath(hostile_marker)},
        timeout=30,
    )
    payload = json.loads(completed.stdout)
    assert payload == {
        "command": "verify-enron-capacity",
        "hostile_marker_exists": False,
        "isolated": True,
        "no_bytecode": True,
        "no_site": True,
        "pycache_prefix": True,
        "result": "safe",
        "sitecustomize_loaded": False,
    }
    assert not hostile_marker.exists()


def test_recorded_production_identity_verifier_does_not_require_current_head(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report, _ = _run(tmp_path)
    execution = copy.deepcopy(report["execution"])
    recorded_capacity = _hash("recorded-capacity-source")
    execution.update(
        {
            "production_evidence": True,
            "fresh_worker": True,
            "git_tree_clean": True,
            "capacity_implementation_sha256": recorded_capacity,
            "native_extension_build_source_sha256": execution["native_build_source_sha256"],
            "monitor_interval_ns": enron_capacity.PRODUCTION_MONITOR_INTERVAL_NS,
        }
    )
    monkeypatch.setattr(enron_capacity, "_git_blob_bytes", lambda *_args: b"recorded-capacity-source")
    monkeypatch.setattr(enron_capacity, "_repository_tree_sha256", lambda *_args: execution["repository_tree_sha256"])
    monkeypatch.setattr(enron_capacity, "_core_source_sha256_at_commit", lambda *_args: execution["core_source_sha256"])
    monkeypatch.setattr(
        enron_capacity,
        "_relevant_module_sha256_at_commit",
        lambda *_args: execution["relevant_module_sha256"],
    )
    monkeypatch.setattr(
        enron_capacity,
        "_extraction_execution_sha256_at_commit",
        lambda *_args: execution["extraction_execution_sha256"],
    )
    monkeypatch.setattr(
        enron_capacity,
        "_native_build_source_sha256_at_commit",
        lambda *_args: execution["native_build_source_sha256"],
    )
    monkeypatch.setattr(
        enron_capacity,
        "_reader_lock_sha256_at_commit",
        lambda *_args: execution["reader_lock_sha256"],
    )

    def recorded_callable(*, role: str, **_kwargs: Any) -> str:
        if role == "resource_probe":
            return execution["resource_probe_implementation_sha256"]
        return execution["runner_implementation_sha256"][role.split(":", 1)[1]]

    monkeypatch.setattr(enron_capacity, "_recorded_callable_sha256", recorded_callable)
    monkeypatch.setattr(
        enron_capacity,
        "_production_execution_identity",
        lambda: pytest.fail("recorded verification must not require the current process or HEAD"),
    )

    enron_capacity._verify_recorded_production_execution(execution)


def test_execution_identity_accepts_the_matching_fresh_production_worker_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe = _Probe()
    runners = enron_capacity._validated_phase_runners(_successful_runners(probe))
    expected = enron_capacity._execution_identity(
        runners,
        probe,
        production_evidence=False,
        monitor_interval_ns=enron_capacity.PRODUCTION_MONITOR_INTERVAL_NS,
    )
    expected.update(
        {
            "production_evidence": True,
            "fresh_worker": True,
            "git_tree_clean": True,
        }
    )
    monkeypatch.setattr(enron_capacity, "_production_execution_identity", lambda: expected)

    execution = enron_capacity._execution_identity(
        runners,
        probe,
        production_evidence=True,
        monitor_interval_ns=enron_capacity.PRODUCTION_MONITOR_INTERVAL_NS,
    )

    assert execution == expected


def test_production_identity_rejects_a_native_extension_built_from_other_sources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(enron_capacity, "_FRESH_PRODUCTION_WORKER", True)
    monkeypatch.setattr(enron_capacity, "_require_globally_clean_checkout", lambda _commit: None)
    monkeypatch.setattr(enron_capacity, "_require_clean_head_sources", lambda _paths, _commit: None)
    monkeypatch.setattr(enron_capacity, "_root_process_peak_rss_bytes", lambda: 1)
    monkeypatch.setattr(
        enron_capacity,
        "_native_extension_embedded_build_source_sha256",
        lambda: _hash("stale-native-build"),
    )

    with pytest.raises(EnronCapacityError, match="production implementation identity"):
        enron_capacity._production_execution_identity()


def test_production_preloads_core_modules_and_rejects_midrun_source_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    imported: list[str] = []
    original_import = enron_capacity.importlib.import_module

    def record_import(name: str, *args: Any, **kwargs: Any) -> Any:
        imported.append(name)
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(enron_capacity.importlib, "import_module", record_import)
    enron_capacity._preload_production_modules()
    assert imported == [f"nerb.{name.removesuffix('.py')}" for name in enron_capacity._PRODUCTION_CORE_SOURCE_NAMES]

    probe = _Probe()
    runners = enron_capacity._validated_phase_runners(_successful_runners(probe))
    execution = enron_capacity._execution_identity(
        runners,
        probe,
        production_evidence=False,
        monitor_interval_ns=enron_capacity.PRODUCTION_MONITOR_INTERVAL_NS,
    )
    execution["production_evidence"] = True
    monkeypatch.setattr(enron_capacity, "_require_globally_clean_checkout", lambda _commit: None)
    monkeypatch.setattr(
        enron_capacity,
        "_relevant_module_sha256",
        lambda: {**execution["relevant_module_sha256"], "src/nerb/enron_splitting.py": _hash("edited-after-capture")},
    )

    with pytest.raises(EnronCapacityError, match="production implementation identity"):
        enron_capacity._reassert_production_execution_current(execution)


def test_relevant_module_identity_uses_only_the_closed_tracked_inventory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path(__file__).parents[2]
    git_commit = subprocess.run(
        ["git", "-C", os.fspath(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    expected_paths = {path for path in enron_capacity._relevant_tracked_worktree_paths() if (root / path).is_file()}
    before = enron_capacity._relevant_module_sha256()
    assert set(before) == expected_paths

    generated = root / "rust" / "target" / f"nerb-capacity-ignored-inventory-{os.getpid()}-{time.time_ns()}"
    injected = generated / "out" / "injected.rs"
    injected.parent.mkdir(parents=True, exist_ok=False)
    try:
        injected.write_text('pub const INJECTED: &str = "ignored";\n', encoding="utf-8")
        ignored = subprocess.run(
            ["git", "-C", os.fspath(root), "check-ignore", "--quiet", os.fspath(injected)],
            check=False,
        )
        assert ignored.returncode == 0
        assert enron_capacity._relevant_module_sha256() == before
        assert injected.relative_to(root).as_posix() not in before

        monkeypatch.setattr(
            enron_capacity,
            "_git_blob_bytes",
            lambda _commit, relative: (root / relative).read_bytes(),
        )
        monkeypatch.setattr(enron_capacity, "_relevant_module_paths_at_commit", lambda _commit: tuple(before))
        assert enron_capacity._relevant_module_sha256_at_commit(git_commit) == before
    finally:
        shutil.rmtree(generated)


def test_native_extension_embeds_the_exact_closed_rust_build_source_inventory() -> None:
    native = __import__("nerb._engine", fromlist=["BUILD_SOURCE_SHA256"])

    assert native.BUILD_SOURCE_SHA256 == enron_capacity._native_build_source_sha256()
    assert enron_capacity._native_extension_embedded_build_source_sha256() == native.BUILD_SOURCE_SHA256


def test_capacity_reader_dependency_is_exact_locked_and_documented() -> None:
    root = Path(__file__).parents[2]
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    lock = (root / "uv.lock").read_text(encoding="utf-8")
    documentation = (root / "docs/enron-bank-building.md").read_text(encoding="utf-8")

    assert 'enron-capacity = ["datasets==5.0.0"]' in pyproject
    assert re.search(r'(?ms)^\[\[package\]\]\nname = "datasets"\nversion = "5\.0\.0"$', lock)
    assert "uv run --locked --no-default-groups --group enron-capacity --no-sync --python 3.13" in documentation
    assert "--reinstall-package nerb" in documentation
    assert "do not use an independently resolved `--with` environment" in documentation
    for distribution, version in {
        "datasets": "5.0.0",
        "huggingface-hub": "1.23.0",
        "fsspec": "2026.4.0",
        "pyarrow": "25.0.0",
    }.items():
        assert f"{distribution}=={version}" in documentation
    assert "passes `token=False` plus the phase cache explicitly" in documentation
    assert "uses umask `077`" in documentation


def test_reader_provenance_stays_unloaded_until_phase_owned_isolation(tmp_path: Path) -> None:
    if any(
        importlib.util.find_spec(module_name) is None
        for module_name in ("datasets", "huggingface_hub", "fsspec", "pyarrow")
    ):
        pytest.skip("The exact locked Enron capacity reader group is not installed.")
    root = Path(__file__).parents[2]
    source_root = root / "src"
    poison = tmp_path / "poison"
    poison.mkdir(mode=0o700)
    poison_home = poison / "home"
    poison_home.mkdir(mode=0o700)
    poison_token = poison / "ambient-token"
    poison_token.write_text("hf_private_ambient_token_sentinel", encoding="utf-8")
    poison_token.chmod(0o600)
    isolated = tmp_path / "isolated"

    environment = dict(os.environ)
    environment.update(
        {
            "HOME": os.fspath(poison_home),
            "XDG_CACHE_HOME": os.fspath(poison / "xdg"),
            "HF_HOME": os.fspath(poison / "hf-home"),
            "HF_DATASETS_CACHE": os.fspath(poison / "datasets"),
            "HF_MODULES_CACHE": os.fspath(poison / "modules"),
            "HF_DATASETS_DOWNLOADED_DATASETS_PATH": os.fspath(poison / "downloads"),
            "HF_DATASETS_EXTRACTED_DATASETS_PATH": os.fspath(poison / "extracted"),
            "HUGGINGFACE_HUB_CACHE": os.fspath(poison / "huggingface-hub"),
            "HF_HUB_CACHE": os.fspath(poison / "hub"),
            "HUGGINGFACE_ASSETS_CACHE": os.fspath(poison / "huggingface-assets"),
            "HF_ASSETS_CACHE": os.fspath(poison / "assets"),
            "HF_XET_CACHE": os.fspath(poison / "xet"),
            "HF_TOKEN_PATH": os.fspath(poison_token),
            "HF_TOKEN": "hf_private_environment_sentinel",
            "HUGGING_FACE_HUB_TOKEN": "hf_private_legacy_sentinel",
            "HF_OIDC_RESOURCE": "poison-resource",
            "HF_OIDC_ID_TOKEN": "poison-oidc-token",
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://poison.invalid/oidc",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "poison-actions-token",
            "HF_ENDPOINT": "https://poison.invalid",
            "HF_HUB_DISABLE_IMPLICIT_TOKEN": "0",
            "HF_HUB_DISABLE_SYMLINKS": "0",
            "HF_HUB_DISABLE_XET": "0",
            "HF_HUB_OFFLINE": "1",
            "HF_DATASETS_OFFLINE": "1",
            "TRANSFORMERS_OFFLINE": "1",
        }
    )
    script = textwrap.dedent(
        """
        import hashlib
        import json
        import os
        import stat
        import sys
        from pathlib import Path

        source_root = Path(sys.argv[1])
        isolated = Path(sys.argv[2])
        poison = Path(sys.argv[3])
        sys.path.insert(0, os.fspath(source_root))
        os.umask(0o022)

        from nerb import enron_capacity as capacity

        def loaded_reader_modules():
            return capacity._loaded_reader_modules()

        def tree_snapshot(root):
            result = []
            for path in sorted(root.rglob("*")):
                info = path.lstat()
                digest = None
                if stat.S_ISREG(info.st_mode):
                    digest = hashlib.sha256(path.read_bytes()).hexdigest()
                result.append((path.relative_to(root).as_posix(), stat.S_IFMT(info.st_mode), info.st_size, digest))
            return result

        poison_before = tree_snapshot(poison)
        assert not loaded_reader_modules()
        capacity._set_production_worker_umask()
        capacity._preload_production_modules()
        baseline = capacity._runtime_environment_identity()
        assert not loaded_reader_modules()
        assert capacity._reader_environment_identity() == baseline["reader_environment"]
        assert not loaded_reader_modules()

        work_dir = isolated / "phases" / "preparation"
        runtime = work_dir / "runtime"
        work_dir.mkdir(parents=True, mode=0o700)
        root_names = (
            "home", "tmp", "hf-home", "hf-datasets", "hf-modules", "hf-downloads", "hf-extracted",
            "hf-hub", "hf-assets", "hf-xet", "hf-token", "transformers", "xdg-cache", "spool", "scratch",
        )
        roots = {}
        for name in root_names:
            path = runtime / name
            path.mkdir(parents=True, mode=0o700)
            roots[name] = path
        phase_environment = {
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
        context = capacity.EnronCapacityPhaseContext(
            "preparation",
            work_dir,
            lambda _records: None,
            lambda path: path,
            lambda: None,
            runtime_environment=phase_environment,
            scratch_dir=roots["scratch"],
            spool_dir=roots["spool"],
            owned_root_count=16,
        )
        with capacity._applied_phase_runtime_environment(phase_environment):
            module, before, runtime_sha256 = capacity._load_phase_scoped_datasets_reader(context)
            mode_dir = roots["hf-hub"] / "mode-dir"
            mode_dir.mkdir()
            mode_file = roots["hf-datasets"] / "mode-file"
            mode_file.write_bytes(b"bounded-cache-probe")
            from huggingface_hub.file_download import are_symlinks_supported
            assert are_symlinks_supported(roots["hf-hub"]) is False
            assert stat.S_IMODE(mode_dir.stat().st_mode) == 0o700
            assert stat.S_IMODE(mode_file.stat().st_mode) == 0o600
            after = capacity._reader_isolation_snapshot(context, module, stage="after_source_read")
            assert before == capacity._expected_reader_isolation_snapshot("before_source_read")
            assert after == capacity._expected_reader_isolation_snapshot("after_source_read")
            assert runtime_sha256 == capacity._canonical_hash(capacity._runtime_environment_identity())
            assert before["cache_symlinks_disabled"] is True
            assert after["ambient_credentials_disabled"] is True
            assert not any(path.is_symlink() for path in work_dir.rglob("*"))
        assert os.environ["HOME"] == os.fspath(poison / "home")
        assert os.environ["HF_TOKEN"] == "hf_private_environment_sentinel"
        assert tree_snapshot(poison) == poison_before
        assert capacity._runtime_environment_identity() == baseline
        assert "datasets" in sys.modules and "huggingface_hub" in sys.modules
        print(json.dumps({"loaded": len(loaded_reader_modules()), "before": before, "after": after}, sort_keys=True))
        """
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-c", script, os.fspath(source_root), os.fspath(isolated), os.fspath(poison)],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        timeout=60,
    )

    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["loaded"] > 0
    assert result["before"]["effective_path_count"] == len(enron_capacity._READER_EFFECTIVE_PATH_LABELS)
    assert result["before"]["official_endpoint_sha256"] == _hash(enron_capacity._READER_OFFICIAL_ENDPOINT)
    assert result["after"]["token_files_absent"] is True
    assert "hf_private" not in completed.stdout

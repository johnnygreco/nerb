#!/usr/bin/env python3
"""Run a same-host synthetic soak of the production resource observer protocol.

The public process is the launcher.  It starts an isolated worker using the
same launcher/worker resource-observer classes as a production capacity run,
but the worker uses only generated data in an owner-only temporary tree.

The default duration is the required thirty-minute soak.  Shorter durations
are useful smoke checks, but the emitted report never labels them
decision-grade.  Output is deliberately aggregate-only: no samples, process
identifiers, source values, hostnames, usernames, or filesystem paths are
serialized. Pass ``--require-decision-grade`` when the process exit status must
enforce the decision gate rather than smoke-level operational success.

PyArrow is optional at import time because it is not a core dependency, but a
run without an exercised PyArrow workload cannot be decision-grade. Observer
CPU overhead is exact per-thread CPU time for the protocol and deadline-
supervisor threads. Memory is only a conservative launcher-process high-water
bound; Python does not expose per-thread allocation high-water marks.
"""

from __future__ import annotations

import argparse
import ctypes
import gc
import hashlib
import importlib
import importlib.metadata
import json
import math
import os
import platform
import re
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
from typing import Any, NoReturn, cast

from nerb import Bank, enron_capacity

_DEFAULT_DURATION_SECONDS = 1_800.0
_INJECTED_STALL_NS = 501_000_000
_EXPECTED_INTERVAL_NS = 100_000_000
_EXPECTED_LIMIT_NS = 500_000_000
_DECISION_GRADE_MAX_ACQUISITION_NS = 250_000_000
_DECISION_GRADE_MAX_COMPLETION_GAP_NS = 400_000_000
_EXPECTED_PYTHON_MAJOR = 3
_EXPECTED_PYTHON_MINOR = 13
_EXPECTED_PYARROW_VERSION = "25.0.0"
_SOURCE_PROVENANCE_BOUNDARY = "trusted_quiescent_worktree_observation"
_READER_LOCK_FILES = ("pyproject.toml", "uv.lock")
_SOAK_BOOTSTRAP_ATTRIBUTE = "_nerb_resource_observer_soak_bootstrap"
_SOAK_BOOTSTRAP_SCHEMA = "nerb.resource_observer_soak.bootstrap"
_SOAK_DISPATCH = "resource-observer-soak"
_BOOTSTRAP_IDENTITY_FIELDS = frozenset(
    {
        "isolated",
        "site_disabled",
        "bytecode_disabled",
        "site_hooks_absent",
        "private_fresh_pycache",
        "source_root_validated",
        "dependency_roots_validated",
        "source_import_guard_validated",
        "dependency_root_count",
        "dependency_root_layouts_sha256",
        "bootstrap_launcher_sha256",
        "source_import_guard_sha256",
        "exact",
    }
)
_MAX_WORKER_RESULT_BYTES = 64 * 1024
_MIN_LARGE_TREE_REGULAR_ENTRIES = 10_000
_LARGE_TREE_DIRECTORIES = 100
_LARGE_TREE_FILES_PER_DIRECTORY = 100
_PHASE = "preparation"
_LIMITATION_SYNTHETIC = "The workload is synthetic and does not establish production-data representativeness."
_LIMITATION_SAMPLING = "Sampling cannot prove capture of every sub-interval RSS or filesystem transient."
_LIMITATION_OBSERVER_MEMORY = (
    "Observer CPU uses exact observer-thread CPU time; memory is a launcher-process high-water bound."
)
_LIMITATION_PYARROW = "PyArrow was unavailable, so columnar workload coverage is absent."
_LIMITATION_SHORT = "This shortened run is a smoke check, not the required thirty-minute same-host soak."
_LIMITATION_DIRTY = "The worktree was not clean, so this run cannot be decision-grade evidence."
_LIMITATION_HEAD = "The observed worktree source bytes did not match the claimed HEAD blobs."
_LIMITATION_NATIVE = "The loaded native extension was not built from the claimed HEAD Rust sources."
_LIMITATION_UNSTABLE = "The source identity changed during the run, so this evidence is invalid."
_LIMITATION_WORKER = "A worker did not attest the same observed worktree source bytes as the launcher."
_LIMITATION_HEADROOM = "Observed latency passed the hard limit but lacked decision-grade operating headroom."
_LIMITATION_ENVIRONMENT = "The runtime did not use the required Python 3.13 and PyArrow 25.0.0 environment."
_LIMITATION_READER_LOCK = "The active reader lock did not match the claimed HEAD reader lock."
_LIMITATION_BOOTSTRAP = "The launcher and workers did not use the exact isolated resource-observer bootstrap."
_LIMITATION_SOURCE_TRUST = (
    "Source provenance assumes a trusted, access-controlled, quiescent worktree for the complete command."
)
_ALLOWED_LIMITATIONS = frozenset(
    {
        _LIMITATION_SYNTHETIC,
        _LIMITATION_SAMPLING,
        _LIMITATION_OBSERVER_MEMORY,
        _LIMITATION_PYARROW,
        _LIMITATION_SHORT,
        _LIMITATION_DIRTY,
        _LIMITATION_HEAD,
        _LIMITATION_NATIVE,
        _LIMITATION_UNSTABLE,
        _LIMITATION_WORKER,
        _LIMITATION_HEADROOM,
        _LIMITATION_ENVIRONMENT,
        _LIMITATION_READER_LOCK,
        _LIMITATION_BOOTSTRAP,
        _LIMITATION_SOURCE_TRUST,
    }
)


def _safe_error_code(exc: BaseException) -> str:
    code = getattr(exc, "code", None)
    if isinstance(code, str) and code and len(code) <= 80 and code.replace("_", "").isalnum():
        return code
    return "soak_failed"


def _implementation_sha256(path: Path) -> str:
    try:
        payload = _read_stable_regular_bytes(path)
    except RuntimeError:
        return "sha256:" + hashlib.sha256(b"nerb/resource-observer-bootstrap-invalid").hexdigest()
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _runtime_bootstrap_identity() -> dict[str, Any]:
    repository_root = Path(__file__).resolve().parents[1]
    launcher_path = repository_root / "scripts" / "run_enron_capacity.py"
    guard_path = repository_root / "src" / "nerb" / "_capacity_bootstrap.py"
    launcher_sha256 = _implementation_sha256(launcher_path)
    guard_sha256 = _implementation_sha256(guard_path)
    isolated = bool(sys.flags.isolated)
    site_disabled = bool(sys.flags.no_site)
    bytecode_disabled = bool(sys.flags.dont_write_bytecode and sys.dont_write_bytecode)
    site_hooks_absent = "sitecustomize" not in sys.modules and "usercustomize" not in sys.modules
    source_root_validated = False
    dependency_roots_validated = False
    import_guard_validated = False
    private_fresh_pycache = False
    dependency_root_count = 0
    dependency_root_layouts_sha256 = (
        "sha256:" + hashlib.sha256(b"nerb/resource-observer-dependency-layouts-unavailable").hexdigest()
    )
    try:
        source_root, dependency_roots, layouts, observer_fd = enron_capacity._validated_capacity_bootstrap()
        marker = getattr(sys, _SOAK_BOOTSTRAP_ATTRIBUTE, None)
        capacity_marker = getattr(sys, "_nerb_capacity_bootstrap", None)
        if (
            observer_fd is not None
            or not isinstance(marker, Mapping)
            or set(marker)
            != {
                "schema",
                "role",
                "source_root",
                "dependency_roots",
                "baseline_path",
                "pycache_root",
                "fresh_private_pycache",
            }
            or not isinstance(capacity_marker, Mapping)
            or marker.get("schema") != _SOAK_BOOTSTRAP_SCHEMA
            or marker.get("role") != "resource_observer_soak"
            or marker.get("source_root") != os.fspath(source_root)
            or marker.get("dependency_roots") != [os.fspath(path) for path in dependency_roots]
            or marker.get("baseline_path") != capacity_marker.get("baseline_path")
            or marker.get("pycache_root") != sys.pycache_prefix
            or marker.get("fresh_private_pycache") is not True
            or source_root != repository_root / "src"
        ):
            raise RuntimeError("resource observer bootstrap marker mismatch")
        pycache_root = Path(str(sys.pycache_prefix))
        pycache_info = pycache_root.stat()
        if (
            pycache_info.st_uid != os.geteuid()
            or stat.S_IMODE(pycache_info.st_mode) & 0o077
            or any(pycache_root.iterdir())
        ):
            raise RuntimeError("resource observer pycache is not fresh and private")
        source_root_validated = True
        dependency_roots_validated = True
        import_guard_validated = True
        private_fresh_pycache = True
        dependency_root_count = len(dependency_roots)
        dependency_root_layouts_sha256 = (
            "sha256:"
            + hashlib.sha256(
                json.dumps(list(layouts), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
            ).hexdigest()
        )
    except (OSError, RuntimeError, TypeError, ValueError, enron_capacity.EnronCapacityError):
        pass
    exact = bool(
        isolated
        and site_disabled
        and bytecode_disabled
        and site_hooks_absent
        and private_fresh_pycache
        and source_root_validated
        and dependency_roots_validated
        and import_guard_validated
        and dependency_root_count > 0
    )
    return {
        "isolated": isolated,
        "site_disabled": site_disabled,
        "bytecode_disabled": bytecode_disabled,
        "site_hooks_absent": site_hooks_absent,
        "private_fresh_pycache": private_fresh_pycache,
        "source_root_validated": source_root_validated,
        "dependency_roots_validated": dependency_roots_validated,
        "source_import_guard_validated": import_guard_validated,
        "dependency_root_count": dependency_root_count,
        "dependency_root_layouts_sha256": dependency_root_layouts_sha256,
        "bootstrap_launcher_sha256": launcher_sha256,
        "source_import_guard_sha256": guard_sha256,
        "exact": exact,
    }


def _assert_aggregate_report_privacy(report: Mapping[str, Any], *, private_paths: Sequence[str] = ()) -> None:
    """Enforce a closed aggregate schema and reject private string sentinels."""

    def fail() -> NoReturn:
        raise RuntimeError("aggregate report contained a private or unrecognized value")

    def mapping(value: Any, fields: set[str]) -> Mapping[str, Any]:
        if not isinstance(value, Mapping) or set(value) != fields:
            fail()
        return value

    def boolean(value: Any) -> bool:
        if type(value) is not bool:
            fail()
        return value

    def integer(value: Any, *, positive: bool = False) -> int:
        if type(value) is not int or value < (1 if positive else 0):
            fail()
        return value

    def number(value: Any) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            fail()
        return float(value)

    def sha256(value: Any) -> str:
        if not isinstance(value, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
            fail()
        return value

    def package_version(value: Any, *, optional: bool = False) -> str | None:
        if optional and value is None:
            return None
        if (
            not isinstance(value, str)
            or re.fullmatch(r"[0-9]{1,4}(?:\.[0-9]{1,4}){1,3}[a-z0-9.+-]{0,32}", value) is None
        ):
            fail()
        return value

    def safe_code(value: Any, *, optional: bool = False) -> str | None:
        if optional and value is None:
            return None
        if not isinstance(value, str) or re.fullmatch(r"[a-z][a-z0-9_]{0,79}", value) is None:
            fail()
        return value

    def percentiles(value: Any) -> None:
        item = mapping(value, {"count", "p50", "p95", "p99", "max"})
        count = integer(item["count"])
        values = [item[field] for field in ("p50", "p95", "p99", "max")]
        if count == 0:
            if any(entry is not None for entry in values):
                fail()
            return
        if any(type(entry) is not int or entry < 0 for entry in values) or values != sorted(values):
            fail()

    def observer(value: Any) -> None:
        item = mapping(
            value,
            {
                "valid_sample_count",
                "invalid_sample_count",
                "percentile_method",
                "acquisition_duration_ns",
                "completion_to_completion_gap_ns",
                "scheduler_lateness_ns",
                "observer_thread_cpu_ns",
                "observer_thread_cpu_fraction",
            },
        )
        integer(item["valid_sample_count"])
        integer(item["invalid_sample_count"])
        if item["percentile_method"] != "nearest_rank":
            fail()
        for field in ("acquisition_duration_ns", "completion_to_completion_gap_ns", "scheduler_lateness_ns"):
            percentiles(item[field])
        integer(item["observer_thread_cpu_ns"])
        number(item["observer_thread_cpu_fraction"])

    def bootstrap_identity(value: Any) -> Mapping[str, Any]:
        bootstrap = mapping(
            value,
            set(_BOOTSTRAP_IDENTITY_FIELDS),
        )
        boolean_fields = {
            "isolated",
            "site_disabled",
            "bytecode_disabled",
            "site_hooks_absent",
            "private_fresh_pycache",
            "source_root_validated",
            "dependency_roots_validated",
            "source_import_guard_validated",
        }
        for field in boolean_fields:
            boolean(bootstrap[field])
        dependency_root_count = integer(bootstrap["dependency_root_count"])
        for field in (
            "dependency_root_layouts_sha256",
            "bootstrap_launcher_sha256",
            "source_import_guard_sha256",
        ):
            sha256(bootstrap[field])
        exact = boolean(bootstrap["exact"])
        expected_exact = bool(all(bootstrap[field] is True for field in boolean_fields) and dependency_root_count > 0)
        if exact is not expected_exact:
            fail()
        return bootstrap

    error_fields = {"report_type", "ok", "decision_grade", "error_code", "policy_constants_verified"}
    if set(report) == error_fields:
        if (
            report["report_type"] != "nerb.resource_observer_soak"
            or boolean(report["ok"])
            or boolean(report["decision_grade"])
        ):
            fail()
        safe_code(report["error_code"])
        boolean(report["policy_constants_verified"])
    else:
        item = mapping(
            report,
            {
                "report_type",
                "ok",
                "decision_grade",
                "same_host",
                "platform",
                "bootstrap",
                "environment",
                "requested_duration_seconds",
                "completed_required_duration",
                "source_identity",
                "source_identity_stable",
                "worker_sources_bound",
                "policy",
                "positive_soak",
                "fail_closed_injection",
                "cleanup",
                "limitations",
            },
        )
        if item["report_type"] != "nerb.resource_observer_soak":
            fail()
        for field in (
            "ok",
            "decision_grade",
            "same_host",
            "completed_required_duration",
            "source_identity_stable",
            "worker_sources_bound",
        ):
            boolean(item[field])
        number(item["requested_duration_seconds"])

        bootstrap = mapping(
            item["bootstrap"],
            {
                "launcher",
                "launcher_stable",
                "positive_worker",
                "positive_worker_stable",
                "fail_closed_worker",
                "fail_closed_worker_stable",
                "all_exact",
            },
        )
        launcher_bootstrap = bootstrap_identity(bootstrap["launcher"])
        positive_bootstrap = bootstrap_identity(bootstrap["positive_worker"])
        fail_closed_bootstrap = bootstrap_identity(bootstrap["fail_closed_worker"])
        for field in ("launcher_stable", "positive_worker_stable", "fail_closed_worker_stable", "all_exact"):
            boolean(bootstrap[field])
        expected_bootstrap_exact = bool(
            bootstrap["launcher_stable"] is True
            and bootstrap["positive_worker_stable"] is True
            and bootstrap["fail_closed_worker_stable"] is True
            and launcher_bootstrap == positive_bootstrap == fail_closed_bootstrap
            and launcher_bootstrap["exact"] is True
        )
        if bootstrap["all_exact"] is not expected_bootstrap_exact:
            fail()

        platform_item = mapping(item["platform"], {"system", "architecture", "expected_process_containment_policy"})
        expected_system = "linux" if sys.platform.startswith("linux") else "darwin"
        expected_architecture = platform.machine().lower()
        if (
            platform_item["system"] != expected_system
            or platform_item["architecture"] != expected_architecture
            or re.fullmatch(r"[a-z0-9_.-]{1,64}", expected_architecture) is None
        ):
            fail()
        containment = mapping(
            platform_item["expected_process_containment_policy"],
            {"mode", "architecture", "policy_sha256"},
        )
        if (
            containment["mode"] != enron_capacity._expected_process_containment_mode()
            or containment["architecture"] != expected_architecture
        ):
            fail()
        sha256(containment["policy_sha256"])

        environment = mapping(
            item["environment"],
            {
                "python_major",
                "python_minor",
                "pyarrow_version",
                "pyarrow_distribution_file_count",
                "pyarrow_distribution_total_bytes",
                "pyarrow_distribution_sha256",
                "pyarrow_distribution_root_bound",
                "launcher_environment_verified",
                "positive_worker_import_origin_bound",
                "positive_worker_module_version_matches_distribution",
                "exact_expected_versions_verified",
            },
        )
        python_major = integer(environment["python_major"], positive=True)
        python_minor = integer(environment["python_minor"])
        pyarrow_version = package_version(environment["pyarrow_version"], optional=True)
        integer(environment["pyarrow_distribution_file_count"])
        integer(environment["pyarrow_distribution_total_bytes"])
        sha256(environment["pyarrow_distribution_sha256"])
        for field in (
            "pyarrow_distribution_root_bound",
            "launcher_environment_verified",
            "positive_worker_import_origin_bound",
            "positive_worker_module_version_matches_distribution",
            "exact_expected_versions_verified",
        ):
            boolean(environment[field])
        exact_environment = bool(
            python_major == _EXPECTED_PYTHON_MAJOR
            and python_minor == _EXPECTED_PYTHON_MINOR
            and pyarrow_version == _EXPECTED_PYARROW_VERSION
            and environment["launcher_environment_verified"] is True
            and environment["pyarrow_distribution_root_bound"] is True
            and environment["positive_worker_import_origin_bound"] is True
            and environment["positive_worker_module_version_matches_distribution"] is True
        )
        runtime_environment = _runtime_environment_identity()
        if (
            (python_major, python_minor) != (sys.version_info.major, sys.version_info.minor)
            or environment["exact_expected_versions_verified"] is not exact_environment
            or {field: environment[field] for field in runtime_environment} != runtime_environment
        ):
            fail()

        source = mapping(
            item["source_identity"],
            {
                "git_commit",
                "git_tree_oid",
                "worktree_clean",
                "head_blobs_match",
                "native_extension_matches_head",
                "reader_lock_matches_head",
                "capacity_implementation_sha256",
                "soak_implementation_sha256",
                "bootstrap_launcher_sha256",
                "source_import_guard_sha256",
                "nerb_source_file_count",
                "nerb_source_inventory_sha256",
                "native_extension_sha256",
                "native_build_source_sha256",
                "native_extension_build_source_sha256",
                "reader_lock_sha256",
                "head_reader_lock_sha256",
            },
        )
        for field in ("git_commit", "git_tree_oid"):
            if not isinstance(source[field], str) or re.fullmatch(r"[0-9a-f]{40}", source[field]) is None:
                fail()
        for field in (
            "worktree_clean",
            "head_blobs_match",
            "native_extension_matches_head",
            "reader_lock_matches_head",
        ):
            boolean(source[field])
        integer(source["nerb_source_file_count"], positive=True)
        for field in (
            "capacity_implementation_sha256",
            "soak_implementation_sha256",
            "bootstrap_launcher_sha256",
            "source_import_guard_sha256",
            "nerb_source_inventory_sha256",
            "native_extension_sha256",
            "native_build_source_sha256",
            "native_extension_build_source_sha256",
            "reader_lock_sha256",
            "head_reader_lock_sha256",
        ):
            sha256(source[field])
        if source["reader_lock_matches_head"] is not (
            source["reader_lock_sha256"] == source["head_reader_lock_sha256"]
        ):
            fail()

        policy = mapping(
            item["policy"],
            {
                "source_provenance_boundary",
                "production_monitor_interval_ns",
                "maximum_resource_observation_wall_gap_ns",
                "maximum_resource_acquisition_duration_ns",
                "decision_grade_maximum_resource_observation_wall_gap_ns",
                "decision_grade_maximum_resource_acquisition_duration_ns",
                "exact_expected_constants_verified",
            },
        )
        if (
            policy["source_provenance_boundary"] != _SOURCE_PROVENANCE_BOUNDARY
            or policy["production_monitor_interval_ns"] != _EXPECTED_INTERVAL_NS
            or policy["maximum_resource_observation_wall_gap_ns"] != _EXPECTED_LIMIT_NS
            or policy["maximum_resource_acquisition_duration_ns"] != _EXPECTED_LIMIT_NS
            or policy["decision_grade_maximum_resource_observation_wall_gap_ns"]
            != _DECISION_GRADE_MAX_COMPLETION_GAP_NS
            or policy["decision_grade_maximum_resource_acquisition_duration_ns"] != _DECISION_GRADE_MAX_ACQUISITION_NS
            or boolean(policy["exact_expected_constants_verified"]) is not True
        ):
            fail()

        positive = mapping(
            item["positive_soak"],
            {
                "passed",
                "decision_headroom_passed",
                "workload_elapsed_ns",
                "workload_iterations",
                "workload_iterations_per_second",
                "workloads",
                "observer",
                "resource_snapshot",
                "launcher_process_peak_rss_bytes",
            },
        )
        boolean(positive["passed"])
        boolean(positive["decision_headroom_passed"])
        integer(positive["workload_elapsed_ns"])
        integer(positive["workload_iterations"])
        number(positive["workload_iterations_per_second"])
        integer(positive["launcher_process_peak_rss_bytes"], positive=True)
        workloads = mapping(
            positive["workloads"],
            {
                "owner_only_tree_mutations",
                "owner_only_tree_seeded_regular_entries",
                "owner_only_tree_retained_seed_regular_entries",
                "owner_only_tree_terminal_regular_entries",
                "sqlite_transactions",
                "pyarrow_available",
                "pyarrow_batches",
                "native_rust_available",
                "native_rust_scans",
                "c_held_gil_intervals",
                "descendant_churn_cycles",
            },
        )
        for field in ("pyarrow_available", "native_rust_available"):
            boolean(workloads[field])
        for field in set(workloads) - {"pyarrow_available", "native_rust_available"}:
            integer(workloads[field])
        observer(positive["observer"])
        positive_observer = positive["observer"]
        acquisition_max = positive_observer["acquisition_duration_ns"]["max"]
        completion_gap_max = positive_observer["completion_to_completion_gap_ns"]["max"]
        expected_headroom = bool(
            type(acquisition_max) is int
            and acquisition_max <= _DECISION_GRADE_MAX_ACQUISITION_NS
            and type(completion_gap_max) is int
            and completion_gap_max <= _DECISION_GRADE_MAX_COMPLETION_GAP_NS
        )
        if positive["decision_headroom_passed"] is not expected_headroom:
            fail()
        snapshot = mapping(
            positive["resource_snapshot"],
            {
                "resource_observation_count",
                "resource_acquisition_retry_count",
                "peak_process_tree_rss_bytes",
                "minimum_free_disk_bytes",
                "owned_disk_high_water_bytes",
                "maximum_resource_observation_wall_gap_ns",
                "maximum_resource_acquisition_duration_ns",
            },
        )
        for snapshot_value in snapshot.values():
            integer(snapshot_value)

        injection = mapping(
            item["fail_closed_injection"],
            {
                "passed",
                "injected_stall_ns",
                "observed_stall_ns",
                "injection_count",
                "expected_failure_code",
                "observed_failure_code",
                "observer",
            },
        )
        boolean(injection["passed"])
        for field in ("injected_stall_ns", "observed_stall_ns", "injection_count"):
            integer(injection[field])
        if injection["expected_failure_code"] != "resource_acquisition_timeout":
            fail()
        safe_code(injection["observed_failure_code"], optional=True)
        observer(injection["observer"])

        cleanup = mapping(
            item["cleanup"],
            {
                "worker_process_groups_gone",
                "descriptor_check_available",
                "open_descriptor_count_before",
                "open_descriptor_count_after",
                "descriptor_leak_free",
                "scratch_removed",
            },
        )
        for field in (
            "worker_process_groups_gone",
            "descriptor_check_available",
            "descriptor_leak_free",
            "scratch_removed",
        ):
            boolean(cleanup[field])
        integer(cleanup["open_descriptor_count_before"])
        integer(cleanup["open_descriptor_count_after"])
        limitations = item["limitations"]
        if (
            not isinstance(limitations, list)
            or len(limitations) != len(set(limitations))
            or any(value not in _ALLOWED_LIMITATIONS for value in limitations)
        ):
            fail()
        if (
            (_LIMITATION_ENVIRONMENT in limitations) != (not exact_environment)
            or (_LIMITATION_READER_LOCK in limitations) != (source["reader_lock_matches_head"] is not True)
            or (_LIMITATION_BOOTSTRAP in limitations) != (bootstrap["all_exact"] is not True)
            or (
                item["decision_grade"] is True
                and (
                    not exact_environment
                    or source["reader_lock_matches_head"] is not True
                    or bootstrap["all_exact"] is not True
                )
            )
        ):
            fail()

    private_path_values = {
        value for value in (*private_paths, os.getcwd(), os.fspath(Path.home())) if isinstance(value, str) and value
    }
    private_identity_values = {
        value
        for value in (os.environ.get("USER"), os.environ.get("LOGNAME"), socket.gethostname())
        if isinstance(value, str) and len(value) >= 4
    }

    def reject_private_strings(value: Any) -> None:
        if isinstance(value, Mapping):
            for item_value in value.values():
                reject_private_strings(item_value)
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            for item_value in value:
                reject_private_strings(item_value)
        elif isinstance(value, str) and (
            value.startswith("/")
            or any(path in value for path in private_path_values)
            or any(identity in value for identity in private_identity_values)
        ):
            fail()

    reject_private_strings(report)


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


def _reject_duplicate_pairs(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate worker result key")
        result[key] = value
    return result


def _validated_worker_result(value: object, *, mode: str, nonce: str) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    item = cast(Mapping[str, Any], value)
    common = {
        "ok",
        "worker_role",
        "protocol_nonce_sha256",
        "runtime_source_identity",
        "runtime_source_stable",
        "runtime_bootstrap_identity",
        "runtime_bootstrap_stable",
    }
    success = common | {
        "workload_elapsed_ns",
        "workload_iterations",
        "workloads",
        "pyarrow_provenance",
        "resource_snapshot",
    }
    failure = common | {"error_code"}
    detailed_failure = failure | {"failure_stage", "failure_origin", "failure_condition"}
    fields = frozenset(item)
    if fields not in {frozenset(success), frozenset(failure), frozenset(detailed_failure)}:
        return None
    if (
        item.get("worker_role") != mode
        or item.get("protocol_nonce_sha256") != "sha256:" + hashlib.sha256(nonce.encode("ascii")).hexdigest()
        or type(item.get("runtime_source_stable")) is not bool
        or type(item.get("runtime_bootstrap_stable")) is not bool
        or not isinstance(item.get("runtime_source_identity"), Mapping)
        or not _bootstrap_identity_is_closed(item.get("runtime_bootstrap_identity"))
    ):
        return None
    if fields == frozenset(success):
        if (
            mode != "positive"
            or item.get("ok") is not True
            or not _pyarrow_provenance_is_closed(item.get("pyarrow_provenance"))
        ):
            return None
    elif (
        item.get("ok") is not False
        or not isinstance(item.get("error_code"), str)
        or re.fullmatch(r"[a-z][a-z0-9_]{0,79}", str(item.get("error_code"))) is None
    ):
        return None
    return dict(item)


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
    filesystems: tuple[enron_capacity._FilesystemPreflight, ...]
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
        self.provenance = _pyarrow_provenance_identity()
        try:
            pa = importlib.import_module("pyarrow")
            pc = importlib.import_module("pyarrow.compute")
            ipc = importlib.import_module("pyarrow.ipc")
            self.provenance = _pyarrow_provenance_identity(imported_modules=(pa, pc, ipc))
            if (
                self.provenance["distribution_root_bound"] is not True
                or self.provenance["import_origin_bound"] is not True
                or self.provenance["module_version_matches_distribution"] is not True
            ):
                raise RuntimeError("PyArrow provenance is invalid")

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
                phase_eligible = bool(
                    state is not None and now >= state.started_ns and wall_now >= state.started_wall_ns
                )
                if (
                    phase_eligible
                    and state is not None
                    and wall_now < (state.last_resource_wall_ns or state.started_wall_ns)
                ):
                    condition = "negative_phase_resource_gap"
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
            "pyarrow_provenance": arrow.provenance,
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
    try:
        observer_fd = int(observer_raw)
        result_fd = int(result_raw)
        duration_seconds = float(duration_raw)
        observer_info = os.fstat(observer_fd)
        result_info = os.fstat(result_fd)
    except (OSError, TypeError, ValueError):
        raise SystemExit(2) from None
    if (
        mode not in {"positive", "stall"}
        or observer_fd < 3
        or result_fd < 3
        or observer_fd == result_fd
        or not stat.S_ISSOCK(observer_info.st_mode)
        or not stat.S_ISFIFO(result_info.st_mode)
        or not math.isfinite(duration_seconds)
        or duration_seconds <= 0
        or re.fullmatch(r"[0-9a-f]{64}", nonce) is None
    ):
        raise SystemExit(2)
    tree_root = Path(tree_raw)
    output_parent = Path(output_raw)
    if not tree_root.is_absolute() or not output_parent.is_absolute():
        raise SystemExit(2)
    ledger_dir = output_parent.parent / "ledger"
    endpoint = socket.socket(fileno=observer_fd)
    endpoint.set_inheritable(False)
    os.set_inheritable(result_fd, False)
    result: dict[str, Any]
    bootstrap_identity_started = _runtime_bootstrap_identity()
    if bootstrap_identity_started["exact"] is not True:
        endpoint.close()
        os.close(result_fd)
        raise SystemExit(2)
    source_identity_started = _runtime_source_hashes()
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
    try:
        source_identity_finished = _runtime_source_hashes()
    except RuntimeError:
        source_identity_finished = {}
    source_identity_stable = source_identity_finished == source_identity_started
    if not source_identity_stable:
        result = {"ok": False, "error_code": "source_identity_changed"}
    bootstrap_identity_finished = _runtime_bootstrap_identity()
    bootstrap_identity_stable = bootstrap_identity_finished == bootstrap_identity_started
    if not bootstrap_identity_stable or bootstrap_identity_finished["exact"] is not True:
        result = {"ok": False, "error_code": "bootstrap_identity_changed"}
    result["runtime_source_identity"] = source_identity_finished
    result["runtime_source_stable"] = source_identity_stable
    result["runtime_bootstrap_identity"] = bootstrap_identity_finished
    result["runtime_bootstrap_stable"] = bootstrap_identity_stable
    result["worker_role"] = mode
    result["protocol_nonce_sha256"] = "sha256:" + hashlib.sha256(nonce.encode("ascii")).hexdigest()
    payload = json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    try:
        _write_all(result_fd, payload)
    finally:
        os.close(result_fd)
    raise SystemExit(0 if result.get("ok") is True else 1)


def _worker_command(
    *,
    mode: str,
    observer_fd: int,
    result_fd: int,
    duration_seconds: float,
    nonce: str,
    tree_root: Path,
    output_parent: Path,
) -> list[str]:
    return [
        sys.executable,
        "-I",
        "-S",
        "-B",
        os.fspath(Path(__file__).resolve().parent / "run_enron_capacity.py"),
        _SOAK_DISPATCH,
        "--worker",
        mode,
        str(observer_fd),
        str(result_fd),
        repr(duration_seconds),
        nonce,
        os.fspath(tree_root),
        os.fspath(output_parent),
    ]


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

    def _record_sample(self, frame: Mapping[str, Any]) -> None:
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

    def _send(self, frame: Mapping[str, Any]) -> None:
        self._record_sample(frame)
        super()._send(frame)

    def _send_final(self, frame: Mapping[str, Any]) -> None:
        self._record_sample(frame)
        super()._send_final(frame)

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
            _worker_command(
                mode=mode,
                observer_fd=worker_endpoint.fileno(),
                result_fd=result_write_fd,
                duration_seconds=duration_seconds,
                nonce=nonce,
                tree_root=tree_root,
                output_parent=output_parent,
            ),
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
            decoded = json.loads(payload, object_pairs_hook=_reject_duplicate_pairs)
            validated = _validated_worker_result(decoded, mode=mode, nonce=nonce)
            if validated is not None:
                worker_result = validated
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
        and _DECISION_GRADE_MAX_ACQUISITION_NS == 250_000_000
        and _DECISION_GRADE_MAX_COMPLETION_GAP_NS == 400_000_000
    )


def _pyarrow_provenance_identity(*, imported_modules: Sequence[Any] = ()) -> dict[str, Any]:
    unavailable_sha256 = "sha256:" + hashlib.sha256(b"nerb/pyarrow-distribution-unavailable").hexdigest()
    identity: dict[str, Any] = {
        "version": None,
        "distribution_file_count": 0,
        "distribution_total_bytes": 0,
        "distribution_sha256": unavailable_sha256,
        "distribution_root_bound": False,
        "import_origin_bound": False,
        "module_version_matches_distribution": False,
    }
    try:
        provenance = enron_capacity._reader_distribution_provenance(
            "pyarrow",
            "pyarrow",
            "pyarrow/__init__.py",
        )
        _source_root, dependency_roots, _layouts, observer_fd = enron_capacity._validated_capacity_bootstrap()
        package_init = provenance.package_init
        if observer_fd is not None or package_init is None:
            return identity
        resolved_init = package_init.resolve(strict=True)
        dependency_root_bound = any(
            resolved_init.is_relative_to(root.resolve(strict=True)) for root in dependency_roots
        )
        identity = {
            "version": provenance.version,
            "distribution_file_count": provenance.file_count,
            "distribution_total_bytes": provenance.total_bytes,
            "distribution_sha256": provenance.sha256,
            "distribution_root_bound": dependency_root_bound,
            "import_origin_bound": False,
            "module_version_matches_distribution": False,
        }
        if not imported_modules:
            return identity
        distribution = importlib.metadata.distribution("pyarrow")
        raw_files = distribution.files
        if raw_files is None:
            return identity
        listed_files = {str(raw_file).replace("\\", "/"): raw_file for raw_file in raw_files}
        expected_module_files = ("pyarrow/__init__.py", "pyarrow/compute.py", "pyarrow/ipc.py")
        if any(relative not in listed_files for relative in expected_module_files):
            return identity
        expected_origins: list[Path] = []
        for relative in expected_module_files:
            expected_path = Path(str(distribution.locate_file(listed_files[relative])))
            _read_stable_regular_bytes(expected_path)
            expected_origins.append(expected_path.resolve(strict=True))
        module_origins: list[Path] = []
        for module in imported_modules:
            origin = getattr(module, "__file__", None)
            if not isinstance(origin, str):
                return identity
            module_origins.append(Path(origin).resolve(strict=True))
        pyarrow_module = imported_modules[0]
        identity["import_origin_bound"] = bool(
            len(module_origins) == len(expected_origins)
            and all(os.path.samefile(origin, expected) for origin, expected in zip(module_origins, expected_origins))
            and all(any(origin.is_relative_to(root) for root in dependency_roots) for origin in module_origins)
        )
        identity["module_version_matches_distribution"] = bool(
            isinstance(provenance.version, str) and getattr(pyarrow_module, "__version__", None) == provenance.version
        )
        return identity
    except (
        importlib.metadata.PackageNotFoundError,
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
        enron_capacity.EnronCapacityError,
    ):
        return identity


def _runtime_environment_identity() -> dict[str, Any]:
    provenance = _pyarrow_provenance_identity()
    candidate = provenance["version"]
    pyarrow_version = candidate if isinstance(candidate, str) else None
    python_major = sys.version_info.major
    python_minor = sys.version_info.minor
    return {
        "python_major": python_major,
        "python_minor": python_minor,
        "pyarrow_version": pyarrow_version,
        "pyarrow_distribution_file_count": provenance["distribution_file_count"],
        "pyarrow_distribution_total_bytes": provenance["distribution_total_bytes"],
        "pyarrow_distribution_sha256": provenance["distribution_sha256"],
        "pyarrow_distribution_root_bound": provenance["distribution_root_bound"],
        "launcher_environment_verified": bool(
            python_major == _EXPECTED_PYTHON_MAJOR
            and python_minor == _EXPECTED_PYTHON_MINOR
            and pyarrow_version == _EXPECTED_PYARROW_VERSION
            and provenance["distribution_root_bound"] is True
        ),
    }


def _reader_lock_sha256(values: Mapping[str, bytes]) -> str:
    file_hashes = {name: f"sha256:{hashlib.sha256(values[name]).hexdigest()}" for name in _READER_LOCK_FILES}
    payload = json.dumps(
        {"schema": "enron_capacity_reader_lock", "files": file_hashes},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _read_stable_regular_bytes(path: Path) -> bytes:
    descriptor: int | None = None
    try:
        before = path.lstat()
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        if os.name != "posix" or not nofollow:
            raise OSError
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow)
        opened_before = os.fstat(descriptor)
        current_before = path.lstat()
        expected_state = (
            int(opened_before.st_dev),
            int(opened_before.st_ino),
            int(opened_before.st_mode),
            int(opened_before.st_nlink),
            int(opened_before.st_uid),
            int(opened_before.st_gid),
            int(opened_before.st_size),
            int(opened_before.st_mtime_ns),
            int(opened_before.st_ctime_ns),
        )

        def state(info: os.stat_result) -> tuple[int, ...]:
            return (
                int(info.st_dev),
                int(info.st_ino),
                int(info.st_mode),
                int(info.st_nlink),
                int(info.st_uid),
                int(info.st_gid),
                int(info.st_size),
                int(info.st_mtime_ns),
                int(info.st_ctime_ns),
            )

        if (
            not stat.S_ISREG(opened_before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or state(before) != expected_state
            or state(current_before) != expected_state
        ):
            raise OSError
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        payload = b"".join(chunks)
        opened_after = os.fstat(descriptor)
        current_after = path.lstat()
        if (
            len(payload) != opened_before.st_size
            or state(opened_after) != expected_state
            or state(current_after) != expected_state
        ):
            raise OSError
    except OSError:
        raise RuntimeError("runtime source unavailable") from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
    return payload


def _runtime_nerb_source_paths(repository_root: Path) -> dict[str, Path]:
    try:
        package_path = repository_root / "src" / "nerb"
        package_info = package_path.lstat()
        package_root = package_path.resolve(strict=True)
    except OSError:
        raise RuntimeError("runtime source unavailable") from None
    if not stat.S_ISDIR(package_info.st_mode) or stat.S_ISLNK(package_info.st_mode):
        raise RuntimeError("runtime source unavailable")

    result: dict[str, Path] = {}
    try:
        candidates = tuple(package_root.rglob("*.py"))
    except OSError:
        raise RuntimeError("runtime source unavailable") from None
    for candidate in candidates:
        try:
            candidate_info = candidate.lstat()
            if not stat.S_ISREG(candidate_info.st_mode) or stat.S_ISLNK(candidate_info.st_mode):
                raise OSError
            path = candidate.resolve(strict=True)
            path.relative_to(package_root)
            relative = path.relative_to(repository_root).as_posix()
        except (OSError, ValueError):
            raise RuntimeError("runtime source unavailable") from None
        if relative in result:
            raise RuntimeError("runtime source inventory invalid")
        _read_stable_regular_bytes(path)
        result[relative] = path

    # Loaded-module origins remain an independent shadow-import guard.  They do
    # not select the inventory: import order must not change source identity.
    for module_name, module in tuple(sys.modules.items()):
        if module_name != "nerb" and not module_name.startswith("nerb."):
            continue
        origin = getattr(module, "__file__", None)
        if not isinstance(origin, str):
            continue
        try:
            path = Path(origin).resolve(strict=True)
        except OSError:
            raise RuntimeError("runtime source unavailable") from None
        if path.suffix != ".py":
            continue
        try:
            path.relative_to(package_root)
            relative = path.relative_to(repository_root).as_posix()
        except ValueError:
            raise RuntimeError("runtime source path mismatch") from None
        if result.get(relative) != path:
            raise RuntimeError("runtime source path mismatch")
        _read_stable_regular_bytes(path)
    required = {
        "src/nerb/__init__.py",
        "src/nerb/_capacity_bootstrap.py",
        "src/nerb/engine.py",
        "src/nerb/enron_capacity.py",
    }
    if not required.issubset(result):
        raise RuntimeError("runtime source inventory incomplete")
    return dict(sorted(result.items()))


def _runtime_source_paths() -> tuple[Path, dict[str, Path], Path, Path, Path]:
    repository_root = Path(__file__).resolve().parents[1]
    capacity_source = repository_root / "src" / "nerb" / "enron_capacity.py"
    soak_source = repository_root / "scripts" / "soak_enron_resource_observer.py"
    bootstrap_source = repository_root / "scripts" / "run_enron_capacity.py"
    import_guard_source = repository_root / "src" / "nerb" / "_capacity_bootstrap.py"
    capacity_origin = getattr(enron_capacity, "__file__", None)
    if (
        not isinstance(capacity_origin, str)
        or Path(capacity_origin).resolve() != capacity_source.resolve()
        or Path(__file__).resolve() != soak_source.resolve()
    ):
        raise RuntimeError("runtime source path mismatch")
    nerb_sources = _runtime_nerb_source_paths(repository_root)
    for path in (soak_source, bootstrap_source, import_guard_source):
        _read_stable_regular_bytes(path)
    return repository_root, nerb_sources, soak_source, bootstrap_source, import_guard_source


def _runtime_source_hashes() -> dict[str, Any]:
    _repository_root, nerb_sources, soak_source, bootstrap_source, import_guard_source = _runtime_source_paths()
    try:
        embedded_build_source = enron_capacity._native_extension_embedded_build_source_sha256()
        source_hashes = {
            relative: f"sha256:{hashlib.sha256(_read_stable_regular_bytes(path)).hexdigest()}"
            for relative, path in nerb_sources.items()
        }
        source_entries = [{"path": relative, "sha256": source_hashes[relative]} for relative in sorted(source_hashes)]
        source_inventory_sha256 = (
            "sha256:"
            + hashlib.sha256(
                json.dumps(source_entries, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
            ).hexdigest()
        )
        return {
            "capacity_implementation_sha256": source_hashes["src/nerb/enron_capacity.py"],
            "soak_implementation_sha256": (
                f"sha256:{hashlib.sha256(_read_stable_regular_bytes(soak_source)).hexdigest()}"
            ),
            "bootstrap_launcher_sha256": (
                f"sha256:{hashlib.sha256(_read_stable_regular_bytes(bootstrap_source)).hexdigest()}"
            ),
            "source_import_guard_sha256": (
                f"sha256:{hashlib.sha256(_read_stable_regular_bytes(import_guard_source)).hexdigest()}"
            ),
            "nerb_source_file_count": len(source_entries),
            "nerb_source_inventory_sha256": source_inventory_sha256,
            "native_extension_sha256": enron_capacity._native_extension_sha256(),
            "native_build_source_sha256": enron_capacity._native_build_source_sha256(),
            "native_extension_build_source_sha256": (
                embedded_build_source or enron_capacity._UNAVAILABLE_NATIVE_BUILD_SOURCE_SHA256
            ),
        }
    except (OSError, RuntimeError, ValueError, enron_capacity.EnronCapacityError):
        raise RuntimeError("runtime source unavailable") from None


def _source_stability_token() -> tuple[tuple[int, ...], ...]:
    repository_root, nerb_sources, soak_source, bootstrap_source, import_guard_source = _runtime_source_paths()
    reader_lock_paths = tuple(repository_root / name for name in _READER_LOCK_FILES)
    native_source_paths = tuple(
        repository_root / "rust" / relative for relative in enron_capacity._NATIVE_BUILD_SOURCE_FILES
    )
    native_module = importlib.import_module("nerb._engine")
    native_origin = getattr(native_module, "__file__", None)
    if not isinstance(native_origin, str):
        raise RuntimeError("runtime source unavailable")
    native_extension_path = Path(native_origin).resolve(strict=True)
    regular_files = {
        *nerb_sources.values(),
        soak_source,
        bootstrap_source,
        import_guard_source,
        native_extension_path,
        *native_source_paths,
        *reader_lock_paths,
    }
    directories = {repository_root, *(path.parent for path in regular_files)}
    result: list[tuple[int, ...]] = []
    try:
        for path in (*sorted(directories), *sorted(regular_files)):
            info = path.lstat()
            if path in regular_files and (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)):
                raise OSError
            result.append(
                (
                    int(info.st_dev),
                    int(info.st_ino),
                    int(info.st_mode),
                    int(info.st_size),
                    int(info.st_mtime_ns),
                    int(info.st_ctime_ns),
                )
            )
    except OSError:
        raise RuntimeError("runtime source unavailable") from None
    return tuple(result)


class _SourceStabilityMonitor:
    def __init__(self) -> None:
        self.expected = _source_stability_token()
        self.changed = threading.Event()
        self.stop_requested = threading.Event()
        self.thread = threading.Thread(target=self._run, name="nerb-soak-source-stability", daemon=True)

    def __enter__(self) -> _SourceStabilityMonitor:
        self.thread.start()
        return self

    def __exit__(self, _exc_type: Any, _exc: Any, _traceback: Any) -> None:
        self.stop_requested.set()
        self.thread.join(5)
        if self.thread.is_alive():
            self.changed.set()
        try:
            if _source_stability_token() != self.expected:
                self.changed.set()
        except RuntimeError:
            self.changed.set()

    def _run(self) -> None:
        while not self.stop_requested.wait(0.1):
            try:
                if _source_stability_token() != self.expected:
                    self.changed.set()
                    return
            except RuntimeError:
                self.changed.set()
                return

    @property
    def stable(self) -> bool:
        return not self.changed.is_set()


def _source_identity() -> dict[str, Any]:
    repository_root, nerb_sources, soak_source, bootstrap_source, import_guard_source = _runtime_source_paths()

    def git(*arguments: str) -> str:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=repository_root,
            check=False,
            capture_output=True,
            encoding="ascii",
            env={"LC_ALL": "C", "PATH": os.environ.get("PATH", "")},
            errors="strict",
            text=True,
            timeout=5,
        )
        if completed.returncode != 0:
            raise RuntimeError("source identity unavailable")
        return completed.stdout.strip()

    def git_bytes(*arguments: str) -> bytes:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=repository_root,
            check=False,
            capture_output=True,
            env={"LC_ALL": "C", "PATH": os.environ.get("PATH", "")},
            timeout=5,
        )
        if completed.returncode != 0:
            raise RuntimeError("source identity unavailable")
        return completed.stdout

    git_root = Path(git("rev-parse", "--show-toplevel")).resolve()
    git_commit = git("rev-parse", "HEAD")
    git_tree_oid = git("rev-parse", "HEAD^{tree}")
    status = git("status", "--porcelain=v1", "--untracked-files=all")
    if (
        git_root != repository_root
        or not re.fullmatch(r"[0-9a-f]{40}", git_commit)
        or not re.fullmatch(r"[0-9a-f]{40}", git_tree_oid)
    ):
        raise RuntimeError("source identity invalid")
    runtime_hashes = _runtime_source_hashes()
    try:
        nerb_source_bytes = {relative: _read_stable_regular_bytes(path) for relative, path in nerb_sources.items()}
        soak_bytes = _read_stable_regular_bytes(soak_source)
        bootstrap_bytes = _read_stable_regular_bytes(bootstrap_source)
        import_guard_bytes = _read_stable_regular_bytes(import_guard_source)
        current_reader_lock_sha256 = _reader_lock_sha256(
            {name: (repository_root / name).read_bytes() for name in _READER_LOCK_FILES}
        )
    except OSError:
        raise RuntimeError("source identity unavailable") from None
    head_reader_lock_sha256 = _reader_lock_sha256(
        {name: git_bytes("show", f"{git_commit}:{name}") for name in _READER_LOCK_FILES}
    )
    head_native_build_source_sha256 = enron_capacity._native_build_source_hash(
        {
            relative: git_bytes("show", f"{git_commit}:rust/{relative}")
            for relative in enron_capacity._NATIVE_BUILD_SOURCE_FILES
        }
    )
    head_blobs_match = bool(
        all(git_bytes("show", f"{git_commit}:{relative}") == payload for relative, payload in nerb_source_bytes.items())
        and git_bytes("show", f"{git_commit}:scripts/soak_enron_resource_observer.py") == soak_bytes
        and git_bytes("show", f"{git_commit}:scripts/run_enron_capacity.py") == bootstrap_bytes
        and git_bytes("show", f"{git_commit}:src/nerb/_capacity_bootstrap.py") == import_guard_bytes
        and runtime_hashes["native_build_source_sha256"] == head_native_build_source_sha256
    )
    native_extension_matches_head = (
        runtime_hashes["native_extension_build_source_sha256"] == head_native_build_source_sha256
    )
    return {
        "git_commit": git_commit,
        "git_tree_oid": git_tree_oid,
        "worktree_clean": status == "",
        "head_blobs_match": head_blobs_match,
        "native_extension_matches_head": native_extension_matches_head,
        "reader_lock_matches_head": current_reader_lock_sha256 == head_reader_lock_sha256,
        "reader_lock_sha256": current_reader_lock_sha256,
        "head_reader_lock_sha256": head_reader_lock_sha256,
        **runtime_hashes,
    }


def _positive_case_passed(case: Mapping[str, Any]) -> bool:
    worker = case["worker_result"]
    metrics = case["observer_metrics"]
    acquisition = metrics["acquisition_duration_ns"]
    gaps = metrics["completion_to_completion_gap_ns"]
    workloads = worker.get("workloads", {}) if isinstance(worker, dict) else {}
    snapshot = worker.get("resource_snapshot", {}) if isinstance(worker, dict) else {}
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
        and metrics["valid_sample_count"] == snapshot.get("resource_observation_count")
        and acquisition["max"] is not None
        and acquisition["max"] <= _EXPECTED_LIMIT_NS
        and acquisition["max"] == snapshot.get("maximum_resource_acquisition_duration_ns")
        and gaps["max"] is not None
        and gaps["max"] <= _EXPECTED_LIMIT_NS
        and gaps["max"] == snapshot.get("maximum_resource_observation_wall_gap_ns")
        and workloads.get("owner_only_tree_mutations", 0) > 0
        and workloads.get("owner_only_tree_seeded_regular_entries", 0) >= _MIN_LARGE_TREE_REGULAR_ENTRIES
        and workloads.get("owner_only_tree_retained_seed_regular_entries", 0)
        == workloads.get("owner_only_tree_seeded_regular_entries", -1)
        and workloads.get("owner_only_tree_terminal_regular_entries", 0)
        >= workloads.get("owner_only_tree_seeded_regular_entries", _MIN_LARGE_TREE_REGULAR_ENTRIES)
        and workloads.get("sqlite_transactions", 0) > 0
        and workloads.get("pyarrow_available") is True
        and workloads.get("pyarrow_batches", 0) > 0
        and workloads.get("native_rust_scans", 0) > 0
        and workloads.get("c_held_gil_intervals", 0) > 0
        and workloads.get("descendant_churn_cycles", 0) > 0
    )


def _decision_headroom_passed(case: Mapping[str, Any]) -> bool:
    """Require operating margin while leaving the production hard gates unchanged."""

    metrics = case["observer_metrics"]
    acquisition_max = metrics["acquisition_duration_ns"]["max"]
    completion_gap_max = metrics["completion_to_completion_gap_ns"]["max"]
    return bool(
        type(acquisition_max) is int
        and 0 <= acquisition_max <= _DECISION_GRADE_MAX_ACQUISITION_NS
        and type(completion_gap_max) is int
        and 0 <= completion_gap_max <= _DECISION_GRADE_MAX_COMPLETION_GAP_NS
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


def _worker_source_is_bound(case: Mapping[str, Any], source_identity: Mapping[str, Any]) -> bool:
    worker = case.get("worker_result")
    identity_fields = {
        "capacity_implementation_sha256",
        "soak_implementation_sha256",
        "bootstrap_launcher_sha256",
        "source_import_guard_sha256",
        "nerb_source_file_count",
        "nerb_source_inventory_sha256",
        "native_extension_sha256",
        "native_build_source_sha256",
        "native_extension_build_source_sha256",
    }
    expected = {field: source_identity.get(field) for field in identity_fields}
    return bool(
        isinstance(worker, Mapping)
        and worker.get("runtime_source_stable") is True
        and worker.get("runtime_source_identity") == expected
    )


def _bootstrap_identity_is_closed(value: object) -> bool:
    if not isinstance(value, Mapping) or set(value) != _BOOTSTRAP_IDENTITY_FIELDS:
        return False
    item = cast(Mapping[str, Any], value)
    boolean_fields = _BOOTSTRAP_IDENTITY_FIELDS - {
        "dependency_root_count",
        "dependency_root_layouts_sha256",
        "bootstrap_launcher_sha256",
        "source_import_guard_sha256",
    }
    if any(type(item.get(field)) is not bool for field in boolean_fields):
        return False
    count = item.get("dependency_root_count")
    if type(count) is not int or count < 0:
        return False
    if any(
        not isinstance(item.get(field), str) or re.fullmatch(r"sha256:[0-9a-f]{64}", str(item.get(field))) is None
        for field in (
            "dependency_root_layouts_sha256",
            "bootstrap_launcher_sha256",
            "source_import_guard_sha256",
        )
    ):
        return False
    expected_exact = bool(all(item.get(field) is True for field in boolean_fields - {"exact"}) and count > 0)
    return item.get("exact") is expected_exact


def _invalid_bootstrap_identity(reference: Mapping[str, Any]) -> dict[str, Any]:
    unavailable_layouts = (
        "sha256:" + hashlib.sha256(b"nerb/resource-observer-dependency-layouts-unavailable").hexdigest()
    )
    return {
        "isolated": False,
        "site_disabled": False,
        "bytecode_disabled": False,
        "site_hooks_absent": False,
        "private_fresh_pycache": False,
        "source_root_validated": False,
        "dependency_roots_validated": False,
        "source_import_guard_validated": False,
        "dependency_root_count": 0,
        "dependency_root_layouts_sha256": unavailable_layouts,
        "bootstrap_launcher_sha256": reference["bootstrap_launcher_sha256"],
        "source_import_guard_sha256": reference["source_import_guard_sha256"],
        "exact": False,
    }


def _worker_bootstrap_identity(case: Mapping[str, Any], reference: Mapping[str, Any]) -> tuple[dict[str, Any], bool]:
    worker = case.get("worker_result")
    if not isinstance(worker, Mapping):
        return _invalid_bootstrap_identity(reference), False
    candidate = worker.get("runtime_bootstrap_identity")
    stable = worker.get("runtime_bootstrap_stable") is True
    if not _bootstrap_identity_is_closed(candidate):
        return _invalid_bootstrap_identity(reference), False
    return dict(cast(Mapping[str, Any], candidate)), stable


def _pyarrow_provenance_is_closed(value: object) -> bool:
    fields = {
        "version",
        "distribution_file_count",
        "distribution_total_bytes",
        "distribution_sha256",
        "distribution_root_bound",
        "import_origin_bound",
        "module_version_matches_distribution",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        return False
    item = cast(Mapping[str, Any], value)
    version = item.get("version")
    if version is not None and (
        not isinstance(version, str)
        or not version
        or len(version.encode("utf-8")) > 128
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+!_-]*", version) is None
    ):
        return False
    if any(
        type(item.get(field)) is not int or cast(int, item[field]) < 0
        for field in ("distribution_file_count", "distribution_total_bytes")
    ):
        return False
    if (
        not isinstance(item.get("distribution_sha256"), str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", str(item.get("distribution_sha256"))) is None
    ):
        return False
    boolean_fields = {
        "distribution_root_bound",
        "import_origin_bound",
        "module_version_matches_distribution",
    }
    if any(type(item.get(field)) is not bool for field in boolean_fields):
        return False
    if item.get("import_origin_bound") is True and item.get("distribution_root_bound") is not True:
        return False
    if item.get("module_version_matches_distribution") is True and version is None:
        return False
    return True


def _worker_pyarrow_bindings(case: Mapping[str, Any], environment: Mapping[str, Any]) -> tuple[bool, bool]:
    worker = case.get("worker_result")
    if not isinstance(worker, Mapping):
        return False, False
    provenance = worker.get("pyarrow_provenance")
    if not _pyarrow_provenance_is_closed(provenance):
        return False, False
    provenance_item = cast(Mapping[str, Any], provenance)
    distribution_expected = {
        "version": environment["pyarrow_version"],
        "distribution_file_count": environment["pyarrow_distribution_file_count"],
        "distribution_total_bytes": environment["pyarrow_distribution_total_bytes"],
        "distribution_sha256": environment["pyarrow_distribution_sha256"],
        "distribution_root_bound": True,
    }
    distribution_bound = all(
        provenance_item.get(field) == expected for field, expected in distribution_expected.items()
    )
    return (
        bool(distribution_bound and provenance_item.get("import_origin_bound") is True),
        bool(distribution_bound and provenance_item.get("module_version_matches_distribution") is True),
    )


def _public_report(duration_seconds: float) -> tuple[dict[str, Any], str]:
    if os.name != "posix" or not (sys.platform.startswith("linux") or sys.platform == "darwin"):
        raise RuntimeError("same-host observer soak is unsupported on this platform")
    if not _policy_is_exact():
        raise RuntimeError("resource observer policy constants changed")

    bootstrap_identity_started = _runtime_bootstrap_identity()
    source_identity = _source_identity()
    environment_base = _runtime_environment_identity()
    descriptors_before = _open_descriptor_set()
    scratch_path = ""
    positive: dict[str, Any]
    stall: dict[str, Any]
    stall_calls = 0
    stall_elapsed_ns = 0
    with (
        _SourceStabilityMonitor() as source_monitor,
        tempfile.TemporaryDirectory(prefix="nerb-resource-observer-soak-") as scratch_raw,
    ):
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
    source_identity_stable = source_monitor.stable and _source_identity() == source_identity
    bootstrap_identity_finished = _runtime_bootstrap_identity()
    bootstrap_identity_stable = bootstrap_identity_finished == bootstrap_identity_started

    positive_passed = _positive_case_passed(positive)
    decision_headroom_passed = _decision_headroom_passed(positive)
    stall_passed = _stall_case_passed(stall, stall_calls, stall_elapsed_ns)
    worker_sources_bound = _worker_source_is_bound(positive, source_identity) and _worker_source_is_bound(
        stall, source_identity
    )
    positive_bootstrap, positive_bootstrap_stable = _worker_bootstrap_identity(
        positive,
        bootstrap_identity_finished,
    )
    fail_closed_bootstrap, fail_closed_bootstrap_stable = _worker_bootstrap_identity(
        stall,
        bootstrap_identity_finished,
    )
    bootstrap_all_exact = bool(
        bootstrap_identity_stable
        and positive_bootstrap_stable
        and fail_closed_bootstrap_stable
        and bootstrap_identity_finished == positive_bootstrap == fail_closed_bootstrap
        and bootstrap_identity_finished["exact"] is True
    )
    worker_pyarrow_origin_bound, worker_pyarrow_version_bound = _worker_pyarrow_bindings(positive, environment_base)
    environment = {
        **environment_base,
        "positive_worker_import_origin_bound": worker_pyarrow_origin_bound,
        "positive_worker_module_version_matches_distribution": worker_pyarrow_version_bound,
        "exact_expected_versions_verified": bool(
            environment_base["launcher_environment_verified"] is True
            and worker_pyarrow_origin_bound
            and worker_pyarrow_version_bound
        ),
    }
    worker = positive["worker_result"]
    snapshot = worker.get("resource_snapshot", {}) if isinstance(worker, dict) else {}
    workloads = worker.get("workloads", {}) if isinstance(worker, dict) else {}
    workload_elapsed_ns = int(worker.get("workload_elapsed_ns", 0)) if isinstance(worker, dict) else 0
    iterations = int(worker.get("workload_iterations", 0)) if isinstance(worker, dict) else 0
    limitations = [
        _LIMITATION_SYNTHETIC,
        _LIMITATION_SAMPLING,
        _LIMITATION_OBSERVER_MEMORY,
        _LIMITATION_SOURCE_TRUST,
    ]
    if not workloads.get("pyarrow_available", False):
        limitations.append(_LIMITATION_PYARROW)
    if duration_seconds < _DEFAULT_DURATION_SECONDS:
        limitations.append(_LIMITATION_SHORT)
    if source_identity["worktree_clean"] is not True:
        limitations.append(_LIMITATION_DIRTY)
    if source_identity["head_blobs_match"] is not True:
        limitations.append(_LIMITATION_HEAD)
    if source_identity["native_extension_matches_head"] is not True:
        limitations.append(_LIMITATION_NATIVE)
    if not source_identity_stable:
        limitations.append(_LIMITATION_UNSTABLE)
    if not worker_sources_bound:
        limitations.append(_LIMITATION_WORKER)
    if not decision_headroom_passed:
        limitations.append(_LIMITATION_HEADROOM)
    if environment["exact_expected_versions_verified"] is not True:
        limitations.append(_LIMITATION_ENVIRONMENT)
    if source_identity["reader_lock_matches_head"] is not True:
        limitations.append(_LIMITATION_READER_LOCK)
    if not bootstrap_all_exact:
        limitations.append(_LIMITATION_BOOTSTRAP)

    overall_ok = bool(
        positive_passed
        and stall_passed
        and scratch_removed
        and descriptors_clean
        and source_identity_stable
        and worker_sources_bound
    )
    completed_required_duration = duration_seconds >= _DEFAULT_DURATION_SECONDS and workload_elapsed_ns >= int(
        _DEFAULT_DURATION_SECONDS * 1_000_000_000
    )
    decision_grade = bool(
        overall_ok
        and decision_headroom_passed
        and completed_required_duration
        and source_identity["worktree_clean"] is True
        and source_identity["head_blobs_match"] is True
        and source_identity["native_extension_matches_head"] is True
        and source_identity["reader_lock_matches_head"] is True
        and environment["exact_expected_versions_verified"] is True
        and bootstrap_all_exact
    )
    expected_containment = enron_capacity._process_containment_identity(production=True)
    report: dict[str, Any] = {
        "report_type": "nerb.resource_observer_soak",
        "ok": overall_ok,
        "decision_grade": decision_grade,
        "same_host": True,
        "platform": {
            "system": "linux" if sys.platform.startswith("linux") else "darwin",
            "architecture": platform.machine().lower(),
            "expected_process_containment_policy": {
                field: expected_containment[field] for field in ("mode", "architecture", "policy_sha256")
            },
        },
        "bootstrap": {
            "launcher": bootstrap_identity_finished,
            "launcher_stable": bootstrap_identity_stable,
            "positive_worker": positive_bootstrap,
            "positive_worker_stable": positive_bootstrap_stable,
            "fail_closed_worker": fail_closed_bootstrap,
            "fail_closed_worker_stable": fail_closed_bootstrap_stable,
            "all_exact": bootstrap_all_exact,
        },
        "environment": environment,
        "requested_duration_seconds": duration_seconds,
        "completed_required_duration": completed_required_duration,
        "source_identity": source_identity,
        "source_identity_stable": source_identity_stable,
        "worker_sources_bound": worker_sources_bound,
        "policy": {
            "source_provenance_boundary": _SOURCE_PROVENANCE_BOUNDARY,
            "production_monitor_interval_ns": enron_capacity.PRODUCTION_MONITOR_INTERVAL_NS,
            "maximum_resource_observation_wall_gap_ns": enron_capacity.MAX_RESOURCE_OBSERVATION_WALL_GAP_NS,
            "maximum_resource_acquisition_duration_ns": enron_capacity.MAX_RESOURCE_ACQUISITION_DURATION_NS,
            "decision_grade_maximum_resource_observation_wall_gap_ns": (_DECISION_GRADE_MAX_COMPLETION_GAP_NS),
            "decision_grade_maximum_resource_acquisition_duration_ns": _DECISION_GRADE_MAX_ACQUISITION_NS,
            "exact_expected_constants_verified": _policy_is_exact(),
        },
        "positive_soak": {
            "passed": positive_passed,
            "decision_headroom_passed": decision_headroom_passed,
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
    _assert_aggregate_report_privacy(report, private_paths=(scratch_path,))
    serialized = json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return report, serialized


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the same-host synthetic resource-observer soak.")
    parser.add_argument(
        "--duration-seconds",
        type=float,
        default=_DEFAULT_DURATION_SECONDS,
        help="positive soak duration; default: 1800 seconds",
    )
    parser.add_argument(
        "--require-decision-grade",
        action="store_true",
        help="exit unsuccessfully unless the emitted report is decision-grade",
    )
    return parser


def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1] == "--worker":
        _worker_main(sys.argv[2:])
    arguments = _parser().parse_args()
    duration_seconds = arguments.duration_seconds
    if not math.isfinite(duration_seconds) or duration_seconds <= 0:
        _parser().error("--duration-seconds must be finite and greater than zero")

    if arguments.require_decision_grade and _runtime_bootstrap_identity()["exact"] is not True:
        report = {
            "report_type": "nerb.resource_observer_soak",
            "ok": False,
            "decision_grade": False,
            "error_code": "bootstrap_required",
            "policy_constants_verified": _policy_is_exact(),
        }
        _assert_aggregate_report_privacy(report)
        print(json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 1

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
        _assert_aggregate_report_privacy(report)
        serialized = json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    finally:
        os.umask(previous_umask)
    print(serialized)
    if arguments.require_decision_grade:
        passed = report.get("decision_grade") is True
    else:
        passed = report.get("ok") is True
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())

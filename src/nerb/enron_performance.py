"""Decision-grade, privacy-safe Enron cache performance orchestration.

The public objects emitted by this module contain only aggregate descriptors,
timing/resource samples, and content hashes.  Corpus text, detector surfaces,
scan records, and local paths remain in ignored transactional run directories.
"""

from __future__ import annotations

import contextlib
import hashlib
import heapq
import importlib
import json
import math
import os
import platform
import re
import secrets
import selectors
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

from . import __version__
from . import enron_bank_workflow as _bank_workflow
from .bank import bank_stats, canonicalize_bank, hash_bank
from .engines import compile_bank_with_report, extraction_execution_sha256
from .enron_bank_builder import EnronBankPolicy
from .enron_bank_workflow import (
    EnronBankBuildError,
    EnronBankBuildOptions,
    _builder_implementation_sha256,
    _verify_enron_bank_build_snapshot,
    build_enron_intelligence_bank,
)
from .enron_contract import (
    PERFORMANCE_PHASE_PROCESS_MODELS,
    PERFORMANCE_SCALE_PATTERNS,
    _public_serialization_diagnostics,
    calculate_enron_breakeven,
    calculate_enron_performance_comparison,
    calculate_enron_performance_statistics,
    hash_enron_breakeven_plan,
    hash_enron_performance_bank,
    hash_enron_performance_baseline,
    hash_enron_performance_comparison_plan,
    hash_enron_performance_harness,
    hash_enron_performance_input,
    hash_enron_performance_inventory,
    hash_enron_performance_manifest,
    hash_enron_workload,
    summarize_enron_performance_inventory,
    validate_enron_performance_output,
)
from .enron_performance_fixtures import (
    EnronPerformanceBankFixture,
    EnronPerformanceFixtureError,
    EnronPerformanceInputFixture,
    make_enron_performance_bank_fixtures,
    make_enron_performance_input_fixtures,
)
from .enron_performance_worker import (
    DEFAULT_MAX_REQUEST_BYTES,
    REQUEST_SCHEMA_VERSION,
    RESULT_SCHEMA_VERSION,
    normalize_peak_rss,
)
from .enron_private_io import (
    EnronPrivateIOError,
    PrivateRun,
    is_owner_only_private_mode,
    open_private_binary_input,
)
from .enron_splitting import EnronSplitError, load_enron_development_split

PERFORMANCE_PLAN_SCHEMA_VERSION = "nerb.enron_performance_plan.v1"
PERFORMANCE_RUN_SCHEMA_VERSION = "nerb.enron_performance_run.v1"
PERFORMANCE_PRIVATE_MANIFEST_SCHEMA_VERSION = "nerb.enron_performance_private_manifest.v1"
PERFORMANCE_RUN_PRIVATE_MANIFEST_SCHEMA_VERSION = "nerb.enron_performance_run_private_manifest.v1"
PERFORMANCE_SUITE_ID = "enron_v2_cache_value"
PERFORMANCE_OPERATION_SPEC_VERSION = "1"
PERFORMANCE_EXACT_CONTROL_ID = "nerb_exact_same_path_control"
PERFORMANCE_UNCACHED_BASELINE_ID = "nerb_uncached_recompile"
PERFORMANCE_GENERIC_REGEX_BASELINE_ID = "generic_email_format_regex"
PERFORMANCE_PYTHON_LITERAL_BASELINE_ID = "python_literal_catalog_scan"
PERFORMANCE_PROFILE_IDS = ("smoke", "decision")
PERFORMANCE_EXACT_VALUE_PATHS = (
    "real_direct_throughput",
    "real_helper_cache_hit",
    "real_helper_cache_miss",
    "real_end_to_end",
)
_EXACT_VALUE_WILLIAMS_ROWS = (
    (0, 1, 3, 2),
    (1, 2, 0, 3),
    (2, 3, 1, 0),
    (3, 0, 2, 1),
)
_EXACT_VALUE_ROW_PATTERN = (0, 1, 2, 3, 1, 0, 3, 2)
DEFAULT_REAL_INPUT_DOCUMENTS = 100
DEFAULT_WARMUPS = 3
DEFAULT_SMOKE_SAMPLES = 5
DEFAULT_SETUP_SAMPLES = 20
DEFAULT_SCAN_SAMPLES = 100
DEFAULT_DOCUMENT_SAMPLES = 500
DEFAULT_CONCURRENCY = 4
DEFAULT_WORKER_TIMEOUT_SECONDS = 120.0
DEFAULT_SOURCE_BUILD_TIMEOUT_SECONDS = 900.0
PERFORMANCE_DECISION_THRESHOLDS = {
    "max_exact_control_noise_floor": 0.25,
    "max_document_p99_seconds": 0.05,
    "min_documents_per_second": 100.0,
    "min_mib_per_second": 1.0,
    "max_peak_rss_bytes": 8 * 1024**3,
}
MAX_WORKER_OUTPUT_BYTES = 64 * 1024
MAX_PLAN_BYTES = 16 * 1024 * 1024
MAX_PRIVATE_PATH_BYTES = 4 * 1024
MAX_BENCHMARK_VERSION_BYTES = 256
MAX_BUILD_TIMESTAMP_BYTES = 256
MAX_PRIVATE_JSON_BYTES = 64 * 1024 * 1024
MAX_INPUT_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_DOCUMENT_BYTES = 10 * 1024 * 1024
MAX_SOURCE_PROFILE_BYTES = 2 * 1024 * 1024 * 1024
MAX_SOURCE_SNAPSHOT_BYTES = 16 * 1024 * 1024 * 1024
MAX_SOURCE_BUILD_SECONDS = 24 * 60 * 60
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_NONCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

PerformanceProfile = Literal["smoke", "decision"]

__all__ = [
    "EnronPerformanceError",
    "EnronPerformancePrepareOptions",
    "EnronPerformanceRunOptions",
    "prepare_enron_performance_manifest",
    "run_enron_performance",
    "verify_enron_performance_run",
]


class EnronPerformanceError(RuntimeError):
    """Raised when performance evidence cannot be produced or verified safely."""


@dataclass(frozen=True, slots=True)
class EnronPerformancePrepareOptions:
    """Inputs used to freeze a path-free performance workload manifest."""

    bank_build_run: Path
    development_run: Path
    output_dir: Path
    annotation_run: Path | None = None
    benchmark_version: str | None = None
    real_input_documents: int = DEFAULT_REAL_INPUT_DOCUMENTS
    concurrency: int = DEFAULT_CONCURRENCY
    source_curation_seconds: float = 60.0
    allow_unignored_output: bool = False


@dataclass(frozen=True, slots=True)
class EnronPerformanceRunOptions:
    """Execution policy for one frozen performance manifest."""

    prepared_run: Path
    output_dir: Path
    profile: PerformanceProfile = "smoke"
    warmups: int = DEFAULT_WARMUPS
    smoke_samples: int = DEFAULT_SMOKE_SAMPLES
    setup_samples: int = DEFAULT_SETUP_SAMPLES
    scan_samples: int = DEFAULT_SCAN_SAMPLES
    document_samples: int = DEFAULT_DOCUMENT_SAMPLES
    worker_timeout_seconds: float = DEFAULT_WORKER_TIMEOUT_SECONDS
    source_build_timeout_seconds: float = DEFAULT_SOURCE_BUILD_TIMEOUT_SECONDS
    allow_unignored_output: bool = False


@dataclass(frozen=True, slots=True)
class _Artifact:
    id: str
    relative_path: str
    sha256: str
    bytes: int

    def ref(self) -> dict[str, Any]:
        return {"id": self.id, "sha256": self.sha256, "bytes": self.bytes}


@dataclass(frozen=True, slots=True)
class _PreparedPerformanceRun:
    root: Path
    manifest: Mapping[str, Any]
    plan: Mapping[str, Any]
    locations: Mapping[str, Any]
    tree: Mapping[str, Any]
    artifact_fingerprints: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class _SourceBuildInputSnapshot:
    root: Path
    development_run: Path
    annotation_run: Path | None
    cmu_catalog_bindings: Path | None


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise EnronPerformanceError("Performance data must be finite canonical UTF-8 JSON.") from None


def _strict_json_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _strict_json_loads(payload: bytes | str) -> Any:
    return json.loads(
        payload,
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        object_pairs_hook=_strict_json_object_pairs,
    )


def _pretty_json_bytes(value: Any) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                indent=2,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise EnronPerformanceError("Performance data must be finite UTF-8 JSON.") from None


def _sha256_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _canonical_hash(value: Any) -> str:
    return _sha256_bytes(_canonical_json_bytes(value))


def _artifact_from_bytes(identifier: str, relative_path: str, payload: bytes) -> _Artifact:
    if not identifier or not relative_path or not payload:
        raise EnronPerformanceError("Performance artifacts require non-empty ids, paths, and bytes.")
    return _Artifact(identifier, relative_path, _sha256_bytes(payload), len(payload))


def _write_artifact(run: PrivateRun, artifact: _Artifact, payload: bytes) -> None:
    if len(payload) != artifact.bytes or _sha256_bytes(payload) != artifact.sha256:
        raise EnronPerformanceError("Performance artifact changed before it was written.")
    with run.open_binary(artifact.relative_path) as file:
        file.write(payload)


def _absolute_private_path(path: Path, *, description: str) -> Path:
    try:
        raw = os.fspath(path)
        if (
            not isinstance(raw, str)
            or not raw
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in raw)
            or len(raw.encode("utf-8")) > MAX_PRIVATE_PATH_BYTES
        ):
            raise ValueError
        candidate = Path(path).expanduser()
        if any(part == os.pardir for part in candidate.parts):
            raise ValueError
        return candidate if candidate.is_absolute() else Path.cwd() / candidate
    except (OSError, RuntimeError, TypeError, ValueError):
        raise EnronPerformanceError(f"{description} path is invalid.") from None


def _bounded_private_string(value: Any, *, maximum_bytes: int, description: str) -> str:
    if not isinstance(value, str):
        raise EnronPerformanceError(f"{description} is invalid.")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        raise EnronPerformanceError(f"{description} is invalid.") from None
    if (
        not value
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        or len(encoded) > maximum_bytes
    ):
        raise EnronPerformanceError(f"{description} is invalid.")
    return value


def _validated_absolute_private_location(value: Any, *, description: str) -> Path:
    raw = _bounded_private_string(value, maximum_bytes=MAX_PRIVATE_PATH_BYTES, description=description)
    path = Path(raw)
    if not path.is_absolute() or any(part == os.pardir for part in path.parts):
        raise EnronPerformanceError(f"{description} is invalid.")
    return path


def _private_identity_payload(identity: Any) -> dict[str, Any]:
    return {
        "kind": identity.kind,
        "device": identity.device,
        "inode": identity.inode,
        "mode": identity.mode,
        "link_count": identity.link_count,
        "size": identity.size,
        "modified_ns": identity.modified_ns,
        "changed_ns": identity.changed_ns,
    }


def _private_tree_payload(tree: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    return {name: _private_identity_payload(identity) for name, identity in sorted(tree.items())}


def _validate_private_identity_payload(value: Any, *, expected_kind: str | None = None) -> dict[str, Any]:
    expected_keys = {
        "kind",
        "device",
        "inode",
        "mode",
        "link_count",
        "size",
        "modified_ns",
        "changed_ns",
    }
    if not isinstance(value, Mapping) or set(value) != expected_keys:
        raise EnronPerformanceError("Frozen private file identity is invalid.")
    kind = value.get("kind")
    if kind not in {"file", "directory"} or (expected_kind is not None and kind != expected_kind):
        raise EnronPerformanceError("Frozen private file identity kind is invalid.")
    numeric = {key: value.get(key) for key in expected_keys - {"kind"}}
    if any(type(item) is not int or item < 0 for item in numeric.values()):
        raise EnronPerformanceError("Frozen private file identity values are invalid.")
    mode = int(value["mode"])
    link_count = int(value["link_count"])
    if not is_owner_only_private_mode(mode) or link_count < 1 or (kind == "file" and link_count != 1):
        raise EnronPerformanceError("Frozen private file identity is not private and single-linked.")
    return dict(value)


def _validate_private_tree_payload(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, Mapping) or not value or len(value) > 256 or "." not in value:
        raise EnronPerformanceError("Frozen private tree identity is invalid.")
    result: dict[str, dict[str, Any]] = {}
    for raw_name, raw_identity in value.items():
        if not isinstance(raw_name, str):
            raise EnronPerformanceError("Frozen private tree path is invalid.")
        if raw_name == ".":
            identity = _validate_private_identity_payload(raw_identity, expected_kind="directory")
        else:
            relative = Path(raw_name)
            try:
                path_bytes = raw_name.encode("utf-8")
            except UnicodeError:
                raise EnronPerformanceError("Frozen private tree path is invalid.") from None
            if (
                relative.is_absolute()
                or not relative.parts
                or len(relative.parts) > 9
                or len(path_bytes) > MAX_PRIVATE_PATH_BYTES
                or any(ord(character) < 0x20 or ord(character) == 0x7F for character in raw_name)
                or relative.as_posix() != raw_name
                or any(part in {"", os.curdir, os.pardir} for part in relative.parts)
            ):
                raise EnronPerformanceError("Frozen private tree path is invalid.")
            identity = _validate_private_identity_payload(raw_identity)
            for length in range(1, len(relative.parts)):
                parent = Path(*relative.parts[:length]).as_posix()
                parent_identity = value.get(parent)
                if not isinstance(parent_identity, Mapping) or parent_identity.get("kind") != "directory":
                    raise EnronPerformanceError("Frozen private tree parent identity is invalid.")
        result[raw_name] = identity
    return result


def _snapshot_performance_private_tree(path: Path, *, description: str) -> tuple[Path, Mapping[str, Any]]:
    root = _absolute_private_path(path, description=description)
    try:
        tree = _bank_workflow._snapshot_private_tree(root)
        _validate_private_tree_payload(_private_tree_payload(tree))
        return root, tree
    except EnronBankBuildError:
        raise EnronPerformanceError(f"{description} is not a stable private tree.") from None


def _fingerprint_performance_private_file(
    root: Path,
    relative_path: str,
    tree: Mapping[str, Any],
    *,
    maximum_bytes: int,
    description: str,
) -> Any:
    expected_identity = tree.get(relative_path)
    if expected_identity is None or expected_identity.kind != "file":
        raise EnronPerformanceError(f"{description} is missing from its private tree.")
    try:
        fingerprint = _bank_workflow._fingerprint_private_artifact(
            root / relative_path,
            max_bytes=maximum_bytes,
        )
    except EnronBankBuildError:
        raise EnronPerformanceError(f"{description} could not be fingerprinted safely.") from None
    if fingerprint.identity != expected_identity:
        raise EnronPerformanceError(f"{description} changed while its private tree was inspected.")
    return fingerprint


def _read_fingerprinted_private_bytes(
    path: Path,
    fingerprint: Any,
    *,
    maximum_bytes: int,
    description: str,
) -> bytes:
    try:
        return _bank_workflow._read_verified_private_bytes(
            path,
            expected_fingerprint=fingerprint,
            max_bytes=maximum_bytes,
            description=description,
        )
    except EnronBankBuildError:
        raise EnronPerformanceError(f"{description} could not be read from its frozen inode.") from None


def _verify_performance_tree_inventory(tree: Mapping[str, Any], relative_paths: Sequence[str]) -> None:
    try:
        _bank_workflow._verify_private_tree_inventory(
            tree,
            {str(index): name for index, name in enumerate(relative_paths)},
        )
    except EnronBankBuildError:
        raise EnronPerformanceError("Performance private tree has an undeclared entry.") from None


def _assert_performance_private_tree_current(
    root: Path,
    expected_tree: Mapping[str, Any],
    *,
    description: str,
) -> None:
    _current_root, current_tree = _snapshot_performance_private_tree(root, description=description)
    if current_tree != expected_tree:
        raise EnronPerformanceError(f"{description} changed after its immutable snapshot was captured.")


def _strict_json_object_bytes(payload: bytes, *, description: str) -> dict[str, Any]:
    try:
        value = _strict_json_loads(payload)
    except (json.JSONDecodeError, RecursionError, UnicodeDecodeError, ValueError):
        raise EnronPerformanceError(f"{description} is not strict finite JSON.") from None
    if not isinstance(value, dict):
        raise EnronPerformanceError(f"{description} must contain a JSON object.")
    return value


def _read_bounded_bytes(path: Path, *, maximum_bytes: int, description: str) -> bytes:
    if maximum_bytes < 1:
        raise EnronPerformanceError("Private read limits must be positive.")
    try:
        with open_private_binary_input(path) as file:
            payload = file.read(maximum_bytes + 1)
    except (EnronPrivateIOError, OSError):
        raise EnronPerformanceError(f"{description} could not be read safely.") from None
    if len(payload) > maximum_bytes:
        raise EnronPerformanceError(f"{description} exceeds its reviewed byte limit.")
    return payload


def _read_json_object(path: Path, *, maximum_bytes: int, description: str) -> dict[str, Any]:
    payload = _read_bounded_bytes(path, maximum_bytes=maximum_bytes, description=description)
    try:
        value = _strict_json_loads(payload)
    except (json.JSONDecodeError, RecursionError, UnicodeDecodeError, ValueError):
        raise EnronPerformanceError(f"{description} is not strict finite JSON.") from None
    if not isinstance(value, dict):
        raise EnronPerformanceError(f"{description} must contain a JSON object.")
    return value


def _validate_profile(profile: str) -> PerformanceProfile:
    if profile not in PERFORMANCE_PROFILE_IDS:
        raise EnronPerformanceError(f"Performance profile must be one of {', '.join(PERFORMANCE_PROFILE_IDS)}.")
    return cast(PerformanceProfile, profile)


def _positive_int(value: Any, description: str, *, maximum: int | None = None) -> int:
    if type(value) is not int or value < 1 or (maximum is not None and value > maximum):
        suffix = "" if maximum is None else f" no greater than {maximum}"
        raise EnronPerformanceError(f"{description} must be a positive integer{suffix}.")
    return value


def _positive_finite(value: Any, description: str, *, maximum: float | None = None) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        raise EnronPerformanceError(f"{description} must be a positive finite number.")
    result = float(value)
    if result <= 0 or (maximum is not None and result > maximum):
        raise EnronPerformanceError(f"{description} must be a positive finite number within the reviewed limit.")
    return result


def _require_sha256(value: Any, description: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise EnronPerformanceError(f"{description} must be a SHA-256 content hash.")
    return value


def _source_sha256(paths: Sequence[Path]) -> str:
    descriptors = []
    for path in paths:
        payload = _read_bounded_bytes(path, maximum_bytes=MAX_PRIVATE_JSON_BYTES, description="Harness source")
        descriptors.append({"name": path.name, "sha256": _sha256_bytes(payload), "bytes": len(payload)})
    return _canonical_hash(descriptors)


def _performance_harness_source_sha256() -> str:
    """Bind the runner, worker, fixture generator, bank builder, and frozen policy."""

    runner_source_sha256 = _source_sha256(
        (
            Path(__file__),
            Path(__file__).with_name("enron_performance_worker.py"),
            Path(__file__).with_name("enron_performance_fixtures.py"),
        )
    )
    try:
        builder_source_sha256 = _builder_implementation_sha256()
    except EnronBankBuildError:
        raise EnronPerformanceError("Performance bank-builder source could not be fingerprinted safely.") from None
    cache_clear = getattr(extraction_execution_sha256, "cache_clear", None)
    if callable(cache_clear):
        cache_clear()
    try:
        execution_source_sha256 = extraction_execution_sha256()
    except (OSError, RuntimeError, TypeError, ValueError):
        raise EnronPerformanceError("Performance execution source could not be fingerprinted safely.") from None
    return _canonical_hash(
        {
            "runner_source_sha256": runner_source_sha256,
            "builder_source_sha256": builder_source_sha256,
            "builder_policy_sha256": EnronBankPolicy().sha256,
            "execution_source_sha256": execution_source_sha256,
        }
    )


def _environment() -> dict[str, Any]:
    cpu_count = os.cpu_count() or 1
    memory_bytes = _memory_bytes()
    return {
        "os": platform.system() or "unknown",
        "architecture": platform.machine() or "unknown",
        "python": platform.python_version(),
        "cpu_count": cpu_count,
        "cpu_model": _cpu_model(),
        "memory_bytes": memory_bytes,
    }


def _memory_bytes() -> int:
    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
        value = int(pages) * int(page_size)
    except (AttributeError, OSError, TypeError, ValueError):
        value = 0
    return max(1, value)


def _cpu_model() -> str:
    if sys.platform == "darwin":
        try:
            completed = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                check=False,
                capture_output=True,
                text=True,
                timeout=2,
            )
        except (OSError, subprocess.SubprocessError):
            completed = None
        if completed is not None and completed.returncode == 0 and completed.stdout.strip():
            return completed.stdout.strip()[:256]
    if sys.platform.startswith("linux"):
        try:
            with open_private_binary_input(Path("/proc/cpuinfo")) as file:
                for raw_line in file:
                    if raw_line.lower().startswith(b"model name") and b":" in raw_line:
                        model = raw_line.split(b":", 1)[1].strip().decode("utf-8", "replace")
                        return model[:256] or "unknown"
        except (EnronPrivateIOError, OSError):
            pass
    return platform.processor()[:256] or "unknown"


def _software() -> dict[str, Any]:
    engine_version = "unknown"
    try:
        native_engine = importlib.import_module("nerb._engine")
        candidate = getattr(native_engine, "__version__", None)
        if isinstance(candidate, str) and candidate:
            engine_version = candidate
    except (ImportError, RuntimeError):
        pass
    return {
        "package_version": __version__,
        "engine_version": engine_version,
        "git_commit": _git_commit(),
        "git_dirty": _git_dirty(),
    }


def _git_commit() -> str:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        completed = None
    value = "" if completed is None or completed.returncode else completed.stdout.strip()
    return value if re.fullmatch(r"[0-9a-f]{40}", value) else "0" * 40


def _git_dirty() -> bool:
    try:
        completed = subprocess.run(
            ["git", "status", "--porcelain"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return True
    return completed.returncode != 0 or bool(completed.stdout)


def _artifact_ref(value: Mapping[str, Any], *, identifier: str | None = None) -> dict[str, Any]:
    artifact_id = identifier if identifier is not None else value.get("id")
    sha256 = value.get("sha256")
    byte_count = value.get("bytes")
    if not isinstance(artifact_id, str) or not artifact_id:
        raise EnronPerformanceError("Artifact reference id is invalid.")
    return {
        "id": artifact_id,
        "sha256": _require_sha256(sha256, "Artifact reference hash"),
        "bytes": _positive_int(byte_count, "Artifact reference bytes"),
    }


def _active_bank_composition(bank: Mapping[str, Any]) -> dict[str, Any]:
    if bank.get("status") != "active" or not isinstance(bank.get("entities"), Mapping):
        raise EnronPerformanceError("Evaluated bank does not have an active entity mapping.")
    taxonomy: list[dict[str, Any]] = []
    for entity_class, raw_entity in sorted(bank["entities"].items()):
        if not isinstance(entity_class, str) or not isinstance(raw_entity, Mapping):
            raise EnronPerformanceError("Evaluated bank entity shape is invalid.")
        if raw_entity.get("status") != "active":
            continue
        raw_names = raw_entity.get("names")
        if not isinstance(raw_names, Mapping):
            raise EnronPerformanceError("Evaluated bank active entity names are invalid.")
        active_names = 0
        literal_patterns = 0
        regex_patterns = 0
        for raw_name in raw_names.values():
            if not isinstance(raw_name, Mapping) or raw_name.get("status") != "active":
                continue
            raw_patterns = raw_name.get("patterns")
            if not isinstance(raw_patterns, Mapping):
                raise EnronPerformanceError("Evaluated bank active name patterns are invalid.")
            name_patterns = [
                pattern
                for pattern in raw_patterns.values()
                if isinstance(pattern, Mapping) and pattern.get("status") == "active"
            ]
            if not name_patterns:
                continue
            active_names += 1
            literal_patterns += sum(pattern.get("kind") == "literal" for pattern in name_patterns)
            regex_patterns += sum(pattern.get("kind") == "regex" for pattern in name_patterns)
        if literal_patterns + regex_patterns == 0:
            continue
        # In the v2 charter, active person-name catalog entries are address-anchored aliases;
        # contact identities (including the bounded generic fallback) are canonical names.
        aliases = active_names if entity_class == "person" else 0
        taxonomy.append(
            {
                "entity_class": entity_class,
                "entities": 1,
                "canonical_names": active_names - aliases,
                "aliases": aliases,
                "literal_patterns": literal_patterns,
                "regex_patterns": regex_patterns,
            }
        )
    if {item["entity_class"] for item in taxonomy} != {"contact", "person"}:
        raise EnronPerformanceError("Evaluated performance taxonomy must contain active contact and person classes.")
    return {"taxonomy": taxonomy}


def _evaluated_bank_descriptor(
    bank: Mapping[str, Any], artifact: _Artifact, native_source_bytes: int
) -> dict[str, Any]:
    stats = bank_stats(bank)
    active = stats["active_totals"]
    composition = _active_bank_composition(bank)
    active_aliases = sum(item["aliases"] for item in composition["taxonomy"])
    canonical_bytes = _canonical_json_bytes(canonicalize_bank(bank))
    descriptor: dict[str, Any] = {
        "id": "evaluated_bank",
        "kind": "evaluated_bank",
        "bank_hash": hash_bank(bank),
        "artifact": artifact.ref(),
        "generator": None,
        "composition": composition,
        "descriptor_sha256": "",
        "active_entities": active["entities"],
        "active_names": active["names"],
        "active_aliases": active_aliases,
        "active_patterns": active["patterns"],
        "canonical_json_bytes": len(canonical_bytes),
        "native_source_bytes": native_source_bytes,
    }
    descriptor["descriptor_sha256"] = hash_enron_performance_bank(descriptor)
    return descriptor


def _select_real_documents(
    rows: Sequence[Mapping[str, Any]],
    *,
    count: int,
    seed: str,
) -> tuple[bytes, ...]:
    selected: list[tuple[int, str, bytes]] = []
    eligible = 0
    for row in rows:
        document_id = row.get("document_id")
        text = row.get("text")
        if not isinstance(document_id, str) or not document_id or not isinstance(text, str):
            raise EnronPerformanceError("Real performance input row has an invalid private shape.")
        try:
            text_bytes = text.encode("utf-8")
        except UnicodeEncodeError:
            raise EnronPerformanceError("Real performance input contains invalid Unicode.") from None
        if not text_bytes or len(text_bytes) > MAX_DOCUMENT_BYTES:
            continue
        eligible += 1
        rank = int.from_bytes(hashlib.sha256(f"{seed}\0{document_id}".encode()).digest(), "big")
        candidate = (-rank, document_id, text_bytes)
        if len(selected) < count:
            heapq.heappush(selected, candidate)
        elif rank < -selected[0][0]:
            heapq.heapreplace(selected, candidate)
    if eligible < count or len(selected) != count:
        raise EnronPerformanceError("Real performance input does not have enough eligible documents.")
    ordered = sorted(selected, key=lambda item: (-item[0], item[1]))
    documents = tuple(item[2] for item in ordered)
    if sum(map(len, documents)) > MAX_INPUT_ARTIFACT_BYTES:
        raise EnronPerformanceError("Selected real performance input exceeds the reviewed byte limit.")
    return documents


def _real_input_fixture(
    documents: Sequence[bytes],
    *,
    bank_descriptor: Mapping[str, Any],
    native_bank: Any,
) -> tuple[dict[str, Any], bytes, bytes, list[dict[str, int]]]:
    inventory: list[dict[str, int]] = []
    for document in documents:
        try:
            records = native_bank.scan_bytes(document)
        except (MemoryError, RuntimeError, TypeError, ValueError):
            raise EnronPerformanceError("Evaluated Bank could not preflight the real performance input.") from None
        inventory.append({"bytes": len(document), "records": len(records)})
    artifact_bytes = b"".join(documents)
    inventory_bytes = _canonical_json_bytes(inventory)
    if hash_enron_performance_inventory(inventory) != _sha256_bytes(inventory_bytes):
        raise EnronPerformanceError("Real performance inventory hash did not reconcile.")
    summary = summarize_enron_performance_inventory(inventory)
    descriptor: dict[str, Any] = {
        "id": "real_validation_input",
        "kind": "real_input",
        "bank_id": bank_descriptor["id"],
        "bank_hash": bank_descriptor["bank_hash"],
        "artifact": {
            "id": "real_validation_documents",
            "sha256": _sha256_bytes(artifact_bytes),
            "bytes": len(artifact_bytes),
        },
        "inventory_ref": {
            "id": "real_validation_inventory",
            "sha256": _sha256_bytes(inventory_bytes),
            "bytes": len(inventory_bytes),
        },
        "generator": None,
        **summary,
        "descriptor_sha256": "",
    }
    descriptor["descriptor_sha256"] = hash_enron_performance_input(descriptor)
    return descriptor, artifact_bytes, inventory_bytes, inventory


def _source_build_projection(card: Mapping[str, Any]) -> dict[str, Any]:
    try:
        selected = next(item for item in card["iterations"] if item["selected"] is True)
        return {
            "benchmark_version": card["benchmark_version"],
            "development_manifest_sha256": card["source"]["development_manifest_sha256"],
            "train_artifact_sha256": card["source"]["train_artifact_sha256"],
            "train_records": card["source"]["train_records"],
            "candidate_source_sha256": card["builder"]["candidate_source_sha256"],
            "candidate_ledger_sha256": card["builder"]["candidate_ledger_sha256"],
            "builder_source_sha256": card["builder"]["source_sha256"],
            "builder_policy_sha256": card["builder"]["policy_sha256"],
            "bank_artifact_sha256": card["bank"]["artifact_sha256"],
            "bank_canonical_sha256": card["bank"]["canonical_sha256"],
            "bank_canonical_json_bytes": card["bank"]["canonical_json_bytes"],
            "active_totals": card["bank"]["stats"]["active_totals"],
            "selected_iteration_id": selected["id"],
            "selected_active_patterns": selected["active_patterns"],
            "conformance": {
                field: card["catalog_conformance"][field]
                for field in (
                    "active_patterns",
                    "approved_positive_cases",
                    "correctly_mapped",
                    "missed",
                    "wrong_canonical",
                    "negative_cases",
                    "unexpected_negative_matches",
                    "passed",
                )
            },
        }
    except (KeyError, StopIteration, TypeError):
        raise EnronPerformanceError("Verified bank card lacks the source-build correctness projection.") from None


def _baseline_descriptor(
    identifier: str,
    name: str,
    semantic_equivalence: str,
    capabilities: Mapping[str, bool],
    source_sha256: str,
) -> dict[str, Any]:
    descriptor: dict[str, Any] = {
        "id": identifier,
        "name": name,
        "version": PERFORMANCE_OPERATION_SPEC_VERSION,
        "source_sha256": source_sha256,
        "capabilities": dict(capabilities),
        "semantic_equivalence": semantic_equivalence,
        "descriptor_sha256": "",
    }
    descriptor["descriptor_sha256"] = hash_enron_performance_baseline(descriptor)
    return descriptor


def _harness_descriptor(
    *,
    identifier: str,
    phase: str,
    source_sha256: str,
    operation: Mapping[str, Any],
    source_artifact: Mapping[str, Any] | None,
) -> dict[str, Any]:
    descriptor: dict[str, Any] = {
        "id": identifier,
        "phase": phase,
        "command_id": "enron_performance_runner",
        "source_sha256": source_sha256,
        "operation_spec_sha256": _canonical_hash(operation),
        "source_artifact": None if source_artifact is None else dict(source_artifact),
        "descriptor_sha256": "",
    }
    descriptor["descriptor_sha256"] = hash_enron_performance_harness(descriptor)
    return descriptor


def _workload_plan(
    *,
    identifier: str,
    phase: str,
    harness: Mapping[str, Any],
    bank: Mapping[str, Any],
    input_descriptor: Mapping[str, Any] | None,
    sample_unit: str,
    concurrency: int,
    warmups: int,
    decision_grade: bool,
    promotion_gate: bool = False,
    baseline_id: str | None = None,
) -> dict[str, Any]:
    setup_phase = phase in {"source_profile", "source_build", "cold_compile"}
    workload: dict[str, Any] = {
        "id": identifier,
        "phase": phase,
        "promotion_gate": promotion_gate,
        "decision_grade": decision_grade,
        "workload_sha256": "",
        "harness_id": harness["id"],
        "harness_sha256": harness["descriptor_sha256"],
        "bank_id": bank["id"],
        "bank_hash": bank["bank_hash"],
        "input_id": None if setup_phase else input_descriptor["id"] if input_descriptor is not None else None,
        "input_sha256": (
            None if setup_phase else input_descriptor["descriptor_sha256"] if input_descriptor is not None else None
        ),
        "baseline_id": baseline_id,
        "warmups": 0 if PERFORMANCE_PHASE_PROCESS_MODELS[phase] == "fresh_process_per_sample" else warmups,
        "sample_unit": "operation" if setup_phase else sample_unit,
        "work_per_sample": 1,
        "concurrency": concurrency,
        "process_model": PERFORMANCE_PHASE_PROCESS_MODELS[phase],
        "median_method": "standard_even_average",
        "percentile_method": "nearest_rank",
    }
    workload["workload_sha256"] = hash_enron_workload(workload)
    return workload


def _comparison_plan(
    candidate: Mapping[str, Any],
    baseline: Mapping[str, Any],
    metric: str,
    *,
    comparison_kind: str = "same_path_stability",
) -> dict[str, Any]:
    direction = (
        "lower_is_better"
        if metric in {"median_seconds", "p95_seconds", "p99_seconds", "seconds_per_document"}
        else "higher_is_better"
    )
    comparison: dict[str, Any] = {
        "id": f"compare_{candidate['id']}_vs_{baseline['id']}_{metric}",
        "candidate_workload_id": candidate["id"],
        "baseline_workload_id": baseline["id"],
        "comparison_kind": comparison_kind,
        "metric": metric,
        "direction": direction,
        "noise_multiplier": 2.0,
        "noise_method": (
            "paired_block_ratio_mad"
            if comparison_kind == "cross_path_value"
            else "paired_relative_mad"
            if comparison_kind == "same_path_stability" and candidate["sample_unit"] == "document"
            else "independent_mad"
        ),
        "regression_tolerance": 0.05,
        "comparison_plan_sha256": "",
    }
    comparison["comparison_plan_sha256"] = hash_enron_performance_comparison_plan(comparison)
    return comparison


def _breakeven_plan(
    candidate_by_id: Mapping[str, Mapping[str, Any]],
    *,
    source_curation_seconds: float,
) -> dict[str, Any]:
    curation_assumption_sha256 = _canonical_hash(
        {"unit": "seconds", "value": source_curation_seconds, "kind": "declared_scenario"}
    )
    components = [
        {
            "id": "baseline_fixed_build",
            "side": "baseline",
            "application": "fixed",
            "category": "bank_build",
            "source": "workload_median_seconds",
            "description": "Shared measured intelligence-bank build time; identical on both cache paths.",
            "workload_id": candidate_by_id["real_source_build"]["id"],
            "assumption_sha256": None,
            "value": None,
        },
        {
            "id": "baseline_fixed_source_curation",
            "side": "baseline",
            "application": "fixed",
            "category": "source_curation",
            "source": "declared_assumption",
            "description": "Shared declared curation scenario; identical on both cache paths.",
            "workload_id": None,
            "assumption_sha256": curation_assumption_sha256,
            "value": source_curation_seconds,
        },
        {
            "id": "baseline_fixed_source_profiling",
            "side": "baseline",
            "application": "fixed",
            "category": "source_profiling",
            "source": "workload_median_seconds",
            "description": "Shared measured source-profiling time; identical on both cache paths.",
            "workload_id": candidate_by_id["real_source_profile"]["id"],
            "assumption_sha256": None,
            "value": None,
        },
        {
            "id": "baseline_per_request_uncached",
            "side": "baseline",
            "application": "per_unit",
            "category": "scan",
            "source": "workload_seconds_per_request",
            "description": "Exact NERB helper-cache-miss cost per frozen whole-input request.",
            "workload_id": candidate_by_id["real_helper_cache_miss"]["id"],
            "assumption_sha256": None,
            "value": None,
        },
        {
            "id": "candidate_fixed_build",
            "side": "candidate",
            "application": "fixed",
            "category": "bank_build",
            "source": "workload_median_seconds",
            "description": "Shared measured intelligence-bank build time; identical on both cache paths.",
            "workload_id": candidate_by_id["real_source_build"]["id"],
            "assumption_sha256": None,
            "value": None,
        },
        {
            "id": "candidate_fixed_cold_compile",
            "side": "candidate",
            "application": "fixed",
            "category": "cold_compile",
            "source": "workload_median_seconds",
            "description": "Measured one-time cold compilation.",
            "workload_id": candidate_by_id["real_cold_compile"]["id"],
            "assumption_sha256": None,
            "value": None,
        },
        {
            "id": "candidate_fixed_source_curation",
            "side": "candidate",
            "application": "fixed",
            "category": "source_curation",
            "source": "declared_assumption",
            "description": "Shared declared curation scenario; identical on both cache paths.",
            "workload_id": None,
            "assumption_sha256": curation_assumption_sha256,
            "value": source_curation_seconds,
        },
        {
            "id": "candidate_fixed_source_profiling",
            "side": "candidate",
            "application": "fixed",
            "category": "source_profiling",
            "source": "workload_median_seconds",
            "description": "Shared measured source-profiling time; identical on both cache paths.",
            "workload_id": candidate_by_id["real_source_profile"]["id"],
            "assumption_sha256": None,
            "value": None,
        },
        {
            "id": "candidate_per_request_direct_reuse",
            "side": "candidate",
            "application": "per_unit",
            "category": "scan",
            "source": "workload_seconds_per_request",
            "description": "Measured direct compiled-Bank reuse cost per frozen whole-input request.",
            "workload_id": candidate_by_id["real_direct_throughput"]["id"],
            "assumption_sha256": None,
            "value": None,
        },
    ]
    model: dict[str, Any] = {
        "id": "compile_once_scan_many_breakeven",
        "parameter_name": "whole_input_scan_requests",
        "parameter_unit": "request",
        "value_unit": "seconds",
        "minimum_units": 1,
        "maximum_units": 1_000_000_000,
        "components": components,
        "model_plan_sha256": "",
    }
    model["model_plan_sha256"] = hash_enron_breakeven_plan(model)
    return model


def _performance_profile_plan(
    *,
    profile: PerformanceProfile,
    banks: Sequence[Mapping[str, Any]],
    inputs: Sequence[Mapping[str, Any]],
    harnesses: Sequence[Mapping[str, Any]],
    baseline_source_sha256: str,
    concurrency: int,
    source_curation_seconds: float,
) -> dict[str, Any]:
    decision = profile == "decision"
    # Keep the frozen warmup policy identical across profiles.  Smoke changes
    # only the number of measured samples; reused-process correctness still
    # exercises the same cache-warming boundary as a decision run.
    warmups = DEFAULT_WARMUPS
    bank_by_id = {str(item["id"]): item for item in banks}
    input_by_id = {str(item["id"]): item for item in inputs}
    harness_by_id = {str(item["id"]): item for item in harnesses}
    evaluated = bank_by_id["evaluated_bank"]
    real_input = input_by_id["real_validation_input"]
    candidates: list[dict[str, Any]] = []

    def add(
        identifier: str,
        phase: str,
        bank_id: str,
        input_id: str | None,
        sample_unit: str,
        *,
        cell_concurrency: int = 1,
        promotion_gate: bool = False,
    ) -> None:
        candidates.append(
            _workload_plan(
                identifier=identifier,
                phase=phase,
                harness=harness_by_id[f"{phase}_harness"],
                bank=bank_by_id[bank_id],
                input_descriptor=None if input_id is None else input_by_id[input_id],
                sample_unit=sample_unit,
                concurrency=cell_concurrency,
                warmups=warmups,
                decision_grade=decision,
                promotion_gate=decision and promotion_gate,
            )
        )

    add("real_source_profile", "source_profile", "evaluated_bank", None, "operation")
    add("real_source_build", "source_build", "evaluated_bank", None, "operation")
    add("real_cold_compile", "cold_compile", "evaluated_bank", None, "operation")
    add("real_helper_cache_miss", "helper_cache_miss", "evaluated_bank", real_input["id"], "whole_input")
    add("real_helper_cache_hit", "helper_cache_hit", "evaluated_bank", real_input["id"], "whole_input")
    add(
        "real_direct_latency",
        "direct_bank_scan",
        "evaluated_bank",
        real_input["id"],
        "document",
        promotion_gate=True,
    )
    add(
        "real_direct_throughput",
        "direct_bank_scan",
        "evaluated_bank",
        real_input["id"],
        "whole_input",
        promotion_gate=True,
    )
    add("real_end_to_end", "end_to_end", "evaluated_bank", real_input["id"], "whole_input")
    for pattern_count in PERFORMANCE_SCALE_PATTERNS:
        add(
            f"scale_{pattern_count}_direct",
            "direct_bank_scan",
            f"scale_{pattern_count}",
            f"scale_{pattern_count}_input",
            "whole_input",
        )
    for density in ("sparse", "normal", "dense"):
        add(
            f"density_{density}_direct",
            "direct_bank_scan",
            "scale_1000",
            f"density_{density}_input",
            "whole_input",
        )
    for size in ("small", "large", "huge"):
        add(
            f"size_{size}_direct",
            "direct_bank_scan",
            "scale_1000",
            f"size_{size}_input",
            "whole_input",
        )
    add(
        f"scale_1000_concurrency_{concurrency}",
        "direct_bank_scan",
        "scale_1000",
        "scale_1000_input",
        "whole_input",
        cell_concurrency=concurrency,
    )
    if len(candidates) != 19:
        raise EnronPerformanceError("Frozen performance matrix does not contain exactly 19 candidate cells.")
    if not decision:
        smoke_ids = {
            "real_cold_compile",
            "real_helper_cache_miss",
            "real_helper_cache_hit",
            "real_direct_throughput",
            "real_end_to_end",
            "scale_1000_direct",
            f"scale_1000_concurrency_{concurrency}",
        }
        candidates = [item for item in candidates if item["id"] in smoke_ids]

    exact_capabilities = {
        "literal_patterns": True,
        "regex_patterns": True,
        "aliases": True,
        "canonical_mapping": True,
        "unicode": True,
    }
    baselines = [
        _baseline_descriptor(
            PERFORMANCE_GENERIC_REGEX_BASELINE_ID,
            "Generic email-format regex",
            "not_equivalent",
            {
                "literal_patterns": False,
                "regex_patterns": True,
                "aliases": False,
                "canonical_mapping": False,
                "unicode": False,
            },
            baseline_source_sha256,
        ),
        _baseline_descriptor(
            PERFORMANCE_PYTHON_LITERAL_BASELINE_ID,
            "Python literal catalog scan",
            "not_equivalent",
            {
                "literal_patterns": True,
                "regex_patterns": False,
                "aliases": True,
                "canonical_mapping": True,
                "unicode": True,
            },
            baseline_source_sha256,
        ),
    ]
    workloads = list(candidates)
    comparisons: list[dict[str, Any]] = []
    breakeven_models: list[dict[str, Any]] = []
    if decision:
        exact_control = _baseline_descriptor(
            PERFORMANCE_EXACT_CONTROL_ID,
            "NERB exact same-path repeated control",
            "exact",
            exact_capabilities,
            baseline_source_sha256,
        )
        uncached_control = _baseline_descriptor(
            PERFORMANCE_UNCACHED_BASELINE_ID,
            "NERB exact uncached/recompile control",
            "exact",
            exact_capabilities,
            baseline_source_sha256,
        )
        baselines.extend((exact_control, uncached_control))
        for candidate in candidates:
            baseline_id = (
                PERFORMANCE_UNCACHED_BASELINE_ID
                if candidate["id"] == "real_helper_cache_miss"
                else PERFORMANCE_EXACT_CONTROL_ID
            )
            control = dict(candidate)
            control.update(
                {
                    "id": f"control_{candidate['id']}",
                    "promotion_gate": False,
                    "decision_grade": False,
                    "baseline_id": baseline_id,
                }
            )
            control["workload_sha256"] = hash_enron_workload(control)
            workloads.append(control)
            tail_metric = (
                "p95_seconds"
                if candidate["phase"] in {"source_profile", "source_build", "cold_compile"}
                else "p99_seconds"
            )
            comparisons.append(_comparison_plan(candidate, control, tail_metric))
            if candidate["sample_unit"] == "whole_input":
                comparisons.append(_comparison_plan(candidate, control, "mib_per_second"))
        candidate_by_id = {str(item["id"]): item for item in candidates}
        for candidate_id, baseline_id in (
            ("real_helper_cache_hit", "real_helper_cache_miss"),
            ("real_direct_throughput", "real_helper_cache_miss"),
            ("real_direct_throughput", "real_helper_cache_hit"),
            ("real_direct_throughput", "real_end_to_end"),
        ):
            for metric in ("median_seconds", "p99_seconds", "mib_per_second"):
                comparisons.append(
                    _comparison_plan(
                        candidate_by_id[candidate_id],
                        candidate_by_id[baseline_id],
                        metric,
                        comparison_kind="cross_path_value",
                    )
                )
        breakeven_models.append(
            _breakeven_plan(
                candidate_by_id,
                source_curation_seconds=source_curation_seconds,
            )
        )

    for baseline_id, harness_id, identifier in (
        (PERFORMANCE_GENERIC_REGEX_BASELINE_ID, "generic_regex_harness", "explore_generic_email_regex"),
        (PERFORMANCE_PYTHON_LITERAL_BASELINE_ID, "python_literal_harness", "explore_python_literal_scan"),
    ):
        workload = _workload_plan(
            identifier=identifier,
            phase="direct_bank_scan",
            harness=harness_by_id[harness_id],
            bank=evaluated,
            input_descriptor=real_input,
            sample_unit="whole_input",
            concurrency=1,
            warmups=warmups,
            decision_grade=False,
            baseline_id=baseline_id,
        )
        workloads.append(workload)

    performance = {
        "evaluated": True,
        "banks": sorted((dict(item) for item in banks), key=lambda item: item["id"]),
        "inputs": sorted((dict(item) for item in inputs), key=lambda item: item["id"]),
        "harnesses": sorted((dict(item) for item in harnesses), key=lambda item: item["id"]),
        "workloads": sorted(workloads, key=lambda item: item["id"]),
        "baselines": sorted(baselines, key=lambda item: item["id"]),
        "comparisons": sorted(comparisons, key=lambda item: item["id"]),
        "breakeven_models": sorted(breakeven_models, key=lambda item: item["id"]),
    }
    return {
        "sample_policy": {
            "setup_samples": DEFAULT_SETUP_SAMPLES if decision else DEFAULT_SMOKE_SAMPLES,
            "scan_samples": DEFAULT_SCAN_SAMPLES if decision else DEFAULT_SMOKE_SAMPLES,
            "document_samples": DEFAULT_DOCUMENT_SAMPLES if decision else None,
            "warmups": warmups,
            "interleaving": "williams_blocked_cross_path_with_abba_controls" if decision else "candidate_only",
            "promotable": decision,
        },
        "performance_manifest_sha256": hash_enron_performance_manifest(performance),
        "performance": performance,
    }


def _performance_plan(
    *,
    benchmark_version: str,
    source_profile_artifact: Mapping[str, Any],
    source_build_artifact: Mapping[str, Any],
    evaluated_bank: Mapping[str, Any],
    bank_fixtures: Sequence[EnronPerformanceBankFixture],
    real_input: Mapping[str, Any],
    input_fixtures: Sequence[EnronPerformanceInputFixture],
    concurrency: int,
    source_curation_seconds: float,
) -> dict[str, Any]:
    source_sha256 = _performance_harness_source_sha256()
    operations = {
        phase: {
            "schema_version": "nerb.enron_performance_operation.v1",
            "phase": phase,
            "operation_spec_version": PERFORMANCE_OPERATION_SPEC_VERSION,
            "implementation": (
                "source_build_subprocess"
                if phase == "source_build"
                else "source_profile"
                if phase == "source_profile"
                else "bank_compile"
                if phase == "cold_compile"
                else "json_helper_scan"
                if phase in {"helper_cache_miss", "helper_cache_hit", "end_to_end"}
                else "direct_bank_scan"
            ),
        }
        for phase in PERFORMANCE_PHASE_PROCESS_MODELS
    }
    harnesses = [
        _harness_descriptor(
            identifier=f"{phase}_harness",
            phase=phase,
            source_sha256=source_sha256,
            operation=operations[phase],
            source_artifact=(
                source_profile_artifact
                if phase == "source_profile"
                else source_build_artifact
                if phase == "source_build"
                else None
            ),
        )
        for phase in PERFORMANCE_PHASE_PROCESS_MODELS
    ]
    harnesses.extend(
        (
            _harness_descriptor(
                identifier="generic_regex_harness",
                phase="direct_bank_scan",
                source_sha256=source_sha256,
                operation={"implementation": "generic_email_regex", "semantic_equivalence": "not_equivalent"},
                source_artifact=None,
            ),
            _harness_descriptor(
                identifier="python_literal_harness",
                phase="direct_bank_scan",
                source_sha256=source_sha256,
                operation={"implementation": "python_literal_catalog", "semantic_equivalence": "not_equivalent"},
                source_artifact=None,
            ),
        )
    )
    banks = [dict(evaluated_bank), *(fixture.descriptor for fixture in bank_fixtures)]
    inputs = [dict(real_input), *(fixture.descriptor for fixture in input_fixtures)]
    profiles = {
        profile: _performance_profile_plan(
            profile=_validate_profile(profile),
            banks=banks,
            inputs=inputs,
            harnesses=harnesses,
            baseline_source_sha256=source_sha256,
            concurrency=concurrency,
            source_curation_seconds=source_curation_seconds,
        )
        for profile in PERFORMANCE_PROFILE_IDS
    }
    plan: dict[str, Any] = {
        "schema_version": PERFORMANCE_PLAN_SCHEMA_VERSION,
        "suite": PERFORMANCE_SUITE_ID,
        "benchmark_version": benchmark_version,
        "scale_axis": "active_matcher_patterns",
        "catalog_aliases_reported_separately": True,
        "decision_thresholds": dict(PERFORMANCE_DECISION_THRESHOLDS),
        "source_profile_artifact": dict(source_profile_artifact),
        "source_build_artifact": dict(source_build_artifact),
        "profiles": profiles,
        "plan_sha256": "",
    }
    plan["plan_sha256"] = _canonical_hash({key: value for key, value in plan.items() if key != "plan_sha256"})
    return cast(dict[str, Any], json.loads(_canonical_json_bytes(plan)))


def _validate_performance_plan_shape(plan: Mapping[str, Any]) -> None:
    expected_keys = {
        "schema_version",
        "suite",
        "benchmark_version",
        "scale_axis",
        "catalog_aliases_reported_separately",
        "source_profile_artifact",
        "source_build_artifact",
        "decision_thresholds",
        "profiles",
        "plan_sha256",
    }
    if (
        set(plan) != expected_keys
        or plan.get("schema_version") != PERFORMANCE_PLAN_SCHEMA_VERSION
        or plan.get("suite") != PERFORMANCE_SUITE_ID
        or plan.get("scale_axis") != "active_matcher_patterns"
        or plan.get("catalog_aliases_reported_separately") is not True
        or plan.get("decision_thresholds") != PERFORMANCE_DECISION_THRESHOLDS
    ):
        raise EnronPerformanceError("Performance plan closed envelope is invalid.")
    for name in ("source_profile_artifact", "source_build_artifact"):
        value = plan.get(name)
        if not isinstance(value, Mapping):
            raise EnronPerformanceError("Performance plan source binding is invalid.")
        _artifact_ref(value)
    profiles = plan.get("profiles")
    if not isinstance(profiles, Mapping) or set(profiles) != set(PERFORMANCE_PROFILE_IDS):
        raise EnronPerformanceError("Performance plan profiles are invalid.")
    for profile in PERFORMANCE_PROFILE_IDS:
        profile_plan = profiles.get(profile)
        if not isinstance(profile_plan, Mapping) or set(profile_plan) != {
            "sample_policy",
            "performance_manifest_sha256",
            "performance",
        }:
            raise EnronPerformanceError("Performance plan profile envelope is invalid.")
        expected_policy = {
            "setup_samples": DEFAULT_SETUP_SAMPLES if profile == "decision" else DEFAULT_SMOKE_SAMPLES,
            "scan_samples": DEFAULT_SCAN_SAMPLES if profile == "decision" else DEFAULT_SMOKE_SAMPLES,
            "document_samples": DEFAULT_DOCUMENT_SAMPLES if profile == "decision" else None,
            "warmups": DEFAULT_WARMUPS,
            "interleaving": (
                "williams_blocked_cross_path_with_abba_controls" if profile == "decision" else "candidate_only"
            ),
            "promotable": profile == "decision",
        }
        performance = profile_plan.get("performance")
        if profile_plan.get("sample_policy") != expected_policy or not isinstance(performance, Mapping):
            raise EnronPerformanceError("Performance plan sample policy is invalid.")
        if (
            set(performance)
            != {
                "evaluated",
                "banks",
                "inputs",
                "harnesses",
                "workloads",
                "baselines",
                "comparisons",
                "breakeven_models",
            }
            or performance.get("evaluated") is not True
            or any(not isinstance(performance[name], list) for name in set(performance) - {"evaluated"})
        ):
            raise EnronPerformanceError("Performance plan workload collections are invalid.")


def _validate_run_report_envelope(report: Mapping[str, Any]) -> None:
    if set(report) != {
        "schema_version",
        "suite",
        "benchmark_version",
        "profile",
        "plan_sha256",
        "performance_manifest_sha256",
        "performance",
        "environment",
        "software",
        "decision_grade",
        "sealed_test_accessed",
        "privacy",
        "run_sha256",
    }:
        raise EnronPerformanceError("Performance aggregate report closed envelope is invalid.")
    environment = report.get("environment")
    software = report.get("software")
    decision = report.get("decision_grade")
    privacy = report.get("privacy")
    if (
        not isinstance(environment, Mapping)
        or set(environment) != {"os", "architecture", "python", "cpu_count", "cpu_model", "memory_bytes"}
        or any(
            not isinstance(environment[name], str) or not environment[name]
            for name in ("os", "architecture", "python", "cpu_model")
        )
        or type(environment.get("cpu_count")) is not int
        or environment["cpu_count"] < 1
        or type(environment.get("memory_bytes")) is not int
        or environment["memory_bytes"] < 1
    ):
        raise EnronPerformanceError("Performance aggregate report environment is invalid.")
    if (
        not isinstance(software, Mapping)
        or set(software) != {"package_version", "engine_version", "git_commit", "git_dirty"}
        or any(
            not isinstance(software[name], str) or not software[name] for name in ("package_version", "engine_version")
        )
        or not isinstance(software.get("git_commit"), str)
        or re.fullmatch(r"[0-9a-f]{40}", software["git_commit"]) is None
        or type(software.get("git_dirty")) is not bool
    ):
        raise EnronPerformanceError("Performance aggregate report software binding is invalid.")
    if (
        not isinstance(decision, Mapping)
        or set(decision) != {"passed", "failure_codes"}
        or type(decision.get("passed")) is not bool
        or not isinstance(decision.get("failure_codes"), list)
        or any(not isinstance(item, str) or not item or len(item) > 256 for item in decision["failure_codes"])
        or len(set(decision["failure_codes"])) != len(decision["failure_codes"])
    ):
        raise EnronPerformanceError("Performance aggregate report decision summary is invalid.")
    if (
        not isinstance(privacy, Mapping)
        or set(privacy)
        != {
            "status",
            "raw_text_included",
            "direct_identifiers_included",
            "private_paths_included",
            "violation_count",
        }
        or privacy.get("status") != "passed"
        or any(
            type(privacy.get(name)) is not bool
            for name in ("raw_text_included", "direct_identifiers_included", "private_paths_included")
        )
        or any(
            privacy[name] is not False
            for name in ("raw_text_included", "direct_identifiers_included", "private_paths_included")
        )
        or privacy.get("violation_count") != 0
    ):
        raise EnronPerformanceError("Performance aggregate report privacy envelope is invalid.")


def prepare_enron_performance_manifest(options: EnronPerformancePrepareOptions) -> dict[str, Any]:
    """Freeze private artifacts and a public path-free Enron performance plan."""

    if not isinstance(options, EnronPerformancePrepareOptions):
        raise EnronPerformanceError("Performance preparation options are invalid.")
    real_input_documents = _positive_int(
        options.real_input_documents,
        "Real input document count",
        maximum=10_000,
    )
    if real_input_documents != DEFAULT_REAL_INPUT_DOCUMENTS:
        raise EnronPerformanceError("The frozen real performance input requires exactly 100 documents.")
    concurrency = _positive_int(options.concurrency, "Performance concurrency", maximum=8)
    if concurrency < 2:
        raise EnronPerformanceError("Performance concurrency sweep requires at least two workers.")
    if concurrency > (os.cpu_count() or 1):
        raise EnronPerformanceError("Performance concurrency cannot exceed the current CPU count.")
    source_curation_seconds = _positive_finite(
        options.source_curation_seconds,
        "Source curation scenario",
        maximum=MAX_SOURCE_BUILD_SECONDS,
    )
    bank_root = _absolute_private_path(options.bank_build_run, description="Bank-build run")
    development_root, development_tree = _snapshot_performance_private_tree(
        options.development_run,
        description="Development source run",
    )
    try:
        bank_snapshot = _verify_enron_bank_build_snapshot(
            options.bank_build_run,
            annotation_run=options.annotation_run,
        )
        verification = bank_snapshot.summary
        card = bank_snapshot.card
        bank_payload = bank_snapshot.bank_payload
        bank_value = bank_snapshot.bank
        validation_documents = bank_snapshot.validation_documents
        build_created_at = bank_snapshot.build_created_at
        bank_tree = getattr(bank_snapshot, "private_tree", None)
        bank_artifact_fingerprints = getattr(bank_snapshot, "artifact_fingerprints", None)
        annotation_tree = getattr(bank_snapshot, "annotation_tree", None)
        del bank_snapshot
        development = load_enron_development_split(development_root)
    except (EnronBankBuildError, EnronPrivateIOError, EnronSplitError):
        raise EnronPerformanceError("Performance source runs did not pass deep verification.") from None
    _assert_performance_private_tree_current(
        development_root,
        development_tree,
        description="Development source run",
    )
    if (
        verification.get("valid") is not True
        or card.get("run_sha256") != verification.get("bank_card_run_sha256")
        or card.get("benchmark_version") != verification.get("benchmark_version")
        or card.get("fixture_mode") != verification.get("fixture_mode")
        or card.get("promotable") != verification.get("promotable")
        or cast(Mapping[str, Any], card.get("bank", {})).get("canonical_sha256") != verification.get("bank_sha256")
        or card.get("privacy") != verification.get("privacy")
        or cast(Mapping[str, Any], card.get("source", {})).get("sealed_test_accessed")
        != verification.get("sealed_test_accessed")
    ):
        raise EnronPerformanceError("Verified bank card differs from its deep-verification result.")
    benchmark_version = str(card.get("benchmark_version", ""))
    if options.benchmark_version is not None and options.benchmark_version != benchmark_version:
        raise EnronPerformanceError("Requested benchmark version does not match the verified bank build.")
    _bounded_private_string(
        benchmark_version,
        maximum_bytes=MAX_BENCHMARK_VERSION_BYTES,
        description="Verified benchmark version",
    )

    bank_card = card.get("bank")
    if not isinstance(bank_card, Mapping):
        raise EnronPerformanceError("Verified bank card is missing its bank binding.")
    if (
        _sha256_bytes(bank_payload) != bank_card.get("artifact_sha256")
        or hash_bank(bank_value) != bank_card.get("canonical_sha256")
        or len(_canonical_json_bytes(canonicalize_bank(bank_value))) != bank_card.get("canonical_json_bytes")
    ):
        raise EnronPerformanceError("Evaluated bank artifact differs from its verified bank card.")
    compiled, _cache_hit, compile_report = compile_bank_with_report(bank_value)
    if compiled.native_bank is None:
        raise EnronPerformanceError("Evaluated bank has no active native matcher set.")
    native_source_bytes = compile_report.get("source", {}).get("extractable_json_bytes")
    native_source_bytes = _positive_int(native_source_bytes, "Evaluated native source bytes")
    evaluated_artifact = _artifact_from_bytes("evaluated_bank_artifact", "banks/evaluated.json", bank_payload)
    evaluated_descriptor = _evaluated_bank_descriptor(bank_value, evaluated_artifact, native_source_bytes)

    documents = _select_real_documents(
        validation_documents,
        count=real_input_documents,
        seed=f"{benchmark_version}:performance-real-input-v1",
    )
    del validation_documents
    real_input, real_input_bytes, real_inventory_bytes, _real_inventory = _real_input_fixture(
        documents,
        bank_descriptor=evaluated_descriptor,
        native_bank=compiled.native_bank,
    )
    try:
        bank_fixtures = make_enron_performance_bank_fixtures(evaluated_bank=evaluated_descriptor)
        input_fixtures = make_enron_performance_input_fixtures(bank_fixtures)
    except EnronPerformanceFixtureError:
        raise EnronPerformanceError("Controlled performance fixtures failed native preflight.") from None

    development_manifest = development.manifest
    try:
        train_ref = _artifact_ref(development_manifest["development_roles"]["train"]["artifact"])
        train_records = development_manifest["development_roles"]["train"]["records"]
        bank_source = card["source"]
        development_manifest_sha256 = development.manifest_sha256
    except (EnronSplitError, KeyError, TypeError):
        raise EnronPerformanceError("Verified development train binding is invalid.") from None
    if (
        bank_source.get("development_manifest_sha256") != development_manifest_sha256
        or bank_source.get("train_artifact_sha256") != train_ref["sha256"]
        or bank_source.get("train_records") != train_records
    ):
        raise EnronPerformanceError("Evaluated bank build does not bind the selected development train artifact.")
    development_manifest_fingerprint = _fingerprint_performance_private_file(
        development_root,
        "manifest.json",
        development_tree,
        maximum_bytes=MAX_PLAN_BYTES,
        description="Development manifest",
    )
    train_fingerprint = _fingerprint_performance_private_file(
        development_root,
        "train.jsonl",
        development_tree,
        maximum_bytes=MAX_SOURCE_PROFILE_BYTES,
        description="Development train artifact",
    )
    if (
        development_manifest_fingerprint.sha256 != development_manifest_sha256
        or train_fingerprint.sha256 != train_ref["sha256"]
        or train_fingerprint.identity.size != train_ref["bytes"]
    ):
        raise EnronPerformanceError("Frozen development source identities differ from their verified descriptors.")
    annotation_root: Path | None = None
    bindings_path: Path | None = None
    bindings_identity: dict[str, Any] | None = None
    annotation_tree_payload: dict[str, dict[str, Any]] | None = None
    bank_tree_payload: dict[str, dict[str, Any]] | None = None
    if options.annotation_run is not None:
        annotation_root = _absolute_private_path(options.annotation_run, description="Annotation source run")
        if annotation_tree is None or bank_tree is None or bank_artifact_fingerprints is None:
            raise EnronPerformanceError("Verified bank build did not retain its auxiliary source identities.")
        _validate_private_tree_payload(_private_tree_payload(annotation_tree))
        _assert_performance_private_tree_current(
            annotation_root,
            annotation_tree,
            description="Annotation source run",
        )
        _assert_performance_private_tree_current(
            bank_root,
            bank_tree,
            description="Bank-build source run",
        )
        bindings_fingerprint = bank_artifact_fingerprints.get("cmu_catalog_bindings")
        bindings_relative = "auxiliary/cmu-train-catalog-bindings.jsonl"
        if bindings_fingerprint is None or bank_tree.get(bindings_relative) != bindings_fingerprint.identity:
            raise EnronPerformanceError("Verified bank build did not retain its auxiliary binding identity.")
        bindings_path = bank_root / bindings_relative
        bindings_identity = _private_identity_payload(bindings_fingerprint.identity)
        annotation_tree_payload = _private_tree_payload(annotation_tree)
        bank_tree_payload = _private_tree_payload(bank_tree)
    plan = _performance_plan(
        benchmark_version=benchmark_version,
        source_profile_artifact=train_ref,
        source_build_artifact=train_ref,
        evaluated_bank=evaluated_descriptor,
        bank_fixtures=bank_fixtures,
        real_input=real_input,
        input_fixtures=input_fixtures,
        concurrency=concurrency,
        source_curation_seconds=source_curation_seconds,
    )
    _validate_performance_plan_shape(plan)
    if _public_serialization_diagnostics(plan):
        raise EnronPerformanceError("Public performance plan failed the aggregate privacy scan.")

    locations = {
        "schema_version": "nerb.enron_performance_locations.v1",
        "profile_source": os.fspath(development_root / "train.jsonl"),
        "development_run": os.fspath(development_root),
        "annotation_run": None if annotation_root is None else os.fspath(annotation_root),
        "cmu_catalog_bindings": None if bindings_path is None else os.fspath(bindings_path),
        "source_identities": {
            "development_tree": _private_tree_payload(development_tree),
            "development_manifest": _private_identity_payload(development_manifest_fingerprint.identity),
            "profile_source": _private_identity_payload(train_fingerprint.identity),
            "annotation_tree": annotation_tree_payload,
            "bank_build_tree": bank_tree_payload,
            "cmu_catalog_bindings": bindings_identity,
        },
        "build_created_at": build_created_at,
        "source_build_projection_sha256": _canonical_hash(_source_build_projection(card)),
    }
    _validate_performance_locations(locations, plan)
    _validate_source_build_request_budget(plan, locations)
    plan_payload = _pretty_json_bytes(plan)
    locations_payload = _pretty_json_bytes(locations)
    artifacts_by_path: dict[str, tuple[_Artifact, bytes, str]] = {}

    def stage_artifact(artifact: _Artifact, payload: bytes, kind: str) -> None:
        prior = artifacts_by_path.get(artifact.relative_path)
        if prior is not None and (prior[0].sha256 != artifact.sha256 or prior[1] != payload):
            raise EnronPerformanceError("Performance artifacts collide at one private logical path.")
        artifacts_by_path[artifact.relative_path] = (artifact, payload, kind)

    stage_artifact(evaluated_artifact, bank_payload, "evaluated_bank")
    stage_artifact(
        _artifact_from_bytes("real_validation_documents", "inputs/real-validation.raw", real_input_bytes),
        real_input_bytes,
        "real_input",
    )
    stage_artifact(
        _artifact_from_bytes(
            "real_validation_inventory",
            "inputs/real-validation.inventory.json",
            real_inventory_bytes,
        ),
        real_inventory_bytes,
        "inventory",
    )
    for fixture in bank_fixtures:
        stage_artifact(
            _artifact_from_bytes(fixture.source_artifact_id, fixture.source_filename, fixture.source_bytes),
            fixture.source_bytes,
            "synthetic_native_bank",
        )
        stage_artifact(
            _artifact_from_bytes(fixture.canonical_artifact_id, fixture.canonical_filename, fixture.canonical_bytes),
            fixture.canonical_bytes,
            "synthetic_canonical_bank",
        )
    for input_fixture in input_fixtures:
        stage_artifact(
            _artifact_from_bytes(
                input_fixture.artifact_id,
                input_fixture.artifact_filename,
                input_fixture.artifact_bytes,
            ),
            input_fixture.artifact_bytes,
            "synthetic_input",
        )
        stage_artifact(
            _artifact_from_bytes(
                input_fixture.inventory_id,
                input_fixture.inventory_filename,
                input_fixture.inventory_bytes,
            ),
            input_fixture.inventory_bytes,
            "inventory",
        )
    plan_artifact = _artifact_from_bytes("performance_plan", "plan.json", plan_payload)
    locations_artifact = _artifact_from_bytes("private_locations", "locations.json", locations_payload)
    stage_artifact(plan_artifact, plan_payload, "public_plan")
    stage_artifact(locations_artifact, locations_payload, "private_locations")
    manifest = {
        "schema_version": PERFORMANCE_PRIVATE_MANIFEST_SCHEMA_VERSION,
        "suite": PERFORMANCE_SUITE_ID,
        "benchmark_version": benchmark_version,
        "plan_sha256": plan["plan_sha256"],
        "artifacts": [
            {
                **artifact.ref(),
                "relative_path": artifact.relative_path,
                "kind": kind,
            }
            for artifact, _payload, kind in sorted(artifacts_by_path.values(), key=lambda item: item[0].relative_path)
        ],
    }
    _assert_performance_private_tree_current(
        development_root,
        development_tree,
        description="Development source run",
    )
    if annotation_root is not None and annotation_tree is not None:
        _assert_performance_private_tree_current(
            annotation_root,
            annotation_tree,
            description="Annotation source run",
        )
    try:
        with PrivateRun(
            options.output_dir,
            allow_unignored_output=options.allow_unignored_output,
        ) as run:
            for artifact, payload, _kind in sorted(artifacts_by_path.values(), key=lambda item: item[0].relative_path):
                _write_artifact(run, artifact, payload)
            with run.open_binary("manifest.json") as file:
                file.write(_pretty_json_bytes(manifest))
            run.commit()
    except EnronPrivateIOError:
        raise EnronPerformanceError("Performance preparation failed safely.") from None
    return {
        "schema_version": PERFORMANCE_PLAN_SCHEMA_VERSION,
        "committed": True,
        "suite": PERFORMANCE_SUITE_ID,
        "benchmark_version": benchmark_version,
        "plan_sha256": plan["plan_sha256"],
        "performance_manifest_sha256": {
            profile: plan["profiles"][profile]["performance_manifest_sha256"] for profile in PERFORMANCE_PROFILE_IDS
        },
        "banks": len(plan["profiles"]["decision"]["performance"]["banks"]),
        "inputs": len(plan["profiles"]["decision"]["performance"]["inputs"]),
        "decision_workloads": len(plan["profiles"]["decision"]["performance"]["workloads"]),
        "sealed_test_accessed": False,
    }


def _load_prepared_performance_run_impl(run_dir: Path) -> _PreparedPerformanceRun:
    root, initial_tree = _snapshot_performance_private_tree(
        run_dir,
        description="Performance preparation run",
    )
    marker_fingerprint = _fingerprint_performance_private_file(
        root,
        "COMMITTED",
        initial_tree,
        maximum_bytes=128,
        description="Performance commit marker",
    )
    marker = _read_fingerprinted_private_bytes(
        root / "COMMITTED",
        marker_fingerprint,
        maximum_bytes=128,
        description="Performance commit marker",
    )
    if marker != b"nerb.enron.private-run.v2\n":
        raise EnronPerformanceError("Performance preparation run is not committed.")
    manifest_fingerprint = _fingerprint_performance_private_file(
        root,
        "manifest.json",
        initial_tree,
        maximum_bytes=MAX_PLAN_BYTES,
        description="Performance private manifest",
    )
    manifest = _strict_json_object_bytes(
        _read_fingerprinted_private_bytes(
            root / "manifest.json",
            manifest_fingerprint,
            maximum_bytes=MAX_PLAN_BYTES,
            description="Performance private manifest",
        ),
        description="Performance private manifest",
    )
    if (
        set(manifest)
        != {
            "schema_version",
            "suite",
            "benchmark_version",
            "plan_sha256",
            "artifacts",
        }
        or manifest.get("schema_version") != PERFORMANCE_PRIVATE_MANIFEST_SCHEMA_VERSION
        or manifest.get("suite") != PERFORMANCE_SUITE_ID
    ):
        raise EnronPerformanceError("Performance private manifest shape is invalid.")
    raw_artifacts = manifest.get("artifacts")
    if not isinstance(raw_artifacts, list) or not raw_artifacts:
        raise EnronPerformanceError("Performance private manifest has no artifacts.")
    identifiers: set[str] = set()
    paths: set[str] = set()
    artifact_by_id: dict[str, Mapping[str, Any]] = {}
    artifact_fingerprints: dict[str, Any] = {}
    for item in raw_artifacts:
        if not isinstance(item, Mapping) or set(item) != {"id", "sha256", "bytes", "relative_path", "kind"}:
            raise EnronPerformanceError("Performance private artifact descriptor is invalid.")
        identifier = item.get("id")
        relative_path = item.get("relative_path")
        fixed_contract = {
            "performance_plan": ("public_plan", "plan.json"),
            "private_locations": ("private_locations", "locations.json"),
        }.get(str(identifier))
        if (
            not isinstance(identifier, str)
            or not identifier
            or identifier in identifiers
            or not isinstance(relative_path, str)
            or not relative_path
            or relative_path in paths
        ):
            raise EnronPerformanceError("Performance private artifact ids and paths must be unique.")
        if fixed_contract is not None and (item.get("kind"), relative_path) != fixed_contract:
            raise EnronPerformanceError("Performance private artifact privacy classification is invalid.")
        relative = Path(relative_path)
        if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
            raise EnronPerformanceError("Performance private artifact path is unsafe.")
        _positive_int(
            item.get("bytes"),
            "Performance artifact bytes",
            maximum=MAX_PRIVATE_JSON_BYTES,
        )
        identifiers.add(identifier)
        paths.add(relative_path)
        artifact_by_id[identifier] = item
    _verify_performance_tree_inventory(initial_tree, ["COMMITTED", "manifest.json", *sorted(paths)])
    for identifier, item in artifact_by_id.items():
        byte_count = int(item["bytes"])
        relative_path = str(item["relative_path"])
        fingerprint = _fingerprint_performance_private_file(
            root,
            relative_path,
            initial_tree,
            maximum_bytes=max(byte_count, 1),
            description="Performance private artifact",
        )
        if fingerprint.identity.size != byte_count or fingerprint.sha256 != item.get("sha256"):
            raise EnronPerformanceError("Performance private artifact changed after preparation.")
        artifact_fingerprints[identifier] = fingerprint
    if "performance_plan" not in artifact_by_id or "private_locations" not in artifact_by_id:
        raise EnronPerformanceError("Performance preparation is missing its plan or private locations.")
    plan_item = artifact_by_id["performance_plan"]
    locations_item = artifact_by_id["private_locations"]
    plan = _strict_json_object_bytes(
        _read_fingerprinted_private_bytes(
            root / str(plan_item["relative_path"]),
            artifact_fingerprints["performance_plan"],
            maximum_bytes=MAX_PLAN_BYTES,
            description="Performance plan",
        ),
        description="Performance plan",
    )
    locations = _strict_json_object_bytes(
        _read_fingerprinted_private_bytes(
            root / str(locations_item["relative_path"]),
            artifact_fingerprints["private_locations"],
            maximum_bytes=MAX_PLAN_BYTES,
            description="Performance private locations",
        ),
        description="Performance private locations",
    )
    _validate_performance_plan_shape(plan)
    expected_artifacts = _prepared_artifact_contracts(plan)
    if set(artifact_by_id) != set(expected_artifacts) or any(
        (artifact_by_id[identifier]["kind"], artifact_by_id[identifier]["relative_path"])
        != expected_artifacts[identifier]
        for identifier in expected_artifacts
    ):
        raise EnronPerformanceError("Performance private artifact privacy classification is invalid.")
    if manifest.get("benchmark_version") != plan.get("benchmark_version"):
        raise EnronPerformanceError("Performance private manifest benchmark binding is invalid.")
    expected_plan_hash = _canonical_hash({key: value for key, value in plan.items() if key != "plan_sha256"})
    if plan.get("plan_sha256") != expected_plan_hash or manifest.get("plan_sha256") != expected_plan_hash:
        raise EnronPerformanceError("Performance plan hash does not match its frozen content.")
    if _public_serialization_diagnostics(plan):
        raise EnronPerformanceError("Performance plan failed its aggregate privacy scan.")
    profiles = cast(Mapping[str, Any], plan["profiles"])
    for profile in PERFORMANCE_PROFILE_IDS:
        profile_plan = profiles[profile]
        if not isinstance(profile_plan, Mapping) or not isinstance(profile_plan.get("performance"), Mapping):
            raise EnronPerformanceError("Performance profile plan is invalid.")
        if profile_plan.get("performance_manifest_sha256") != hash_enron_performance_manifest(
            profile_plan["performance"]
        ):
            raise EnronPerformanceError("Performance profile manifest hash is invalid.")
    _validate_performance_locations(locations, plan)
    _validate_source_build_request_budget(plan, locations)
    _assert_performance_private_tree_current(
        root,
        initial_tree,
        description="Performance preparation run",
    )
    return _PreparedPerformanceRun(
        root=root,
        manifest=manifest,
        plan=plan,
        locations=locations,
        tree=initial_tree,
        artifact_fingerprints=artifact_fingerprints,
    )


def _prepared_artifact_contracts(plan: Mapping[str, Any]) -> dict[str, tuple[str, str]]:
    performance = plan["profiles"]["decision"]["performance"]
    contracts: dict[str, tuple[str, str]] = {
        "performance_plan": ("public_plan", "plan.json"),
        "private_locations": ("private_locations", "locations.json"),
    }

    def add(identifier: str, contract: tuple[str, str]) -> None:
        prior = contracts.get(identifier)
        if prior is not None and prior != contract:
            raise EnronPerformanceError("Performance plan has conflicting private artifact contracts.")
        contracts[identifier] = contract

    for bank in performance["banks"]:
        bank_id = str(bank["id"])
        artifact_id = str(bank["artifact"]["id"])
        if bank["kind"] == "evaluated_bank":
            add(artifact_id, ("evaluated_bank", "banks/evaluated.json"))
        else:
            add(artifact_id, ("synthetic_canonical_bank", f"banks/{bank_id}.canonical.json"))
            add(f"{bank_id}_native_source", ("synthetic_native_bank", f"banks/{bank_id}.native.jsonl"))
    for input_descriptor in performance["inputs"]:
        artifact_id = str(input_descriptor["artifact"]["id"])
        inventory_id = str(input_descriptor["inventory_ref"]["id"])
        if input_descriptor["kind"] == "real_input":
            add(artifact_id, ("real_input", "inputs/real-validation.raw"))
            add(inventory_id, ("inventory", "inputs/real-validation.inventory.json"))
        else:
            if not artifact_id.endswith("_documents") or not inventory_id.endswith("_inventory"):
                raise EnronPerformanceError("Performance synthetic artifact ids are not canonical.")
            add(artifact_id, ("synthetic_input", f"inputs/{artifact_id.removesuffix('_documents')}.raw"))
            add(
                inventory_id,
                ("inventory", f"inputs/{inventory_id.removesuffix('_inventory')}.inventory.json"),
            )
    return contracts


def _validate_performance_locations(locations: Mapping[str, Any], plan: Mapping[str, Any]) -> None:
    if (
        set(locations)
        != {
            "schema_version",
            "profile_source",
            "development_run",
            "annotation_run",
            "cmu_catalog_bindings",
            "source_identities",
            "build_created_at",
            "source_build_projection_sha256",
        }
        or locations.get("schema_version") != "nerb.enron_performance_locations.v1"
    ):
        raise EnronPerformanceError("Performance private location binding is invalid.")
    _bounded_private_string(
        plan.get("benchmark_version"),
        maximum_bytes=MAX_BENCHMARK_VERSION_BYTES,
        description="Performance benchmark version",
    )
    development_value = locations.get("development_run")
    profile_value = locations.get("profile_source")
    development_path = _validated_absolute_private_location(
        development_value,
        description="Performance development run location",
    )
    profile_path = _validated_absolute_private_location(
        profile_value,
        description="Performance profile source location",
    )
    if profile_path != development_path / "train.jsonl":
        raise EnronPerformanceError("Performance development source locations are invalid.")
    identities = locations.get("source_identities")
    if not isinstance(identities, Mapping) or set(identities) != {
        "development_tree",
        "development_manifest",
        "profile_source",
        "annotation_tree",
        "bank_build_tree",
        "cmu_catalog_bindings",
    }:
        raise EnronPerformanceError("Performance source identity binding is invalid.")
    development_tree = _validate_private_tree_payload(identities.get("development_tree"))
    manifest_identity = _validate_private_identity_payload(
        identities.get("development_manifest"),
        expected_kind="file",
    )
    profile_identity = _validate_private_identity_payload(
        identities.get("profile_source"),
        expected_kind="file",
    )
    if (
        development_tree.get("manifest.json") != manifest_identity
        or development_tree.get("train.jsonl") != profile_identity
    ):
        raise EnronPerformanceError("Performance development source identity binding is inconsistent.")
    source_profile_ref = plan.get("source_profile_artifact")
    source_build_ref = plan.get("source_build_artifact")
    if (
        not isinstance(source_profile_ref, Mapping)
        or not isinstance(source_build_ref, Mapping)
        or source_profile_ref != source_build_ref
        or profile_identity["size"] != source_profile_ref.get("bytes")
    ):
        raise EnronPerformanceError("Performance train identity differs from its frozen plan descriptor.")
    annotation_value = locations.get("annotation_run")
    bindings_value = locations.get("cmu_catalog_bindings")
    annotation_identities = identities.get("annotation_tree")
    bank_build_identities = identities.get("bank_build_tree")
    bindings_identity = identities.get("cmu_catalog_bindings")
    optional_values = (
        annotation_value,
        bindings_value,
        annotation_identities,
        bank_build_identities,
        bindings_identity,
    )
    if any(item is None for item in optional_values) and any(item is not None for item in optional_values):
        raise EnronPerformanceError("Performance auxiliary source identity binding is incomplete.")
    if annotation_value is not None:
        _validated_absolute_private_location(
            annotation_value,
            description="Performance annotation run location",
        )
        bindings_path = _validated_absolute_private_location(
            bindings_value,
            description="Performance auxiliary binding location",
        )
        _validate_private_tree_payload(annotation_identities)
        bank_build_tree = _validate_private_tree_payload(bank_build_identities)
        frozen_bindings_identity = _validate_private_identity_payload(bindings_identity, expected_kind="file")
        try:
            bindings_relative = bindings_path.relative_to(bindings_path.parents[1]).as_posix()
        except (IndexError, ValueError):
            raise EnronPerformanceError("Performance auxiliary binding location is invalid.") from None
        if bindings_relative != "auxiliary/cmu-train-catalog-bindings.jsonl" or (
            bank_build_tree.get(bindings_relative) != frozen_bindings_identity
        ):
            raise EnronPerformanceError("Performance auxiliary binding identity is inconsistent.")
    _bounded_private_string(
        locations.get("build_created_at"),
        maximum_bytes=MAX_BUILD_TIMESTAMP_BYTES,
        description="Performance source-build timestamp",
    )
    _require_sha256(locations.get("source_build_projection_sha256"), "Performance source-build projection")


def _load_prepared_performance_run(run_dir: Path) -> _PreparedPerformanceRun:
    try:
        return _load_prepared_performance_run_impl(run_dir)
    except EnronPerformanceError:
        raise
    except (AttributeError, IndexError, KeyError, OverflowError, RecursionError, StopIteration, TypeError, ValueError):
        raise EnronPerformanceError("Performance preparation failed closed structural verification.") from None


def _prepared_artifact_paths(prepared: _PreparedPerformanceRun) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for item in prepared.manifest["artifacts"]:
        result[str(item["id"])] = prepared.root / str(item["relative_path"])
    return result


def _read_prepared_artifact(
    prepared: _PreparedPerformanceRun,
    identifier: str,
    *,
    maximum_bytes: int,
    description: str,
) -> bytes:
    paths = _prepared_artifact_paths(prepared)
    path = paths.get(identifier)
    fingerprint = prepared.artifact_fingerprints.get(identifier)
    if path is None or fingerprint is None:
        raise EnronPerformanceError(f"{description} has no frozen private artifact binding.")
    return _read_fingerprinted_private_bytes(
        path,
        fingerprint,
        maximum_bytes=maximum_bytes,
        description=description,
    )


def _worker_artifact(
    reference: Mapping[str, Any],
    paths: Mapping[str, Path],
    prepared: _PreparedPerformanceRun,
) -> dict[str, Any]:
    identifier = str(reference["id"])
    path = paths.get(identifier)
    fingerprint = prepared.artifact_fingerprints.get(identifier)
    if path is None or fingerprint is None:
        raise EnronPerformanceError("Frozen worker artifact has no private location binding.")
    return {
        "path": os.fspath(path.absolute()),
        "sha256": reference["sha256"],
        "bytes": reference["bytes"],
        "identity": _private_identity_payload(fingerprint.identity),
    }


def _worker_request(
    workload: Mapping[str, Any],
    performance: Mapping[str, Any],
    prepared: _PreparedPerformanceRun,
    *,
    nonce: str,
) -> dict[str, Any]:
    banks = {str(item["id"]): item for item in performance["banks"]}
    inputs = {str(item["id"]): item for item in performance["inputs"]}
    harnesses = {str(item["id"]): item for item in performance["harnesses"]}
    bank = banks[str(workload["bank_id"])]
    input_descriptor = None if workload["input_id"] is None else inputs[str(workload["input_id"])]
    harness = harnesses[str(workload["harness_id"])]
    paths = _prepared_artifact_paths(prepared)
    phase = str(workload["phase"])
    artifacts: dict[str, Any]
    parameters: dict[str, Any]
    if phase == "source_profile":
        source_ref = prepared.plan["source_profile_artifact"]
        artifacts = {
            "source": {
                "path": str(prepared.locations["profile_source"]),
                "sha256": source_ref["sha256"],
                "bytes": source_ref["bytes"],
                "identity": prepared.locations["source_identities"]["profile_source"],
            }
        }
        parameters = {"max_line_bytes": 16 * 1024 * 1024, "max_records": 750_000}
        operation = "source_profile"
    elif phase == "cold_compile":
        artifacts = {"bank": _worker_artifact(bank["artifact"], paths, prepared)}
        parameters = {
            "bank_format": "json_bank_active" if bank["kind"] == "evaluated_bank" else "native_json",
            "cache_mode": "miss",
        }
        operation = "bank_compile"
    elif phase in {"helper_cache_miss", "helper_cache_hit", "end_to_end"}:
        if input_descriptor is None:
            raise EnronPerformanceError("Scan-bearing helper workload is missing its input.")
        artifacts = {
            "bank": _worker_artifact(bank["artifact"], paths, prepared),
            "input": _worker_artifact(input_descriptor["artifact"], paths, prepared),
            "inventory": _worker_artifact(input_descriptor["inventory_ref"], paths, prepared),
        }
        parameters = {
            "cache_mode": "hit" if phase == "helper_cache_hit" else "miss",
            "concurrency": workload["concurrency"],
            "input_mode": "end_to_end" if phase == "end_to_end" else "prepared",
        }
        operation = "json_helper_scan"
    elif phase == "direct_bank_scan":
        if input_descriptor is None:
            raise EnronPerformanceError("Direct scan workload is missing its input.")
        artifacts = {
            "input": _worker_artifact(input_descriptor["artifact"], paths, prepared),
            "inventory": _worker_artifact(input_descriptor["inventory_ref"], paths, prepared),
        }
        if harness["id"] == "generic_regex_harness":
            parameters = {
                "concurrency": workload["concurrency"],
                "max_records": 5_000_000,
                "pattern_set": "email_format_v1",
            }
            operation = "generic_regex_scan"
        elif harness["id"] == "python_literal_harness":
            artifacts["bank"] = _worker_artifact(bank["artifact"], paths, prepared)
            parameters = {"concurrency": workload["concurrency"], "max_records": 5_000_000}
            operation = "python_literal_scan"
        else:
            artifacts["bank"] = _worker_artifact(bank["artifact"], paths, prepared)
            parameters = {
                "bank_format": "json_bank_active" if bank["kind"] == "evaluated_bank" else "native_json",
                "concurrency": workload["concurrency"],
                "sample_unit": workload["sample_unit"],
            }
            operation = "direct_bank_scan"
    else:
        raise EnronPerformanceError("Unsupported worker phase in frozen plan.")
    return {
        "schema_version": REQUEST_SCHEMA_VERSION,
        "nonce": nonce,
        "workload_sha256": workload["workload_sha256"],
        "operation": operation,
        "warmups": workload["warmups"],
        "artifacts": artifacts,
        "parameters": parameters,
    }


def _decode_worker_result(payload: bytes, request: Mapping[str, Any]) -> dict[str, Any]:
    if not payload or len(payload) > MAX_WORKER_OUTPUT_BYTES:
        raise EnronPerformanceError("Performance worker output exceeded its fixed bound.")
    try:
        result = _strict_json_loads(payload)
    except (json.JSONDecodeError, RecursionError, UnicodeDecodeError, ValueError):
        raise EnronPerformanceError("Performance worker emitted invalid aggregate JSON.") from None
    expected_keys = {
        "schema_version",
        "nonce",
        "workload_sha256",
        "pid",
        "status",
        "error_code",
        "elapsed_ns",
        "peak_rss_bytes",
        "peak_rss_status",
        "record_count",
        "correctness_sha256",
    }
    if not isinstance(result, dict) or set(result) != expected_keys:
        raise EnronPerformanceError("Performance worker result shape is invalid.")
    if (
        result.get("schema_version") != RESULT_SCHEMA_VERSION
        or result.get("status") != "ok"
        or result.get("error_code") is not None
        or result.get("nonce") != request["nonce"]
        or result.get("workload_sha256") != request["workload_sha256"]
        or type(result.get("pid")) is not int
        or result["pid"] < 1
        or type(result.get("elapsed_ns")) is not int
        or result["elapsed_ns"] < 1
        or type(result.get("record_count")) is not int
        or result["record_count"] < 0
        or not isinstance(result.get("correctness_sha256"), str)
        or _SHA256_RE.fullmatch(result["correctness_sha256"]) is None
    ):
        raise EnronPerformanceError("Performance worker failed its aggregate correctness protocol.")
    rss = result.get("peak_rss_bytes")
    if rss is not None and (type(rss) is not int or rss < 1):
        raise EnronPerformanceError("Performance worker returned an invalid RSS observation.")
    rss_status = result.get("peak_rss_status")
    if rss_status not in {
        "supported",
        "unsupported_platform",
        "invalid_value",
        "resource_unavailable",
    }:
        raise EnronPerformanceError("Performance worker returned an invalid RSS support status.")
    if (rss_status == "supported") != (rss is not None):
        raise EnronPerformanceError("Performance worker returned an inconsistent RSS support observation.")
    return result


def _kill_and_reap(process: subprocess.Popen[bytes]) -> None:
    """Best-effort immediate cleanup for a failed bounded child protocol."""

    try:
        if process.poll() is None:
            process.kill()
    except OSError:
        pass
    try:
        process.wait(timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            pass


def _run_bounded_fresh_process(
    command: Sequence[str],
    request: Mapping[str, Any],
    *,
    timeout_seconds: float,
    boundary_error: str,
    exit_error: str,
) -> tuple[bytes, int]:
    """Run one child request without ever buffering unbounded child output."""

    payload = _canonical_json_bytes(request)
    if not payload or len(payload) > DEFAULT_MAX_REQUEST_BYTES:
        raise EnronPerformanceError("Performance worker request exceeded its fixed bound.")

    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        if process.stdin is None or process.stdout is None:
            raise OSError

        os.set_blocking(process.stdin.fileno(), False)
        os.set_blocking(process.stdout.fileno(), False)
        selector = selectors.DefaultSelector()
        selector.register(process.stdin, selectors.EVENT_WRITE)
        selector.register(process.stdout, selectors.EVENT_READ)

        deadline = time.monotonic() + timeout_seconds
        input_offset = 0
        output = bytearray()
        stdout_eof = False
        while not stdout_eof:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, timeout_seconds)
            ready = selector.select(remaining)
            if not ready:
                raise subprocess.TimeoutExpired(command, timeout_seconds)
            for key, _events in ready:
                if key.fileobj is process.stdin:
                    try:
                        written = os.write(process.stdin.fileno(), payload[input_offset:])
                    except BlockingIOError:
                        continue
                    if written < 1:
                        raise OSError
                    input_offset += written
                    if input_offset == len(payload):
                        selector.unregister(process.stdin)
                        process.stdin.close()
                elif key.fileobj is process.stdout:
                    try:
                        chunk = os.read(
                            process.stdout.fileno(),
                            min(8192, MAX_WORKER_OUTPUT_BYTES + 1 - len(output)),
                        )
                    except BlockingIOError:
                        continue
                    if not chunk:
                        stdout_eof = True
                        break
                    output.extend(chunk)
                    if len(output) > MAX_WORKER_OUTPUT_BYTES:
                        raise EnronPerformanceError("Performance worker output exceeded its fixed bound.")

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(command, timeout_seconds)
        returncode = process.wait(timeout=remaining)
        if returncode != 0:
            raise EnronPerformanceError(exit_error)
        return bytes(output), process.pid
    except EnronPerformanceError:
        if process is not None:
            _kill_and_reap(process)
        raise
    except (OSError, OverflowError, ValueError, subprocess.SubprocessError):
        if process is not None:
            _kill_and_reap(process)
        raise EnronPerformanceError(boundary_error) from None
    finally:
        if selector is not None:
            selector.close()
        if process is not None:
            for pipe in (process.stdin, process.stdout):
                if pipe is not None and not pipe.closed:
                    try:
                        pipe.close()
                    except OSError:
                        pass


def _run_worker_once(request: Mapping[str, Any], *, timeout_seconds: float) -> dict[str, Any]:
    payload, child_pid = _run_bounded_fresh_process(
        [sys.executable, "-m", "nerb.enron_performance_worker"],
        request,
        timeout_seconds=timeout_seconds,
        boundary_error="Performance worker did not complete within its fixed boundary.",
        exit_error="Performance worker exited unsuccessfully.",
    )
    result = _decode_worker_result(payload, request)
    if result["pid"] != child_pid:
        raise EnronPerformanceError("Performance worker failed its process identity protocol.")
    return result


class _WorkerSession:
    def __init__(self, *, timeout_seconds: float) -> None:
        self.timeout_seconds = timeout_seconds
        self._closed = False
        try:
            self.process = subprocess.Popen(
                [sys.executable, "-m", "nerb.enron_performance_worker", "--json-lines"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
        except OSError:
            raise EnronPerformanceError("Reusable performance worker could not be started.") from None
        if self.process.stdin is None or self.process.stdout is None:
            self._abort()
            raise EnronPerformanceError("Reusable performance worker pipes are unavailable.")
        try:
            os.set_blocking(self.process.stdin.fileno(), False)
            os.set_blocking(self.process.stdout.fileno(), False)
        except OSError:
            self._abort()
            raise EnronPerformanceError("Reusable performance worker pipes are unavailable.") from None

    def request(self, request: Mapping[str, Any]) -> dict[str, Any]:
        selector: selectors.BaseSelector | None = None
        try:
            if self._closed or self.process.poll() is not None:
                raise EnronPerformanceError("Reusable performance worker is not running.")
            assert self.process.stdin is not None
            assert self.process.stdout is not None
            payload = _canonical_json_bytes(request) + b"\n"
            if len(payload) > DEFAULT_MAX_REQUEST_BYTES:
                raise EnronPerformanceError("Reusable performance worker request exceeded its fixed bound.")

            selector = selectors.DefaultSelector()
            selector.register(self.process.stdin, selectors.EVENT_WRITE)
            selector.register(self.process.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + self.timeout_seconds
            input_offset = 0
            output = bytearray()
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise EnronPerformanceError("Reusable performance worker timed out.")
                ready = selector.select(remaining)
                if not ready:
                    raise EnronPerformanceError("Reusable performance worker timed out.")
                for key, _events in ready:
                    if key.fileobj is self.process.stdin:
                        try:
                            written = os.write(self.process.stdin.fileno(), payload[input_offset:])
                        except BlockingIOError:
                            continue
                        if written < 1:
                            raise OSError
                        input_offset += written
                        if input_offset == len(payload):
                            selector.unregister(self.process.stdin)
                    elif key.fileobj is self.process.stdout:
                        try:
                            chunk = os.read(
                                self.process.stdout.fileno(),
                                min(8192, MAX_WORKER_OUTPUT_BYTES + 1 - len(output)),
                            )
                        except BlockingIOError:
                            continue
                        if not chunk:
                            raise EnronPerformanceError("Reusable performance worker pipe closed unexpectedly.")
                        output.extend(chunk)
                        if len(output) > MAX_WORKER_OUTPUT_BYTES:
                            raise EnronPerformanceError("Performance worker output exceeded its fixed bound.")
                        newline = output.find(b"\n")
                        if newline >= 0:
                            if newline != len(output) - 1:
                                raise EnronPerformanceError("Reusable performance worker emitted invalid framing.")
                            result = _decode_worker_result(bytes(output), request)
                            if result["pid"] != self.process.pid:
                                raise EnronPerformanceError(
                                    "Reusable performance worker failed its process identity protocol."
                                )
                            return result
        except EnronPerformanceError:
            self._abort()
            raise
        except (OSError, OverflowError, ValueError, subprocess.SubprocessError):
            self._abort()
            raise EnronPerformanceError("Reusable performance worker pipe failed.") from None
        finally:
            if selector is not None:
                selector.close()

    def _close_pipes(self) -> None:
        for pipe in (self.process.stdin, self.process.stdout):
            if pipe is not None and not pipe.closed:
                try:
                    pipe.close()
                except OSError:
                    pass

    def _abort(self) -> None:
        if self._closed:
            return
        self._closed = True
        _kill_and_reap(self.process)
        self._close_pipes()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self.process.stdin is not None:
            try:
                self.process.stdin.close()
            except OSError:
                pass
        try:
            self.process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            try:
                self.process.terminate()
            except OSError:
                pass
            try:
                self.process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                _kill_and_reap(self.process)
        self._close_pipes()

    def __enter__(self) -> _WorkerSession:
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()


def _source_build_request(
    workload: Mapping[str, Any], prepared: _PreparedPerformanceRun, *, nonce: str
) -> dict[str, Any]:
    return _source_build_request_from_bindings(
        workload,
        prepared.plan,
        prepared.locations,
        nonce=nonce,
    )


def _source_build_request_from_bindings(
    workload: Mapping[str, Any],
    plan: Mapping[str, Any],
    locations: Mapping[str, Any],
    *,
    nonce: str,
) -> dict[str, Any]:
    return {
        "schema_version": "nerb.enron_performance_source_build_request.v1",
        "nonce": nonce,
        "workload_sha256": workload["workload_sha256"],
        "development_run": locations["development_run"],
        "annotation_run": locations["annotation_run"],
        "cmu_catalog_bindings": locations["cmu_catalog_bindings"],
        "source_identities": locations["source_identities"],
        "benchmark_version": plan["benchmark_version"],
        "created_at": locations["build_created_at"],
        "expected_projection_sha256": locations["source_build_projection_sha256"],
    }


def _reserved_source_build_output_path() -> str:
    suffix = "/build"
    return "/" + "\\" * (MAX_PRIVATE_PATH_BYTES - len(suffix) - 1) + suffix


def _validate_source_build_request_budget(plan: Mapping[str, Any], locations: Mapping[str, Any]) -> None:
    profiles = plan.get("profiles")
    if not isinstance(profiles, Mapping):
        raise EnronPerformanceError("Performance source-build request plan is invalid.")
    workloads: list[Mapping[str, Any]] = []
    for profile in PERFORMANCE_PROFILE_IDS:
        profile_value = profiles.get(profile)
        performance = profile_value.get("performance") if isinstance(profile_value, Mapping) else None
        raw_workloads = performance.get("workloads") if isinstance(performance, Mapping) else None
        if not isinstance(raw_workloads, list):
            raise EnronPerformanceError("Performance source-build request plan is invalid.")
        workloads.extend(
            workload
            for workload in raw_workloads
            if isinstance(workload, Mapping) and workload.get("phase") == "source_build"
        )
    if not workloads:
        raise EnronPerformanceError("Performance source-build request plan has no source-build workload.")
    for workload in workloads:
        request = {
            **_source_build_request_from_bindings(
                workload,
                plan,
                locations,
                nonce="N" * 128,
            ),
            "output_dir": _reserved_source_build_output_path(),
        }
        if len(_canonical_json_bytes(request)) > DEFAULT_MAX_REQUEST_BYTES:
            raise EnronPerformanceError("Performance source-build request exceeds its complete worker budget.")


def _run_source_build_once(request: Mapping[str, Any], *, timeout_seconds: float) -> dict[str, Any]:
    try:
        system_temporary_root = Path(tempfile.gettempdir()).resolve()
        with tempfile.TemporaryDirectory(dir=system_temporary_root, prefix="nerb-performance-build-") as temporary:
            temporary_root = Path(temporary)
            child_request = {**request, "output_dir": os.fspath(temporary_root / "build")}
            payload, child_pid = _run_bounded_fresh_process(
                [sys.executable, "-m", "nerb.enron_performance", "--source-build-worker"],
                child_request,
                timeout_seconds=timeout_seconds,
                boundary_error="Source-build performance worker exceeded its fixed boundary.",
                exit_error="Source-build performance worker exited unsuccessfully.",
            )
            result = _decode_worker_result(payload, child_request)
            if result["pid"] != child_pid:
                raise EnronPerformanceError("Source-build performance worker failed its process identity protocol.")
            return result
    except EnronPerformanceError:
        raise
    except OSError:
        raise EnronPerformanceError("Source-build performance worker temporary storage failed safely.") from None


def _run_one_observation(
    workload: Mapping[str, Any],
    performance: Mapping[str, Any],
    prepared: _PreparedPerformanceRun,
    *,
    sequence: int,
    worker_timeout_seconds: float,
    source_build_timeout_seconds: float,
    session: _WorkerSession | None = None,
) -> dict[str, Any]:
    nonce = f"sample-{sequence}-{secrets.token_hex(8)}"
    if workload["phase"] == "source_build":
        result = _run_source_build_once(
            _source_build_request(workload, prepared, nonce=nonce),
            timeout_seconds=source_build_timeout_seconds,
        )
    else:
        request = _worker_request(workload, performance, prepared, nonce=nonce)
        result = (
            session.request(request)
            if session is not None
            else _run_worker_once(request, timeout_seconds=worker_timeout_seconds)
        )
    return {**result, "sequence": sequence}


def _interleaved_labels(sample_count: int) -> tuple[str, ...]:
    counts = {"candidate": 0, "control": 0}
    result: list[str] = []
    while counts["candidate"] < sample_count or counts["control"] < sample_count:
        for label in ("candidate", "control", "control", "candidate"):
            if counts[label] < sample_count:
                result.append(label)
                counts[label] += 1
    return tuple(result)


def _exact_value_schedule(sample_count: int) -> tuple[str, ...]:
    """Return a Williams-balanced path order inside the exact-control ABBA schedule."""

    if type(sample_count) is not int or sample_count < 4 or sample_count % 4:
        raise EnronPerformanceError("Exact cache-value samples require a positive multiple-of-four block size.")
    schedule: list[str] = []
    for round_index, label in enumerate(_interleaved_labels(sample_count)):
        row = _EXACT_VALUE_WILLIAMS_ROWS[_EXACT_VALUE_ROW_PATTERN[round_index % 8]]
        for path_index in row:
            identifier = PERFORMANCE_EXACT_VALUE_PATHS[path_index]
            schedule.append(identifier if label == "candidate" else f"control_{identifier}")
    return tuple(schedule)


def _execute_exact_value_block(
    workloads: Mapping[str, Mapping[str, Any]],
    performance: Mapping[str, Any],
    prepared: _PreparedPerformanceRun,
    *,
    sample_count: int,
    worker_timeout_seconds: float,
    source_build_timeout_seconds: float,
    sequence_start: int,
) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Measure exact cache paths in temporally balanced, paired blocks."""

    schedule = _exact_value_schedule(sample_count)
    required_ids = {identifier for path in PERFORMANCE_EXACT_VALUE_PATHS for identifier in (path, f"control_{path}")}
    if not required_ids <= set(workloads):
        raise EnronPerformanceError("Decision cache-value block is missing a frozen workload.")
    results: dict[str, list[dict[str, Any]]] = {identifier: [] for identifier in required_ids}
    sessions: dict[str, _WorkerSession] = {}
    sequence = sequence_start
    try:
        for identifier in sorted(required_ids):
            if workloads[identifier]["process_model"] == "reused_process":
                sessions[identifier] = _WorkerSession(timeout_seconds=worker_timeout_seconds)
        for identifier in schedule:
            workload = workloads[identifier]
            observation = _run_one_observation(
                workload,
                performance,
                prepared,
                sequence=sequence,
                worker_timeout_seconds=worker_timeout_seconds,
                source_build_timeout_seconds=source_build_timeout_seconds,
                session=sessions.get(identifier),
            )
            results[identifier].append({**observation, "sequence": sequence})
            sequence += 1
    finally:
        for session in sessions.values():
            session.close()

    reference: list[tuple[int, str]] | None = None
    for path in PERFORMANCE_EXACT_VALUE_PATHS:
        candidate_results = results[path]
        control_results = results[f"control_{path}"]
        candidate_correctness = [(item["record_count"], item["correctness_sha256"]) for item in candidate_results]
        control_correctness = [(item["record_count"], item["correctness_sha256"]) for item in control_results]
        if len(set(candidate_correctness)) != 1 or len(set(control_correctness)) != 1:
            raise EnronPerformanceError("Exact cache-value correctness changed across repeated samples.")
        if candidate_correctness != control_correctness:
            raise EnronPerformanceError("Exact cache-value control differs from its candidate correctness sequence.")
        if reference is None:
            reference = candidate_correctness
        elif candidate_correctness != reference:
            raise EnronPerformanceError("Semantically exact cache-value paths produced different scan results.")
    return results, sequence


def _execute_workload(
    workload: Mapping[str, Any],
    performance: Mapping[str, Any],
    prepared: _PreparedPerformanceRun,
    *,
    sample_count: int,
    worker_timeout_seconds: float,
    source_build_timeout_seconds: float,
    sequence_start: int,
) -> tuple[list[dict[str, Any]], int]:
    observations: list[dict[str, Any]] = []
    sequence = sequence_start
    if workload["process_model"] == "reused_process":
        with _WorkerSession(timeout_seconds=worker_timeout_seconds) as session:
            for _ in range(sample_count):
                observation = _run_one_observation(
                    workload,
                    performance,
                    prepared,
                    sequence=sequence,
                    worker_timeout_seconds=worker_timeout_seconds,
                    source_build_timeout_seconds=source_build_timeout_seconds,
                    session=session,
                )
                observations.append({**observation, "sequence": sequence})
                sequence += 1
    else:
        for _ in range(sample_count):
            observation = _run_one_observation(
                workload,
                performance,
                prepared,
                sequence=sequence,
                worker_timeout_seconds=worker_timeout_seconds,
                source_build_timeout_seconds=source_build_timeout_seconds,
            )
            observations.append({**observation, "sequence": sequence})
            sequence += 1
    if (
        workload["sample_unit"] != "document"
        and len({(item["record_count"], item["correctness_sha256"]) for item in observations}) != 1
    ):
        raise EnronPerformanceError("Performance workload correctness changed across repeated samples.")
    return observations, sequence


def _execute_pair(
    candidate: Mapping[str, Any],
    control: Mapping[str, Any],
    performance: Mapping[str, Any],
    prepared: _PreparedPerformanceRun,
    *,
    sample_count: int,
    worker_timeout_seconds: float,
    source_build_timeout_seconds: float,
    sequence_start: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    results: dict[str, list[dict[str, Any]]] = {"candidate": [], "control": []}
    sequence = sequence_start
    reused = candidate["process_model"] == "reused_process"
    candidate_session = _WorkerSession(timeout_seconds=worker_timeout_seconds) if reused else None
    control_session = _WorkerSession(timeout_seconds=worker_timeout_seconds) if reused else None
    try:
        for label in _interleaved_labels(sample_count):
            workload = candidate if label == "candidate" else control
            session = candidate_session if label == "candidate" else control_session
            observation = _run_one_observation(
                workload,
                performance,
                prepared,
                sequence=sequence,
                worker_timeout_seconds=worker_timeout_seconds,
                source_build_timeout_seconds=source_build_timeout_seconds,
                session=session,
            )
            results[label].append({**observation, "sequence": sequence})
            sequence += 1
    finally:
        if candidate_session is not None:
            candidate_session.close()
        if control_session is not None:
            control_session.close()
    candidate_results = results["candidate"]
    control_results = results["control"]
    if (
        candidate["sample_unit"] != "document"
        and len({(item["record_count"], item["correctness_sha256"]) for item in candidate_results}) != 1
    ):
        raise EnronPerformanceError("Performance candidate correctness changed across repeated samples.")
    if (
        control["sample_unit"] != "document"
        and len({(item["record_count"], item["correctness_sha256"]) for item in control_results}) != 1
    ):
        raise EnronPerformanceError("Performance control correctness changed across repeated samples.")
    if [(item["record_count"], item["correctness_sha256"]) for item in candidate_results] != [
        (item["record_count"], item["correctness_sha256"]) for item in control_results
    ]:
        raise EnronPerformanceError("Exact performance control differs from its candidate correctness sequence.")
    return candidate_results, control_results, sequence


def _materialize_workload(
    plan: Mapping[str, Any],
    observations: Sequence[Mapping[str, Any]],
    input_by_id: Mapping[str, Mapping[str, Any]],
    *,
    require_rss: bool,
) -> dict[str, Any]:
    samples = [int(item["elapsed_ns"]) / 1_000_000_000 for item in observations]
    record_counts = [int(item["record_count"]) for item in observations]
    rss_samples = [item["peak_rss_bytes"] for item in observations if item["peak_rss_bytes"] is not None]
    if require_rss and len(rss_samples) != len(samples):
        raise EnronPerformanceError("Decision-grade workload lacks a supported RSS sample.")
    input_descriptor = None if plan["input_id"] is None else input_by_id[str(plan["input_id"])]
    records_per_sample = (
        record_counts[0] if plan["sample_unit"] == "whole_input" and len(set(record_counts)) == 1 else None
    )
    stats = calculate_enron_performance_statistics(
        samples,
        input_descriptor,
        phase=str(plan["phase"]),
        sample_unit=str(plan["sample_unit"]),
        work_per_sample=int(plan["work_per_sample"]),
        records_per_sample=records_per_sample,
    )
    return {
        **plan,
        "samples_seconds": samples,
        "samples_ref": None,
        "stats": stats,
        "records_per_sample": records_per_sample,
        "rss_samples_bytes": rss_samples if len(rss_samples) == len(samples) else [],
        "peak_rss_bytes": max(rss_samples) if len(rss_samples) == len(samples) else None,
    }


def _materialize_comparison(plan: Mapping[str, Any], workloads: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    candidate = workloads[str(plan["candidate_workload_id"])]
    baseline = workloads[str(plan["baseline_workload_id"])]
    paired = plan["noise_method"] in {"paired_relative_mad", "paired_block_ratio_mad"}
    outputs = calculate_enron_performance_comparison(
        candidate["stats"],
        baseline["stats"],
        metric=str(plan["metric"]),
        noise_multiplier=float(plan["noise_multiplier"]),
        regression_tolerance=float(plan["regression_tolerance"]),
        noise_method=str(plan["noise_method"]),
        candidate_samples=candidate["samples_seconds"] if paired else None,
        baseline_samples=baseline["samples_seconds"] if paired else None,
    )
    return {**plan, **outputs}


def _materialize_breakeven(plan: Mapping[str, Any], workloads: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    components: list[dict[str, Any]] = []
    for item in plan["components"]:
        component = dict(item)
        if component["source"] == "declared_assumption":
            value = float(component["value"])
        else:
            workload = workloads[str(component["workload_id"])]
            stats = workload["stats"]
            if component["source"] == "workload_median_seconds":
                value = float(stats["median_seconds"])
            elif component["source"] == "workload_seconds_per_document":
                value = float(stats["seconds_per_document"])
            elif component["source"] == "workload_seconds_per_request":
                value = float(stats["median_seconds"]) / int(workload["work_per_sample"])
            else:
                raise EnronPerformanceError("Unsupported measured breakeven component source.")
        component["value"] = value
        components.append(component)
    totals = {
        (side, application): sum(
            float(item["value"]) for item in components if item["side"] == side and item["application"] == application
        )
        for side in ("candidate", "baseline")
        for application in ("fixed", "per_unit")
    }
    outputs = calculate_enron_breakeven(
        totals[("candidate", "fixed")],
        totals[("baseline", "fixed")],
        totals[("candidate", "per_unit")],
        totals[("baseline", "per_unit")],
        minimum_units=int(plan["minimum_units"]),
        maximum_units=int(plan["maximum_units"]),
    )
    return {
        **plan,
        "components": components,
        "candidate_fixed_value": totals[("candidate", "fixed")],
        "baseline_fixed_value": totals[("baseline", "fixed")],
        "candidate_value_per_unit": totals[("candidate", "per_unit")],
        "baseline_value_per_unit": totals[("baseline", "per_unit")],
        **outputs,
    }


def _decision_grade_summary(
    performance: Mapping[str, Any],
    thresholds: Mapping[str, Any],
    environment: Mapping[str, Any],
) -> dict[str, Any]:
    workloads = {str(item["id"]): item for item in performance["workloads"]}
    comparisons = performance["comparisons"]
    decision_cells = [item for item in workloads.values() if item["decision_grade"]]
    input_by_id = {str(item["id"]): item for item in performance["inputs"]}
    failures: list[str] = []
    if len(decision_cells) != 19:
        failures.append("decision_cell_count")
    if any(item["peak_rss_bytes"] is None for item in decision_cells):
        failures.append("rss_support")
    if any(item["concurrency"] > int(environment["cpu_count"]) for item in decision_cells):
        failures.append("execution_cpu_capacity")
    if any(
        item["peak_rss_bytes"] is not None and item["peak_rss_bytes"] > int(environment["memory_bytes"])
        for item in decision_cells
    ):
        failures.append("execution_memory_capacity")
    if any(
        item["result"] == "regressed" or item["noise_floor"] > float(thresholds["max_exact_control_noise_floor"])
        for item in comparisons
    ):
        failures.append("comparison_regression_or_noise")
    for item in decision_cells:
        if item["peak_rss_bytes"] is not None and item["peak_rss_bytes"] > int(thresholds["max_peak_rss_bytes"]):
            failures.append(f"{item['id']}:rss")
        if item["phase"] != "direct_bank_scan" or item["baseline_id"] is not None:
            continue
        if item["sample_unit"] == "document" and item["stats"]["p99_seconds"] > float(
            thresholds["max_document_p99_seconds"]
        ):
            failures.append(f"{item['id']}:latency")
        elif item["sample_unit"] == "whole_input":
            input_descriptor = input_by_id[str(item["input_id"])]
            tail_bound = min(
                input_descriptor["documents"] / float(thresholds["min_documents_per_second"]),
                (input_descriptor["bytes"] / (1024 * 1024)) / float(thresholds["min_mib_per_second"]),
            )
            if (
                item["stats"]["documents_per_second"] < float(thresholds["min_documents_per_second"])
                or item["stats"]["mib_per_second"] < float(thresholds["min_mib_per_second"])
                or item["stats"]["p99_seconds"] > tail_bound
            ):
                failures.append(f"{item['id']}:throughput")
    models = performance["breakeven_models"]
    if len(models) != 1 or models[0]["result"] not in {"candidate_already_better", "finite_breakeven"}:
        failures.append("finite_breakeven")
    return {"passed": not failures, "failure_codes": sorted(set(failures))}


def _run_enron_performance_impl(options: EnronPerformanceRunOptions) -> dict[str, Any]:
    """Execute a frozen plan and commit aggregate timing/resource evidence."""

    if not isinstance(options, EnronPerformanceRunOptions):
        raise EnronPerformanceError("Performance run options are invalid.")
    profile = _validate_profile(options.profile)
    if (
        options.warmups != DEFAULT_WARMUPS
        or options.smoke_samples != DEFAULT_SMOKE_SAMPLES
        or options.setup_samples != DEFAULT_SETUP_SAMPLES
        or options.scan_samples != DEFAULT_SCAN_SAMPLES
        or options.document_samples != DEFAULT_DOCUMENT_SAMPLES
    ):
        raise EnronPerformanceError("Performance sample policy must match the frozen manifest defaults.")
    worker_timeout = _positive_finite(options.worker_timeout_seconds, "Worker timeout", maximum=3_600)
    source_build_timeout = _positive_finite(
        options.source_build_timeout_seconds,
        "Source-build timeout",
        maximum=MAX_SOURCE_BUILD_SECONDS,
    )
    prepared = _load_prepared_performance_run(options.prepared_run)
    profile_plan = prepared.plan["profiles"][profile]
    performance_plan = profile_plan["performance"]
    workload_plans = {str(item["id"]): item for item in performance_plan["workloads"]}
    current_source_sha256 = _performance_harness_source_sha256()
    if any(item["source_sha256"] != current_source_sha256 for item in performance_plan["harnesses"]) or any(
        item["source_sha256"] != current_source_sha256 for item in performance_plan["baselines"]
    ):
        raise EnronPerformanceError("Frozen performance harness source differs from the current implementation.")
    starting_software = _software()
    environment = _environment()
    if any(int(item["concurrency"]) > int(environment["cpu_count"]) for item in workload_plans.values()):
        raise EnronPerformanceError("Performance workload concurrency exceeds the current CPU count.")
    observations: dict[str, list[dict[str, Any]]] = {}
    sequence = 0
    if profile == "decision":
        exact_value_ids = set(PERFORMANCE_EXACT_VALUE_PATHS)
        candidates = sorted(
            (
                item
                for item in workload_plans.values()
                if item["decision_grade"] and str(item["id"]) not in exact_value_ids
            ),
            key=lambda item: str(item["id"]),
        )
        for candidate in candidates:
            control = workload_plans.get(f"control_{candidate['id']}")
            if control is None:
                raise EnronPerformanceError("Decision candidate lacks its exact control twin.")
            sample_count = (
                DEFAULT_SETUP_SAMPLES
                if candidate["phase"] in {"source_profile", "source_build", "cold_compile"}
                else DEFAULT_DOCUMENT_SAMPLES
                if candidate["sample_unit"] == "document"
                else DEFAULT_SCAN_SAMPLES
            )
            candidate_results, control_results, sequence = _execute_pair(
                candidate,
                control,
                performance_plan,
                prepared,
                sample_count=sample_count,
                worker_timeout_seconds=worker_timeout,
                source_build_timeout_seconds=source_build_timeout,
                sequence_start=sequence,
            )
            observations[str(candidate["id"])] = candidate_results
            observations[str(control["id"])] = control_results
        value_results, sequence = _execute_exact_value_block(
            workload_plans,
            performance_plan,
            prepared,
            sample_count=DEFAULT_SCAN_SAMPLES,
            worker_timeout_seconds=worker_timeout,
            source_build_timeout_seconds=source_build_timeout,
            sequence_start=sequence,
        )
        observations.update(value_results)
        remaining = [item for item in workload_plans.values() if str(item["id"]) not in observations]
        for workload in sorted(remaining, key=lambda item: str(item["id"])):
            results, sequence = _execute_workload(
                workload,
                performance_plan,
                prepared,
                sample_count=DEFAULT_SCAN_SAMPLES,
                worker_timeout_seconds=worker_timeout,
                source_build_timeout_seconds=source_build_timeout,
                sequence_start=sequence,
            )
            observations[str(workload["id"])] = results
    else:
        for workload in sorted(workload_plans.values(), key=lambda item: str(item["id"])):
            results, sequence = _execute_workload(
                workload,
                performance_plan,
                prepared,
                sample_count=DEFAULT_SMOKE_SAMPLES,
                worker_timeout_seconds=worker_timeout,
                source_build_timeout_seconds=source_build_timeout,
                sequence_start=sequence,
            )
            observations[str(workload["id"])] = results

    if all(identifier in observations for identifier in PERFORMANCE_EXACT_VALUE_PATHS):
        reference = [
            (item["record_count"], item["correctness_sha256"]) for item in observations["real_direct_throughput"]
        ]
        for identifier in PERFORMANCE_EXACT_VALUE_PATHS[1:]:
            observed = [(item["record_count"], item["correctness_sha256"]) for item in observations[identifier]]
            if observed != reference:
                raise EnronPerformanceError("Semantically exact cache-value paths produced different scan results.")

    input_by_id = {str(item["id"]): item for item in performance_plan["inputs"]}
    materialized_workloads = [
        _materialize_workload(
            workload_plans[identifier],
            results,
            input_by_id,
            require_rss=profile == "decision" and workload_plans[identifier]["decision_grade"],
        )
        for identifier, results in sorted(observations.items())
    ]
    materialized_by_id = {str(item["id"]): item for item in materialized_workloads}
    comparisons = [_materialize_comparison(item, materialized_by_id) for item in performance_plan["comparisons"]]
    breakeven_models = [
        _materialize_breakeven(item, materialized_by_id) for item in performance_plan["breakeven_models"]
    ]
    performance = {
        "evaluated": True,
        "banks": performance_plan["banks"],
        "inputs": performance_plan["inputs"],
        "harnesses": performance_plan["harnesses"],
        "workloads": materialized_workloads,
        "baselines": performance_plan["baselines"],
        "comparisons": comparisons,
        "breakeven_models": breakeven_models,
    }
    schema_result = validate_enron_performance_output(performance)
    if schema_result["valid"] is not True:
        raise EnronPerformanceError("Materialized performance output failed its closed schema.")
    manifest_hash = hash_enron_performance_manifest(performance)
    if manifest_hash != profile_plan["performance_manifest_sha256"]:
        raise EnronPerformanceError("Materialized performance output changed its frozen plan hash.")
    decision_summary: dict[str, Any] = (
        _decision_grade_summary(performance, prepared.plan["decision_thresholds"], environment)
        if profile == "decision"
        else {"passed": False, "failure_codes": ["smoke_profile_nonpromotable"]}
    )
    _assert_performance_private_tree_current(
        prepared.root,
        prepared.tree,
        description="Performance preparation run",
    )
    ending_source_sha256 = _performance_harness_source_sha256()
    software = _software()
    if ending_source_sha256 != current_source_sha256 or software != starting_software:
        raise EnronPerformanceError("Performance implementation changed during the measurement run.")
    if profile == "decision" and software["git_dirty"] is True:
        failure_codes = decision_summary.get("failure_codes")
        if not isinstance(failure_codes, list) or any(not isinstance(item, str) for item in failure_codes):
            raise EnronPerformanceError("Decision-grade summary failure codes are invalid.")
        decision_summary = {
            "passed": False,
            "failure_codes": sorted({*failure_codes, "dirty_git_worktree"}),
        }
    audit_rows = [
        {
            "workload_id": identifier,
            "samples": [
                {
                    "sequence": item["sequence"],
                    "pid": item["pid"],
                    "record_count": item["record_count"],
                    "correctness_sha256": item["correctness_sha256"],
                    "elapsed_ns": item["elapsed_ns"],
                    "peak_rss_bytes": item["peak_rss_bytes"],
                }
                for item in results
            ],
        }
        for identifier, results in sorted(observations.items())
    ]
    report: dict[str, Any] = {
        "schema_version": PERFORMANCE_RUN_SCHEMA_VERSION,
        "suite": PERFORMANCE_SUITE_ID,
        "benchmark_version": prepared.plan["benchmark_version"],
        "profile": profile,
        "plan_sha256": prepared.plan["plan_sha256"],
        "performance_manifest_sha256": manifest_hash,
        "performance": performance,
        "environment": environment,
        "software": software,
        "decision_grade": decision_summary,
        "sealed_test_accessed": False,
        "privacy": {
            "status": "pending",
            "raw_text_included": False,
            "direct_identifiers_included": False,
            "private_paths_included": False,
            "violation_count": 0,
        },
        "run_sha256": "",
    }
    privacy_diagnostics = _public_serialization_diagnostics(report)
    report["privacy"] = {
        "status": "passed" if not privacy_diagnostics else "failed",
        "raw_text_included": False,
        "direct_identifiers_included": bool(privacy_diagnostics),
        "private_paths_included": any(item["code"] == "contract.public_private_path" for item in privacy_diagnostics),
        "violation_count": len(privacy_diagnostics),
    }
    if privacy_diagnostics:
        raise EnronPerformanceError("Aggregate performance report failed its privacy scan.")
    report["run_sha256"] = _canonical_hash({key: value for key, value in report.items() if key != "run_sha256"})
    report_payload = _pretty_json_bytes(report)
    audit_payload = b"".join(_canonical_json_bytes(item) + b"\n" for item in audit_rows)
    plan_payload = _pretty_json_bytes(prepared.plan)
    prepared_paths = _prepared_artifact_paths(prepared)
    inventory_payloads: dict[str, bytes] = {}
    for input_descriptor in performance["inputs"]:
        inventory_ref = input_descriptor["inventory_ref"]
        inventory_id = str(inventory_ref["id"])
        if inventory_id in inventory_payloads:
            continue
        inventory_path = prepared_paths.get(inventory_id)
        if inventory_path is None:
            raise EnronPerformanceError("Prepared performance inventory location is unavailable.")
        inventory_payloads[inventory_id] = _read_prepared_artifact(
            prepared,
            inventory_id,
            maximum_bytes=int(inventory_ref["bytes"]),
            description="Performance inventory",
        )
    run_artifacts = [
        (
            _artifact_from_bytes("performance_report", "report.json", report_payload),
            report_payload,
            "aggregate_report",
        ),
        (
            _artifact_from_bytes("performance_audit", "audit/results.jsonl", audit_payload),
            audit_payload,
            "private_correctness_audit",
        ),
        (
            _artifact_from_bytes("performance_plan", "plan.json", plan_payload),
            plan_payload,
            "public_plan",
        ),
    ]
    for inventory_id, payload in sorted(inventory_payloads.items()):
        run_artifacts.append(
            (
                _artifact_from_bytes(inventory_id, f"inventories/{inventory_id}.json", payload),
                payload,
                "inventory",
            )
        )
    private_manifest = {
        "schema_version": PERFORMANCE_RUN_PRIVATE_MANIFEST_SCHEMA_VERSION,
        "suite": PERFORMANCE_SUITE_ID,
        "benchmark_version": prepared.plan["benchmark_version"],
        "plan_sha256": prepared.plan["plan_sha256"],
        "run_sha256": report["run_sha256"],
        "artifacts": [
            {
                **artifact.ref(),
                "relative_path": artifact.relative_path,
                "kind": kind,
            }
            for artifact, _payload, kind in sorted(run_artifacts, key=lambda item: item[0].relative_path)
        ],
    }
    _assert_performance_private_tree_current(
        prepared.root,
        prepared.tree,
        description="Performance preparation run",
    )
    try:
        with PrivateRun(options.output_dir, allow_unignored_output=options.allow_unignored_output) as run:
            for artifact, payload, _kind in sorted(run_artifacts, key=lambda item: item[0].relative_path):
                _write_artifact(run, artifact, payload)
            with run.open_binary("manifest.json") as file:
                file.write(_pretty_json_bytes(private_manifest))
            run.commit()
    except EnronPrivateIOError:
        raise EnronPerformanceError("Performance run failed safely.") from None
    return report


def run_enron_performance(options: EnronPerformanceRunOptions) -> dict[str, Any]:
    """Execute a frozen performance plan and sanitize malformed-plan failures."""

    try:
        return _run_enron_performance_impl(options)
    except EnronPerformanceError:
        raise
    except (AttributeError, IndexError, KeyError, OverflowError, RecursionError, StopIteration, TypeError, ValueError):
        raise EnronPerformanceError("Performance run failed closed structural verification.") from None


def _open_frozen_private_input(path: Path, expected_identity: Mapping[str, Any], *, description: str) -> Any:
    frozen = _validate_private_identity_payload(expected_identity, expected_kind="file")
    handle = None
    try:
        handle = open_private_binary_input(path)
        observed_identity = _bank_workflow._private_entry_identity(os.fstat(handle.fileno()), kind="file")
        _bank_workflow._require_private_entry(observed_identity)
        observed = _private_identity_payload(observed_identity)
    except (EnronBankBuildError, EnronPrivateIOError, OSError):
        if handle is not None:
            handle.close()
        raise EnronPerformanceError(f"{description} could not be opened from its frozen private inode.") from None
    if observed != frozen:
        handle.close()
        raise EnronPerformanceError(f"{description} identity changed before use.")
    return handle


def _assert_pinned_private_input(handle: Any, expected_identity: Mapping[str, Any], *, description: str) -> None:
    try:
        observed_identity = _bank_workflow._private_entry_identity(os.fstat(handle.fileno()), kind="file")
        _bank_workflow._require_private_entry(observed_identity)
    except (EnronBankBuildError, OSError):
        raise EnronPerformanceError(f"{description} changed during use.") from None
    if _private_identity_payload(observed_identity) != dict(expected_identity):
        raise EnronPerformanceError(f"{description} changed during use.")


def _copy_frozen_private_input(
    run: PrivateRun,
    source: Path,
    destination: Path,
    expected_identity: Mapping[str, Any],
    *,
    description: str,
) -> tuple[str, int]:
    frozen = _validate_private_identity_payload(expected_identity, expected_kind="file")
    expected_bytes = int(frozen["size"])
    if expected_bytes > MAX_SOURCE_SNAPSHOT_BYTES:
        raise EnronPerformanceError(f"{description} exceeds the private snapshot byte limit.")
    digest = hashlib.sha256()
    observed_bytes = 0
    try:
        with _open_frozen_private_input(source, frozen, description=description) as source_handle:
            with run.open_binary(destination) as destination_handle:
                while chunk := source_handle.read(min(1024 * 1024, expected_bytes - observed_bytes + 1)):
                    observed_bytes += len(chunk)
                    if observed_bytes > expected_bytes:
                        raise EnronPerformanceError(f"{description} changed while it was snapshotted.")
                    digest.update(chunk)
                    destination_handle.write(chunk)
            _assert_pinned_private_input(source_handle, frozen, description=description)
    except EnronPerformanceError:
        raise
    except (EnronPrivateIOError, OSError, OverflowError):
        raise EnronPerformanceError(f"{description} could not be snapshotted safely.") from None
    if observed_bytes != expected_bytes:
        raise EnronPerformanceError(f"{description} changed while it was snapshotted.")
    return "sha256:" + digest.hexdigest(), observed_bytes


def _copy_frozen_private_tree(
    run: PrivateRun,
    source_root: Path,
    destination_root: Path,
    expected_tree_value: Mapping[str, Any],
    *,
    description: str,
) -> tuple[dict[str, tuple[str, int]], set[str]]:
    expected_tree = _validate_private_tree_payload(expected_tree_value)
    _root, current_tree = _snapshot_performance_private_tree(source_root, description=description)
    if _private_tree_payload(current_tree) != expected_tree:
        raise EnronPerformanceError(f"{description} identity changed before snapshotting.")
    total_bytes = sum(int(identity["size"]) for identity in expected_tree.values() if identity["kind"] == "file")
    if total_bytes > MAX_SOURCE_SNAPSHOT_BYTES:
        raise EnronPerformanceError(f"{description} exceeds the private snapshot byte limit.")
    run.ensure_directory(destination_root)
    destination_directories = {destination_root.as_posix()}
    directories = sorted(
        (name for name, identity in expected_tree.items() if name != "." and identity["kind"] == "directory"),
        key=lambda name: (len(Path(name).parts), name),
    )
    for name in directories:
        run.ensure_directory(destination_root / name)
        destination_directories.add((destination_root / name).as_posix())
    copied: dict[str, tuple[str, int]] = {}
    for name, identity in sorted(expected_tree.items()):
        if identity["kind"] != "file":
            continue
        target = destination_root / name
        copied[target.as_posix()] = _copy_frozen_private_input(
            run,
            source_root / name,
            target,
            identity,
            description=f"{description} file",
        )
    _root, final_tree = _snapshot_performance_private_tree(source_root, description=description)
    if _private_tree_payload(final_tree) != expected_tree:
        raise EnronPerformanceError(f"{description} changed while it was snapshotted.")
    return copied, destination_directories


def _verify_source_build_snapshot(
    root: Path,
    copied: Mapping[str, tuple[str, int]],
    expected_directories: set[str],
) -> Mapping[str, Any]:
    snapshot_root, tree = _snapshot_performance_private_tree(root, description="Source-build private input snapshot")
    expected_files = {"COMMITTED", "manifest.json", *copied}
    for name in expected_files:
        parts = Path(name).parts[:-1]
        for length in range(1, len(parts) + 1):
            expected_directories.add(Path(*parts[:length]).as_posix())
    observed_files = {name for name, identity in tree.items() if identity.kind == "file"}
    observed_directories = {name for name, identity in tree.items() if name != "." and identity.kind == "directory"}
    if observed_files != expected_files or observed_directories != expected_directories:
        raise EnronPerformanceError("Source-build private input snapshot inventory is invalid.")
    for relative_path, (expected_sha256, expected_bytes) in copied.items():
        fingerprint = _fingerprint_performance_private_file(
            snapshot_root,
            relative_path,
            tree,
            maximum_bytes=max(expected_bytes, 1),
            description="Source-build private input snapshot file",
        )
        if fingerprint.sha256 != expected_sha256 or fingerprint.identity.size != expected_bytes:
            raise EnronPerformanceError("Source-build private input snapshot differs from its copied source.")
    return tree


@contextlib.contextmanager
def _source_build_input_boundary(request: Mapping[str, Any]):
    identities = request.get("source_identities")
    if not isinstance(identities, Mapping) or set(identities) != {
        "development_tree",
        "development_manifest",
        "profile_source",
        "annotation_tree",
        "bank_build_tree",
        "cmu_catalog_bindings",
    }:
        raise EnronPerformanceError("Source-build frozen identity request is invalid.")
    development_tree = _validate_private_tree_payload(identities["development_tree"])
    manifest_identity = _validate_private_identity_payload(
        identities["development_manifest"],
        expected_kind="file",
    )
    train_identity = _validate_private_identity_payload(identities["profile_source"], expected_kind="file")
    if (
        development_tree.get("manifest.json") != manifest_identity
        or development_tree.get("train.jsonl") != train_identity
    ):
        raise EnronPerformanceError("Source-build development identities are inconsistent.")
    development_root = _validated_absolute_private_location(
        request.get("development_run"),
        description="Source-build development run location",
    )
    annotation_value = request.get("annotation_run")
    bindings_value = request.get("cmu_catalog_bindings")
    annotation_tree_value = identities.get("annotation_tree")
    bank_tree_value = identities.get("bank_build_tree")
    bindings_identity_value = identities.get("cmu_catalog_bindings")
    optional_values = (
        annotation_value,
        bindings_value,
        annotation_tree_value,
        bank_tree_value,
        bindings_identity_value,
    )
    if any(value is None for value in optional_values) and any(value is not None for value in optional_values):
        raise EnronPerformanceError("Source-build auxiliary identities are incomplete.")

    annotation_root: Path | None = None
    annotation_tree: dict[str, dict[str, Any]] | None = None
    bank_root: Path | None = None
    bank_tree: dict[str, dict[str, Any]] | None = None
    bindings_path: Path | None = None
    bindings_identity: dict[str, Any] | None = None
    if annotation_value is not None:
        annotation_root = _validated_absolute_private_location(
            annotation_value,
            description="Source-build annotation run location",
        )
        annotation_tree = _validate_private_tree_payload(annotation_tree_value)
        bank_tree = _validate_private_tree_payload(bank_tree_value)
        bindings_path = _validated_absolute_private_location(
            bindings_value,
            description="Source-build auxiliary binding location",
        )
        bank_root = bindings_path.parents[1]
        bindings_identity = _validate_private_identity_payload(bindings_identity_value, expected_kind="file")
    output_dir = _validated_absolute_private_location(
        request.get("output_dir"),
        description="Source-build output location",
    )
    declared_snapshot_bytes = sum(
        int(identity["size"]) for identity in development_tree.values() if identity["kind"] == "file"
    )
    if annotation_tree is not None:
        declared_snapshot_bytes += sum(
            int(identity["size"]) for identity in annotation_tree.values() if identity["kind"] == "file"
        )
    if bindings_identity is not None:
        declared_snapshot_bytes += int(bindings_identity["size"])
    if declared_snapshot_bytes > MAX_SOURCE_SNAPSHOT_BYTES:
        raise EnronPerformanceError("Source-build inputs exceed the private snapshot byte limit.")
    snapshot_root = output_dir.parent / "inputs"
    copied: dict[str, tuple[str, int]] = {}
    snapshot_directories: set[str] = set()
    try:
        with PrivateRun(snapshot_root, allow_unignored_output=True) as run:
            development_copied, development_directories = _copy_frozen_private_tree(
                run,
                development_root,
                Path("development"),
                development_tree,
                description="Source-build development run",
            )
            copied.update(development_copied)
            snapshot_directories.update(development_directories)
            if (
                annotation_root is not None
                and annotation_tree is not None
                and bank_root is not None
                and bank_tree is not None
                and bindings_path is not None
                and bindings_identity is not None
            ):
                annotation_copied, annotation_directories = _copy_frozen_private_tree(
                    run,
                    annotation_root,
                    Path("annotation"),
                    annotation_tree,
                    description="Source-build annotation run",
                )
                copied.update(annotation_copied)
                snapshot_directories.update(annotation_directories)
                _bank_root, current_bank_tree = _snapshot_performance_private_tree(
                    bank_root,
                    description="Source-build bank run",
                )
                if _private_tree_payload(current_bank_tree) != bank_tree:
                    raise EnronPerformanceError("Source-build bank run identity changed before snapshotting.")
                binding_target = Path("bindings/cmu-train-catalog-bindings.jsonl")
                copied[binding_target.as_posix()] = _copy_frozen_private_input(
                    run,
                    bindings_path,
                    binding_target,
                    bindings_identity,
                    description="Source-build auxiliary bindings",
                )
                _bank_root, final_bank_tree = _snapshot_performance_private_tree(
                    bank_root,
                    description="Source-build bank run",
                )
                if _private_tree_payload(final_bank_tree) != bank_tree:
                    raise EnronPerformanceError("Source-build bank run changed while it was snapshotted.")
            if sum(byte_count for _sha256, byte_count in copied.values()) > MAX_SOURCE_SNAPSHOT_BYTES:
                raise EnronPerformanceError("Source-build inputs exceed the private snapshot byte limit.")
            snapshot_manifest = {
                "schema_version": "nerb.enron_performance_source_snapshot.v1",
                "files": {
                    name: {"sha256": sha256, "bytes": byte_count}
                    for name, (sha256, byte_count) in sorted(copied.items())
                },
            }
            with run.open_binary("manifest.json") as file:
                file.write(_pretty_json_bytes(snapshot_manifest))
            run.commit()
    except EnronPerformanceError:
        raise
    except EnronPrivateIOError:
        raise EnronPerformanceError("Source-build private input snapshot failed safely.") from None
    snapshot_tree = _verify_source_build_snapshot(snapshot_root, copied, snapshot_directories)
    snapshot = _SourceBuildInputSnapshot(
        root=snapshot_root,
        development_run=snapshot_root / "development",
        annotation_run=None if annotation_root is None else snapshot_root / "annotation",
        cmu_catalog_bindings=(
            None if bindings_path is None else snapshot_root / "bindings" / "cmu-train-catalog-bindings.jsonl"
        ),
    )
    try:
        yield snapshot
    finally:
        _assert_performance_private_tree_current(
            snapshot.root,
            snapshot_tree,
            description="Source-build private input snapshot",
        )


def _source_build_worker_result(raw: bytes) -> dict[str, Any]:
    nonce: str | None = None
    workload_sha256: str | None = None
    try:
        if not raw or len(raw) > DEFAULT_MAX_REQUEST_BYTES:
            raise ValueError
        request = _strict_json_loads(raw)
        if not isinstance(request, dict) or set(request) != {
            "schema_version",
            "nonce",
            "workload_sha256",
            "development_run",
            "annotation_run",
            "cmu_catalog_bindings",
            "source_identities",
            "benchmark_version",
            "created_at",
            "expected_projection_sha256",
            "output_dir",
        }:
            raise ValueError
        raw_nonce = request.get("nonce")
        raw_workload_sha256 = request.get("workload_sha256")
        nonce = raw_nonce if isinstance(raw_nonce, str) and _NONCE_RE.fullmatch(raw_nonce) is not None else None
        workload_sha256 = (
            raw_workload_sha256
            if isinstance(raw_workload_sha256, str) and _SHA256_RE.fullmatch(raw_workload_sha256) is not None
            else None
        )
        if (
            request.get("schema_version") != "nerb.enron_performance_source_build_request.v1"
            or nonce is None
            or workload_sha256 is None
            or not isinstance(request.get("expected_projection_sha256"), str)
            or _SHA256_RE.fullmatch(request["expected_projection_sha256"]) is None
        ):
            raise ValueError
        _validated_absolute_private_location(
            request.get("development_run"),
            description="Source-build development run location",
        )
        _bounded_private_string(
            request.get("benchmark_version"),
            maximum_bytes=MAX_BENCHMARK_VERSION_BYTES,
            description="Source-build benchmark version",
        )
        _bounded_private_string(
            request.get("created_at"),
            maximum_bytes=MAX_BUILD_TIMESTAMP_BYTES,
            description="Source-build timestamp",
        )
        output_dir = _validated_absolute_private_location(
            request.get("output_dir"),
            description="Source-build output location",
        )
        temporary_root = output_dir.parent
        system_temporary_root = Path(tempfile.gettempdir()).resolve()
        if (
            not output_dir.is_absolute()
            or output_dir.name != "build"
            or temporary_root.parent.resolve() != system_temporary_root
            or temporary_root.resolve().parent != system_temporary_root
            or not temporary_root.is_dir()
            or not temporary_root.name.startswith("nerb-performance-build-")
        ):
            raise ValueError
        annotation_value = request.get("annotation_run")
        bindings_value = request.get("cmu_catalog_bindings")
        if (annotation_value is None) != (bindings_value is None):
            raise ValueError
        if annotation_value is not None:
            _validated_absolute_private_location(
                annotation_value,
                description="Source-build annotation run location",
            )
            _validated_absolute_private_location(
                bindings_value,
                description="Source-build auxiliary binding location",
            )
        identities = request.get("source_identities")
        if not isinstance(identities, Mapping) or set(identities) != {
            "development_tree",
            "development_manifest",
            "profile_source",
            "annotation_tree",
            "bank_build_tree",
            "cmu_catalog_bindings",
        }:
            raise ValueError
        _validate_private_tree_payload(identities["development_tree"])
        _validate_private_identity_payload(identities["development_manifest"], expected_kind="file")
        _validate_private_identity_payload(identities["profile_source"], expected_kind="file")
        optional_identities = (
            identities["annotation_tree"],
            identities["bank_build_tree"],
            identities["cmu_catalog_bindings"],
        )
        if annotation_value is None:
            if any(value is not None for value in optional_identities):
                raise ValueError
        else:
            _validate_private_tree_payload(identities["annotation_tree"])
            _validate_private_tree_payload(identities["bank_build_tree"])
            _validate_private_identity_payload(identities["cmu_catalog_bindings"], expected_kind="file")
    except (EnronPerformanceError, OSError, json.JSONDecodeError, RecursionError, UnicodeDecodeError, ValueError):
        return _source_build_error_result(nonce, workload_sha256, "request_shape")

    try:
        started = time.perf_counter_ns()
        with _source_build_input_boundary(request) as source_snapshot:
            options = EnronBankBuildOptions(
                development_run=source_snapshot.development_run,
                output_dir=output_dir,
                annotation_run=source_snapshot.annotation_run,
                cmu_catalog_bindings_path=source_snapshot.cmu_catalog_bindings,
                benchmark_version=request["benchmark_version"],
                created_at=request["created_at"],
                allow_unignored_output=True,
            )
            with open(os.devnull, "w", encoding="utf-8") as sink:
                with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
                    card = build_enron_intelligence_bank(options)
        elapsed_ns = time.perf_counter_ns() - started
        projection_sha256 = _canonical_hash(_source_build_projection(card))
        if projection_sha256 != request["expected_projection_sha256"]:
            return _source_build_error_result(nonce, workload_sha256, "correctness_mismatch", elapsed_ns=elapsed_ns)
        active_patterns = card["bank"]["stats"]["active_totals"]["patterns"]
        if type(active_patterns) is not int or active_patterns < 1:
            raise ValueError
        rss_bytes, rss_status = _source_build_peak_rss()
        return {
            "schema_version": RESULT_SCHEMA_VERSION,
            "nonce": nonce,
            "workload_sha256": workload_sha256,
            "pid": os.getpid(),
            "status": "ok",
            "error_code": None,
            "elapsed_ns": elapsed_ns,
            "peak_rss_bytes": rss_bytes,
            "peak_rss_status": rss_status,
            "record_count": active_patterns,
            "correctness_sha256": projection_sha256,
        }
    except EnronPerformanceError:
        return _source_build_error_result(nonce, workload_sha256, "source_identity_changed")
    except BaseException:
        return _source_build_error_result(nonce, workload_sha256, "operation_failed")


def _source_build_peak_rss() -> tuple[int | None, str]:
    try:
        resource_module = __import__("resource")
        raw = resource_module.getrusage(resource_module.RUSAGE_SELF).ru_maxrss
    except BaseException:
        return None, "resource_unavailable"
    return normalize_peak_rss(raw)


def _source_build_error_result(
    nonce: str | None,
    workload_sha256: str | None,
    error_code: str,
    *,
    elapsed_ns: int | None = None,
) -> dict[str, Any]:
    rss_bytes, rss_status = _source_build_peak_rss()
    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "nonce": nonce,
        "workload_sha256": workload_sha256,
        "pid": os.getpid(),
        "status": "error",
        "error_code": error_code,
        "elapsed_ns": elapsed_ns,
        "peak_rss_bytes": rss_bytes,
        "peak_rss_status": rss_status,
        "record_count": None,
        "correctness_sha256": None,
    }


def _read_run_artifacts(
    root: Path,
    manifest: Mapping[str, Any],
    tree: Mapping[str, Any],
) -> dict[str, bytes]:
    raw_artifacts = manifest.get("artifacts")
    if not isinstance(raw_artifacts, list) or not raw_artifacts:
        raise EnronPerformanceError("Performance run manifest has no artifacts.")
    result: dict[str, bytes] = {}
    descriptors: dict[str, Mapping[str, Any]] = {}
    paths: set[str] = set()
    for item in raw_artifacts:
        if not isinstance(item, Mapping) or set(item) != {"id", "sha256", "bytes", "relative_path", "kind"}:
            raise EnronPerformanceError("Performance run artifact descriptor is invalid.")
        identifier = item.get("id")
        relative_path = item.get("relative_path")
        if (
            not isinstance(identifier, str)
            or not identifier
            or identifier in descriptors
            or not isinstance(relative_path, str)
            or not relative_path
            or relative_path in paths
        ):
            raise EnronPerformanceError("Performance run artifact ids and paths must be unique.")
        fixed_contracts = {
            "performance_report": ("aggregate_report", "report.json"),
            "performance_audit": ("private_correctness_audit", "audit/results.jsonl"),
            "performance_plan": ("public_plan", "plan.json"),
        }
        expected_contract = fixed_contracts.get(str(identifier), ("inventory", f"inventories/{identifier}.json"))
        if (item.get("kind"), relative_path) != expected_contract:
            raise EnronPerformanceError("Performance run artifact privacy classification is invalid.")
        relative = Path(relative_path)
        if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
            raise EnronPerformanceError("Performance run artifact path is unsafe.")
        _positive_int(
            item.get("bytes"),
            "Performance run artifact bytes",
            maximum=MAX_PRIVATE_JSON_BYTES,
        )
        descriptors[identifier] = item
        paths.add(relative_path)
    _verify_performance_tree_inventory(tree, ["COMMITTED", "manifest.json", *sorted(paths)])
    for identifier, item in descriptors.items():
        byte_count = int(item["bytes"])
        relative_path = str(item["relative_path"])
        relative = Path(relative_path)
        fingerprint = _fingerprint_performance_private_file(
            root,
            relative_path,
            tree,
            maximum_bytes=max(byte_count, 1),
            description="Performance run artifact",
        )
        if fingerprint.identity.size != byte_count or fingerprint.sha256 != item.get("sha256"):
            raise EnronPerformanceError("Performance run artifact changed after commit.")
        payload = _read_fingerprinted_private_bytes(
            root / relative,
            fingerprint,
            maximum_bytes=max(byte_count, 1),
            description="Performance run artifact",
        )
        result[identifier] = payload
    return result


def _verify_materialized_performance(
    performance: Mapping[str, Any],
    plan_performance: Mapping[str, Any],
    inventories: Mapping[str, Sequence[Mapping[str, int]]],
    environment: Mapping[str, Any],
) -> None:
    if validate_enron_performance_output(performance)["valid"] is not True:
        raise EnronPerformanceError("Performance report output schema is invalid.")
    if performance["evaluated"] is not True or plan_performance["evaluated"] is not True:
        raise EnronPerformanceError("Performance report evaluated status is invalid.")
    if hash_enron_performance_manifest(performance) != hash_enron_performance_manifest(plan_performance):
        raise EnronPerformanceError("Performance report differs from its frozen manifest plan.")
    input_by_id = {str(item["id"]): item for item in performance["inputs"]}
    for input_descriptor in input_by_id.values():
        inventory_id = str(input_descriptor["inventory_ref"]["id"])
        inventory = inventories.get(inventory_id)
        if inventory is None:
            raise EnronPerformanceError("Performance report inventory is unavailable.")
        payload = _canonical_json_bytes(inventory)
        if (
            _sha256_bytes(payload) != input_descriptor["inventory_ref"]["sha256"]
            or len(payload) != input_descriptor["inventory_ref"]["bytes"]
        ):
            raise EnronPerformanceError("Performance report inventory hash is invalid.")
        expected = summarize_enron_performance_inventory(inventory)
        if any(input_descriptor[field] != expected[field] for field in expected):
            raise EnronPerformanceError("Performance report inventory arithmetic is invalid.")
        if input_descriptor["descriptor_sha256"] != hash_enron_performance_input(input_descriptor):
            raise EnronPerformanceError("Performance input descriptor hash is invalid.")
    bank_by_id = {str(item["id"]): item for item in performance["banks"]}
    if any(item["descriptor_sha256"] != hash_enron_performance_bank(item) for item in bank_by_id.values()):
        raise EnronPerformanceError("Performance bank descriptor hash is invalid.")
    if any(item["descriptor_sha256"] != hash_enron_performance_harness(item) for item in performance["harnesses"]):
        raise EnronPerformanceError("Performance harness descriptor hash is invalid.")
    if any(item["descriptor_sha256"] != hash_enron_performance_baseline(item) for item in performance["baselines"]):
        raise EnronPerformanceError("Performance baseline descriptor hash is invalid.")
    baseline_by_id = {str(item["id"]): item for item in performance["baselines"]}
    workload_by_id = {str(item["id"]): item for item in performance["workloads"]}
    for workload in workload_by_id.values():
        if workload["workload_sha256"] != hash_enron_workload(workload):
            raise EnronPerformanceError("Performance workload hash is invalid.")
        rss_samples = workload["rss_samples_bytes"]
        peak_rss = workload["peak_rss_bytes"]
        if (peak_rss is None) != (not rss_samples) or (
            peak_rss is not None
            and (len(rss_samples) != len(workload["samples_seconds"]) or peak_rss != max(rss_samples))
        ):
            raise EnronPerformanceError("Performance workload RSS aggregation is invalid.")
        if workload["decision_grade"] and peak_rss is None:
            raise EnronPerformanceError("Decision-grade performance workload lacks complete RSS evidence.")
        if int(workload["concurrency"]) > int(environment["cpu_count"]):
            raise EnronPerformanceError("Performance workload concurrency exceeds the recorded CPU count.")
        if peak_rss is not None and peak_rss > int(environment["memory_bytes"]):
            raise EnronPerformanceError("Performance workload RSS exceeds recorded machine memory.")
        input_descriptor = None if workload["input_id"] is None else input_by_id[str(workload["input_id"])]
        records_per_sample = workload["records_per_sample"]
        baseline = None if workload["baseline_id"] is None else baseline_by_id[str(workload["baseline_id"])]
        records_must_match_inventory = baseline is None or baseline["semantic_equivalence"] == "exact"
        expected_inventory_records = (
            None
            if input_descriptor is None or workload["sample_unit"] != "whole_input"
            else input_descriptor["records"] * workload["work_per_sample"]
        )
        if (workload["sample_unit"] == "whole_input") != (records_per_sample is not None) or (
            records_per_sample is not None
            and records_must_match_inventory
            and records_per_sample != expected_inventory_records
        ):
            raise EnronPerformanceError("Performance workload record denominator is invalid.")
        expected = calculate_enron_performance_statistics(
            workload["samples_seconds"],
            input_descriptor,
            phase=str(workload["phase"]),
            sample_unit=str(workload["sample_unit"]),
            work_per_sample=int(workload["work_per_sample"]),
            records_per_sample=records_per_sample,
        )
        if any(
            not (
                workload["stats"][field] is expected_value
                if expected_value is None
                else math.isclose(
                    float(workload["stats"][field]),
                    float(expected_value),
                    rel_tol=1e-12,
                    abs_tol=1e-15,
                )
            )
            for field, expected_value in expected.items()
        ):
            raise EnronPerformanceError("Performance workload statistic is invalid.")
    for comparison in performance["comparisons"]:
        if comparison["comparison_plan_sha256"] != hash_enron_performance_comparison_plan(comparison):
            raise EnronPerformanceError("Performance comparison plan hash is invalid.")
        paired = comparison["noise_method"] in {"paired_relative_mad", "paired_block_ratio_mad"}
        expected = calculate_enron_performance_comparison(
            workload_by_id[str(comparison["candidate_workload_id"])]["stats"],
            workload_by_id[str(comparison["baseline_workload_id"])]["stats"],
            metric=str(comparison["metric"]),
            noise_multiplier=float(comparison["noise_multiplier"]),
            regression_tolerance=float(comparison["regression_tolerance"]),
            noise_method=str(comparison["noise_method"]),
            candidate_samples=(
                workload_by_id[str(comparison["candidate_workload_id"])]["samples_seconds"] if paired else None
            ),
            baseline_samples=(
                workload_by_id[str(comparison["baseline_workload_id"])]["samples_seconds"] if paired else None
            ),
        )
        if any(
            comparison[field] != value
            if isinstance(value, str)
            else not math.isclose(float(comparison[field]), float(value), rel_tol=1e-12, abs_tol=1e-15)
            for field, value in expected.items()
        ):
            raise EnronPerformanceError("Performance comparison arithmetic is invalid.")
    for model in performance["breakeven_models"]:
        if model["model_plan_sha256"] != hash_enron_breakeven_plan(model):
            raise EnronPerformanceError("Performance breakeven plan hash is invalid.")
        plan_model = next(item for item in plan_performance["breakeven_models"] if item["id"] == model["id"])
        expected = _materialize_breakeven(plan_model, workload_by_id)
        if model != expected:
            raise EnronPerformanceError("Performance breakeven arithmetic is invalid.")


def _verify_enron_performance_run_impl(run_dir: Path) -> dict[str, Any]:
    """Verify a committed performance run without reading protected corpus text."""

    root, initial_tree = _snapshot_performance_private_tree(
        run_dir,
        description="Performance evidence run",
    )
    marker_fingerprint = _fingerprint_performance_private_file(
        root,
        "COMMITTED",
        initial_tree,
        maximum_bytes=128,
        description="Performance commit marker",
    )
    marker = _read_fingerprinted_private_bytes(
        root / "COMMITTED",
        marker_fingerprint,
        maximum_bytes=128,
        description="Performance commit marker",
    )
    if marker != b"nerb.enron.private-run.v2\n":
        raise EnronPerformanceError("Performance run is not committed.")
    manifest_fingerprint = _fingerprint_performance_private_file(
        root,
        "manifest.json",
        initial_tree,
        maximum_bytes=MAX_PLAN_BYTES,
        description="Performance run manifest",
    )
    manifest = _strict_json_object_bytes(
        _read_fingerprinted_private_bytes(
            root / "manifest.json",
            manifest_fingerprint,
            maximum_bytes=MAX_PLAN_BYTES,
            description="Performance run manifest",
        ),
        description="Performance run manifest",
    )
    if (
        set(manifest)
        != {
            "schema_version",
            "suite",
            "benchmark_version",
            "plan_sha256",
            "run_sha256",
            "artifacts",
        }
        or manifest.get("schema_version") != PERFORMANCE_RUN_PRIVATE_MANIFEST_SCHEMA_VERSION
        or manifest.get("suite") != PERFORMANCE_SUITE_ID
    ):
        raise EnronPerformanceError("Performance run manifest shape is invalid.")
    artifacts = _read_run_artifacts(root, manifest, initial_tree)
    if not {"performance_report", "performance_audit", "performance_plan"} <= set(artifacts):
        raise EnronPerformanceError("Performance run is missing required artifacts.")
    try:
        report = _strict_json_loads(artifacts["performance_report"])
        plan = _strict_json_loads(artifacts["performance_plan"])
    except (json.JSONDecodeError, RecursionError, UnicodeDecodeError, ValueError):
        raise EnronPerformanceError("Performance report or plan is invalid JSON.") from None
    if not isinstance(report, dict) or not isinstance(plan, dict):
        raise EnronPerformanceError("Performance report and plan must be JSON objects.")
    _validate_performance_plan_shape(plan)
    _validate_run_report_envelope(report)
    if manifest.get("benchmark_version") != plan.get("benchmark_version") or manifest.get(
        "benchmark_version"
    ) != report.get("benchmark_version"):
        raise EnronPerformanceError("Performance run manifest benchmark binding is invalid.")
    expected_plan_sha256 = _canonical_hash({key: value for key, value in plan.items() if key != "plan_sha256"})
    if plan.get("plan_sha256") != expected_plan_sha256 or manifest.get("plan_sha256") != expected_plan_sha256:
        raise EnronPerformanceError("Performance run plan hash is invalid.")
    profile = _validate_profile(str(report.get("profile")))
    profiles = plan.get("profiles")
    if not isinstance(profiles, Mapping):
        raise EnronPerformanceError("Performance run plan profile shape is invalid.")
    profile_plan = profiles.get(profile)
    if not isinstance(profile_plan, Mapping) or not isinstance(profile_plan.get("performance"), Mapping):
        raise EnronPerformanceError("Performance run plan profile binding is invalid.")
    report_performance = report.get("performance")
    if (
        not isinstance(report_performance, Mapping)
        or validate_enron_performance_output(report_performance)["valid"] is not True
    ):
        raise EnronPerformanceError("Performance aggregate report output shape is invalid.")
    inventories: dict[str, Sequence[Mapping[str, int]]] = {}
    for input_descriptor in report_performance["inputs"]:
        inventory_id = str(input_descriptor["inventory_ref"]["id"])
        payload = artifacts.get(inventory_id)
        if payload is None:
            raise EnronPerformanceError("Performance run inventory artifact is missing.")
        try:
            value = _strict_json_loads(payload)
        except (json.JSONDecodeError, RecursionError, UnicodeDecodeError, ValueError):
            raise EnronPerformanceError("Performance run inventory is invalid JSON.") from None
        if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
            raise EnronPerformanceError("Performance run inventory shape is invalid.")
        inventories[inventory_id] = value
    expected_artifact_ids = {
        "performance_report",
        "performance_audit",
        "performance_plan",
        *inventories,
    }
    if set(artifacts) != expected_artifact_ids:
        raise EnronPerformanceError("Performance run manifest contains an undeclared artifact.")
    _verify_materialized_performance(
        report_performance,
        profile_plan["performance"],
        inventories,
        report["environment"],
    )
    for workload in report_performance["workloads"]:
        expected_samples = (
            DEFAULT_SMOKE_SAMPLES
            if profile == "smoke"
            else DEFAULT_SETUP_SAMPLES
            if workload["phase"] in {"source_profile", "source_build", "cold_compile"}
            else DEFAULT_DOCUMENT_SAMPLES
            if workload["sample_unit"] == "document"
            else DEFAULT_SCAN_SAMPLES
        )
        if workload["stats"]["sample_count"] != expected_samples:
            raise EnronPerformanceError("Performance report does not match the frozen profile sample policy.")
    expected_decision = (
        {"passed": False, "failure_codes": ["smoke_profile_nonpromotable"]}
        if profile == "smoke"
        else _decision_grade_summary(report_performance, plan["decision_thresholds"], report["environment"])
    )
    if profile == "decision" and report["software"]["git_dirty"] is True:
        failure_codes = expected_decision["failure_codes"]
        if not isinstance(failure_codes, list) or any(not isinstance(item, str) for item in failure_codes):
            raise EnronPerformanceError("Performance report decision failure codes are invalid.")
        expected_decision = {
            "passed": False,
            "failure_codes": sorted({*failure_codes, "dirty_git_worktree"}),
        }
    if report["decision_grade"] != expected_decision:
        raise EnronPerformanceError("Performance report decision-grade summary is invalid.")
    if (
        report.get("schema_version") != PERFORMANCE_RUN_SCHEMA_VERSION
        or report.get("suite") != PERFORMANCE_SUITE_ID
        or report.get("plan_sha256") != expected_plan_sha256
        or report.get("performance_manifest_sha256") != hash_enron_performance_manifest(report_performance)
        or report.get("sealed_test_accessed") is not False
        or report.get("privacy", {}).get("status") != "passed"
        or _public_serialization_diagnostics(report)
    ):
        raise EnronPerformanceError("Performance aggregate report binding or privacy status is invalid.")
    expected_run_sha256 = _canonical_hash({key: value for key, value in report.items() if key != "run_sha256"})
    if report.get("run_sha256") != expected_run_sha256 or manifest.get("run_sha256") != expected_run_sha256:
        raise EnronPerformanceError("Performance aggregate run hash is invalid.")
    audit_rows: dict[str, Mapping[str, Any]] = {}
    for line in artifacts["performance_audit"].splitlines():
        try:
            value = _strict_json_loads(line)
        except (json.JSONDecodeError, RecursionError, UnicodeDecodeError, ValueError):
            raise EnronPerformanceError("Performance correctness audit is invalid JSONL.") from None
        if not isinstance(value, dict) or set(value) != {"workload_id", "samples"}:
            raise EnronPerformanceError("Performance correctness audit shape is invalid.")
        identifier = value.get("workload_id")
        if not isinstance(identifier, str) or identifier in audit_rows:
            raise EnronPerformanceError("Performance correctness audit workload ids are invalid.")
        audit_rows[identifier] = value
    workload_by_id = {str(item["id"]): item for item in report_performance["workloads"]}
    if set(audit_rows) != set(workload_by_id):
        raise EnronPerformanceError("Performance correctness audit coverage is invalid.")
    sequence_to_workload: dict[int, str] = {}
    for identifier, row in audit_rows.items():
        samples = row["samples"]
        workload = workload_by_id[identifier]
        if not isinstance(samples, list) or len(samples) != workload["stats"]["sample_count"]:
            raise EnronPerformanceError("Performance correctness audit sample coverage is invalid.")
        for index, item in enumerate(samples):
            item_map = cast(Mapping[str, Any], item) if isinstance(item, Mapping) else {}
            if (
                not item_map
                or set(item_map)
                != {"sequence", "pid", "record_count", "correctness_sha256", "elapsed_ns", "peak_rss_bytes"}
                or type(item_map["sequence"]) is not int
                or item_map["sequence"] < 0
                or item_map["sequence"] in sequence_to_workload
                or type(item_map["pid"]) is not int
                or item_map["pid"] < 1
                or type(item_map["record_count"]) is not int
                or item_map["record_count"] < 0
                or not isinstance(item_map["correctness_sha256"], str)
                or _SHA256_RE.fullmatch(item_map["correctness_sha256"]) is None
                or type(item_map["elapsed_ns"]) is not int
                or item_map["elapsed_ns"] / 1_000_000_000 != workload["samples_seconds"][index]
                or item_map["peak_rss_bytes"]
                != (workload["rss_samples_bytes"][index] if workload["rss_samples_bytes"] else None)
            ):
                raise EnronPerformanceError("Performance correctness audit sample binding is invalid.")
            sequence_to_workload[item_map["sequence"]] = identifier
        sample_sequences = [item["sequence"] for item in samples]
        if sample_sequences != sorted(sample_sequences):
            raise EnronPerformanceError("Performance correctness audit sample order is not chronological.")
        if (
            workload["sample_unit"] != "document"
            and len({(item["record_count"], item["correctness_sha256"]) for item in samples}) != 1
        ):
            raise EnronPerformanceError("Performance correctness audit is unstable across repeated samples.")
        if workload["sample_unit"] == "whole_input" and any(
            item["record_count"] != workload["records_per_sample"] for item in samples
        ):
            raise EnronPerformanceError("Performance correctness audit record denominator is invalid.")
        pids = [item["pid"] for item in samples]
        if (workload["process_model"] == "reused_process" and len(set(pids)) != 1) or (
            workload["process_model"] == "fresh_process_per_sample" and len(set(pids)) != len(pids)
        ):
            raise EnronPerformanceError("Performance correctness audit process isolation is invalid.")
    if set(sequence_to_workload) != set(range(len(sequence_to_workload))):
        raise EnronPerformanceError("Performance correctness audit global sequence is invalid.")
    for identifier, workload in workload_by_id.items():
        if not identifier.startswith("control_"):
            continue
        candidate_id = identifier.removeprefix("control_")
        if candidate_id not in audit_rows:
            raise EnronPerformanceError("Performance exact control candidate is missing.")
        candidate_sequence = [
            (item["record_count"], item["correctness_sha256"]) for item in audit_rows[candidate_id]["samples"]
        ]
        control_sequence = [
            (item["record_count"], item["correctness_sha256"]) for item in audit_rows[identifier]["samples"]
        ]
        if candidate_sequence != control_sequence:
            raise EnronPerformanceError("Performance exact control correctness sequence differs.")
    if profile == "decision":
        for workload in workload_by_id.values():
            if workload["decision_grade"] is not True:
                continue
            candidate_id = str(workload["id"])
            control_id = f"control_{candidate_id}"
            ordered = sorted(
                ((item["sequence"], "candidate") for item in audit_rows[candidate_id]["samples"]),
            ) + sorted(
                ((item["sequence"], "control") for item in audit_rows[control_id]["samples"]),
            )
            observed_labels = tuple(label for _sequence, label in sorted(ordered))
            if observed_labels != _interleaved_labels(workload["stats"]["sample_count"]):
                raise EnronPerformanceError("Performance correctness audit ABBA ordering is invalid.")
            control = workload_by_id[control_id]
            if workload["process_model"] == "reused_process" and (
                control["process_model"] != "reused_process"
                or audit_rows[candidate_id]["samples"][0]["pid"] == audit_rows[control_id]["samples"][0]["pid"]
            ):
                raise EnronPerformanceError("Performance reused exact-control process isolation is invalid.")
    if all(path in audit_rows for path in PERFORMANCE_EXACT_VALUE_PATHS):
        reference_sequence = [
            (item["record_count"], item["correctness_sha256"])
            for item in audit_rows[PERFORMANCE_EXACT_VALUE_PATHS[0]]["samples"]
        ]
        if any(
            [(item["record_count"], item["correctness_sha256"]) for item in audit_rows[path]["samples"]]
            != reference_sequence
            for path in PERFORMANCE_EXACT_VALUE_PATHS[1:]
        ):
            raise EnronPerformanceError("Performance exact cache-value paths differ semantically.")
    if profile == "decision":
        exact_value_ids = {
            identifier for path in PERFORMANCE_EXACT_VALUE_PATHS for identifier in (path, f"control_{path}")
        }
        ordered_value_samples = sorted(
            (item["sequence"], identifier)
            for identifier in exact_value_ids
            for item in audit_rows[identifier]["samples"]
        )
        observed_value_schedule = tuple(identifier for _sequence, identifier in ordered_value_samples)
        observed_value_sequences = [sequence for sequence, _identifier in ordered_value_samples]
        contiguous_value_sequences = list(
            range(observed_value_sequences[0], observed_value_sequences[0] + len(observed_value_sequences))
        )
        if observed_value_sequences != contiguous_value_sequences or observed_value_schedule != _exact_value_schedule(
            DEFAULT_SCAN_SAMPLES
        ):
            raise EnronPerformanceError("Performance correctness audit cache-value block ordering is invalid.")
        reused_value_ids = [
            identifier
            for identifier in exact_value_ids
            if workload_by_id[identifier]["process_model"] == "reused_process"
        ]
        reused_value_pids = [audit_rows[identifier]["samples"][0]["pid"] for identifier in reused_value_ids]
        if len(set(reused_value_pids)) != len(reused_value_pids):
            raise EnronPerformanceError("Performance cache-value reused-process isolation is invalid.")
    _assert_performance_private_tree_current(
        root,
        initial_tree,
        description="Performance evidence run",
    )
    return {
        "valid": True,
        "schema_version": PERFORMANCE_RUN_SCHEMA_VERSION,
        "suite": PERFORMANCE_SUITE_ID,
        "benchmark_version": report["benchmark_version"],
        "profile": profile,
        "plan_sha256": expected_plan_sha256,
        "run_sha256": expected_run_sha256,
        "decision_grade": report["decision_grade"],
        "sealed_test_accessed": False,
    }


def verify_enron_performance_run(run_dir: Path) -> dict[str, Any]:
    """Verify a committed performance run and sanitize malformed-artifact failures."""

    try:
        return _verify_enron_performance_run_impl(run_dir)
    except EnronPerformanceError:
        raise
    except (AttributeError, IndexError, KeyError, OverflowError, RecursionError, StopIteration, TypeError, ValueError):
        raise EnronPerformanceError("Performance run failed closed structural verification.") from None


def _module_main(argv: Sequence[str] | None = None) -> None:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments != ["--source-build-worker"]:
        raise SystemExit(2)
    stdin = getattr(sys.stdin, "buffer", None)
    raw = sys.stdin.read(64 * 1024 + 1).encode("utf-8") if stdin is None else stdin.read(64 * 1024 + 1)
    result = _source_build_worker_result(raw)
    payload = _canonical_json_bytes(result) + b"\n"
    stdout = getattr(sys.stdout, "buffer", None)
    if stdout is None:
        sys.stdout.write(payload.decode("ascii"))
        sys.stdout.flush()
    else:
        stdout.write(payload)
        stdout.flush()


if __name__ == "__main__":  # pragma: no cover - exercised through the source-build subprocess.
    _module_main()

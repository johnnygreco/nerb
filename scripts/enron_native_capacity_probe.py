#!/usr/bin/env python3
"""Locked synthetic probe for the Enron production bank shape and max-size mapped scan."""

from __future__ import annotations

import argparse
import importlib
import json
import os
import platform
import resource
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from pathlib import Path
from typing import Any

import nerb.enron_bank_builder as bank_builder
from nerb.enron_bank_builder import GENERIC_EMAIL_REGEX
from nerb.enron_capacity import (
    EnronCapacityError,
    _git_head,
    _native_build_source_sha256,
    _native_build_source_sha256_at_commit,
    _require_globally_clean_checkout,
)

native_engine: Any = importlib.import_module("nerb._engine")

CONTACT_PATTERNS = 12_000
PERSON_PATTERNS = 12_999
FALLBACK_PATTERNS = 1
TOTAL_PATTERNS = CONTACT_PATTERNS + PERSON_PATTERNS + FALLBACK_PATTERNS
DOCUMENT_BYTES = 10 * 1024 * 1024
CONCURRENCY = 8
MAX_COMPILE_SECONDS = 30.0
MAX_CONCURRENT_SCAN_SECONDS = 10.0
MAX_RSS_GROWTH_BYTES = 2 * 1024 * 1024 * 1024
MAX_ABSOLUTE_RSS_BYTES = 3 * 1024 * 1024 * 1024
_DENSE_MAPPING_CHUNK = ":\u2003Kſ".encode("utf-8")
_CLEAR_WINDOW_BYTES = len(_DENSE_MAPPING_CHUNK) * 16


def _max_rss_bytes() -> int:
    observed = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return observed if sys.platform == "darwin" else observed * 1024


def _file_fingerprint(path: Path) -> tuple[str, int]:
    digest = sha256()
    byte_count = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            byte_count += len(chunk)
    return "sha256:" + digest.hexdigest(), byte_count


def _implementation_fingerprints() -> tuple[str, str, str]:
    script_sha256, _ = _file_fingerprint(Path(__file__))
    builder_sha256, _ = _file_fingerprint(Path(bank_builder.__file__))
    digest = sha256(b"nerb/enron-native-capacity-probe-implementation/v1\0")
    for component in (script_sha256, builder_sha256):
        encoded = component.encode("ascii")
        digest.update(len(encoded).to_bytes(2, "big"))
        digest.update(encoded)
    return "sha256:" + digest.hexdigest(), script_sha256, builder_sha256


def _source_bytes() -> bytes:
    contact = {
        "_flags": ["IGNORECASE"],
        **{
            f"contact_{index:05d}": rf"\b(?:CONTACT{index:08d}@EXAMPLE\.INVALID)\b" for index in range(CONTACT_PATTERNS)
        },
        "email_fallback": GENERIC_EMAIL_REGEX,
    }
    person = {
        "_flags": ["IGNORECASE"],
        **{f"person_alias_{index:05d}": rf"\b(?:PERSON{index:08d}\s+ALIAS)\b" for index in range(PERSON_PATTERNS)},
    }
    return json.dumps(
        {"CONTACT": contact, "PERSON": person},
        ensure_ascii=True,
        sort_keys=False,
        separators=(",", ":"),
    ).encode("ascii")


def _document() -> tuple[bytes, list[tuple[int, int, int]]]:
    repetitions, remainder = divmod(DOCUMENT_BYTES, len(_DENSE_MAPPING_CHUNK))
    document = bytearray(_DENSE_MAPPING_CHUNK * repetitions + b":" * remainder)
    fixtures = [
        (101, "PERSON00000042\u2003\tALIAS", CONTACT_PATTERNS + FALLBACK_PATTERNS + 42),
        (DOCUMENT_BYTES // 2, "CONTACT00000042@EXAMPLE.INVALID", 42),
        (DOCUMENT_BYTES - 256, "PERSON00001234  ALIAS", CONTACT_PATTERNS + FALLBACK_PATTERNS + 1_234),
    ]
    expected_matches: list[tuple[int, int, int]] = []
    for desired_offset, value, detector_index in fixtures:
        window_start = desired_offset // len(_DENSE_MAPPING_CHUNK) * len(_DENSE_MAPPING_CHUNK)
        document[window_start : window_start + _CLEAR_WINDOW_BYTES] = b":" * _CLEAR_WINDOW_BYTES
        offset = window_start + len(_DENSE_MAPPING_CHUNK)
        encoded = value.encode("utf-8")
        document[offset : offset + len(encoded)] = encoded
        expected_matches.append((detector_index, offset, offset + len(encoded)))
    return bytes(document), expected_matches


def _raw_matches(buffer: Any) -> list[tuple[int, int, int]]:
    matches: list[tuple[int, int, int]] = []
    for index in range(len(buffer)):
        detector, start, end = buffer[index]
        matches.append((int(detector), int(start), int(end)))
    return matches


def _matches_sha256(matches: list[tuple[int, int, int]]) -> str:
    payload = json.dumps(matches, separators=(",", ":")).encode("ascii")
    return "sha256:" + sha256(payload).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-clean-commit",
        action="store_true",
        help="Require the working tree, native sources, embedded extension identity, and HEAD blobs to agree.",
    )
    arguments = parser.parse_args()
    implementation_sha256, script_sha256, builder_sha256 = _implementation_fingerprints()
    source = _source_bytes()
    document, expected_matches = _document()
    document_sha256 = "sha256:" + sha256(document).hexdigest()
    expected_output_sha256 = _matches_sha256(expected_matches)
    native_binary_sha256, native_binary_bytes = _file_fingerprint(Path(native_engine.__file__))
    python_executable_sha256, python_executable_bytes = _file_fingerprint(Path(sys.executable))
    rss_before = _max_rss_bytes()
    compile_started = time.perf_counter()
    bank = native_engine.Bank.from_source_bytes(source, format_hint="json")
    compile_seconds = time.perf_counter() - compile_started
    rss_after_compile = _max_rss_bytes()
    metadata = dict(bank.metadata())
    current_native_build_source_sha256 = _native_build_source_sha256()
    git_commit: str | None = None
    commit_native_build_source_sha256: str | None = None
    git_tree_clean = False
    try:
        git_commit = _git_head()
        commit_native_build_source_sha256 = _native_build_source_sha256_at_commit(git_commit)
        _require_globally_clean_checkout(git_commit)
        git_tree_clean = True
    except EnronCapacityError:
        pass

    scan_started = time.perf_counter()
    serial_matches = _raw_matches(bank.scan_bytes(document))
    serial_scan_seconds = time.perf_counter() - scan_started
    concurrent_started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
        concurrent_matches = list(
            executor.map(lambda _index: _raw_matches(bank.scan_bytes(document)), range(CONCURRENCY))
        )
    concurrent_scan_seconds = time.perf_counter() - concurrent_started
    serial_output_sha256 = _matches_sha256(serial_matches)
    concurrent_output_sha256s = sorted({_matches_sha256(matches) for matches in concurrent_matches})
    rss_after_scan = _max_rss_bytes()
    regex_resources = metadata.get("regex_resources")
    expected_regex_profile = isinstance(regex_resources, dict) and all(
        (
            regex_resources.get("scope") == "entity_independent_shards",
            regex_resources.get("physical_regex_layers") == 1,
            regex_resources.get("maximum_regex_layers_per_entity") == 1,
            regex_resources.get("size_limit_bisections") == 0,
            regex_resources.get("resource_limit_bisections") == 0,
            regex_resources.get("cache_concurrency_budget") == CONCURRENCY,
            regex_resources.get("explicit_regex_cache_slots") == CONCURRENCY,
            regex_resources.get("internal_meta_cache_pool_used") is False,
            regex_resources.get("per_lazy_dfa_cache_capacity_bytes") == 32 * 1024,
            regex_resources.get("maximum_lazy_dfa_caches_per_regex") == 3,
            regex_resources.get("pikevm_stack_nfa_memory_multiplier") == 16,
            regex_resources.get("onepass_enabled") is False,
            regex_resources.get("bounded_backtracker_enabled") is False,
            regex_resources.get("maximum_patterns_per_regex_layer") == 128,
            isinstance(regex_resources.get("compiled_regex_static_bytes"), int),
            regex_resources.get("compiled_regex_static_bytes", 0) > 0,
            isinstance(regex_resources.get("eager_cache_bytes_per_scan"), int),
            regex_resources.get("eager_cache_bytes_per_scan", 0) > 0,
            isinstance(regex_resources.get("pikevm_cache_projection_bytes_per_scan"), int),
            regex_resources.get("pikevm_cache_projection_bytes_per_scan", 0) > 0,
            isinstance(regex_resources.get("pikevm_stack_growth_allowance_bytes_per_scan"), int),
            regex_resources.get("pikevm_stack_growth_allowance_bytes_per_scan", 0) > 0,
            regex_resources.get("lazy_dfa_growth_allowance_bytes_per_scan")
            == regex_resources.get("physical_regex_layers", -1)
            * regex_resources.get("per_lazy_dfa_cache_capacity_bytes", -1)
            * regex_resources.get("maximum_lazy_dfa_caches_per_regex", -1),
            isinstance(regex_resources.get("regex_cache_allowance_bytes"), int),
            regex_resources.get("regex_cache_allowance_bytes")
            == (
                regex_resources.get("eager_cache_bytes_per_scan", -1)
                + regex_resources.get("pikevm_cache_projection_bytes_per_scan", -1)
                + regex_resources.get("pikevm_stack_growth_allowance_bytes_per_scan", -1)
                + regex_resources.get("lazy_dfa_growth_allowance_bytes_per_scan", -1)
            )
            * regex_resources.get("cache_concurrency_budget", -1),
            regex_resources.get("accounted_bytes")
            == regex_resources.get("compiled_regex_static_bytes", -1)
            + regex_resources.get("regex_cache_allowance_bytes", -1),
            regex_resources.get("accounted_bytes", 1) <= regex_resources.get("maximum_accounted_bytes", 0),
        )
    )
    expected_scan_limits = metadata.get("scan_limits") == {
        "maximum_input_bytes": DOCUMENT_BYTES,
        "maximum_concurrent_scans_per_bank": CONCURRENCY,
    }

    criteria = {
        "compile_within_30_seconds": compile_seconds <= MAX_COMPILE_SECONDS,
        "concurrent_scan_within_10_seconds": concurrent_scan_seconds <= MAX_CONCURRENT_SCAN_SECONDS,
        "document_is_exactly_10_mib": len(document) == DOCUMENT_BYTES,
        "match_mode_is_production_entity_independent": metadata.get("match_mode")
        == {
            "name": "entity_independent",
            "status": "production_default",
            "production_default": True,
            "internal_only": False,
            "semantic_notes": "reports cross-entity overlap with leftmost-first matching within each entity",
        },
        "logical_entity_count_is_2": metadata.get("entity_count") == 2,
        "pattern_count_is_exactly_25000": metadata.get("pattern_count") == TOTAL_PATTERNS,
        "regex_profile_matches_topology": expected_regex_profile,
        "scan_limits_match_probe_envelope": expected_scan_limits,
        "serial_output_exact": serial_matches == expected_matches,
        "concurrent_output_exact": all(matches == expected_matches for matches in concurrent_matches),
        "absolute_rss_within_3_gib": rss_after_scan <= MAX_ABSOLUTE_RSS_BYTES,
        "rss_growth_within_2_gib": rss_after_scan - rss_before <= MAX_RSS_GROWTH_BYTES,
        "source_identity_exposed": metadata.get("build_source_sha256") == native_engine.BUILD_SOURCE_SHA256,
        "embedded_source_identity_matches_current": (
            metadata.get("build_source_sha256")
            == native_engine.BUILD_SOURCE_SHA256
            == current_native_build_source_sha256
        ),
        "clean_commit_identity_requirement": not arguments.require_clean_commit
        or (
            git_tree_clean
            and commit_native_build_source_sha256
            == current_native_build_source_sha256
            == native_engine.BUILD_SOURCE_SHA256
        ),
    }
    report = {
        "schema_version": "nerb.enron_native_capacity_probe.v1",
        "fixture": {
            "contact_patterns": CONTACT_PATTERNS,
            "person_alias_patterns": PERSON_PATTERNS,
            "fallback_patterns": FALLBACK_PATTERNS,
            "total_patterns": TOTAL_PATTERNS,
            "document_bytes": len(document),
            "document_sha256": document_sha256,
            "dense_mapping_chunk_repetitions": DOCUMENT_BYTES // len(_DENSE_MAPPING_CHUNK),
            "expected_output_sha256": expected_output_sha256,
            "concurrency": CONCURRENCY,
            "source_bytes": len(source),
            "source_sha256": "sha256:" + sha256(source).hexdigest(),
            "implementation_sha256": implementation_sha256,
            "script_sha256": script_sha256,
            "builder_source_sha256": builder_sha256,
        },
        "measurements": {
            "compile_seconds": compile_seconds,
            "serial_scan_seconds": serial_scan_seconds,
            "concurrent_scan_seconds": concurrent_scan_seconds,
            "rss_before_bytes": rss_before,
            "rss_after_compile_bytes": rss_after_compile,
            "rss_after_scan_bytes": rss_after_scan,
            "rss_growth_bytes": rss_after_scan - rss_before,
            "serial_output_sha256": serial_output_sha256,
            "concurrent_output_sha256s": concurrent_output_sha256s,
        },
        "native": {
            "build_source_sha256": metadata.get("build_source_sha256"),
            "current_build_source_sha256": current_native_build_source_sha256,
            "commit_build_source_sha256": commit_native_build_source_sha256,
            "version": native_engine.__version__,
            "binary_sha256": native_binary_sha256,
            "binary_bytes": native_binary_bytes,
            "entity_count": metadata.get("entity_count"),
            "pattern_count": metadata.get("pattern_count"),
            "regex_resources": regex_resources,
        },
        "environment": {
            "python_implementation": platform.python_implementation(),
            "python_version": platform.python_version(),
            "python_executable_sha256": python_executable_sha256,
            "python_executable_bytes": python_executable_bytes,
            "os": platform.system(),
            "os_release": platform.release(),
            "architecture": platform.machine(),
            "cpu": platform.processor() or platform.machine(),
            "logical_cpu_count": os.cpu_count(),
            "git_commit": git_commit,
            "git_tree_clean": git_tree_clean,
            "clean_commit_required": arguments.require_clean_commit,
        },
        "criteria": criteria,
        "passed": all(criteria.values()),
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

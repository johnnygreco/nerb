"""Portable, aggregate-only publication for the Enron benchmark decision.

The publication boundary deliberately accepts the already committed benchmark
manifest/evidence and aggregate run receipts.  It never reads source messages,
the entity bank, annotations, predictions, or per-document audit material.
"""

from __future__ import annotations

import copy
import hashlib
import html
import json
import math
import os
import re
import shutil
import stat
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn

from .enron_contract import (
    hash_enron_manifest,
    hash_enron_performance_manifest,
    validate_enron_evidence,
    validate_enron_manifest,
)
from .enron_performance import EnronPerformanceError, evaluate_enron_performance_decision

PUBLICATION_SCHEMA = "nerb.enron_publication"
PUBLIC_BANK_CARD_SCHEMA = "nerb.enron_public_bank_card"
MAX_PUBLICATION_FILE_BYTES = 32 * 1024 * 1024
MAX_PUBLICATION_BYTES = 64 * 1024 * 1024
_HASH_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SAFE_ID_RE = re.compile(r"[a-zA-Z0-9_-]{1,128}\Z")
_EMAIL_RE = re.compile(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_FORBIDDEN_PUBLIC_BYTES = (
    b"/Users/",
    b"/home/",
    b"\\Users\\",
    b"agent-scratchpads",
    b".nerb/",
    b".nerb\\",
)
_ROOT_ARTIFACTS = (
    "bank-card.json",
    "benchmark-evidence.json",
    "benchmark-manifest.json",
    "capacity-decision.json",
    "performance-report.json",
    "summary.md",
)
_FIGURE_ARTIFACTS = (
    "figures/bank-coverage.svg",
    "figures/known-bank-contract.svg",
    "figures/performance-scale.svg",
    "figures/standalone-redaction.svg",
)
_CARD_REASON_RE = re.compile(r"[a-z][a-z0-9_]{0,127}\Z")

_COUNT_TRIPLE = {"entities": "count", "names": "count", "patterns": "count"}
_PUBLIC_BANK_CARD_SHAPE: dict[str, Any] = {
    "schema_version": ("const", PUBLIC_BANK_CARD_SCHEMA),
    "benchmark_version": "text",
    "source": {
        "dataset_id": "text",
        "dataset_revision": "text",
        "dataset_split": "text",
        "development_manifest_sha256": "hash",
        "full_split_manifest_sha256": "hash",
        "preparation_manifest_sha256": "hash",
        "split_policy_sha256": "hash",
        "train_artifact_sha256": "hash",
        "train_groups": "count",
        "train_records": "count",
        "validation_artifact_sha256": "hash",
        "validation_groups": "count",
        "validation_records": "count",
    },
    "builder": {
        "policy_sha256": "hash",
        "source_sha256": "hash",
        "candidate_source_sha256": "hash",
        "candidate_ledger_sha256": "hash",
        "train_records": "count",
        "observations": "count",
        "iteration_count": "positive_count",
        "selected_iteration_id": "category",
    },
    "bank": {
        "id": "text",
        "version": "text",
        "canonical_sha256": "hash",
        "artifact_sha256": "hash",
        "canonical_json_bytes": "positive_count",
        "stats": {
            "active_totals": _COUNT_TRIPLE,
            "by_kind": {"literal": "count", "regex": "count"},
            "by_status": {
                "active": _COUNT_TRIPLE,
                "deprecated": _COUNT_TRIPLE,
                "draft": _COUNT_TRIPLE,
                "inactive": _COUNT_TRIPLE,
            },
            "totals": _COUNT_TRIPLE,
        },
    },
    "candidate_funnel": {
        "schema_version": ("const", "nerb.enron_candidate_funnel.v2"),
        "total_candidates": "positive_count",
        "by_decision": {"active": "count", "draft": "count", "rejected": "count"},
        "by_type": (
            "fixed_map",
            {"contact", "contact_fallback", "organization_domain", "person_alias", "phone_fallback"},
            {"active": "count", "draft": "count", "rejected": "count", "total": "count"},
        ),
        "by_primary_reason": ("count_map",),
    },
    "iterations": (
        "list",
        {
            "id": "category",
            "parent_id": "category_or_none",
            "policy_sha256": "hash",
            "bank_sha256": "hash",
            "validation_protocol_sha256": "hash",
            "quality_run_sha256": "hash",
            "contact_labeled_spans": "positive_count",
            "contact_labeled_true_positive": "count",
            "contact_labeled_false_negative": "count",
            "contact_labeled_recall": "ratio",
            "contact_cataloged_false_negative": "count",
            "contact_cataloged_wrong_canonical": "count",
            "person_labeled_spans": "count_or_none",
            "person_cataloged_false_negative": "count_or_none",
            "person_cataloged_wrong_canonical": "count_or_none",
            "open_world_metrics_supported": "bool",
            "utility_metrics_supported": "bool",
            "active_patterns": "positive_count",
            "canonical_json_bytes": "positive_count",
            "decision": ("enum", {"keep", "discard"}),
            "decision_reason_code": "category",
            "selected": "bool",
        },
    ),
    "development_validation": {
        "contact": {
            "catalog_coverage": "ratio_or_none",
            "cataloged_false_negative": "count",
            "cataloged_gold_spans": "count",
            "cataloged_recall": "ratio_or_none",
            "cataloged_true_positive": "count",
            "cataloged_wrong_canonical": "count",
            "documents": "count",
            "documents_with_sensitive_gold": "count",
            "false_negative": "count",
            "gold_spans": "count",
            "labeled_span_recall": "ratio_or_none",
            "negative_document_false_alarm_rate": "ratio_or_none",
            "open_world_recall": "ratio_or_none",
            "over_redaction_rate": "ratio_or_none",
            "precision": "ratio_or_none",
            "true_positive": "count",
        },
        "evaluator_sha256": "hash",
        "label_strength": "category",
        "open_world_metrics_supported": "bool",
        "person": {
            "catalog_coverage": "ratio_or_none",
            "cataloged_false_negative": "count",
            "cataloged_gold_spans": "count",
            "cataloged_recall": "ratio_or_none",
            "cataloged_true_positive": "count",
            "cataloged_wrong_canonical": "count",
            "documents": "count",
            "documents_with_sensitive_gold": "count",
            "evaluated": "bool",
            "false_negative": "count",
            "gold_spans": "count",
            "labeled_span_recall": "ratio_or_none",
            "negative_document_false_alarm_rate": "ratio_or_none",
            "open_world_recall": "ratio_or_none",
            "over_redaction_rate": "ratio_or_none",
            "precision": "ratio_or_none",
            "reason_code": "category",
            "true_positive": "count",
        },
        "protocol_sha256": "hash",
        "quality_run_sha256": "hash",
        "unsupported_reason_code": "category",
        "utility_metrics_supported": "bool",
    },
    "catalog_conformance": {
        "evaluated": "bool",
        "label_artifact_id": "category_or_none",
        "active_patterns": "count",
        "patterns_with_positive_cases": "count",
        "approved_positive_cases": "count",
        "correctly_mapped": "count",
        "missed": "count",
        "wrong_canonical": "count",
        "negative_cases": "count",
        "unexpected_negative_matches": "count",
        "positive_cases_artifact": "artifact_or_none",
        "negative_cases_artifact": "artifact_or_none",
        "policy_sha256": "hash_or_none",
        "recall": "ratio_or_none",
        "passed": "bool",
    },
    "privacy": {
        "aggregate_only": "bool",
        "raw_text_included": "bool",
        "direct_identifiers_included": "bool",
        "bank_values_included": "bool",
        "private_paths_included": "bool",
        "violation_count": "count",
    },
    "card_sha256": "hash",
}


class EnronPublicationError(ValueError):
    """Raised when aggregate evidence cannot be published or verified safely."""

    def __init__(self, message: str, *, code: str = "enron_publication_invalid") -> None:
        super().__init__(message)
        self.code = code


def _fail(message: str, *, code: str = "enron_publication_invalid") -> NoReturn:
    raise EnronPublicationError(message, code=code)


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(
            "utf-8"
        )
    except (TypeError, ValueError):
        _fail("Publication data is not finite JSON.")


def _pretty_json_bytes(value: Any) -> bytes:
    try:
        return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
    except (TypeError, ValueError):
        _fail("Publication data is not finite JSON.")


def _sha256_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _canonical_hash(value: Any) -> str:
    return _sha256_bytes(_canonical_bytes(value))


def _without(mapping: Mapping[str, Any], field: str) -> dict[str, Any]:
    return {key: value for key, value in mapping.items() if key != field}


def _duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            _fail("Publication JSON contains a duplicate key.")
        value[key] = item
    return value


def _read_regular_bytes(path: Path, *, maximum: int = MAX_PUBLICATION_FILE_BYTES) -> bytes:
    try:
        if path.is_symlink():
            _fail("Publication artifacts must not be symbolic links.")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
    except EnronPublicationError:
        raise
    except OSError:
        _fail("Publication artifact could not be opened safely.")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size < 1 or before.st_size > maximum:
            _fail("Publication artifact is not a bounded regular file.")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                _fail("Publication artifact changed while it was read.")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            _fail("Publication artifact changed while it was read.")
        after = os.fstat(descriptor)
        identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if identity_before != identity_after:
            _fail("Publication artifact changed while it was read.")
        return b"".join(chunks)
    except EnronPublicationError:
        raise
    except OSError:
        _fail("Publication artifact could not be read safely.")
    finally:
        os.close(descriptor)


def _load_json(path: Path) -> dict[str, Any]:
    payload = _read_regular_bytes(path)
    try:
        value = json.loads(
            payload.decode("utf-8"),
            parse_constant=lambda _value: _fail("Non-finite JSON is invalid."),
            object_pairs_hook=_duplicate_keys,
        )
    except EnronPublicationError:
        raise
    except (RecursionError, UnicodeDecodeError, ValueError):
        _fail("Publication artifact must contain valid UTF-8 JSON.")
    if type(value) is not dict:
        _fail("Publication JSON roots must be objects.")
    return value


def _load_inventory(path: Path) -> list[dict[str, int]]:
    payload = _read_regular_bytes(path)
    try:
        value = json.loads(
            payload.decode("utf-8"),
            parse_constant=lambda _value: _fail("Non-finite JSON is invalid."),
            object_pairs_hook=_duplicate_keys,
        )
    except EnronPublicationError:
        raise
    except (RecursionError, UnicodeDecodeError, ValueError):
        _fail("Performance inventory must contain valid UTF-8 JSON.")
    if type(value) is not list or not value or len(value) > 10_000:
        _fail("Performance inventory has an invalid shape.")
    normalized: list[dict[str, int]] = []
    for row in value:
        if type(row) is not dict or set(row) != {"bytes", "records"}:
            _fail("Performance inventory has an invalid row.")
        if any(type(row[field]) is not int or row[field] < 0 for field in ("bytes", "records")):
            _fail("Performance inventory has an invalid row.")
        normalized.append({"bytes": row["bytes"], "records": row["records"]})
    return normalized


def _write_new(path: Path, payload: bytes) -> None:
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0), 0o644)
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    _fail("Publication artifact could not be written safely.", code="enron_publication_write_failed")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except EnronPublicationError:
        raise
    except OSError:
        _fail("Publication artifact could not be written safely.", code="enron_publication_write_failed")


def _require_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        _fail("Publication directory does not exist.")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        _fail("Publication root must be a real directory.")


def _resolve_pointer(value: Mapping[str, Any], pointer: str) -> Any:
    current: Any = value
    try:
        for raw_part in pointer.removeprefix("/").split("/"):
            part = raw_part.replace("~1", "/").replace("~0", "~")
            current = current[int(part)] if type(current) is list else current[part]
    except (IndexError, KeyError, TypeError, ValueError):
        _fail("Publication evidence contains an invalid metric pointer.")
    return current


def _find_by_id(items: Sequence[Mapping[str, Any]], identifier: str, description: str) -> Mapping[str, Any]:
    matches = [item for item in items if item.get("id") == identifier]
    if len(matches) != 1:
        _fail(f"Publication evidence must contain exactly one {description}.")
    return matches[0]


def _privacy_scan(files: Mapping[str, bytes]) -> None:
    for relative_path, payload in files.items():
        if any(token in payload for token in _FORBIDDEN_PUBLIC_BYTES) or _EMAIL_RE.search(payload):
            _fail(f"Aggregate privacy scan failed for {relative_path}.")


def _valid_public_count(value: Any, *, positive: bool = False) -> bool:
    return type(value) is int and (value > 0 if positive else value >= 0) and value <= 2**63 - 1


def _valid_public_text(value: Any) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 256
        and all(character >= " " and character != "\x7f" for character in value)
    )


def _validate_closed_public_value(value: Any, shape: Any) -> None:
    if isinstance(shape, dict):
        if type(value) is not dict or set(value) != set(shape):
            _fail("Public bank card has an invalid recursively closed shape.")
        for field, child_shape in shape.items():
            _validate_closed_public_value(value[field], child_shape)
        return
    if isinstance(shape, tuple):
        kind = shape[0]
        if kind == "const":
            valid = value == shape[1]
        elif kind == "enum":
            valid = type(value) is str and value in shape[1]
        elif kind == "list":
            valid = type(value) is list and 1 <= len(value) <= 16
            if valid:
                for item in value:
                    _validate_closed_public_value(item, shape[1])
        elif kind == "fixed_map":
            valid = type(value) is dict and set(value) == shape[1]
            if valid:
                for item in value.values():
                    _validate_closed_public_value(item, shape[2])
        elif kind == "count_map":
            valid = (
                type(value) is dict
                and 1 <= len(value) <= 64
                and all(type(key) is str and _CARD_REASON_RE.fullmatch(key) for key in value)
                and all(_valid_public_count(item) for item in value.values())
            )
        else:  # pragma: no cover - developer-authored shape is static.
            raise AssertionError(f"Unsupported public-card shape marker: {kind}")
        if not valid:
            _fail("Public bank card contains an invalid aggregate category.")
        return
    if shape == "bool":
        valid = type(value) is bool
    elif shape == "count":
        valid = _valid_public_count(value)
    elif shape == "positive_count":
        valid = _valid_public_count(value, positive=True)
    elif shape == "count_or_none":
        valid = value is None or _valid_public_count(value)
    elif shape == "hash":
        valid = type(value) is str and _HASH_RE.fullmatch(value) is not None
    elif shape == "hash_or_none":
        valid = value is None or (type(value) is str and _HASH_RE.fullmatch(value) is not None)
    elif shape == "text":
        valid = _valid_public_text(value)
    elif shape == "text_or_none":
        valid = value is None or _valid_public_text(value)
    elif shape == "category":
        valid = type(value) is str and _CARD_REASON_RE.fullmatch(value) is not None
    elif shape == "category_or_none":
        valid = value is None or (type(value) is str and _CARD_REASON_RE.fullmatch(value) is not None)
    elif shape == "ratio":
        valid = (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(float(value))
            and 0 <= float(value) <= 1
        )
    elif shape == "ratio_or_none":
        valid = value is None or (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(float(value))
            and 0 <= float(value) <= 1
        )
    elif shape == "artifact_or_none":
        if value is None:
            return
        _validate_closed_public_value(value, {"id": "text", "sha256": "hash", "bytes": "positive_count"})
        return
    else:  # pragma: no cover - developer-authored shape is static.
        raise AssertionError(f"Unsupported public-card scalar marker: {shape}")
    if not valid:
        _fail("Public bank card contains an invalid aggregate scalar.")


def _validate_source_bank_card(value: Mapping[str, Any]) -> None:
    try:
        from .enron_bank_workflow import EnronBankBuildError, _validate_public_card

        _validate_public_card(value)
    except (EnronBankBuildError, ImportError, OSError, RuntimeError, TypeError, ValueError):
        _fail("Source bank card failed its closed aggregate validation.")


def _sanitize_bank_card(value: Mapping[str, Any]) -> dict[str, Any]:
    if value.get("schema_version") == PUBLIC_BANK_CARD_SCHEMA:
        existing_card = copy.deepcopy(dict(value))
        _verify_bank_card(existing_card)
        return existing_card
    _validate_source_bank_card(value)
    required = {
        "schema_version",
        "artifact_kind",
        "bank",
        "benchmark_version",
        "builder",
        "candidate_funnel",
        "catalog_conformance",
        "iterations",
        "privacy",
        "source",
        "validation",
    }
    if not required.issubset(value):
        _fail("Source bank card lacks required aggregate fields.")
    privacy = value["privacy"]
    privacy_passed = isinstance(privacy, Mapping) and (
        privacy.get("public_card_privacy_passed") is True
        or (
            privacy.get("status") == "passed"
            and privacy.get("raw_text_included") is False
            and privacy.get("direct_identifiers_included") is False
            and privacy.get("private_paths_included") is False
            and privacy.get("violation_count") == 0
        )
    )
    if not privacy_passed:
        _fail("Source bank card did not pass its aggregate privacy scan.")
    source = value["source"]
    builder = value["builder"]
    bank = value["bank"]
    if not all(isinstance(item, Mapping) for item in (source, builder, bank)):
        _fail("Source bank card has an invalid aggregate shape.")
    iterations: list[dict[str, Any]] = []
    raw_iterations = value["iterations"]
    if not isinstance(raw_iterations, list):
        _fail("Source bank card iterations are invalid.")
    iteration_fields = (
        "id",
        "parent_id",
        "bank_sha256",
        "active_patterns",
        "canonical_json_bytes",
        "contact_cataloged_false_negative",
        "contact_cataloged_wrong_canonical",
        "contact_labeled_false_negative",
        "contact_labeled_recall",
        "contact_labeled_spans",
        "contact_labeled_true_positive",
        "decision",
        "decision_reason_code",
        "open_world_metrics_supported",
        "person_cataloged_false_negative",
        "person_cataloged_wrong_canonical",
        "person_labeled_spans",
        "policy_sha256",
        "quality_run_sha256",
        "selected",
        "utility_metrics_supported",
        "validation_protocol_sha256",
    )
    for item in raw_iterations:
        if not isinstance(item, Mapping) or any(field not in item for field in iteration_fields):
            _fail("Source bank card iteration lacks a required aggregate field.")
        iterations.append({field: copy.deepcopy(item[field]) for field in iteration_fields})
    card: dict[str, Any] = {
        "schema_version": PUBLIC_BANK_CARD_SCHEMA,
        "benchmark_version": value["benchmark_version"],
        "source": {
            field: source[field]
            for field in (
                "dataset_id",
                "dataset_revision",
                "dataset_split",
                "development_manifest_sha256",
                "full_split_manifest_sha256",
                "preparation_manifest_sha256",
                "split_policy_sha256",
                "train_artifact_sha256",
                "train_groups",
                "train_records",
                "validation_artifact_sha256",
                "validation_groups",
                "validation_records",
            )
        },
        "builder": {
            field: builder[field]
            for field in (
                "policy_sha256",
                "source_sha256",
                "candidate_source_sha256",
                "candidate_ledger_sha256",
                "train_records",
                "observations",
                "iteration_count",
                "selected_iteration_id",
            )
        },
        "bank": copy.deepcopy(dict(bank)),
        "candidate_funnel": copy.deepcopy(value["candidate_funnel"]),
        "iterations": iterations,
        "development_validation": copy.deepcopy(value["validation"]),
        "catalog_conformance": copy.deepcopy(value["catalog_conformance"]),
        "privacy": {
            "aggregate_only": True,
            "raw_text_included": False,
            "direct_identifiers_included": False,
            "bank_values_included": False,
            "private_paths_included": False,
            "violation_count": 0,
        },
        "card_sha256": "",
    }
    card["card_sha256"] = _canonical_hash(_without(card, "card_sha256"))
    _verify_bank_card(card)
    return card


def _verify_bank_card(card: Mapping[str, Any]) -> None:
    _validate_closed_public_value(card, _PUBLIC_BANK_CARD_SHAPE)
    expected = {
        "schema_version",
        "benchmark_version",
        "source",
        "builder",
        "bank",
        "candidate_funnel",
        "iterations",
        "development_validation",
        "catalog_conformance",
        "privacy",
        "card_sha256",
    }
    if set(card) != expected or card.get("schema_version") != PUBLIC_BANK_CARD_SCHEMA:
        _fail("Public bank card has an invalid closed shape.")
    if card.get("card_sha256") != _canonical_hash(_without(card, "card_sha256")):
        _fail("Public bank-card hash is invalid.")
    privacy = card.get("privacy")
    if privacy != {
        "aggregate_only": True,
        "raw_text_included": False,
        "direct_identifiers_included": False,
        "bank_values_included": False,
        "private_paths_included": False,
        "violation_count": 0,
    }:
        _fail("Public bank-card privacy state is invalid.")
    funnel = card.get("candidate_funnel")
    bank = card.get("bank")
    iterations = card.get("iterations")
    if not isinstance(funnel, Mapping) or not isinstance(bank, Mapping) or not isinstance(iterations, list):
        _fail("Public bank-card aggregates are invalid.")
    by_decision = funnel.get("by_decision")
    by_type = funnel.get("by_type")
    total = funnel.get("total_candidates")
    if (
        type(total) is not int
        or type(by_decision) is not dict
        or type(by_type) is not dict
        or any(type(value) is not int or value < 0 for value in by_decision.values())
        or sum(by_decision.values()) != total
    ):
        _fail("Public candidate-funnel conservation is invalid.")
    type_total = 0
    for item in by_type.values():
        if type(item) is not dict or set(item) != {"active", "draft", "rejected", "total"}:
            _fail("Public candidate-funnel type aggregate is invalid.")
        if any(type(item[field]) is not int or item[field] < 0 for field in item):
            _fail("Public candidate-funnel type aggregate is invalid.")
        if item["active"] + item["draft"] + item["rejected"] != item["total"]:
            _fail("Public candidate-funnel type conservation is invalid.")
        type_total += item["total"]
    by_reason = funnel["by_primary_reason"]
    stats = bank["stats"]
    status_totals = stats["by_status"]
    if (
        type_total != total
        or sum(by_reason.values()) != total
        or by_decision.get("active") != stats["active_totals"]["patterns"]
        or stats["active_totals"] != status_totals["active"]
        or any(
            stats["totals"][field] != sum(status_totals[status][field] for status in status_totals)
            for field in ("entities", "names", "patterns")
        )
        or stats["by_kind"]["literal"] + stats["by_kind"]["regex"] != stats["totals"]["patterns"]
    ):
        _fail("Public candidate funnel does not bind the selected bank.")
    selected = [item for item in iterations if isinstance(item, Mapping) and item.get("selected") is True]
    builder = card.get("builder")
    if (
        len(selected) != 1
        or not isinstance(builder, Mapping)
        or builder.get("iteration_count") != len(iterations)
        or builder.get("selected_iteration_id") != selected[0].get("id")
        or selected[0].get("bank_sha256") != bank.get("canonical_sha256")
        or selected[0].get("active_patterns") != bank.get("stats", {}).get("active_totals", {}).get("patterns")
    ):
        _fail("Public bank-card iteration selection is invalid.")


def _capacity_phase(capacity: Mapping[str, Any], phase_id: str) -> Mapping[str, Any]:
    report = capacity.get("report")
    phases = report.get("phases") if isinstance(report, Mapping) else None
    if not isinstance(phases, list):
        _fail("Capacity decision lacks phase evidence.")
    matches = [item for item in phases if isinstance(item, Mapping) and item.get("phase") == phase_id]
    if len(matches) != 1 or not isinstance(matches[0].get("commitments"), Mapping):
        _fail("Capacity decision lacks a required phase commitment.")
    return matches[0]["commitments"]


def _verify_capacity_artifact(path: Path) -> dict[str, Any]:
    try:
        from .enron_capacity import EnronCapacityError, verify_portable_capacity_decision
    except (ImportError, OSError, RuntimeError, ValueError):
        _fail("Portable capacity decision verification failed.")
    try:
        return verify_portable_capacity_decision(path, require_production=False)
    except EnronCapacityError:
        _fail("Portable capacity decision verification failed.")
    except (OSError, RuntimeError, ValueError):
        _fail("Portable capacity decision verification failed.")


def _validate_components(
    bundle_dir: Path,
) -> tuple[
    dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], dict[str, list[dict[str, int]]]
]:
    manifest = _load_json(bundle_dir / "benchmark-manifest.json")
    evidence = _load_json(bundle_dir / "benchmark-evidence.json")
    performance_report = _load_json(bundle_dir / "performance-report.json")
    bank_card = _load_json(bundle_dir / "bank-card.json")
    capacity = _verify_capacity_artifact(bundle_dir / "capacity-decision.json")
    manifest_result = validate_enron_manifest(manifest)
    if manifest_result.get("valid") is not True:
        _fail("Published benchmark manifest failed contract validation.")
    performance = evidence.get("performance")
    inputs = performance.get("inputs") if isinstance(performance, Mapping) else None
    if not isinstance(inputs, list):
        _fail("Published performance evidence lacks input descriptors.")
    inventory_refs: dict[str, Mapping[str, Any]] = {}
    for input_descriptor in inputs:
        if not isinstance(input_descriptor, Mapping):
            _fail("Published performance input descriptor is invalid.")
        reference = input_descriptor.get("inventory_ref")
        if reference is None:
            continue
        if not isinstance(reference, Mapping) or not _SAFE_ID_RE.fullmatch(str(reference.get("id", ""))):
            _fail("Published performance inventory reference is invalid.")
        identifier = str(reference["id"])
        prior = inventory_refs.setdefault(identifier, reference)
        if prior != reference:
            _fail("Published performance inventory references conflict.")
    inventories: dict[str, list[dict[str, int]]] = {}
    for identifier, reference in sorted(inventory_refs.items()):
        path = bundle_dir / "inventories" / f"{identifier}.json"
        payload = _read_regular_bytes(path)
        rows = _load_inventory(path)
        if len(payload) != reference.get("bytes") or _sha256_bytes(payload) != reference.get("sha256"):
            _fail("Published performance inventory content address is invalid.")
        inventories[identifier] = rows
    evidence_result = validate_enron_evidence(
        evidence,
        manifest=manifest,
        referenced_input_inventories=inventories,
    )
    if evidence_result.get("valid") is not True:
        _fail("Published benchmark evidence failed semantic contract validation.")
    if (
        performance_report.get("schema_version") != "nerb.enron_performance_run.v1"
        or performance_report.get("benchmark_version") != manifest.get("benchmark_version")
        or performance_report.get("profile") != "decision"
        or performance_report.get("suite") != "enron_cache_value"
        or performance_report.get("performance") != evidence.get("performance")
        or performance_report.get("performance_manifest_sha256") != evidence.get("performance_manifest_sha256")
        or performance_report.get("performance_manifest_sha256")
        != hash_enron_performance_manifest(performance_report["performance"])
        or performance_report.get("software") != evidence.get("software")
        or performance_report.get("environment") != evidence.get("environment")
        or performance_report.get("sealed_test_accessed") is not False
        or performance_report.get("privacy")
        != {
            "status": "passed",
            "raw_text_included": False,
            "direct_identifiers_included": False,
            "private_paths_included": False,
            "violation_count": 0,
        }
        or performance_report.get("run_sha256") != _canonical_hash(_without(performance_report, "run_sha256"))
    ):
        _fail("Published performance report binding is invalid.")
    decision_grade = performance_report.get("decision_grade")
    if (
        not isinstance(decision_grade, Mapping)
        or type(decision_grade.get("passed")) is not bool
        or not isinstance(decision_grade.get("failure_codes"), list)
    ):
        _fail("Published performance decision is invalid.")
    try:
        expected_decision_grade = evaluate_enron_performance_decision(
            performance_report["performance"],
            performance_report["environment"],
            performance_report["software"],
            profile=str(performance_report["profile"]),
        )
    except EnronPerformanceError:
        _fail("Published performance decision could not be recomputed.")
    if decision_grade != expected_decision_grade:
        _fail("Published performance decision differs from the frozen aggregate decision.")
    _verify_bank_card(bank_card)
    if (
        bank_card.get("benchmark_version") != manifest.get("benchmark_version")
        or bank_card.get("catalog_conformance") != evidence.get("catalog_conformance")
        or bank_card.get("bank", {}).get("canonical_sha256") != evidence.get("bank", {}).get("canonical_hash")
        or bank_card.get("bank", {}).get("artifact_sha256") != evidence.get("bank", {}).get("artifact_sha256")
        or bank_card.get("source", {}).get("dataset_id") != evidence.get("source", {}).get("id")
        or bank_card.get("source", {}).get("dataset_revision") != evidence.get("source", {}).get("revision")
        or bank_card.get("source", {}).get("full_split_manifest_sha256")
        != evidence.get("splits", {}).get("manifest_sha256")
    ):
        _fail("Published bank-card binding is invalid.")
    capacity_report = capacity.get("report")
    capacity_totals = capacity_report.get("totals") if isinstance(capacity_report, Mapping) else None
    capacity_gates = capacity_report.get("gates") if isinstance(capacity_report, Mapping) else None
    preparation = _capacity_phase(capacity, "preparation")
    build = _capacity_phase(capacity, "build")
    if (
        not isinstance(capacity_totals, Mapping)
        or not isinstance(capacity_gates, Mapping)
        or type(capacity_gates.get("passed")) is not bool
        or capacity_totals.get("source_rows_accounted") != evidence.get("source", {}).get("input_records")
        or preparation.get("source_row_multiset_sha256") != evidence.get("source", {}).get("content_sha256")
        or preparation.get("prepared_artifact_sha256")
        != evidence.get("preparation", {}).get("prepared_artifact", {}).get("sha256")
        or preparation.get("prepared_records") != evidence.get("preparation", {}).get("output_records")
        or build.get("bank_sha256") != evidence.get("bank", {}).get("canonical_hash")
        or build.get("bank_artifact_sha256") != evidence.get("bank", {}).get("artifact_sha256")
        or build.get("full_split_manifest_sha256") != evidence.get("splits", {}).get("manifest_sha256")
        or build.get("test_records") != evidence.get("splits", {}).get("roles", {}).get("test", {}).get("records")
    ):
        _fail("Published capacity evidence does not bind the benchmark evidence.")
    return manifest, evidence, performance_report, bank_card, capacity, inventories


def _decision_summary(
    evidence: Mapping[str, Any], performance: Mapping[str, Any], capacity: Mapping[str, Any]
) -> dict[str, Any]:
    prediction = evidence["audit_chain"]["prediction_audit"]
    score = evidence["audit_chain"]["score"]
    terminal_quality_eligible = (
        prediction["status"] == "accepted"
        and prediction["release"] == "quality_eligible"
        and prediction["decision_eligible"] is True
        and score["quality_decision_passed"] is True
    )
    performance_passed = performance["decision_grade"]["passed"] is True
    capacity_passed = capacity["report"]["gates"]["passed"] is True
    conformance_passed = evidence["catalog_conformance"]["passed"] is True
    return {
        "standalone_privacy_audit_status": prediction["status"],
        "standalone_privacy_audit_outcome": prediction["release"],
        "catalog_conformance_passed": conformance_passed,
        "capacity_gates_passed": capacity_passed,
        "performance_gates_passed": performance_passed,
        "standalone_privacy_redaction_allowed": (
            terminal_quality_eligible and conformance_passed and performance_passed and capacity_passed
        ),
        "standalone_privacy_redaction_quality_passed": score["quality_decision_passed"],
    }


def _fmt_percent(value: Any) -> str:
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(float(value)):
        return "n/a"
    return f"{float(value):.2%}"


def _fmt_number(value: Any, digits: int = 3) -> str:
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(float(value)):
        return "n/a"
    return f"{float(value):,.{digits}f}"


def _combined_quality_slice(evidence: Mapping[str, Any]) -> Mapping[str, Any] | None:
    quality = evidence["quality"]
    if quality["evaluated"] is False and quality["slices"] == []:
        return None
    return _find_by_id(quality["slices"], "person_contact_all_test", "combined quality slice")


def _planned_audit_documents(manifest: Mapping[str, Any]) -> int | None:
    planned = {
        item["sample_documents"]
        for item in manifest["quality_plan"]
        if item.get("promotion_gate") is True and type(item.get("sample_documents")) is int
    }
    return next(iter(planned)) if len(planned) == 1 else None


def _render_insufficient_support_summary(
    manifest: Mapping[str, Any],
    evidence: Mapping[str, Any],
    performance_report: Mapping[str, Any],
    bank_card: Mapping[str, Any],
    capacity: Mapping[str, Any],
) -> bytes:
    direct = _find_by_id(performance_report["performance"]["workloads"], "real_direct_throughput", "direct workload")
    latency = _find_by_id(performance_report["performance"]["workloads"], "real_direct_latency", "latency workload")
    conformance = evidence["catalog_conformance"]
    decision = _decision_summary(evidence, performance_report, capacity)
    contract_status = "PASS" if decision["catalog_conformance_passed"] else "FAIL"
    planned_documents = _planned_audit_documents(manifest)
    panel_description = (
        f"The preregistered panel called for {planned_documents:,} documents"
        if planned_documents is not None
        else "The preregistered audit panel"
    )
    failure_codes = evidence["audit_chain"]["score"]["support_failure_codes"]
    rendered_codes = ", ".join(f"`{item}`" for item in failure_codes) or "`unspecified_support_failure`"
    capacity_status = "passed" if decision["capacity_gates_passed"] else "failed"
    performance_status = "passed" if decision["performance_gates_passed"] else "failed"
    lines = [
        "# NERB Enron evidence",
        "",
        f"**Known-bank contract evidence: {contract_status}.** NERB detected and correctly mapped "
        f"{conformance['approved_positive_cases']:,} approved cases across all "
        f"{conformance['active_patterns']:,} active patterns, with {conformance['wrong_canonical']:,} wrong canonical "
        f"mappings and {conformance['unexpected_negative_matches']:,} unexpected matches on "
        f"{conformance['negative_cases']:,} required negative and adversarial cases.",
        "",
        "This is the contract NERB is built to make: given the same validated bank, engine, scan options, and input "
        "bytes, qualifying occurrences are detected and mapped under the bank's declared normalization, boundary, "
        "priority, and overlap semantics. It is not a guarantee to discover entities absent from the bank.",
        "",
        "## Known-bank contract",
        "",
        "![Known-bank contract evidence](figures/known-bank-contract.svg)",
        "",
        "## Bank coverage and standalone redaction",
        "",
        f"{panel_description}, selected from the {manifest['splits']['roles']['test']['records']:,}-document sealed "
        f"frame. Scoring ended with insufficient independent support ({rendered_codes}), so bank-coverage, open-world, "
        "and "
        "standalone-redaction rates and miss counts are intentionally unavailable rather than inferred or replaced "
        "with zeros.",
        "",
        "![Bank coverage unavailable](figures/bank-coverage.svg)",
        "",
        "![Standalone redaction unavailable](figures/standalone-redaction.svg)",
        "",
        "## Scale and reuse",
        "",
        f"The evaluated {evidence['bank']['active_patterns']:,}-pattern bank scanned the 100-document throughput input "
        f"in a median {_fmt_number(direct['stats']['median_seconds'] * 1_000, 3)} ms "
        f"({_fmt_number(direct['stats']['documents_per_second'], 1)} documents/s). Per-document direct-scan latency "
        f"was {_fmt_number(latency['stats']['median_seconds'] * 1_000_000, 3)} µs median.",
        "",
        "![Scale throughput](figures/performance-scale.svg)",
        "",
        "## Scope and provenance",
        "",
        f"- Public source rows: {manifest['source']['input_records']:,}; prepared records: "
        f"{manifest['preparation']['output_records']:,}.",
        f"- Sealed test frame: {manifest['splits']['roles']['test']['records']:,} documents; independently scored "
        "quality panel: unavailable because support was insufficient.",
        f"- Candidate funnel: {bank_card['candidate_funnel']['total_candidates']:,} candidates to "
        f"{evidence['bank']['active_patterns']:,} active patterns.",
        f"- Full-source capacity gates: {capacity_status}; performance decision-grade gates: {performance_status}.",
        f"- Frozen measurement commit: `{evidence['software']['git_commit']}`; bank: "
        f"`{evidence['bank']['canonical_hash']}`.",
        "",
        "No tuning, resampling, re-annotation, or rescoring is implied by this terminal result.",
        "",
        "## Reproduce",
        "",
        "```console",
        "uv run nerb verify-enron-evidence --bundle evidence/enron",
        "uv run nerb render-enron-evidence --bundle evidence/enron --output-dir /tmp/nerb-enron-render",
        "```",
        "",
        "Use `--require-standalone-redaction-eligible` only when a workflow requires this particular bank to qualify "
        "as a comprehensive standalone privacy redactor.",
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def _render_summary(
    manifest: Mapping[str, Any],
    evidence: Mapping[str, Any],
    performance_report: Mapping[str, Any],
    bank_card: Mapping[str, Any],
    capacity: Mapping[str, Any],
) -> bytes:
    combined = _combined_quality_slice(evidence)
    if combined is None:
        return _render_insufficient_support_summary(manifest, evidence, performance_report, bank_card, capacity)
    contact = _find_by_id(evidence["quality"]["slices"], "contact_all_test", "contact quality slice")
    person = _find_by_id(evidence["quality"]["slices"], "person_all_test", "person quality slice")
    direct = _find_by_id(performance_report["performance"]["workloads"], "real_direct_throughput", "direct workload")
    latency = _find_by_id(performance_report["performance"]["workloads"], "real_direct_latency", "latency workload")
    compile_workload = _find_by_id(
        performance_report["performance"]["workloads"], "real_cold_compile", "compile workload"
    )
    scale = _find_by_id(performance_report["performance"]["workloads"], "scale_100000_direct", "scale workload")
    conformance = evidence["catalog_conformance"]
    decision = _decision_summary(evidence, performance_report, capacity)
    contract_status = "PASS" if decision["catalog_conformance_passed"] else "FAIL"
    redaction_status = "ELIGIBLE" if decision["standalone_privacy_redaction_allowed"] else "NOT ELIGIBLE"
    metrics = combined["metrics"]
    contact_metrics = contact["metrics"]
    person_metrics = person["metrics"]

    def application_row(label: str, field: str, requirement: str) -> str:
        return (
            f"| {label} | {_fmt_percent(metrics[field])} | {_fmt_percent(contact_metrics[field])} | "
            f"{_fmt_percent(person_metrics[field])} | {requirement} |"
        )

    capacity_status = "passed" if decision["capacity_gates_passed"] else "failed"
    performance_status = "passed" if decision["performance_gates_passed"] else "failed"
    measurement_commit = evidence["software"]["git_commit"]
    bank_hash = evidence["bank"]["canonical_hash"]
    lines = [
        "# NERB Enron evidence",
        "",
        f"**Known-bank contract evidence: {contract_status}.** NERB detected and correctly mapped "
        f"{conformance['approved_positive_cases']:,} approved cases across all "
        f"{conformance['active_patterns']:,} active patterns. It produced {conformance['wrong_canonical']:,} wrong "
        f"canonical mappings and {conformance['unexpected_negative_matches']:,} unexpected matches on "
        f"{conformance['negative_cases']:,} required negative and adversarial cases.",
        "",
        "This is the contract NERB is built to make: given the same validated bank, engine, scan options, and input "
        "bytes, qualifying occurrences are detected and mapped under the bank's declared normalization, boundary, "
        "priority, and overlap semantics. It is not a guarantee to discover entities absent from the bank.",
        "",
        f"**Separate application result: {redaction_status} for standalone PII redaction.** The frozen audit found "
        f"that this constructed bank cataloged only {combined['cataloged_gold_spans']:,} of "
        f"{combined['gold_spans']:,} independently labeled spans. That result limits this bank's use as a "
        "comprehensive redactor; it does not control whether the NERB package can be released.",
        "",
        "The source corpus is public. This bundle remains aggregate-only so the same publication boundary works for "
        "private organizational sources: it contains no source text, bank values, document IDs, span surfaces, or "
        "private paths.",
        "",
        "## 1. Known-bank contract",
        "",
        "| Contract evidence | Result |",
        "|---|---:|",
        f"| Active patterns exercised | {conformance['patterns_with_positive_cases']:,} / "
        f"{conformance['active_patterns']:,} |",
        f"| Approved positives detected and mapped | {conformance['correctly_mapped']:,} / "
        f"{conformance['approved_positive_cases']:,} |",
        f"| Required negative/adversarial cases without unexpected matches | "
        f"{conformance['negative_cases'] - conformance['unexpected_negative_matches']:,} / "
        f"{conformance['negative_cases']:,} |",
        f"| Wrong canonical mappings | {conformance['wrong_canonical']:,} |",
        "",
        "The independent natural-text panel adds a stricter exact-span, class, and canonical-mapping diagnostic. It "
        f"found {combined['cataloged_true_positive']:,} of {combined['cataloged_gold_spans']:,} catalog-qualified "
        f"occurrences exactly ({_fmt_percent(metrics['cataloged_recall'])}), with "
        f"{combined['cataloged_false_negative']} contact exact-span evaluation misses and zero wrong canonical "
        "mappings. Person occurrences "
        f"were {person['cataloged_true_positive']}/{person['cataloged_gold_spans']}; contacts were "
        f"{contact['cataloged_true_positive']}/{contact['cataloged_gold_spans']}. The contact slice still covered "
        "100% of sensitive characters, so exact-span record recall and character coverage answer different questions.",
        "",
        "![Known-bank contract evidence](figures/known-bank-contract.svg)",
        "",
        "## 2. Bank coverage, outside the guarantee",
        "",
        "Catalog coverage asks how much of the independently labeled population the constructed bank knew before "
        "scanning. Open-world recall counts every labeled span, including entities absent from the bank. Neither is "
        "matcher recall.",
        "",
        "| Class | All gold | Cataloged | Outside bank | Catalog coverage |",
        "|---|---:|---:|---:|---:|",
        f"| Combined | {combined['gold_spans']:,} | {combined['cataloged_gold_spans']:,} | "
        f"{combined['gold_spans'] - combined['cataloged_gold_spans']:,} | "
        f"{_fmt_percent(metrics['catalog_coverage'])} |",
        f"| Contact | {contact['gold_spans']:,} | {contact['cataloged_gold_spans']:,} | "
        f"{contact['gold_spans'] - contact['cataloged_gold_spans']:,} | "
        f"{_fmt_percent(contact_metrics['catalog_coverage'])} |",
        f"| Person | {person['gold_spans']:,} | {person['cataloged_gold_spans']:,} | "
        f"{person['gold_spans'] - person['cataloged_gold_spans']:,} | "
        f"{_fmt_percent(person_metrics['catalog_coverage'])} |",
        "",
        f"Of the {combined['false_negative']:,} exact-span misses, "
        f"{combined['false_negative'] - combined['cataloged_false_negative']:,} were person mentions outside the "
        "bank and four were catalog-qualified contact diagnostics.",
        "",
        "![Coverage decomposition](figures/bank-coverage.svg)",
        "",
        "## 3. Standalone privacy-redaction assessment",
        "",
        "The preregistered application gate deliberately asked a broader question: could this bank, by itself, "
        "redact all in-scope person and contact PII? It could not. These frozen results remain important when someone "
        "wants that application, but they are not part of NERB's known-bank guarantee.",
        "",
        "| Application metric | Combined | Contact | Person | Frozen requirement |",
        "|---|---:|---:|---:|---:|",
        application_row("Open-world recall", "open_world_recall", "≥95%"),
        application_row("Catalog coverage", "catalog_coverage", "≥80%"),
        application_row("Cataloged exact-span recall", "cataloged_recall", "100%"),
        application_row("Sensitive-character recall", "sensitive_character_recall", "≥98%"),
        application_row("Document leakage", "document_leak_rate", "≤5%"),
        application_row("Sensitive-character leakage", "sensitive_character_leak_rate", "≤2%"),
        application_row("Precision", "precision", "diagnostic"),
        application_row("Over-redaction", "over_redaction_rate", "≤5%"),
        "",
        "![Standalone privacy-redaction assessment](figures/standalone-redaction.svg)",
        "",
        "## 4. Scale and reuse",
        "",
        f"The evaluated {evidence['bank']['active_patterns']:,}-pattern bank scanned the 100-document throughput "
        "input in a "
        f"median {_fmt_number(direct['stats']['median_seconds'] * 1_000, 3)} ms "
        f"({_fmt_number(direct['stats']['documents_per_second'], 1)} documents/s). Per-document direct-scan "
        "latency was "
        f"{_fmt_number(latency['stats']['median_seconds'] * 1_000_000, 3)} µs median and "
        f"{_fmt_number(latency['stats']['p95_seconds'] * 1_000_000, 3)} µs p95. Cold compilation took "
        f"{_fmt_number(compile_workload['stats']['median_seconds'], 3)} s. At 100,000 patterns, throughput remained "
        f"{_fmt_number(scale['stats']['documents_per_second'], 1)} documents/s on the recorded Apple M4 environment.",
        "",
        "![Scale throughput](figures/performance-scale.svg)",
        "",
        "The value mechanism is compile once, scan many: curated aliases map detected text to canonical entity "
        "metadata, while the compiled bank is reused across messages. Applications decide which entities must be in "
        "the bank; comprehensive redaction additionally requires independently validated population coverage.",
        "",
        "## 5. Scope and provenance",
        "",
        f"- Public source rows: {manifest['source']['input_records']:,}; prepared records: "
        f"{manifest['preparation']['output_records']:,}.",
        f"- Sealed test frame: {manifest['splits']['roles']['test']['records']:,} documents; independently "
        "annotated panel: "
        f"{combined['documents']} documents, {combined['gold_spans']:,} spans, and "
        f"{combined['negative_documents']} exhaustive negatives.",
        f"- Candidate funnel: {bank_card['candidate_funnel']['total_candidates']:,} candidates to "
        f"{evidence['bank']['active_patterns']:,} active patterns.",
        f"- Full-source capacity gates: {capacity_status}; performance decision-grade gates: {performance_status}.",
        f"- Frozen measurement commit: `{measurement_commit}`; bank: `{bank_hash}`.",
        "",
        "The 100 documents were selected by the preregistered deterministic stratified design from the 51,704-document "
        "frame. The result is decision-grade for the frozen panel, not a census, iid estimate, or rare-class "
        "prevalence claim. "
        "No tuning, resampling, re-annotation, or rescoring followed sealed access.",
        "",
        "## Reproduce",
        "",
        "```console",
        "uv run nerb verify-enron-evidence --bundle evidence/enron",
        "uv run nerb render-enron-evidence --bundle evidence/enron --output-dir /tmp/nerb-enron-render",
        "```",
        "",
        "Use `--require-standalone-redaction-eligible` only when a workflow requires this particular bank to qualify "
        "as a comprehensive standalone privacy redactor. This bundle verifies as authentic evidence, while that "
        "application-specific check fails by design.",
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def _svg_chart(
    title: str,
    subtitle: str,
    rows: Sequence[tuple[str, float, str, float | None, str]],
) -> bytes:
    width = 960
    left = 260
    chart_width = 620
    row_height = 62
    height = 120 + row_height * len(rows)
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        'role="img" aria-labelledby="title desc">',
        f'<title id="title">{html.escape(title)}</title>',
        f'<desc id="desc">{html.escape(subtitle)}</desc>',
        '<rect width="100%" height="100%" fill="#0b1020"/>',
        "<style>text{font-family:ui-sans-serif,system-ui,sans-serif;fill:#e8eefc}.title{font-size:25px;font-weight:700}.sub{font-size:14px;fill:#aebbd4}.label{font-size:15px}.value{font-size:14px;font-weight:700}.axis{stroke:#53617d;stroke-width:1}.threshold{stroke:#f7c948;stroke-width:3}</style>",
        f'<text class="title" x="34" y="38">{html.escape(title)}</text>',
        f'<text class="sub" x="34" y="64">{html.escape(subtitle)}</text>',
        f'<line class="axis" x1="{left}" y1="88" x2="{left + chart_width}" y2="88"/>',
    ]
    fills = {"pass": "#29c7a9", "fail": "#f05b67", "neutral": "#65a9ff"}
    for index, (label, value, display, threshold, tone) in enumerate(rows):
        if not 0 <= value <= 1 or (threshold is not None and not 0 <= threshold <= 1):
            _fail("Chart values must be bounded ratios.")
        if tone not in fills:
            _fail("Chart row has an invalid tone.")
        y = 108 + index * row_height
        bar_width = max(1, round(value * chart_width))
        parts.extend(
            (
                f'<text class="label" x="34" y="{y + 22}">{html.escape(label)}</text>',
                f'<rect x="{left}" y="{y}" width="{chart_width}" height="28" rx="5" fill="#202a42"/>',
                f'<rect x="{left}" y="{y}" width="{bar_width}" height="28" rx="5" fill="{fills[tone]}"/>',
                f'<text class="value" x="{left + chart_width - 6}" y="{y + 20}" '
                f'text-anchor="end">{html.escape(display)}</text>',
            )
        )
        if threshold is not None:
            threshold_x = left + round(threshold * chart_width)
            parts.append(f'<line class="threshold" x1="{threshold_x}" y1="{y - 4}" x2="{threshold_x}" y2="{y + 32}"/>')
    parts.append("</svg>\n")
    return "".join(parts).encode("utf-8")


def _svg_coverage_decomposition(slices: Sequence[Mapping[str, Any]]) -> bytes:
    width = 960
    left = 260
    chart_width = 620
    row_height = 74
    height = 154 + row_height * len(slices)
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        'role="img" aria-labelledby="title desc">',
        '<title id="title">Bank coverage decomposition</title>',
        '<desc id="desc">Gold spans are split into cataloged exact matches, cataloged exact-span misses, and entities '
        "outside the bank. Outside-bank spans measure bank construction coverage, not NERB matcher recall.</desc>",
        '<rect width="100%" height="100%" fill="#0b1020"/>',
        "<style>text{font-family:ui-sans-serif,system-ui,sans-serif;fill:#e8eefc}.title{font-size:25px;"
        "font-weight:700}.sub{font-size:14px;fill:#aebbd4}.label{font-size:15px;font-weight:700}.value{font-size:13px;"
        "fill:#cbd6eb}.legend{font-size:13px;fill:#cbd6eb}</style>",
        '<text class="title" x="34" y="38">Bank coverage decomposition</text>',
        '<text class="sub" x="34" y="64">Outside-bank spans are a catalog-construction result, '
        "not matcher misses.</text>",
    ]
    for index, item in enumerate(slices):
        label = str(item["entity_class"]).replace("person_contact", "combined").title()
        total = int(item["gold_spans"])
        exact = int(item["cataloged_true_positive"])
        catalog_miss = int(item["cataloged_false_negative"])
        outside = total - int(item["cataloged_gold_spans"])
        if min(total, exact, catalog_miss, outside) < 0 or exact + catalog_miss + outside != total or total == 0:
            _fail("Coverage decomposition counts are invalid.")
        y = 92 + index * row_height
        summary = f"{exact:,} exact · {catalog_miss:,} catalog miss · {outside:,} outside bank"
        parts.extend(
            (
                f'<text class="label" x="34" y="{y + 18}">{html.escape(label)}</text>',
                f'<text class="value" x="{left}" y="{y + 18}">{html.escape(summary)}</text>',
                f'<rect x="{left}" y="{y + 28}" width="{chart_width}" height="24" rx="4" fill="#202a42"/>',
            )
        )
        cumulative = 0
        for count, fill in ((exact, "#29c7a9"), (catalog_miss, "#f7c948"), (outside, "#71819f")):
            segment_start = left + round(cumulative / total * chart_width)
            cumulative += count
            segment_end = left + round(cumulative / total * chart_width)
            if segment_end > segment_start:
                parts.append(
                    f'<rect x="{segment_start}" y="{y + 28}" width="{segment_end - segment_start}" '
                    f'height="24" fill="{fill}"/>'
                )
    legend_y = 110 + row_height * len(slices)
    parts.extend(
        (
            f'<rect x="260" y="{legend_y}" width="14" height="14" fill="#29c7a9"/>',
            f'<text class="legend" x="282" y="{legend_y + 12}">cataloged + exact</text>',
            f'<rect x="430" y="{legend_y}" width="14" height="14" fill="#f7c948"/>',
            f'<text class="legend" x="452" y="{legend_y + 12}">cataloged exact-span miss</text>',
            f'<rect x="670" y="{legend_y}" width="14" height="14" fill="#71819f"/>',
            f'<text class="legend" x="692" y="{legend_y + 12}">outside bank</text>',
            "</svg>\n",
        )
    )
    return "".join(parts).encode("utf-8")


def _svg_unavailable(title: str, message: str) -> bytes:
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 960 240" role="img" '
        'aria-labelledby="title desc">'
        f'<title id="title">{html.escape(title)}</title>'
        f'<desc id="desc">{html.escape(message)}</desc>'
        '<rect width="100%" height="100%" fill="#0b1020"/>'
        "<style>text{font-family:ui-sans-serif,system-ui,sans-serif;fill:#e8eefc}.title{font-size:25px;"
        "font-weight:700}.message{font-size:17px;fill:#aebbd4}</style>"
        f'<text class="title" x="34" y="52">{html.escape(title)}</text>'
        f'<text class="message" x="34" y="112">{html.escape(message)}</text>'
        '<text class="message" x="34" y="150">No rate or zero-value substitute is reported.</text>'
        "</svg>\n"
    ).encode()


def _render_figures(evidence: Mapping[str, Any], performance_report: Mapping[str, Any]) -> dict[str, bytes]:
    combined = _combined_quality_slice(evidence)
    conformance = evidence["catalog_conformance"]
    workloads = performance_report["performance"]["workloads"]
    scale_specs = (
        ("1,000 patterns", "scale_1000_direct"),
        ("10,000 patterns", "scale_10000_direct"),
        ("25,000 patterns", "scale_25000_direct"),
        ("100,000 patterns", "scale_100000_direct"),
    )
    scale_values = [
        float(_find_by_id(workloads, identifier, f"{label} workload")["stats"]["documents_per_second"])
        for label, identifier in scale_specs
    ]
    maximum = max(scale_values)

    def ratio(numerator: int, denominator: int) -> float:
        return numerator / denominator if denominator else 0.0

    scale_rows = tuple(
        (label, value / maximum, f"{value:,.0f} docs/s", None, "pass")
        for (label, _identifier), value in zip(scale_specs, scale_values, strict=True)
    )
    contract_rows = (
        (
            "Active patterns exercised",
            ratio(conformance["patterns_with_positive_cases"], conformance["active_patterns"]),
            f"{conformance['patterns_with_positive_cases']:,} / {conformance['active_patterns']:,}",
            1.0,
            "pass" if conformance["patterns_with_positive_cases"] == conformance["active_patterns"] else "fail",
        ),
        (
            "Approved cases mapped",
            ratio(conformance["correctly_mapped"], conformance["approved_positive_cases"]),
            f"{conformance['correctly_mapped']:,} / {conformance['approved_positive_cases']:,}",
            1.0,
            "pass" if conformance["correctly_mapped"] == conformance["approved_positive_cases"] else "fail",
        ),
        (
            "Negative cases clean",
            ratio(
                conformance["negative_cases"] - conformance["unexpected_negative_matches"],
                conformance["negative_cases"],
            ),
            f"{conformance['negative_cases'] - conformance['unexpected_negative_matches']:,} / "
            f"{conformance['negative_cases']:,}",
            1.0,
            "pass" if conformance["unexpected_negative_matches"] == 0 else "fail",
        ),
    )
    if combined is None:
        quality_figures = {
            "figures/known-bank-contract.svg": _svg_chart(
                "Known-bank contract evidence",
                "The exhaustive suite exercises every approved pattern and required conformance case.",
                contract_rows,
            ),
            "figures/bank-coverage.svg": _svg_unavailable(
                "Bank coverage unavailable",
                "The terminal audit had insufficient support to calculate population coverage.",
            ),
            "figures/standalone-redaction.svg": _svg_unavailable(
                "Standalone redaction unavailable",
                "The terminal audit had insufficient support to calculate application-level quality.",
            ),
        }
    else:
        metrics = combined["metrics"]
        natural_contract_row = (
            "Natural exact matches",
            float(metrics["cataloged_recall"]),
            f"{combined['cataloged_true_positive']:,} / {combined['cataloged_gold_spans']:,}",
            1.0,
            "pass" if metrics["cataloged_recall"] >= 1.0 else "fail",
        )
        fully_covered_documents = combined["documents_with_sensitive_gold"] - combined["documents_with_any_miss"]
        standalone_rows = (
            (
                "Open-world exact-span recall",
                float(metrics["open_world_recall"]),
                _fmt_percent(metrics["open_world_recall"]),
                0.95,
                "pass" if metrics["open_world_recall"] >= 0.95 else "fail",
            ),
            (
                "Sensitive-character coverage",
                float(metrics["sensitive_character_recall"]),
                _fmt_percent(metrics["sensitive_character_recall"]),
                0.98,
                "pass" if metrics["sensitive_character_recall"] >= 0.98 else "fail",
            ),
            (
                "Fully covered documents",
                1.0 - float(metrics["document_leak_rate"]),
                f"{fully_covered_documents:,} / {combined['documents_with_sensitive_gold']:,}",
                0.95,
                "pass" if metrics["document_leak_rate"] <= 0.05 else "fail",
            ),
            (
                "Precision (diagnostic)",
                float(metrics["precision"]),
                _fmt_percent(metrics["precision"]),
                None,
                "neutral",
            ),
        )
        quality_figures = {
            "figures/known-bank-contract.svg": _svg_chart(
                "Known-bank contract and natural diagnostic",
                "The first three rows are exhaustive conformance; the last is a stricter natural exact-span check.",
                (*contract_rows, natural_contract_row),
            ),
            "figures/bank-coverage.svg": _svg_coverage_decomposition(
                (
                    combined,
                    _find_by_id(evidence["quality"]["slices"], "contact_all_test", "contact quality slice"),
                    _find_by_id(evidence["quality"]["slices"], "person_all_test", "person quality slice"),
                )
            ),
            "figures/standalone-redaction.svg": _svg_chart(
                "Standalone privacy-redaction assessment",
                "This application-level gate includes unknown entities and sits outside NERB's known-bank guarantee.",
                standalone_rows,
            ),
        }
    return {
        **quality_figures,
        "figures/performance-scale.svg": _svg_chart(
            "Direct scan throughput by bank size",
            "Apple M4, 100-document controlled input; bars are normalized to the fastest cell.",
            scale_rows,
        ),
    }


def _rendered_artifacts(
    manifest: Mapping[str, Any],
    evidence: Mapping[str, Any],
    performance_report: Mapping[str, Any],
    bank_card: Mapping[str, Any],
    capacity: Mapping[str, Any],
) -> dict[str, bytes]:
    return {
        "summary.md": _render_summary(manifest, evidence, performance_report, bank_card, capacity),
        **_render_figures(evidence, performance_report),
    }


def _artifact_descriptor(relative_path: str, payload: bytes) -> dict[str, Any]:
    return {"path": relative_path, "sha256": _sha256_bytes(payload), "bytes": len(payload)}


def _publication_manifest(
    files: Mapping[str, bytes],
    manifest: Mapping[str, Any],
    evidence: Mapping[str, Any],
    performance_report: Mapping[str, Any],
    bank_card: Mapping[str, Any],
    capacity: Mapping[str, Any],
) -> dict[str, Any]:
    decision = _decision_summary(evidence, performance_report, capacity)
    combined_quality = _combined_quality_slice(evidence)
    publication: dict[str, Any] = {
        "schema_version": PUBLICATION_SCHEMA,
        "artifact_kind": "aggregate_benchmark_publication",
        "decision": decision,
        "scope": {
            "source_input_rows": manifest["source"]["input_records"],
            "prepared_records": manifest["preparation"]["output_records"],
            "sealed_test_frame_documents": manifest["splits"]["roles"]["test"]["records"],
            "gold_sample_documents": None if combined_quality is None else combined_quality["documents"],
            "gold_spans": None if combined_quality is None else combined_quality["gold_spans"],
            "active_patterns": evidence["bank"]["active_patterns"],
            "candidate_count": bank_card["candidate_funnel"]["total_candidates"],
        },
        "bindings": {
            "benchmark_manifest_sha256": hash_enron_manifest(manifest),
            "evidence_manifest_sha256": evidence["manifest_sha256"],
            "bank_sha256": evidence["bank"]["canonical_hash"],
            "performance_manifest_sha256": evidence["performance_manifest_sha256"],
            "performance_run_sha256": performance_report["run_sha256"],
            "capacity_decision_sha256": capacity["decision_sha256"],
            "audit_chain_sha256": evidence["audit_chain"]["chain_sha256"],
            "gold_sha256": evidence["audit_chain"]["gold"]["gold_sha256"],
            "catalog_binding_sha256": evidence["audit_chain"]["catalog"]["catalog_binding_sha256"],
            "score_manifest_sha256": evidence["audit_chain"]["score"]["manifest_sha256"],
            "prediction_audit_manifest_sha256": evidence["audit_chain"]["prediction_audit"]["manifest_sha256"],
            "measurement_git_commit": evidence["software"]["git_commit"],
        },
        "artifacts": [_artifact_descriptor(path, files[path]) for path in sorted(files)],
        "privacy": {
            "aggregate_only": True,
            "raw_text_included": False,
            "direct_identifiers_included": False,
            "bank_values_included": False,
            "document_ids_included": False,
            "span_surfaces_included": False,
            "private_paths_included": False,
            "violation_count": 0,
        },
        "publication_sha256": "",
    }
    publication["publication_sha256"] = _canonical_hash(_without(publication, "publication_sha256"))
    return publication


def _actual_paths(bundle_dir: Path) -> set[str]:
    paths: set[str] = set()
    total_bytes = 0
    for root, directories, filenames in os.walk(bundle_dir, followlinks=False):
        root_path = Path(root)
        for name in directories:
            child = root_path / name
            if child.is_symlink():
                _fail("Publication directories must not be symbolic links.")
        for name in filenames:
            child = root_path / name
            if child.is_symlink():
                _fail("Publication artifacts must not be symbolic links.")
            relative = child.relative_to(bundle_dir).as_posix()
            paths.add(relative)
            try:
                total_bytes += child.stat().st_size
            except OSError:
                _fail("Publication artifact metadata could not be read.")
    if total_bytes > MAX_PUBLICATION_BYTES:
        _fail("Publication bundle exceeds its total byte limit.")
    return paths


def _verify_publication_manifest(
    publication: Mapping[str, Any],
    *,
    files: Mapping[str, bytes],
    manifest: Mapping[str, Any],
    evidence: Mapping[str, Any],
    performance_report: Mapping[str, Any],
    bank_card: Mapping[str, Any],
    capacity: Mapping[str, Any],
) -> None:
    expected_keys = {
        "schema_version",
        "artifact_kind",
        "decision",
        "scope",
        "bindings",
        "artifacts",
        "privacy",
        "publication_sha256",
    }
    if (
        set(publication) != expected_keys
        or publication.get("schema_version") != PUBLICATION_SCHEMA
        or publication.get("artifact_kind") != "aggregate_benchmark_publication"
        or publication.get("publication_sha256") != _canonical_hash(_without(publication, "publication_sha256"))
    ):
        _fail("Publication manifest has an invalid closed shape or hash.")
    expected = _publication_manifest(files, manifest, evidence, performance_report, bank_card, capacity)
    if publication != expected:
        _fail("Publication manifest does not match the verified aggregate artifacts.")
    if publication.get("privacy") != expected["privacy"]:
        _fail("Publication privacy statement is invalid.")


def _verify_bundle_core(
    bundle_dir: Path,
    *,
    check_generated: bool,
    require_standalone_redaction_eligible: bool,
) -> tuple[dict[str, Any], dict[str, bytes]]:
    _require_directory(bundle_dir)
    manifest, evidence, performance_report, bank_card, capacity, inventories = _validate_components(bundle_dir)
    publication = _load_json(bundle_dir / "publication.json")
    raw_artifacts = publication.get("artifacts")
    if not isinstance(raw_artifacts, list) or not raw_artifacts:
        _fail("Publication manifest lacks its artifact inventory.")
    files: dict[str, bytes] = {}
    for descriptor in raw_artifacts:
        if type(descriptor) is not dict or set(descriptor) != {"path", "sha256", "bytes"}:
            _fail("Publication artifact descriptor has an invalid shape.")
        relative = descriptor.get("path")
        if type(relative) is not str:
            _fail("Publication artifact path is invalid.")
        pure = PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts or relative == "publication.json" or relative in files:
            _fail("Publication artifact path is unsafe or duplicated.")
        payload = _read_regular_bytes(bundle_dir / Path(*pure.parts))
        if descriptor.get("bytes") != len(payload) or descriptor.get("sha256") != _sha256_bytes(payload):
            _fail("Publication artifact hash or byte count is invalid.")
        files[relative] = payload
    expected_inventory_paths = {f"inventories/{identifier}.json" for identifier in inventories}
    expected_paths = {*_ROOT_ARTIFACTS, *_FIGURE_ARTIFACTS, *expected_inventory_paths}
    if set(files) != expected_paths or _actual_paths(bundle_dir) != {"publication.json", *expected_paths}:
        _fail("Publication bundle contains a missing or undeclared artifact.")
    if check_generated:
        expected_generated = _rendered_artifacts(manifest, evidence, performance_report, bank_card, capacity)
        if any(files[path] != payload for path, payload in expected_generated.items()):
            _fail("Committed summary or figure is stale.")
    _privacy_scan({**files, "publication.json": _read_regular_bytes(bundle_dir / "publication.json")})
    _verify_publication_manifest(
        publication,
        files=files,
        manifest=manifest,
        evidence=evidence,
        performance_report=performance_report,
        bank_card=bank_card,
        capacity=capacity,
    )
    decision = publication["decision"]
    if require_standalone_redaction_eligible and decision["standalone_privacy_redaction_allowed"] is not True:
        _fail(
            "The verified evidence is valid, but the evaluated bank is not eligible for standalone privacy redaction.",
            code="enron_standalone_redaction_ineligible",
        )
    result = {
        "valid": True,
        "schema_version": publication["schema_version"],
        "publication_sha256": publication["publication_sha256"],
        "decision": copy.deepcopy(decision),
        "bindings": copy.deepcopy(publication["bindings"]),
        "artifacts_verified": len(files),
        "privacy": copy.deepcopy(publication["privacy"]),
    }
    return result, _rendered_artifacts(manifest, evidence, performance_report, bank_card, capacity)


def verify_enron_publication(
    bundle_dir: Path, *, require_standalone_redaction_eligible: bool = False
) -> dict[str, Any]:
    """Verify a clean-clone publication, including hashes, arithmetic, privacy, and terminal decision."""

    result, _generated = _verify_bundle_core(
        Path(bundle_dir),
        check_generated=True,
        require_standalone_redaction_eligible=require_standalone_redaction_eligible,
    )
    return result


def render_enron_publication(bundle_dir: Path, output_dir: Path) -> dict[str, Any]:
    """Regenerate the summary and figures into a new directory from committed aggregates only."""

    result, generated = _verify_bundle_core(
        Path(bundle_dir),
        check_generated=True,
        require_standalone_redaction_eligible=False,
    )
    output = Path(output_dir)
    if output.exists() or output.is_symlink():
        _fail("Render output directory must not already exist.", code="enron_publication_write_failed")
    try:
        output.mkdir(mode=0o755, parents=False)
        (output / "figures").mkdir(mode=0o755)
        for relative, payload in sorted(generated.items()):
            _write_new(output / relative, payload)
    except BaseException:
        shutil.rmtree(output, ignore_errors=True)
        raise
    return {
        "valid": True,
        "source_publication_sha256": result["publication_sha256"],
        "artifacts": [_artifact_descriptor(path, generated[path]) for path in sorted(generated)],
    }


def export_enron_publication(
    output_dir: Path,
    *,
    benchmark_manifest_path: Path,
    benchmark_evidence_path: Path,
    performance_report_path: Path,
    capacity_decision_path: Path,
    bank_card_path: Path,
    inventory_dir: Path,
    require_standalone_redaction_eligible: bool = False,
) -> dict[str, Any]:
    """Create one immutable aggregate publication without reading private per-record artifacts."""

    output = Path(output_dir)
    parent = output.parent
    _require_directory(parent)
    if output.exists() or output.is_symlink():
        _fail("Publication output directory must not already exist.", code="enron_publication_write_failed")
    manifest = _load_json(Path(benchmark_manifest_path))
    evidence = _load_json(Path(benchmark_evidence_path))
    performance_report = _load_json(Path(performance_report_path))
    capacity_payload = _read_regular_bytes(Path(capacity_decision_path))
    bank_card = _sanitize_bank_card(_load_json(Path(bank_card_path)))
    performance = evidence.get("performance")
    inputs = performance.get("inputs") if isinstance(performance, Mapping) else None
    if not isinstance(inputs, list):
        _fail("Benchmark evidence lacks performance inventory references.")
    inventory_payloads: dict[str, bytes] = {}
    for descriptor in inputs:
        reference = descriptor.get("inventory_ref") if isinstance(descriptor, Mapping) else None
        if reference is None:
            continue
        identifier = str(reference.get("id", "")) if isinstance(reference, Mapping) else ""
        if not _SAFE_ID_RE.fullmatch(identifier):
            _fail("Benchmark evidence contains an unsafe inventory id.")
        payload = _read_regular_bytes(Path(inventory_dir) / f"{identifier}.json")
        if len(payload) != reference.get("bytes") or _sha256_bytes(payload) != reference.get("sha256"):
            _fail("Source performance inventory content address is invalid.")
        inventory_payloads[f"inventories/{identifier}.json"] = payload
    base_files: dict[str, bytes] = {
        "benchmark-manifest.json": _pretty_json_bytes(manifest),
        "benchmark-evidence.json": _pretty_json_bytes(evidence),
        "performance-report.json": _pretty_json_bytes(performance_report),
        "capacity-decision.json": capacity_payload,
        "bank-card.json": _pretty_json_bytes(bank_card),
        **inventory_payloads,
    }
    stage = Path(tempfile.mkdtemp(prefix=".enron-publication-", dir=parent))
    try:
        (stage / "inventories").mkdir(mode=0o755)
        (stage / "figures").mkdir(mode=0o755)
        for relative, payload in sorted(base_files.items()):
            _write_new(stage / relative, payload)
        verified_manifest, verified_evidence, verified_performance, verified_card, verified_capacity, _inventories = (
            _validate_components(stage)
        )
        generated = _rendered_artifacts(
            verified_manifest,
            verified_evidence,
            verified_performance,
            verified_card,
            verified_capacity,
        )
        for relative, payload in sorted(generated.items()):
            _write_new(stage / relative, payload)
        all_files = {**base_files, **generated}
        publication = _publication_manifest(
            all_files,
            verified_manifest,
            verified_evidence,
            verified_performance,
            verified_card,
            verified_capacity,
        )
        _write_new(stage / "publication.json", _pretty_json_bytes(publication))
        result = verify_enron_publication(
            stage,
            require_standalone_redaction_eligible=require_standalone_redaction_eligible,
        )
        os.replace(stage, output)
        return result
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise


__all__ = [
    "EnronPublicationError",
    "PUBLICATION_SCHEMA",
    "export_enron_publication",
    "render_enron_publication",
    "verify_enron_publication",
]

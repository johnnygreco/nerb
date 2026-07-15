"""Prediction-independent catalog qualification for frozen Enron gold spans.

Qualification inspects active bank definitions directly.  It deliberately does
not call ``Bank.scan`` or consume benchmark predictions, so an engine miss
cannot cause an otherwise cataloged occurrence to be relabeled as unknown.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
import stat
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .bank import canonicalize_bank, hash_bank
from .enron_gold_annotations import (
    EnronGoldAnnotationError,
    _load_verified_enron_gold_annotations_files,
    _load_verified_enron_gold_role_identities,
    enron_gold_annotation_policy_sha256,
)
from .enron_private_io import (
    EnronPrivateIOError,
    PrivateRun,
    is_owner_only_private_mode,
    iter_strict_jsonl,
    open_private_binary_input,
    open_private_binary_input_at,
    open_private_directory_input,
)
from .enron_sealed_audit import AUDIT_EXECUTION_POLICY_SHA256
from .schema import validate_bank_schema

CATALOG_POLICY_SCHEMA_VERSION = "nerb.enron_catalog_qualification_policy"
CATALOG_BINDING_SCHEMA_VERSION = "nerb.enron_catalog_bindings"
CATALOG_REVIEW_SCHEMA_VERSION = "nerb.enron_catalog_review"
CATALOG_PUBLIC_RECEIPT_SCHEMA_VERSION = "nerb.enron_catalog_public_receipt"
CATALOG_RUN_MANIFEST_SCHEMA_VERSION = "nerb.enron_catalog_qualification_run"
CATALOG_RUN_RECEIPT_SCHEMA_VERSION = "nerb.enron_catalog_qualification_run_receipt"

_COMMIT_PAYLOAD = b"nerb.enron.private-run.v2\n"
_RUN_FILES = frozenset({"COMMITTED", "binding.jsonl", "catalog-review.jsonl", "manifest.json", "receipt.json"})
_BINDING_FIELDS = frozenset({"document_id", "entity_class", "start", "end", "catalog_identity"})
_CATALOG_IDENTITY_FIELDS = frozenset({"entity_id", "name_id", "pattern_id"})
_CATALOG_REVIEW_FIELDS = frozenset(
    {
        "schema_version",
        "document_id",
        "text_sha256",
        "bank_sha256",
        "gold_sha256",
        "reviewer_id",
        "decisions",
        "unresolved",
    }
)
_CATALOG_REVIEW_DECISION_FIELDS = frozenset({"entity_class", "start", "end", "catalog_identity"})
_GOLD_COMMITMENT_FIELDS = frozenset({"gold_sha256", "manifest_sha256", "artifacts_sha256"})
_MAX_BANK_BYTES = 64 * 1024 * 1024
_MAX_METADATA_BYTES = 16 * 1024 * 1024
_MAX_BINDING_LINE_BYTES = 1024 * 1024
_MAX_BINDINGS = 1_000_000
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

_SUPPORTED_GENERIC_EMAIL_REGEX = (
    r"(?i)\b[a-z0-9_][a-z0-9.!#$%&'*+/=?^_`{|}~-]*@"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\b"
)

_SUPPORTED_ENTITY_CLASSES = frozenset({"contact", "person"})
_FLAG_MAP = {
    "IGNORECASE": re.IGNORECASE,
    "MULTILINE": re.MULTILINE,
    "DOTALL": re.DOTALL,
    "VERBOSE": re.VERBOSE,
    "ASCII": re.ASCII,
}

CATALOG_QUALIFICATION_POLICY: dict[str, Any] = {
    "schema_version": CATALOG_POLICY_SCHEMA_VERSION,
    "input": "immutable_independent_gold",
    "prediction_visibility": "forbidden",
    "review": "one_bounded_private_reviewer_distinct_from_all_gold_roles_exactly_replays_active_bank_qualification",
    "bank_scope": "active_bank_entity_name_pattern_chain",
    "literal_matching": "native_rust_conservative_ascii_fold_exact_whitespace_and_regex_syntax_word_boundary",
    "regex_matching": "closed_ascii_exact_context_subset",
    "winner": "ascending_priority_then_name_id_then_pattern_id",
    "catalog_identity": "entity_name_and_one_qualifying_active_pattern",
    "supported_active_regex_sha256": "sha256:"
    + hashlib.sha256(_SUPPORTED_GENERIC_EMAIL_REGEX.encode("ascii")).hexdigest(),
    "unsupported_semantics": "never_qualify_or_reject_bank",
}

_native_engine = importlib.import_module("nerb._engine")


class EnronCatalogAdjudicationError(ValueError):
    """Raised when catalog qualification cannot be completed independently."""


@dataclass(frozen=True, slots=True)
class _Pattern:
    entity_id: str
    name_id: str
    pattern_id: str
    priority: int
    kind: str
    value: str
    flags: int
    case_sensitive: bool | None
    normalize_whitespace: bool | None
    left_boundary: str | None
    right_boundary: str | None
    compiled: re.Pattern[str] | None

    @property
    def identity(self) -> tuple[str, str, str]:
        return self.entity_id, self.name_id, self.pattern_id


def enron_catalog_qualification_policy_sha256() -> str:
    """Return the canonical catalog-qualification policy commitment."""

    return _canonical_hash(CATALOG_QUALIFICATION_POLICY)


def qualify_enron_gold_catalog(
    bank: Mapping[str, Any],
    documents: Sequence[Mapping[str, Any]],
    gold: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind each private gold span to a qualifying active pattern or ``None``."""

    canonical_bank = _prepare_bank(bank)
    document_map = _prepare_documents(documents)
    gold_documents, gold_sha256 = _prepare_gold(gold, document_map)
    catalog = _active_catalog(canonical_bank)
    bindings: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    class_counts: dict[str, Counter[str]] = defaultdict(Counter)
    for gold_document in gold_documents:
        document_id = str(gold_document["document_id"])
        text = document_map[document_id]
        for span in gold_document["spans"]:
            entity_class = str(span["entity_class"])
            start = int(span["start"])
            end = int(span["end"])
            candidates = [
                pattern
                for pattern in catalog.get(entity_class, ())
                if _pattern_matches_exact_context(pattern, text, start, end)
            ]
            candidates.sort(key=lambda item: (item.priority, item.name_id, item.pattern_id))
            selected = candidates[0] if candidates else None
            catalog_identity = (
                None
                if selected is None
                else {
                    "entity_id": selected.entity_id,
                    "name_id": selected.name_id,
                    "pattern_id": selected.pattern_id,
                }
            )
            bindings.append(
                {
                    "document_id": document_id,
                    "entity_class": entity_class,
                    "start": start,
                    "end": end,
                    "catalog_identity": catalog_identity,
                }
            )
            counts["gold_spans"] += 1
            class_counts[entity_class]["gold_spans"] += 1
            if selected is not None:
                counts["cataloged_gold_spans"] += 1
                class_counts[entity_class]["cataloged_gold_spans"] += 1
    bindings.sort(key=lambda item: (item["document_id"], item["start"], item["end"], item["entity_class"]))
    aggregate_counts = {
        "gold_spans": counts["gold_spans"],
        "cataloged_gold_spans": counts["cataloged_gold_spans"],
        "uncataloged_gold_spans": counts["gold_spans"] - counts["cataloged_gold_spans"],
        "by_class": {
            entity_class: {
                "gold_spans": class_counts[entity_class]["gold_spans"],
                "cataloged_gold_spans": class_counts[entity_class]["cataloged_gold_spans"],
                "uncataloged_gold_spans": (
                    class_counts[entity_class]["gold_spans"] - class_counts[entity_class]["cataloged_gold_spans"]
                ),
            }
            for entity_class in sorted(_SUPPORTED_ENTITY_CLASSES)
        },
    }
    core = {
        "schema_version": CATALOG_BINDING_SCHEMA_VERSION,
        "bank_sha256": hash_bank(canonical_bank),
        "gold_sha256": gold_sha256,
        "policy_sha256": enron_catalog_qualification_policy_sha256(),
        "bindings": bindings,
        "counts": aggregate_counts,
    }
    return {**core, "catalog_binding_sha256": _canonical_hash(core)}


def public_enron_catalog_receipt(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return aggregate catalog coverage without coordinates or identities."""

    expected = {
        "schema_version",
        "bank_sha256",
        "gold_sha256",
        "policy_sha256",
        "bindings",
        "counts",
        "catalog_binding_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise EnronCatalogAdjudicationError("Catalog binding artifact schema is invalid.")
    core = {key: value[key] for key in value if key != "catalog_binding_sha256"}
    if value["catalog_binding_sha256"] != _canonical_hash(core):
        raise EnronCatalogAdjudicationError("Catalog binding commitment is invalid.")
    gold_spans = value["counts"].get("gold_spans") if isinstance(value["counts"], Mapping) else None
    cataloged = value["counts"].get("cataloged_gold_spans") if isinstance(value["counts"], Mapping) else None
    if type(gold_spans) is not int or type(cataloged) is not int or gold_spans < 0 or not 0 <= cataloged <= gold_spans:
        raise EnronCatalogAdjudicationError("Catalog binding aggregate counts are invalid.")
    return {
        "schema_version": CATALOG_PUBLIC_RECEIPT_SCHEMA_VERSION,
        "bank_sha256": value["bank_sha256"],
        "gold_sha256": value["gold_sha256"],
        "policy_sha256": value["policy_sha256"],
        "catalog_binding_sha256": value["catalog_binding_sha256"],
        "counts": value["counts"],
        "catalog_coverage": None if gold_spans == 0 else cataloged / gold_spans,
        "privacy": {
            "raw_text_included": False,
            "document_ids_included": False,
            "span_coordinates_included": False,
            "catalog_identities_included": False,
            "private_paths_included": False,
        },
    }


def finalize_enron_catalog_qualification_files(
    sample_run_dir: Path,
    gold_run_dir: Path,
    bank: Mapping[str, Any] | Path,
    catalog_review_path: Path,
    output_dir: Path,
    *,
    expected_audit_output_binding_sha256: str | None = None,
    expected_gold_commitment: Mapping[str, str] | None = None,
    gold_state_dir: Path | None = None,
    allow_unignored_output: bool = False,
) -> dict[str, Any]:
    """Commit prediction-blind per-span catalog bindings before scoring."""

    try:
        documents, gold, gold_receipt = _load_verified_enron_gold_annotations_files(
            Path(gold_run_dir),
            Path(sample_run_dir),
            expected_audit_output_binding_sha256=expected_audit_output_binding_sha256,
            expected_gold_commitment=expected_gold_commitment,
            gold_state_dir=gold_state_dir,
        )
        _validate_upstream_policy_bindings(gold_receipt)
        trusted_gold_commitment = _trusted_gold_commitment(gold_receipt, expected_gold_commitment)
        canonical_bank, bank_artifact = _load_catalog_bank(bank)
        _validate_planned_bank_binding(gold_receipt, canonical_bank)
        qualification = qualify_enron_gold_catalog(canonical_bank, documents, gold)
        review_rows, _source_review_descriptor = _load_catalog_review_jsonl(
            Path(catalog_review_path),
            require_canonical=False,
        )
        canonical_review_rows, reviewer_id, review_counts = _prepare_catalog_reviews(
            review_rows,
            documents,
            qualification,
        )
        _reject_gold_role_reuse(
            reviewer_id,
            _load_verified_enron_gold_role_identities(Path(gold_run_dir), gold_receipt),
        )
        review_payload = _canonical_jsonl(canonical_review_rows)
        review_artifact = _artifact_descriptor("catalog-review.jsonl", review_payload, len(canonical_review_rows))
        review_provenance = _catalog_review_provenance(reviewer_id, review_artifact, review_counts)
        binding_rows = tuple(qualification["bindings"])
        binding_payload = _canonical_jsonl(binding_rows)
        binding_artifact = _artifact_descriptor("binding.jsonl", binding_payload, len(binding_rows))
        manifest = _catalog_run_manifest(
            gold_receipt,
            trusted_gold_commitment,
            bank_artifact,
            binding_artifact,
            review_artifact,
            review_provenance,
            qualification,
        )
        receipt = _catalog_run_receipt(manifest)

        with PrivateRun(Path(output_dir), allow_unignored_output=allow_unignored_output) as run:
            with run.open_binary("binding.jsonl") as file:
                file.write(binding_payload)
            with run.open_binary("catalog-review.jsonl") as file:
                file.write(review_payload)
            with run.open_binary("manifest.json") as file:
                file.write(_canonical_json_file(manifest))
            with run.open_binary("receipt.json") as file:
                file.write(_canonical_json_file(receipt))
            run.commit()
        return _detached_mapping(receipt)
    except EnronCatalogAdjudicationError:
        raise
    except (EnronGoldAnnotationError, EnronPrivateIOError, OSError, TypeError, ValueError):
        raise EnronCatalogAdjudicationError("Catalog qualification files could not be finalized safely.") from None


def verify_enron_catalog_qualification(
    run_dir: Path,
    sample_run_dir: Path,
    gold_run_dir: Path,
    bank: Mapping[str, Any] | Path,
    *,
    expected_audit_output_binding_sha256: str | None = None,
    expected_gold_commitment: Mapping[str, str] | None = None,
    gold_state_dir: Path | None = None,
) -> dict[str, Any]:
    """Replay a committed catalog qualification and return aggregate evidence."""

    try:
        documents, gold, gold_receipt = _load_verified_enron_gold_annotations_files(
            Path(gold_run_dir),
            Path(sample_run_dir),
            expected_audit_output_binding_sha256=expected_audit_output_binding_sha256,
            expected_gold_commitment=expected_gold_commitment,
            gold_state_dir=gold_state_dir,
        )
        _validate_upstream_policy_bindings(gold_receipt)
        trusted_gold_commitment = _trusted_gold_commitment(gold_receipt, expected_gold_commitment)
        canonical_bank, bank_artifact = _load_catalog_bank(bank)
        _validate_planned_bank_binding(gold_receipt, canonical_bank)
        expected = qualify_enron_gold_catalog(canonical_bank, documents, gold)

        root = _validate_private_run_tree(Path(run_dir))
        bindings, binding_descriptor = _load_binding_jsonl(root / "binding.jsonl")
        if bindings != expected["bindings"]:
            raise EnronCatalogAdjudicationError("Stored catalog bindings differ from direct qualification replay.")
        stored_review_rows, review_descriptor = _load_catalog_review_jsonl(
            root / "catalog-review.jsonl",
            require_canonical=True,
        )
        canonical_review_rows, reviewer_id, review_counts = _prepare_catalog_reviews(
            stored_review_rows,
            documents,
            expected,
        )
        _reject_gold_role_reuse(
            reviewer_id,
            _load_verified_enron_gold_role_identities(Path(gold_run_dir), gold_receipt),
        )
        if stored_review_rows != list(canonical_review_rows):
            raise EnronCatalogAdjudicationError("Stored catalog review rows are not in canonical order.")
        manifest, manifest_raw = _load_strict_json_object(root / "manifest.json", "Catalog qualification manifest")
        receipt, receipt_raw = _load_strict_json_object(root / "receipt.json", "Catalog qualification receipt")
        if manifest_raw != _canonical_json_file(manifest) or receipt_raw != _canonical_json_file(receipt):
            raise EnronCatalogAdjudicationError("Catalog qualification metadata is not canonically encoded.")
        binding_artifact = {"name": "binding.jsonl", **binding_descriptor}
        review_artifact = {"name": "catalog-review.jsonl", **review_descriptor}
        review_provenance = _catalog_review_provenance(reviewer_id, review_artifact, review_counts)
        expected_manifest = _catalog_run_manifest(
            gold_receipt,
            trusted_gold_commitment,
            bank_artifact,
            binding_artifact,
            review_artifact,
            review_provenance,
            expected,
        )
        if manifest != expected_manifest:
            raise EnronCatalogAdjudicationError("Catalog qualification manifest differs from replay.")
        expected_receipt = _catalog_run_receipt(expected_manifest)
        if receipt != expected_receipt:
            raise EnronCatalogAdjudicationError("Catalog qualification receipt differs from replay.")
        return _detached_mapping(expected_receipt)
    except EnronCatalogAdjudicationError:
        raise
    except (EnronGoldAnnotationError, EnronPrivateIOError, OSError, TypeError, ValueError):
        raise EnronCatalogAdjudicationError("Catalog qualification run could not be verified safely.") from None


def _load_verified_enron_catalog_qualification_files(
    run_dir: Path,
    sample_run_dir: Path,
    gold_run_dir: Path,
    bank: Mapping[str, Any] | Path,
    *,
    expected_audit_output_binding_sha256: str | None = None,
    expected_gold_commitment: Mapping[str, str] | None = None,
    gold_state_dir: Path | None = None,
) -> tuple[list[dict[str, Any]], str, dict[str, Any]]:
    """Load private bindings only after full sample, gold, bank, and run replay.

    Downstream scorers should call this helper once and consume its returned
    rows.  They must not reopen ``binding.jsonl`` or independently rescan the
    bank to reconstruct catalog status.
    """

    receipt = verify_enron_catalog_qualification(
        run_dir,
        sample_run_dir,
        gold_run_dir,
        bank,
        expected_audit_output_binding_sha256=expected_audit_output_binding_sha256,
        expected_gold_commitment=expected_gold_commitment,
        gold_state_dir=gold_state_dir,
    )
    root = _validate_private_run_tree(run_dir)
    rows, descriptor = _load_binding_jsonl(root / "binding.jsonl")
    if descriptor["sha256"] != receipt["binding_artifact_sha256"]:
        raise EnronCatalogAdjudicationError("Verified catalog bindings changed before loading.")
    review_rows, review_descriptor = _load_catalog_review_jsonl(root / "catalog-review.jsonl", require_canonical=True)
    if review_descriptor["sha256"] != receipt["review_artifact_sha256"]:
        raise EnronCatalogAdjudicationError("Verified catalog review changed before loading.")
    reviewer_ids = {str(row["reviewer_id"]) for row in review_rows}
    if len(reviewer_ids) != 1:
        raise EnronCatalogAdjudicationError("Verified catalog review does not have one reviewer identity.")
    return rows, reviewer_ids.pop(), receipt


def _validate_upstream_policy_bindings(gold_receipt: Mapping[str, Any]) -> None:
    if (
        gold_receipt.get("valid") is not True
        or gold_receipt.get("annotation_policy_sha256") != enron_gold_annotation_policy_sha256()
        or gold_receipt.get("catalog_policy_sha256") != enron_catalog_qualification_policy_sha256()
        or gold_receipt.get("audit_execution_policy_sha256") != AUDIT_EXECUTION_POLICY_SHA256
        or not isinstance(gold_receipt.get("audit_plan_sha256"), str)
        or not isinstance(gold_receipt.get("audit_output_binding_sha256"), str)
        or not isinstance(gold_receipt.get("sample_artifact_sha256"), str)
        or not isinstance(gold_receipt.get("gold_sha256"), str)
        or not isinstance(gold_receipt.get("planned_bank_sha256"), str)
        or not isinstance(gold_receipt.get("planned_evaluator_source_sha256"), str)
        or not isinstance(gold_receipt.get("planned_thresholds_sha256"), str)
    ):
        raise EnronCatalogAdjudicationError(
            "Gold run does not bind the current annotation and catalog qualification policies."
        )


def _validate_planned_bank_binding(gold_receipt: Mapping[str, Any], bank: Mapping[str, Any]) -> None:
    if gold_receipt.get("planned_bank_sha256") != hash_bank(bank):
        raise EnronCatalogAdjudicationError("Catalog bank differs from the bank frozen in the audit plan.")


def _trusted_gold_commitment(
    gold_receipt: Mapping[str, Any],
    expected_gold_commitment: Mapping[str, str] | None,
) -> dict[str, str]:
    actual = {key: gold_receipt.get(key) for key in sorted(_GOLD_COMMITMENT_FIELDS)}
    if any(not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None for value in actual.values()):
        raise EnronCatalogAdjudicationError("Gold receipt commitments are invalid.")
    if expected_gold_commitment is None:
        if gold_receipt.get("fixture_mode") is not True:
            raise EnronCatalogAdjudicationError(
                "Production catalog qualification requires an explicit trusted gold commitment."
            )
    elif (
        not isinstance(expected_gold_commitment, Mapping)
        or set(expected_gold_commitment) != _GOLD_COMMITMENT_FIELDS
        or any(
            not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None
            for value in expected_gold_commitment.values()
        )
        or dict(expected_gold_commitment) != actual
    ):
        raise EnronCatalogAdjudicationError(
            "Trusted gold commitment is invalid or does not match the verified gold run."
        )
    return {key: str(actual[key]) for key in sorted(actual)}


def _load_catalog_bank(source: Mapping[str, Any] | Path) -> tuple[dict[str, Any], dict[str, Any]]:
    if isinstance(source, Mapping):
        value: Any = source
    elif isinstance(source, Path):
        raw = _read_regular_file(source, _MAX_BANK_BYTES, "Catalog bank")
        value = _decode_strict_json(raw, "Catalog bank")
    else:
        raise EnronCatalogAdjudicationError("Catalog bank must be a mapping or Path.")
    if not isinstance(value, Mapping):
        raise EnronCatalogAdjudicationError("Catalog bank must contain one JSON object.")
    canonical = _prepare_bank(value)
    payload = _canonical_json_file(canonical)
    return canonical, {"sha256": _hash_bytes(payload), "bytes": len(payload)}


def _read_regular_file(path: Path, maximum: int, description: str) -> bytes:
    candidate = _absolute_path(path)
    descriptor: int | None = None
    try:
        descriptor = os.open(
            candidate,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise EnronCatalogAdjudicationError(f"{description} must be a single-link regular file.")
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > maximum:
                raise EnronCatalogAdjudicationError(f"{description} exceeds the byte limit.")
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or after.st_nlink != 1:
            raise EnronCatalogAdjudicationError(f"{description} changed while it was read.")
        return b"".join(chunks)
    except EnronCatalogAdjudicationError:
        raise
    except (OSError, OverflowError, ValueError):
        raise EnronCatalogAdjudicationError(f"{description} could not be read safely.") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _validate_private_run_tree(path: Path) -> Path:
    root = _absolute_path(path)
    directory_fd: int | None = None
    try:
        directory_fd = open_private_directory_input(root)
        root_info = os.fstat(directory_fd)
        if stat.S_IMODE(root_info.st_mode) != 0o700 or root_info.st_uid != os.geteuid():
            raise EnronCatalogAdjudicationError("Catalog qualification directory permissions are invalid.")
        if set(os.listdir(directory_fd)) != _RUN_FILES:
            raise EnronCatalogAdjudicationError("Catalog qualification run inventory is invalid.")
        for name in _RUN_FILES:
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or not is_owner_only_private_mode(stat.S_IMODE(info.st_mode))
            ):
                raise EnronCatalogAdjudicationError("Catalog qualification artifact identity is invalid.")
        with open_private_binary_input_at(directory_fd, "COMMITTED") as marker:
            if marker.read(len(_COMMIT_PAYLOAD) + 1) != _COMMIT_PAYLOAD:
                raise EnronCatalogAdjudicationError("Catalog qualification commit marker is invalid.")
    except EnronCatalogAdjudicationError:
        raise
    except (EnronPrivateIOError, OSError, ValueError):
        raise EnronCatalogAdjudicationError("Catalog qualification run could not be opened safely.") from None
    finally:
        if directory_fd is not None:
            os.close(directory_fd)
    return root


def _load_binding_jsonl(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    digest = hashlib.sha256()
    byte_count = 0
    try:
        for line_no, raw, row in iter_strict_jsonl(path, _MAX_BINDING_LINE_BYTES):
            if line_no > _MAX_BINDINGS:
                raise EnronCatalogAdjudicationError("Catalog binding artifact exceeds the row limit.")
            detached = dict(row)
            if raw != _canonical_bytes(detached) + b"\n" or set(detached) != _BINDING_FIELDS:
                raise EnronCatalogAdjudicationError(f"Catalog binding row {line_no} is not canonical and closed.")
            identity = detached["catalog_identity"]
            if identity is not None and (
                not isinstance(identity, Mapping) or set(identity) != _CATALOG_IDENTITY_FIELDS
            ):
                raise EnronCatalogAdjudicationError(f"Catalog binding row {line_no} identity is invalid.")
            rows.append(detached)
            digest.update(raw)
            byte_count += len(raw)
    except EnronPrivateIOError:
        raise EnronCatalogAdjudicationError("Catalog binding artifact is not valid private JSONL.") from None
    if rows != sorted(rows, key=lambda row: (row["document_id"], row["start"], row["end"], row["entity_class"])):
        raise EnronCatalogAdjudicationError("Catalog binding rows are not in canonical order.")
    return rows, {"sha256": "sha256:" + digest.hexdigest(), "bytes": byte_count, "records": len(rows)}


def _load_catalog_review_jsonl(
    path: Path,
    *,
    require_canonical: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    digest = hashlib.sha256()
    byte_count = 0
    try:
        for line_no, raw, row in iter_strict_jsonl(path, _MAX_BINDING_LINE_BYTES):
            if line_no > _MAX_BINDINGS:
                raise EnronCatalogAdjudicationError("Catalog review artifact exceeds the row limit.")
            detached = dict(row)
            if require_canonical and raw != _canonical_bytes(detached) + b"\n":
                raise EnronCatalogAdjudicationError(f"Catalog review row {line_no} is not canonical.")
            rows.append(detached)
            digest.update(raw)
            byte_count += len(raw)
    except EnronPrivateIOError:
        raise EnronCatalogAdjudicationError("Catalog review artifact is not valid private JSONL.") from None
    return rows, {"sha256": "sha256:" + digest.hexdigest(), "bytes": byte_count, "records": len(rows)}


def _prepare_catalog_reviews(
    rows: Sequence[Mapping[str, Any]],
    documents: Sequence[Mapping[str, Any]],
    qualification: Mapping[str, Any],
) -> tuple[tuple[dict[str, Any], ...], str, dict[str, int]]:
    if isinstance(rows, (str, bytes)) or not isinstance(rows, Sequence):
        raise EnronCatalogAdjudicationError("Catalog review must be a sequence.")
    document_text = _prepare_documents(documents)
    bank_sha256 = qualification.get("bank_sha256")
    gold_sha256 = qualification.get("gold_sha256")
    expected_bindings = qualification.get("bindings")
    if (
        not isinstance(bank_sha256, str)
        or _SHA256_RE.fullmatch(bank_sha256) is None
        or not isinstance(gold_sha256, str)
        or _SHA256_RE.fullmatch(gold_sha256) is None
        or not isinstance(expected_bindings, list)
    ):
        raise EnronCatalogAdjudicationError("Deterministic catalog qualification is invalid.")
    expected_by_document: dict[str, list[dict[str, Any]]] = {document_id: [] for document_id in document_text}
    for binding in expected_bindings:
        if not isinstance(binding, Mapping) or set(binding) != _BINDING_FIELDS:
            raise EnronCatalogAdjudicationError("Deterministic catalog binding is invalid.")
        document_id = binding["document_id"]
        if not isinstance(document_id, str) or document_id not in expected_by_document:
            raise EnronCatalogAdjudicationError("Deterministic catalog binding document is invalid.")
        expected_by_document[document_id].append(
            {
                "entity_class": binding["entity_class"],
                "start": binding["start"],
                "end": binding["end"],
                "catalog_identity": _normalize_catalog_identity(binding["catalog_identity"]),
            }
        )
    for decisions in expected_by_document.values():
        decisions.sort(key=_catalog_review_decision_key)

    canonical_rows: list[dict[str, Any]] = []
    reviewers: set[str] = set()
    reviewed_documents: set[str] = set()
    reviewed_occurrences: set[tuple[str, str, int, int]] = set()
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping) or set(row) != _CATALOG_REVIEW_FIELDS:
            raise EnronCatalogAdjudicationError(f"Catalog review row {index} schema is invalid.")
        if row["schema_version"] != CATALOG_REVIEW_SCHEMA_VERSION:
            raise EnronCatalogAdjudicationError(f"Catalog review row {index} version is invalid.")
        document_id = row["document_id"]
        if not isinstance(document_id, str) or document_id not in document_text:
            raise EnronCatalogAdjudicationError(f"Catalog review row {index} document is invalid.")
        if document_id in reviewed_documents:
            raise EnronCatalogAdjudicationError("Catalog review document rows must be unique.")
        if (
            row["text_sha256"] != _hash_bytes(document_text[document_id].encode("utf-8"))
            or row["bank_sha256"] != bank_sha256
            or row["gold_sha256"] != gold_sha256
        ):
            raise EnronCatalogAdjudicationError("Catalog review does not bind the exact gold and active bank.")
        reviewer_id = _identifier(row["reviewer_id"], "Catalog reviewer identity")
        if row["unresolved"] != []:
            raise EnronCatalogAdjudicationError("Catalog review must have zero unresolved decisions.")
        decisions = row["decisions"]
        if not isinstance(decisions, list):
            raise EnronCatalogAdjudicationError("Catalog review decisions must be a list.")
        normalized_decisions: list[dict[str, Any]] = []
        for decision_index, decision in enumerate(decisions):
            if not isinstance(decision, Mapping) or set(decision) != _CATALOG_REVIEW_DECISION_FIELDS:
                raise EnronCatalogAdjudicationError(
                    f"Catalog review row {index} decision {decision_index} schema is invalid."
                )
            detached_decision = dict(decision)
            entity_class = detached_decision["entity_class"]
            start = detached_decision["start"]
            end = detached_decision["end"]
            if (
                entity_class not in _SUPPORTED_ENTITY_CLASSES
                or type(start) is not int
                or type(end) is not int
                or not 0 <= start < end <= len(document_text[document_id])
            ):
                raise EnronCatalogAdjudicationError(
                    f"Catalog review row {index} decision {decision_index} occurrence is invalid."
                )
            occurrence = (document_id, str(entity_class), start, end)
            if occurrence in reviewed_occurrences:
                raise EnronCatalogAdjudicationError("Catalog review contains a duplicate gold occurrence decision.")
            reviewed_occurrences.add(occurrence)
            normalized_decisions.append(
                {
                    "entity_class": str(entity_class),
                    "start": start,
                    "end": end,
                    "catalog_identity": _normalize_catalog_identity(detached_decision["catalog_identity"]),
                }
            )
        normalized_decisions.sort(key=_catalog_review_decision_key)
        expected_decisions = expected_by_document[document_id]
        observed_keys = {_catalog_review_decision_occurrence_key(value) for value in normalized_decisions}
        expected_keys = {_catalog_review_decision_occurrence_key(value) for value in expected_decisions}
        if observed_keys != expected_keys:
            raise EnronCatalogAdjudicationError(
                "Catalog review must cover every exact gold occurrence once, including uncataloged decisions."
            )
        if normalized_decisions != expected_decisions:
            raise EnronCatalogAdjudicationError(
                "Catalog review decisions differ from deterministic active-bank qualification."
            )
        reviewers.add(reviewer_id)
        reviewed_documents.add(document_id)
        canonical_rows.append(
            {
                "schema_version": CATALOG_REVIEW_SCHEMA_VERSION,
                "document_id": document_id,
                "text_sha256": row["text_sha256"],
                "bank_sha256": bank_sha256,
                "gold_sha256": gold_sha256,
                "reviewer_id": reviewer_id,
                "decisions": normalized_decisions,
                "unresolved": [],
            }
        )
    if reviewed_documents != set(document_text):
        raise EnronCatalogAdjudicationError("Catalog review must cover every gold document exactly once.")
    if len(reviewers) != 1:
        raise EnronCatalogAdjudicationError("Catalog review must use exactly one bounded reviewer identity.")
    canonical_rows.sort(key=lambda row: row["document_id"])
    return (
        tuple(canonical_rows),
        reviewers.pop(),
        {
            "documents_reviewed": len(canonical_rows),
            "decisions_reviewed": len(reviewed_occurrences),
            "reviewers": 1,
            "unresolved": 0,
        },
    )


def _normalize_catalog_identity(value: Any) -> dict[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping) or set(value) != _CATALOG_IDENTITY_FIELDS:
        raise EnronCatalogAdjudicationError("Catalog review identity is invalid.")
    return {key: _identifier(value[key], f"Catalog review {key}") for key in ("entity_id", "name_id", "pattern_id")}


def _catalog_review_decision_key(value: Mapping[str, Any]) -> tuple[int, int, str]:
    return int(value["start"]), int(value["end"]), str(value["entity_class"])


def _catalog_review_decision_occurrence_key(value: Mapping[str, Any]) -> tuple[str, int, int]:
    return str(value["entity_class"]), int(value["start"]), int(value["end"])


def _identifier(value: Any, description: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise EnronCatalogAdjudicationError(f"{description} is invalid.")
    return value


def _catalog_review_provenance(
    reviewer_id: str,
    review_artifact: Mapping[str, Any],
    counts: Mapping[str, int],
) -> dict[str, Any]:
    artifact_sha256 = review_artifact.get("sha256")
    if not isinstance(artifact_sha256, str) or _SHA256_RE.fullmatch(artifact_sha256) is None:
        raise EnronCatalogAdjudicationError("Catalog review artifact commitment is invalid.")
    return {
        **{key: counts[key] for key in ("documents_reviewed", "decisions_reviewed", "reviewers", "unresolved")},
        "bank_aware": True,
        "prediction_blind": True,
        "reviewer_identity_sha256": _canonical_hash(
            {
                "schema_version": "nerb.enron_catalog_reviewer_binding",
                "review_artifact_sha256": artifact_sha256,
                "reviewer_id": reviewer_id,
            }
        ),
    }


def _load_strict_json_object(path: Path, description: str) -> tuple[dict[str, Any], bytes]:
    try:
        with open_private_binary_input(path) as file:
            raw = file.read(_MAX_METADATA_BYTES + 1)
    except EnronPrivateIOError:
        raise EnronCatalogAdjudicationError(f"{description} could not be opened safely.") from None
    if len(raw) > _MAX_METADATA_BYTES:
        raise EnronCatalogAdjudicationError(f"{description} exceeds the byte limit.")
    value = _decode_strict_json(raw, description)
    if not isinstance(value, dict):
        raise EnronCatalogAdjudicationError(f"{description} must contain one JSON object.")
    return value, raw


def _decode_strict_json(raw: bytes, description: str) -> Any:
    def reject_duplicates(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def reject_constant(_value: str) -> None:
        raise ValueError("non-finite JSON number")

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise EnronCatalogAdjudicationError(f"{description} is not strict JSON.") from None


def _absolute_path(path: Path) -> Path:
    candidate = Path(path).expanduser()
    if any(part == os.pardir for part in candidate.parts):
        raise EnronCatalogAdjudicationError("Catalog paths must not contain parent traversal.")
    return candidate if candidate.is_absolute() else Path.cwd() / candidate


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _canonical_json_file(value: Any) -> bytes:
    return _canonical_bytes(value) + b"\n"


def _canonical_jsonl(rows: Sequence[Mapping[str, Any]]) -> bytes:
    return b"".join(_canonical_bytes(row) + b"\n" for row in rows)


def _artifact_descriptor(name: str, payload: bytes, records: int) -> dict[str, Any]:
    return {"name": name, "sha256": _hash_bytes(payload), "bytes": len(payload), "records": records}


def _catalog_run_manifest(
    gold_receipt: Mapping[str, Any],
    trusted_gold_commitment: Mapping[str, str],
    bank_artifact: Mapping[str, Any],
    binding_artifact: Mapping[str, Any],
    review_artifact: Mapping[str, Any],
    review_provenance: Mapping[str, Any],
    qualification: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": CATALOG_RUN_MANIFEST_SCHEMA_VERSION,
        "fixture_mode": gold_receipt["fixture_mode"],
        "promotable": gold_receipt["promotable"],
        "audit_plan_sha256": gold_receipt["audit_plan_sha256"],
        "audit_output_binding_sha256": gold_receipt["audit_output_binding_sha256"],
        "audit_execution_policy_sha256": gold_receipt["audit_execution_policy_sha256"],
        "sample_plan_artifact_sha256": gold_receipt["sample_plan_artifact_sha256"],
        "sample_artifact_sha256": gold_receipt["sample_artifact_sha256"],
        "sample_receipt_artifact_sha256": gold_receipt["sample_receipt_artifact_sha256"],
        "sample_binding_sha256": gold_receipt["sample_binding_sha256"],
        "planned_evaluator_source_sha256": gold_receipt["planned_evaluator_source_sha256"],
        "planned_thresholds_sha256": gold_receipt["planned_thresholds_sha256"],
        "gold_sha256": gold_receipt["gold_sha256"],
        "gold_manifest_sha256": gold_receipt["manifest_sha256"],
        "gold_artifacts_sha256": gold_receipt["artifacts_sha256"],
        "trusted_gold_commitment": _detached_mapping(trusted_gold_commitment),
        "trusted_gold_commitment_sha256": _canonical_hash(trusted_gold_commitment),
        "annotation_policy_sha256": gold_receipt["annotation_policy_sha256"],
        "catalog_policy_sha256": qualification["policy_sha256"],
        "planned_bank_sha256": gold_receipt["planned_bank_sha256"],
        "bank_sha256": qualification["bank_sha256"],
        "bank_artifact": _detached_mapping(bank_artifact),
        "binding_artifact": _detached_mapping(binding_artifact),
        "review_artifact": _detached_mapping(review_artifact),
        "review_provenance": _detached_mapping(review_provenance),
        "catalog_binding_sha256": qualification["catalog_binding_sha256"],
        "counts": _detached_mapping(qualification["counts"]),
    }


def _catalog_run_receipt(manifest: Mapping[str, Any]) -> dict[str, Any]:
    binding_artifact = manifest["binding_artifact"]
    bank_artifact = manifest["bank_artifact"]
    review_artifact = manifest["review_artifact"]
    review_provenance = manifest["review_provenance"]
    counts = manifest["counts"]
    trusted_gold_commitment = manifest["trusted_gold_commitment"]
    if not all(
        isinstance(value, Mapping)
        for value in (
            binding_artifact,
            bank_artifact,
            review_artifact,
            review_provenance,
            counts,
            trusted_gold_commitment,
        )
    ):
        raise EnronCatalogAdjudicationError("Catalog qualification manifest aggregates are invalid.")
    gold_spans = counts.get("gold_spans")
    cataloged = counts.get("cataloged_gold_spans")
    if type(gold_spans) is not int or type(cataloged) is not int or not 0 <= cataloged <= gold_spans:
        raise EnronCatalogAdjudicationError("Catalog qualification counts are invalid.")
    return {
        "schema_version": CATALOG_RUN_RECEIPT_SCHEMA_VERSION,
        "valid": True,
        "fixture_mode": manifest["fixture_mode"],
        "promotable": manifest["promotable"],
        "audit_plan_sha256": manifest["audit_plan_sha256"],
        "audit_output_binding_sha256": manifest["audit_output_binding_sha256"],
        "audit_execution_policy_sha256": manifest["audit_execution_policy_sha256"],
        "sample_artifact_sha256": manifest["sample_artifact_sha256"],
        "sample_binding_sha256": manifest["sample_binding_sha256"],
        "planned_evaluator_source_sha256": manifest["planned_evaluator_source_sha256"],
        "planned_thresholds_sha256": manifest["planned_thresholds_sha256"],
        "gold_sha256": manifest["gold_sha256"],
        "gold_manifest_sha256": manifest["gold_manifest_sha256"],
        "gold_artifacts_sha256": manifest["gold_artifacts_sha256"],
        "trusted_gold_commitment": _detached_mapping(trusted_gold_commitment),
        "trusted_gold_commitment_sha256": manifest["trusted_gold_commitment_sha256"],
        "annotation_policy_sha256": manifest["annotation_policy_sha256"],
        "catalog_policy_sha256": manifest["catalog_policy_sha256"],
        "bank_sha256": manifest["bank_sha256"],
        "bank_artifact_sha256": bank_artifact["sha256"],
        "binding_artifact_sha256": binding_artifact["sha256"],
        "review_artifact_sha256": review_artifact["sha256"],
        "review_provenance": _detached_mapping(review_provenance),
        "catalog_binding_sha256": manifest["catalog_binding_sha256"],
        "manifest_sha256": _canonical_hash(manifest),
        "artifacts_sha256": _canonical_hash(
            {
                "bank_artifact": bank_artifact,
                "binding_artifact": binding_artifact,
                "review_artifact": review_artifact,
            }
        ),
        "counts": _detached_mapping(counts),
        "catalog_coverage": None if gold_spans == 0 else cataloged / gold_spans,
        "unresolved": review_provenance["unresolved"],
        "privacy": {
            "aggregate_only": True,
            "raw_text_included": False,
            "document_ids_included": False,
            "span_coordinates_included": False,
            "span_surfaces_included": False,
            "catalog_identities_included": False,
            "entity_names_included": False,
            "pattern_ids_included": False,
            "reviewer_ids_included": False,
            "private_paths_included": False,
        },
    }


def _detached_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    detached = json.loads(_canonical_bytes(value))
    if not isinstance(detached, dict):
        raise EnronCatalogAdjudicationError("Canonical catalog projection failed.")
    return detached


def _prepare_bank(bank: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(bank, Mapping):
        raise EnronCatalogAdjudicationError("Catalog bank must be an object.")
    result = validate_bank_schema(bank)
    if result["valid"] is not True:
        raise EnronCatalogAdjudicationError("Catalog bank schema is invalid.")
    canonical = canonicalize_bank(bank)
    if canonical.get("status") != "active":
        raise EnronCatalogAdjudicationError("Catalog bank must be active.")
    return canonical


def _active_catalog(bank: Mapping[str, Any]) -> dict[str, tuple[_Pattern, ...]]:
    result: dict[str, list[_Pattern]] = defaultdict(list)
    default_flags = _flags(bank.get("default_regex_flags"))
    entities = bank.get("entities")
    if not isinstance(entities, Mapping):
        raise EnronCatalogAdjudicationError("Catalog bank entity inventory is invalid.")
    for entity_id, entity in entities.items():
        if (
            entity_id not in _SUPPORTED_ENTITY_CLASSES
            or not isinstance(entity, Mapping)
            or entity.get("status") != "active"
        ):
            continue
        entity_flags = default_flags | _flags(entity.get("regex_flags"))
        names = entity.get("names")
        if not isinstance(names, Mapping):
            raise EnronCatalogAdjudicationError("Catalog bank name inventory is invalid.")
        for name_id, name in names.items():
            if not isinstance(name, Mapping) or name.get("status") != "active":
                continue
            patterns = name.get("patterns")
            if not isinstance(patterns, Mapping):
                raise EnronCatalogAdjudicationError("Catalog bank pattern inventory is invalid.")
            for pattern_id, pattern in patterns.items():
                if not isinstance(pattern, Mapping) or pattern.get("status") != "active":
                    continue
                kind = pattern.get("kind")
                value = pattern.get("value")
                priority = pattern.get("priority")
                if kind not in {"literal", "regex"} or not isinstance(value, str) or type(priority) is not int:
                    raise EnronCatalogAdjudicationError("Active catalog pattern is invalid.")
                flags = entity_flags | (_flags(pattern.get("regex_flags")) if kind == "regex" else 0)
                compiled: re.Pattern[str] | None = None
                if kind == "regex":
                    if value != _SUPPORTED_GENERIC_EMAIL_REGEX or flags != 0:
                        raise EnronCatalogAdjudicationError(
                            "Active catalog regex uses unsupported semantics outside the frozen Rust-equivalent subset."
                        )
                    try:
                        compiled = re.compile(value, re.ASCII)
                    except (re.error, ValueError):
                        raise EnronCatalogAdjudicationError(
                            "Active catalog regex is unsupported by the independent qualifier."
                        ) from None
                result[str(entity_id)].append(
                    _Pattern(
                        entity_id=str(entity_id),
                        name_id=str(name_id),
                        pattern_id=str(pattern_id),
                        priority=priority,
                        kind=str(kind),
                        value=value,
                        flags=flags,
                        case_sensitive=pattern.get("case_sensitive") if kind == "literal" else None,
                        normalize_whitespace=pattern.get("normalize_whitespace") if kind == "literal" else None,
                        left_boundary=pattern.get("left_boundary") if kind == "literal" else None,
                        right_boundary=pattern.get("right_boundary") if kind == "literal" else None,
                        compiled=compiled,
                    )
                )
    for entity_id, patterns in result.items():
        priorities = [pattern.priority for pattern in patterns]
        if len(priorities) != len(set(priorities)):
            raise EnronCatalogAdjudicationError(
                f"Active {entity_id} catalog priorities must be unique for deterministic qualification."
            )
    return {entity_id: tuple(patterns) for entity_id, patterns in result.items()}


def _flags(value: Any) -> int:
    if value is None:
        return 0
    if not isinstance(value, list) or any(flag not in _FLAG_MAP for flag in value):
        raise EnronCatalogAdjudicationError("Catalog regex flags are unsupported.")
    result = 0
    for flag in value:
        result |= _FLAG_MAP[str(flag)]
    return result


def _pattern_matches_exact_context(pattern: _Pattern, text: str, start: int, end: int) -> bool:
    if pattern.kind == "regex":
        assert pattern.compiled is not None
        context = text[max(0, start - 1) : min(len(text), end + 1)]
        if not text[start:end].isascii() or not context.isascii():
            return False
        match = pattern.compiled.match(text, start)
        return match is not None and match.start() == start and match.end() == end
    surface = text[start:end]
    expected = pattern.value
    if pattern.normalize_whitespace:
        surface = _normalize_rust_whitespace(surface)
        expected = _normalize_rust_whitespace(expected)
    case_insensitive = pattern.case_sensitive is False or bool(pattern.flags & re.IGNORECASE)
    if pattern.flags & ~int(re.IGNORECASE):
        raise EnronCatalogAdjudicationError("Active catalog literal uses unsupported independent semantics.")
    if case_insensitive and surface != expected:
        if not expected.isascii():
            return False
        folded_surface = _rust_ascii_fold(surface)
        if folded_surface is None:
            return False
        surface = folded_surface
        expected = expected.lower()
    if surface != expected:
        return False
    if pattern.left_boundary == "word" and not _rust_word_boundary(text, start):
        return False
    if pattern.right_boundary == "word" and not _rust_word_boundary(text, end):
        return False
    return True


def _normalize_rust_whitespace(value: str) -> str:
    normalized: list[str] = []
    previous_was_whitespace = False
    for character in value:
        whitespace = _is_rust_regex_whitespace(character)
        if whitespace:
            if not previous_was_whitespace:
                normalized.append(" ")
        else:
            normalized.append(character)
        previous_was_whitespace = whitespace
    return "".join(normalized)


def _is_rust_regex_whitespace(character: str) -> bool:
    codepoint = ord(character)
    return (
        0x0009 <= codepoint <= 0x000D
        or codepoint
        in {
            0x0020,
            0x0085,
            0x00A0,
            0x1680,
            0x2028,
            0x2029,
            0x202F,
            0x205F,
            0x3000,
        }
        or 0x2000 <= codepoint <= 0x200A
    )


def _rust_ascii_fold(value: str) -> str | None:
    folded: list[str] = []
    for character in value:
        if character.isascii():
            folded.append(character.lower() if "A" <= character <= "Z" else character)
        elif character == "\N{LATIN SMALL LETTER LONG S}":
            folded.append("s")
        elif character == "\N{KELVIN SIGN}":
            folded.append("k")
        else:
            return None
    return "".join(folded)


def _rust_word_boundary(text: str, offset: int) -> bool:
    left = offset > 0 and _rust_word_character(text[offset - 1])
    right = offset < len(text) and _rust_word_character(text[offset])
    return left != right


def _rust_word_character(character: str) -> bool:
    if not isinstance(character, str) or len(character) != 1:
        raise EnronCatalogAdjudicationError("Catalog word-boundary input is invalid.")
    try:
        result = _native_engine._is_word_character(character)
    except Exception:
        raise EnronCatalogAdjudicationError("Catalog word-boundary input is invalid.") from None
    if type(result) is not bool:
        raise EnronCatalogAdjudicationError("Catalog word-boundary input is invalid.")
    return result


def _reject_gold_role_reuse(reviewer_id: str, gold_role_identities: set[str]) -> None:
    if reviewer_id in gold_role_identities:
        raise EnronCatalogAdjudicationError(
            "Catalog reviewer must be distinct from every gold annotation and review role."
        )


def _prepare_documents(values: Sequence[Mapping[str, Any]]) -> dict[str, str]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise EnronCatalogAdjudicationError("Catalog documents must be a sequence.")
    result: dict[str, str] = {}
    for value in values:
        if not isinstance(value, Mapping):
            raise EnronCatalogAdjudicationError("Catalog document is invalid.")
        document_id = value.get("document_id")
        text = value.get("text")
        text_sha256 = value.get("text_sha256")
        if (
            not isinstance(document_id, str)
            or not isinstance(text, str)
            or not isinstance(text_sha256, str)
            or text_sha256 != _hash_bytes(text.encode("utf-8"))
            or document_id in result
        ):
            raise EnronCatalogAdjudicationError("Catalog document commitment is invalid.")
        result[document_id] = text
    return result


def _prepare_gold(gold: Mapping[str, Any], documents: Mapping[str, str]) -> tuple[Sequence[Mapping[str, Any]], str]:
    if not isinstance(gold, Mapping) or gold.get("schema_version") != "nerb.enron_gold":
        raise EnronCatalogAdjudicationError("Catalog gold artifact is invalid.")
    gold_sha256 = gold.get("gold_sha256")
    core = {key: gold[key] for key in gold if key != "gold_sha256"}
    if not isinstance(gold_sha256, str) or gold_sha256 != _canonical_hash(core):
        raise EnronCatalogAdjudicationError("Catalog gold commitment is invalid.")
    gold_documents = gold.get("documents")
    if (
        not isinstance(gold_documents, list)
        or any(not isinstance(item, Mapping) for item in gold_documents)
        or {item.get("document_id") for item in gold_documents} != set(documents)
    ):
        raise EnronCatalogAdjudicationError("Catalog gold population differs from the sample.")
    for item in gold_documents:
        if not isinstance(item, Mapping) or not isinstance(item.get("spans"), list):
            raise EnronCatalogAdjudicationError("Catalog gold document is invalid.")
        document_id = item.get("document_id")
        text = documents.get(str(document_id))
        if text is None or item.get("text_sha256") != _hash_bytes(text.encode("utf-8")):
            raise EnronCatalogAdjudicationError("Catalog gold document binding is invalid.")
        for span in item["spans"]:
            if (
                not isinstance(span, Mapping)
                or set(span) != {"entity_class", "start", "end"}
                or span["entity_class"] not in _SUPPORTED_ENTITY_CLASSES
                or type(span["start"]) is not int
                or type(span["end"]) is not int
                or not 0 <= span["start"] < span["end"] <= len(text)
            ):
                raise EnronCatalogAdjudicationError("Catalog gold span is invalid.")
    return gold_documents, gold_sha256


def _canonical_hash(value: Any) -> str:
    return _hash_bytes(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    )


def _hash_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


__all__ = [
    "CATALOG_BINDING_SCHEMA_VERSION",
    "CATALOG_QUALIFICATION_POLICY",
    "CATALOG_RUN_MANIFEST_SCHEMA_VERSION",
    "CATALOG_RUN_RECEIPT_SCHEMA_VERSION",
    "EnronCatalogAdjudicationError",
    "enron_catalog_qualification_policy_sha256",
    "finalize_enron_catalog_qualification_files",
    "public_enron_catalog_receipt",
    "qualify_enron_gold_catalog",
    "verify_enron_catalog_qualification",
]

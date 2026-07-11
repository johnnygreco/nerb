"""Private transactional workflow for Enron v2 bank construction."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import unicodedata
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from itertools import zip_longest
from pathlib import Path
from typing import Any, cast

from . import enron_bank_builder as _bank_builder_module
from .bank import bank_stats, hash_bank
from .enron_annotations import EnronAnnotationError, load_cmu_enron_training_quality_source
from .enron_bank_builder import (
    BANK_BUILD_ITERATION_SCHEMA_VERSION,
    BANK_BUILD_MANIFEST_SCHEMA_VERSION,
    BANK_BUILD_TIMESTAMP,
    BANK_CARD_SCHEMA_VERSION,
    CANDIDATE_FUNNEL_SCHEMA_VERSION,
    CANDIDATE_SCHEMA_VERSION,
    ITERATION_POLICIES,
    CandidatePool,
    CuratedIteration,
    EnronBankBuildError,
    EnronBankPolicy,
    _canonical_hash,
    _canonical_json_bytes,
    _normalize_email,
    _normalize_person_name,
    candidate_funnel,
    curate_enron_iteration,
    mine_enron_candidates,
)
from .enron_conformance import (
    ADVERSARIAL_TAGS,
    NEGATIVE_CASE_SCHEMA_VERSION,
    POSITIVE_CASE_SCHEMA_VERSION,
    EnronConformanceError,
    evaluate_enron_conformance,
)
from .enron_private_io import (
    EnronPrivateIOError,
    PrivateRun,
    iter_strict_jsonl,
    open_private_binary_input,
)
from .enron_quality import (
    EnronQualityError,
    evaluate_cmu_enron_training_quality,
    evaluate_enron_quality,
)
from .enron_splitting import EnronSplitError, load_enron_development_split
from .validation import validate_bank

__all__ = [
    "EnronBankBuildOptions",
    "build_enron_intelligence_bank",
    "verify_enron_bank_build",
]

_PUBLIC_CARD_FIELDS = frozenset(
    {
        "schema_version",
        "benchmark_version",
        "artifact_kind",
        "fixture_mode",
        "promotable",
        "nonpromotable_reasons",
        "source",
        "charter",
        "builder",
        "bank",
        "candidate_funnel",
        "iterations",
        "validation",
        "catalog_conformance",
        "independent_auxiliary",
        "privacy",
        "run_sha256",
    }
)
_SHA256_PREFIX = "sha256:"
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_EMAIL_SHAPE_RE = re.compile(r"[^\s@]+@[^\s@]+")
_PHONE_SHAPE_RE = re.compile(r"(?<![0-9])[0-9]{3}[ .-][0-9]{3}[ .-][0-9]{4}(?![0-9])")
_DOCUMENT_ID_RE = re.compile(r"^doc_[0-9a-f]{64}$")
_MAX_PRIVATE_JSON_BYTES = 512 * 1024 * 1024
_MAX_PRIVATE_JSONL_LINE_BYTES = 16 * 1024 * 1024
_MAX_PRIVATE_JSONL_RECORDS = 3_000_000
_PRIVATE_COMMIT_MARKER_SHA256 = _SHA256_PREFIX + hashlib.sha256(b"nerb.enron.private-run.v2\n").hexdigest()

_REQUIRED_ARTIFACT_NAMES = {
    "iteration_01_bank": f"banks/{ITERATION_POLICIES[0].id}.json",
    "iteration_02_bank": f"banks/{ITERATION_POLICIES[1].id}.json",
    "iteration_03_bank": f"banks/{ITERATION_POLICIES[2].id}.json",
    "selected_bank": "bank.json",
    "candidates": "candidates.jsonl",
    "candidate_funnel": "candidate-funnel.json",
    "collision_report": "collision-report.json",
    "iterations": "iterations.jsonl",
    "validation_documents": "validation/documents.jsonl",
    "validation_slices": "validation/slices.jsonl",
    "validation_unsupported": "validation/unsupported.jsonl",
    "validation_gold_01": "validation/gold-iteration-01.jsonl",
    "validation_quality_01": "validation/quality-iteration-01.json",
    "validation_structural_01": "validation/structural-iteration-01.json",
    "validation_gold_02": "validation/gold-iteration-02.jsonl",
    "validation_quality_02": "validation/quality-iteration-02.json",
    "validation_structural_02": "validation/structural-iteration-02.json",
    "validation_gold_03": "validation/gold-iteration-03.jsonl",
    "validation_quality_03": "validation/quality-iteration-03.json",
    "validation_structural_03": "validation/structural-iteration-03.json",
    "conformance_positive": "conformance/positive.jsonl",
    "conformance_negative": "conformance/negative.jsonl",
    "conformance_result": "conformance/result.json",
    "mining_spool": "mining.sqlite3",
    "bank_card": "bank-card.json",
}
_OPTIONAL_CMU_ARTIFACT_NAMES = {
    "cmu_catalog_bindings": "auxiliary/cmu-train-catalog-bindings.jsonl",
    "cmu_quality": "auxiliary/cmu-train-quality.json",
}


@dataclass(frozen=True, slots=True)
class EnronBankBuildOptions:
    development_run: Path
    output_dir: Path
    annotation_run: Path | None = None
    benchmark_version: str = "enron-v2"
    created_at: str = BANK_BUILD_TIMESTAMP
    policy: EnronBankPolicy = EnronBankPolicy()
    allow_unignored_output: bool = False


@dataclass(frozen=True, slots=True)
class _ValidationProjection:
    documents: tuple[dict[str, Any], ...]
    spans: tuple[dict[str, Any], ...]
    slices: tuple[dict[str, Any], ...]
    unsupported: tuple[dict[str, Any], ...]
    artifact_sha256: str
    records: int


@dataclass(frozen=True, slots=True)
class _PrivateEntryIdentity:
    kind: str
    device: int
    inode: int
    mode: int
    link_count: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True, slots=True)
class _PrivateFileFingerprint:
    identity: _PrivateEntryIdentity
    sha256: str


def build_enron_intelligence_bank(options: EnronBankBuildOptions) -> dict[str, Any]:
    """Build three validation-only iterations and commit one private selected run."""

    if not isinstance(options, EnronBankBuildOptions):
        raise EnronBankBuildError("Bank-build options are invalid.")
    try:
        development = load_enron_development_split(Path(options.development_run))
    except (EnronPrivateIOError, EnronSplitError):
        raise EnronBankBuildError("Development split could not be loaded safely.") from None
    source_binding = _source_binding(development, Path(options.development_run), options.benchmark_version)
    if source_binding["benchmark_version"] != options.benchmark_version:
        raise EnronBankBuildError("Development split benchmark version does not match the build target.")

    try:
        with PrivateRun(
            Path(options.output_dir),
            allow_unignored_output=options.allow_unignored_output,
        ) as run:
            with run.open_binary("mining.sqlite3"):
                pass
            pool = mine_enron_candidates(
                _paired_role(
                    development.iter_train_records(),
                    development.iter_train_memberships(),
                    role="train",
                ),
                sqlite_path=run.stage_dir / "mining.sqlite3",
                train_artifact_sha256=str(source_binding["train_artifact_sha256"]),
                policy=options.policy,
            )
            curated = tuple(
                curate_enron_iteration(
                    pool,
                    policy=options.policy,
                    iteration=iteration,
                    source_binding=source_binding,
                    created_at=options.created_at,
                )
                for iteration in ITERATION_POLICIES
            )
            validation = _validation_projection(
                _paired_role(
                    development.iter_validation_records(),
                    development.iter_validation_memberships(),
                    role="validation",
                ),
                source_binding=source_binding,
                policy=options.policy,
            )
            evaluated = tuple(_evaluate_iteration(item, validation, options.policy) for item in curated)
            iteration_records = _decide_iterations(evaluated)
            selected = curated[1]
            selected_record = iteration_records[1]
            if selected_record["decision"] != "keep" or selected_record["selected"] is not True:
                raise EnronBankBuildError("Frozen iteration selection did not select the bounded email-recall bank.")

            positive_cases, negative_cases = _conformance_cases(selected.bank)
            try:
                conformance = evaluate_enron_conformance(selected.bank, positive_cases, negative_cases)
            except EnronConformanceError:
                raise EnronBankBuildError("Selected-bank catalog conformance could not be evaluated safely.") from None
            conformance_gate = conformance["catalog_conformance"]
            if conformance_gate["passed"] is not True:
                raise EnronBankBuildError("Selected-bank catalog conformance failed.")

            if options.annotation_run is None:
                cmu_bindings: tuple[dict[str, Any], ...] = ()
                cmu_quality: dict[str, Any] | None = None
            else:
                cmu_bindings, cmu_quality = _evaluate_cmu_auxiliary(
                    selected.bank,
                    Path(options.annotation_run),
                )

            artifacts = _write_private_artifacts(
                run,
                pool=pool,
                curated=curated,
                validation=validation,
                evaluated=evaluated,
                iteration_records=iteration_records,
                selected=selected,
                positive_cases=positive_cases,
                negative_cases=negative_cases,
                conformance=conformance,
                cmu_bindings=cmu_bindings,
                cmu_quality=cmu_quality,
            )
            card = _bank_card(
                options,
                source_binding=source_binding,
                pool=pool,
                selected=selected,
                iteration_records=iteration_records,
                selected_quality=cast(Mapping[str, Any], evaluated[1]["quality"]),
                conformance=conformance,
                cmu_quality=cmu_quality,
                artifacts=artifacts,
            )
            _validate_public_card(card)
            with run.open_binary("bank-card.json") as file:
                file.write(_pretty_json_bytes(card))
            artifacts["bank_card"] = _artifact_descriptor(run.stage_dir / "bank-card.json", "bank_card")
            manifest = _private_manifest(
                options,
                source_binding=source_binding,
                pool=pool,
                card=card,
                artifacts=artifacts,
            )
            with run.open_binary("manifest.json") as file:
                file.write(_pretty_json_bytes(manifest))
            run.commit()
    except EnronPrivateIOError:
        raise EnronBankBuildError("Private bank-build run failed safely.") from None

    return card


def _source_binding(development: Any, root: Path, benchmark_version: str) -> dict[str, Any]:
    manifest = development.manifest
    if manifest.get("benchmark_version") != benchmark_version:
        raise EnronBankBuildError("Development split benchmark version does not match the build target.")
    preparation = manifest.get("preparation")
    policy = manifest.get("policy")
    roles = manifest.get("development_roles")
    artifacts = manifest.get("artifacts")
    if not all(isinstance(item, Mapping) for item in (preparation, policy, roles, artifacts)):
        raise EnronBankBuildError("Development split binding is invalid.")
    preparation = cast(Mapping[str, Any], preparation)
    policy = cast(Mapping[str, Any], policy)
    roles = cast(Mapping[str, Any], roles)
    artifacts = cast(Mapping[str, Any], artifacts)
    train = roles.get("train")
    validation = roles.get("validation")
    memberships = artifacts.get("memberships")
    if not all(isinstance(item, Mapping) for item in (train, validation, memberships)):
        raise EnronBankBuildError("Development role binding is invalid.")
    train = cast(Mapping[str, Any], train)
    validation = cast(Mapping[str, Any], validation)
    memberships = cast(Mapping[str, Any], memberships)
    return {
        "benchmark_version": manifest["benchmark_version"],
        "dataset_id": preparation.get("dataset_id"),
        "dataset_revision": preparation.get("dataset_revision"),
        "dataset_split": preparation.get("dataset_split"),
        "development_manifest_sha256": _hash_private_file(root / "manifest.json"),
        "full_split_manifest_sha256": manifest.get("full_split_manifest_sha256"),
        "split_policy_sha256": policy.get("sha256"),
        "preparation_manifest_sha256": preparation.get("manifest_sha256"),
        "train_artifact_sha256": cast(Mapping[str, Any], train.get("artifact"))["sha256"],
        "train_artifact_bytes": cast(Mapping[str, Any], train.get("artifact"))["bytes"],
        "train_records": train.get("records"),
        "train_groups": train.get("groups"),
        "validation_artifact_sha256": cast(Mapping[str, Any], validation.get("artifact"))["sha256"],
        "validation_artifact_bytes": cast(Mapping[str, Any], validation.get("artifact"))["bytes"],
        "validation_records": validation.get("records"),
        "validation_groups": validation.get("groups"),
        "development_memberships_sha256": memberships.get("sha256"),
        "fixture_mode": manifest.get("fixture_mode"),
        "sealed_test_accessed": False,
    }


def _paired_role(
    records: Iterable[Mapping[str, Any]],
    memberships: Iterable[Mapping[str, Any]],
    *,
    role: str,
) -> Iterator[tuple[Mapping[str, Any], Mapping[str, Any]]]:
    sentinel = object()
    for record, membership in zip_longest(records, memberships, fillvalue=sentinel):
        if record is sentinel or membership is sentinel:
            raise EnronBankBuildError(f"{role.capitalize()} records and memberships differ in length.")
        record_map = cast(Mapping[str, Any], record)
        membership_map = cast(Mapping[str, Any], membership)
        if record_map.get("document_id") != membership_map.get("document_id") or membership_map.get("role") != role:
            raise EnronBankBuildError(f"{role.capitalize()} records and memberships are not aligned.")
        yield record_map, membership_map


def _validation_projection(
    records_and_memberships: Iterable[tuple[Mapping[str, Any], Mapping[str, Any]]],
    *,
    source_binding: Mapping[str, Any],
    policy: EnronBankPolicy,
) -> _ValidationProjection:
    documents: list[dict[str, Any]] = []
    spans: list[dict[str, Any]] = []
    records = 0
    total_entries = 0
    total_spans = 0
    total_text_utf8_bytes = 0
    digest = hashlib.sha256(b"nerb/enron/validation-structured-view/v2\0")
    for record, membership in records_and_memberships:
        records += 1
        if records > policy.max_validation_records:
            raise EnronBankBuildError("Validation record count exceeds the bank-build limit.")
        document_id = str(record["document_id"])
        if membership.get("role") != "validation":
            raise EnronBankBuildError("Validation membership role is invalid.")
        headers = record.get("headers")
        if not isinstance(headers, Mapping):
            raise EnronBankBuildError("Validation structured headers are invalid.")
        text_parts: list[str] = []
        offset = 0
        entry_count = 0
        for field_name in ("from", "to", "cc", "bcc"):
            entries = headers.get(field_name)
            if not isinstance(entries, list):
                raise EnronBankBuildError("Validation structured header field is invalid.")
            for entry in entries:
                entry_count += 1
                total_entries += 1
                if entry_count > policy.max_header_entries_per_document:
                    raise EnronBankBuildError("Validation structured header count exceeds the bank-build limit.")
                if total_entries > policy.max_validation_entries:
                    raise EnronBankBuildError("Validation structured header entries exceed the bank-build limit.")
                if not isinstance(entry, Mapping):
                    raise EnronBankBuildError("Validation structured header entry is invalid.")
                name = entry.get("name")
                address = entry.get("address")
                if not isinstance(name, str) or not isinstance(address, str):
                    raise EnronBankBuildError("Validation structured header values are invalid.")
                if max(len(name.encode("utf-8")), len(address.encode("utf-8"))) > policy.max_candidate_value_bytes:
                    raise EnronBankBuildError("Validation structured header value exceeds the bank-build byte limit.")
                prefix = "\n" if text_parts else ""
                normalized_name_surface = " ".join(name.split())
                normalized_address = _normalize_email(address)
                if normalized_name_surface and normalized_address:
                    segment = f"{prefix}{field_name}: {normalized_name_surface} <{normalized_address}>"
                    name_start = offset + len(prefix) + len(field_name) + 2
                    address_start = name_start + len(normalized_name_surface) + 2
                elif normalized_address:
                    segment = f"{prefix}{field_name}: {normalized_address}"
                    name_start = -1
                    address_start = offset + len(prefix) + len(field_name) + 2
                elif normalized_name_surface:
                    segment = f"{prefix}{field_name}: {normalized_name_surface}"
                    name_start = offset + len(prefix) + len(field_name) + 2
                    address_start = -1
                else:
                    continue
                total_text_utf8_bytes += len(segment.encode("utf-8"))
                if total_text_utf8_bytes > policy.max_validation_text_utf8_bytes:
                    raise EnronBankBuildError("Validation structured text exceeds the bank-build byte limit.")
                text_parts.append(segment)
                if normalized_name_surface and _normalize_person_name(normalized_name_surface):
                    total_spans += 1
                    if total_spans > policy.max_validation_spans:
                        raise EnronBankBuildError("Validation structured spans exceed the bank-build limit.")
                    spans.append(
                        {
                            "document_id": document_id,
                            "entity_class": "person",
                            "start": name_start,
                            "end": name_start + len(normalized_name_surface),
                            "surface": normalized_name_surface,
                        }
                    )
                if normalized_address:
                    total_spans += 1
                    if total_spans > policy.max_validation_spans:
                        raise EnronBankBuildError("Validation structured spans exceed the bank-build limit.")
                    spans.append(
                        {
                            "document_id": document_id,
                            "entity_class": "contact",
                            "start": address_start,
                            "end": address_start + len(normalized_address),
                            "surface": normalized_address,
                        }
                    )
                offset += len(segment)
        text = "".join(text_parts)
        document = {
            "document_id": document_id,
            "text": text,
            "text_view": "structured_headers_v2",
            "split_role": "validation",
        }
        documents.append(document)
        digest.update(_canonical_json_bytes(document))
    if records == 0:
        raise EnronBankBuildError("Validation split is empty.")
    artifact_sha256 = _SHA256_PREFIX + digest.hexdigest()
    document_ids = [str(item["document_id"]) for item in documents]
    view_descriptor = {
        "id": "structured_headers_v2",
        "artifact_sha256": artifact_sha256,
        "content_policy_sha256": _canonical_hash(
            {
                "schema_version": "nerb.enron_structured_header_view.v2",
                "fields": ["from", "to", "cc", "bcc"],
                "serialization": "field_colon_display_name_angle_normalized_address",
                "answer_bearing": True,
                "source_artifact_sha256": source_binding["validation_artifact_sha256"],
            }
        ),
        "document_regions": ["structured_headers"],
        "primary_for_quality": False,
        "answer_bearing_fields_included": True,
    }
    annotation_policy_sha256 = _canonical_hash(
        {
            "schema_version": "nerb.enron_structured_weak_labels.v2",
            "contact": "every_valid_parsed_address",
            "person": "plausible_multi_token_display_name",
            "offset_unit": "unicode_scalar",
        }
    )
    slices = (
        {
            "id": "validation_contact_structured_weak",
            "label_artifact_id": "enron_validation_structured_headers",
            "label_strength": "structured_weak",
            "annotation_scope": {
                "entity_classes": ["contact"],
                "document_regions": ["structured_headers"],
                "span_policy_sha256": annotation_policy_sha256,
                "exclusions": ["invalid_or_missing_parsed_addresses"],
            },
            "annotation_completeness": "exhaustive_within_scope",
            "entity_class": "contact",
            "cohort": "all",
            "split_role": "validation",
            "text_view": "structured_headers_v2",
            "text_view_descriptor": view_descriptor,
            "promotion_gate": False,
            "document_ids": document_ids,
        },
        {
            "id": "validation_person_structured_weak",
            "label_artifact_id": "enron_validation_structured_headers",
            "label_strength": "structured_weak",
            "annotation_scope": {
                "entity_classes": ["person"],
                "document_regions": ["structured_headers"],
                "span_policy_sha256": annotation_policy_sha256,
                "exclusions": ["single_token_role_or_ambiguous_display_names"],
            },
            "annotation_completeness": "partial",
            "entity_class": "person",
            "cohort": "all",
            "split_role": "validation",
            "text_view": "structured_headers_v2",
            "text_view_descriptor": view_descriptor,
            "promotion_gate": False,
            "document_ids": document_ids,
        },
    )
    unsupported = (
        {
            "id": "main_validation_open_world_utility",
            "dimension": "independent_exhaustive_negative",
            "reason_code": "independent_exhaustive_validation_labels_unavailable",
        },
        {
            "id": "validation_phone_quality",
            "dimension": "phone_number",
            "reason_code": "independent_phone_labels_unavailable",
        },
        {
            "id": "validation_organization_quality",
            "dimension": "organization_domain",
            "reason_code": "independent_organization_labels_unavailable",
        },
    )
    return _ValidationProjection(
        documents=tuple(documents),
        spans=tuple(spans),
        slices=slices,
        unsupported=unsupported,
        artifact_sha256=artifact_sha256,
        records=records,
    )


def _evaluate_iteration(
    curated: CuratedIteration,
    validation: _ValidationProjection,
    policy: EnronBankPolicy,
) -> dict[str, Any]:
    structural = validate_bank(curated.bank, level="deep", strict=True, check_engine_compile=True)
    structural_summary = {
        "valid": structural["valid"],
        "hash": structural["hash"],
        "stats": structural["stats"],
        "diagnostic_codes": sorted({str(item["code"]) for item in structural["diagnostics"]}),
        "engine_compatible": structural["engine_compatibility"]["compatible"],
    }
    if structural_summary["valid"] is not True or structural_summary["engine_compatible"] is not True:
        raise EnronBankBuildError(f"Iteration {curated.iteration.id} failed private structural validation.")
    gold = _qualified_validation_gold(curated.bank, validation.spans)
    try:
        quality = evaluate_enron_quality(
            curated.bank,
            documents=validation.documents,
            gold_spans=gold,
            slice_specs=validation.slices,
            unsupported_slice_specs=validation.unsupported,
        )
    except EnronQualityError:
        raise EnronBankBuildError(f"Iteration {curated.iteration.id} quality evaluation failed safely.") from None
    contract_codes = set(quality["contract_validation"]["diagnostic_codes"])
    source_metadata = cast(Mapping[str, Any], curated.bank["metadata"])["source"]
    fixture_small_slice_only = (
        isinstance(source_metadata, Mapping)
        and source_metadata.get("fixture_mode") is True
        and contract_codes == {"contract.privacy_small_slice"}
    )
    if quality["evaluated"] is not True or (
        quality["contract_validation"]["valid"] is not True and not fixture_small_slice_only
    ):
        raise EnronBankBuildError(f"Iteration {curated.iteration.id} quality evidence failed closed.")
    return {
        "iteration": curated.iteration,
        "bank": curated.bank,
        "structural": structural_summary,
        "gold": gold,
        "quality": quality,
        "limits": {
            "active_patterns": structural["stats"]["active_totals"]["patterns"],
            "max_active_patterns": policy.max_active_patterns,
            "canonical_json_bytes": len(_canonical_json_bytes(curated.bank)),
            "max_canonical_json_bytes": policy.max_bank_json_bytes,
            "passed": True,
        },
    }


def _qualified_validation_gold(
    bank: Mapping[str, Any],
    spans: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    contact_exact: dict[str, tuple[str, str, str]] = {}
    person_aliases: dict[str, tuple[str, str, str]] = {}
    entities = bank.get("entities")
    if not isinstance(entities, Mapping):
        raise EnronBankBuildError("Iteration bank entity inventory is invalid.")
    for entity_id in ("contact", "person"):
        entity = entities.get(entity_id)
        if not isinstance(entity, Mapping) or entity.get("status") != "active":
            continue
        names = entity.get("names")
        if not isinstance(names, Mapping):
            continue
        for name_id, name in names.items():
            if not isinstance(name_id, str) or not isinstance(name, Mapping) or name.get("status") != "active":
                continue
            patterns = name.get("patterns")
            if not isinstance(patterns, Mapping):
                continue
            for pattern_id, pattern in patterns.items():
                if (
                    not isinstance(pattern_id, str)
                    or not isinstance(pattern, Mapping)
                    or pattern.get("status") != "active"
                ):
                    continue
                value = pattern.get("value")
                if not isinstance(value, str):
                    continue
                pattern_identity = (entity_id, name_id, pattern_id)
                if entity_id == "contact" and pattern.get("kind") == "literal":
                    normalized = _normalize_email(value)
                    if normalized:
                        contact_exact[normalized] = pattern_identity
                elif entity_id == "person" and pattern.get("kind") == "literal":
                    normalized_name = _normalize_person_name(value)
                    if normalized_name:
                        if normalized_name in person_aliases and person_aliases[normalized_name] != pattern_identity:
                            raise EnronBankBuildError("Active person alias maps to multiple canonical identities.")
                        person_aliases[normalized_name] = pattern_identity

    gold: list[dict[str, Any]] = []
    for item in spans:
        entity_class = str(item["entity_class"])
        surface = str(item["surface"])
        identity: tuple[str, str, str] | None
        if entity_class == "contact":
            normalized = _normalize_email(surface)
            identity = contact_exact.get(normalized or "")
        elif entity_class == "person":
            normalized_name = _normalize_person_name(surface)
            identity = person_aliases.get(normalized_name or "")
        else:  # pragma: no cover - closed projection invariant
            identity = None
        gold.append(
            {
                "document_id": item["document_id"],
                "entity_class": entity_class,
                "start": item["start"],
                "end": item["end"],
                "catalog_identity": (
                    None
                    if identity is None
                    else {"entity_id": identity[0], "name_id": identity[1], "pattern_id": identity[2]}
                ),
            }
        )
    return tuple(gold)


def _decide_iterations(evaluated: Sequence[Mapping[str, Any]]) -> tuple[dict[str, Any], ...]:
    if len(evaluated) != 3:
        raise EnronBankBuildError("Bank build requires exactly three frozen construction iterations.")
    contact_summaries = [_slice_by_id(item["quality"], "validation_contact_structured_weak") for item in evaluated]
    protocol_sha256s = {str(item["quality"]["protocol_sha256"]) for item in evaluated}
    if len(protocol_sha256s) != 1:
        raise EnronBankBuildError("Validation protocol changed across construction iterations.")
    if contact_summaries[1]["false_negative"] > contact_summaries[0]["false_negative"]:
        raise EnronBankBuildError("Bounded email fallback regressed structured contact recall.")
    if contact_summaries[1]["false_negative"] != 0:
        raise EnronBankBuildError("Selected email fallback leaves structured validation contact misses.")
    if contact_summaries[1]["cataloged_false_negative"] != 0 or contact_summaries[1]["cataloged_wrong_canonical"] != 0:
        raise EnronBankBuildError("Selected bank has a cataloged contact miss or wrong mapping.")

    decisions = (
        ("discard", "superseded_by_bounded_email_fallback", False),
        ("keep", "best_supported_privacy_recall_without_unsupported_phone_activation", True),
        ("discard", "independent_phone_negative_evidence_unavailable", False),
    )
    records: list[dict[str, Any]] = []
    for item, contact, (decision, reason, selected) in zip(evaluated, contact_summaries, decisions, strict=True):
        iteration = item["iteration"]
        quality = cast(Mapping[str, Any], item["quality"])
        records.append(
            {
                "schema_version": BANK_BUILD_ITERATION_SCHEMA_VERSION,
                "id": iteration.id,
                "parent_id": iteration.parent_id,
                "policy_sha256": iteration.sha256,
                "bank_sha256": hash_bank(cast(Mapping[str, Any], item["bank"])),
                "validation_protocol_sha256": quality["protocol_sha256"],
                "catalog_binding_sha256": quality["catalog_binding_sha256"],
                "quality_run_sha256": quality["run_sha256"],
                "contact_labeled_spans": contact["gold_spans"],
                "contact_labeled_true_positive": contact["true_positive"],
                "contact_labeled_false_negative": contact["false_negative"],
                "contact_labeled_recall": _ratio(contact["true_positive"], contact["gold_spans"]),
                "contact_cataloged_false_negative": contact["cataloged_false_negative"],
                "contact_cataloged_wrong_canonical": contact["cataloged_wrong_canonical"],
                "open_world_metrics_supported": False,
                "utility_metrics_supported": False,
                "active_patterns": item["structural"]["stats"]["active_totals"]["patterns"],
                "canonical_json_bytes": item["limits"]["canonical_json_bytes"],
                "decision": decision,
                "decision_reason_code": reason,
                "selected": selected,
            }
        )
    return tuple(records)


def _slice_by_id(quality: Mapping[str, Any], slice_id: str) -> Mapping[str, Any]:
    result = _slice_by_id_or_none(quality, slice_id)
    if result is not None:
        return result
    raise EnronBankBuildError(f"Quality result is missing required slice {slice_id}.")


def _slice_by_id_or_none(quality: Mapping[str, Any], slice_id: str) -> Mapping[str, Any] | None:
    payload = quality.get("quality")
    if not isinstance(payload, Mapping):
        raise EnronBankBuildError("Quality result is missing its aggregate payload.")
    for item in cast(Sequence[Mapping[str, Any]], payload.get("slices", ())):
        if item.get("id") == slice_id:
            return item
    return None


def _evaluate_cmu_auxiliary(
    bank: Mapping[str, Any],
    annotation_run: Path,
) -> tuple[tuple[dict[str, Any], ...], dict[str, Any]]:
    try:
        source = load_cmu_enron_training_quality_source(annotation_run)
    except EnronAnnotationError:
        raise EnronBankBuildError("Auxiliary CMU annotation run could not be loaded safely.") from None
    documents = {
        str(item["document_id"]): str(item["text"]) for item in cast(Sequence[Mapping[str, Any]], source["documents"])
    }
    person_aliases = _active_person_alias_inventory(bank)
    bindings: list[dict[str, Any]] = []
    for label in cast(Sequence[Mapping[str, Any]], source["labels"]):
        document_id = str(label["document_id"])
        start = int(label["start"])
        end = int(label["end"])
        text = documents.get(document_id)
        if text is None or end > len(text):
            raise EnronBankBuildError("Auxiliary CMU label differs from its bound document.")
        surface_key = _person_literal_catalog_key(text[start:end])
        identity = person_aliases.get(surface_key)
        if identity is not None and not _person_literal_boundaries_match(text, start, end):
            identity = None
        bindings.append(
            {
                "document_id": document_id,
                "start": start,
                "end": end,
                "catalog_identity": (
                    None
                    if identity is None
                    else {"entity_id": identity[0], "name_id": identity[1], "pattern_id": identity[2]}
                ),
            }
        )
    bindings.sort(key=lambda item: (str(item["document_id"]), int(item["start"]), int(item["end"])))
    try:
        quality = evaluate_cmu_enron_training_quality(
            bank,
            annotation_run_dir=annotation_run,
            catalog_bindings=bindings,
        )
    except (EnronAnnotationError, EnronQualityError):
        raise EnronBankBuildError("Auxiliary CMU quality evaluation failed safely.") from None
    if quality["evaluated"] is not True or quality["contract_validation"]["valid"] is not True:
        raise EnronBankBuildError("Auxiliary CMU quality evaluation failed closed.")
    return tuple(bindings), quality


def _active_person_alias_inventory(bank: Mapping[str, Any]) -> dict[str, tuple[str, str, str]]:
    result: dict[str, tuple[str, str, str]] = {}
    entities = cast(Mapping[str, Any], bank.get("entities", {}))
    person = entities.get("person")
    if not isinstance(person, Mapping) or person.get("status") != "active":
        return result
    for name_id, name in cast(Mapping[str, Any], person.get("names", {})).items():
        if not isinstance(name_id, str) or not isinstance(name, Mapping) or name.get("status") != "active":
            continue
        for pattern_id, pattern in cast(Mapping[str, Any], name.get("patterns", {})).items():
            if (
                isinstance(pattern_id, str)
                and isinstance(pattern, Mapping)
                and pattern.get("status") == "active"
                and pattern.get("kind") == "literal"
                and isinstance(pattern.get("value"), str)
            ):
                normalized = _person_literal_catalog_key(str(pattern["value"]))
                identity = ("person", name_id, pattern_id)
                if normalized in result and result[normalized] != identity:
                    raise EnronBankBuildError("Person catalog contains an ambiguous active alias.")
                if normalized:
                    result[normalized] = identity
    return result


def _person_literal_catalog_key(value: str) -> str:
    return " ".join(value.split()).casefold()


def _person_literal_boundaries_match(text: str, start: int, end: int) -> bool:
    if start < 0 or end <= start or end > len(text):
        return False
    left = start == 0 or _is_unicode_word(text[start - 1]) != _is_unicode_word(text[start])
    right = end == len(text) or _is_unicode_word(text[end - 1]) != _is_unicode_word(text[end])
    return left and right


def _is_unicode_word(value: str) -> bool:
    return value == "_" or value.isalnum() or value in {"\u200c", "\u200d"} or unicodedata.category(value)[0] == "M"


def _conformance_cases(
    bank: Mapping[str, Any],
) -> tuple[tuple[dict[str, Any], ...], tuple[dict[str, Any], ...]]:
    positives: list[dict[str, Any]] = []
    negative_specs: list[tuple[set[str], str, str]] = []
    entities = cast(Mapping[str, Any], bank.get("entities", {}))
    bank_sha256 = hash_bank(bank)
    active: list[dict[str, Any]] = []
    for entity_id, entity in sorted(entities.items()):
        if not isinstance(entity_id, str) or not isinstance(entity, Mapping) or entity.get("status") != "active":
            continue
        for name_id, name in sorted(cast(Mapping[str, Any], entity.get("names", {})).items()):
            if not isinstance(name_id, str) or not isinstance(name, Mapping) or name.get("status") != "active":
                continue
            canonical = str(name["canonical"])
            for pattern_id, pattern in sorted(cast(Mapping[str, Any], name.get("patterns", {})).items()):
                if (
                    not isinstance(pattern_id, str)
                    or not isinstance(pattern, Mapping)
                    or pattern.get("status") != "active"
                ):
                    continue
                kind = str(pattern["kind"])
                if kind == "literal":
                    witness = str(pattern["value"])
                elif entity_id == "contact" and pattern_id == "structured_email":
                    witness = f"unknown.{bank_sha256[7:19]}@example.invalid"
                elif entity_id == "phone_number" and pattern_id == "structured_us_phone":
                    witness = "212-555-0198"
                else:
                    raise EnronBankBuildError("Active regex lacks a frozen conformance witness.")
                active.append(
                    {
                        "entity_id": entity_id,
                        "name_id": name_id,
                        "pattern_id": pattern_id,
                        "pattern_kind": kind,
                        "canonical_name": canonical,
                        "pattern": pattern,
                        "witness": witness,
                    }
                )
    if not active:
        raise EnronBankBuildError("Selected bank has no active patterns for conformance.")

    fallback = next(
        (item for item in active if item["entity_id"] == "contact" and item["pattern_id"] == "structured_email"),
        None,
    )
    for item in active:
        witness = str(item["witness"])
        cased = witness.swapcase()
        _append_conformance_positive(positives, cased, ((item, cased, 0),), {"casing"})

        prefix = "<p>Regards,<br>"
        contextual = prefix + witness + "</p>"
        _append_conformance_positive(
            positives,
            contextual,
            ((item, witness, len(prefix)),),
            {"html", "punctuation", "signature"},
        )

        pattern = cast(Mapping[str, Any], item["pattern"])
        if pattern.get("kind") == "literal" and pattern.get("normalize_whitespace") is True:
            spaced = re.sub(r"\s+", " \t ", witness)
            if spaced != witness:
                _append_conformance_positive(positives, spaced, ((item, spaced, 0),), {"whitespace"})

        if (
            pattern.get("kind") == "literal"
            and pattern.get("left_boundary") == "word"
            and pattern.get("right_boundary") == "word"
        ):
            boundary_text = "x" + witness + "y"
            if item["entity_id"] == "contact" and fallback is not None:
                _append_conformance_positive(
                    positives,
                    boundary_text,
                    ((fallback, boundary_text, 0),),
                    {"boundary"},
                )
            else:
                negative_specs.append(({"boundary"}, boundary_text, "literal_word_boundary"))

    if fallback is not None:
        first = f"first.{bank_sha256[7:19]}@example.invalid"
        second = f"second.{bank_sha256[19:31]}@example.invalid"
        separator = " and "
        overlap_text = first + separator + second
        _append_conformance_positive(
            positives,
            overlap_text,
            (
                (fallback, first, 0),
                (fallback, second, len(first) + len(separator)),
            ),
            {"overlap"},
        )

    negative_specs.extend(
        [
            ({"malformed"}, "missing.domain@localhost", "email_missing_domain_suffix"),
            ({"malformed"}, "contact: @example.invalid", "email_missing_local_part"),
            ({"malformed"}, "name@example..invalid", "email_empty_domain_label"),
            ({"malformed"}, "name@example.123", "email_numeric_top_level_domain"),
            ({"malformed", "whitespace"}, "name @example.invalid", "email_embedded_whitespace"),
            ({"malformed"}, "name@-example.invalid", "email_invalid_domain_label"),
            ({"malformed"}, "price@risk ratio", "email_missing_domain_separator"),
            ({"signature"}, "Call 202-555-0198", "phone_fallback_not_promoted"),
            ({"signature"}, "Call 415.555.0199 x123", "phone_extension_fallback_not_promoted"),
            (
                {"boundary", "unicode"},
                f"Ωunknown.{bank_sha256[7:19]}@example.invalidΩ",
                "unicode_word_boundary",
            ),
        ]
    )
    negatives = tuple(
        {
            "schema_version": NEGATIVE_CASE_SCHEMA_VERSION,
            "case_id": f"negative_{index:08d}",
            "text": text,
            "tags": sorted({"negative", *tags}),
            "reason_code": reason,
        }
        for index, (tags, text, reason) in enumerate(negative_specs)
    )
    covered_tags = {tag for item in (*positives, *negatives) for tag in item["tags"]}
    if covered_tags != set(ADVERSARIAL_TAGS):
        raise EnronBankBuildError("Generated conformance suite does not cover every adversarial tag.")
    return tuple(positives), negatives


def _append_conformance_positive(
    cases: list[dict[str, Any]],
    text: str,
    matches: Sequence[tuple[Mapping[str, Any], str, int]],
    tags: set[str],
) -> None:
    expected: list[dict[str, Any]] = []
    for item, matched, scalar_start in matches:
        byte_start = len(text[:scalar_start].encode("utf-8"))
        expected.append(
            {
                "entity_id": item["entity_id"],
                "name_id": item["name_id"],
                "pattern_id": item["pattern_id"],
                "pattern_kind": item["pattern_kind"],
                "canonical_name": item["canonical_name"],
                "string": matched,
                "start": byte_start,
                "end": byte_start + len(matched.encode("utf-8")),
            }
        )
    cases.append(
        {
            "schema_version": POSITIVE_CASE_SCHEMA_VERSION,
            "case_id": f"pattern_{len(cases):08d}",
            "text": text,
            "tags": sorted(tags),
            "expected": expected,
        }
    )


def _write_private_artifacts(
    run: PrivateRun,
    *,
    pool: CandidatePool,
    curated: Sequence[CuratedIteration],
    validation: _ValidationProjection,
    evaluated: Sequence[Mapping[str, Any]],
    iteration_records: Sequence[Mapping[str, Any]],
    selected: CuratedIteration,
    positive_cases: Sequence[Mapping[str, Any]],
    negative_cases: Sequence[Mapping[str, Any]],
    conformance: Mapping[str, Any],
    cmu_bindings: Sequence[Mapping[str, Any]],
    cmu_quality: Mapping[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    artifacts: dict[str, dict[str, Any]] = {}

    for index, item in enumerate(curated, start=1):
        key = f"iteration_{index:02d}_bank"
        name = f"banks/{item.iteration.id}.json"
        _write_run_json(run, name, item.bank)
        artifacts[key] = _artifact_descriptor(run.stage_dir / name, key, records=1)
    _write_run_json(run, "bank.json", selected.bank)
    artifacts["selected_bank"] = _artifact_descriptor(run.stage_dir / "bank.json", "selected_bank", records=1)

    _write_run_jsonl(run, "candidates.jsonl", selected.candidates)
    artifacts["candidates"] = _artifact_descriptor(
        run.stage_dir / "candidates.jsonl", "candidates", records=len(selected.candidates)
    )
    _write_run_json(run, "candidate-funnel.json", selected.funnel)
    artifacts["candidate_funnel"] = _artifact_descriptor(
        run.stage_dir / "candidate-funnel.json", "candidate_funnel", records=1
    )
    _write_run_json(run, "collision-report.json", selected.collisions)
    artifacts["collision_report"] = _artifact_descriptor(
        run.stage_dir / "collision-report.json", "collision_report", records=1
    )
    _write_run_jsonl(run, "iterations.jsonl", iteration_records)
    artifacts["iterations"] = _artifact_descriptor(
        run.stage_dir / "iterations.jsonl", "iterations", records=len(iteration_records)
    )

    _write_run_jsonl(run, "validation/documents.jsonl", validation.documents)
    artifacts["validation_documents"] = _artifact_descriptor(
        run.stage_dir / "validation/documents.jsonl", "validation_documents", records=len(validation.documents)
    )
    _write_run_jsonl(run, "validation/slices.jsonl", validation.slices)
    artifacts["validation_slices"] = _artifact_descriptor(
        run.stage_dir / "validation/slices.jsonl", "validation_slices", records=len(validation.slices)
    )
    _write_run_jsonl(run, "validation/unsupported.jsonl", validation.unsupported)
    artifacts["validation_unsupported"] = _artifact_descriptor(
        run.stage_dir / "validation/unsupported.jsonl",
        "validation_unsupported",
        records=len(validation.unsupported),
    )
    for index, evaluated_item in enumerate(evaluated, start=1):
        gold_name = f"validation/gold-iteration-{index:02d}.jsonl"
        quality_name = f"validation/quality-iteration-{index:02d}.json"
        structural_name = f"validation/structural-iteration-{index:02d}.json"
        gold = cast(Sequence[Mapping[str, Any]], evaluated_item["gold"])
        _write_run_jsonl(run, gold_name, gold)
        _write_run_json(run, quality_name, evaluated_item["quality"])
        _write_run_json(run, structural_name, evaluated_item["structural"])
        artifacts[f"validation_gold_{index:02d}"] = _artifact_descriptor(
            run.stage_dir / gold_name, f"validation_gold_{index:02d}", records=len(gold)
        )
        artifacts[f"validation_quality_{index:02d}"] = _artifact_descriptor(
            run.stage_dir / quality_name, f"validation_quality_{index:02d}", records=1
        )
        artifacts[f"validation_structural_{index:02d}"] = _artifact_descriptor(
            run.stage_dir / structural_name, f"validation_structural_{index:02d}", records=1
        )

    _write_run_jsonl(run, "conformance/positive.jsonl", positive_cases)
    _write_run_jsonl(run, "conformance/negative.jsonl", negative_cases)
    _write_run_json(run, "conformance/result.json", conformance)
    artifacts["conformance_positive"] = _artifact_descriptor(
        run.stage_dir / "conformance/positive.jsonl", "conformance_positive", records=len(positive_cases)
    )
    artifacts["conformance_negative"] = _artifact_descriptor(
        run.stage_dir / "conformance/negative.jsonl", "conformance_negative", records=len(negative_cases)
    )
    artifacts["conformance_result"] = _artifact_descriptor(
        run.stage_dir / "conformance/result.json", "conformance_result", records=1
    )

    if cmu_quality is not None:
        _write_run_jsonl(run, "auxiliary/cmu-train-catalog-bindings.jsonl", cmu_bindings)
        _write_run_json(run, "auxiliary/cmu-train-quality.json", cmu_quality)
        artifacts["cmu_catalog_bindings"] = _artifact_descriptor(
            run.stage_dir / "auxiliary/cmu-train-catalog-bindings.jsonl",
            "cmu_catalog_bindings",
            records=len(cmu_bindings),
        )
        artifacts["cmu_quality"] = _artifact_descriptor(
            run.stage_dir / "auxiliary/cmu-train-quality.json", "cmu_quality", records=1
        )

    artifacts["mining_spool"] = _artifact_descriptor(
        run.stage_dir / "mining.sqlite3", "mining_spool", records=pool.observations
    )
    return artifacts


def _bank_card(
    options: EnronBankBuildOptions,
    *,
    source_binding: Mapping[str, Any],
    pool: CandidatePool,
    selected: CuratedIteration,
    iteration_records: Sequence[Mapping[str, Any]],
    selected_quality: Mapping[str, Any],
    conformance: Mapping[str, Any],
    cmu_quality: Mapping[str, Any] | None,
    artifacts: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    stats = bank_stats(selected.bank)
    contact = _slice_by_id(selected_quality, "validation_contact_structured_weak")
    person = _slice_by_id_or_none(selected_quality, "validation_person_structured_weak")
    nonpromotable = [
        "sealed_final_test_unopened",
        "main_validation_independent_exhaustive_labels_unavailable",
        "main_validation_utility_metrics_unsupported",
    ]
    if source_binding["fixture_mode"] is True:
        nonpromotable.append("fixture_development_split")
    if cmu_quality is None:
        auxiliary: dict[str, Any] = {
            "evaluated": False,
            "reason_code": "annotation_run_not_supplied",
        }
    else:
        cmu_slice = _slice_by_id(cmu_quality, "cmu_person_all_train")
        auxiliary = {
            "evaluated": True,
            "scope": "cmu_meetings_person_train_auxiliary_nonpromotable",
            "label_strength": cmu_slice["label_strength"],
            "annotation_completeness": cmu_slice["annotation_completeness"],
            "documents": cmu_slice["documents"],
            "gold_spans": cmu_slice["gold_spans"],
            "true_positive": cmu_slice["true_positive"],
            "false_negative": cmu_slice["false_negative"],
            "false_positive": cmu_slice["false_positive"],
            "metrics": cmu_slice["metrics"],
            "protocol_sha256": cmu_quality["protocol_sha256"],
            "run_sha256": cmu_quality["run_sha256"],
            "nonpromotable": True,
        }
    card: dict[str, Any] = {
        "schema_version": BANK_CARD_SCHEMA_VERSION,
        "benchmark_version": options.benchmark_version,
        "artifact_kind": "aggregate_private_bank_build",
        "fixture_mode": source_binding["fixture_mode"],
        "promotable": False,
        "nonpromotable_reasons": sorted(nonpromotable),
        "source": {
            key: source_binding[key]
            for key in (
                "dataset_id",
                "dataset_revision",
                "dataset_split",
                "development_manifest_sha256",
                "full_split_manifest_sha256",
                "split_policy_sha256",
                "preparation_manifest_sha256",
                "train_artifact_sha256",
                "train_records",
                "train_groups",
                "validation_artifact_sha256",
                "validation_records",
                "validation_groups",
                "development_memberships_sha256",
                "sealed_test_accessed",
            )
        },
        "charter": {
            "id": "privacy_first_enron_intelligence_v2",
            "primary_user_value": "prevent_sensitive_contact_and_person_name_leakage",
            "recall_priority": True,
            "guarantee_boundary": "active_catalog_patterns_only",
            "entity_classes": [
                {
                    "id": "contact",
                    "user_value": "known_contact_identity_and_unknown_structured_email_discovery",
                    "label_source": "train_and_validation_structured_headers",
                    "active_scope": "recurring_exact_addresses_plus_bounded_unknown_email_fallback",
                },
                {
                    "id": "person",
                    "user_value": "canonical_person_identity_from_observed_full_name_aliases",
                    "label_source": (
                        "train_display_names_sender_body_confirmed_local_parts_and_auxiliary_independent_person_labels"
                    ),
                    "active_scope": "recurring_unique_address_anchored_full_names",
                },
                {
                    "id": "organization_domain",
                    "user_value": "organization_domain_intelligence",
                    "label_source": "train_structured_headers",
                    "active_scope": "draft_until_exact_domain_boundary_is_expressible",
                },
                {
                    "id": "phone_number",
                    "user_value": "unknown_structured_phone_discovery",
                    "label_source": "synthetic_only",
                    "active_scope": "draft_because_independent_negative_evidence_is_unavailable",
                },
            ],
        },
        "builder": {
            "policy_sha256": options.policy.sha256,
            "source_sha256": _builder_implementation_sha256(),
            "candidate_source_sha256": pool.source_sha256,
            "candidate_ledger_sha256": pool.ledger_sha256,
            "train_records": pool.train_records,
            "observations": pool.observations,
            "iteration_count": len(iteration_records),
            "selected_iteration_id": "iteration_02_email_recall",
        },
        "bank": {
            "id": selected.bank["id"],
            "version": selected.bank["version"],
            "canonical_sha256": hash_bank(selected.bank),
            "artifact_sha256": artifacts["selected_bank"]["sha256"],
            "canonical_json_bytes": len(_canonical_json_bytes(selected.bank)),
            "stats": stats,
        },
        "candidate_funnel": selected.funnel,
        "iterations": [dict(item) for item in iteration_records],
        "validation": {
            "label_strength": "structured_weak",
            "protocol_sha256": selected_quality["protocol_sha256"],
            "quality_run_sha256": selected_quality["run_sha256"],
            "contact": _safe_slice_summary(contact),
            "person": (
                _safe_slice_summary(person)
                if person is not None
                else _unsupported_slice_summary("zero_labeled_person_spans")
            ),
            "open_world_metrics_supported": False,
            "utility_metrics_supported": False,
            "unsupported_reason_code": "independent_exhaustive_validation_labels_unavailable",
        },
        "catalog_conformance": dict(conformance["catalog_conformance"]),
        "independent_auxiliary": auxiliary,
        "privacy": {},
        "run_sha256": "",
    }
    privacy_report = {
        "status": "passed",
        "raw_text_included": False,
        "direct_identifiers_included": False,
        "private_paths_included": False,
        "scanner": "nerb.enron_bank_workflow.public_card_scan.v2",
        "scanner_source_sha256": _hash_private_file(Path(__file__)),
        "violation_count": 0,
    }
    privacy_report["report_sha256"] = _canonical_hash(privacy_report)
    card["privacy"] = privacy_report
    card["run_sha256"] = _canonical_hash({key: value for key, value in card.items() if key != "run_sha256"})
    return card


def _safe_slice_summary(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "documents": item["documents"],
        "documents_with_sensitive_gold": item["documents_with_sensitive_gold"],
        "gold_spans": item["gold_spans"],
        "true_positive": item["true_positive"],
        "false_negative": item["false_negative"],
        "cataloged_gold_spans": item["cataloged_gold_spans"],
        "cataloged_true_positive": item["cataloged_true_positive"],
        "cataloged_false_negative": item["cataloged_false_negative"],
        "cataloged_wrong_canonical": item["cataloged_wrong_canonical"],
        "labeled_span_recall": _ratio(item["true_positive"], item["gold_spans"]),
        "catalog_coverage": item["metrics"]["catalog_coverage"],
        "cataloged_recall": item["metrics"]["cataloged_recall"],
        "open_world_recall": None,
        "precision": None,
        "over_redaction_rate": None,
        "negative_document_false_alarm_rate": None,
    }


def _unsupported_slice_summary(reason_code: str) -> dict[str, Any]:
    return {
        "evaluated": False,
        "reason_code": reason_code,
        "documents": 0,
        "documents_with_sensitive_gold": 0,
        "gold_spans": 0,
        "true_positive": 0,
        "false_negative": 0,
        "cataloged_gold_spans": 0,
        "cataloged_true_positive": 0,
        "cataloged_false_negative": 0,
        "cataloged_wrong_canonical": 0,
        "labeled_span_recall": None,
        "catalog_coverage": None,
        "cataloged_recall": None,
        "open_world_recall": None,
        "precision": None,
        "over_redaction_rate": None,
        "negative_document_false_alarm_rate": None,
    }


def _private_manifest(
    options: EnronBankBuildOptions,
    *,
    source_binding: Mapping[str, Any],
    pool: CandidatePool,
    card: Mapping[str, Any],
    artifacts: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    return {
        "schema_version": BANK_BUILD_MANIFEST_SCHEMA_VERSION,
        "benchmark_version": options.benchmark_version,
        "artifact_kind": "private_enron_bank_build",
        "created_at": options.created_at,
        "source": dict(source_binding),
        "builder": {
            "source_sha256": _builder_implementation_sha256(),
            "policy": options.policy.descriptor(),
            "policy_sha256": options.policy.sha256,
            "candidate_source_sha256": pool.source_sha256,
            "candidate_ledger_sha256": pool.ledger_sha256,
        },
        "selected_bank_sha256": card["bank"]["canonical_sha256"],
        "bank_card_run_sha256": card["run_sha256"],
        "artifacts": {key: dict(value) for key, value in sorted(artifacts.items())},
        "privacy": {
            "private_pii_present": True,
            "public_card_privacy_passed": True,
            "sealed_test_accessed": False,
        },
    }


def _validate_public_card(card: Mapping[str, Any]) -> None:
    if set(card) != _PUBLIC_CARD_FIELDS or card.get("schema_version") != BANK_CARD_SCHEMA_VERSION:
        raise EnronBankBuildError("Public bank card schema is invalid.")
    expected_run = _canonical_hash({key: value for key, value in card.items() if key != "run_sha256"})
    if card.get("run_sha256") != expected_run:
        raise EnronBankBuildError("Public bank card run commitment is invalid.")
    violations: list[str] = []
    for path, value in _iter_strings(card):
        if _EMAIL_SHAPE_RE.search(value) or "@" in value:
            violations.append(path)
        elif _PHONE_SHAPE_RE.search(value):
            violations.append(path)
        elif _DOCUMENT_ID_RE.fullmatch(value):
            violations.append(path)
        elif _looks_like_private_path(value):
            violations.append(path)
    if violations:
        raise EnronBankBuildError("Public bank card contains a direct identifier or private path shape.")
    privacy = card.get("privacy")
    if (
        not isinstance(privacy, Mapping)
        or privacy.get("status") != "passed"
        or privacy.get("violation_count") != 0
        or privacy.get("raw_text_included") is not False
        or privacy.get("direct_identifiers_included") is not False
        or privacy.get("private_paths_included") is not False
    ):
        raise EnronBankBuildError("Public bank card privacy declaration is invalid.")


def _iter_strings(value: Any, path: str = "") -> Iterator[tuple[str, str]]:
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, Mapping):
        for key, item in value.items():
            yield from _iter_strings(item, f"{path}/{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, item in enumerate(value):
            yield from _iter_strings(item, f"{path}/{index}")


def _looks_like_private_path(value: str) -> bool:
    if value.startswith(("~/", "~\\", "file://")) or "../" in value or "..\\" in value:
        return True
    if re.search(r"(?i)(?:^|\s)[a-z]:[\\/]", value) or value.startswith("\\\\"):
        return True
    return value.startswith("/")


def verify_enron_bank_build(
    run_dir: Path,
    *,
    annotation_run: Path | None = None,
) -> dict[str, Any]:
    """Deep-verify a committed private build and return aggregate-only evidence."""

    root = _assert_private_run(Path(run_dir))
    initial_tree = _snapshot_private_tree(root)
    initial_marker = _fingerprint_private_artifact(root / "COMMITTED")
    initial_manifest = _fingerprint_private_artifact(root / "manifest.json")
    if (
        initial_tree.get("COMMITTED") != initial_marker.identity
        or initial_marker.sha256 != _PRIVATE_COMMIT_MARKER_SHA256
        or initial_tree.get("manifest.json") != initial_manifest.identity
    ):
        raise EnronBankBuildError("Private bank-build tree changed while verification started.")
    manifest = _read_private_json(root / "manifest.json")
    if (
        not isinstance(manifest, Mapping)
        or manifest.get("schema_version") != BANK_BUILD_MANIFEST_SCHEMA_VERSION
        or not isinstance(manifest.get("artifacts"), Mapping)
    ):
        raise EnronBankBuildError("Private bank-build manifest is invalid.")
    raw_artifacts = cast(Mapping[str, Any], manifest["artifacts"])
    artifact_names = _expected_artifact_names(raw_artifacts)
    _verify_private_tree_inventory(initial_tree, artifact_names)
    artifacts: dict[str, Mapping[str, Any]] = {}
    for artifact_id, expected_name in artifact_names.items():
        descriptor = raw_artifacts.get(artifact_id)
        if not isinstance(descriptor, Mapping):
            raise EnronBankBuildError("Private artifact descriptor schema is invalid.")
        _verify_artifact_descriptor(
            root,
            artifact_id,
            descriptor,
            expected_name=expected_name,
            tree=initial_tree,
        )
        artifacts[artifact_id] = cast(Mapping[str, Any], descriptor)

    card = _read_private_json(root / "bank-card.json")
    if not isinstance(card, Mapping):
        raise EnronBankBuildError("Private bank card is invalid.")
    _validate_public_card(card)
    if manifest.get("bank_card_run_sha256") != card.get("run_sha256"):
        raise EnronBankBuildError("Private manifest does not bind the bank card.")

    bank = _read_private_json(root / "bank.json")
    if not isinstance(bank, Mapping):
        raise EnronBankBuildError("Selected private bank is invalid.")
    structural = validate_bank(bank, level="deep", strict=True, check_engine_compile=True)
    if structural["valid"] is not True or structural["engine_compatibility"]["compatible"] is not True:
        raise EnronBankBuildError("Selected private bank failed deep verification.")
    if hash_bank(bank) != manifest.get("selected_bank_sha256") or hash_bank(bank) != card["bank"]["canonical_sha256"]:
        raise EnronBankBuildError("Selected private bank commitment is invalid.")

    positive = _read_private_jsonl(root / "conformance/positive.jsonl")
    negative = _read_private_jsonl(root / "conformance/negative.jsonl")
    expected_conformance = _read_private_json(root / "conformance/result.json")
    try:
        actual_conformance = evaluate_enron_conformance(bank, positive, negative)
    except EnronConformanceError:
        raise EnronBankBuildError("Private conformance evidence could not be re-evaluated.") from None
    if (
        actual_conformance != expected_conformance
        or actual_conformance["catalog_conformance"] != card["catalog_conformance"]
    ):
        raise EnronBankBuildError("Private conformance evidence changed during verification.")

    documents = _read_private_jsonl(root / "validation/documents.jsonl")
    slices = _read_private_jsonl(root / "validation/slices.jsonl")
    unsupported = _read_private_jsonl(root / "validation/unsupported.jsonl")
    iteration_rows = _read_private_jsonl(root / "iterations.jsonl")
    if len(iteration_rows) != 3:
        raise EnronBankBuildError("Private iteration ledger is incomplete.")
    replayed_iterations: list[dict[str, Any]] = []
    iteration_banks: list[Mapping[str, Any]] = []
    for index in range(1, 4):
        iteration_bank = _read_private_json(root / f"banks/{ITERATION_POLICIES[index - 1].id}.json")
        gold = _read_private_jsonl(root / f"validation/gold-iteration-{index:02d}.jsonl")
        expected_quality = _read_private_json(root / f"validation/quality-iteration-{index:02d}.json")
        if not isinstance(iteration_bank, Mapping) or not isinstance(expected_quality, Mapping):
            raise EnronBankBuildError("Private iteration artifact is invalid.")
        iteration_structural = validate_bank(
            iteration_bank,
            level="deep",
            strict=True,
            check_engine_compile=True,
        )
        if (
            iteration_structural["valid"] is not True
            or iteration_structural["engine_compatibility"]["compatible"] is not True
        ):
            raise EnronBankBuildError("Private iteration bank failed deep verification.")
        try:
            actual_quality = evaluate_enron_quality(
                iteration_bank,
                documents=documents,
                gold_spans=gold,
                slice_specs=slices,
                unsupported_slice_specs=unsupported,
            )
        except EnronQualityError:
            raise EnronBankBuildError("Private validation evidence could not be re-evaluated.") from None
        if actual_quality != expected_quality:
            raise EnronBankBuildError("Private validation evidence changed during verification.")
        if iteration_rows[index - 1]["quality_run_sha256"] != actual_quality["run_sha256"]:
            raise EnronBankBuildError("Private iteration ledger does not bind quality evidence.")
        iteration_banks.append(iteration_bank)
        replayed_iterations.append(
            {
                "iteration": ITERATION_POLICIES[index - 1],
                "bank": iteration_bank,
                "quality": actual_quality,
                "structural": {"stats": iteration_structural["stats"]},
                "limits": {"canonical_json_bytes": len(_canonical_json_bytes(iteration_bank))},
            }
        )

    replayed_ledger = _decide_iterations(replayed_iterations)
    card_builder = card.get("builder")
    if (
        not isinstance(card_builder, Mapping)
        or tuple(iteration_rows) != replayed_ledger
        or card.get("iterations") != [dict(item) for item in replayed_ledger]
        or card_builder.get("selected_iteration_id") != ITERATION_POLICIES[1].id
        or _canonical_json_bytes(bank) != _canonical_json_bytes(iteration_banks[1])
    ):
        raise EnronBankBuildError("Private promotion ledger differs from the replayed decision.")

    cmu_reverified = False
    if "cmu_quality" in artifacts:
        stored_cmu = _read_private_json(root / "auxiliary/cmu-train-quality.json")
        bindings = _read_private_jsonl(root / "auxiliary/cmu-train-catalog-bindings.jsonl")
        if annotation_run is not None:
            try:
                actual_cmu = evaluate_cmu_enron_training_quality(
                    bank,
                    annotation_run_dir=annotation_run,
                    catalog_bindings=bindings,
                )
            except (EnronAnnotationError, EnronQualityError):
                raise EnronBankBuildError("Auxiliary CMU evidence could not be re-evaluated.") from None
            if actual_cmu != stored_cmu:
                raise EnronBankBuildError("Auxiliary CMU evidence changed during verification.")
            cmu_reverified = True

    candidates = _read_private_jsonl(root / "candidates.jsonl")
    actual_funnel = _verify_candidate_ledger(candidates, bank)
    funnel = _read_private_json(root / "candidate-funnel.json")
    if not isinstance(funnel, Mapping) or funnel.get("schema_version") != CANDIDATE_FUNNEL_SCHEMA_VERSION:
        raise EnronBankBuildError("Private candidate funnel is invalid.")
    candidate_count = int(artifacts["candidates"]["records"])
    if len(candidates) != candidate_count or funnel != actual_funnel or funnel != card.get("candidate_funnel"):
        raise EnronBankBuildError("Private candidate funnel does not conserve the candidate ledger.")

    final_tree = _snapshot_private_tree(root)
    final_marker = _fingerprint_private_artifact(root / "COMMITTED")
    final_manifest = _fingerprint_private_artifact(root / "manifest.json")
    if final_tree != initial_tree or final_marker != initial_marker or final_manifest != initial_manifest:
        raise EnronBankBuildError("Private bank-build tree changed during verification.")

    return {
        "schema_version": "nerb.enron_bank_build_verification.v2",
        "valid": True,
        "benchmark_version": manifest["benchmark_version"],
        "fixture_mode": card["fixture_mode"],
        "promotable": False,
        "bank_sha256": hash_bank(bank),
        "bank_card_run_sha256": card["run_sha256"],
        "candidate_count": candidate_count,
        "iteration_count": len(iteration_rows),
        "selected_iteration_id": card["builder"]["selected_iteration_id"],
        "catalog_conformance_passed": True,
        "validation_reverified": True,
        "cmu_reverified": cmu_reverified,
        "sealed_test_accessed": False,
        "privacy": card["privacy"],
    }


def _verify_candidate_ledger(
    candidates: Sequence[Mapping[str, Any]],
    bank: Mapping[str, Any],
) -> dict[str, Any]:
    expected_fields = {
        "schema_version",
        "candidate_id",
        "candidate_type",
        "normalized_value",
        "surfaces",
        "related_values",
        "decision",
        "primary_reason_code",
        "secondary_reason_codes",
        "evidence",
        "bank_ref",
    }
    allowed_types = {
        "contact",
        "contact_fallback",
        "organization_domain",
        "person_alias",
        "phone_fallback",
    }
    seen_ids: set[str] = set()
    seen_pattern_refs: set[tuple[str, str, str]] = set()
    entities = bank.get("entities")
    if not isinstance(entities, Mapping):
        raise EnronBankBuildError("Private candidate ledger bank binding is invalid.")
    for row in candidates:
        if set(row) != expected_fields or row.get("schema_version") != CANDIDATE_SCHEMA_VERSION:
            raise EnronBankBuildError("Private candidate ledger schema is invalid.")
        candidate_id = row.get("candidate_id")
        candidate_type = row.get("candidate_type")
        decision = row.get("decision")
        reason = row.get("primary_reason_code")
        if (
            not isinstance(candidate_id, str)
            or not candidate_id
            or candidate_id in seen_ids
            or candidate_type not in allowed_types
            or decision not in {"active", "draft", "rejected"}
            or not isinstance(reason, str)
            or not reason
            or not isinstance(row.get("surfaces"), list)
            or not isinstance(row.get("related_values"), list)
            or not isinstance(row.get("secondary_reason_codes"), list)
            or not isinstance(row.get("evidence"), Mapping)
        ):
            raise EnronBankBuildError("Private candidate ledger values are invalid.")
        surfaces = cast(list[Any], row["surfaces"])
        related_values = cast(list[Any], row["related_values"])
        secondary_reasons = cast(list[Any], row["secondary_reason_codes"])
        if (
            any(
                not isinstance(surface, Mapping)
                or set(surface) != {"value", "observations"}
                or not isinstance(surface.get("value"), str)
                or type(surface.get("observations")) is not int
                or int(surface["observations"]) <= 0
                for surface in surfaces
            )
            or any(not isinstance(value, str) for value in related_values)
            or any(not isinstance(value, str) for value in secondary_reasons)
        ):
            raise EnronBankBuildError("Private candidate ledger evidence surfaces are invalid.")
        seen_ids.add(candidate_id)
        bank_ref = row.get("bank_ref")
        if decision == "rejected":
            if bank_ref is not None:
                raise EnronBankBuildError("Rejected private candidate unexpectedly references the bank.")
            continue
        if not isinstance(bank_ref, Mapping) or set(bank_ref) != {"entity_id", "name_id", "pattern_ids"}:
            raise EnronBankBuildError("Retained private candidate is missing its bank reference.")
        entity_id = bank_ref.get("entity_id")
        name_id = bank_ref.get("name_id")
        pattern_ids = bank_ref.get("pattern_ids")
        if (
            not isinstance(entity_id, str)
            or not isinstance(name_id, str)
            or not isinstance(pattern_ids, list)
            or not pattern_ids
            or len(pattern_ids) != len(set(pattern_ids))
            or any(not isinstance(item, str) for item in pattern_ids)
        ):
            raise EnronBankBuildError("Private candidate bank reference is invalid.")
        entity = entities.get(entity_id)
        names = entity.get("names") if isinstance(entity, Mapping) else None
        name = names.get(name_id) if isinstance(names, Mapping) else None
        patterns = name.get("patterns") if isinstance(name, Mapping) else None
        if not isinstance(patterns, Mapping):
            raise EnronBankBuildError("Private candidate bank reference does not resolve.")
        for pattern_id in pattern_ids:
            pattern = patterns.get(pattern_id)
            if not isinstance(pattern, Mapping) or pattern.get("status") != decision:
                raise EnronBankBuildError("Private candidate lifecycle differs from its bank pattern.")
            pattern_ref = (entity_id, name_id, pattern_id)
            if pattern_ref in seen_pattern_refs:
                raise EnronBankBuildError("Private bank pattern is referenced by multiple candidates.")
            seen_pattern_refs.add(pattern_ref)
            metadata = pattern.get("metadata")
            if (
                not isinstance(metadata, Mapping)
                or metadata.get("review_status") != decision
                or metadata.get("curation_reason_code") != reason
            ):
                raise EnronBankBuildError("Private candidate rationale differs from its bank pattern.")
            normalized_value = row.get("normalized_value")
            pattern_value = pattern.get("value")
            if candidate_type == "contact":
                corresponds = (
                    isinstance(normalized_value, str) and _normalize_email(str(pattern_value)) == normalized_value
                )
            elif candidate_type == "person_alias":
                corresponds = (
                    isinstance(normalized_value, str)
                    and isinstance(pattern_value, str)
                    and _normalize_person_name(pattern_value) == normalized_value
                )
            elif candidate_type == "organization_domain":
                corresponds = (
                    isinstance(normalized_value, str)
                    and isinstance(pattern_value, str)
                    and pattern_value == "@" + normalized_value
                )
            else:
                corresponds = normalized_value is None and pattern.get("kind") == "regex"
            if not corresponds:
                raise EnronBankBuildError("Private candidate normalized value differs from its bank pattern.")
            evidence = cast(Mapping[str, Any], row["evidence"])
            if candidate_type in {"contact", "person_alias", "organization_domain"} and metadata.get(
                "evidence_sha256"
            ) != evidence.get("evidence_sha256"):
                raise EnronBankBuildError("Private candidate evidence commitment differs from its bank pattern.")
    try:
        return candidate_funnel(candidates)
    except (KeyError, TypeError, ValueError):
        raise EnronBankBuildError("Private candidate funnel could not be recomputed safely.") from None


def _assert_private_run(path: Path) -> Path:
    try:
        root = path.expanduser()
        if any(part == os.pardir for part in root.parts):
            raise EnronBankBuildError("Private bank-build path must not contain parent traversal.")
        if not root.is_absolute():
            root = Path.cwd() / root
    except (OSError, RuntimeError, TypeError, ValueError):
        raise EnronBankBuildError("Private bank-build path is invalid.") from None
    try:
        root_fd = _open_private_directory(root)
        try:
            info = os.fstat(root_fd)
        finally:
            os.close(root_fd)
    except (OSError, ValueError):
        raise EnronBankBuildError("Private bank-build run does not exist safely.") from None
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
        raise EnronBankBuildError("Private bank-build root is not a private regular directory.")
    marker = root / "COMMITTED"
    try:
        with open_private_binary_input(marker) as file:
            marker_info = os.fstat(file.fileno())
            payload = file.read(128)
    except (EnronPrivateIOError, OSError):
        raise EnronBankBuildError("Private bank-build commit marker is invalid.") from None
    if (
        not stat.S_ISREG(marker_info.st_mode)
        or stat.S_ISLNK(marker_info.st_mode)
        or marker_info.st_nlink != 1
        or stat.S_IMODE(marker_info.st_mode) & 0o077
        or payload != b"nerb.enron.private-run.v2\n"
    ):
        raise EnronBankBuildError("Private bank-build commit marker is invalid.")
    return root


def _open_private_directory(path: Path) -> int:
    if path.anchor == "" or len(path.parts) < 2:
        raise EnronBankBuildError("Private bank-build path must identify a directory.")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    current_fd: int | None = None
    try:
        current_fd = os.open(path.anchor, flags)
        for component in path.parts[1:]:
            before = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
                raise EnronBankBuildError("Private bank-build path components must be non-symlink directories.")
            next_fd = os.open(component, flags, dir_fd=current_fd)
            after = os.fstat(next_fd)
            if not stat.S_ISDIR(after.st_mode) or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                os.close(next_fd)
                raise EnronBankBuildError("Private bank-build directory changed while it was opened.")
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except EnronBankBuildError:
        if current_fd is not None:
            os.close(current_fd)
        raise
    except (OSError, TypeError, ValueError):
        if current_fd is not None:
            try:
                os.close(current_fd)
            except OSError:
                pass
        raise EnronBankBuildError("Private bank-build directory could not be opened safely.") from None


def _snapshot_private_tree(root: Path) -> dict[str, _PrivateEntryIdentity]:
    entries: dict[str, _PrivateEntryIdentity] = {}
    root_fd = _open_private_directory(root)
    try:
        root_identity = _private_entry_identity(os.fstat(root_fd), kind="directory")
        _require_private_entry(root_identity)
        entries["."] = root_identity
        _snapshot_private_directory(root_fd, relative="", entries=entries)
        if _private_entry_identity(os.fstat(root_fd), kind="directory") != root_identity:
            raise EnronBankBuildError("Private bank-build root changed while it was inspected.")
    except EnronBankBuildError:
        raise
    except (OSError, TypeError, ValueError):
        raise EnronBankBuildError("Private bank-build tree could not be inspected safely.") from None
    finally:
        os.close(root_fd)
    return entries


def _snapshot_private_directory(
    directory_fd: int,
    *,
    relative: str,
    entries: dict[str, _PrivateEntryIdentity],
) -> None:
    try:
        names = sorted(os.listdir(directory_fd))
    except OSError:
        raise EnronBankBuildError("Private bank-build directory could not be listed safely.") from None
    for name in names:
        if not isinstance(name, str) or name in {os.curdir, os.pardir} or "/" in name:
            raise EnronBankBuildError("Private bank-build entry name is invalid.")
        entry_name = f"{relative}/{name}" if relative else name
        try:
            before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError:
            raise EnronBankBuildError("Private bank-build entry could not be inspected safely.") from None
        if stat.S_ISLNK(before.st_mode):
            raise EnronBankBuildError("Private bank-build tree must not contain symlinks.")
        if stat.S_ISDIR(before.st_mode):
            flags = (
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
            )
            try:
                child_fd = os.open(name, flags, dir_fd=directory_fd)
            except OSError:
                raise EnronBankBuildError("Private bank-build directory could not be opened safely.") from None
            try:
                after = os.fstat(child_fd)
                if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                    raise EnronBankBuildError("Private bank-build directory changed while it was opened.")
                identity = _private_entry_identity(after, kind="directory")
                _require_private_entry(identity)
                entries[entry_name] = identity
                _snapshot_private_directory(child_fd, relative=entry_name, entries=entries)
                if _private_entry_identity(os.fstat(child_fd), kind="directory") != identity:
                    raise EnronBankBuildError("Private bank-build directory changed while it was inspected.")
            finally:
                os.close(child_fd)
            continue
        if not stat.S_ISREG(before.st_mode):
            raise EnronBankBuildError("Private bank-build tree contains a non-regular entry.")
        identity = _private_entry_identity(before, kind="file")
        _require_private_entry(identity)
        entries[entry_name] = identity


def _private_entry_identity(info: os.stat_result, *, kind: str) -> _PrivateEntryIdentity:
    return _PrivateEntryIdentity(
        kind=kind,
        device=info.st_dev,
        inode=info.st_ino,
        mode=stat.S_IMODE(info.st_mode),
        link_count=info.st_nlink,
        size=info.st_size,
        modified_ns=info.st_mtime_ns,
        changed_ns=info.st_ctime_ns,
    )


def _require_private_entry(identity: _PrivateEntryIdentity) -> None:
    if identity.mode & 0o077:
        raise EnronBankBuildError("Private bank-build tree contains a non-private entry.")
    if identity.kind == "file" and identity.link_count != 1:
        raise EnronBankBuildError("Private bank-build files must not have multiple hard links.")


def _expected_artifact_names(raw_artifacts: Mapping[str, Any]) -> dict[str, str]:
    artifact_ids = set(raw_artifacts)
    required_ids = set(_REQUIRED_ARTIFACT_NAMES)
    with_cmu_ids = required_ids | set(_OPTIONAL_CMU_ARTIFACT_NAMES)
    if artifact_ids == required_ids:
        return dict(_REQUIRED_ARTIFACT_NAMES)
    if artifact_ids == with_cmu_ids:
        return {**_REQUIRED_ARTIFACT_NAMES, **_OPTIONAL_CMU_ARTIFACT_NAMES}
    raise EnronBankBuildError("Private bank-build artifact inventory is invalid.")


def _verify_private_tree_inventory(
    tree: Mapping[str, _PrivateEntryIdentity],
    artifact_names: Mapping[str, str],
) -> None:
    expected_files = {"COMMITTED", "manifest.json", *artifact_names.values()}
    expected_directories: set[str] = set()
    for name in expected_files:
        parts = Path(name).parts[:-1]
        for length in range(1, len(parts) + 1):
            expected_directories.add(Path(*parts[:length]).as_posix())
    observed_files = {name for name, identity in tree.items() if identity.kind == "file"}
    observed_directories = {name for name, identity in tree.items() if name != "." and identity.kind == "directory"}
    if observed_files != expected_files or observed_directories != expected_directories:
        raise EnronBankBuildError("Private bank-build file inventory is invalid.")


def _fingerprint_private_artifact(path: Path) -> _PrivateFileFingerprint:
    digest = hashlib.sha256()
    try:
        with open_private_binary_input(path) as file:
            before = _private_entry_identity(os.fstat(file.fileno()), kind="file")
            _require_private_entry(before)
            while chunk := file.read(1024 * 1024):
                digest.update(chunk)
            after = _private_entry_identity(os.fstat(file.fileno()), kind="file")
    except (EnronPrivateIOError, OSError):
        raise EnronBankBuildError("Private artifact could not be fingerprinted safely.") from None
    if before != after:
        raise EnronBankBuildError("Private artifact changed while it was fingerprinted.")
    return _PrivateFileFingerprint(identity=after, sha256=_SHA256_PREFIX + digest.hexdigest())


def _verify_artifact_descriptor(
    root: Path,
    artifact_id: str,
    descriptor: Mapping[str, Any],
    *,
    expected_name: str,
    tree: Mapping[str, _PrivateEntryIdentity],
) -> None:
    if set(descriptor) != {"id", "name", "sha256", "bytes", "records"} or descriptor.get("id") != artifact_id:
        raise EnronBankBuildError("Private artifact descriptor schema is invalid.")
    name = descriptor.get("name")
    if name != expected_name:
        raise EnronBankBuildError("Private artifact name is invalid.")
    assert isinstance(name, str)
    relative = Path(name)
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {os.curdir, os.pardir} for part in relative.parts)
        or relative.as_posix() != name
    ):
        raise EnronBankBuildError("Private artifact name is unsafe.")
    sha256 = descriptor.get("sha256")
    byte_count = descriptor.get("bytes")
    record_count = descriptor.get("records")
    if (
        not isinstance(sha256, str)
        or _SHA256_RE.fullmatch(sha256) is None
        or type(byte_count) is not int
        or byte_count < 0
        or type(record_count) is not int
        or record_count < 0
    ):
        raise EnronBankBuildError("Private artifact descriptor values are invalid.")
    path = root / relative
    expected_identity = tree.get(name)
    if expected_identity is None or expected_identity.kind != "file":
        raise EnronBankBuildError("Private artifact is missing.") from None
    fingerprint = _fingerprint_private_artifact(path)
    if (
        fingerprint.identity != expected_identity
        or byte_count != fingerprint.identity.size
        or sha256 != fingerprint.sha256
    ):
        raise EnronBankBuildError("Private artifact descriptor does not match its file.")
    if name.endswith(".jsonl"):
        try:
            observed_records = sum(1 for _ in iter_strict_jsonl(path, _MAX_PRIVATE_JSONL_LINE_BYTES))
        except EnronPrivateIOError:
            raise EnronBankBuildError("Private JSONL artifact could not be counted safely.") from None
        if observed_records != descriptor.get("records"):
            raise EnronBankBuildError("Private JSONL artifact count is invalid.")


def _write_run_json(run: PrivateRun, name: str, value: Mapping[str, Any]) -> None:
    with run.open_binary(name) as file:
        file.write(_pretty_json_bytes(value))


def _write_run_jsonl(run: PrivateRun, name: str, values: Sequence[Mapping[str, Any]]) -> None:
    if len(values) > _MAX_PRIVATE_JSONL_RECORDS:
        raise EnronBankBuildError("Private JSONL artifact exceeds the record limit.")
    with run.open_binary(name) as file:
        for value in values:
            line = _canonical_json_bytes(value) + b"\n"
            if len(line) > _MAX_PRIVATE_JSONL_LINE_BYTES:
                raise EnronBankBuildError("Private JSONL artifact line exceeds the byte limit.")
            file.write(line)


def _artifact_descriptor(path: Path, artifact_id: str, *, records: int = 0) -> dict[str, Any]:
    size = path.stat().st_size
    return {
        "id": artifact_id,
        "name": path.name
        if path.parent.name not in {"banks", "validation", "conformance", "auxiliary"}
        else (f"{path.parent.name}/{path.name}"),
        "sha256": _hash_private_file(path),
        "bytes": size,
        "records": records,
    }


def _builder_implementation_sha256() -> str:
    digest = hashlib.sha256(b"nerb/enron/bank-builder-implementation/v2\0")
    sources = (
        ("candidate_builder", Path(_bank_builder_module.__file__)),
        ("workflow", Path(__file__)),
    )
    for label, path in sources:
        try:
            payload = path.read_bytes()
        except OSError:
            raise EnronBankBuildError("Bank-builder implementation could not be fingerprinted safely.") from None
        digest.update(label.encode("ascii") + b"\0")
        digest.update(hashlib.sha256(payload).digest())
    return _SHA256_PREFIX + digest.hexdigest()


def _hash_private_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with open_private_binary_input(path) as file:
            while chunk := file.read(1024 * 1024):
                digest.update(chunk)
    except (EnronPrivateIOError, OSError):
        raise EnronBankBuildError("Private artifact could not be hashed safely.") from None
    return _SHA256_PREFIX + digest.hexdigest()


def _read_private_json(path: Path) -> Any:
    try:
        with open_private_binary_input(path) as file:
            payload = file.read(_MAX_PRIVATE_JSON_BYTES + 1)
    except (EnronPrivateIOError, OSError):
        raise EnronBankBuildError("Private JSON artifact could not be read safely.") from None
    if len(payload) > _MAX_PRIVATE_JSON_BYTES:
        raise EnronBankBuildError("Private JSON artifact exceeds the byte limit.")
    try:
        return json.loads(payload, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant)
    except (TypeError, ValueError, UnicodeError):
        raise EnronBankBuildError("Private JSON artifact is invalid.") from None


def _read_private_jsonl(path: Path) -> tuple[dict[str, Any], ...]:
    rows: list[dict[str, Any]] = []
    try:
        for _line_no, raw, row in iter_strict_jsonl(path, _MAX_PRIVATE_JSONL_LINE_BYTES):
            if raw != _canonical_json_bytes(row) + b"\n":
                raise EnronBankBuildError("Private JSONL artifact is not canonical.")
            rows.append(dict(row))
            if len(rows) > _MAX_PRIVATE_JSONL_RECORDS:
                raise EnronBankBuildError("Private JSONL artifact exceeds the record limit.")
    except EnronPrivateIOError:
        raise EnronBankBuildError("Private JSONL artifact could not be read safely.") from None
    return tuple(rows)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError("nonfinite value")


def _pretty_json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise EnronBankBuildError("Private JSON value could not be serialized safely.") from None


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None

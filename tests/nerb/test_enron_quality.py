from __future__ import annotations

import copy
import gc
import json
import os
import re
import sqlite3
import stat
import subprocess
import sys
import threading
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import pytest

import nerb.enron_private_io as private_io_module
import nerb.enron_quality as quality_module
from nerb.engines import compile_bank
from nerb.enron_contract import CHARACTER_POSITION_SEMANTICS, MATCHING_SEMANTICS, validate_enron_quality_output
from nerb.enron_quality import (
    DEFAULT_MAX_QUALITY_DIAGNOSTICS,
    DEFAULT_MAX_QUALITY_GOLD_PER_DOCUMENT,
    DEFAULT_MAX_QUALITY_PREDICTIONS_PER_DOCUMENT,
    DEFAULT_MAX_QUALITY_PREDICTIONS_TOTAL,
    EnronQualityError,
    evaluate_cmu_enron_training_quality,
    evaluate_cmu_enron_training_quality_files,
    evaluate_enron_quality,
    evaluate_enron_quality_files,
    prepare_enron_quality,
)


def _pattern(value: str, *, priority: int = 50) -> dict[str, Any]:
    return {
        "kind": "literal",
        "value": value,
        "description": "Synthetic quality pattern.",
        "status": "active",
        "priority": priority,
        "case_sensitive": True,
        "normalize_whitespace": False,
        "left_boundary": "none",
        "right_boundary": "none",
        "metadata": {},
    }


def _name(canonical: str, value: str) -> dict[str, Any]:
    return {
        "canonical": canonical,
        "description": "Synthetic quality identity.",
        "status": "active",
        "patterns": {"primary": _pattern(value)},
        "metadata": {},
    }


def _bank(names: dict[str, tuple[str, str]] | None = None) -> dict[str, Any]:
    names = names or {
        "alice": ("Alice", "Alice"),
        "alicia": ("Alicia", "Alicia"),
        "noise": ("Noise", "Noise"),
    }
    return {
        "schema_version": "nerb.bank.v1",
        "id": "synthetic_quality_bank",
        "name": "Synthetic Quality Bank",
        "description": "Synthetic bank for aggregate quality tests.",
        "version": "fixture-v1",
        "status": "active",
        "created_at": "2026-07-11T00:00:00Z",
        "updated_at": "2026-07-11T00:00:00Z",
        "unicode_normalization": "none",
        "default_regex_flags": [],
        "entities": {
            "person": {
                "description": "Synthetic people.",
                "status": "active",
                "regex_flags": [],
                "names": {name_id: _name(canonical, value) for name_id, (canonical, value) in names.items()},
                "metadata": {},
            }
        },
        "metadata": {},
    }


_SPAN_POLICY_SHA256 = "sha256:" + "1" * 64


def _document(document_id: str, text: str, *, split_role: str = "validation") -> dict[str, Any]:
    return {
        "document_id": document_id,
        "text": text,
        "text_view": "natural_body",
        "split_role": split_role,
    }


def _gold(
    document_id: str,
    start: int,
    end: int,
    *,
    catalog_name_id: str | None,
    catalog_pattern_id: str = "primary",
) -> dict[str, Any]:
    return {
        "document_id": document_id,
        "entity_class": "person",
        "start": start,
        "end": end,
        "catalog_identity": (
            None
            if catalog_name_id is None
            else {
                "entity_id": "person",
                "name_id": catalog_name_id,
                "pattern_id": catalog_pattern_id,
            }
        ),
    }


def _slice(
    *,
    slice_id: str = "person_all_validation",
    label_strength: str = "independent",
    completeness: str = "exhaustive_within_scope",
    cohort: str = "all",
    split_role: str = "validation",
    promotion_gate: bool = False,
) -> dict[str, Any]:
    return {
        "id": slice_id,
        "label_artifact_id": "synthetic_person_labels",
        "label_strength": label_strength,
        "annotation_scope": {
            "entity_classes": ["person"],
            "document_regions": ["natural_body"],
            "span_policy_sha256": _SPAN_POLICY_SHA256,
            "exclusions": [],
        },
        "annotation_completeness": completeness,
        "entity_class": "person",
        "cohort": cohort,
        "split_role": split_role,
        "text_view": "natural_body",
        "text_view_descriptor": {
            "id": "natural_body",
            "artifact_sha256": "sha256:" + "2" * 64,
            "content_policy_sha256": "sha256:" + "3" * 64,
            "document_regions": ["natural_body"],
            "primary_for_quality": True,
            "answer_bearing_fields_included": False,
        },
        "promotion_gate": promotion_gate,
    }


def _record(
    document_id: str,
    text: str,
    gold: Sequence[Mapping[str, Any]] = (),
    *,
    slice_ids: Sequence[str] = ("person_all_validation",),
    split_role: str = "validation",
) -> dict[str, Any]:
    return {
        "document": _document(document_id, text, split_role=split_role),
        "gold_spans": list(gold),
        "slice_ids": list(slice_ids),
    }


def _run(
    records: Iterable[Mapping[str, Any]],
    *,
    bank: Mapping[str, Any] | None = None,
    slices: Sequence[Mapping[str, Any]] | None = None,
    unsupported: Sequence[Mapping[str, Any]] = (),
    **limits: Any,
) -> dict[str, Any]:
    return evaluate_enron_quality(
        _bank() if bank is None else bank,
        records=records,
        slice_specs=[_slice()] if slices is None else slices,
        unsupported_slice_specs=unsupported,
        **limits,
    )


def test_quality_finalization_heartbeats_inside_each_full_spool_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(quality_module, "ACTIVITY_RECORD_INTERVAL", 1)
    callbacks = 0

    def heartbeat() -> None:
        nonlocal callbacks
        callbacks += 1

    result = _run(
        [
            _record("doc_1", "Alice", [_gold("doc_1", 0, 5, catalog_name_id="alice")]),
            _record("doc_2", "Alicia", [_gold("doc_2", 0, 6, catalog_name_id="alicia")]),
        ],
        activity_callback=heartbeat,
    )

    assert result["evaluated"] is True
    assert callbacks >= 20


def _merge(values: Sequence[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
    result: list[tuple[int, int]] = []
    for start, end in sorted(values):
        if not result or start > result[-1][1]:
            result.append((start, end))
        else:
            result[-1] = (result[-1][0], max(result[-1][1], end))
    return tuple(result)


def _length(values: Sequence[tuple[int, int]]) -> int:
    return sum(end - start for start, end in values)


def _intersection(first: Sequence[tuple[int, int]], second: Sequence[tuple[int, int]]) -> int:
    total = 0
    left = right = 0
    while left < len(first) and right < len(second):
        total += max(0, min(first[left][1], second[right][1]) - max(first[left][0], second[right][0]))
        if first[left][1] <= second[right][1]:
            left += 1
        else:
            right += 1
    return total


def _reference_slice(
    spec: Any,
    document_ids: Sequence[str],
    documents: Mapping[str, Any],
    gold_by_document: Mapping[str, Sequence[Any]],
    predictions_by_document: Mapping[str, Sequence[Any]],
) -> dict[str, Any]:
    gold = sorted(
        (
            item
            for document_id in document_ids
            for item in gold_by_document.get(document_id, ())
            if item.entity_class == spec.entity_class
        ),
        key=lambda item: item.key,
    )
    predictions = sorted(
        (
            item
            for document_id in document_ids
            for item in predictions_by_document.get(document_id, ())
            if item.entity_class == spec.entity_class
        ),
        key=lambda item: (*item.key, item.entity_id, item.name_id, item.pattern_id),
    )
    prediction_indices: dict[tuple[str, str, int, int], list[int]] = defaultdict(list)
    for index, prediction in enumerate(predictions):
        prediction_indices[prediction.key].append(index)
    selected: dict[tuple[str, str, int, int], int] = {}
    for item in gold:
        candidates = prediction_indices.get(item.key, [])
        if not candidates:
            continue
        chosen = candidates[0]
        if item.catalog_identity is not None:
            chosen = next(
                (
                    prediction_index
                    for prediction_index in candidates
                    if predictions[prediction_index].identity == item.catalog_identity[:2]
                ),
                chosen,
            )
        selected[item.key] = chosen

    true_positive = len(selected)
    false_negative = len(gold) - true_positive
    false_positive = len(predictions) - true_positive if spec.open_world_eligible else 0
    predicted_spans = len(predictions) if spec.open_world_eligible else true_positive
    miss_documents: set[str] = set()
    catalog_miss_documents: set[str] = set()
    cataloged_true_positive = cataloged_false_negative = cataloged_wrong_canonical = 0
    for item in gold:
        selected_index = selected.get(item.key)
        if selected_index is None:
            miss_documents.add(item.document_id)
        if item.catalog_identity is None:
            continue
        if selected_index is None:
            cataloged_false_negative += 1
            catalog_miss_documents.add(item.document_id)
        elif predictions[selected_index].identity == item.catalog_identity[:2]:
            cataloged_true_positive += 1
        else:
            cataloged_wrong_canonical += 1
            catalog_miss_documents.add(item.document_id)
    gold_documents = {item.document_id for item in gold}
    catalog_documents = {item.document_id for item in gold if item.catalog_identity is not None}
    cataloged_gold_spans = cataloged_true_positive + cataloged_false_negative + cataloged_wrong_canonical

    sensitive = covered = predicted = leaked_documents = 0
    if spec.open_world_eligible:
        for document_id in document_ids:
            gold_union = _merge([(item.start, item.end) for item in gold if item.document_id == document_id])
            prediction_union = _merge(
                [(item.start, item.end) for item in predictions if item.document_id == document_id]
            )
            gold_count = _length(gold_union)
            covered_count = _intersection(gold_union, prediction_union)
            sensitive += gold_count
            covered += covered_count
            predicted += _length(prediction_union)
            leaked_documents += int(gold_count > covered_count)
        negative_documents = set(document_ids) - gold_documents
        prediction_documents = {item.document_id for item in predictions}
        negative_with_predictions = len(negative_documents & prediction_documents)
        evaluated_characters = sum(len(documents[document_id].text) for document_id in document_ids)
    else:
        negative_documents = set()
        negative_with_predictions = evaluated_characters = 0
        sensitive = covered = predicted = leaked_documents = 0
    leaked = sensitive - covered
    over_redacted = predicted - covered
    ratio = quality_module._ratio
    metrics = {
        "precision": ratio(true_positive, predicted_spans) if spec.open_world_eligible else None,
        "open_world_recall": ratio(true_positive, len(gold)) if spec.open_world_eligible else None,
        "f1": (quality_module._f1(true_positive, false_positive, false_negative) if spec.open_world_eligible else None),
        "catalog_coverage": ratio(cataloged_gold_spans, len(gold)),
        "cataloged_recall": ratio(cataloged_true_positive, cataloged_gold_spans),
        "document_leak_rate": ratio(len(miss_documents), len(gold_documents)) if spec.open_world_eligible else None,
        "cataloged_document_leak_rate": (
            ratio(len(catalog_miss_documents), len(catalog_documents)) if spec.open_world_eligible else None
        ),
        "sensitive_character_recall": ratio(covered, sensitive) if spec.open_world_eligible else None,
        "sensitive_character_leak_rate": ratio(leaked, sensitive) if spec.open_world_eligible else None,
        "negative_document_false_alarm_rate": (
            ratio(negative_with_predictions, len(negative_documents)) if spec.open_world_eligible else None
        ),
        "over_redaction_rate": ratio(over_redacted, evaluated_characters) if spec.open_world_eligible else None,
    }
    return {
        "id": spec.id,
        "label_artifact_id": spec.label_artifact_id,
        "label_strength": spec.label_strength,
        "annotation_scope": spec.annotation_scope,
        "annotation_completeness": spec.annotation_completeness,
        "entity_class": spec.entity_class,
        "cohort": spec.cohort,
        "split_role": spec.split_role,
        "text_view": spec.text_view,
        "promotion_gate": spec.promotion_gate,
        "documents": len(document_ids),
        "documents_with_sensitive_gold": len(gold_documents),
        "documents_with_any_miss": len(miss_documents),
        "documents_with_cataloged_gold": len(catalog_documents),
        "documents_with_any_cataloged_miss": len(catalog_miss_documents),
        "documents_with_any_leaked_character": leaked_documents,
        "gold_spans": len(gold),
        "predicted_spans": predicted_spans,
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "cataloged_gold_spans": cataloged_gold_spans,
        "cataloged_true_positive": cataloged_true_positive,
        "cataloged_false_negative": cataloged_false_negative,
        "cataloged_wrong_canonical": cataloged_wrong_canonical,
        "sensitive_gold_characters": sensitive,
        "covered_sensitive_characters": covered,
        "leaked_sensitive_characters": leaked,
        "predicted_characters": predicted,
        "over_redacted_characters": over_redacted,
        "evaluated_characters": evaluated_characters,
        "negative_documents": len(negative_documents),
        "negative_documents_with_predictions": negative_with_predictions,
        "metrics": metrics,
    }


def _bulk_reference(
    bank: Mapping[str, Any],
    records: Sequence[Mapping[str, Any]],
    slice_plans: Sequence[Mapping[str, Any]],
    unsupported: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    specs = quality_module._prepare_slices(slice_plans)
    declared_unsupported = quality_module._prepare_declared_unsupported(unsupported, specs)
    compiled, _cache_hit = compile_bank(bank, options={"include_statuses": ["active"]})
    active_patterns = quality_module._active_pattern_inventory(compiled.extractable_bank)
    documents: dict[str, Any] = {}
    gold: list[Any] = []
    predictions: list[Any] = []
    membership: dict[str, list[str]] = {spec.id: [] for spec in specs}
    for record in records:
        document = quality_module._prepare_stream_document(record["document"])
        if document.document_id in documents:
            raise EnronQualityError("Document identifiers must be unique.")
        document_gold = quality_module._prepare_stream_gold(
            record["gold_spans"], document, max_items=DEFAULT_MAX_QUALITY_GOLD_PER_DOCUMENT
        )
        slice_ids = quality_module._prepare_stream_slice_ids(record["slice_ids"], {spec.id: spec for spec in specs})
        assigned = tuple({spec.id: spec for spec in specs}[slice_id] for slice_id in slice_ids)
        quality_module._validate_stream_coverage(document, document_gold, assigned, specs)
        quality_module._validate_catalog_identities(document_gold, active_patterns)
        document_predictions = quality_module._scan_document(
            compiled, document, max_predictions=DEFAULT_MAX_QUALITY_PREDICTIONS_PER_DOCUMENT
        )
        documents[document.document_id] = document
        gold.extend(document_gold)
        predictions.extend(document_predictions)
        for slice_id in slice_ids:
            membership[slice_id].append(document.document_id)
    if len(predictions) > DEFAULT_MAX_QUALITY_PREDICTIONS_TOTAL:
        raise EnronQualityError("Quality scan exceeded the cumulative prediction limit.")
    gold.sort(key=lambda item: item.key)
    predictions.sort(key=lambda item: (*item.key, item.entity_id, item.name_id, item.pattern_id))
    gold_by_document: dict[str, list[Any]] = defaultdict(list)
    predictions_by_document: dict[str, list[Any]] = defaultdict(list)
    for item in gold:
        gold_by_document[item.document_id].append(item)
    for item in predictions:
        predictions_by_document[item.document_id].append(item)

    evaluated_slices: list[dict[str, Any]] = []
    unsupported_slices: list[dict[str, str]] = list(declared_unsupported)
    for spec in specs:
        document_ids = sorted(membership[spec.id])
        has_gold = any(
            item.entity_class == spec.entity_class
            for document_id in document_ids
            for item in gold_by_document.get(document_id, ())
        )
        reason = (
            "empty_document_population"
            if not document_ids
            else "zero_gold_promotion_support"
            if spec.promotion_gate and not has_gold
            else "zero_labeled_spans"
            if not spec.open_world_eligible and not has_gold
            else None
        )
        if reason is None:
            evaluated_slices.append(
                _reference_slice(spec, document_ids, documents, gold_by_document, predictions_by_document)
            )
        else:
            unsupported_slices.append({"id": spec.id, "dimension": "population", "reason_code": reason})
    evaluator = quality_module._evaluator_identity()
    policy_sha256 = quality_module._canonical_hash(
        quality_module._execution_policy_descriptor(
            max_predictions_per_document=DEFAULT_MAX_QUALITY_PREDICTIONS_PER_DOCUMENT,
            max_predictions_total=DEFAULT_MAX_QUALITY_PREDICTIONS_TOTAL,
            max_gold_per_document=DEFAULT_MAX_QUALITY_GOLD_PER_DOCUMENT,
            max_diagnostics=DEFAULT_MAX_QUALITY_DIAGNOSTICS,
            max_memberships_total=quality_module.DEFAULT_MAX_QUALITY_MEMBERSHIPS_TOTAL,
            max_spool_bytes=quality_module.DEFAULT_MAX_QUALITY_SPOOL_BYTES,
        )
    )
    protocol_sha256 = quality_module._canonical_hash(
        {
            "evaluator": evaluator,
            "policy_sha256": policy_sha256,
            "documents": [
                {
                    "document_id": item.document_id,
                    "text_sha256": quality_module._hash_bytes(item.text.encode("utf-8")),
                    "unicode_scalars": len(item.text),
                    "text_view": item.text_view,
                    "split_role": item.split_role,
                }
                for item in sorted(documents.values(), key=lambda value: value.document_id)
            ],
            "gold_spans": [
                {
                    "document_id": item.document_id,
                    "entity_class": item.entity_class,
                    "start": item.start,
                    "end": item.end,
                }
                for item in gold
            ],
            "slice_specs": [spec.fingerprint_payload(sorted(membership[spec.id])) for spec in specs],
            "unsupported_slice_specs": list(declared_unsupported),
        }
    )
    canonical_bank_sha256 = quality_module.hash_bank(compiled.bank)
    catalog_binding_sha256 = quality_module._canonical_hash(
        {
            "schema_version": "nerb.enron-catalog-binding.v2",
            "bank_sha256": canonical_bank_sha256,
            "bindings": [
                {
                    "document_id": item.document_id,
                    "entity_class": item.entity_class,
                    "start": item.start,
                    "end": item.end,
                    "catalog_identity": (
                        None
                        if item.catalog_identity is None
                        else {
                            "entity_id": item.catalog_identity[0],
                            "name_id": item.catalog_identity[1],
                            "pattern_id": item.catalog_identity[2],
                        }
                    ),
                }
                for item in gold
            ],
        }
    )
    quality = {
        "evaluated": bool(evaluated_slices),
        "matching_semantics": MATCHING_SEMANTICS,
        "character_position_semantics": CHARACTER_POSITION_SEMANTICS,
        "slices": evaluated_slices,
    }
    raw_validation = validate_enron_quality_output(quality)
    contract_validation = {
        "valid": raw_validation["valid"],
        "diagnostic_codes": sorted({str(item["code"]) for item in raw_validation["diagnostics"]}),
    }
    if any(spec.promotion_gate for spec in specs) and contract_validation["valid"] is not True:
        raise EnronQualityError("Promotion-gated quality output failed standalone contract validation.")
    run_sha256 = quality_module._canonical_hash(
        {
            "protocol_sha256": protocol_sha256,
            "catalog_binding_sha256": catalog_binding_sha256,
            "canonical_bank_sha256": canonical_bank_sha256,
            "engine_bank_sha256": compiled.bank_hash,
            "quality": quality,
            "contract_validation": contract_validation,
            "unsupported_slices": unsupported_slices,
        }
    )
    return {
        "schema_version": quality_module.QUALITY_EXECUTION_SCHEMA_VERSION,
        "evaluator": evaluator,
        "evaluator_sha256": quality_module._canonical_hash(evaluator),
        "policy_sha256": policy_sha256,
        "protocol_sha256": protocol_sha256,
        "catalog_binding_sha256": catalog_binding_sha256,
        "run_sha256": run_sha256,
        "bank": {"canonical_sha256": canonical_bank_sha256, "engine_sha256": compiled.bank_hash},
        "evaluated": bool(evaluated_slices),
        "quality": quality,
        "contract_validation": contract_validation,
        "unsupported_slices": unsupported_slices,
    }


def _complex_case() -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    bank = _bank()
    bank["entities"]["person"]["names"]["alice"]["patterns"]["alicia_qualifier"] = {
        "kind": "regex",
        "value": r"Alici[a]",
        "description": "Independently adjudicated overlap qualifier.",
        "status": "active",
        "priority": 100,
        "regex_flags": [],
        "metadata": {},
    }
    bank["entities"]["person"]["names"]["alicia"]["patterns"]["primary"]["priority"] = 10
    weak = _slice(
        slice_id="person_weak_validation",
        label_strength="structured_weak",
        completeness="partial",
        cohort="weak",
    )
    records = [
        _record(
            "doc_1",
            "Café Alice",
            [_gold("doc_1", 5, 10, catalog_name_id="alice")],
            slice_ids=("person_all_validation", "person_weak_validation"),
        ),
        _record(
            "doc_2",
            "Bob",
            [_gold("doc_2", 0, 3, catalog_name_id=None)],
            slice_ids=("person_all_validation", "person_weak_validation"),
        ),
        _record(
            "doc_3",
            "Alicia",
            [_gold("doc_3", 0, 6, catalog_name_id="alice", catalog_pattern_id="alicia_qualifier")],
            slice_ids=("person_all_validation", "person_weak_validation"),
        ),
        _record("doc_4", "Noise"),
    ]
    return bank, records, [_slice(), weak]


def test_streaming_matches_test_local_authoritative_bulk_reference_exactly() -> None:
    bank, records, slices = _complex_case()
    unsupported = [{"id": "known_novel", "dimension": "known_novel", "reason_code": "unavailable"}]
    actual = _run(records, bank=bank, slices=slices, unsupported=unsupported)
    expected = _bulk_reference(bank, records, slices, unsupported)

    assert actual == expected
    item = actual["quality"]["slices"][0]
    assert item["true_positive"] == 2
    assert item["false_positive"] == item["false_negative"] == 1
    assert item["cataloged_wrong_canonical"] == 1
    assert item["sensitive_gold_characters"] == 14
    assert item["covered_sensitive_characters"] == 11
    assert item["negative_documents"] == item["negative_documents_with_predictions"] == 1
    weak = actual["quality"]["slices"][1]
    assert weak["metrics"]["precision"] is None
    assert weak["predicted_spans"] == weak["true_positive"]


@pytest.mark.parametrize(
    ("records", "plans"),
    [
        ([], [_slice()]),
        (
            [_record("doc_1", "No match")],
            [
                _slice(
                    label_strength="structured_weak",
                    completeness="partial",
                )
            ],
        ),
    ],
)
def test_streaming_matches_bulk_reference_for_empty_failure_states(
    records: list[dict[str, Any]], plans: list[dict[str, Any]]
) -> None:
    assert _run(records, slices=plans) == _bulk_reference(_bank(), records, plans)


def test_record_and_per_document_gold_order_do_not_change_any_output() -> None:
    bank, records, slices = _complex_case()
    baseline = _run(records, bank=bank, slices=slices)
    reordered = copy.deepcopy(list(reversed(records)))
    for record in reordered:
        record["gold_spans"].reverse()
        record["slice_ids"].reverse()

    assert _run(reordered, bank=bank, slices=slices) == baseline


def test_protocol_excludes_catalog_adjudication_but_catalog_digest_binds_it() -> None:
    uncataloged = _run([_record("doc_1", "Alice", [_gold("doc_1", 0, 5, catalog_name_id=None)])])
    cataloged = _run([_record("doc_1", "Alice", [_gold("doc_1", 0, 5, catalog_name_id="alice")])])

    assert cataloged["protocol_sha256"] == uncataloged["protocol_sha256"]
    assert cataloged["catalog_binding_sha256"] != uncataloged["catalog_binding_sha256"]
    assert cataloged["run_sha256"] != uncataloged["run_sha256"]


def test_consumed_slice_membership_is_part_of_the_protocol_commitment() -> None:
    weak = _slice(
        slice_id="person_weak_validation",
        label_strength="structured_weak",
        completeness="partial",
        cohort="weak",
    )
    plans = [_slice(), weak]
    baseline = _run(
        [
            _record(
                "doc_1",
                "Alice",
                [_gold("doc_1", 0, 5, catalog_name_id="alice")],
                slice_ids=("person_all_validation", "person_weak_validation"),
            ),
            _record("doc_2", "Noise"),
        ],
        slices=plans,
    )
    changed = _run(
        [
            _record(
                "doc_1",
                "Alice",
                [_gold("doc_1", 0, 5, catalog_name_id="alice")],
                slice_ids=("person_all_validation", "person_weak_validation"),
            ),
            _record(
                "doc_2",
                "Noise",
                slice_ids=("person_all_validation", "person_weak_validation"),
            ),
        ],
        slices=plans,
    )

    assert changed["protocol_sha256"] != baseline["protocol_sha256"]


def test_unicode_overlap_and_negative_document_arithmetic() -> None:
    bank = _bank({"alice": ("Alice", "Alice"), "lice": ("lice", "lice"), "noise": ("Noise", "Noise")})
    records = [
        _record("doc_1", "éAlice", [_gold("doc_1", 1, 6, catalog_name_id="alice")]),
        _record("doc_2", "Noise"),
    ]
    result = _run(records, bank=bank)
    item = result["quality"]["slices"][0]

    assert item["true_positive"] == 1
    assert item["negative_documents"] == 1
    assert item["negative_documents_with_predictions"] == 1
    assert item["sensitive_gold_characters"] == item["covered_sensitive_characters"] == 5
    assert item["evaluated_characters"] == 11


def test_wider_prediction_is_an_exact_span_miss_but_covers_sensitive_characters() -> None:
    result = _run(
        [_record("doc_1", "Alice Smith", [_gold("doc_1", 0, 5, catalog_name_id="alice")])],
        bank=_bank({"alice": ("Alice", "Alice Smith")}),
    )
    item = result["quality"]["slices"][0]

    assert (item["true_positive"], item["false_positive"], item["false_negative"]) == (0, 1, 1)
    assert (item["cataloged_false_negative"], item["cataloged_wrong_canonical"]) == (1, 0)
    assert item["documents_with_any_miss"] == 1
    assert item["documents_with_any_leaked_character"] == 0
    assert item["covered_sensitive_characters"] == item["sensitive_gold_characters"] == 5
    assert item["leaked_sensitive_characters"] == 0
    assert item["predicted_characters"] == 11
    assert item["over_redacted_characters"] == 6
    assert item["metrics"]["open_world_recall"] == 0.0
    assert item["metrics"]["sensitive_character_recall"] == 1.0


def test_overlapping_gold_and_predictions_count_character_unions_once() -> None:
    session = prepare_enron_quality(_bank(), slice_specs=[_slice()])

    class Compiled:
        def finditer(self, _text: str, *, max_matches: int) -> list[dict[str, Any]]:
            assert max_matches >= 2
            return [
                {
                    "entity_id": "person",
                    "name_id": "alice",
                    "pattern_id": "primary",
                    "start": 0,
                    "end": 5,
                    "offset_unit": "byte",
                },
                {
                    "entity_id": "person",
                    "name_id": "alice",
                    "pattern_id": "primary",
                    "start": 1,
                    "end": 5,
                    "offset_unit": "byte",
                },
            ]

    session._compiled = Compiled()
    session.consume(
        _document("doc_1", "Alice"),
        [_gold("doc_1", 0, 5, catalog_name_id=None), _gold("doc_1", 1, 5, catalog_name_id=None)],
        ["person_all_validation"],
    )
    item = session.finish()["quality"]["slices"][0]

    assert item["true_positive"] == 2
    assert item["sensitive_gold_characters"] == 5
    assert item["predicted_characters"] == 5
    assert item["covered_sensitive_characters"] == 5
    assert item["over_redacted_characters"] == 0


def test_prepare_compiles_once_and_consume_never_recompiles(monkeypatch: pytest.MonkeyPatch) -> None:
    original = quality_module.compile_bank
    calls = 0

    def counted(*args: Any, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(quality_module, "compile_bank", counted)
    session = prepare_enron_quality(_bank(), slice_specs=[_slice()])
    session.consume(
        _document("doc_1", "Alice"),
        [_gold("doc_1", 0, 5, catalog_name_id="alice")],
        ["person_all_validation"],
    )
    session.consume(_document("doc_2", "Noise"), [], ["person_all_validation"])
    session.finish()

    assert calls == 1


def test_exact_span_prefers_expected_canonical_identity_when_multiple_predictions_exist() -> None:
    session = prepare_enron_quality(_bank(), slice_specs=[_slice()])

    class Compiled:
        def finditer(self, _text: str, *, max_matches: int) -> list[dict[str, Any]]:
            assert max_matches > 1
            return [
                {
                    "entity_id": "person",
                    "name_id": "alicia",
                    "pattern_id": "primary",
                    "start": 0,
                    "end": 5,
                    "offset_unit": "byte",
                },
                {
                    "entity_id": "person",
                    "name_id": "alice",
                    "pattern_id": "primary",
                    "start": 0,
                    "end": 5,
                    "offset_unit": "byte",
                },
            ]

    session._compiled = Compiled()
    session.consume(
        _document("doc_1", "Alice"),
        [_gold("doc_1", 0, 5, catalog_name_id="alice")],
        ["person_all_validation"],
    )
    item = session.finish()["quality"]["slices"][0]

    assert item["cataloged_true_positive"] == 1
    assert item["cataloged_wrong_canonical"] == 0


@pytest.mark.parametrize(
    "record",
    [
        {
            "entity_id": "person",
            "name_id": "alice",
            "pattern_id": "primary",
            "start": 0,
            "end": 5,
            "offset_unit": "char",
        },
        {
            "entity_id": "person",
            "name_id": "alice",
            "pattern_id": "primary",
            "start": "0",
            "end": 5,
            "offset_unit": "byte",
        },
        {
            "entity_id": "person",
            "name_id": "alice",
            "pattern_id": "primary",
            "start": 0,
            "end": 6,
            "offset_unit": "byte",
        },
    ],
)
def test_native_prediction_offsets_must_be_bounded_utf8_bytes(record: dict[str, Any]) -> None:
    class Compiled:
        def finditer(self, _text: str, *, max_matches: int) -> list[dict[str, Any]]:
            assert max_matches > 0
            return [record]

    session = prepare_enron_quality(_bank(), slice_specs=[_slice()])
    session._compiled = Compiled()

    with pytest.raises(EnronQualityError, match="bounded offsets|byte length"):
        session.consume(_document("doc_1", "Alice"), [], ["person_all_validation"])


def test_per_document_prediction_ceiling_fails_closed_and_cleans(tmp_path: Path) -> None:
    class Compiled:
        def finditer(self, _text: str, *, max_matches: int) -> list[dict[str, Any]]:
            assert max_matches == 1
            return [
                {
                    "entity_id": "person",
                    "name_id": "alice",
                    "pattern_id": "primary",
                    "start": 0,
                    "end": 1,
                    "offset_unit": "byte",
                },
                {
                    "entity_id": "person",
                    "name_id": "alice",
                    "pattern_id": "primary",
                    "start": 1,
                    "end": 2,
                    "offset_unit": "byte",
                },
            ]

    spool = tmp_path / "per-document.sqlite3"
    session = prepare_enron_quality(
        _bank(),
        slice_specs=[_slice()],
        spool_path=spool,
        max_predictions_per_document=1,
    )
    session._compiled = Compiled()

    with pytest.raises(EnronQualityError, match="per-document prediction"):
        session.consume(_document("doc_1", "AA"), [], ["person_all_validation"])
    assert not spool.exists()


def test_empty_and_terminal_session_states_fail_closed(tmp_path: Path) -> None:
    spool = tmp_path / "empty.sqlite3"
    session = prepare_enron_quality(_bank(), slice_specs=[_slice()], spool_path=spool)
    result = session.finish()

    assert result["evaluated"] is False
    assert result["quality"]["slices"] == []
    assert result["unsupported_slices"] == [
        {"id": "person_all_validation", "dimension": "population", "reason_code": "empty_document_population"}
    ]
    assert not spool.exists()
    with pytest.raises(EnronQualityError, match="not active"):
        session.finish()
    with pytest.raises(EnronQualityError, match="not active"):
        session.consume(_document("doc_1", "Alice"), [], ["person_all_validation"])


def test_context_abandonment_and_duplicate_failure_clean_the_spool(tmp_path: Path) -> None:
    abandoned = tmp_path / "abandoned.sqlite3"
    with prepare_enron_quality(_bank(), slice_specs=[_slice()], spool_path=abandoned):
        assert abandoned.exists()
    assert not abandoned.exists()

    duplicate = tmp_path / "duplicate.sqlite3"
    session = prepare_enron_quality(_bank(), slice_specs=[_slice()], spool_path=duplicate)
    session.consume(_document("doc_1", "Alice"), [], ["person_all_validation"])
    with pytest.raises(EnronQualityError, match="unique"):
        session.consume(_document("doc_1", "Noise"), [], ["person_all_validation"])
    assert not duplicate.exists()
    with pytest.raises(EnronQualityError, match="not active"):
        session.finish()

    dropped = tmp_path / "dropped.sqlite3"
    dropped_session = prepare_enron_quality(_bank(), slice_specs=[_slice()], spool_path=dropped)
    assert dropped.exists()
    del dropped_session
    gc.collect()
    assert not dropped.exists()


def test_promotion_membership_must_cover_every_matching_document() -> None:
    promotion = _slice(split_role="test", promotion_gate=True)
    support = _slice(slice_id="support_test", split_role="test", cohort="support")
    session = prepare_enron_quality(_bank(), slice_specs=[promotion, support])

    with pytest.raises(EnronQualityError, match="complete role"):
        session.consume(_document("doc_1", "Alice", split_role="test"), [], ["support_test"])


def test_active_catalog_validation_and_gold_limit_fail_the_same_as_reference() -> None:
    invalid = [_record("doc_1", "Alice", [_gold("doc_1", 0, 5, catalog_name_id="missing")])]
    with pytest.raises(EnronQualityError) as streaming:
        _run(invalid)
    with pytest.raises(EnronQualityError) as reference:
        _bulk_reference(_bank(), invalid, [_slice()])
    assert str(streaming.value) == str(reference.value)

    session = prepare_enron_quality(_bank(), slice_specs=[_slice()], max_gold_per_document=1)
    with pytest.raises(EnronQualityError, match="gold spans exceed"):
        session.consume(
            _document("doc_1", "Alice Noise"),
            [_gold("doc_1", 0, 5, catalog_name_id="alice"), _gold("doc_1", 6, 11, catalog_name_id="noise")],
            ["person_all_validation"],
        )


def test_cumulative_prediction_limit_fails_and_cleans(tmp_path: Path) -> None:
    spool = tmp_path / "predictions.sqlite3"
    session = prepare_enron_quality(_bank(), slice_specs=[_slice()], spool_path=spool, max_predictions_total=1)
    session.consume(_document("doc_1", "Alice"), [], ["person_all_validation"])
    with pytest.raises(EnronQualityError, match="cumulative prediction"):
        session.consume(_document("doc_2", "Noise"), [], ["person_all_validation"])
    assert not spool.exists()


def test_document_utf8_byte_limit_fails_before_scan_or_commitment_hashing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(quality_module, "DEFAULT_MAX_SCAN_INPUT_BYTES", 8)
    for index, text in enumerate(("x" * 9, "é" * 5)):
        spool = tmp_path / f"oversized-{index}.sqlite3"
        session = prepare_enron_quality(_bank(), slice_specs=[_slice()], spool_path=spool)
        with pytest.raises(EnronQualityError, match="native scan byte limit"):
            session.consume(_document(f"doc_{index}", text), [], ["person_all_validation"])
        assert not spool.exists()

    invalid_spool = tmp_path / "invalid-utf8.sqlite3"
    invalid_session = prepare_enron_quality(_bank(), slice_specs=[_slice()], spool_path=invalid_spool)
    with pytest.raises(EnronQualityError, match="valid UTF-8"):
        invalid_session.consume(_document("doc_invalid", "\ud800"), [], ["person_all_validation"])
    assert not invalid_spool.exists()


def test_membership_and_spool_byte_limits_fail_closed_and_are_policy_bound(tmp_path: Path) -> None:
    second = _slice(
        slice_id="person_weak_validation",
        label_strength="structured_weak",
        completeness="partial",
        cohort="weak",
    )
    membership_spool = tmp_path / "memberships.sqlite3"
    membership_session = prepare_enron_quality(
        _bank(),
        slice_specs=[_slice(), second],
        spool_path=membership_spool,
        max_memberships_total=1,
    )
    with pytest.raises(EnronQualityError, match="memberships exceed"):
        membership_session.consume(
            _document("doc_1", "Alice"),
            [],
            ["person_all_validation", "person_weak_validation"],
        )
    assert not membership_spool.exists()

    byte_spool = tmp_path / "bounded.sqlite3"
    byte_session = prepare_enron_quality(
        _bank(),
        slice_specs=[_slice()],
        spool_path=byte_spool,
        max_spool_bytes=64 * 1024,
    )
    with pytest.raises(EnronQualityError, match="failed safely|byte limit"):
        for index in range(10_000):
            byte_session.consume(
                _document(f"doc_{index:08d}", ""),
                [],
                ["person_all_validation"],
            )
    assert not byte_spool.exists()


def test_full_validation_prediction_envelope_is_bound_into_the_policy() -> None:
    assert DEFAULT_MAX_QUALITY_PREDICTIONS_TOTAL == 5_000_000
    expected = quality_module._canonical_hash(
        quality_module._execution_policy_descriptor(
            max_predictions_per_document=DEFAULT_MAX_QUALITY_PREDICTIONS_PER_DOCUMENT,
            max_predictions_total=5_000_000,
            max_gold_per_document=DEFAULT_MAX_QUALITY_GOLD_PER_DOCUMENT,
            max_diagnostics=DEFAULT_MAX_QUALITY_DIAGNOSTICS,
            max_memberships_total=quality_module.DEFAULT_MAX_QUALITY_MEMBERSHIPS_TOTAL,
            max_spool_bytes=quality_module.DEFAULT_MAX_QUALITY_SPOOL_BYTES,
        )
    )
    result = _run([_record("doc_1", "Alice")])

    assert result["policy_sha256"] == expected
    with pytest.raises(EnronQualityError, match="frozen execution envelope"):
        prepare_enron_quality(
            _bank(),
            slice_specs=[_slice()],
            max_predictions_total=5_000_001,
        )


def test_zero_labeled_weak_slice_is_explicitly_unsupported() -> None:
    weak = _slice(
        slice_id="person_weak_validation",
        label_strength="structured_weak",
        completeness="partial",
        cohort="weak",
    )
    result = _run(
        [_record("doc_1", "No labels", slice_ids=("person_weak_validation",))],
        slices=[weak],
    )

    assert result["evaluated"] is False
    assert result["quality"]["slices"] == []
    assert result["unsupported_slices"] == [
        {
            "id": "person_weak_validation",
            "dimension": "population",
            "reason_code": "zero_labeled_spans",
        }
    ]


def test_run_fingerprint_binds_normalized_contract_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    records = [_record("doc_1", "Alice", [_gold("doc_1", 0, 5, catalog_name_id="alice")])]
    baseline = _run(records)
    monkeypatch.setattr(
        quality_module,
        "validate_enron_quality_output",
        lambda _quality: {"valid": True, "diagnostics": [{"code": "contract.synthetic_probe"}]},
    )

    changed = _run(records)

    assert changed["protocol_sha256"] == baseline["protocol_sha256"]
    assert changed["quality"] == baseline["quality"]
    assert changed["contract_validation"] == {
        "valid": True,
        "diagnostic_codes": ["contract.synthetic_probe"],
    }
    assert changed["run_sha256"] != baseline["run_sha256"]


def test_compile_failure_is_privacy_safe_and_creates_no_spool(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    marker = "PRIVATE CANONICAL AND SURFACE"

    def leaking_compile(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError(marker)

    monkeypatch.setattr(quality_module, "compile_bank", leaking_compile)
    spool = tmp_path / "compile-failure.sqlite3"
    with pytest.raises(EnronQualityError, match="compiled safely") as error:
        prepare_enron_quality(
            _bank({"private": ("Private Canonical", "Private Surface")}),
            slice_specs=[_slice()],
            spool_path=spool,
        )

    assert marker not in str(error.value)
    assert "Private" not in str(error.value)
    assert not spool.exists()


def test_diagnostics_are_opaque_deterministic_and_bounded_to_100() -> None:
    session = prepare_enron_quality(_bank(), slice_specs=[_slice()])
    document_ids = [f"doc_{index:04d}" for index in range(250)]
    for document_id in document_ids:
        session.consume(
            _document(document_id, "Bob"),
            [_gold(document_id, 0, 3, catalog_name_id=None)],
            ["person_all_validation"],
        )
    diagnostics = session.diagnostics
    state = session.retained_state
    session.finish()

    assert len(diagnostics) == DEFAULT_MAX_QUALITY_DIAGNOSTICS
    assert state["diagnostics"] == DEFAULT_MAX_QUALITY_DIAGNOSTICS
    assert state["diagnostic_events"] == 500
    assert all(set(item) == {"id", "slice_id", "reason_code"} for item in diagnostics)
    assert "doc_" not in json.dumps(diagnostics)

    reordered = prepare_enron_quality(_bank(), slice_specs=[_slice()])
    for document_id in reversed(document_ids):
        reordered.consume(
            _document(document_id, "Bob"),
            [_gold(document_id, 0, 3, catalog_name_id=None)],
            ["person_all_validation"],
        )
    assert reordered.diagnostics == diagnostics
    reordered.finish()


def test_metadata_spool_contains_no_text_or_predictions_and_is_private(tmp_path: Path) -> None:
    spool = tmp_path / "metadata.sqlite3"
    session = prepare_enron_quality(_bank(), slice_specs=[_slice()], spool_path=spool)
    session.consume(
        _document("doc_private", "PRIVATE_MARKER Alice"),
        [_gold("doc_private", 15, 20, catalog_name_id="alice")],
        ["person_all_validation"],
    )
    payload = spool.read_bytes()

    assert os.stat(spool).st_mode & 0o077 == 0
    assert b"PRIVATE_MARKER" not in payload
    assert b"predictions" not in payload
    assert session.retained_state["retained_documents"] == 0
    assert session.retained_state["retained_predictions"] == 0
    session.finish()


def test_implicit_metadata_spool_accepts_pinned_sticky_shared_temp_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    temp_root = tmp_path / "shared-sticky-temp"
    temp_root.mkdir(mode=0o700)
    temp_root.chmod(0o1777)
    monkeypatch.setattr(quality_module.tempfile, "tempdir", os.fspath(temp_root))

    session = prepare_enron_quality(_bank(), slice_specs=[_slice()])
    session.consume(
        _document("doc_private", "PRIVATE_MARKER Alice"),
        [_gold("doc_private", 15, 20, catalog_name_id="alice")],
        ["person_all_validation"],
    )
    session.finish()

    entries = list(temp_root.iterdir())
    assert len(entries) == 1
    tombstone = entries[0]
    assert re.fullmatch(r"\.nerb-cleanup-[0-9a-f]{48}", tombstone.name)
    assert tombstone.is_dir()
    assert stat.S_IMODE(tombstone.stat().st_mode) == 0o700
    for path in tombstone.rglob("*"):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            assert stat.S_IMODE(info.st_mode) == 0o700
        else:
            assert stat.S_ISREG(info.st_mode)
            assert stat.S_IMODE(info.st_mode) == 0o600
            assert info.st_size == 0


def test_implicit_metadata_spool_rejects_nonsticky_shared_temp_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    temp_root = tmp_path / "unsafe-shared-temp"
    temp_root.mkdir(mode=0o700)
    temp_root.chmod(0o777)
    monkeypatch.setattr(quality_module.tempfile, "tempdir", os.fspath(temp_root))

    with pytest.raises(EnronQualityError, match="metadata spool could not be created safely"):
        prepare_enron_quality(_bank(), slice_specs=[_slice()])

    assert not list(temp_root.iterdir())


def test_metadata_spool_uses_memory_journal_and_temp_storage_without_sidecars(tmp_path: Path) -> None:
    spool = tmp_path / "owned-metadata.sqlite3"
    session = prepare_enron_quality(_bank(), slice_specs=[_slice()], spool_path=spool)

    assert session._connection.execute("PRAGMA journal_mode").fetchone() == ("memory",)
    assert session._connection.execute("PRAGMA temp_store").fetchone() == (2,)
    assert sorted(path.name for path in tmp_path.iterdir()) == [spool.name]

    session.consume(_document("doc_1", "Alice"), [], ["person_all_validation"])
    session.finish()
    _assert_single_empty_cleanup_tombstone(tmp_path)


def test_metadata_spool_fails_closed_when_sqlite_declines_memory_journal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    actual_connect = sqlite3.connect

    class DeclinedCursor:
        def fetchone(self) -> tuple[str]:
            return ("delete",)

    class DecliningConnection:
        def __init__(self, connection: sqlite3.Connection) -> None:
            self._connection = connection

        def execute(self, statement: str, *args: Any) -> Any:
            cursor = self._connection.execute(statement, *args)
            if statement.strip().upper() == "PRAGMA JOURNAL_MODE=MEMORY":
                return DeclinedCursor()
            return cursor

        def __getattr__(self, name: str) -> Any:
            return getattr(self._connection, name)

    monkeypatch.setattr(
        quality_module.sqlite3,
        "connect",
        lambda *args, **kwargs: DecliningConnection(actual_connect(*args, **kwargs)),
    )
    spool = tmp_path / "declined.sqlite3"

    with pytest.raises(EnronQualityError, match="metadata spool could not be created safely"):
        prepare_enron_quality(_bank(), slice_specs=[_slice()], spool_path=spool)
    _assert_single_empty_cleanup_tombstone(tmp_path)


def test_metadata_spool_unproven_close_retains_setup_cleanup_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    actual_connect = sqlite3.connect
    wrappers: list[FailingSetupAndCloseConnection] = []

    class FailingSetupAndCloseConnection:
        def __init__(self, connection: sqlite3.Connection) -> None:
            self._connection = connection
            self.fail_close = True

        def execute(self, _statement: str, *_args: Any) -> None:
            raise sqlite3.OperationalError("injected setup failure")

        def close(self) -> None:
            self._connection.close()
            if self.fail_close:
                raise sqlite3.OperationalError("injected close failure")

        def __getattr__(self, name: str) -> Any:
            return getattr(self._connection, name)

    def connect(*args: Any, **kwargs: Any) -> FailingSetupAndCloseConnection:
        wrapper = FailingSetupAndCloseConnection(actual_connect(*args, **kwargs))
        wrappers.append(wrapper)
        return wrapper

    monkeypatch.setattr(quality_module.sqlite3, "connect", connect)
    spool = tmp_path / "cleanup-failure.sqlite3"

    with pytest.raises(EnronQualityError, match="writer could not be closed safely") as caught:
        prepare_enron_quality(_bank(), slice_specs=[_slice()], spool_path=spool)

    assert isinstance(caught.value.__cause__, sqlite3.OperationalError)
    assert spool.exists()
    assert len(quality_module._PENDING_SPOOL_CLEANUPS) == 1
    wrappers[0].fail_close = False
    quality_module._retry_pending_spool_cleanups()
    _assert_single_empty_cleanup_tombstone(tmp_path)
    assert not quality_module._PENDING_SPOOL_CLEANUPS


@pytest.mark.parametrize(
    ("interrupt_before_close", "control_error"),
    [
        pytest.param(False, KeyboardInterrupt(), id="after-close"),
        pytest.param(True, SystemExit(23), id="before-close"),
    ],
)
def test_terminal_cleanup_defers_connection_close_control_until_spool_is_settled(
    tmp_path: Path,
    interrupt_before_close: bool,
    control_error: KeyboardInterrupt | SystemExit,
) -> None:
    spool = tmp_path / "interrupted-close.sqlite3"
    session = prepare_enron_quality(_bank(), slice_specs=[_slice()], spool_path=spool)
    connection = session._connection
    accounting_before = _cleanup_fd_accounting_snapshot()

    class OneShotInterruptedClose:
        def __init__(self) -> None:
            self.close_calls = 0

        def close(self) -> None:
            self.close_calls += 1
            if self.close_calls == 1 and interrupt_before_close:
                raise control_error
            connection.close()
            if self.close_calls == 1:
                raise control_error

        def __getattr__(self, name: str) -> Any:
            return getattr(connection, name)

    interrupted = OneShotInterruptedClose()
    session._connection = cast(sqlite3.Connection, interrupted)

    with pytest.raises(type(control_error)) as caught:
        session.finish()

    if isinstance(control_error, SystemExit):
        assert isinstance(caught.value, SystemExit)
        assert caught.value.code == control_error.code
    assert interrupted.close_calls == 2
    assert session._state == "finished"
    assert session._result is not None
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connection.execute("SELECT 1")
    _assert_single_empty_cleanup_tombstone(tmp_path)
    assert _cleanup_fd_accounting_snapshot() == accounting_before


def test_cross_thread_close_rejection_retains_live_writer_and_cleanup_authority(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    actual_connect = sqlite3.connect

    def thread_affine_connect(*args: Any, **kwargs: Any) -> sqlite3.Connection:
        kwargs["check_same_thread"] = True
        return actual_connect(*args, **kwargs)

    monkeypatch.setattr(quality_module.sqlite3, "connect", thread_affine_connect)
    spool = tmp_path / "cross-thread-close.sqlite3"
    session = prepare_enron_quality(_bank(), slice_specs=[_slice()], spool_path=spool)
    file_fd = session._spool_cleanup.file_fd
    parent_fd = session._spool_cleanup.parent_fd
    file_identity = os.fstat(file_fd).st_dev, os.fstat(file_fd).st_ino
    parent_identity = os.fstat(parent_fd).st_dev, os.fstat(parent_fd).st_ino
    outcomes: list[EnronQualityError | None] = []

    worker = threading.Thread(target=lambda: outcomes.append(session._terminate("failed")))
    worker.start()
    worker.join(timeout=5)

    assert not worker.is_alive()
    assert len(outcomes) == 1
    assert isinstance(outcomes[0], EnronQualityError)
    assert "writer could not be closed safely" in str(outcomes[0])
    assert session._state == "cleanup_pending"
    assert len(quality_module._PENDING_SPOOL_CLEANUPS) == 1
    assert spool.exists()
    assert (os.fstat(file_fd).st_dev, os.fstat(file_fd).st_ino) == file_identity
    assert (os.fstat(parent_fd).st_dev, os.fstat(parent_fd).st_ino) == parent_identity

    session._connection.execute("PRAGMA user_version=37")
    session._connection.commit()
    assert session._connection.execute("PRAGMA user_version").fetchone() == (37,)
    assert [path.name for path in tmp_path.iterdir()] == [spool.name]

    assert session._terminate("failed") is None
    assert session._state == "failed"
    assert not quality_module._PENDING_SPOOL_CLEANUPS
    _assert_single_empty_cleanup_tombstone(tmp_path)


def test_persistent_sqlite_close_error_returns_once_without_wiping_or_releasing(
    tmp_path: Path,
) -> None:
    spool = tmp_path / "persistent-close.sqlite3"
    session = prepare_enron_quality(_bank(), slice_specs=[_slice()], spool_path=spool)
    connection = session._connection
    file_fd = session._spool_cleanup.file_fd
    parent_fd = session._spool_cleanup.parent_fd
    file_identity = os.fstat(file_fd).st_dev, os.fstat(file_fd).st_ino
    parent_identity = os.fstat(parent_fd).st_dev, os.fstat(parent_fd).st_ino

    class PersistentCloseError:
        def __init__(self) -> None:
            self.close_calls = 0
            self.fail_close = True

        def close(self) -> None:
            self.close_calls += 1
            if self.fail_close:
                raise sqlite3.OperationalError("injected persistent close failure")
            connection.close()

        def __getattr__(self, name: str) -> Any:
            return getattr(connection, name)

    wrapper = PersistentCloseError()
    session._connection = cast(sqlite3.Connection, wrapper)

    cleanup_error = session._terminate("failed")

    assert isinstance(cleanup_error, EnronQualityError)
    assert wrapper.close_calls == 1
    assert session._state == "cleanup_pending"
    assert len(quality_module._PENDING_SPOOL_CLEANUPS) == 1
    assert spool.exists()
    assert (os.fstat(file_fd).st_dev, os.fstat(file_fd).st_ino) == file_identity
    assert (os.fstat(parent_fd).st_dev, os.fstat(parent_fd).st_ino) == parent_identity
    connection.execute("PRAGMA user_version=41")
    connection.commit()
    assert connection.execute("PRAGMA user_version").fetchone() == (41,)
    assert [path.name for path in tmp_path.iterdir()] == [spool.name]

    blocked_spool = tmp_path / "must-not-open.sqlite3"
    with pytest.raises(EnronQualityError, match="prior quality metadata spool writer is still live"):
        prepare_enron_quality(_bank(), slice_specs=[_slice()], spool_path=blocked_spool)
    assert wrapper.close_calls == 2
    assert not blocked_spool.exists()

    wrapper.fail_close = False
    assert session._terminate("failed") is None
    assert wrapper.close_calls == 3
    assert session._state == "failed"
    assert not quality_module._PENDING_SPOOL_CLEANUPS
    _assert_single_empty_cleanup_tombstone(tmp_path)


def test_owner_retry_serializes_settlement_against_new_prepare(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    spool = tmp_path / "serialized-owner.sqlite3"
    session = prepare_enron_quality(_bank(), slice_specs=[_slice()], spool_path=spool)
    connection = session._connection

    class OneShotCloseGate:
        fail_close = True

        def close(self) -> None:
            if self.fail_close:
                raise sqlite3.OperationalError("injected close failure")
            connection.close()

        def __getattr__(self, name: str) -> Any:
            return getattr(connection, name)

    close_gate = OneShotCloseGate()
    session._connection = cast(sqlite3.Connection, close_gate)
    assert isinstance(session._terminate("failed"), EnronQualityError)
    assert len(quality_module._PENDING_SPOOL_CLEANUPS) == 1
    close_gate.fail_close = False

    expected_identity = (session._spool_identity.device, session._spool_identity.inode)
    real_wipe = quality_module._wipe_and_quarantine_pinned_private_file
    wipe_entered = threading.Event()
    permit_wipe = threading.Event()
    prepare_done = threading.Event()
    old_wipe_calls = 0

    def block_old_bundle_wipe(*args: Any, **kwargs: Any) -> tuple[bool, bool, int]:
        nonlocal old_wipe_calls
        if args[4] == expected_identity:
            old_wipe_calls += 1
            wipe_entered.set()
            if not permit_wipe.wait(timeout=5):
                raise RuntimeError("timed out waiting to release synthetic wipe gate")
        return real_wipe(*args, **kwargs)

    monkeypatch.setattr(quality_module, "_wipe_and_quarantine_pinned_private_file", block_old_bundle_wipe)
    owner_results: list[EnronQualityError | None] = []
    owner_errors: list[BaseException] = []
    prepared_sessions: list[Any] = []
    prepare_errors: list[BaseException] = []
    new_spool = tmp_path / "serialized-new.sqlite3"

    def settle_owner() -> None:
        try:
            owner_results.append(session._terminate("failed"))
        except BaseException as exc:
            owner_errors.append(exc)

    def prepare_new_session() -> None:
        try:
            prepared_sessions.append(prepare_enron_quality(_bank(), slice_specs=[_slice()], spool_path=new_spool))
        except BaseException as exc:
            prepare_errors.append(exc)
        finally:
            prepare_done.set()

    owner = threading.Thread(target=settle_owner)
    owner.start()
    assert wipe_entered.wait(timeout=5)
    creator = threading.Thread(target=prepare_new_session)
    creator.start()

    assert not prepare_done.wait(timeout=0.2)
    assert not new_spool.exists()
    permit_wipe.set()
    owner.join(timeout=5)
    creator.join(timeout=5)

    assert not owner.is_alive()
    assert not creator.is_alive()
    assert owner_errors == []
    assert prepare_errors == []
    assert owner_results == [None]
    assert old_wipe_calls == 1
    assert session._state == "failed"
    assert session._pending_cleanup.settled is True
    assert not quality_module._PENDING_SPOOL_CLEANUPS
    assert len(prepared_sessions) == 1
    assert new_spool.exists()

    prepared_sessions[0].finish()
    assert not quality_module._PENDING_SPOOL_CLEANUPS


def test_dropped_session_parks_unclosed_writer_and_cleanup_descriptors_for_retry(tmp_path: Path) -> None:
    spool = tmp_path / "dropped-pending-close.sqlite3"
    session = prepare_enron_quality(_bank(), slice_specs=[_slice()], spool_path=spool)
    connection = session._connection

    class PersistentCloseError:
        def __init__(self) -> None:
            self.fail_close = True

        def close(self) -> None:
            if self.fail_close:
                raise sqlite3.OperationalError("injected persistent close failure")
            connection.close()

        def __getattr__(self, name: str) -> Any:
            return getattr(connection, name)

    wrapper = PersistentCloseError()
    session._connection = cast(sqlite3.Connection, wrapper)
    file_fd = session._spool_cleanup.file_fd
    parent_fd = session._spool_cleanup.parent_fd

    del session
    gc.collect()

    assert len(quality_module._PENDING_SPOOL_CLEANUPS) == 1
    assert spool.exists()
    os.fstat(file_fd)
    os.fstat(parent_fd)
    connection.execute("PRAGMA user_version=43")
    connection.commit()

    wrapper.fail_close = False
    quality_module._retry_pending_spool_cleanups()
    assert not quality_module._PENDING_SPOOL_CLEANUPS
    _assert_single_empty_cleanup_tombstone(tmp_path)


def test_wipe_failure_retains_closed_writer_bundle_and_blocks_new_sessions_until_private_bytes_are_zeroed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    marker = "PRIVATE_SYNTHETIC_SPOOL_MARKER_9f6b7a"
    spool = tmp_path / "wipe-retry.sqlite3"
    session = prepare_enron_quality(_bank(), slice_specs=[_slice()], spool_path=spool)
    session._connection.execute("CREATE TABLE private_probe (value TEXT NOT NULL)")
    session._connection.execute("INSERT INTO private_probe VALUES (?)", (marker,))
    session._connection.commit()
    assert marker.encode() in spool.read_bytes()
    file_fd = session._spool_cleanup.file_fd
    parent_fd = session._spool_cleanup.parent_fd
    real_wipe = quality_module._wipe_and_quarantine_pinned_private_file
    permit_wipe = False
    wipe_calls = 0

    def fail_wipe_until_permitted(*args: Any, **kwargs: Any) -> tuple[bool, bool, int]:
        nonlocal wipe_calls
        wipe_calls += 1
        if not permit_wipe:
            raise quality_module.EnronPrivateIOError("injected wipe failure")
        return real_wipe(*args, **kwargs)

    monkeypatch.setattr(quality_module, "_wipe_and_quarantine_pinned_private_file", fail_wipe_until_permitted)

    cleanup_error = session._terminate("failed")

    assert isinstance(cleanup_error, EnronQualityError)
    assert "could not be cleaned safely" in str(cleanup_error)
    assert session._state == "cleanup_pending"
    assert session._pending_cleanup.writer_closed is True
    assert session._pending_cleanup.settled is False
    assert len(quality_module._PENDING_SPOOL_CLEANUPS) == 1
    assert marker.encode() in spool.read_bytes()
    os.fstat(file_fd)
    os.fstat(parent_fd)
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        session._connection.execute("SELECT 1")

    blocked_spool = tmp_path / "blocked-by-private-bytes.sqlite3"
    with pytest.raises(EnronQualityError, match="still contains private bytes"):
        prepare_enron_quality(_bank(), slice_specs=[_slice()], spool_path=blocked_spool)
    assert wipe_calls == 2
    assert not blocked_spool.exists()
    assert marker.encode() in spool.read_bytes()

    permit_wipe = True
    assert session._terminate("failed") is None
    assert session._state == "failed"
    assert session._pending_cleanup.settled is True
    assert not quality_module._PENDING_SPOOL_CLEANUPS
    _assert_single_empty_cleanup_tombstone(tmp_path)
    assert marker.encode() not in next(tmp_path.iterdir()).read_bytes()


def test_post_transition_wipe_control_recognizes_authenticated_zero_payload_and_settles(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    spool = tmp_path / "post-wipe-control.sqlite3"
    session = prepare_enron_quality(_bank(), slice_specs=[_slice()], spool_path=spool)
    file_fd = session._spool_cleanup.file_fd
    parent_fd = session._spool_cleanup.parent_fd
    real_wipe = quality_module._wipe_and_quarantine_pinned_private_file
    wipe_calls = 0

    def interrupt_after_wipe(*args: Any, **kwargs: Any) -> tuple[bool, bool, int]:
        nonlocal wipe_calls
        wipe_calls += 1
        result = real_wipe(*args, **kwargs)
        if wipe_calls == 1:
            raise KeyboardInterrupt
        return result

    monkeypatch.setattr(quality_module, "_wipe_and_quarantine_pinned_private_file", interrupt_after_wipe)

    with pytest.raises(KeyboardInterrupt):
        session.finish()

    assert wipe_calls == 2
    assert session._state == "finished"
    assert session._pending_cleanup.settled is True
    assert not quality_module._PENDING_SPOOL_CLEANUPS
    _assert_single_empty_cleanup_tombstone(tmp_path)
    for descriptor in (file_fd, parent_fd):
        with pytest.raises(OSError):
            os.fstat(descriptor)


def test_gc_publication_retries_one_shot_control_before_explicit_bundle_publish(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    spool = tmp_path / "gc-publication.sqlite3"
    session = prepare_enron_quality(_bank(), slice_specs=[_slice()], spool_path=spool)
    connection = session._connection

    class CloseFailure:
        fail_close = True

        def close(self) -> None:
            if self.fail_close:
                raise sqlite3.OperationalError("injected close failure")
            connection.close()

        def __getattr__(self, name: str) -> Any:
            return getattr(connection, name)

    wrapper = CloseFailure()
    session._connection = cast(sqlite3.Connection, wrapper)
    file_fd = session._spool_cleanup.file_fd
    parent_fd = session._spool_cleanup.parent_fd
    real_publish = quality_module._publish_pending_spool_cleanup
    publication_calls = 0

    def interrupt_at_publisher_entry(*args: Any, **kwargs: Any) -> Any:
        nonlocal publication_calls
        publication_calls += 1
        if publication_calls == 1:
            raise KeyboardInterrupt
        return real_publish(*args, **kwargs)

    monkeypatch.setattr(quality_module, "_publish_pending_spool_cleanup", interrupt_at_publisher_entry)

    del session
    gc.collect()

    assert publication_calls >= 2
    assert len(quality_module._PENDING_SPOOL_CLEANUPS) == 1
    assert spool.exists()
    os.fstat(file_fd)
    os.fstat(parent_fd)

    wrapper.fail_close = False
    quality_module._retry_pending_spool_cleanups()
    assert not quality_module._PENDING_SPOOL_CLEANUPS
    _assert_single_empty_cleanup_tombstone(tmp_path)


def test_constructor_rollback_publication_retries_post_publish_control_for_owned_spool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    actual_connect = sqlite3.connect
    wrappers: list[Any] = []

    class CloseFailure:
        def __init__(self, connection: sqlite3.Connection) -> None:
            self._connection = connection
            self.fail_close = True

        def close(self) -> None:
            if self.fail_close:
                raise sqlite3.OperationalError("injected close failure")
            self._connection.close()

        def __getattr__(self, name: str) -> Any:
            return getattr(self._connection, name)

    def connect(*args: Any, **kwargs: Any) -> CloseFailure:
        wrapper = CloseFailure(actual_connect(*args, **kwargs))
        wrappers.append(wrapper)
        return wrapper

    def fail_constructor(**_kwargs: Any) -> None:
        raise RuntimeError("injected constructor failure")

    real_publish = quality_module._publish_pending_spool_cleanup_once
    publication_calls = 0

    def interrupt_after_publish(pending: Any) -> None:
        nonlocal publication_calls
        publication_calls += 1
        real_publish(pending)
        if publication_calls == 1:
            raise SystemExit(47)

    monkeypatch.setattr(quality_module.sqlite3, "connect", connect)
    monkeypatch.setattr(quality_module, "EnronQualitySession", fail_constructor)
    monkeypatch.setattr(quality_module, "_publish_pending_spool_cleanup_once", interrupt_after_publish)

    with pytest.raises(EnronQualityError, match="writer could not be closed safely") as caught:
        prepare_enron_quality(_bank(), slice_specs=[_slice()])

    assert isinstance(caught.value.__cause__, SystemExit)
    assert caught.value.__cause__.code == 47
    assert publication_calls >= 2
    assert len(quality_module._PENDING_SPOOL_CLEANUPS) == 1
    pending = next(iter(quality_module._PENDING_SPOOL_CLEANUPS.values()))
    assert pending.spool_cleanup.owned_run is not None
    assert pending.spool_path.exists()
    os.fstat(pending.spool_cleanup.file_fd)
    os.fstat(pending.spool_cleanup.parent_fd)

    wrappers[0].fail_close = False
    quality_module._retry_pending_spool_cleanups()
    assert pending.settled is True
    assert not quality_module._PENDING_SPOOL_CLEANUPS
    assert not pending.spool_path.exists()


def test_setup_rollback_publication_retries_pre_publish_control_for_explicit_spool(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    actual_connect = sqlite3.connect
    wrappers: list[Any] = []

    class SetupAndCloseFailure:
        def __init__(self, connection: sqlite3.Connection) -> None:
            self._connection = connection
            self.fail_close = True

        def execute(self, statement: str, *args: Any) -> Any:
            if statement.strip().upper() == "PRAGMA LOCKING_MODE=EXCLUSIVE":
                raise sqlite3.OperationalError("injected setup failure")
            return self._connection.execute(statement, *args)

        def close(self) -> None:
            if self.fail_close:
                raise sqlite3.OperationalError("injected close failure")
            self._connection.close()

        def __getattr__(self, name: str) -> Any:
            return getattr(self._connection, name)

    def connect(*args: Any, **kwargs: Any) -> SetupAndCloseFailure:
        wrapper = SetupAndCloseFailure(actual_connect(*args, **kwargs))
        wrappers.append(wrapper)
        return wrapper

    real_publish = quality_module._publish_pending_spool_cleanup_once
    publication_calls = 0

    def interrupt_before_publish(pending: Any) -> None:
        nonlocal publication_calls
        publication_calls += 1
        if publication_calls == 1:
            raise SystemExit(53)
        real_publish(pending)

    monkeypatch.setattr(quality_module.sqlite3, "connect", connect)
    monkeypatch.setattr(quality_module, "_publish_pending_spool_cleanup_once", interrupt_before_publish)
    spool = tmp_path / "setup-publication.sqlite3"

    with pytest.raises(EnronQualityError, match="writer could not be closed safely") as caught:
        prepare_enron_quality(_bank(), slice_specs=[_slice()], spool_path=spool)

    assert isinstance(caught.value.__cause__, SystemExit)
    assert caught.value.__cause__.code == 53
    assert publication_calls >= 2
    assert len(quality_module._PENDING_SPOOL_CLEANUPS) == 1
    pending = next(iter(quality_module._PENDING_SPOOL_CLEANUPS.values()))
    assert pending.spool_cleanup.owned_run is None
    assert pending.spool_path == spool
    assert spool.exists()
    os.fstat(pending.spool_cleanup.file_fd)
    os.fstat(pending.spool_cleanup.parent_fd)

    wrappers[0].fail_close = False
    quality_module._retry_pending_spool_cleanups()
    assert pending.settled is True
    assert not quality_module._PENDING_SPOOL_CLEANUPS
    _assert_single_empty_cleanup_tombstone(tmp_path)


def test_constructor_rollback_helper_entry_control_publishes_exact_live_bundle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    actual_connect = sqlite3.connect
    wrappers: list[Any] = []

    class PersistentCloseError:
        def __init__(self, connection: sqlite3.Connection) -> None:
            self._connection = connection
            self.fail_close = True
            self.close_calls = 0

        def close(self) -> None:
            self.close_calls += 1
            if self.fail_close:
                raise sqlite3.OperationalError("injected persistent close failure")
            self._connection.close()

        def __getattr__(self, name: str) -> Any:
            return getattr(self._connection, name)

    def connect(*args: Any, **kwargs: Any) -> PersistentCloseError:
        wrapper = PersistentCloseError(actual_connect(*args, **kwargs))
        wrappers.append(wrapper)
        return wrapper

    def fail_constructor(**_kwargs: Any) -> None:
        raise RuntimeError("injected constructor failure")

    real_helper = quality_module._settle_or_publish_pending_spool_cleanup
    helper_calls = 0

    def interrupt_at_helper_entry(*args: Any, **kwargs: Any) -> Any:
        nonlocal helper_calls
        helper_calls += 1
        if helper_calls == 1:
            raise KeyboardInterrupt
        return real_helper(*args, **kwargs)

    monkeypatch.setattr(quality_module.sqlite3, "connect", connect)
    monkeypatch.setattr(quality_module, "EnronQualitySession", fail_constructor)
    monkeypatch.setattr(quality_module, "_settle_or_publish_pending_spool_cleanup", interrupt_at_helper_entry)
    spool = tmp_path / "constructor-helper-entry.sqlite3"

    with pytest.raises(EnronQualityError, match="writer could not be closed safely") as caught:
        prepare_enron_quality(_bank(), slice_specs=[_slice()], spool_path=spool)

    assert isinstance(caught.value.__cause__, KeyboardInterrupt)
    assert helper_calls == 1
    assert wrappers[0].close_calls == 0
    assert len(quality_module._PENDING_SPOOL_CLEANUPS) == 1
    pending = next(iter(quality_module._PENDING_SPOOL_CLEANUPS.values()))
    assert pending.connection is wrappers[0]
    assert pending.writer_closed is False
    assert pending.settled is False
    assert pending.spool_path == spool
    os.fstat(pending.spool_cleanup.file_fd)
    os.fstat(pending.spool_cleanup.parent_fd)

    wrappers[0].fail_close = False
    quality_module._retry_pending_spool_cleanups()
    assert wrappers[0].close_calls == 1
    assert pending.settled is True
    assert not quality_module._PENDING_SPOOL_CLEANUPS
    _assert_single_empty_cleanup_tombstone(tmp_path)


def test_setup_rollback_helper_entry_control_publishes_exact_live_bundle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    actual_connect = sqlite3.connect
    wrappers: list[Any] = []

    class SetupAndPersistentCloseError:
        def __init__(self, connection: sqlite3.Connection) -> None:
            self._connection = connection
            self.fail_close = True
            self.close_calls = 0

        def execute(self, statement: str, *args: Any) -> Any:
            if statement.strip().upper() == "PRAGMA LOCKING_MODE=EXCLUSIVE":
                raise sqlite3.OperationalError("injected setup failure")
            return self._connection.execute(statement, *args)

        def close(self) -> None:
            self.close_calls += 1
            if self.fail_close:
                raise sqlite3.OperationalError("injected persistent close failure")
            self._connection.close()

        def __getattr__(self, name: str) -> Any:
            return getattr(self._connection, name)

    def connect(*args: Any, **kwargs: Any) -> SetupAndPersistentCloseError:
        wrapper = SetupAndPersistentCloseError(actual_connect(*args, **kwargs))
        wrappers.append(wrapper)
        return wrapper

    real_helper = quality_module._settle_or_publish_pending_spool_cleanup
    helper_calls = 0

    def interrupt_at_helper_entry(*args: Any, **kwargs: Any) -> Any:
        nonlocal helper_calls
        helper_calls += 1
        if helper_calls == 1:
            raise SystemExit(59)
        return real_helper(*args, **kwargs)

    monkeypatch.setattr(quality_module.sqlite3, "connect", connect)
    monkeypatch.setattr(quality_module, "_settle_or_publish_pending_spool_cleanup", interrupt_at_helper_entry)
    spool = tmp_path / "setup-helper-entry.sqlite3"

    with pytest.raises(EnronQualityError, match="writer could not be closed safely") as caught:
        prepare_enron_quality(_bank(), slice_specs=[_slice()], spool_path=spool)

    assert isinstance(caught.value.__cause__, SystemExit)
    assert caught.value.__cause__.code == 59
    assert helper_calls == 1
    assert wrappers[0].close_calls == 0
    assert len(quality_module._PENDING_SPOOL_CLEANUPS) == 1
    pending = next(iter(quality_module._PENDING_SPOOL_CLEANUPS.values()))
    assert pending.connection is wrappers[0]
    assert pending.writer_closed is False
    assert pending.settled is False
    assert pending.spool_path == spool
    os.fstat(pending.spool_cleanup.file_fd)
    os.fstat(pending.spool_cleanup.parent_fd)

    wrappers[0].fail_close = False
    quality_module._retry_pending_spool_cleanups()
    assert wrappers[0].close_calls == 1
    assert pending.settled is True
    assert not quality_module._PENDING_SPOOL_CLEANUPS
    _assert_single_empty_cleanup_tombstone(tmp_path)


def test_constructor_rollback_defers_connection_close_control_until_spool_is_settled(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    actual_connect = sqlite3.connect
    connections: list[sqlite3.Connection] = []
    close_calls = 0

    class OneShotInterruptedClose:
        def __init__(self, connection: sqlite3.Connection) -> None:
            self._connection = connection

        def close(self) -> None:
            nonlocal close_calls
            close_calls += 1
            if close_calls == 1:
                raise KeyboardInterrupt
            self._connection.close()

        def __getattr__(self, name: str) -> Any:
            return getattr(self._connection, name)

    def connect(*args: Any, **kwargs: Any) -> OneShotInterruptedClose:
        connection = actual_connect(*args, **kwargs)
        connections.append(connection)
        return OneShotInterruptedClose(connection)

    def fail_constructor(**_kwargs: Any) -> None:
        raise RuntimeError("injected constructor failure")

    monkeypatch.setattr(quality_module.sqlite3, "connect", connect)
    monkeypatch.setattr(quality_module, "EnronQualitySession", fail_constructor)
    spool = tmp_path / "constructor-rollback.sqlite3"
    accounting_before = _cleanup_fd_accounting_snapshot()

    with pytest.raises(KeyboardInterrupt):
        prepare_enron_quality(_bank(), slice_specs=[_slice()], spool_path=spool)

    assert close_calls == 2
    assert len(connections) == 1
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connections[0].execute("SELECT 1")
    _assert_single_empty_cleanup_tombstone(tmp_path)
    assert _cleanup_fd_accounting_snapshot() == accounting_before


def test_setup_rollback_defers_post_close_control_until_spool_is_settled(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    actual_connect = sqlite3.connect
    connections: list[sqlite3.Connection] = []
    close_calls = 0

    class FailingSetupAndInterruptedClose:
        def __init__(self, connection: sqlite3.Connection) -> None:
            self._connection = connection

        def execute(self, statement: str, *args: Any) -> Any:
            if statement.strip().upper() == "PRAGMA LOCKING_MODE=EXCLUSIVE":
                raise sqlite3.OperationalError("injected setup failure")
            return self._connection.execute(statement, *args)

        def close(self) -> None:
            nonlocal close_calls
            close_calls += 1
            self._connection.close()
            if close_calls == 1:
                raise SystemExit(29)

        def __getattr__(self, name: str) -> Any:
            return getattr(self._connection, name)

    def connect(*args: Any, **kwargs: Any) -> FailingSetupAndInterruptedClose:
        connection = actual_connect(*args, **kwargs)
        connections.append(connection)
        return FailingSetupAndInterruptedClose(connection)

    monkeypatch.setattr(quality_module.sqlite3, "connect", connect)
    spool = tmp_path / "setup-rollback.sqlite3"
    accounting_before = _cleanup_fd_accounting_snapshot()

    with pytest.raises(SystemExit) as caught:
        prepare_enron_quality(_bank(), slice_specs=[_slice()], spool_path=spool)

    assert caught.value.code == 29
    assert close_calls == 2
    assert len(connections) == 1
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connections[0].execute("SELECT 1")
    _assert_single_empty_cleanup_tombstone(tmp_path)
    assert _cleanup_fd_accounting_snapshot() == accounting_before


def test_spool_symlinks_and_substitution_fail_closed(tmp_path: Path) -> None:
    target = tmp_path / "target.sqlite3"
    target.write_bytes(b"target")
    target.chmod(0o600)
    symlink = tmp_path / "symlink.sqlite3"
    symlink.symlink_to(target)
    with pytest.raises(EnronQualityError, match="could not be created"):
        prepare_enron_quality(_bank(), slice_specs=[_slice()], spool_path=symlink)

    private_parent = tmp_path / "private-parent"
    private_parent.mkdir(mode=0o700)
    parent_symlink = tmp_path / "parent-symlink"
    parent_symlink.symlink_to(private_parent, target_is_directory=True)
    with pytest.raises(EnronQualityError, match="could not be created"):
        prepare_enron_quality(
            _bank(),
            slice_specs=[_slice()],
            spool_path=parent_symlink / "metadata.sqlite3",
        )

    spool = tmp_path / "replace.sqlite3"
    parked = tmp_path / "parked-original.sqlite3"
    session = prepare_enron_quality(_bank(), slice_specs=[_slice()], spool_path=spool)
    session.consume(_document("doc_1", "Alice"), [], ["person_all_validation"])
    spool.replace(parked)
    spool.write_bytes(b"replacement")
    spool.chmod(0o600)
    with pytest.raises(EnronQualityError, match="changed|cleaned"):
        session.finish()
    assert spool.read_bytes() == b"replacement"
    assert parked.read_bytes() == b""
    assert session._state == "cleanup_pending"
    assert len(quality_module._PENDING_SPOOL_CLEANUPS) == 1

    replacement = spool.read_bytes()
    spool.unlink()
    parked.replace(spool)
    assert session._terminate("failed") is None
    assert not quality_module._PENDING_SPOOL_CLEANUPS
    spool.write_bytes(replacement)
    spool.chmod(0o600)
    assert spool.read_bytes() == b"replacement"


def test_spool_hardlink_substitution_wipes_every_link_before_failing(tmp_path: Path) -> None:
    spool = tmp_path / "linked.sqlite3"
    linked = tmp_path / "linked-copy.sqlite3"
    session = prepare_enron_quality(_bank(), slice_specs=[_slice()], spool_path=spool)
    session.consume(_document("doc_private", "PRIVATE_MARKER Alice"), [], ["person_all_validation"])
    os.link(spool, linked)

    with pytest.raises(EnronQualityError, match="changed|cleaned|private"):
        session.finish()

    assert spool.read_bytes() == linked.read_bytes() == b""
    assert session._state == "cleanup_pending"
    assert len(quality_module._PENDING_SPOOL_CLEANUPS) == 1
    linked.unlink()
    assert session._terminate("failed") is None
    assert not quality_module._PENDING_SPOOL_CLEANUPS
    _assert_single_empty_cleanup_tombstone(tmp_path)


def test_spool_in_place_mutation_is_locked_and_authenticated(tmp_path: Path) -> None:
    spool = tmp_path / "authenticated.sqlite3"
    session = prepare_enron_quality(_bank(), slice_specs=[_slice()], spool_path=spool)
    session.consume(_document("doc_1", "Alice"), [], ["person_all_validation"])

    outsider = sqlite3.connect(spool, timeout=0)
    try:
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            outsider.execute("UPDATE documents SET text_sha256 = ?", ("sha256:" + "0" * 64,))
    finally:
        outsider.close()

    session._connection.execute("UPDATE documents SET text_sha256 = ?", ("sha256:" + "0" * 64,))
    with pytest.raises(EnronQualityError, match="content changed"):
        session.finish()
    assert not spool.exists()


def _write_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def _assert_single_empty_cleanup_tombstone(root: Path) -> None:
    entries = list(root.iterdir())
    assert len(entries) == 1
    tombstone = entries[0]
    assert re.fullmatch(r"\.nerb-cleanup-[0-9a-f]{48}", tombstone.name)
    assert tombstone.is_file()
    assert tombstone.stat().st_size == 0
    assert stat.S_IMODE(tombstone.stat().st_mode) == 0o600


def _cleanup_fd_accounting_snapshot() -> tuple[int, int, int, int]:
    with private_io_module._CLEANUP_FD_ACCOUNTING_LOCK:  # noqa: SLF001 - regression invariant
        return (
            private_io_module._PENDING_CLEANUP_FDS,  # noqa: SLF001
            private_io_module._LIVE_CLEANUP_FDS,  # noqa: SLF001
            len(private_io_module._PENDING_CLEANUP_RESERVATIONS),  # noqa: SLF001
            len(private_io_module._ACCOUNTED_CLEANUP_FDS),  # noqa: SLF001
        )


def test_file_entrypoint_streams_same_result_and_enforces_cumulative_budget(tmp_path: Path) -> None:
    records = [
        _record("doc_1", "Alice", [_gold("doc_1", 0, 5, catalog_name_id="alice")]),
        _record("doc_2", "Noise"),
    ]
    records_path = tmp_path / "records.jsonl"
    slices_path = tmp_path / "slices.jsonl"
    _write_jsonl(records_path, records)
    _write_jsonl(slices_path, [_slice()])

    actual = evaluate_enron_quality_files(_bank(), records_path=records_path, slice_specs_path=slices_path)
    assert actual == _run(records)
    with pytest.raises(EnronQualityError, match="cumulative byte"):
        evaluate_enron_quality_files(
            _bank(),
            records_path=records_path,
            slice_specs_path=slices_path,
            max_input_bytes=1,
        )


def test_generator_failure_cleans_explicit_spool(tmp_path: Path) -> None:
    spool = tmp_path / "generator.sqlite3"

    def records() -> Iterable[Mapping[str, Any]]:
        yield _record("doc_1", "Alice")
        raise RuntimeError("private generator detail")

    with pytest.raises(EnronQualityError, match="input stream failed") as error:
        _run(records(), spool_path=spool)
    assert "private generator detail" not in str(error.value)
    assert not spool.exists()


def test_retained_state_is_constant_as_document_count_grows() -> None:
    session = prepare_enron_quality(_bank(), slice_specs=[_slice()])
    for index in range(10):
        session.consume(_document(f"doc_small_{index}", ""), [], ["person_all_validation"])
    small = session.retained_state
    for index in range(2_000):
        session.consume(_document(f"doc_large_{index}", ""), [], ["person_all_validation"])
    large = session.retained_state

    assert large["slice_accumulators"] == small["slice_accumulators"] == 1
    assert large["retained_documents"] == small["retained_documents"] == 0
    assert large["retained_predictions"] == small["retained_predictions"] == 0
    assert large["diagnostics"] <= large["diagnostic_capacity"] == 100
    session.finish()


def _isolated_streaming_rss(document_count: int) -> dict[str, Any]:
    script = r"""
import json
import resource
import sys

from nerb.enron_quality import prepare_enron_quality

bank = json.loads(sys.argv[2])
plan = json.loads(sys.argv[3])
count = int(sys.argv[1])
session = prepare_enron_quality(bank, slice_specs=[plan], max_diagnostics=0)
for index in range(count):
    session.consume(
        {
            "document_id": f"doc_{index:08d}",
            "text": "",
            "text_view": "natural_body",
            "split_role": "validation",
        },
        [],
        ["person_all_validation"],
    )
state = session.retained_state
session.finish()
raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
rss_bytes = int(raw) if sys.platform == "darwin" else int(raw) * 1024
print(json.dumps({"rss_bytes": rss_bytes, "state": state}, sort_keys=True))
"""
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            str(document_count),
            json.dumps(_bank(), separators=(",", ":")),
            json.dumps(_slice(), separators=(",", ":")),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return json.loads(completed.stdout)


@pytest.mark.skipif(sys.platform not in {"darwin", "linux"}, reason="ru_maxrss units are frozen on macOS/Linux")
def test_isolated_peak_rss_growth_is_sublinear_as_stream_size_grows() -> None:
    small = _isolated_streaming_rss(100)
    large = _isolated_streaming_rss(20_000)
    rss_growth = max(0, large["rss_bytes"] - small["rss_bytes"])

    assert rss_growth <= 32 * 1024**2
    assert large["state"]["consumed_documents"] == 20_000
    assert large["state"]["retained_documents"] == 0
    assert large["state"]["retained_predictions"] == 0
    assert large["state"]["slice_accumulators"] == small["state"]["slice_accumulators"] == 1


def test_stream_record_and_slice_plan_schemas_are_closed() -> None:
    plan = _slice()
    plan["document_ids"] = ["doc_1"]
    with pytest.raises(EnronQualityError, match="closed quality schema"):
        prepare_enron_quality(_bank(), slice_specs=[plan])

    record = _record("doc_1", "Alice")
    record["documents"] = []
    with pytest.raises(EnronQualityError, match="closed quality schema"):
        _run([record])


@pytest.mark.parametrize("field", ["entity_classes", "document_regions", "exclusions"])
def test_nested_slice_plan_lists_have_a_fixed_item_ceiling(field: str) -> None:
    plan = _slice()
    values = [f"item_{index}" for index in range(quality_module.DEFAULT_MAX_QUALITY_SLICES + 1)]
    if field == "entity_classes":
        values[0] = "person"
    plan["annotation_scope"][field] = values

    with pytest.raises(EnronQualityError, match="bounded item limit"):
        prepare_enron_quality(_bank(), slice_specs=[plan])


@pytest.mark.parametrize("field", ["max_line_bytes", "max_input_bytes", "max_records"])
@pytest.mark.parametrize("value", [True, 0, -1])
def test_cmu_file_helper_rejects_invalid_resource_limits(tmp_path: Path, field: str, value: Any) -> None:
    bindings = tmp_path / "bindings.jsonl"
    bindings.write_text("", encoding="utf-8")
    arguments: dict[str, Any] = {
        "annotation_run_dir": tmp_path,
        "catalog_bindings_path": bindings,
        field: value,
    }

    with pytest.raises(EnronQualityError, match="positive integers"):
        evaluate_cmu_enron_training_quality_files(_bank(), **arguments)


def test_scan_failure_is_privacy_safe_and_spool_is_removed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    class Broken:
        def finditer(self, text: str, *, max_matches: int) -> list[Any]:
            raise RuntimeError(text)

    spool = tmp_path / "broken.sqlite3"
    session = prepare_enron_quality(_bank(), slice_specs=[_slice()], spool_path=spool)
    session._compiled = Broken()
    marker = "private@example.invalid"
    with pytest.raises(EnronQualityError) as error:
        session.consume(_document("doc_1", marker), [], ["person_all_validation"])
    assert marker not in str(error.value)
    assert not spool.exists()


def test_cmu_adapter_binds_verified_source_and_requires_catalog_adjudication(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import nerb.enron_annotations as annotations

    source = {
        "documents": [
            _document(f"doc_{index}", "Alice" if index == 0 else "No match", split_role="train") for index in range(6)
        ],
        "labels": [{"document_id": "doc_0", "entity_class": "person", "start": 0, "end": 5}],
        "label_artifact_id": "cmu_enron_meetings_person_labels",
        "annotation_scope": {
            "entity_classes": ["person"],
            "document_regions": ["published_source_fragment"],
            "span_policy_sha256": "sha256:" + "6" * 64,
            "exclusions": ["names_inside_email_addresses"],
        },
        "annotation_completeness": "exhaustive_within_scope",
        "label_strength": "independent",
        "text_view_descriptor": {
            "id": "natural_body",
            "artifact_sha256": "sha256:" + "7" * 64,
            "content_policy_sha256": "sha256:" + "8" * 64,
            "document_regions": ["published_source_fragment"],
            "primary_for_quality": True,
            "answer_bearing_fields_included": False,
        },
        "public_binding": {
            "source_sha256": "sha256:" + "9" * 64,
            "documents_sha256": "sha256:" + "a" * 64,
            "labels_sha256": "sha256:" + "b" * 64,
            "span_policy_sha256": "sha256:" + "6" * 64,
            "promotable": False,
            "nonpromotable_reason": "auxiliary_source_without_bound_content_adjudication",
        },
    }
    monkeypatch.setattr(annotations, "load_cmu_enron_training_quality_source", lambda _path: source)
    binding = {
        "document_id": "doc_0",
        "start": 0,
        "end": 5,
        "catalog_identity": {"entity_id": "person", "name_id": "alice", "pattern_id": "primary"},
    }
    spool_path = tmp_path / "cmu-quality.sqlite3"

    result = evaluate_cmu_enron_training_quality(
        _bank({"alice": ("Alice", "Alice")}),
        annotation_run_dir=tmp_path,
        catalog_bindings=[binding],
        spool_path=spool_path,
        max_spool_bytes=1024 * 1024,
    )

    assert result["annotation_source"] == source["public_binding"]
    assert result["quality_run_sha256"].startswith("sha256:")
    assert result["run_sha256"] != result["quality_run_sha256"]
    assert [item["id"] for item in result["quality"]["slices"]] == [
        "cmu_person_all_train",
        "cmu_person_negative_train",
    ]
    assert result["quality"]["slices"][0]["cataloged_true_positive"] == 1
    assert "Alice" not in json.dumps(result)
    assert "doc_0" not in json.dumps(result)
    assert not spool_path.exists()

    source["public_binding"] = {**source["public_binding"], "labels_sha256": "sha256:" + "c" * 64}
    changed = evaluate_cmu_enron_training_quality(
        _bank({"alice": ("Alice", "Alice")}),
        annotation_run_dir=tmp_path,
        catalog_bindings=[binding],
        spool_path=spool_path,
        max_spool_bytes=1024 * 1024,
    )
    assert changed["quality_run_sha256"] == result["quality_run_sha256"]
    assert changed["annotation_binding_sha256"] != result["annotation_binding_sha256"]
    assert changed["run_sha256"] != result["run_sha256"]

    with pytest.raises(EnronQualityError, match="exactly cover"):
        evaluate_cmu_enron_training_quality(
            _bank({"alice": ("Alice", "Alice")}),
            annotation_run_dir=tmp_path,
            catalog_bindings=[],
        )

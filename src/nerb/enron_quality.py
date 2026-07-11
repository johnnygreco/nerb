"""Privacy-safe, provenance-aware quality aggregation for Enron benchmark v2.

The core executor is intentionally in-memory and has no sealed-test capability.
An explicit file helper reads bounded private JSONL through the shared no-follow
input boundary. Callers provide closed document, gold-span, and slice-plan
objects; only aggregate counts and content fingerprints are returned.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from . import enron_contract
from .bank import hash_bank
from .engines import compile_bank, extraction_execution_sha256
from .enron_contract import CHARACTER_POSITION_SEMANTICS, MATCHING_SEMANTICS, validate_enron_quality_output
from .enron_private_io import EnronPrivateIOError, iter_strict_jsonl

__all__ = [
    "EnronQualityError",
    "evaluate_cmu_enron_training_quality",
    "evaluate_cmu_enron_training_quality_files",
    "evaluate_enron_quality",
    "evaluate_enron_quality_files",
]

QUALITY_EXECUTION_SCHEMA_VERSION = "nerb.enron_quality_execution.v2"
EVALUATOR_ID = "nerb-enron-quality"
EVALUATOR_VERSION = "2.0.0"
DEFAULT_MAX_QUALITY_LINE_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_QUALITY_INPUT_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_QUALITY_RECORDS = 2_000_000
DEFAULT_MAX_QUALITY_PREDICTIONS_PER_DOCUMENT = 100_000
DEFAULT_MAX_QUALITY_PREDICTIONS_TOTAL = 500_000

_DOCUMENT_FIELDS = frozenset({"document_id", "text", "text_view", "split_role"})
_GOLD_FIELDS = frozenset({"document_id", "entity_class", "start", "end", "catalog_identity"})
_CATALOG_IDENTITY_FIELDS = frozenset({"entity_id", "name_id", "pattern_id"})
_ANNOTATION_SCOPE_FIELDS = frozenset({"entity_classes", "document_regions", "span_policy_sha256", "exclusions"})
_UNSUPPORTED_SLICE_FIELDS = frozenset({"id", "dimension", "reason_code"})
_TEXT_VIEW_DESCRIPTOR_FIELDS = frozenset(
    {
        "id",
        "artifact_sha256",
        "content_policy_sha256",
        "document_regions",
        "primary_for_quality",
        "answer_bearing_fields_included",
    }
)
_CMU_CATALOG_BINDING_FIELDS = frozenset({"document_id", "start", "end", "catalog_identity"})
_SLICE_FIELDS = frozenset(
    {
        "id",
        "label_artifact_id",
        "label_strength",
        "annotation_scope",
        "annotation_completeness",
        "entity_class",
        "cohort",
        "split_role",
        "text_view",
        "text_view_descriptor",
        "promotion_gate",
        "document_ids",
    }
)
_SPLIT_ROLES = frozenset({"train", "validation", "test"})
_LABEL_STRENGTHS = frozenset({"independent", "structured_weak"})
_ANNOTATION_COMPLETENESS = frozenset({"exhaustive_within_scope", "partial"})
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_PUBLIC_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")

_LABEL_SCHEMA_DESCRIPTOR = {
    "documents": sorted(_DOCUMENT_FIELDS),
    "gold_spans": sorted(_GOLD_FIELDS),
    "catalog_identity": sorted(_CATALOG_IDENTITY_FIELDS),
    "slice_specs": sorted(_SLICE_FIELDS),
    "position_semantics": CHARACTER_POSITION_SEMANTICS,
}
_POLICY_DESCRIPTOR = {
    "version": "nerb.enron-quality-policy.v2",
    "matching": MATCHING_SEMANTICS,
    "native_offsets": "utf8_byte",
    "quality_offsets": CHARACTER_POSITION_SEMANTICS,
    "catalog_eligibility": "explicit_frozen_gold_active_entity_name_and_pattern_qualification_or_null",
    "catalog_inventory": "active_bank_names_with_active_patterns",
    "prediction_class": "bank_entity_id",
    "canonical_identity": "entity_id_and_name_id",
    "character_sets": "document_disjoint_interval_unions",
    "partial_and_weak_policy": "labeled_span_and_catalog_diagnostics_only",
    "empty_policy": "fail_closed",
    "prediction_limits": {
        "per_document": DEFAULT_MAX_QUALITY_PREDICTIONS_PER_DOCUMENT,
        "total": DEFAULT_MAX_QUALITY_PREDICTIONS_TOTAL,
    },
}


class EnronQualityError(ValueError):
    """Raised when quality inputs cannot be evaluated without ambiguity."""


@dataclass(frozen=True, slots=True)
class _Document:
    document_id: str
    text: str
    text_view: str
    split_role: str


@dataclass(frozen=True, slots=True)
class _GoldSpan:
    document_id: str
    entity_class: str
    start: int
    end: int
    catalog_identity: tuple[str, str, str] | None

    @property
    def key(self) -> tuple[str, str, int, int]:
        return (self.document_id, self.entity_class, self.start, self.end)


@dataclass(frozen=True, slots=True)
class _Prediction:
    document_id: str
    entity_class: str
    start: int
    end: int
    entity_id: str
    name_id: str
    pattern_id: str

    @property
    def key(self) -> tuple[str, str, int, int]:
        return (self.document_id, self.entity_class, self.start, self.end)

    @property
    def identity(self) -> tuple[str, str]:
        return (self.entity_id, self.name_id)


@dataclass(frozen=True, slots=True)
class _SliceSpec:
    id: str
    label_artifact_id: str
    label_strength: str
    annotation_entity_classes: tuple[str, ...]
    annotation_document_regions: tuple[str, ...]
    annotation_span_policy_sha256: str
    annotation_exclusions: tuple[str, ...]
    annotation_completeness: str
    entity_class: str
    cohort: str
    split_role: str
    text_view: str
    text_view_artifact_sha256: str
    text_view_content_policy_sha256: str
    text_view_document_regions: tuple[str, ...]
    text_view_primary_for_quality: bool
    text_view_answer_bearing_fields_included: bool
    promotion_gate: bool
    document_ids: tuple[str, ...]

    @property
    def open_world_eligible(self) -> bool:
        return (
            self.label_strength == "independent"
            and self.annotation_completeness == "exhaustive_within_scope"
            and set(self.annotation_document_regions) == set(self.text_view_document_regions)
        )

    def fingerprint_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label_artifact_id": self.label_artifact_id,
            "label_strength": self.label_strength,
            "annotation_scope": self.annotation_scope,
            "annotation_completeness": self.annotation_completeness,
            "entity_class": self.entity_class,
            "cohort": self.cohort,
            "split_role": self.split_role,
            "text_view": self.text_view,
            "text_view_descriptor": self.text_view_descriptor,
            "promotion_gate": self.promotion_gate,
            "document_ids": list(self.document_ids),
        }

    @property
    def annotation_scope(self) -> dict[str, Any]:
        return {
            "entity_classes": list(self.annotation_entity_classes),
            "document_regions": list(self.annotation_document_regions),
            "span_policy_sha256": self.annotation_span_policy_sha256,
            "exclusions": list(self.annotation_exclusions),
        }

    @property
    def text_view_descriptor(self) -> dict[str, Any]:
        return {
            "id": self.text_view,
            "artifact_sha256": self.text_view_artifact_sha256,
            "content_policy_sha256": self.text_view_content_policy_sha256,
            "document_regions": list(self.text_view_document_regions),
            "primary_for_quality": self.text_view_primary_for_quality,
            "answer_bearing_fields_included": self.text_view_answer_bearing_fields_included,
        }


def evaluate_enron_quality(
    bank: Mapping[str, Any],
    *,
    documents: Sequence[Mapping[str, Any]],
    gold_spans: Sequence[Mapping[str, Any]],
    slice_specs: Sequence[Mapping[str, Any]],
    unsupported_slice_specs: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Evaluate one bank and return aggregate-only Enron-v2 quality evidence.

    ``catalog_identity`` on every gold span is required and is either ``None``
    (the occurrence was not cataloged by the frozen plan) or an exact
    ``{"entity_id": ..., "name_id": ..., "pattern_id": ...}`` qualification.
    The executor validates non-null qualifications against the active pattern
    inventory and never infers catalog membership from scan output.

    Evaluation presence is reported separately from later promotion thresholds;
    this executor does not emit a quality pass claim.
    """

    prepared_documents = _prepare_documents(documents)
    prepared_gold = _prepare_gold(gold_spans, prepared_documents)
    prepared_slices = _prepare_slices(slice_specs, prepared_documents)
    declared_unsupported = _prepare_declared_unsupported(unsupported_slice_specs, prepared_slices)
    _validate_slice_coverage(prepared_documents, prepared_gold, prepared_slices)

    # This is the only bank compilation in the execution path.  Each document
    # is then scanned directly through the same compiled instance.
    try:
        compiled, _cache_hit = compile_bank(bank, options={"include_statuses": ["active"]})
    except Exception:
        raise EnronQualityError("Quality bank could not be compiled safely.") from None
    active_patterns = _active_pattern_inventory(compiled.extractable_bank)
    _validate_catalog_identities(prepared_gold, active_patterns)

    predictions = _scan_documents(compiled, prepared_documents)
    evaluator = _evaluator_identity()
    policy_sha256 = _canonical_hash(_POLICY_DESCRIPTOR)
    canonical_bank_sha256 = hash_bank(compiled.bank)
    engine_bank_sha256 = compiled.bank_hash
    protocol_sha256 = _protocol_hash(
        evaluator,
        policy_sha256,
        prepared_documents,
        prepared_gold,
        prepared_slices,
        declared_unsupported,
    )
    catalog_binding_sha256 = _catalog_binding_hash(prepared_gold, canonical_bank_sha256)

    gold_by_document: dict[str, list[_GoldSpan]] = defaultdict(list)
    for gold_span in prepared_gold:
        gold_by_document[gold_span.document_id].append(gold_span)
    predictions_by_document: dict[str, list[_Prediction]] = defaultdict(list)
    for prediction in predictions:
        predictions_by_document[prediction.document_id].append(prediction)

    evaluated_slices: list[dict[str, Any]] = []
    unsupported_slices: list[dict[str, str]] = list(declared_unsupported)
    for spec in prepared_slices:
        reason = _unsupported_reason(spec, gold_by_document)
        if reason is not None:
            unsupported_slices.append({"id": spec.id, "dimension": "population", "reason_code": reason})
            continue
        evaluated_slices.append(
            _evaluate_slice(
                spec,
                prepared_documents,
                gold_by_document,
                predictions_by_document,
            )
        )

    quality = {
        "evaluated": bool(evaluated_slices),
        "matching_semantics": MATCHING_SEMANTICS,
        "character_position_semantics": CHARACTER_POSITION_SEMANTICS,
        "slices": evaluated_slices,
    }
    raw_contract_validation = validate_enron_quality_output(quality)
    contract_validation = {
        "valid": raw_contract_validation["valid"],
        "diagnostic_codes": sorted({str(item["code"]) for item in raw_contract_validation["diagnostics"]}),
    }
    if any(spec.promotion_gate for spec in prepared_slices) and contract_validation["valid"] is not True:
        raise EnronQualityError("Promotion-gated quality output failed standalone contract validation.")
    run_sha256 = _canonical_hash(
        {
            "protocol_sha256": protocol_sha256,
            "catalog_binding_sha256": catalog_binding_sha256,
            "canonical_bank_sha256": canonical_bank_sha256,
            "engine_bank_sha256": engine_bank_sha256,
            "quality": quality,
            "contract_validation": contract_validation,
            "unsupported_slices": unsupported_slices,
        }
    )
    evaluated = bool(evaluated_slices)
    return {
        "schema_version": QUALITY_EXECUTION_SCHEMA_VERSION,
        "evaluator": evaluator,
        "evaluator_sha256": _canonical_hash(evaluator),
        "policy_sha256": policy_sha256,
        "protocol_sha256": protocol_sha256,
        "catalog_binding_sha256": catalog_binding_sha256,
        "run_sha256": run_sha256,
        "bank": {
            "canonical_sha256": canonical_bank_sha256,
            "engine_sha256": engine_bank_sha256,
        },
        "evaluated": evaluated,
        "quality": quality,
        "contract_validation": contract_validation,
        "unsupported_slices": unsupported_slices,
    }


def evaluate_enron_quality_files(
    bank: Mapping[str, Any],
    *,
    documents_path: str | Path,
    gold_spans_path: str | Path,
    slice_specs_path: str | Path,
    unsupported_slice_specs_path: str | Path | None = None,
    max_line_bytes: int = DEFAULT_MAX_QUALITY_LINE_BYTES,
    max_input_bytes: int = DEFAULT_MAX_QUALITY_INPUT_BYTES,
    max_records: int = DEFAULT_MAX_QUALITY_RECORDS,
) -> dict[str, Any]:
    """Evaluate explicit strict private JSONL inputs and return aggregate-only evidence."""

    if type(max_line_bytes) is not int or max_line_bytes <= 0:
        raise EnronQualityError("Quality JSONL line limit must be a positive integer.")
    if type(max_input_bytes) is not int or max_input_bytes <= 0:
        raise EnronQualityError("Quality JSONL cumulative byte limit must be a positive integer.")
    if type(max_records) is not int or max_records <= 0:
        raise EnronQualityError("Quality JSONL record limit must be a positive integer.")
    try:
        remaining_bytes = max_input_bytes
        remaining_records = max_records
        documents, document_bytes = _load_quality_jsonl(
            Path(documents_path),
            max_line_bytes=max_line_bytes,
            max_records=remaining_records,
            max_bytes=remaining_bytes,
        )
        remaining_bytes -= document_bytes
        remaining_records -= len(documents)
        gold_spans, gold_bytes = _load_quality_jsonl(
            Path(gold_spans_path),
            max_line_bytes=max_line_bytes,
            max_records=remaining_records,
            max_bytes=remaining_bytes,
        )
        remaining_bytes -= gold_bytes
        remaining_records -= len(gold_spans)
        slice_specs, slice_bytes = _load_quality_jsonl(
            Path(slice_specs_path),
            max_line_bytes=max_line_bytes,
            max_records=remaining_records,
            max_bytes=remaining_bytes,
        )
        remaining_bytes -= slice_bytes
        remaining_records -= len(slice_specs)
        if unsupported_slice_specs_path is None:
            unsupported_slice_specs: list[Mapping[str, Any]] = []
            unsupported_bytes = 0
        else:
            unsupported_slice_specs, unsupported_bytes = _load_quality_jsonl(
                Path(unsupported_slice_specs_path),
                max_line_bytes=max_line_bytes,
                max_records=remaining_records,
                max_bytes=remaining_bytes,
            )
        total_bytes = document_bytes + gold_bytes + slice_bytes + unsupported_bytes
        if total_bytes > max_input_bytes:
            raise EnronQualityError("Quality JSONL inputs exceed the cumulative byte limit.")
    except EnronPrivateIOError:
        raise EnronQualityError("Quality JSONL input could not be read safely.") from None
    return evaluate_enron_quality(
        bank,
        documents=documents,
        gold_spans=gold_spans,
        slice_specs=slice_specs,
        unsupported_slice_specs=unsupported_slice_specs,
    )


def evaluate_cmu_enron_training_quality(
    bank: Mapping[str, Any],
    *,
    annotation_run_dir: str | Path,
    catalog_bindings: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Evaluate the verifier-bound CMU training population with explicit catalog adjudication."""

    from .enron_annotations import load_cmu_enron_training_quality_source

    source = load_cmu_enron_training_quality_source(Path(annotation_run_dir))
    bindings = _prepare_cmu_catalog_bindings(catalog_bindings, source["labels"])
    gold_spans = [
        {
            **label,
            "catalog_identity": bindings[(label["document_id"], label["start"], label["end"])],
        }
        for label in source["labels"]
    ]
    document_ids = [str(document["document_id"]) for document in source["documents"]]
    positive_document_ids = {str(label["document_id"]) for label in source["labels"]}
    negative_document_ids = [document_id for document_id in document_ids if document_id not in positive_document_ids]
    slice_spec = {
        "id": "cmu_person_all_train",
        "label_artifact_id": source["label_artifact_id"],
        "label_strength": source["label_strength"],
        "annotation_scope": source["annotation_scope"],
        "annotation_completeness": source["annotation_completeness"],
        "entity_class": "person",
        "cohort": "all",
        "split_role": "train",
        "text_view": source["text_view_descriptor"]["id"],
        "text_view_descriptor": source["text_view_descriptor"],
        "promotion_gate": False,
        "document_ids": document_ids,
    }
    slice_specs = [slice_spec]
    unsupported = [
        {
            "id": "cmu_identity_known_novel",
            "dimension": "known_novel",
            "reason_code": "canonical_identity_linkage_unavailable",
        },
        {
            "id": "cmu_identity_head_tail",
            "dimension": "head_tail",
            "reason_code": "train_identity_frequency_unavailable",
        },
        {
            "id": "cmu_alternate_text_view",
            "dimension": "text_view",
            "reason_code": "alternate_text_view_unavailable",
        },
    ]
    if negative_document_ids:
        slice_specs.append(
            {
                **slice_spec,
                "id": "cmu_person_negative_train",
                "cohort": "negative",
                "document_ids": negative_document_ids,
            }
        )
    else:
        unsupported.append(
            {
                "id": "cmu_person_negative_train",
                "dimension": "negative",
                "reason_code": "zero_negative_documents",
            }
        )
    result = evaluate_enron_quality(
        bank,
        documents=source["documents"],
        gold_spans=gold_spans,
        slice_specs=slice_specs,
        unsupported_slice_specs=unsupported,
    )
    annotation_source = dict(source["public_binding"])
    annotation_binding_sha256 = _canonical_hash(annotation_source)
    quality_run_sha256 = result["run_sha256"]
    return {
        **result,
        "quality_run_sha256": quality_run_sha256,
        "annotation_source": annotation_source,
        "annotation_binding_sha256": annotation_binding_sha256,
        "run_sha256": _canonical_hash(
            {
                "schema_version": "nerb.enron-cmu-training-quality-run.v2",
                "quality_run_sha256": quality_run_sha256,
                "annotation_binding_sha256": annotation_binding_sha256,
            }
        ),
    }


def evaluate_cmu_enron_training_quality_files(
    bank: Mapping[str, Any],
    *,
    annotation_run_dir: str | Path,
    catalog_bindings_path: str | Path,
    max_line_bytes: int = DEFAULT_MAX_QUALITY_LINE_BYTES,
    max_input_bytes: int = DEFAULT_MAX_QUALITY_INPUT_BYTES,
    max_records: int = DEFAULT_MAX_QUALITY_RECORDS,
) -> dict[str, Any]:
    """Evaluate a verified CMU training bundle using strict private catalog-binding JSONL."""

    try:
        bindings, _bytes = _load_quality_jsonl(
            Path(catalog_bindings_path),
            max_line_bytes=max_line_bytes,
            max_records=max_records,
            max_bytes=max_input_bytes,
        )
    except EnronPrivateIOError:
        raise EnronQualityError("CMU catalog-binding JSONL could not be read safely.") from None
    return evaluate_cmu_enron_training_quality(
        bank,
        annotation_run_dir=annotation_run_dir,
        catalog_bindings=bindings,
    )


def _prepare_cmu_catalog_bindings(
    values: Sequence[Mapping[str, Any]], labels: Sequence[Mapping[str, Any]]
) -> dict[tuple[str, int, int], Mapping[str, str] | None]:
    _require_sequence(values, "CMU catalog bindings")
    _require_item_limit(values, "CMU catalog bindings")
    expected = {(str(label["document_id"]), int(label["start"]), int(label["end"])) for label in labels}
    result: dict[tuple[str, int, int], Mapping[str, str] | None] = {}
    for index, value in enumerate(values):
        _require_closed_mapping(value, _CMU_CATALOG_BINDING_FIELDS, "CMU catalog binding", index)
        document_id = _required_id(value["document_id"], "CMU binding document_id", index)
        start = _nonnegative_integer(value["start"], "CMU binding start", index)
        end = _nonnegative_integer(value["end"], "CMU binding end", index)
        catalog_identity = _prepare_catalog_identity(value["catalog_identity"], "person", index)
        key = (document_id, start, end)
        if key in result or start >= end:
            raise EnronQualityError("CMU catalog bindings must contain unique valid spans.")
        result[key] = (
            None
            if catalog_identity is None
            else {
                "entity_id": catalog_identity[0],
                "name_id": catalog_identity[1],
                "pattern_id": catalog_identity[2],
            }
        )
    if set(result) != expected:
        raise EnronQualityError("CMU catalog bindings must exactly cover the verified annotation spans.")
    return result


def _load_quality_jsonl(
    path: Path, *, max_line_bytes: int, max_records: int, max_bytes: int
) -> tuple[list[Mapping[str, Any]], int]:
    rows: list[Mapping[str, Any]] = []
    total_bytes = 0
    for _line, raw, row in iter_strict_jsonl(path, max_line_bytes):
        total_bytes += len(raw)
        if total_bytes > max_bytes:
            raise EnronQualityError("Quality JSONL input exceeds the cumulative byte limit.")
        rows.append(row)
        if len(rows) > max_records:
            raise EnronQualityError("Quality JSONL input exceeds the record limit.")
    return rows, total_bytes


def _prepare_documents(values: Sequence[Mapping[str, Any]]) -> dict[str, _Document]:
    _require_sequence(values, "documents")
    _require_item_limit(values, "documents")
    documents: dict[str, _Document] = {}
    for index, value in enumerate(values):
        _require_closed_mapping(value, _DOCUMENT_FIELDS, "document", index)
        document_id = _required_id(value["document_id"], "document_id", index)
        text = value["text"]
        text_view = _required_id(value["text_view"], "text_view", index)
        split_role = value["split_role"]
        if not isinstance(text, str):
            raise EnronQualityError(f"Document {index} text must be a string.")
        try:
            text.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise EnronQualityError(f"Document {index} text must be valid UTF-8 text.") from exc
        if not isinstance(split_role, str) or split_role not in _SPLIT_ROLES:
            raise EnronQualityError(f"Document {index} split_role is invalid.")
        if document_id in documents:
            raise EnronQualityError("Document identifiers must be unique.")
        documents[document_id] = _Document(document_id, text, text_view, split_role)
    return documents


def _prepare_gold(values: Sequence[Mapping[str, Any]], documents: Mapping[str, _Document]) -> tuple[_GoldSpan, ...]:
    _require_sequence(values, "gold_spans")
    _require_item_limit(values, "gold_spans")
    spans: list[_GoldSpan] = []
    seen: set[tuple[str, str, int, int]] = set()
    for index, value in enumerate(values):
        _require_closed_mapping(value, _GOLD_FIELDS, "gold span", index)
        document_id = _required_id(value["document_id"], "document_id", index)
        entity_class = _required_id(value["entity_class"], "entity_class", index)
        document = documents.get(document_id)
        if document is None:
            raise EnronQualityError(f"Gold span {index} references an unknown document.")
        start = _nonnegative_integer(value["start"], "start", index)
        end = _nonnegative_integer(value["end"], "end", index)
        if start >= end or end > len(document.text):
            raise EnronQualityError(f"Gold span {index} has invalid scalar bounds.")
        catalog_identity = _prepare_catalog_identity(value["catalog_identity"], entity_class, index)
        span = _GoldSpan(document_id, entity_class, start, end, catalog_identity)
        if span.key in seen:
            raise EnronQualityError("Gold exact-span/class keys must be unique.")
        seen.add(span.key)
        spans.append(span)
    return tuple(sorted(spans, key=lambda item: item.key))


def _prepare_catalog_identity(value: Any, entity_class: str, index: int) -> tuple[str, str, str] | None:
    if value is None:
        return None
    _require_closed_mapping(value, _CATALOG_IDENTITY_FIELDS, "catalog identity", index)
    entity_id = _required_id(value["entity_id"], "catalog entity_id", index)
    name_id = _required_id(value["name_id"], "catalog name_id", index)
    pattern_id = _required_id(value["pattern_id"], "catalog pattern_id", index)
    if entity_id != entity_class:
        raise EnronQualityError(f"Gold span {index} catalog identity must use its declared entity class.")
    return entity_id, name_id, pattern_id


def _prepare_slices(values: Sequence[Mapping[str, Any]], documents: Mapping[str, _Document]) -> tuple[_SliceSpec, ...]:
    _require_sequence(values, "slice_specs")
    _require_item_limit(values, "slice_specs")
    slices: list[_SliceSpec] = []
    seen_ids: set[str] = set()
    for index, value in enumerate(values):
        _require_closed_mapping(value, _SLICE_FIELDS, "slice spec", index)
        slice_id = _required_public_id(value["id"], "slice id", index)
        if slice_id in seen_ids:
            raise EnronQualityError("Slice identifiers must be unique.")
        seen_ids.add(slice_id)
        label_artifact_id = _required_public_id(value["label_artifact_id"], "label_artifact_id", index)
        label_strength = value["label_strength"]
        annotation_scope = _prepare_annotation_scope(value["annotation_scope"], index)
        completeness = value["annotation_completeness"]
        entity_class = _required_public_id(value["entity_class"], "entity_class", index)
        cohort = _required_public_id(value["cohort"], "cohort", index)
        split_role = value["split_role"]
        text_view = _required_public_id(value["text_view"], "text_view", index)
        text_view_descriptor = _prepare_text_view_descriptor(value["text_view_descriptor"], text_view, index)
        promotion_gate = value["promotion_gate"]
        if not isinstance(label_strength, str) or label_strength not in _LABEL_STRENGTHS:
            raise EnronQualityError(f"Slice spec {index} label_strength is unsupported.")
        if not isinstance(completeness, str) or completeness not in _ANNOTATION_COMPLETENESS:
            raise EnronQualityError(f"Slice spec {index} annotation_completeness is unsupported.")
        if (
            label_strength == "independent"
            and completeness == "exhaustive_within_scope"
            and set(annotation_scope["document_regions"]) != set(text_view_descriptor["document_regions"])
        ):
            raise EnronQualityError(
                f"Slice spec {index} exhaustive independent evidence must cover the complete text view."
            )
        if not isinstance(split_role, str) or split_role not in _SPLIT_ROLES:
            raise EnronQualityError(f"Slice spec {index} split_role is invalid.")
        if type(promotion_gate) is not bool:
            raise EnronQualityError(f"Slice spec {index} promotion_gate must be a boolean.")
        if promotion_gate and (
            label_strength != "independent" or completeness != "exhaustive_within_scope" or split_role != "test"
        ):
            raise EnronQualityError(
                f"Slice spec {index} promotion gate requires independent exhaustive final-test evidence."
            )
        if promotion_gate and (
            annotation_scope["entity_classes"] != (entity_class,)
            or set(annotation_scope["document_regions"]) != set(text_view_descriptor["document_regions"])
            or annotation_scope["exclusions"]
            or cohort != "all"
            or not text_view_descriptor["primary_for_quality"]
            or text_view_descriptor["answer_bearing_fields_included"]
        ):
            raise EnronQualityError(
                f"Slice spec {index} promotion gate requires a complete unexcluded annotation scope."
            )
        if entity_class not in annotation_scope["entity_classes"] or not set(
            annotation_scope["document_regions"]
        ).issubset(text_view_descriptor["document_regions"]):
            raise EnronQualityError(f"Slice spec {index} is outside its annotation scope.")
        raw_document_ids = value["document_ids"]
        _require_sequence(raw_document_ids, f"slice spec {index} document_ids")
        document_ids = tuple(sorted(_required_id(item, "slice document_id", index) for item in raw_document_ids))
        if len(document_ids) != len(set(document_ids)):
            raise EnronQualityError(f"Slice spec {index} document identifiers must be unique.")
        for document_id in document_ids:
            document = documents.get(document_id)
            if document is None:
                raise EnronQualityError(f"Slice spec {index} references an unknown document.")
            if document.split_role != split_role or document.text_view != text_view:
                raise EnronQualityError(f"Slice spec {index} differs from its document role or text view.")
        slices.append(
            _SliceSpec(
                slice_id,
                label_artifact_id,
                label_strength,
                annotation_scope["entity_classes"],
                annotation_scope["document_regions"],
                annotation_scope["span_policy_sha256"],
                annotation_scope["exclusions"],
                completeness,
                entity_class,
                cohort,
                split_role,
                text_view,
                text_view_descriptor["artifact_sha256"],
                text_view_descriptor["content_policy_sha256"],
                text_view_descriptor["document_regions"],
                text_view_descriptor["primary_for_quality"],
                text_view_descriptor["answer_bearing_fields_included"],
                promotion_gate,
                document_ids,
            )
        )
    return tuple(slices)


def _prepare_text_view_descriptor(value: Any, text_view: str, index: int) -> dict[str, Any]:
    _require_closed_mapping(value, _TEXT_VIEW_DESCRIPTOR_FIELDS, "text view descriptor", index)
    descriptor_id = _required_public_id(value["id"], "text view descriptor id", index)
    artifact_sha256 = value["artifact_sha256"]
    content_policy_sha256 = value["content_policy_sha256"]
    document_regions = tuple(
        sorted(_bounded_public_id_sequence(value["document_regions"], "text view document region", index))
    )
    primary_for_quality = value["primary_for_quality"]
    answer_bearing_fields_included = value["answer_bearing_fields_included"]
    if descriptor_id != text_view:
        raise EnronQualityError(f"Slice spec {index} text view descriptor id does not match its text view.")
    if (
        not isinstance(artifact_sha256, str)
        or not _SHA256_RE.fullmatch(artifact_sha256)
        or not isinstance(content_policy_sha256, str)
        or not _SHA256_RE.fullmatch(content_policy_sha256)
        or type(primary_for_quality) is not bool
        or type(answer_bearing_fields_included) is not bool
    ):
        raise EnronQualityError(f"Slice spec {index} text view descriptor is invalid.")
    return {
        "id": descriptor_id,
        "artifact_sha256": artifact_sha256,
        "content_policy_sha256": content_policy_sha256,
        "document_regions": document_regions,
        "primary_for_quality": primary_for_quality,
        "answer_bearing_fields_included": answer_bearing_fields_included,
    }


def _prepare_declared_unsupported(
    values: Sequence[Mapping[str, Any]], slices: Sequence[_SliceSpec]
) -> tuple[dict[str, str], ...]:
    _require_sequence(values, "unsupported_slice_specs")
    _require_item_limit(values, "unsupported_slice_specs")
    occupied = {item.id for item in slices}
    result: list[dict[str, str]] = []
    for index, value in enumerate(values):
        _require_closed_mapping(value, _UNSUPPORTED_SLICE_FIELDS, "unsupported slice spec", index)
        item = {
            "id": _required_public_id(value["id"], "unsupported slice id", index),
            "dimension": _required_public_id(value["dimension"], "unsupported slice dimension", index),
            "reason_code": _required_public_id(value["reason_code"], "unsupported slice reason code", index),
        }
        if item["id"] in occupied:
            raise EnronQualityError("Supported and unsupported slice identifiers must be unique.")
        occupied.add(item["id"])
        result.append(item)
    return tuple(sorted(result, key=lambda item: item["id"]))


def _validate_slice_coverage(
    documents: Mapping[str, _Document], gold_spans: Sequence[_GoldSpan], slices: Sequence[_SliceSpec]
) -> None:
    referenced_documents = {document_id for spec in slices for document_id in spec.document_ids}
    if referenced_documents != set(documents):
        raise EnronQualityError("Every quality document must be assigned to at least one supported slice.")
    covered_pairs = {(document_id, spec.entity_class) for spec in slices for document_id in spec.document_ids}
    if any((gold.document_id, gold.entity_class) not in covered_pairs for gold in gold_spans):
        raise EnronQualityError("Every gold span must be assigned to an in-class supported slice.")
    for spec in slices:
        if not spec.promotion_gate:
            continue
        frozen_population = {
            document.document_id
            for document in documents.values()
            if document.split_role == spec.split_role and document.text_view == spec.text_view
        }
        if set(spec.document_ids) != frozen_population:
            raise EnronQualityError("A promotion-gated slice must cover its complete role and text-view population.")


def _prepare_annotation_scope(value: Any, index: int) -> dict[str, Any]:
    _require_closed_mapping(value, _ANNOTATION_SCOPE_FIELDS, "annotation scope", index)
    entity_classes = _bounded_public_id_sequence(value["entity_classes"], "annotation entity class", index)
    document_regions = _bounded_public_id_sequence(value["document_regions"], "annotation document region", index)
    exclusions = _bounded_public_id_sequence(value["exclusions"], "annotation exclusion", index, allow_empty=True)
    span_policy_sha256 = value["span_policy_sha256"]
    if not isinstance(span_policy_sha256, str) or not _SHA256_RE.fullmatch(span_policy_sha256):
        raise EnronQualityError(f"Slice spec {index} annotation span policy hash is invalid.")
    return {
        "entity_classes": entity_classes,
        "document_regions": document_regions,
        "span_policy_sha256": span_policy_sha256,
        "exclusions": exclusions,
    }


def _bounded_public_id_sequence(
    value: Any,
    description: str,
    index: int,
    *,
    allow_empty: bool = False,
) -> tuple[str, ...]:
    _require_sequence(value, f"slice spec {index} {description}s")
    items = tuple(_required_public_id(item, description, index) for item in value)
    if (not items and not allow_empty) or len(items) != len(set(items)):
        raise EnronQualityError(f"Slice spec {index} {description}s must be a unique bounded list.")
    return items


def _active_pattern_inventory(bank: Mapping[str, Any] | None) -> frozenset[tuple[str, str, str]]:
    if bank is None:
        return frozenset()
    inventory: set[tuple[str, str, str]] = set()
    entities = bank.get("entities")
    if not isinstance(entities, Mapping):
        return frozenset()
    for entity_id, entity in entities.items():
        if not isinstance(entity_id, str) or not isinstance(entity, Mapping):
            continue
        names = entity.get("names")
        if not isinstance(names, Mapping):
            continue
        for name_id, name in names.items():
            if not isinstance(name_id, str) or not isinstance(name, Mapping):
                continue
            patterns = name.get("patterns")
            if not isinstance(patterns, Mapping):
                continue
            for pattern_id in patterns:
                if isinstance(pattern_id, str):
                    inventory.add((entity_id, name_id, pattern_id))
    return frozenset(inventory)


def _validate_catalog_identities(
    gold_spans: Sequence[_GoldSpan], active_patterns: frozenset[tuple[str, str, str]]
) -> None:
    if any(item.catalog_identity is not None and item.catalog_identity not in active_patterns for item in gold_spans):
        raise EnronQualityError("A frozen catalog qualification is not present in the active pattern inventory.")


def _scan_documents(compiled: Any, documents: Mapping[str, _Document]) -> tuple[_Prediction, ...]:
    predictions: list[_Prediction] = []
    for document_id in sorted(documents):
        document = documents[document_id]
        try:
            records = compiled.finditer(
                document.text,
                max_matches=DEFAULT_MAX_QUALITY_PREDICTIONS_PER_DOCUMENT,
            )
        except MemoryError:
            raise EnronQualityError("Quality scan exceeded the per-document prediction limit.") from None
        except Exception:
            raise EnronQualityError("A private quality document could not be scanned safely.") from None
        if not records:
            continue
        if len(predictions) + len(records) > DEFAULT_MAX_QUALITY_PREDICTIONS_TOTAL:
            raise EnronQualityError("Quality scan exceeded the cumulative prediction limit.")
        raw_offsets: set[int] = set()
        for record in records:
            try:
                start = record["start"]
                end = record["end"]
            except KeyError as exc:
                raise EnronQualityError("A native prediction did not contain bounded offsets.") from exc
            if (
                record.get("offset_unit") != "byte"
                or type(start) is not int
                or type(end) is not int
                or start < 0
                or end <= start
            ):
                raise EnronQualityError("A native prediction did not contain bounded offsets.")
            raw_offsets.update((start, end))
        byte_to_scalar = _selected_byte_to_scalar_boundaries(document.text, raw_offsets)
        for record in records:
            try:
                start = byte_to_scalar[record["start"]]
                end = byte_to_scalar[record["end"]]
            except KeyError as exc:
                raise EnronQualityError("A native prediction did not align to Unicode scalar boundaries.") from exc
            predictions.append(
                _Prediction(
                    document_id,
                    str(record["entity_id"]),
                    start,
                    end,
                    str(record["entity_id"]),
                    str(record["name_id"]),
                    str(record["pattern_id"]),
                )
            )
    return tuple(
        sorted(
            predictions,
            key=lambda item: (*item.key, item.entity_id, item.name_id, item.pattern_id),
        )
    )


def _selected_byte_to_scalar_boundaries(text: str, requested: set[int]) -> dict[int, int]:
    targets = sorted(requested)
    boundaries: dict[int, int] = {}
    target_index = 0
    while target_index < len(targets) and targets[target_index] == 0:
        boundaries[0] = 0
        target_index += 1
    byte_offset = 0
    for scalar_offset, character in enumerate(text, start=1):
        byte_offset += len(character.encode("utf-8"))
        if target_index < len(targets) and targets[target_index] < byte_offset:
            raise EnronQualityError("A native prediction did not align to Unicode scalar boundaries.")
        while target_index < len(targets) and targets[target_index] == byte_offset:
            boundaries[byte_offset] = scalar_offset
            target_index += 1
        if target_index == len(targets):
            break
    if target_index != len(targets):
        raise EnronQualityError("A native prediction exceeded the document byte length.")
    return boundaries


def _unsupported_reason(
    spec: _SliceSpec,
    gold_by_document: Mapping[str, Sequence[_GoldSpan]],
) -> str | None:
    if not spec.document_ids:
        return "empty_document_population"
    has_gold = any(
        gold.entity_class == spec.entity_class
        for document_id in spec.document_ids
        for gold in gold_by_document.get(document_id, ())
    )
    if spec.promotion_gate and not has_gold:
        return "zero_gold_promotion_support"
    if not spec.open_world_eligible and not any(
        gold.entity_class == spec.entity_class
        for document_id in spec.document_ids
        for gold in gold_by_document.get(document_id, ())
    ):
        return "zero_labeled_spans"
    return None


def _evaluate_slice(
    spec: _SliceSpec,
    documents: Mapping[str, _Document],
    gold_by_document: Mapping[str, Sequence[_GoldSpan]],
    predictions_by_document: Mapping[str, Sequence[_Prediction]],
) -> dict[str, Any]:
    document_ids = frozenset(spec.document_ids)
    gold = sorted(
        (
            item
            for document_id in spec.document_ids
            for item in gold_by_document.get(document_id, ())
            if item.entity_class == spec.entity_class
        ),
        key=lambda item: item.key,
    )
    predictions = sorted(
        (
            item
            for document_id in spec.document_ids
            for item in predictions_by_document.get(document_id, ())
            if item.entity_class == spec.entity_class
        ),
        key=lambda item: (*item.key, item.entity_id, item.name_id, item.pattern_id),
    )

    prediction_indices: dict[tuple[str, str, int, int], list[int]] = defaultdict(list)
    for index, prediction in enumerate(predictions):
        prediction_indices[prediction.key].append(index)
    selected_predictions: dict[tuple[str, str, int, int], int] = {}
    for item in gold:
        candidates = prediction_indices.get(item.key, [])
        if not candidates:
            continue
        selected = candidates[0]
        if item.catalog_identity is not None:
            expected_identity = item.catalog_identity[:2]
            selected = next(
                (
                    prediction_index
                    for prediction_index in candidates
                    if predictions[prediction_index].identity == expected_identity
                ),
                selected,
            )
        selected_predictions[item.key] = selected

    true_positive = len(selected_predictions)
    false_negative = len(gold) - true_positive
    false_positive = len(predictions) - true_positive if spec.open_world_eligible else 0
    predicted_spans = len(predictions) if spec.open_world_eligible else true_positive

    miss_documents: set[str] = set()
    catalog_miss_documents: set[str] = set()
    cataloged_true_positive = 0
    cataloged_false_negative = 0
    cataloged_wrong_canonical = 0
    for item in gold:
        selected_index = selected_predictions.get(item.key)
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

    if spec.open_world_eligible:
        character_counts = _character_counts(document_ids, documents, gold, predictions)
        negative_documents = document_ids - gold_documents
        prediction_documents = {item.document_id for item in predictions}
        negative_documents_with_predictions = len(negative_documents & prediction_documents)
    else:
        character_counts = {
            "sensitive_gold_characters": 0,
            "covered_sensitive_characters": 0,
            "leaked_sensitive_characters": 0,
            "predicted_characters": 0,
            "over_redacted_characters": 0,
            "evaluated_characters": 0,
            "documents_with_any_leaked_character": 0,
        }
        negative_documents = frozenset()
        negative_documents_with_predictions = 0

    metrics = {
        "precision": _ratio(true_positive, predicted_spans) if spec.open_world_eligible else None,
        "open_world_recall": _ratio(true_positive, len(gold)) if spec.open_world_eligible else None,
        "f1": _f1(true_positive, false_positive, false_negative) if spec.open_world_eligible else None,
        "catalog_coverage": _ratio(cataloged_gold_spans, len(gold)),
        "cataloged_recall": _ratio(cataloged_true_positive, cataloged_gold_spans),
        "document_leak_rate": (_ratio(len(miss_documents), len(gold_documents)) if spec.open_world_eligible else None),
        "cataloged_document_leak_rate": (
            _ratio(len(catalog_miss_documents), len(catalog_documents)) if spec.open_world_eligible else None
        ),
        "sensitive_character_recall": (
            _ratio(character_counts["covered_sensitive_characters"], character_counts["sensitive_gold_characters"])
            if spec.open_world_eligible
            else None
        ),
        "sensitive_character_leak_rate": (
            _ratio(character_counts["leaked_sensitive_characters"], character_counts["sensitive_gold_characters"])
            if spec.open_world_eligible
            else None
        ),
        "negative_document_false_alarm_rate": (
            _ratio(negative_documents_with_predictions, len(negative_documents)) if spec.open_world_eligible else None
        ),
        "over_redaction_rate": (
            _ratio(character_counts["over_redacted_characters"], character_counts["evaluated_characters"])
            if spec.open_world_eligible
            else None
        ),
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
        "documents_with_any_leaked_character": character_counts["documents_with_any_leaked_character"],
        "gold_spans": len(gold),
        "predicted_spans": predicted_spans,
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "cataloged_gold_spans": cataloged_gold_spans,
        "cataloged_true_positive": cataloged_true_positive,
        "cataloged_false_negative": cataloged_false_negative,
        "cataloged_wrong_canonical": cataloged_wrong_canonical,
        "sensitive_gold_characters": character_counts["sensitive_gold_characters"],
        "covered_sensitive_characters": character_counts["covered_sensitive_characters"],
        "leaked_sensitive_characters": character_counts["leaked_sensitive_characters"],
        "predicted_characters": character_counts["predicted_characters"],
        "over_redacted_characters": character_counts["over_redacted_characters"],
        "evaluated_characters": character_counts["evaluated_characters"],
        "negative_documents": len(negative_documents),
        "negative_documents_with_predictions": negative_documents_with_predictions,
        "metrics": metrics,
    }


def _character_counts(
    document_ids: frozenset[str],
    documents: Mapping[str, _Document],
    gold: Sequence[_GoldSpan],
    predictions: Sequence[_Prediction],
) -> dict[str, int]:
    gold_intervals: dict[str, list[tuple[int, int]]] = defaultdict(list)
    prediction_intervals: dict[str, list[tuple[int, int]]] = defaultdict(list)
    for gold_span in gold:
        gold_intervals[gold_span.document_id].append((gold_span.start, gold_span.end))
    for prediction in predictions:
        prediction_intervals[prediction.document_id].append((prediction.start, prediction.end))

    sensitive = 0
    covered = 0
    predicted = 0
    documents_with_leak = 0
    for document_id in document_ids:
        gold_union = _merge_intervals(gold_intervals.get(document_id, ()))
        prediction_union = _merge_intervals(prediction_intervals.get(document_id, ()))
        gold_count = _interval_length(gold_union)
        covered_count = _intersection_length(gold_union, prediction_union)
        prediction_count = _interval_length(prediction_union)
        sensitive += gold_count
        covered += covered_count
        predicted += prediction_count
        if gold_count > covered_count:
            documents_with_leak += 1
    return {
        "sensitive_gold_characters": sensitive,
        "covered_sensitive_characters": covered,
        "leaked_sensitive_characters": sensitive - covered,
        "predicted_characters": predicted,
        "over_redacted_characters": predicted - covered,
        "evaluated_characters": sum(len(documents[document_id].text) for document_id in document_ids),
        "documents_with_any_leaked_character": documents_with_leak,
    }


def _merge_intervals(values: Sequence[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(values):
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
    return tuple(merged)


def _interval_length(values: Sequence[tuple[int, int]]) -> int:
    return sum(end - start for start, end in values)


def _intersection_length(first: Sequence[tuple[int, int]], second: Sequence[tuple[int, int]]) -> int:
    total = 0
    first_index = 0
    second_index = 0
    while first_index < len(first) and second_index < len(second):
        first_start, first_end = first[first_index]
        second_start, second_end = second[second_index]
        total += max(0, min(first_end, second_end) - max(first_start, second_start))
        if first_end <= second_end:
            first_index += 1
        else:
            second_index += 1
    return total


def _protocol_hash(
    evaluator: Mapping[str, Any],
    policy_sha256: str,
    documents: Mapping[str, _Document],
    gold_spans: Sequence[_GoldSpan],
    slices: Sequence[_SliceSpec],
    unsupported_slices: Sequence[Mapping[str, str]],
) -> str:
    document_descriptors = [
        {
            "document_id": item.document_id,
            "text_sha256": _hash_bytes(item.text.encode("utf-8")),
            "unicode_scalars": len(item.text),
            "text_view": item.text_view,
            "split_role": item.split_role,
        }
        for item in sorted(documents.values(), key=lambda value: value.document_id)
    ]
    gold_descriptors = [
        {
            "document_id": item.document_id,
            "entity_class": item.entity_class,
            "start": item.start,
            "end": item.end,
        }
        for item in gold_spans
    ]
    return _canonical_hash(
        {
            "evaluator": evaluator,
            "policy_sha256": policy_sha256,
            "documents": document_descriptors,
            "gold_spans": gold_descriptors,
            "slice_specs": [item.fingerprint_payload() for item in slices],
            "unsupported_slice_specs": list(unsupported_slices),
        }
    )


def _catalog_binding_hash(gold_spans: Sequence[_GoldSpan], canonical_bank_sha256: str) -> str:
    return _canonical_hash(
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
                for item in gold_spans
            ],
        }
    )


def _evaluator_identity() -> dict[str, str]:
    try:
        source_sha256 = _hash_bytes(Path(__file__).read_bytes())
        contract_validator_source_sha256 = _hash_bytes(Path(enron_contract.__file__).read_bytes())
        execution_adapter_sha256 = extraction_execution_sha256()
    except (OSError, RuntimeError, ValueError):
        raise EnronQualityError("Quality evaluator source could not be fingerprinted.") from None
    return {
        "id": EVALUATOR_ID,
        "version": EVALUATOR_VERSION,
        "source_sha256": source_sha256,
        "label_schema_sha256": _canonical_hash(_LABEL_SCHEMA_DESCRIPTOR),
        "contract_validator_source_sha256": contract_validator_source_sha256,
        "contract_schema_sha256": _canonical_hash(enron_contract.ENRON_QUALITY_OUTPUT_SCHEMA),
        "execution_adapter_sha256": execution_adapter_sha256,
    }


def _canonical_hash(value: Any) -> str:
    return _hash_bytes(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def _hash_bytes(value: bytes) -> str:
    return "sha256:" + sha256(value).hexdigest()


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _f1(true_positive: int, false_positive: int, false_negative: int) -> float | None:
    denominator = 2 * true_positive + false_positive + false_negative
    return (2 * true_positive) / denominator if denominator else None


def _required_id(value: Any, field: str, index: int) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise EnronQualityError(f"Item {index} {field} must be a non-empty bounded string.")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise EnronQualityError(f"Item {index} {field} must be valid UTF-8 text.") from None
    return value


def _required_public_id(value: Any, field: str, index: int) -> str:
    item = _required_id(value, field, index)
    if not _PUBLIC_ID_RE.fullmatch(item):
        raise EnronQualityError(f"Item {index} {field} must be a privacy-safe logical identifier.")
    return item


def _nonnegative_integer(value: Any, field: str, index: int) -> int:
    if type(value) is not int or value < 0:
        raise EnronQualityError(f"Item {index} {field} must be a non-negative integer.")
    return value


def _require_sequence(value: Any, description: str) -> None:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise EnronQualityError(f"{description} must be a sequence.")


def _require_item_limit(value: Sequence[Any], description: str) -> None:
    if len(value) > DEFAULT_MAX_QUALITY_RECORDS:
        raise EnronQualityError(f"{description} exceeds the quality record limit.")


def _require_closed_mapping(value: Any, fields: frozenset[str], description: str, index: int) -> None:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise EnronQualityError(f"{description.capitalize()} {index} must use the closed quality schema.")

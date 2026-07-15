"""One-shot scoring and post-score review for the frozen Enron gold audit.

The scoring path verifies the sealed sample, independent gold, and
prediction-blind catalog qualification before compiling the bank.  It scans
each document once, commits the exact text-free prediction stream, and writes
private cases for a distinct post-score reviewer.  Verification replays the
committed score from gold, catalog bindings, and predictions without compiling
or scanning a bank.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from . import enron_catalog_adjudication as _catalog
from . import enron_gold_annotations as _gold
from . import enron_quality as _quality
from .bank import hash_bank
from .enron_contract import (
    CHARACTER_POSITION_SEMANTICS,
    MATCHING_SEMANTICS,
    MAX_QUALITY_THRESHOLDS,
    MIN_DECISION_GRADE_DOCUMENTS,
    MIN_DECISION_GRADE_GOLD_SPANS,
    MIN_DECISION_GRADE_NEGATIVE_DOCUMENTS,
    MIN_DECISION_GRADE_SENSITIVE_CHARACTERS,
    MIN_QUALITY_THRESHOLDS,
    PERSON_CONTACT_ENTITY_CLASSES,
    PERSON_CONTACT_SCOPE_ID,
    hash_enron_thresholds,
    validate_enron_quality_output,
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

__all__ = [
    "AUDIT_SCORING_POLICY",
    "AUDIT_SCORING_POLICY_SHA256",
    "EnronAuditScoringError",
    "PREDICTION_AUDIT_POLICY",
    "PREDICTION_AUDIT_POLICY_SHA256",
    "QUALITY_DECISION_POLICY",
    "QUALITY_DECISION_POLICY_SHA256",
    "finalize_enron_prediction_audit_files",
    "score_enron_gold_audit_files",
    "verify_enron_gold_audit_score",
    "verify_enron_prediction_audit",
]

SCORE_MANIFEST_SCHEMA_VERSION = "nerb.enron_gold_audit_score_run"
SCORE_RECEIPT_SCHEMA_VERSION = "nerb.enron_gold_audit_score_receipt"
INSUFFICIENT_SUPPORT_MANIFEST_SCHEMA_VERSION = "nerb.enron_gold_audit_insufficient_support_run"
INSUFFICIENT_SUPPORT_RECEIPT_SCHEMA_VERSION = "nerb.enron_gold_audit_insufficient_support_receipt"
CASE_SCHEMA_VERSION = "nerb.enron_prediction_audit_case"
PREDICTION_AUDIT_REVIEW_SCHEMA_VERSION = "nerb.enron_prediction_audit_review"
PREDICTION_AUDIT_MANIFEST_SCHEMA_VERSION = "nerb.enron_prediction_audit_run"
PREDICTION_AUDIT_RECEIPT_SCHEMA_VERSION = "nerb.enron_prediction_audit_receipt"

_COMMIT_PAYLOAD = b"nerb.enron.private-run.v2\n"
_SUCCESSFUL_SCORE_RUN_FILES = frozenset(
    {"COMMITTED", "predictions.jsonl", "cases.jsonl", "quality.json", "manifest.json", "receipt.json"}
)
_INSUFFICIENT_SCORE_RUN_FILES = frozenset({"COMMITTED", "manifest.json", "receipt.json"})
_AUDIT_RUN_FILES = frozenset({"COMMITTED", "reviews.jsonl", "manifest.json", "receipt.json"})
_PREDICTION_FIELDS = frozenset({"document_id", "entity_class", "start", "end", "entity_id", "name_id", "pattern_id"})
_CATALOG_IDENTITY_FIELDS = frozenset({"entity_id", "name_id", "pattern_id"})
_CASE_FIELDS = frozenset(
    {
        "schema_version",
        "case_id",
        "document_id",
        "reasons",
        "gold",
        "prediction",
        "selection_rank_sha256",
    }
)
_CASE_GOLD_FIELDS = frozenset({"entity_class", "start", "end", "catalog_identity"})
_CASE_PREDICTION_FIELDS = frozenset(
    {"stream_index", "entity_class", "start", "end", "entity_id", "name_id", "pattern_id"}
)
_REVIEW_FIELDS = frozenset({"schema_version", "case_id", "reviewer_id", "finding", "reason_codes", "unresolved"})
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
_PROMOTION_CHECK_CONFIGURATION_FIELDS = frozenset({"id", "category", "target", "operator", "threshold"})
_PROMOTION_CHECK_FIELDS = _PROMOTION_CHECK_CONFIGURATION_FIELDS | {"actual", "passed"}
_QUALITY_RESULT_FIELDS = frozenset(
    {
        "schema_version",
        "evaluator",
        "evaluator_sha256",
        "policy_sha256",
        "protocol_sha256",
        "catalog_binding_sha256",
        "prediction_commitment",
        "run_sha256",
        "bank",
        "evaluated",
        "quality",
        "contract_validation",
        "unsupported_slices",
    }
)
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MAX_JSON_BYTES = 64 * 1024 * 1024
_MAX_LINE_BYTES = 16 * 1024 * 1024
_MAX_ROWS = 5_000_000
_CASE_REASON_ORDER = (
    "false_negative",
    "false_positive",
    "boundary_or_class_mismatch",
    "wrong_canonical",
    "true_positive_sample",
    "certified_negative_document",
)
_CASE_REASONS = frozenset(_CASE_REASON_ORDER)
_FINDINGS = frozenset({"confirmed", "gold_defect"})
_CONFIRMED_REASON_CODES = frozenset({"case_confirmed"})
_GOLD_DEFECT_REASON_CODES = frozenset(
    {
        "missing_gold_span",
        "incorrect_gold_span",
        "incorrect_gold_class",
        "incorrect_catalog_binding",
        "other_gold_defect",
    }
)
_SUPPORT_FAILURE_ORDER = (
    "production_document_count_mismatch",
    "documents_below_minimum",
    "gold_spans_below_minimum",
    "negative_documents_below_minimum",
    "sensitive_characters_below_minimum",
    "contact_gold_support_missing",
    "person_gold_support_missing",
)
_SCORE_CLAIM_SCHEMA_VERSION = "nerb.enron_gold_audit_score_claim.v1"
_SCORE_OUTCOME_SCHEMA_VERSION = "nerb.enron_gold_audit_score_outcome.v1"

QUALITY_DECISION_POLICY: dict[str, Any] = {
    "schema_version": "nerb.enron_gold_audit_quality_decision_policy",
    "slice_id": "person_contact_all_test",
    "scope": PERSON_CONTACT_SCOPE_ID,
    "contract_gate": {"id": "contract_valid", "operator": "eq", "threshold": True},
    "requirements": [
        {
            "id": "cataloged_false_negative",
            "target": "/quality/slices/0/cataloged_false_negative",
            "operator": "eq",
            "policy_threshold": 0,
        },
        {
            "id": "cataloged_wrong_canonical",
            "target": "/quality/slices/0/cataloged_wrong_canonical",
            "operator": "eq",
            "policy_threshold": 0,
        },
        {
            "id": "documents_with_any_cataloged_miss",
            "target": "/quality/slices/0/documents_with_any_cataloged_miss",
            "operator": "eq",
            "policy_threshold": 0,
        },
        {
            "id": "open_world_recall",
            "target": "/quality/slices/0/metrics/open_world_recall",
            "operator": "gte",
            "policy_threshold": MIN_QUALITY_THRESHOLDS["open_world_recall"],
        },
        {
            "id": "catalog_coverage",
            "target": "/quality/slices/0/metrics/catalog_coverage",
            "operator": "gte",
            "policy_threshold": MIN_QUALITY_THRESHOLDS["catalog_coverage"],
        },
        {
            "id": "cataloged_recall",
            "target": "/quality/slices/0/metrics/cataloged_recall",
            "operator": "gte",
            "policy_threshold": MIN_QUALITY_THRESHOLDS["cataloged_recall"],
        },
        {
            "id": "sensitive_character_recall",
            "target": "/quality/slices/0/metrics/sensitive_character_recall",
            "operator": "gte",
            "policy_threshold": MIN_QUALITY_THRESHOLDS["sensitive_character_recall"],
        },
        {
            "id": "document_leak_rate",
            "target": "/quality/slices/0/metrics/document_leak_rate",
            "operator": "lte",
            "policy_threshold": MAX_QUALITY_THRESHOLDS["document_leak_rate"],
        },
        {
            "id": "sensitive_character_leak_rate",
            "target": "/quality/slices/0/metrics/sensitive_character_leak_rate",
            "operator": "lte",
            "policy_threshold": MAX_QUALITY_THRESHOLDS["sensitive_character_leak_rate"],
        },
        {
            "id": "negative_document_false_alarm_rate",
            "target": "/quality/slices/0/metrics/negative_document_false_alarm_rate",
            "operator": "lte",
            "policy_threshold": MAX_QUALITY_THRESHOLDS["negative_document_false_alarm_rate"],
        },
        {
            "id": "over_redaction_rate",
            "target": "/quality/slices/0/metrics/over_redaction_rate",
            "operator": "lte",
            "policy_threshold": MAX_QUALITY_THRESHOLDS["over_redaction_rate"],
        },
    ],
}
QUALITY_DECISION_POLICY_SHA256 = (
    "sha256:"
    + hashlib.sha256(
        json.dumps(QUALITY_DECISION_POLICY, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
)

AUDIT_SCORING_POLICY: dict[str, Any] = {
    "schema_version": "nerb.enron_gold_audit_scoring_policy",
    "document_order": "document_id_ascending",
    "text_view": {
        "id": "subject_current_body",
        "document_regions": ["subject", "current_body"],
        "primary_for_quality": True,
        "answer_bearing_fields_included": False,
    },
    "scope": {"id": PERSON_CONTACT_SCOPE_ID, "entity_classes": list(PERSON_CONTACT_ENTITY_CLASSES)},
    "slices": [
        {"id": "person_contact_all_test", "entity_class": PERSON_CONTACT_SCOPE_ID, "promotion_gate": True},
        {"id": "contact_all_test", "entity_class": "contact", "promotion_gate": False},
        {"id": "person_all_test", "entity_class": "person", "promotion_gate": False},
    ],
    "matching": "first_exact_key_prefer_expected_catalog_entity_and_name",
    "scan": {"bank_compilations": 1, "scans_per_document": 1},
    "prediction_artifact": "exact_consume_then_scan_order_text_free",
    "support": {
        "production_documents": MIN_DECISION_GRADE_DOCUMENTS,
        "gold_spans": MIN_DECISION_GRADE_GOLD_SPANS,
        "negative_documents": MIN_DECISION_GRADE_NEGATIVE_DOCUMENTS,
        "sensitive_characters": MIN_DECISION_GRADE_SENSITIVE_CHARACTERS,
        "nonzero_classes": list(PERSON_CONTACT_ENTITY_CLASSES),
    },
    "case_review": {
        "all_false_negatives": True,
        "all_false_positives": True,
        "all_wrong_canonical": True,
        "overlap_tag": "boundary_or_class_mismatch",
        "true_positive_sample": 20,
        "certified_negative_document_sample": 20,
        "selection": "domain_separated_min_sha256",
    },
    "quality_decision_policy_sha256": QUALITY_DECISION_POLICY_SHA256,
    "gold_mutability_after_scoring": "forbidden",
}
AUDIT_SCORING_POLICY_SHA256 = (
    "sha256:"
    + hashlib.sha256(
        json.dumps(AUDIT_SCORING_POLICY, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
)

PREDICTION_AUDIT_POLICY: dict[str, Any] = {
    "schema_version": "nerb.enron_prediction_audit_policy",
    "coverage": "every_committed_case_exactly_once",
    "reviewer": "one_identity_distinct_from_all_gold_roles_and_catalog_reviewer",
    "findings": sorted(_FINDINGS),
    "confirmed_reason_codes": sorted(_CONFIRMED_REASON_CODES),
    "gold_defect_reason_codes": sorted(_GOLD_DEFECT_REASON_CODES),
    "unresolved": "forbidden",
    "gold_defect": {
        "status": "invalidated_gold_defect",
        "decision_eligible": False,
        "release": "do_not_ship",
        "gold_mutation": "forbidden",
        "rescore": "forbidden",
    },
    "quality_failure": {
        "status": "quality_gates_failed",
        "decision_eligible": False,
        "release": "do_not_ship",
    },
    "accepted": {"status": "accepted", "decision_eligible": True, "release": "quality_eligible"},
}
PREDICTION_AUDIT_POLICY_SHA256 = (
    "sha256:"
    + hashlib.sha256(
        json.dumps(PREDICTION_AUDIT_POLICY, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
)


class EnronAuditScoringError(ValueError):
    """Raised when a frozen audit score or prediction review is invalid."""


def score_enron_gold_audit_files(
    sample_run_dir: Path,
    gold_run_dir: Path,
    catalog_run_dir: Path,
    bank: Mapping[str, Any] | Path,
    output_dir: Path,
    *,
    promotion_checks: Sequence[Mapping[str, Any]] | Mapping[str, Any] | Path,
    score_state_dir: Path,
    gold_state_dir: Path,
    expected_gold_commitment: Mapping[str, str],
    text_view_descriptor: Mapping[str, Any],
    expected_audit_output_binding_sha256: str | None = None,
    allow_unignored_output: bool = False,
) -> dict[str, Any]:
    """Score one immutable gold panel with one bank compilation and scan per document."""

    claim: dict[str, Any] | None = None
    terminalized = False
    try:
        prepared = _load_prepared_inputs(
            Path(sample_run_dir),
            Path(gold_run_dir),
            Path(catalog_run_dir),
            bank,
            gold_state_dir=Path(gold_state_dir),
            expected_gold_commitment=expected_gold_commitment,
            expected_audit_output_binding_sha256=expected_audit_output_binding_sha256,
        )
        descriptor = _validate_text_view_descriptor(text_view_descriptor)
        frozen = _prepare_frozen_decision_inputs(prepared, promotion_checks)
        claim = _acquire_score_claim(Path(score_state_dir), prepared, Path(output_dir))
        support = _support_assessment(prepared)
        if support["failure_codes"]:
            manifest = _insufficient_support_manifest(prepared, descriptor, frozen, claim, support)
            receipt = _insufficient_support_receipt(manifest)
            with PrivateRun(Path(output_dir), allow_unignored_output=allow_unignored_output) as run:
                with run.open_binary("manifest.json") as file:
                    file.write(_canonical_json_file(manifest))
                with run.open_binary("receipt.json") as file:
                    file.write(_canonical_json_file(receipt))
                run.commit()
            _terminalize_score_claim(Path(score_state_dir), claim, receipt)
            terminalized = True
            return _detached(receipt)

        slice_specs = _slice_specs(descriptor, str(prepared["gold_receipt"]["annotation_policy_sha256"]))
        predictions: list[dict[str, Any]] = []
        session = _quality.prepare_enron_quality(prepared["bank"], slice_specs=slice_specs, max_diagnostics=0)
        with session:
            for document_id in prepared["document_ids"]:
                document = prepared["documents"][document_id]
                predictions.extend(
                    session.consume_with_predictions(
                        {
                            "document_id": document_id,
                            "text": document["text"],
                            "text_view": "subject_current_body",
                            "split_role": "test",
                        },
                        prepared["gold_by_document"][document_id],
                        [spec["id"] for spec in slice_specs],
                    )
                )
            quality_result = session.finish()

        prediction_commitment = _quality.hash_enron_quality_predictions(predictions)
        if quality_result.get("prediction_commitment") != prediction_commitment:
            raise EnronAuditScoringError("Quality output does not commit the exact persisted prediction stream.")
        _validate_prediction_order_and_bounds(predictions, prepared["documents"])
        cases = _build_cases(prepared, predictions, prediction_commitment)
        _verify_quality_result(prepared, descriptor, slice_specs, predictions, quality_result, frozen)

        prediction_payload = _canonical_jsonl(predictions)
        case_payload = _canonical_jsonl(cases)
        quality_payload = _canonical_json_file(quality_result)
        artifacts = {
            "predictions": _artifact_descriptor("predictions.jsonl", prediction_payload, len(predictions)),
            "cases": _artifact_descriptor("cases.jsonl", case_payload, len(cases)),
            "quality": _artifact_descriptor("quality.json", quality_payload, 1),
        }
        manifest = _score_manifest(prepared, descriptor, slice_specs, quality_result, artifacts, cases, frozen, claim)
        receipt = _score_receipt(manifest, quality_result)
        with PrivateRun(Path(output_dir), allow_unignored_output=allow_unignored_output) as run:
            with run.open_binary("predictions.jsonl") as file:
                file.write(prediction_payload)
            with run.open_binary("cases.jsonl") as file:
                file.write(case_payload)
            with run.open_binary("quality.json") as file:
                file.write(quality_payload)
            with run.open_binary("manifest.json") as file:
                file.write(_canonical_json_file(manifest))
            with run.open_binary("receipt.json") as file:
                file.write(_canonical_json_file(receipt))
            run.commit()
        _terminalize_score_claim(Path(score_state_dir), claim, receipt)
        terminalized = True
        return _detached(receipt)
    except BaseException as exc:
        if claim is not None and not terminalized:
            _terminalize_failed_score_claim(Path(score_state_dir), claim)
        if isinstance(exc, (KeyboardInterrupt, SystemExit, EnronAuditScoringError)):
            raise
        if isinstance(
            exc,
            (
                _catalog.EnronCatalogAdjudicationError,
                _gold.EnronGoldAnnotationError,
                _quality.EnronQualityError,
                EnronPrivateIOError,
                OSError,
                TypeError,
                ValueError,
            ),
        ):
            raise EnronAuditScoringError("Enron gold audit scoring could not be completed safely.") from None
        raise


def verify_enron_gold_audit_score(
    run_dir: Path,
    sample_run_dir: Path,
    gold_run_dir: Path,
    catalog_run_dir: Path,
    bank: Mapping[str, Any] | Path,
    *,
    promotion_checks: Sequence[Mapping[str, Any]] | Mapping[str, Any] | Path,
    score_state_dir: Path,
    gold_state_dir: Path,
    expected_gold_commitment: Mapping[str, str],
    expected_audit_output_binding_sha256: str | None = None,
) -> dict[str, Any]:
    """Replay a committed score without compiling or scanning a bank."""

    try:
        receipt, _stored = _verify_enron_gold_audit_score(
            Path(run_dir),
            Path(sample_run_dir),
            Path(gold_run_dir),
            Path(catalog_run_dir),
            bank,
            promotion_checks=promotion_checks,
            score_state_dir=Path(score_state_dir),
            gold_state_dir=Path(gold_state_dir),
            expected_gold_commitment=expected_gold_commitment,
            expected_audit_output_binding_sha256=expected_audit_output_binding_sha256,
        )
        return _detached(receipt)
    except EnronAuditScoringError:
        raise
    except (
        _catalog.EnronCatalogAdjudicationError,
        _gold.EnronGoldAnnotationError,
        _quality.EnronQualityError,
        EnronPrivateIOError,
        OSError,
        TypeError,
        ValueError,
    ):
        raise EnronAuditScoringError("Enron gold audit score could not be verified safely.") from None


def _verify_enron_gold_audit_score(
    run_dir: Path,
    sample_run_dir: Path,
    gold_run_dir: Path,
    catalog_run_dir: Path,
    bank: Mapping[str, Any] | Path,
    *,
    promotion_checks: Sequence[Mapping[str, Any]] | Mapping[str, Any] | Path,
    score_state_dir: Path,
    gold_state_dir: Path,
    expected_gold_commitment: Mapping[str, str],
    expected_audit_output_binding_sha256: str | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        prepared = _load_prepared_inputs(
            sample_run_dir,
            gold_run_dir,
            catalog_run_dir,
            bank,
            gold_state_dir=gold_state_dir,
            expected_gold_commitment=expected_gold_commitment,
            expected_audit_output_binding_sha256=expected_audit_output_binding_sha256,
        )
        frozen = _prepare_frozen_decision_inputs(prepared, promotion_checks)
        support = _support_assessment(prepared)
        if support["failure_codes"]:
            stored = _load_insufficient_score_run(run_dir)
            descriptor = _validate_text_view_descriptor(stored["manifest"].get("text_view_descriptor"))
            claim = _expected_score_claim(prepared, run_dir)
            expected_manifest = _insufficient_support_manifest(prepared, descriptor, frozen, claim, support)
            if stored["manifest"] != expected_manifest:
                raise EnronAuditScoringError("Insufficient-support score manifest differs from deterministic replay.")
            expected_receipt = _insufficient_support_receipt(expected_manifest)
            if stored["receipt"] != expected_receipt:
                raise EnronAuditScoringError("Insufficient-support score receipt differs from deterministic replay.")
            _verify_score_claim(score_state_dir, prepared, run_dir, expected_receipt)
            stored["status"] = "insufficient_support"
            stored["catalog_reviewer_id"] = prepared["catalog_reviewer_id"]
            return _detached(expected_receipt), stored

        stored = _load_score_run(run_dir, frozen)
        descriptor = _validate_text_view_descriptor(stored["manifest"].get("text_view_descriptor"))
        slice_specs = _slice_specs(descriptor, str(prepared["gold_receipt"]["annotation_policy_sha256"]))
        predictions = stored["predictions"]
        _validate_prediction_order_and_bounds(predictions, prepared["documents"])
        commitment = _quality.hash_enron_quality_predictions(predictions)
        if commitment != stored["quality"]["prediction_commitment"]:
            raise EnronAuditScoringError("Stored predictions differ from the quality commitment.")
        expected_cases = _build_cases(prepared, predictions, commitment)
        if stored["cases"] != expected_cases:
            raise EnronAuditScoringError("Stored prediction-audit cases differ from deterministic replay.")
        _verify_quality_result(prepared, descriptor, slice_specs, predictions, stored["quality"], frozen)
        claim = _expected_score_claim(prepared, run_dir)
        expected_manifest = _score_manifest(
            prepared,
            descriptor,
            slice_specs,
            stored["quality"],
            stored["artifacts"],
            expected_cases,
            frozen,
            claim,
        )
        if stored["manifest"] != expected_manifest:
            raise EnronAuditScoringError("Score manifest differs from deterministic replay.")
        expected_receipt = _score_receipt(expected_manifest, stored["quality"])
        if stored["receipt"] != expected_receipt:
            raise EnronAuditScoringError("Score receipt differs from deterministic replay.")
        _verify_score_claim(score_state_dir, prepared, run_dir, expected_receipt)
        stored["status"] = "scored_pending_prediction_audit"
        stored["catalog_reviewer_id"] = prepared["catalog_reviewer_id"]
        return _detached(expected_receipt), stored
    except EnronAuditScoringError:
        raise
    except (
        _catalog.EnronCatalogAdjudicationError,
        _gold.EnronGoldAnnotationError,
        _quality.EnronQualityError,
        EnronPrivateIOError,
        OSError,
        TypeError,
        ValueError,
    ):
        raise EnronAuditScoringError("Enron gold audit score could not be verified safely.") from None


def finalize_enron_prediction_audit_files(
    score_run_dir: Path,
    gold_run_dir: Path,
    reviews_path: Path,
    output_dir: Path,
    *,
    sample_run_dir: Path,
    catalog_run_dir: Path,
    bank: Mapping[str, Any] | Path,
    promotion_checks: Sequence[Mapping[str, Any]] | Mapping[str, Any] | Path,
    score_state_dir: Path,
    gold_state_dir: Path,
    expected_gold_commitment: Mapping[str, str],
    expected_score_receipt: Mapping[str, Any],
    expected_audit_output_binding_sha256: str | None = None,
    allow_unignored_output: bool = False,
) -> dict[str, Any]:
    """Commit complete distinct-reviewer findings for every frozen score case."""

    try:
        verified_receipt, score = _verify_enron_gold_audit_score(
            Path(score_run_dir),
            Path(sample_run_dir),
            Path(gold_run_dir),
            Path(catalog_run_dir),
            bank,
            promotion_checks=promotion_checks,
            score_state_dir=Path(score_state_dir),
            gold_state_dir=Path(gold_state_dir),
            expected_gold_commitment=expected_gold_commitment,
            expected_audit_output_binding_sha256=expected_audit_output_binding_sha256,
        )
        _require_trusted_score_receipt(expected_score_receipt, verified_receipt, score)
        if score.get("status") != "scored_pending_prediction_audit":
            raise EnronAuditScoringError("Prediction audit requires a successfully completed score run.")
        reviewer_identities = _load_bound_gold_reviewer_identities(Path(gold_run_dir), score["receipt"])
        reviewer_identities.add(_identifier(score["catalog_reviewer_id"], "catalog_reviewer_id"))
        reviews, _source_descriptor = _load_prediction_audit_reviews(Path(reviews_path), score["cases"])
        _validate_prediction_audit_reviews(reviews, score["cases"], reviewer_identities)
        review_payload = _canonical_jsonl(reviews)
        review_artifact = _artifact_descriptor("reviews.jsonl", review_payload, len(reviews))
        manifest = _prediction_audit_manifest(score, review_artifact, reviews)
        receipt = _prediction_audit_receipt(manifest)
        with PrivateRun(Path(output_dir), allow_unignored_output=allow_unignored_output) as run:
            with run.open_binary("reviews.jsonl") as file:
                file.write(review_payload)
            with run.open_binary("manifest.json") as file:
                file.write(_canonical_json_file(manifest))
            with run.open_binary("receipt.json") as file:
                file.write(_canonical_json_file(receipt))
            run.commit()
        return _detached(receipt)
    except EnronAuditScoringError:
        raise
    except (EnronPrivateIOError, OSError, TypeError, ValueError):
        raise EnronAuditScoringError("Prediction audit could not be finalized safely.") from None


def verify_enron_prediction_audit(
    run_dir: Path,
    score_run_dir: Path,
    gold_run_dir: Path,
    *,
    sample_run_dir: Path,
    catalog_run_dir: Path,
    bank: Mapping[str, Any] | Path,
    promotion_checks: Sequence[Mapping[str, Any]] | Mapping[str, Any] | Path,
    score_state_dir: Path,
    gold_state_dir: Path,
    expected_gold_commitment: Mapping[str, str],
    expected_score_receipt: Mapping[str, Any],
    expected_audit_output_binding_sha256: str | None = None,
) -> dict[str, Any]:
    """Replay prediction-audit coverage and immutable score/gold bindings."""

    try:
        verified_receipt, score = _verify_enron_gold_audit_score(
            Path(score_run_dir),
            Path(sample_run_dir),
            Path(gold_run_dir),
            Path(catalog_run_dir),
            bank,
            promotion_checks=promotion_checks,
            score_state_dir=Path(score_state_dir),
            gold_state_dir=Path(gold_state_dir),
            expected_gold_commitment=expected_gold_commitment,
            expected_audit_output_binding_sha256=expected_audit_output_binding_sha256,
        )
        _require_trusted_score_receipt(expected_score_receipt, verified_receipt, score)
        if score.get("status") != "scored_pending_prediction_audit":
            raise EnronAuditScoringError("Prediction audit requires a successfully completed score run.")
        reviewer_identities = _load_bound_gold_reviewer_identities(Path(gold_run_dir), score["receipt"])
        reviewer_identities.add(_identifier(score["catalog_reviewer_id"], "catalog_reviewer_id"))
        root = _validate_private_run_tree(Path(run_dir), _AUDIT_RUN_FILES, "Prediction audit")
        reviews, review_descriptor = _load_jsonl(
            root / "reviews.jsonl",
            description="Prediction audit reviews",
            fields=_REVIEW_FIELDS,
            maximum_rows=_MAX_ROWS,
        )
        if reviews != sorted(reviews, key=lambda row: str(row["case_id"])):
            raise EnronAuditScoringError("Prediction audit reviews are not in canonical case order.")
        _validate_prediction_audit_reviews(reviews, score["cases"], reviewer_identities)
        manifest, manifest_raw = _load_json_object(root / "manifest.json", "Prediction audit manifest")
        receipt, receipt_raw = _load_json_object(root / "receipt.json", "Prediction audit receipt")
        if manifest_raw != _canonical_json_file(manifest) or receipt_raw != _canonical_json_file(receipt):
            raise EnronAuditScoringError("Prediction audit metadata is not canonically encoded.")
        review_artifact = {"name": "reviews.jsonl", **review_descriptor}
        expected_manifest = _prediction_audit_manifest(score, review_artifact, reviews)
        if manifest != expected_manifest:
            raise EnronAuditScoringError("Prediction audit manifest differs from deterministic replay.")
        expected_receipt = _prediction_audit_receipt(expected_manifest)
        if receipt != expected_receipt:
            raise EnronAuditScoringError("Prediction audit receipt differs from deterministic replay.")
        return _detached(expected_receipt)
    except EnronAuditScoringError:
        raise
    except (EnronPrivateIOError, OSError, TypeError, ValueError):
        raise EnronAuditScoringError("Prediction audit could not be verified safely.") from None


def _load_prepared_inputs(
    sample_run_dir: Path,
    gold_run_dir: Path,
    catalog_run_dir: Path,
    bank: Mapping[str, Any] | Path,
    *,
    gold_state_dir: Path,
    expected_gold_commitment: Mapping[str, str],
    expected_audit_output_binding_sha256: str | None,
) -> dict[str, Any]:
    if (
        not isinstance(expected_gold_commitment, Mapping)
        or set(expected_gold_commitment) != {"gold_sha256", "manifest_sha256", "artifacts_sha256"}
        or any(not _is_sha256(value) for value in expected_gold_commitment.values())
    ):
        raise EnronAuditScoringError("Trusted expected gold commitment is invalid.")
    trusted_gold_commitment = dict(expected_gold_commitment)
    documents, gold, gold_receipt = _gold._load_verified_enron_gold_annotations_files(
        gold_run_dir,
        sample_run_dir,
        expected_audit_output_binding_sha256=expected_audit_output_binding_sha256,
        expected_gold_commitment=trusted_gold_commitment,
        gold_state_dir=gold_state_dir,
    )
    if any(gold_receipt.get(field) != value for field, value in trusted_gold_commitment.items()):
        raise EnronAuditScoringError("Verified gold run differs from the trusted expected commitment.")
    bindings, catalog_reviewer_id, catalog_receipt = _catalog._load_verified_enron_catalog_qualification_files(
        catalog_run_dir,
        sample_run_dir,
        gold_run_dir,
        bank,
        expected_audit_output_binding_sha256=expected_audit_output_binding_sha256,
        expected_gold_commitment=trusted_gold_commitment,
        gold_state_dir=gold_state_dir,
    )
    canonical_bank, _bank_artifact = _catalog._load_catalog_bank(bank)
    cross_fields = (
        "fixture_mode",
        "promotable",
        "audit_plan_sha256",
        "audit_output_binding_sha256",
        "audit_execution_policy_sha256",
        "sample_artifact_sha256",
        "sample_binding_sha256",
        "gold_sha256",
        "annotation_policy_sha256",
        "catalog_policy_sha256",
        "planned_evaluator_source_sha256",
        "planned_thresholds_sha256",
    )
    if any(catalog_receipt.get(field) != gold_receipt.get(field) for field in cross_fields):
        raise EnronAuditScoringError("Gold and catalog runs do not share one immutable upstream binding.")
    if catalog_receipt.get("bank_sha256") != hash_bank(canonical_bank) or gold_receipt.get(
        "planned_bank_sha256"
    ) != catalog_receipt.get("bank_sha256"):
        raise EnronAuditScoringError("Scoring bank differs from the frozen catalog and audit bank.")
    if catalog_receipt.get("trusted_gold_commitment") != trusted_gold_commitment or catalog_receipt.get(
        "trusted_gold_commitment_sha256"
    ) != _canonical_hash(trusted_gold_commitment):
        raise EnronAuditScoringError("Catalog qualification does not preserve the trusted gold commitment.")
    catalog_reviewer_id = _identifier(catalog_reviewer_id, "catalog_reviewer_id")

    document_map: dict[str, dict[str, Any]] = {}
    for index, value in enumerate(documents):
        if not isinstance(value, Mapping):
            raise EnronAuditScoringError(f"Sample document {index} is invalid.")
        document_id = _identifier(value.get("document_id"), "document_id")
        text = value.get("text")
        text_sha256 = value.get("text_sha256")
        unicode_scalars = value.get("unicode_scalars")
        text_view = value.get("text_view", "subject_current_body")
        if (
            not isinstance(text, str)
            or text_view != "subject_current_body"
            or not _is_sha256(text_sha256)
            or text_sha256 != _hash_bytes(text.encode("utf-8"))
            or type(unicode_scalars) is not int
            or unicode_scalars != len(text)
            or document_id in document_map
        ):
            raise EnronAuditScoringError(f"Sample document {index} has an invalid text binding.")
        document_map[document_id] = {
            "document_id": document_id,
            "text": text,
            "text_sha256": text_sha256,
            "unicode_scalars": unicode_scalars,
        }

    gold_documents = gold.get("documents") if isinstance(gold, Mapping) else None
    if not isinstance(gold_documents, list):
        raise EnronAuditScoringError("Verified gold documents are invalid.")
    bare_gold: dict[tuple[str, str, int, int], dict[str, Any]] = {}
    gold_by_document: dict[str, list[dict[str, Any]]] = {document_id: [] for document_id in document_map}
    seen_gold_documents: set[str] = set()
    for index, value in enumerate(gold_documents):
        if not isinstance(value, Mapping) or set(value) != {
            "document_id",
            "text_sha256",
            "unicode_scalars",
            "spans",
        }:
            raise EnronAuditScoringError(f"Gold document {index} schema is invalid.")
        value_map = dict(value)
        document_id = _identifier(value_map["document_id"], "document_id")
        document = document_map.get(document_id)
        spans = value_map["spans"]
        if (
            document is None
            or document_id in seen_gold_documents
            or value_map["text_sha256"] != document["text_sha256"]
            or value_map["unicode_scalars"] != document["unicode_scalars"]
            or not isinstance(spans, list)
        ):
            raise EnronAuditScoringError(f"Gold document {index} differs from the sample.")
        seen_gold_documents.add(document_id)
        for span_index, span in enumerate(spans):
            if not isinstance(span, Mapping) or set(span) != {"entity_class", "start", "end"}:
                raise EnronAuditScoringError(f"Gold span {span_index} schema is invalid.")
            span_map = dict(span)
            entity_class = span_map["entity_class"]
            start = span_map["start"]
            end = span_map["end"]
            if (
                entity_class not in PERSON_CONTACT_ENTITY_CLASSES
                or type(start) is not int
                or type(end) is not int
                or start < 0
                or end <= start
                or end > len(str(document["text"]))
            ):
                raise EnronAuditScoringError(f"Gold span {span_index} bounds or class are invalid.")
            key = (document_id, str(entity_class), start, end)
            if key in bare_gold:
                raise EnronAuditScoringError("Gold exact-span/class keys must be unique.")
            bare_gold[key] = {
                "document_id": document_id,
                "entity_class": str(entity_class),
                "start": start,
                "end": end,
            }
    if seen_gold_documents != set(document_map):
        raise EnronAuditScoringError("Gold must contain exactly one row for every sampled document.")

    binding_map: dict[tuple[str, str, int, int], Any] = {}
    for index, value in enumerate(bindings):
        if not isinstance(value, Mapping) or set(value) != {
            "document_id",
            "entity_class",
            "start",
            "end",
            "catalog_identity",
        }:
            raise EnronAuditScoringError(f"Catalog binding {index} schema is invalid.")
        key = (str(value["document_id"]), str(value["entity_class"]), value["start"], value["end"])
        if key in binding_map:
            raise EnronAuditScoringError("Catalog bindings must be unique by exact gold key.")
        identity = value["catalog_identity"]
        if identity is not None and (
            not isinstance(identity, Mapping)
            or set(identity) != _CATALOG_IDENTITY_FIELDS
            or identity.get("entity_id") != value["entity_class"]
            or any(not isinstance(identity.get(field), str) for field in _CATALOG_IDENTITY_FIELDS)
        ):
            raise EnronAuditScoringError(f"Catalog binding {index} identity is invalid.")
        binding_map[key] = None if identity is None else dict(identity)
    if set(binding_map) != set(bare_gold):
        raise EnronAuditScoringError("Catalog bindings must form a bijection with the exact gold spans.")
    for key in sorted(bare_gold):
        row = {**bare_gold[key], "catalog_identity": binding_map[key]}
        gold_by_document[key[0]].append(row)

    document_ids = tuple(sorted(document_map))
    return {
        "bank": canonical_bank,
        "documents": document_map,
        "document_ids": document_ids,
        "gold_by_document": gold_by_document,
        "gold": gold,
        "gold_receipt": gold_receipt,
        "catalog_receipt": catalog_receipt,
        "catalog_reviewer_id": catalog_reviewer_id,
    }


def _support_assessment(prepared: Mapping[str, Any]) -> dict[str, Any]:
    document_ids = prepared["document_ids"]
    gold_by_document = prepared["gold_by_document"]
    gold_receipt = prepared["gold_receipt"]
    if not isinstance(document_ids, tuple) or not isinstance(gold_by_document, Mapping):
        raise EnronAuditScoringError("Prepared audit support is invalid.")
    documents = len(document_ids)
    gold_spans = 0
    sensitive_characters = 0
    negative_documents = 0
    by_class: Counter[str] = Counter()
    for document_id in document_ids:
        spans = gold_by_document[document_id]
        gold_spans += len(spans)
        if not spans:
            negative_documents += 1
        intervals = _merge_intervals([(int(span["start"]), int(span["end"])) for span in spans])
        sensitive_characters += sum(end - start for start, end in intervals)
        by_class.update(str(span["entity_class"]) for span in spans)
    receipt_counts = gold_receipt.get("counts")
    if not isinstance(receipt_counts, Mapping) or (
        receipt_counts.get("documents") != documents
        or receipt_counts.get("gold_spans") != gold_spans
        or receipt_counts.get("negative_documents") != negative_documents
        or receipt_counts.get("sensitive_gold_characters") != sensitive_characters
    ):
        raise EnronAuditScoringError("Gold receipt support counts differ from private replay.")
    failures: list[str] = []
    if gold_receipt.get("promotable") is True and documents != MIN_DECISION_GRADE_DOCUMENTS:
        failures.append("production_document_count_mismatch")
    if documents < MIN_DECISION_GRADE_DOCUMENTS:
        failures.append("documents_below_minimum")
    if gold_spans < MIN_DECISION_GRADE_GOLD_SPANS:
        failures.append("gold_spans_below_minimum")
    if negative_documents < MIN_DECISION_GRADE_NEGATIVE_DOCUMENTS:
        failures.append("negative_documents_below_minimum")
    if sensitive_characters < MIN_DECISION_GRADE_SENSITIVE_CHARACTERS:
        failures.append("sensitive_characters_below_minimum")
    for entity_class in PERSON_CONTACT_ENTITY_CLASSES:
        if by_class[entity_class] == 0:
            failures.append(f"{entity_class}_gold_support_missing")
    failures.sort(key=_SUPPORT_FAILURE_ORDER.index)
    counts = {
        "documents": documents,
        "gold_spans": gold_spans,
        "negative_documents": negative_documents,
        "sensitive_gold_characters": sensitive_characters,
        "gold_spans_by_class": {entity_class: by_class[entity_class] for entity_class in PERSON_CONTACT_ENTITY_CLASSES},
    }
    requirements = {
        "production_documents_exact": MIN_DECISION_GRADE_DOCUMENTS,
        "minimum_documents": MIN_DECISION_GRADE_DOCUMENTS,
        "minimum_gold_spans": MIN_DECISION_GRADE_GOLD_SPANS,
        "minimum_negative_documents": MIN_DECISION_GRADE_NEGATIVE_DOCUMENTS,
        "minimum_sensitive_gold_characters": MIN_DECISION_GRADE_SENSITIVE_CHARACTERS,
        "nonzero_classes": list(PERSON_CONTACT_ENTITY_CLASSES),
    }
    core = {"counts": counts, "requirements": requirements, "failure_codes": failures}
    return {**core, "support_assessment_sha256": _canonical_hash(core)}


def _prepare_frozen_decision_inputs(
    prepared: Mapping[str, Any],
    source: Sequence[Mapping[str, Any]] | Mapping[str, Any] | Path,
) -> dict[str, Any]:
    gold_receipt = prepared["gold_receipt"]
    catalog_receipt = prepared["catalog_receipt"]
    planned_evaluator = gold_receipt.get("planned_evaluator_source_sha256")
    planned_thresholds = gold_receipt.get("planned_thresholds_sha256")
    if (
        not _is_sha256(planned_evaluator)
        or catalog_receipt.get("planned_evaluator_source_sha256") != planned_evaluator
        or not _is_sha256(planned_thresholds)
        or catalog_receipt.get("planned_thresholds_sha256") != planned_thresholds
    ):
        raise EnronAuditScoringError("Upstream runs do not propagate the frozen evaluator and threshold commitments.")
    evaluator = _quality.enron_quality_evaluator_identity()
    if evaluator.get("source_sha256") != planned_evaluator:
        raise EnronAuditScoringError("Installed quality evaluator differs from the source frozen in the audit plan.")
    checks = _load_promotion_checks(source)
    try:
        thresholds_sha256 = hash_enron_thresholds(checks)
    except (KeyError, TypeError, ValueError):
        raise EnronAuditScoringError("Frozen promotion checks cannot be hashed as threshold configuration.") from None
    if thresholds_sha256 != planned_thresholds:
        raise EnronAuditScoringError(
            "Promotion checks differ from the threshold configuration frozen in the audit plan."
        )
    gate_configurations = _select_quality_gate_configurations(checks)
    return {
        "evaluator": _detached(evaluator),
        "planned_evaluator_source_sha256": planned_evaluator,
        "thresholds_sha256": thresholds_sha256,
        "quality_gate_configurations": gate_configurations,
        "quality_gate_configuration_sha256": _canonical_hash(gate_configurations),
    }


def _load_promotion_checks(
    source: Sequence[Mapping[str, Any]] | Mapping[str, Any] | Path,
) -> list[dict[str, Any]]:
    value: Any = source
    if isinstance(source, Path):
        raw = _read_regular_file(source, _MAX_JSON_BYTES, "Frozen promotion-check artifact")
        try:
            value = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_pairs,
                parse_constant=_reject_json_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, TypeError, ValueError):
            raise EnronAuditScoringError("Frozen promotion-check artifact is not strict JSON.") from None
    if isinstance(value, Mapping):
        if isinstance(value.get("checks"), list):
            value = value["checks"]
        elif isinstance(value.get("promotion"), Mapping) and isinstance(value["promotion"].get("checks"), list):
            value = value["promotion"]["checks"]
        else:
            raise EnronAuditScoringError("Frozen promotion-check mapping does not contain a checks sequence.")
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise EnronAuditScoringError("Frozen promotion checks must be a sequence, mapping, or JSON file.")
    checks: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_targets: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, Mapping) or set(item) not in {
            _PROMOTION_CHECK_CONFIGURATION_FIELDS,
            _PROMOTION_CHECK_FIELDS,
        }:
            raise EnronAuditScoringError(f"Promotion check {index} schema is invalid.")
        check = dict(item)
        check_id = _identifier(check.get("id"), "promotion check id")
        target = check.get("target")
        threshold = check.get("threshold")
        if (
            check_id in seen_ids
            or not isinstance(target, str)
            or not target.startswith("/")
            or target in seen_targets
            or check.get("category") not in {"quality", "catalog_conformance", "performance", "privacy", "provenance"}
            or check.get("operator") not in {"gte", "lte", "eq"}
            or not _is_json_gate_scalar(threshold)
            or ("actual" in check and not _is_json_gate_scalar(check["actual"]))
            or ("passed" in check and not isinstance(check["passed"], bool))
        ):
            raise EnronAuditScoringError(f"Promotion check {index} identity or values are invalid.")
        seen_ids.add(check_id)
        seen_targets.add(target)
        checks.append(check)
    if not checks:
        raise EnronAuditScoringError("Frozen promotion-check artifact is empty.")
    return checks


def _select_quality_gate_configurations(checks: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    by_target = {str(check["target"]): check for check in checks}
    configurations: list[dict[str, Any]] = []
    for requirement in QUALITY_DECISION_POLICY["requirements"]:
        target = str(requirement["target"])
        check = by_target.get(target)
        if check is None:
            raise EnronAuditScoringError(f"Frozen promotion checks omit required quality gate {requirement['id']}.")
        threshold = check["threshold"]
        operator = requirement["operator"]
        policy_threshold = requirement["policy_threshold"]
        if (
            check.get("id") != requirement["id"]
            or check.get("category") != "quality"
            or check.get("operator") != operator
        ):
            raise EnronAuditScoringError(f"Frozen quality gate {requirement['id']} has mismatched semantics.")
        if operator == "eq":
            strong_enough = type(threshold) is int and threshold == policy_threshold
        elif operator == "gte":
            strong_enough = (
                type(threshold) in {int, float}
                and 0 < float(threshold) <= 1
                and float(threshold) >= float(policy_threshold)
            )
        else:
            strong_enough = (
                type(threshold) in {int, float}
                and 0 <= float(threshold) < 1
                and float(threshold) <= float(policy_threshold)
            )
        if not strong_enough:
            raise EnronAuditScoringError(f"Frozen quality gate {requirement['id']} is weaker than policy.")
        configurations.append(
            {
                "id": check["id"],
                "category": check["category"],
                "target": check["target"],
                "operator": check["operator"],
                "threshold": threshold,
            }
        )
    return configurations


def _is_json_gate_scalar(value: Any) -> bool:
    if value is None or isinstance(value, (str, bool)):
        return True
    if type(value) not in {int, float}:
        return False
    try:
        _canonical_bytes(value)
    except (TypeError, ValueError):
        return False
    return True


def _validate_text_view_descriptor(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _TEXT_VIEW_DESCRIPTOR_FIELDS:
        raise EnronAuditScoringError("Text-view descriptor schema is invalid.")
    if (
        value.get("id") != "subject_current_body"
        or value.get("document_regions") != ["subject", "current_body"]
        or value.get("primary_for_quality") is not True
        or value.get("answer_bearing_fields_included") is not False
        or not _is_sha256(value.get("artifact_sha256"))
        or not _is_sha256(value.get("content_policy_sha256"))
    ):
        raise EnronAuditScoringError("Text-view descriptor does not describe the frozen complete primary view.")
    return _detached(value)


def _slice_specs(text_view_descriptor: Mapping[str, Any], annotation_policy_sha256: str) -> list[dict[str, Any]]:
    specs: list[dict[str, Any]] = []
    definitions = (
        ("person_contact_all_test", PERSON_CONTACT_SCOPE_ID, list(PERSON_CONTACT_ENTITY_CLASSES), True),
        ("contact_all_test", "contact", ["contact"], False),
        ("person_all_test", "person", ["person"], False),
    )
    for slice_id, entity_class, scope, promotion_gate in definitions:
        specs.append(
            {
                "id": slice_id,
                "label_artifact_id": f"enron_gold_{entity_class}",
                "label_strength": "independent",
                "annotation_scope": {
                    "entity_classes": scope,
                    "document_regions": ["subject", "current_body"],
                    "span_policy_sha256": annotation_policy_sha256,
                    "exclusions": [],
                },
                "annotation_completeness": "exhaustive_within_scope",
                "entity_class": entity_class,
                "cohort": "all",
                "split_role": "test",
                "text_view": "subject_current_body",
                "text_view_descriptor": _detached(text_view_descriptor),
                "promotion_gate": promotion_gate,
            }
        )
    return specs


def _quality_policy_sha256() -> str:
    descriptor = _quality._execution_policy_descriptor(
        max_predictions_per_document=_quality.DEFAULT_MAX_QUALITY_PREDICTIONS_PER_DOCUMENT,
        max_predictions_total=_quality.DEFAULT_MAX_QUALITY_PREDICTIONS_TOTAL,
        max_gold_per_document=_quality.DEFAULT_MAX_QUALITY_GOLD_PER_DOCUMENT,
        max_diagnostics=0,
        max_memberships_total=_quality.DEFAULT_MAX_QUALITY_MEMBERSHIPS_TOTAL,
        max_spool_bytes=_quality.DEFAULT_MAX_QUALITY_SPOOL_BYTES,
    )
    return _canonical_hash(descriptor)


def _validate_prediction_order_and_bounds(
    predictions: Sequence[Mapping[str, Any]], documents: Mapping[str, Mapping[str, Any]]
) -> None:
    prepared: list[dict[str, Any]] = []
    for index, value in enumerate(predictions):
        if not isinstance(value, Mapping) or set(value) != _PREDICTION_FIELDS:
            raise EnronAuditScoringError(f"Prediction {index} schema is invalid.")
        document_id = _identifier(value["document_id"], "document_id")
        document = documents.get(document_id)
        entity_class = _identifier(value["entity_class"], "entity_class")
        entity_id = _identifier(value["entity_id"], "entity_id")
        name_id = _identifier(value["name_id"], "name_id")
        pattern_id = _identifier(value["pattern_id"], "pattern_id")
        start = value["start"]
        end = value["end"]
        if (
            document is None
            or entity_class != entity_id
            or type(start) is not int
            or type(end) is not int
            or start < 0
            or end <= start
            or end > len(str(document["text"]))
        ):
            raise EnronAuditScoringError(f"Prediction {index} bounds, class, or document are invalid.")
        prepared.append(
            {
                "document_id": document_id,
                "entity_class": entity_class,
                "start": start,
                "end": end,
                "entity_id": entity_id,
                "name_id": name_id,
                "pattern_id": pattern_id,
            }
        )
    expected = sorted(
        prepared,
        key=lambda row: (
            row["document_id"],
            row["entity_class"],
            row["start"],
            row["end"],
            row["entity_id"],
            row["name_id"],
            row["pattern_id"],
        ),
    )
    if prepared != expected:
        raise EnronAuditScoringError("Predictions are not in exact consume-then-deterministic-scan order.")


def _verify_quality_result(
    prepared: Mapping[str, Any],
    text_view_descriptor: Mapping[str, Any],
    slice_specs: Sequence[Mapping[str, Any]],
    predictions: Sequence[Mapping[str, Any]],
    result: Mapping[str, Any],
    frozen: Mapping[str, Any],
) -> None:
    if not isinstance(result, Mapping) or set(result) != _QUALITY_RESULT_FIELDS:
        raise EnronAuditScoringError("Quality result schema is invalid.")
    evaluator = _quality.enron_quality_evaluator_identity()
    if evaluator != frozen.get("evaluator") or evaluator.get("source_sha256") != frozen.get(
        "planned_evaluator_source_sha256"
    ):
        raise EnronAuditScoringError("Quality evaluator no longer matches the frozen source commitment.")
    policy_sha256 = _quality_policy_sha256()
    specs = _quality._prepare_slices(slice_specs)
    normalized_descriptor = dict(text_view_descriptor)
    normalized_descriptor["document_regions"] = sorted(normalized_descriptor["document_regions"])
    if [spec.text_view_descriptor for spec in specs] != [normalized_descriptor] * len(specs):
        raise EnronAuditScoringError("Quality slices do not preserve the frozen text-view descriptor.")
    expected_protocol = _quality_protocol_sha256(prepared, evaluator, policy_sha256, specs)
    expected_catalog_binding = _quality_catalog_binding_sha256(prepared)
    expected_prediction_commitment = _quality.hash_enron_quality_predictions(predictions)
    expected_quality = _replay_quality(prepared, specs, predictions)
    raw_validation = validate_enron_quality_output(expected_quality)
    contract_validation = {
        "valid": raw_validation["valid"],
        "diagnostic_codes": sorted({str(item["code"]) for item in raw_validation["diagnostics"]}),
    }
    bank_value = result.get("bank")
    engine_sha256 = bank_value.get("engine_sha256") if isinstance(bank_value, Mapping) else None
    if (
        result.get("schema_version") != _quality.QUALITY_EXECUTION_SCHEMA_VERSION
        or result.get("evaluator") != evaluator
        or result.get("evaluator_sha256") != _canonical_hash(evaluator)
        or result.get("policy_sha256") != policy_sha256
        or result.get("protocol_sha256") != expected_protocol
        or result.get("catalog_binding_sha256") != expected_catalog_binding
        or result.get("prediction_commitment") != expected_prediction_commitment
        or not isinstance(bank_value, Mapping)
        or set(bank_value) != {"canonical_sha256", "engine_sha256"}
        or bank_value.get("canonical_sha256") != hash_bank(prepared["bank"])
        or not _is_sha256(engine_sha256)
        or result.get("evaluated") is not True
        or result.get("quality") != expected_quality
        or result.get("contract_validation") != contract_validation
        or result.get("unsupported_slices") != []
        or contract_validation["valid"] is not True
    ):
        raise EnronAuditScoringError("Quality result differs from scan-free deterministic replay.")
    expected_run_sha256 = _canonical_hash(
        {
            "protocol_sha256": expected_protocol,
            "catalog_binding_sha256": expected_catalog_binding,
            "canonical_bank_sha256": hash_bank(prepared["bank"]),
            "engine_bank_sha256": engine_sha256,
            "prediction_commitment": expected_prediction_commitment,
            "quality": expected_quality,
            "contract_validation": contract_validation,
            "unsupported_slices": [],
        }
    )
    if result.get("run_sha256") != expected_run_sha256:
        raise EnronAuditScoringError("Quality run commitment differs from deterministic replay.")


def _quality_protocol_sha256(
    prepared: Mapping[str, Any],
    evaluator: Mapping[str, Any],
    policy_sha256: str,
    specs: Sequence[Any],
) -> str:
    document_ids = list(prepared["document_ids"])
    documents = prepared["documents"]
    gold_by_document = prepared["gold_by_document"]
    return _canonical_hash(
        {
            "documents": [
                {
                    "document_id": document_id,
                    "text_sha256": documents[document_id]["text_sha256"],
                    "unicode_scalars": documents[document_id]["unicode_scalars"],
                    "text_view": "subject_current_body",
                    "split_role": "test",
                }
                for document_id in document_ids
            ],
            "evaluator": dict(evaluator),
            "gold_spans": [
                {
                    "document_id": span["document_id"],
                    "entity_class": span["entity_class"],
                    "start": span["start"],
                    "end": span["end"],
                }
                for document_id in document_ids
                for span in sorted(
                    gold_by_document[document_id],
                    key=lambda row: (row["entity_class"], row["start"], row["end"]),
                )
            ],
            "policy_sha256": policy_sha256,
            "slice_specs": [spec.fingerprint_payload(document_ids) for spec in specs],
            "unsupported_slice_specs": [],
        }
    )


def _quality_catalog_binding_sha256(prepared: Mapping[str, Any]) -> str:
    document_ids = prepared["document_ids"]
    gold_by_document = prepared["gold_by_document"]
    return _canonical_hash(
        {
            "bank_sha256": hash_bank(prepared["bank"]),
            "bindings": [
                _detached(span)
                for document_id in document_ids
                for span in sorted(
                    gold_by_document[document_id],
                    key=lambda row: (row["entity_class"], row["start"], row["end"]),
                )
            ],
            "schema_version": "nerb.enron-catalog-binding.v2",
        }
    )


def _replay_quality(
    prepared: Mapping[str, Any], specs: Sequence[Any], predictions: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    predictions_by_document: dict[str, list[Any]] = defaultdict(list)
    for row in predictions:
        predictions_by_document[str(row["document_id"])].append(
            _quality._Prediction(
                str(row["document_id"]),
                str(row["entity_class"]),
                int(row["start"]),
                int(row["end"]),
                str(row["entity_id"]),
                str(row["name_id"]),
                str(row["pattern_id"]),
            )
        )
    accumulators = {spec.id: _quality._SliceAccumulator() for spec in specs}
    for document_id in prepared["document_ids"]:
        source = prepared["documents"][document_id]
        document = _quality._Document(document_id, str(source["text"]), "subject_current_body", "test")
        gold = tuple(
            _quality._GoldSpan(
                document_id,
                str(row["entity_class"]),
                int(row["start"]),
                int(row["end"]),
                (
                    None
                    if row["catalog_identity"] is None
                    else (
                        str(row["catalog_identity"]["entity_id"]),
                        str(row["catalog_identity"]["name_id"]),
                        str(row["catalog_identity"]["pattern_id"]),
                    )
                ),
            )
            for row in prepared["gold_by_document"][document_id]
        )
        document_predictions = tuple(predictions_by_document[document_id])
        for spec in specs:
            _quality._accumulate_slice_document(accumulators[spec.id], spec, document, gold, document_predictions)
    slices = [_quality._finish_slice(spec, accumulators[spec.id]) for spec in specs]
    return {
        "evaluated": True,
        "matching_semantics": MATCHING_SEMANTICS,
        "character_position_semantics": CHARACTER_POSITION_SEMANTICS,
        "slices": slices,
    }


def _build_cases(
    prepared: Mapping[str, Any],
    predictions: Sequence[Mapping[str, Any]],
    prediction_commitment: Mapping[str, Any],
) -> list[dict[str, Any]]:
    scoped_predictions: dict[str, list[tuple[int, Mapping[str, Any]]]] = defaultdict(list)
    for index, prediction in enumerate(predictions):
        if prediction["entity_class"] in PERSON_CONTACT_ENTITY_CLASSES:
            scoped_predictions[str(prediction["document_id"])].append((index, prediction))
    cases: list[dict[str, Any]] = []
    selected_pairs: list[tuple[Mapping[str, Any], int, Mapping[str, Any]]] = []
    for document_id in prepared["document_ids"]:
        gold = list(prepared["gold_by_document"][document_id])
        indexed_predictions = scoped_predictions[document_id]
        indices_by_key: dict[tuple[str, str, int, int], list[tuple[int, Mapping[str, Any]]]] = defaultdict(list)
        for index, prediction in indexed_predictions:
            indices_by_key[_prediction_key(prediction)].append((index, prediction))
        selected_indices: set[int] = set()
        selected_gold: set[tuple[str, str, int, int]] = set()
        for gold_span in gold:
            key = _gold_key(gold_span)
            candidates = indices_by_key.get(key, [])
            if not candidates:
                continue
            selected_index, selected_prediction = candidates[0]
            identity = gold_span["catalog_identity"]
            if identity is not None:
                selected_index, selected_prediction = next(
                    (
                        candidate
                        for candidate in candidates
                        if candidate[1]["entity_id"] == identity["entity_id"]
                        and candidate[1]["name_id"] == identity["name_id"]
                    ),
                    (selected_index, selected_prediction),
                )
            selected_indices.add(selected_index)
            selected_gold.add(key)
            selected_pairs.append((gold_span, selected_index, selected_prediction))

        unmatched_gold = [span for span in gold if _gold_key(span) not in selected_gold]
        unmatched_predictions = [item for item in indexed_predictions if item[0] not in selected_indices]
        for gold_span in unmatched_gold:
            reasons = {"false_negative"}
            if any(
                _overlaps(gold_span, prediction) and _gold_key(gold_span) != _prediction_key(prediction)
                for _index, prediction in unmatched_predictions
            ):
                reasons.add("boundary_or_class_mismatch")
            cases.append(_case_seed(document_id, reasons, gold_span, None, None))
        for prediction_index, prediction in unmatched_predictions:
            reasons = {"false_positive"}
            if any(
                _overlaps(gold_span, prediction) and _gold_key(gold_span) != _prediction_key(prediction)
                for gold_span in unmatched_gold
            ):
                reasons.add("boundary_or_class_mismatch")
            cases.append(_case_seed(document_id, reasons, None, prediction, prediction_index))

    pair_cases: dict[tuple[tuple[str, str, int, int], int], dict[str, Any]] = {}
    for gold_span, prediction_index, prediction in selected_pairs:
        identity = gold_span["catalog_identity"]
        if identity is not None and (
            prediction["entity_id"] != identity["entity_id"] or prediction["name_id"] != identity["name_id"]
        ):
            pair_key = (_gold_key(gold_span), prediction_index)
            pair_cases[pair_key] = _case_seed(
                str(gold_span["document_id"]),
                {"wrong_canonical"},
                gold_span,
                prediction,
                prediction_index,
            )

    binding = _case_binding(prepared, prediction_commitment)
    ranked_pairs = sorted(
        (
            _selection_rank("true_positive", binding, _pair_rank_payload(gold_span, prediction_index, prediction)),
            gold_span,
            prediction_index,
            prediction,
        )
        for gold_span, prediction_index, prediction in selected_pairs
    )
    for rank, gold_span, prediction_index, prediction in ranked_pairs[: min(20, len(ranked_pairs))]:
        pair_key = (_gold_key(gold_span), prediction_index)
        seed = pair_cases.setdefault(
            pair_key,
            _case_seed(str(gold_span["document_id"]), set(), gold_span, prediction, prediction_index),
        )
        seed["reasons"].add("true_positive_sample")
        seed["selection_rank_sha256"] = rank
    cases.extend(pair_cases.values())

    negative_documents = [
        document_id for document_id in prepared["document_ids"] if not prepared["gold_by_document"][document_id]
    ]
    ranked_negatives = sorted(
        (_selection_rank("certified_negative", binding, {"document_id": document_id}), document_id)
        for document_id in negative_documents
    )
    for rank, document_id in ranked_negatives[: min(20, len(ranked_negatives))]:
        cases.append(
            _case_seed(
                document_id,
                {"certified_negative_document"},
                None,
                None,
                None,
                selection_rank_sha256=rank,
            )
        )

    finalized = [_finalize_case(seed, binding) for seed in cases]
    finalized.sort(key=_case_sort_key)
    _validate_case_rows(finalized)
    return finalized


def _case_binding(prepared: Mapping[str, Any], prediction_commitment: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "audit_plan_sha256": prepared["gold_receipt"]["audit_plan_sha256"],
        "gold_sha256": prepared["gold_receipt"]["gold_sha256"],
        "catalog_binding_sha256": prepared["catalog_receipt"]["catalog_binding_sha256"],
        "prediction_commitment": dict(prediction_commitment),
    }


def _case_seed(
    document_id: str,
    reasons: set[str],
    gold_span: Mapping[str, Any] | None,
    prediction: Mapping[str, Any] | None,
    prediction_index: int | None,
    *,
    selection_rank_sha256: str | None = None,
) -> dict[str, Any]:
    gold_payload = None
    if gold_span is not None:
        gold_payload = {
            "entity_class": gold_span["entity_class"],
            "start": gold_span["start"],
            "end": gold_span["end"],
            "catalog_identity": _detached_or_none(gold_span["catalog_identity"]),
        }
    prediction_payload = None
    if prediction is not None:
        assert prediction_index is not None
        prediction_payload = {
            "stream_index": prediction_index,
            "entity_class": prediction["entity_class"],
            "start": prediction["start"],
            "end": prediction["end"],
            "entity_id": prediction["entity_id"],
            "name_id": prediction["name_id"],
            "pattern_id": prediction["pattern_id"],
        }
    return {
        "document_id": document_id,
        "reasons": reasons,
        "gold": gold_payload,
        "prediction": prediction_payload,
        "selection_rank_sha256": selection_rank_sha256,
    }


def _finalize_case(seed: Mapping[str, Any], binding: Mapping[str, Any]) -> dict[str, Any]:
    reasons = sorted(seed["reasons"], key=_CASE_REASON_ORDER.index)
    core = {
        "schema_version": CASE_SCHEMA_VERSION,
        "document_id": seed["document_id"],
        "reasons": reasons,
        "gold": seed["gold"],
        "prediction": seed["prediction"],
        "selection_rank_sha256": seed["selection_rank_sha256"],
    }
    case_id = _canonical_hash({"domain": "nerb/enron/prediction-audit/case-id/v1", "binding": binding, "case": core})
    return {
        "schema_version": CASE_SCHEMA_VERSION,
        "case_id": case_id,
        **{key: core[key] for key in core if key != "schema_version"},
    }


def _selection_rank(domain: str, binding: Mapping[str, Any], item: Mapping[str, Any]) -> str:
    return _canonical_hash(
        {"domain": f"nerb/enron/prediction-audit/{domain}-rank/v1", "binding": binding, "item": item}
    )


def _pair_rank_payload(
    gold_span: Mapping[str, Any], prediction_index: int, prediction: Mapping[str, Any]
) -> dict[str, Any]:
    return {
        "document_id": gold_span["document_id"],
        "gold": {
            "entity_class": gold_span["entity_class"],
            "start": gold_span["start"],
            "end": gold_span["end"],
            "catalog_identity": gold_span["catalog_identity"],
        },
        "prediction": {"stream_index": prediction_index, **dict(prediction)},
    }


def _gold_key(value: Mapping[str, Any]) -> tuple[str, str, int, int]:
    return str(value["document_id"]), str(value["entity_class"]), int(value["start"]), int(value["end"])


def _prediction_key(value: Mapping[str, Any]) -> tuple[str, str, int, int]:
    return str(value["document_id"]), str(value["entity_class"]), int(value["start"]), int(value["end"])


def _overlaps(first: Mapping[str, Any], second: Mapping[str, Any]) -> bool:
    return max(int(first["start"]), int(second["start"])) < min(int(first["end"]), int(second["end"]))


def _case_sort_key(value: Mapping[str, Any]) -> tuple[Any, ...]:
    gold = value["gold"]
    prediction = value["prediction"]
    return (
        value["document_id"],
        tuple(_CASE_REASON_ORDER.index(reason) for reason in value["reasons"]),
        -1 if gold is None else gold["start"],
        -1 if gold is None else gold["end"],
        "" if gold is None else gold["entity_class"],
        -1 if prediction is None else prediction["stream_index"],
        value["case_id"],
    )


def _validate_case_rows(rows: Sequence[Mapping[str, Any]]) -> None:
    case_ids: set[str] = set()
    for index, value in enumerate(rows):
        if not isinstance(value, Mapping) or set(value) != _CASE_FIELDS:
            raise EnronAuditScoringError(f"Prediction-audit case {index} schema is invalid.")
        case_id = value["case_id"]
        document_id = value["document_id"]
        reasons = value["reasons"]
        gold = value["gold"]
        prediction = value["prediction"]
        rank = value["selection_rank_sha256"]
        if (
            value["schema_version"] != CASE_SCHEMA_VERSION
            or not _is_sha256(case_id)
            or case_id in case_ids
            or not isinstance(document_id, str)
            or _IDENTIFIER_RE.fullmatch(document_id) is None
            or not isinstance(reasons, list)
            or not reasons
            or len(reasons) != len(set(reasons))
            or any(reason not in _CASE_REASONS for reason in reasons)
            or reasons != sorted(reasons, key=_CASE_REASON_ORDER.index)
            or (rank is not None and not _is_sha256(rank))
        ):
            raise EnronAuditScoringError(f"Prediction-audit case {index} identity or reasons are invalid.")
        case_ids.add(str(case_id))
        if gold is not None:
            if not isinstance(gold, Mapping) or set(gold) != _CASE_GOLD_FIELDS:
                raise EnronAuditScoringError(f"Prediction-audit case {index} gold schema is invalid.")
            _validate_case_span(gold, index, catalog=True)
        if prediction is not None:
            if not isinstance(prediction, Mapping) or set(prediction) != _CASE_PREDICTION_FIELDS:
                raise EnronAuditScoringError(f"Prediction-audit case {index} prediction schema is invalid.")
            _validate_case_span(prediction, index, catalog=False)
            if type(prediction["stream_index"]) is not int or prediction["stream_index"] < 0:
                raise EnronAuditScoringError(f"Prediction-audit case {index} stream index is invalid.")
        reason_set = set(reasons)
        if (
            ("false_negative" in reason_set and (gold is None or prediction is not None))
            or ("false_positive" in reason_set and (gold is not None or prediction is None))
            or (reason_set & {"wrong_canonical", "true_positive_sample"} and (gold is None or prediction is None))
            or ("certified_negative_document" in reason_set and (gold is not None or prediction is not None))
            or ("boundary_or_class_mismatch" in reason_set and not reason_set & {"false_negative", "false_positive"})
            or (rank is None and reason_set & {"true_positive_sample", "certified_negative_document"})
            or (rank is not None and not reason_set & {"true_positive_sample", "certified_negative_document"})
        ):
            raise EnronAuditScoringError(f"Prediction-audit case {index} payload conflicts with its reasons.")
    if list(rows) != sorted(rows, key=_case_sort_key):
        raise EnronAuditScoringError("Prediction-audit cases are not in canonical deterministic order.")


def _validate_case_span(value: Mapping[str, Any], index: int, *, catalog: bool) -> None:
    entity_class = value["entity_class"]
    start = value["start"]
    end = value["end"]
    if (
        entity_class not in PERSON_CONTACT_ENTITY_CLASSES
        or type(start) is not int
        or type(end) is not int
        or start < 0
        or end <= start
    ):
        raise EnronAuditScoringError(f"Prediction-audit case {index} span is invalid.")
    if catalog:
        identity = value["catalog_identity"]
        if identity is not None and (
            not isinstance(identity, Mapping)
            or set(identity) != _CATALOG_IDENTITY_FIELDS
            or identity.get("entity_id") != entity_class
            or any(not isinstance(identity.get(field), str) for field in _CATALOG_IDENTITY_FIELDS)
        ):
            raise EnronAuditScoringError(f"Prediction-audit case {index} catalog identity is invalid.")
    elif value["entity_id"] != entity_class or any(
        not isinstance(value[field], str) or _IDENTIFIER_RE.fullmatch(value[field]) is None
        for field in ("entity_id", "name_id", "pattern_id")
    ):
        raise EnronAuditScoringError(f"Prediction-audit case {index} prediction identity is invalid.")


def _insufficient_support_manifest(
    prepared: Mapping[str, Any],
    text_view_descriptor: Mapping[str, Any],
    frozen: Mapping[str, Any],
    claim: Mapping[str, Any],
    support: Mapping[str, Any],
) -> dict[str, Any]:
    gold_receipt = prepared["gold_receipt"]
    catalog_receipt = prepared["catalog_receipt"]
    return {
        "schema_version": INSUFFICIENT_SUPPORT_MANIFEST_SCHEMA_VERSION,
        "status": "insufficient_support",
        "decision_eligible": False,
        "release": "do_not_ship",
        "scoring_policy_sha256": AUDIT_SCORING_POLICY_SHA256,
        "prediction_audit_policy_sha256": PREDICTION_AUDIT_POLICY_SHA256,
        "fixture_mode": gold_receipt["fixture_mode"],
        "promotable": gold_receipt["promotable"],
        "audit_plan_sha256": gold_receipt["audit_plan_sha256"],
        "audit_output_binding_sha256": gold_receipt["audit_output_binding_sha256"],
        "audit_execution_policy_sha256": gold_receipt["audit_execution_policy_sha256"],
        "sample_artifact_sha256": gold_receipt["sample_artifact_sha256"],
        "sample_binding_sha256": gold_receipt["sample_binding_sha256"],
        "annotation_policy_sha256": gold_receipt["annotation_policy_sha256"],
        "catalog_policy_sha256": catalog_receipt["catalog_policy_sha256"],
        "gold_sha256": gold_receipt["gold_sha256"],
        "gold_manifest_sha256": gold_receipt["manifest_sha256"],
        "gold_artifacts_sha256": gold_receipt["artifacts_sha256"],
        "bank_sha256": catalog_receipt["bank_sha256"],
        "catalog_binding_sha256": catalog_receipt["catalog_binding_sha256"],
        "catalog_binding_artifact_sha256": catalog_receipt["binding_artifact_sha256"],
        "trusted_gold_commitment_sha256": catalog_receipt["trusted_gold_commitment_sha256"],
        "text_view_descriptor": _detached(text_view_descriptor),
        "planned_evaluator_source_sha256": frozen["planned_evaluator_source_sha256"],
        "thresholds_sha256": frozen["thresholds_sha256"],
        "quality_gate_configuration_sha256": frozen["quality_gate_configuration_sha256"],
        "score_attempt_binding_sha256": claim["score_attempt_binding_sha256"],
        "score_claim_sha256": claim["score_claim_sha256"],
        "support": _detached(support),
        "artifacts": {},
    }


def _insufficient_support_receipt(manifest: Mapping[str, Any]) -> dict[str, Any]:
    support = manifest["support"]
    if not isinstance(support, Mapping):
        raise EnronAuditScoringError("Insufficient-support manifest aggregates are invalid.")
    return {
        "schema_version": INSUFFICIENT_SUPPORT_RECEIPT_SCHEMA_VERSION,
        "valid": True,
        "status": "insufficient_support",
        "decision_eligible": False,
        "release": "do_not_ship",
        "fixture_mode": manifest["fixture_mode"],
        "promotable": manifest["promotable"],
        "audit_plan_sha256": manifest["audit_plan_sha256"],
        "audit_output_binding_sha256": manifest["audit_output_binding_sha256"],
        "audit_execution_policy_sha256": manifest["audit_execution_policy_sha256"],
        "scoring_policy_sha256": manifest["scoring_policy_sha256"],
        "prediction_audit_policy_sha256": manifest["prediction_audit_policy_sha256"],
        "sample_artifact_sha256": manifest["sample_artifact_sha256"],
        "sample_binding_sha256": manifest["sample_binding_sha256"],
        "gold_sha256": manifest["gold_sha256"],
        "gold_manifest_sha256": manifest["gold_manifest_sha256"],
        "gold_artifacts_sha256": manifest["gold_artifacts_sha256"],
        "bank_sha256": manifest["bank_sha256"],
        "catalog_binding_sha256": manifest["catalog_binding_sha256"],
        "catalog_binding_artifact_sha256": manifest["catalog_binding_artifact_sha256"],
        "trusted_gold_commitment_sha256": manifest["trusted_gold_commitment_sha256"],
        "planned_evaluator_source_sha256": manifest["planned_evaluator_source_sha256"],
        "evaluator_source_sha256": manifest["planned_evaluator_source_sha256"],
        "thresholds_sha256": manifest["thresholds_sha256"],
        "quality_gate_configuration_sha256": manifest["quality_gate_configuration_sha256"],
        "score_attempt_binding_sha256": manifest["score_attempt_binding_sha256"],
        "score_claim_sha256": manifest["score_claim_sha256"],
        "prediction_commitment": None,
        "prediction_commitment_sha256": None,
        "quality_decision": None,
        "quality_decision_sha256": None,
        "quality_decision_passed": False,
        "support_failure_codes": list(support["failure_codes"]),
        "manifest_sha256": _canonical_hash(manifest),
        "artifacts_sha256": _canonical_hash({}),
        "counts": _detached(support["counts"]),
        "privacy": {
            "aggregate_only": True,
            "raw_text_included": False,
            "document_ids_included": False,
            "reviewer_ids_included": False,
            "span_coordinates_included": False,
            "span_surfaces_included": False,
            "catalog_identities_included": False,
            "private_paths_included": False,
        },
    }


def _score_manifest(
    prepared: Mapping[str, Any],
    text_view_descriptor: Mapping[str, Any],
    slice_specs: Sequence[Mapping[str, Any]],
    quality_result: Mapping[str, Any],
    artifacts: Mapping[str, Mapping[str, Any]],
    cases: Sequence[Mapping[str, Any]],
    frozen: Mapping[str, Any],
    claim: Mapping[str, Any],
) -> dict[str, Any]:
    gold_receipt = prepared["gold_receipt"]
    catalog_receipt = prepared["catalog_receipt"]
    case_counts = {reason: sum(reason in case["reasons"] for case in cases) for reason in _CASE_REASON_ORDER}
    quality_decision = _quality_decision(
        quality_result,
        frozen["quality_gate_configurations"],
        str(frozen["thresholds_sha256"]),
    )
    return {
        "schema_version": SCORE_MANIFEST_SCHEMA_VERSION,
        "scoring_policy_sha256": AUDIT_SCORING_POLICY_SHA256,
        "prediction_audit_policy_sha256": PREDICTION_AUDIT_POLICY_SHA256,
        "fixture_mode": gold_receipt["fixture_mode"],
        "promotable": gold_receipt["promotable"],
        "audit_plan_sha256": gold_receipt["audit_plan_sha256"],
        "audit_output_binding_sha256": gold_receipt["audit_output_binding_sha256"],
        "audit_execution_policy_sha256": gold_receipt["audit_execution_policy_sha256"],
        "sample_artifact_sha256": gold_receipt["sample_artifact_sha256"],
        "sample_binding_sha256": gold_receipt["sample_binding_sha256"],
        "annotation_policy_sha256": gold_receipt["annotation_policy_sha256"],
        "catalog_policy_sha256": catalog_receipt["catalog_policy_sha256"],
        "gold_sha256": gold_receipt["gold_sha256"],
        "gold_manifest_sha256": gold_receipt["manifest_sha256"],
        "gold_artifacts_sha256": gold_receipt["artifacts_sha256"],
        "bank_sha256": catalog_receipt["bank_sha256"],
        "catalog_binding_sha256": catalog_receipt["catalog_binding_sha256"],
        "catalog_binding_artifact_sha256": catalog_receipt["binding_artifact_sha256"],
        "trusted_gold_commitment_sha256": catalog_receipt["trusted_gold_commitment_sha256"],
        "text_view_descriptor": _detached(text_view_descriptor),
        "slice_specs_sha256": _canonical_hash(list(slice_specs)),
        "planned_evaluator_source_sha256": frozen["planned_evaluator_source_sha256"],
        "thresholds_sha256": frozen["thresholds_sha256"],
        "quality_gate_configuration_sha256": frozen["quality_gate_configuration_sha256"],
        "quality_evaluator_sha256": quality_result["evaluator_sha256"],
        "quality_policy_sha256": quality_result["policy_sha256"],
        "quality_protocol_sha256": quality_result["protocol_sha256"],
        "quality_catalog_binding_sha256": quality_result["catalog_binding_sha256"],
        "prediction_commitment": _detached(quality_result["prediction_commitment"]),
        "quality_run_sha256": quality_result["run_sha256"],
        "quality_decision": quality_decision,
        "score_attempt_binding_sha256": claim["score_attempt_binding_sha256"],
        "score_claim_sha256": claim["score_claim_sha256"],
        "support": _detached(gold_receipt["counts"]),
        "case_counts": case_counts,
        "artifacts": {key: _detached(artifacts[key]) for key in sorted(artifacts)},
    }


def _score_receipt(manifest: Mapping[str, Any], quality_result: Mapping[str, Any]) -> dict[str, Any]:
    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, Mapping):
        raise EnronAuditScoringError("Score manifest artifacts are invalid.")
    return {
        "schema_version": SCORE_RECEIPT_SCHEMA_VERSION,
        "valid": True,
        "status": "scored_pending_prediction_audit",
        "decision_eligible": False,
        "release": "pending_prediction_audit",
        "fixture_mode": manifest["fixture_mode"],
        "promotable": manifest["promotable"],
        "audit_plan_sha256": manifest["audit_plan_sha256"],
        "audit_output_binding_sha256": manifest["audit_output_binding_sha256"],
        "audit_execution_policy_sha256": manifest["audit_execution_policy_sha256"],
        "scoring_policy_sha256": manifest["scoring_policy_sha256"],
        "prediction_audit_policy_sha256": manifest["prediction_audit_policy_sha256"],
        "sample_artifact_sha256": manifest["sample_artifact_sha256"],
        "sample_binding_sha256": manifest["sample_binding_sha256"],
        "gold_sha256": manifest["gold_sha256"],
        "gold_manifest_sha256": manifest["gold_manifest_sha256"],
        "gold_artifacts_sha256": manifest["gold_artifacts_sha256"],
        "bank_sha256": manifest["bank_sha256"],
        "catalog_binding_sha256": manifest["catalog_binding_sha256"],
        "catalog_binding_artifact_sha256": manifest["catalog_binding_artifact_sha256"],
        "trusted_gold_commitment_sha256": manifest["trusted_gold_commitment_sha256"],
        "planned_evaluator_source_sha256": manifest["planned_evaluator_source_sha256"],
        "evaluator_source_sha256": manifest["planned_evaluator_source_sha256"],
        "thresholds_sha256": manifest["thresholds_sha256"],
        "quality_gate_configuration_sha256": manifest["quality_gate_configuration_sha256"],
        "prediction_commitment": _detached(manifest["prediction_commitment"]),
        "prediction_commitment_sha256": manifest["prediction_commitment"]["sha256"],
        "quality_run_sha256": manifest["quality_run_sha256"],
        "quality_decision": _detached(manifest["quality_decision"]),
        "quality_decision_sha256": manifest["quality_decision"]["quality_decision_sha256"],
        "quality_decision_passed": manifest["quality_decision"]["passed"],
        "support_failure_codes": [],
        "score_attempt_binding_sha256": manifest["score_attempt_binding_sha256"],
        "score_claim_sha256": manifest["score_claim_sha256"],
        "manifest_sha256": _canonical_hash(manifest),
        "artifacts_sha256": _canonical_hash(artifacts),
        "prediction_artifact_sha256": artifacts["predictions"]["sha256"],
        "case_artifact_sha256": artifacts["cases"]["sha256"],
        "quality_artifact_sha256": artifacts["quality"]["sha256"],
        "counts": {
            "documents": manifest["support"]["documents"],
            "gold_spans": manifest["support"]["gold_spans"],
            "predictions": manifest["prediction_commitment"]["count"],
            "cases": artifacts["cases"]["records"],
            "case_reasons": _detached(manifest["case_counts"]),
        },
        "quality": _detached(quality_result["quality"]),
        "contract_validation": _detached(quality_result["contract_validation"]),
        "privacy": {
            "aggregate_only": True,
            "raw_text_included": False,
            "document_ids_included": False,
            "reviewer_ids_included": False,
            "span_coordinates_included": False,
            "span_surfaces_included": False,
            "catalog_identities_included": False,
            "private_paths_included": False,
        },
    }


def _quality_decision(
    quality_result: Mapping[str, Any],
    gate_configurations: Sequence[Mapping[str, Any]],
    thresholds_sha256: str,
) -> dict[str, Any]:
    quality = quality_result.get("quality")
    contract_validation = quality_result.get("contract_validation")
    slices = quality.get("slices") if isinstance(quality, Mapping) else None
    if not isinstance(slices, list) or not isinstance(contract_validation, Mapping):
        raise EnronAuditScoringError("Quality result cannot produce a frozen quality decision.")
    combined = [
        item
        for item in slices
        if isinstance(item, Mapping)
        and item.get("id") == "person_contact_all_test"
        and item.get("entity_class") == PERSON_CONTACT_SCOPE_ID
        and item.get("promotion_gate") is True
    ]
    if len(combined) != 1 or not isinstance(combined[0].get("metrics"), Mapping):
        raise EnronAuditScoringError("Quality result must contain exactly one combined promotion slice.")
    item = combined[0]
    metrics = item["metrics"]
    actuals = {
        "contract_valid": contract_validation.get("valid"),
        "cataloged_false_negative": item.get("cataloged_false_negative"),
        "cataloged_wrong_canonical": item.get("cataloged_wrong_canonical"),
        "documents_with_any_cataloged_miss": item.get("documents_with_any_cataloged_miss"),
        "open_world_recall": metrics.get("open_world_recall"),
        "catalog_coverage": metrics.get("catalog_coverage"),
        "cataloged_recall": metrics.get("cataloged_recall"),
        "sensitive_character_recall": metrics.get("sensitive_character_recall"),
        "document_leak_rate": metrics.get("document_leak_rate"),
        "sensitive_character_leak_rate": metrics.get("sensitive_character_leak_rate"),
        "negative_document_false_alarm_rate": metrics.get("negative_document_false_alarm_rate"),
        "over_redaction_rate": metrics.get("over_redaction_rate"),
    }
    contract_gate = QUALITY_DECISION_POLICY["contract_gate"]
    gates: list[dict[str, Any]] = [
        {
            "id": contract_gate["id"],
            "operator": contract_gate["operator"],
            "threshold": contract_gate["threshold"],
            "actual": actuals["contract_valid"],
            "passed": actuals["contract_valid"] is True,
        }
    ]
    if len(gate_configurations) != len(QUALITY_DECISION_POLICY["requirements"]):
        raise EnronAuditScoringError("Frozen quality gate configuration is incomplete.")
    for requirement, configuration in zip(QUALITY_DECISION_POLICY["requirements"], gate_configurations, strict=True):
        gate_id = requirement["id"]
        if (
            configuration.get("id") != gate_id
            or configuration.get("target") != requirement["target"]
            or configuration.get("operator") != requirement["operator"]
        ):
            raise EnronAuditScoringError("Frozen quality gate configuration differs from the scoring policy.")
        operator = configuration["operator"]
        threshold = configuration["threshold"]
        actual = actuals[gate_id]
        if operator == "eq":
            passed = type(actual) is type(threshold) and actual == threshold
        elif operator == "gte":
            passed = type(actual) in {int, float} and actual >= threshold
        else:
            passed = type(actual) in {int, float} and actual <= threshold
        gates.append(
            {
                "id": gate_id,
                "target": configuration["target"],
                "operator": operator,
                "threshold": threshold,
                "actual": actual,
                "passed": passed,
            }
        )
    core = {
        "policy_sha256": QUALITY_DECISION_POLICY_SHA256,
        "thresholds_sha256": thresholds_sha256,
        "gate_configuration_sha256": _canonical_hash(list(gate_configurations)),
        "slice_id": "person_contact_all_test",
        "gates": gates,
        "passed": all(gate["passed"] for gate in gates),
    }
    return {**core, "quality_decision_sha256": _canonical_hash(core)}


def _load_score_run(path: Path, frozen: Mapping[str, Any]) -> dict[str, Any]:
    root = _validate_private_run_tree(path, _SUCCESSFUL_SCORE_RUN_FILES, "Gold audit score")
    predictions, prediction_descriptor = _load_jsonl(
        root / "predictions.jsonl",
        description="Gold audit predictions",
        fields=_PREDICTION_FIELDS,
        maximum_rows=_MAX_ROWS,
    )
    cases, case_descriptor = _load_jsonl(
        root / "cases.jsonl",
        description="Gold audit cases",
        fields=_CASE_FIELDS,
        maximum_rows=_MAX_ROWS,
    )
    _validate_case_rows(cases)
    quality, quality_raw = _load_json_object(root / "quality.json", "Gold audit quality")
    manifest, manifest_raw = _load_json_object(root / "manifest.json", "Gold audit score manifest")
    receipt, receipt_raw = _load_json_object(root / "receipt.json", "Gold audit score receipt")
    if any(
        raw != _canonical_json_file(value)
        for raw, value in ((quality_raw, quality), (manifest_raw, manifest), (receipt_raw, receipt))
    ):
        raise EnronAuditScoringError("Gold audit score metadata is not canonically encoded.")
    artifacts = {
        "predictions": {"name": "predictions.jsonl", **prediction_descriptor},
        "cases": {"name": "cases.jsonl", **case_descriptor},
        "quality": _artifact_descriptor("quality.json", quality_raw, 1),
    }
    if manifest.get("artifacts") != artifacts:
        raise EnronAuditScoringError("Gold audit score artifacts differ from the manifest.")
    if (
        manifest.get("schema_version") != SCORE_MANIFEST_SCHEMA_VERSION
        or manifest.get("scoring_policy_sha256") != AUDIT_SCORING_POLICY_SHA256
        or manifest.get("prediction_audit_policy_sha256") != PREDICTION_AUDIT_POLICY_SHA256
        or manifest.get("quality_decision")
        != _quality_decision(
            quality,
            frozen["quality_gate_configurations"],
            str(frozen["thresholds_sha256"]),
        )
    ):
        raise EnronAuditScoringError("Gold audit score manifest schema is invalid.")
    if receipt != _score_receipt(manifest, quality):
        raise EnronAuditScoringError("Gold audit score receipt differs from its manifest.")
    return {
        "root": root,
        "predictions": predictions,
        "cases": cases,
        "quality": quality,
        "manifest": manifest,
        "receipt": receipt,
        "artifacts": artifacts,
        "metadata_artifacts": {
            "manifest": _artifact_descriptor("manifest.json", manifest_raw, 1),
            "receipt": _artifact_descriptor("receipt.json", receipt_raw, 1),
        },
    }


def _load_insufficient_score_run(path: Path) -> dict[str, Any]:
    root = _validate_private_run_tree(path, _INSUFFICIENT_SCORE_RUN_FILES, "Insufficient-support score")
    manifest, manifest_raw = _load_json_object(root / "manifest.json", "Insufficient-support score manifest")
    receipt, receipt_raw = _load_json_object(root / "receipt.json", "Insufficient-support score receipt")
    if manifest_raw != _canonical_json_file(manifest) or receipt_raw != _canonical_json_file(receipt):
        raise EnronAuditScoringError("Insufficient-support score metadata is not canonically encoded.")
    if (
        manifest.get("schema_version") != INSUFFICIENT_SUPPORT_MANIFEST_SCHEMA_VERSION
        or manifest.get("status") != "insufficient_support"
        or receipt.get("schema_version") != INSUFFICIENT_SUPPORT_RECEIPT_SCHEMA_VERSION
        or receipt.get("status") != "insufficient_support"
        or receipt != _insufficient_support_receipt(manifest)
    ):
        raise EnronAuditScoringError("Insufficient-support score metadata is invalid.")
    return {
        "root": root,
        "manifest": manifest,
        "receipt": receipt,
        "metadata_artifacts": {
            "manifest": _artifact_descriptor("manifest.json", manifest_raw, 1),
            "receipt": _artifact_descriptor("receipt.json", receipt_raw, 1),
        },
    }


def _load_bound_gold_reviewer_identities(gold_run_dir: Path, score_receipt: Mapping[str, Any]) -> set[str]:
    commitment = {
        "gold_sha256": score_receipt.get("gold_sha256"),
        "manifest_sha256": score_receipt.get("gold_manifest_sha256"),
        "artifacts_sha256": score_receipt.get("gold_artifacts_sha256"),
    }
    try:
        return _gold._load_verified_enron_gold_role_identities(gold_run_dir, commitment)
    except _gold.EnronGoldAnnotationError:
        raise EnronAuditScoringError("Gold annotation run differs from the score-bound gold evidence.") from None


def _require_trusted_score_receipt(
    expected: Mapping[str, Any], verified: Mapping[str, Any], score: Mapping[str, Any]
) -> None:
    if not isinstance(expected, Mapping):
        raise EnronAuditScoringError("Prediction audit requires a trusted expected score receipt.")
    expected_detached = _detached(expected)
    metadata = score.get("metadata_artifacts")
    receipt_artifact = metadata.get("receipt") if isinstance(metadata, Mapping) else None
    if (
        expected_detached != verified
        or expected_detached.get("manifest_sha256") != score["receipt"].get("manifest_sha256")
        or expected_detached.get("prediction_commitment") != score["receipt"].get("prediction_commitment")
        or expected_detached.get("prediction_commitment_sha256") != score["receipt"].get("prediction_commitment_sha256")
        or not isinstance(receipt_artifact, Mapping)
        or receipt_artifact.get("sha256") != _hash_bytes(_canonical_json_file(expected_detached))
    ):
        raise EnronAuditScoringError(
            "Verified score receipt, manifest, or prediction commitment differs from the trusted expectation."
        )


def _load_prediction_audit_reviews(
    path: Path, cases: Sequence[Mapping[str, Any]]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    del cases
    rows, descriptor = _load_jsonl(
        path,
        description="Prediction audit review input",
        fields=_REVIEW_FIELDS,
        maximum_rows=_MAX_ROWS,
    )
    rows.sort(key=lambda row: str(row["case_id"]))
    return rows, descriptor


def _validate_prediction_audit_reviews(
    reviews: Sequence[Mapping[str, Any]],
    cases: Sequence[Mapping[str, Any]],
    gold_reviewer_identities: set[str],
) -> None:
    expected_case_ids = {str(case["case_id"]) for case in cases}
    seen_case_ids: set[str] = set()
    reviewers: set[str] = set()
    for index, row in enumerate(reviews):
        if not isinstance(row, Mapping) or set(row) != _REVIEW_FIELDS:
            raise EnronAuditScoringError(f"Prediction audit review {index} schema is invalid.")
        case_id = row["case_id"]
        reviewer_id = row["reviewer_id"]
        finding = row["finding"]
        reason_codes = row["reason_codes"]
        unresolved = row["unresolved"]
        if (
            row["schema_version"] != PREDICTION_AUDIT_REVIEW_SCHEMA_VERSION
            or not _is_sha256(case_id)
            or case_id not in expected_case_ids
            or case_id in seen_case_ids
            or not isinstance(reviewer_id, str)
            or _IDENTIFIER_RE.fullmatch(reviewer_id) is None
            or finding not in _FINDINGS
            or not isinstance(reason_codes, list)
            or not reason_codes
            or len(reason_codes) != len(set(reason_codes))
            or not isinstance(unresolved, list)
            or unresolved
        ):
            raise EnronAuditScoringError(f"Prediction audit review {index} is invalid or unresolved.")
        allowed = _CONFIRMED_REASON_CODES if finding == "confirmed" else _GOLD_DEFECT_REASON_CODES
        if any(code not in allowed for code in reason_codes) or reason_codes != sorted(reason_codes):
            raise EnronAuditScoringError(f"Prediction audit review {index} reason codes are invalid.")
        seen_case_ids.add(str(case_id))
        reviewers.add(str(reviewer_id))
    if seen_case_ids != expected_case_ids:
        raise EnronAuditScoringError("Prediction audit must review every committed case exactly once.")
    if len(reviewers) != 1:
        raise EnronAuditScoringError("Prediction audit must use exactly one reviewer identity.")
    if reviewers & gold_reviewer_identities:
        raise EnronAuditScoringError("Prediction audit reviewer must be distinct from every gold-review role.")
    if list(reviews) != sorted(reviews, key=lambda row: str(row["case_id"])):
        raise EnronAuditScoringError("Prediction audit reviews are not in canonical case order.")


def _prediction_audit_manifest(
    score: Mapping[str, Any], review_artifact: Mapping[str, Any], reviews: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    gold_defects = sum(row["finding"] == "gold_defect" for row in reviews)
    quality_passed = score["receipt"]["quality_decision"].get("passed") is True
    if gold_defects:
        status = "invalidated_gold_defect"
        release = "do_not_ship"
        decision_eligible = False
    elif not quality_passed:
        status = "quality_gates_failed"
        release = "do_not_ship"
        decision_eligible = False
    else:
        status = "accepted"
        release = "quality_eligible"
        decision_eligible = True
    return {
        "schema_version": PREDICTION_AUDIT_MANIFEST_SCHEMA_VERSION,
        "prediction_audit_policy_sha256": PREDICTION_AUDIT_POLICY_SHA256,
        "audit_plan_sha256": score["receipt"]["audit_plan_sha256"],
        "audit_output_binding_sha256": score["receipt"]["audit_output_binding_sha256"],
        "score_manifest_sha256": score["receipt"]["manifest_sha256"],
        "score_receipt_artifact_sha256": score["metadata_artifacts"]["receipt"]["sha256"],
        "score_quality_run_sha256": score["receipt"]["quality_run_sha256"],
        "quality_decision_sha256": score["receipt"]["quality_decision"]["quality_decision_sha256"],
        "quality_gates_passed": quality_passed,
        "score_case_artifact_sha256": score["receipt"]["case_artifact_sha256"],
        "prediction_commitment_sha256": score["receipt"]["prediction_commitment_sha256"],
        "catalog_binding_sha256": score["receipt"]["catalog_binding_sha256"],
        "gold_sha256": score["receipt"]["gold_sha256"],
        "gold_manifest_sha256": score["receipt"]["gold_manifest_sha256"],
        "gold_artifacts_sha256": score["receipt"]["gold_artifacts_sha256"],
        "planned_evaluator_source_sha256": score["receipt"]["planned_evaluator_source_sha256"],
        "thresholds_sha256": score["receipt"]["thresholds_sha256"],
        "quality_gate_configuration_sha256": score["receipt"]["quality_gate_configuration_sha256"],
        "score_attempt_binding_sha256": score["receipt"]["score_attempt_binding_sha256"],
        "score_claim_sha256": score["receipt"]["score_claim_sha256"],
        "review_artifact": _detached(review_artifact),
        "counts": {
            "cases": len(score["cases"]),
            "reviews": len(reviews),
            "confirmed": len(reviews) - gold_defects,
            "gold_defects": gold_defects,
            "unresolved": 0,
        },
        "status": status,
        "decision_eligible": decision_eligible,
        "release": release,
    }


def _prediction_audit_receipt(manifest: Mapping[str, Any]) -> dict[str, Any]:
    review_artifact = manifest["review_artifact"]
    return {
        "schema_version": PREDICTION_AUDIT_RECEIPT_SCHEMA_VERSION,
        "valid": True,
        "status": manifest["status"],
        "decision_eligible": manifest["decision_eligible"],
        "release": manifest["release"],
        "prediction_audit_policy_sha256": manifest["prediction_audit_policy_sha256"],
        "audit_plan_sha256": manifest["audit_plan_sha256"],
        "audit_output_binding_sha256": manifest["audit_output_binding_sha256"],
        "score_manifest_sha256": manifest["score_manifest_sha256"],
        "score_receipt_artifact_sha256": manifest["score_receipt_artifact_sha256"],
        "score_quality_run_sha256": manifest["score_quality_run_sha256"],
        "quality_decision_sha256": manifest["quality_decision_sha256"],
        "quality_gates_passed": manifest["quality_gates_passed"],
        "score_case_artifact_sha256": manifest["score_case_artifact_sha256"],
        "prediction_commitment_sha256": manifest["prediction_commitment_sha256"],
        "catalog_binding_sha256": manifest["catalog_binding_sha256"],
        "gold_sha256": manifest["gold_sha256"],
        "gold_manifest_sha256": manifest["gold_manifest_sha256"],
        "gold_artifacts_sha256": manifest["gold_artifacts_sha256"],
        "planned_evaluator_source_sha256": manifest["planned_evaluator_source_sha256"],
        "evaluator_source_sha256": manifest["planned_evaluator_source_sha256"],
        "thresholds_sha256": manifest["thresholds_sha256"],
        "quality_gate_configuration_sha256": manifest["quality_gate_configuration_sha256"],
        "score_attempt_binding_sha256": manifest["score_attempt_binding_sha256"],
        "score_claim_sha256": manifest["score_claim_sha256"],
        "review_artifact_sha256": review_artifact["sha256"],
        "manifest_sha256": _canonical_hash(manifest),
        "artifacts_sha256": _canonical_hash({"review": review_artifact}),
        "unresolved_cases": manifest["counts"]["unresolved"],
        "counts": _detached(manifest["counts"]),
        "privacy": {
            "aggregate_only": True,
            "raw_text_included": False,
            "document_ids_included": False,
            "reviewer_ids_included": False,
            "span_coordinates_included": False,
            "span_surfaces_included": False,
            "catalog_identities_included": False,
            "private_paths_included": False,
        },
    }


def _score_attempt_binding_sha256(prepared: Mapping[str, Any]) -> str:
    return _canonical_hash(
        {
            "domain": "nerb/enron/gold-audit/sole-score-attempt/v1",
            "audit_plan_sha256": prepared["gold_receipt"]["audit_plan_sha256"],
            "audit_output_binding_sha256": prepared["gold_receipt"]["audit_output_binding_sha256"],
        }
    )


def _expected_score_claim(prepared: Mapping[str, Any], output_dir: Path) -> dict[str, Any]:
    core = {
        "schema_version": _SCORE_CLAIM_SCHEMA_VERSION,
        "audit_plan_sha256": prepared["gold_receipt"]["audit_plan_sha256"],
        "audit_output_binding_sha256": prepared["gold_receipt"]["audit_output_binding_sha256"],
        "score_attempt_binding_sha256": _score_attempt_binding_sha256(prepared),
        "score_output_directory_sha256": _canonical_hash(
            {"absolute_output_directory": os.fspath(_absolute_path(output_dir))}
        ),
    }
    return {**core, "score_claim_sha256": _canonical_hash(core)}


def _score_state_filenames(claim: Mapping[str, Any]) -> tuple[str, str]:
    binding = claim.get("score_attempt_binding_sha256")
    if not _is_sha256(binding):
        raise EnronAuditScoringError("Score claim binding is invalid.")
    suffix = str(binding).removeprefix("sha256:")
    return f"claim-{suffix}.json", f"outcome-{suffix}.json"


def _acquire_score_claim(score_state_dir: Path, prepared: Mapping[str, Any], output_dir: Path) -> dict[str, Any]:
    claim = _expected_score_claim(prepared, output_dir)
    claim_name, _outcome_name = _score_state_filenames(claim)
    directory_fd = _open_score_state_directory(score_state_dir)
    try:
        _write_exclusive_state_record(directory_fd, claim_name, claim)
    except FileExistsError:
        raise EnronAuditScoringError(
            "This audit plan and sealed output binding already consumed their sole score attempt."
        ) from None
    except (EnronPrivateIOError, OSError, TypeError, ValueError):
        raise EnronAuditScoringError("Sole-score claim could not be acquired durably.") from None
    finally:
        os.close(directory_fd)
    return claim


def _terminalize_score_claim(
    score_state_dir: Path, claim: Mapping[str, Any], score_receipt: Mapping[str, Any]
) -> dict[str, Any]:
    core = {
        "schema_version": _SCORE_OUTCOME_SCHEMA_VERSION,
        "audit_plan_sha256": claim["audit_plan_sha256"],
        "audit_output_binding_sha256": claim["audit_output_binding_sha256"],
        "score_attempt_binding_sha256": claim["score_attempt_binding_sha256"],
        "score_claim_sha256": claim["score_claim_sha256"],
        "status": score_receipt["status"],
        "decision_eligible": score_receipt["decision_eligible"],
        "release": score_receipt["release"],
        "score_receipt_sha256": _canonical_hash(score_receipt),
        "failure_codes": list(score_receipt.get("support_failure_codes", [])),
    }
    outcome = {**core, "score_outcome_sha256": _canonical_hash(core)}
    _write_score_outcome(score_state_dir, claim, outcome)
    return outcome


def _terminalize_failed_score_claim(score_state_dir: Path, claim: Mapping[str, Any]) -> None:
    core = {
        "schema_version": _SCORE_OUTCOME_SCHEMA_VERSION,
        "audit_plan_sha256": claim["audit_plan_sha256"],
        "audit_output_binding_sha256": claim["audit_output_binding_sha256"],
        "score_attempt_binding_sha256": claim["score_attempt_binding_sha256"],
        "score_claim_sha256": claim["score_claim_sha256"],
        "status": "score_failed",
        "decision_eligible": False,
        "release": "do_not_ship",
        "score_receipt_sha256": None,
        "failure_codes": ["score_execution_failed"],
    }
    outcome = {**core, "score_outcome_sha256": _canonical_hash(core)}
    try:
        _write_score_outcome(score_state_dir, claim, outcome)
    except (EnronAuditScoringError, EnronPrivateIOError, OSError, TypeError, ValueError):
        # The exclusive claim itself is terminal and continues to forbid resampling.
        pass


def _write_score_outcome(score_state_dir: Path, claim: Mapping[str, Any], outcome: Mapping[str, Any]) -> None:
    _claim_name, outcome_name = _score_state_filenames(claim)
    directory_fd = _open_score_state_directory(score_state_dir)
    try:
        _write_exclusive_state_record(directory_fd, outcome_name, outcome)
    except FileExistsError:
        raise EnronAuditScoringError("Sole-score claim already has a terminal outcome.") from None
    except (EnronPrivateIOError, OSError, TypeError, ValueError):
        raise EnronAuditScoringError("Sole-score outcome could not be committed durably.") from None
    finally:
        os.close(directory_fd)


def _verify_score_claim(
    score_state_dir: Path,
    prepared: Mapping[str, Any],
    output_dir: Path,
    score_receipt: Mapping[str, Any],
) -> None:
    expected_claim = _expected_score_claim(prepared, output_dir)
    claim_name, outcome_name = _score_state_filenames(expected_claim)
    directory_fd = _open_score_state_directory(score_state_dir)
    try:
        claim = _load_score_state_record(directory_fd, claim_name, "Sole-score claim")
        outcome = _load_score_state_record(directory_fd, outcome_name, "Sole-score outcome")
    finally:
        os.close(directory_fd)
    if claim != expected_claim or score_receipt.get("score_claim_sha256") != expected_claim["score_claim_sha256"]:
        raise EnronAuditScoringError("Sole-score claim differs from the score-bound audit attempt.")
    core = {
        "schema_version": _SCORE_OUTCOME_SCHEMA_VERSION,
        "audit_plan_sha256": claim["audit_plan_sha256"],
        "audit_output_binding_sha256": claim["audit_output_binding_sha256"],
        "score_attempt_binding_sha256": claim["score_attempt_binding_sha256"],
        "score_claim_sha256": claim["score_claim_sha256"],
        "status": score_receipt["status"],
        "decision_eligible": score_receipt["decision_eligible"],
        "release": score_receipt["release"],
        "score_receipt_sha256": _canonical_hash(score_receipt),
        "failure_codes": list(score_receipt.get("support_failure_codes", [])),
    }
    expected_outcome = {**core, "score_outcome_sha256": _canonical_hash(core)}
    if outcome != expected_outcome:
        raise EnronAuditScoringError("Sole-score terminal outcome differs from the verified score receipt.")


def _open_score_state_directory(path: Path) -> int:
    root = _absolute_path(path)
    try:
        descriptor = os.open(
            root,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            os.close(descriptor)
            raise EnronAuditScoringError("Score-state directory must be owner-only mode 0700.")
        return descriptor
    except EnronAuditScoringError:
        raise
    except OSError:
        raise EnronAuditScoringError("Score-state directory could not be opened safely.") from None


def _write_exclusive_state_record(directory_fd: int, name: str, value: Mapping[str, Any]) -> None:
    payload = _canonical_json_file(value)
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        0o600,
        dir_fd=directory_fd,
    )
    try:
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.fsync(directory_fd)


def _load_score_state_record(directory_fd: int, name: str, description: str) -> dict[str, Any]:
    try:
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise EnronAuditScoringError(f"{description} identity is invalid.")
        with open_private_binary_input_at(directory_fd, name) as file:
            raw = file.read(_MAX_JSON_BYTES + 1)
    except EnronAuditScoringError:
        raise
    except (EnronPrivateIOError, OSError):
        raise EnronAuditScoringError(f"{description} could not be opened safely.") from None
    if len(raw) > _MAX_JSON_BYTES:
        raise EnronAuditScoringError(f"{description} exceeds the byte limit.")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise EnronAuditScoringError(f"{description} is not strict JSON.") from None
    if not isinstance(value, dict) or raw != _canonical_json_file(value):
        raise EnronAuditScoringError(f"{description} is not one canonical object.")
    return value


def _validate_private_run_tree(path: Path, expected_files: frozenset[str], description: str) -> Path:
    root = _absolute_path(path)
    directory_fd: int | None = None
    try:
        directory_fd = open_private_directory_input(root)
        root_info = os.fstat(directory_fd)
        if stat.S_IMODE(root_info.st_mode) != 0o700 or root_info.st_uid != os.geteuid():
            raise EnronAuditScoringError(f"{description} directory permissions are invalid.")
        if set(os.listdir(directory_fd)) != expected_files:
            raise EnronAuditScoringError(f"{description} artifact inventory is invalid.")
        for name in expected_files:
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            mode = stat.S_IMODE(info.st_mode)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.geteuid()
                or mode != 0o600
                or not is_owner_only_private_mode(mode)
            ):
                raise EnronAuditScoringError(f"{description} artifact identity is invalid.")
        with open_private_binary_input_at(directory_fd, "COMMITTED") as marker:
            if marker.read(len(_COMMIT_PAYLOAD) + 1) != _COMMIT_PAYLOAD:
                raise EnronAuditScoringError(f"{description} commit marker is invalid.")
    except EnronAuditScoringError:
        raise
    except (EnronPrivateIOError, OSError, ValueError):
        raise EnronAuditScoringError(f"{description} run could not be opened safely.") from None
    finally:
        if directory_fd is not None:
            os.close(directory_fd)
    return root


def _load_jsonl(
    path: Path,
    *,
    description: str,
    fields: frozenset[str] | None,
    maximum_rows: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    digest = hashlib.sha256()
    byte_count = 0
    try:
        for line_no, raw, value in iter_strict_jsonl(path, _MAX_LINE_BYTES):
            if line_no > maximum_rows:
                raise EnronAuditScoringError(f"{description} exceeds the row limit.")
            row = dict(value)
            if raw != _canonical_bytes(row) + b"\n" or (fields is not None and set(row) != fields):
                raise EnronAuditScoringError(f"{description} row {line_no} is not canonical and closed.")
            rows.append(row)
            digest.update(raw)
            byte_count += len(raw)
    except EnronAuditScoringError:
        raise
    except EnronPrivateIOError:
        raise EnronAuditScoringError(f"{description} is not valid private JSONL.") from None
    return rows, {"sha256": "sha256:" + digest.hexdigest(), "bytes": byte_count, "records": len(rows)}


def _load_json_object(path: Path, description: str) -> tuple[dict[str, Any], bytes]:
    try:
        with open_private_binary_input(path) as file:
            raw = file.read(_MAX_JSON_BYTES + 1)
    except EnronPrivateIOError:
        raise EnronAuditScoringError(f"{description} could not be opened safely.") from None
    if len(raw) > _MAX_JSON_BYTES:
        raise EnronAuditScoringError(f"{description} exceeds the byte limit.")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise EnronAuditScoringError(f"{description} is not strict JSON.") from None
    if not isinstance(value, dict):
        raise EnronAuditScoringError(f"{description} must contain one JSON object.")
    return value, raw


def _read_regular_file(path: Path, maximum_bytes: int, description: str) -> bytes:
    candidate = _absolute_path(path)
    descriptor: int | None = None
    try:
        descriptor = os.open(
            candidate,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise EnronAuditScoringError(f"{description} must be a single-link regular file.")
        payload = bytearray()
        while len(payload) <= maximum_bytes:
            chunk = os.read(descriptor, min(1024 * 1024, maximum_bytes + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > maximum_bytes:
            raise EnronAuditScoringError(f"{description} exceeds the byte limit.")
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino, after.st_size) != (info.st_dev, info.st_ino, info.st_size):
            raise EnronAuditScoringError(f"{description} changed while it was read.")
        return bytes(payload)
    except EnronAuditScoringError:
        raise
    except OSError:
        raise EnronAuditScoringError(f"{description} could not be opened safely.") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _reject_duplicate_pairs(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _absolute_path(path: Path) -> Path:
    candidate = Path(path).expanduser()
    if any(part == os.pardir for part in candidate.parts):
        raise EnronAuditScoringError("Private paths must not contain parent traversal.")
    return candidate if candidate.is_absolute() else Path.cwd() / candidate


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _canonical_json_file(value: Any) -> bytes:
    return _canonical_bytes(value) + b"\n"


def _canonical_jsonl(rows: Iterable[Mapping[str, Any]]) -> bytes:
    return b"".join(_canonical_bytes(row) + b"\n" for row in rows)


def _canonical_hash(value: Any) -> str:
    return _hash_bytes(_canonical_bytes(value))


def _hash_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _artifact_descriptor(name: str, payload: bytes, records: int) -> dict[str, Any]:
    return {"name": name, "sha256": _hash_bytes(payload), "bytes": len(payload), "records": records}


def _detached(value: Mapping[str, Any]) -> dict[str, Any]:
    result = json.loads(_canonical_bytes(value))
    if not isinstance(result, dict):
        raise EnronAuditScoringError("Canonical object projection failed.")
    return result


def _detached_or_none(value: Mapping[str, Any] | None) -> dict[str, Any] | None:
    return None if value is None else _detached(value)


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _identifier(value: Any, description: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        raise EnronAuditScoringError(f"{description} is invalid.")
    return value


def _merge_intervals(values: Sequence[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(values):
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
    return merged

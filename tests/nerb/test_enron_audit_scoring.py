from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

import nerb.enron_audit_scoring as scoring
from nerb.bank import hash_bank
from nerb.enron_contract import hash_enron_thresholds
from nerb.enron_gold_annotations import enron_gold_annotation_policy_sha256
from nerb.enron_private_io import PrivateRun
from nerb.enron_sealed_audit import AUDIT_EXECUTION_POLICY_SHA256


def _hash(value: bytes) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(value).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _write_private_jsonl(path: Path, rows: list[dict[str, Any]]) -> Path:
    path.write_bytes(b"".join(_canonical(row) for row in rows))
    path.chmod(0o600)
    return path


def _pattern(value: str, priority: int) -> dict[str, Any]:
    return {
        "kind": "literal",
        "value": value,
        "description": "Audit scoring fixture pattern.",
        "status": "active",
        "priority": priority,
        "case_sensitive": True,
        "normalize_whitespace": False,
        "left_boundary": "none",
        "right_boundary": "none",
        "metadata": {},
    }


def _name(canonical: str, value: str, priority: int) -> dict[str, Any]:
    return {
        "canonical": canonical,
        "description": "Audit scoring fixture name.",
        "status": "active",
        "patterns": {"primary": _pattern(value, priority)},
        "metadata": {},
    }


def _bank() -> dict[str, Any]:
    return {
        "schema_version": "nerb.bank.v1",
        "id": "audit_scoring_fixture",
        "name": "Audit scoring fixture",
        "description": "Synthetic bank for the sealed scoring workflow.",
        "version": "fixture-v1",
        "status": "active",
        "created_at": "2026-07-14T00:00:00Z",
        "updated_at": "2026-07-14T00:00:00Z",
        "unicode_normalization": "none",
        "default_regex_flags": [],
        "entities": {
            "contact": {
                "description": "Contacts.",
                "status": "active",
                "regex_flags": [],
                "names": {"alice_email": _name("Alice email", "alice@example.com", 10)},
                "metadata": {},
            },
            "person": {
                "description": "People.",
                "status": "active",
                "regex_flags": [],
                "names": {
                    "alice": _name("Alice", "Alice", 10),
                    "boundary": _name("Boundary", "licx", 20),
                    "wrong_actual": _name("Wrong actual", "Wrong", 30),
                    "wrong_expected": _name("Wrong expected", "Expected", 40),
                    "noise": _name("Noise", "Noise", 50),
                },
                "metadata": {},
            },
        },
        "metadata": {},
    }


def _text_view_descriptor() -> dict[str, Any]:
    return {
        "id": "subject_current_body",
        "artifact_sha256": "sha256:" + "a" * 64,
        "content_policy_sha256": "sha256:" + "b" * 64,
        "document_regions": ["subject", "current_body"],
        "primary_for_quality": True,
        "answer_bearing_fields_included": False,
    }


def _promotion_checks() -> list[dict[str, Any]]:
    checks = [
        {
            "id": requirement["id"],
            "category": "quality",
            "target": requirement["target"],
            "operator": requirement["operator"],
            "threshold": requirement["policy_threshold"],
            "actual": None,
            "passed": False,
        }
        for requirement in scoring.QUALITY_DECISION_POLICY["requirements"]
    ]
    checks.extend(
        [
            {
                "id": "catalog_conformance",
                "category": "catalog_conformance",
                "target": "/catalog_conformance/passed",
                "operator": "eq",
                "threshold": True,
                "actual": None,
                "passed": False,
            },
            {
                "id": "clean_git",
                "category": "provenance",
                "target": "/software/git_dirty",
                "operator": "eq",
                "threshold": False,
                "actual": None,
                "passed": False,
            },
        ]
    )
    return checks


def _build_private_inputs(tmp_path: Path) -> dict[str, Any]:
    bank = _bank()
    promotion_checks = _promotion_checks()
    evaluator_source_sha256 = scoring._quality.enron_quality_evaluator_identity()["source_sha256"]
    thresholds_sha256 = hash_enron_thresholds(promotion_checks)
    documents: list[dict[str, Any]] = []
    gold_documents: list[dict[str, Any]] = []
    bindings: list[dict[str, Any]] = []
    class_counts = {"contact": 0, "person": 0}
    sensitive_characters = 0
    for index in range(100):
        document_id = f"doc_{index:03d}"
        if index == 0:
            text = "Blicx alice@example.com"
            person_identity = None
        elif index == 1:
            text = "Wrong alice@example.com"
            person_identity = {"entity_id": "person", "name_id": "wrong_expected", "pattern_id": "primary"}
        elif index < 80:
            text = "Alice alice@example.com"
            person_identity = {"entity_id": "person", "name_id": "alice", "pattern_id": "primary"}
        elif index == 80:
            text = "Noise"
            person_identity = None
        else:
            text = "Nothing"
            person_identity = None
        text_sha256 = _hash(text.encode())
        documents.append(
            {
                "document_id": document_id,
                "text": text,
                "text_sha256": text_sha256,
                "unicode_scalars": len(text),
                "text_view": "subject_current_body",
            }
        )
        spans: list[dict[str, Any]] = []
        if index < 80:
            spans = [
                {"entity_class": "person", "start": 0, "end": 5},
                {"entity_class": "contact", "start": 6, "end": 23},
            ]
            class_counts["person"] += 1
            class_counts["contact"] += 1
            sensitive_characters += 22
            bindings.extend(
                [
                    {
                        "document_id": document_id,
                        "entity_class": "person",
                        "start": 0,
                        "end": 5,
                        "catalog_identity": person_identity,
                    },
                    {
                        "document_id": document_id,
                        "entity_class": "contact",
                        "start": 6,
                        "end": 23,
                        "catalog_identity": {
                            "entity_id": "contact",
                            "name_id": "alice_email",
                            "pattern_id": "primary",
                        },
                    },
                ]
            )
        gold_documents.append(
            {
                "document_id": document_id,
                "text_sha256": text_sha256,
                "unicode_scalars": len(text),
                "spans": spans,
            }
        )
    counts = {
        "documents": 100,
        "documents_with_sensitive_gold": 80,
        "negative_documents": 20,
        "gold_spans": 160,
        "sensitive_gold_characters": sensitive_characters,
        "by_class": {
            entity_class: {
                "documents_with_sensitive_gold": 80,
                "negative_documents": 20,
                "gold_spans": class_counts[entity_class],
                "sensitive_gold_characters": 80 * (17 if entity_class == "contact" else 5),
            }
            for entity_class in ("contact", "person")
        },
    }
    provenance = {
        "annotation_passes": 2,
        "pass_a_reviewers": 1,
        "pass_b_reviewers": 1,
        "adjudicators": 1,
        "independent_reviewers": 1,
        "disagreements": 0,
        "adjudication_decisions": 0,
        "agreement_audit_documents": 20,
        "full_character_coverage": True,
        "unresolved": 0,
    }
    gold_core = {
        "schema_version": scoring._gold.GOLD_SCHEMA_VERSION,
        "annotation_policy_sha256": enron_gold_annotation_policy_sha256(),
        "sample_binding_sha256": "sha256:" + "1" * 64,
        "documents": gold_documents,
        "counts": counts,
        "provenance": provenance,
    }
    gold = {**gold_core, "gold_sha256": scoring._canonical_hash(gold_core)}
    audit_plan_sha256 = "sha256:" + "2" * 64
    output_binding_sha256 = "sha256:" + "3" * 64
    catalog_policy_sha256 = scoring._catalog.enron_catalog_qualification_policy_sha256()
    sample_binding = {
        "audit_plan_sha256": audit_plan_sha256,
        "audit_output_binding_sha256": output_binding_sha256,
        "audit_execution_policy_sha256": AUDIT_EXECUTION_POLICY_SHA256,
        "annotation_policy_sha256": enron_gold_annotation_policy_sha256(),
        "catalog_policy_sha256": catalog_policy_sha256,
        "bank_sha256": hash_bank(bank),
        "evaluator_source_sha256": evaluator_source_sha256,
        "thresholds_sha256": thresholds_sha256,
        "plan_artifact": {"sha256": "sha256:" + "4" * 64, "bytes": 1},
        "sample_artifact": {"sha256": "sha256:" + "5" * 64, "bytes": 1, "records": 100},
        "receipt_artifact": {"sha256": "sha256:" + "6" * 64, "bytes": 1, "records": 1},
        "fixture_mode": True,
        "promotable": False,
    }

    role_rows = {
        "pass_a": [
            {
                "schema_version": scoring._gold.ANNOTATION_PASS_SCHEMA_VERSION,
                "document_id": "doc_000",
                "text_sha256": documents[0]["text_sha256"],
                "reviewer_id": "pass_a",
                "coverage": [{"start": 0, "end": len(documents[0]["text"])}],
                "spans": [],
                "unresolved": [],
            }
        ],
        "pass_b": [
            {
                "schema_version": scoring._gold.ANNOTATION_PASS_SCHEMA_VERSION,
                "document_id": "doc_000",
                "text_sha256": documents[0]["text_sha256"],
                "reviewer_id": "pass_b",
                "coverage": [{"start": 0, "end": len(documents[0]["text"])}],
                "spans": [],
                "unresolved": [],
            }
        ],
        "adjudication": [
            {
                "schema_version": scoring._gold.ADJUDICATION_SCHEMA_VERSION,
                "document_id": "doc_000",
                "text_sha256": documents[0]["text_sha256"],
                "adjudicator_id": "adjudicator",
                "spans": [],
                "decisions": [],
                "unresolved": [],
            }
        ],
        "review": [
            {
                "schema_version": scoring._gold.ANNOTATION_REVIEW_SCHEMA_VERSION,
                "document_id": "doc_000",
                "text_sha256": documents[0]["text_sha256"],
                "reviewer_id": "gold_reviewer",
                "adjudication_sha256": "sha256:" + "a" * 64,
                "disagreements_reviewed": True,
                "agreement_audit": True,
                "status": "accepted",
                "unresolved": [],
            }
        ],
        "gold": gold_documents,
    }
    artifact_payloads: dict[str, bytes] = {}
    artifacts: dict[str, dict[str, Any]] = {}
    for key, rows in role_rows.items():
        filename = scoring._gold._ARTIFACT_FILENAMES[key]
        payload = b"".join(_canonical(row) for row in rows)
        artifact_payloads[filename] = payload
        artifacts[key] = scoring._artifact_descriptor(filename, payload, len(rows))
    manifest = scoring._gold._gold_run_manifest(sample_binding, artifacts, gold)
    receipt = scoring._gold._gold_run_receipt(manifest)
    expected_gold_commitment = {
        "gold_sha256": receipt["gold_sha256"],
        "manifest_sha256": receipt["manifest_sha256"],
        "artifacts_sha256": receipt["artifacts_sha256"],
    }
    gold_run = tmp_path / "gold-run"
    with PrivateRun(gold_run, allow_unignored_output=True) as run:
        for filename, payload in artifact_payloads.items():
            with run.open_binary(filename) as file:
                file.write(payload)
        with run.open_binary("manifest.json") as file:
            file.write(_canonical(manifest))
        with run.open_binary("receipt.json") as file:
            file.write(_canonical(receipt))
        run.commit()

    catalog_counts = {
        "gold_spans": 160,
        "cataloged_gold_spans": 159,
        "uncataloged_gold_spans": 1,
        "by_class": {
            "contact": {"gold_spans": 80, "cataloged_gold_spans": 80, "uncataloged_gold_spans": 0},
            "person": {"gold_spans": 80, "cataloged_gold_spans": 79, "uncataloged_gold_spans": 1},
        },
    }
    catalog_receipt = {
        "schema_version": scoring._catalog.CATALOG_RUN_RECEIPT_SCHEMA_VERSION,
        "valid": True,
        "fixture_mode": True,
        "promotable": False,
        "audit_plan_sha256": audit_plan_sha256,
        "audit_output_binding_sha256": output_binding_sha256,
        "audit_execution_policy_sha256": AUDIT_EXECUTION_POLICY_SHA256,
        "sample_artifact_sha256": receipt["sample_artifact_sha256"],
        "sample_binding_sha256": receipt["sample_binding_sha256"],
        "planned_evaluator_source_sha256": evaluator_source_sha256,
        "planned_thresholds_sha256": thresholds_sha256,
        "gold_sha256": receipt["gold_sha256"],
        "gold_manifest_sha256": receipt["manifest_sha256"],
        "gold_artifacts_sha256": receipt["artifacts_sha256"],
        "trusted_gold_commitment": expected_gold_commitment,
        "trusted_gold_commitment_sha256": scoring._canonical_hash(expected_gold_commitment),
        "annotation_policy_sha256": receipt["annotation_policy_sha256"],
        "catalog_policy_sha256": catalog_policy_sha256,
        "bank_sha256": hash_bank(bank),
        "bank_artifact_sha256": "sha256:" + "7" * 64,
        "binding_artifact_sha256": "sha256:" + "8" * 64,
        "catalog_binding_sha256": "sha256:" + "9" * 64,
        "manifest_sha256": "sha256:" + "c" * 64,
        "artifacts_sha256": "sha256:" + "d" * 64,
        "review_artifact_sha256": "sha256:" + "e" * 64,
        "review_provenance": {
            "documents_reviewed": 100,
            "decisions_reviewed": 160,
            "reviewers": 1,
            "unresolved": 0,
            "bank_aware": True,
            "prediction_blind": True,
            "reviewer_identity_sha256": "sha256:" + "f" * 64,
        },
        "counts": catalog_counts,
        "catalog_coverage": 159 / 160,
        "privacy": {
            "aggregate_only": True,
            "raw_text_included": False,
            "document_ids_included": False,
            "span_coordinates_included": False,
            "span_surfaces_included": False,
            "catalog_identities_included": False,
            "entity_names_included": False,
            "pattern_ids_included": False,
            "private_paths_included": False,
        },
    }
    score_state = tmp_path / "score-state"
    score_state.mkdir(mode=0o700)
    score_state.chmod(0o700)
    gold_state = tmp_path / "gold-state"
    gold_state.mkdir(mode=0o700)
    gold_state.chmod(0o700)
    return {
        "bank": bank,
        "documents": documents,
        "gold": gold,
        "gold_receipt": receipt,
        "bindings": sorted(
            bindings, key=lambda row: (row["document_id"], row["start"], row["end"], row["entity_class"])
        ),
        "catalog_receipt": catalog_receipt,
        "catalog_reviewer_id": "catalog_reviewer",
        "promotion_checks": promotion_checks,
        "expected_gold_commitment": expected_gold_commitment,
        "score_state": score_state,
        "gold_state": gold_state,
        "gold_run": gold_run,
        "sample_run": tmp_path / "sample-run-placeholder",
        "catalog_run": tmp_path / "catalog-run-placeholder",
        "output_binding": output_binding_sha256,
    }


def _install_upstream(monkeypatch: pytest.MonkeyPatch, data: dict[str, Any]) -> None:
    def load_catalog(*_args: Any, **_kwargs: Any) -> tuple[list[dict[str, Any]], str, dict[str, Any]]:
        return (
            copy.deepcopy(data["bindings"]),
            data["catalog_reviewer_id"],
            copy.deepcopy(data["catalog_receipt"]),
        )

    def load_gold(*_args: Any, **_kwargs: Any) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
        return (
            copy.deepcopy(data["documents"]),
            copy.deepcopy(data["gold"]),
            copy.deepcopy(data["gold_receipt"]),
        )

    monkeypatch.setattr(scoring._catalog, "_load_verified_enron_catalog_qualification_files", load_catalog)
    monkeypatch.setattr(scoring._gold, "_load_verified_enron_gold_annotations_files", load_gold)


def _apply_support_failure(data: dict[str, Any], failure_code: str) -> None:
    if failure_code == "documents_below_minimum":
        data["documents"].pop(79)
        data["gold"]["documents"].pop(79)
        data["bindings"] = [row for row in data["bindings"] if row["document_id"] != "doc_079"]
        counts = (99, 158, 20, 1738)
    elif failure_code == "gold_spans_below_minimum":
        for document in data["gold"]["documents"][40:80]:
            document["spans"] = []
        data["bindings"] = [row for row in data["bindings"] if int(row["document_id"].removeprefix("doc_")) < 40]
        counts = (100, 80, 60, 880)
    elif failure_code == "negative_documents_below_minimum":
        data["gold"]["documents"][80]["spans"] = [{"entity_class": "person", "start": 0, "end": 1}]
        data["bindings"].append(
            {
                "document_id": "doc_080",
                "entity_class": "person",
                "start": 0,
                "end": 1,
                "catalog_identity": None,
            }
        )
        counts = (100, 161, 19, 1761)
    elif failure_code == "sensitive_characters_below_minimum":
        for document in data["gold"]["documents"][:80]:
            document["spans"] = [
                {"entity_class": "person", "start": 0, "end": 1},
                {"entity_class": "contact", "start": 6, "end": 7},
            ]
        for row in data["bindings"]:
            row["end"] = row["start"] + 1
        counts = (100, 160, 20, 160)
    else:
        missing_class = failure_code.removesuffix("_gold_support_missing")
        retained_class = "person" if missing_class == "contact" else "contact"
        base_start, base_end = (0, 5) if retained_class == "person" else (6, 23)
        data["bindings"] = [row for row in data["bindings"] if row["entity_class"] == retained_class]
        for index, document in enumerate(data["gold"]["documents"][:80]):
            document["spans"] = [{"entity_class": retained_class, "start": base_start, "end": base_end}]
            if index < 60:
                for start in (0, 1) if retained_class == "contact" else (5, 6):
                    document["spans"].append({"entity_class": retained_class, "start": start, "end": start + 1})
                    data["bindings"].append(
                        {
                            "document_id": document["document_id"],
                            "entity_class": retained_class,
                            "start": start,
                            "end": start + 1,
                            "catalog_identity": None,
                        }
                    )
        sensitive = 1480 if retained_class == "contact" else 520
        counts = (100, 200, 20, sensitive)
    data["bindings"].sort(key=lambda row: (row["document_id"], row["start"], row["end"], row["entity_class"]))
    receipt_counts = data["gold_receipt"]["counts"]
    (
        receipt_counts["documents"],
        receipt_counts["gold_spans"],
        receipt_counts["negative_documents"],
        receipt_counts["sensitive_gold_characters"],
    ) = counts


def _score(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, quality_pass: bool = False
) -> tuple[dict[str, Any], dict[str, Any], Path]:
    data = _build_private_inputs(tmp_path)
    if quality_pass:
        person_binding = next(
            row for row in data["bindings"] if row["document_id"] == "doc_001" and row["entity_class"] == "person"
        )
        person_binding["catalog_identity"] = {
            "entity_id": "person",
            "name_id": "wrong_actual",
            "pattern_id": "primary",
        }
    _install_upstream(monkeypatch, data)
    score_run = tmp_path / "score-run"
    receipt = scoring.score_enron_gold_audit_files(
        data["sample_run"],
        data["gold_run"],
        data["catalog_run"],
        data["bank"],
        score_run,
        promotion_checks=data["promotion_checks"],
        score_state_dir=data["score_state"],
        gold_state_dir=data["gold_state"],
        expected_gold_commitment=data["expected_gold_commitment"],
        text_view_descriptor=_text_view_descriptor(),
        allow_unignored_output=True,
    )
    return data, receipt, score_run


def _reviews_for(score_run: Path, *, reviewer: str = "prediction_reviewer") -> list[dict[str, Any]]:
    cases = [json.loads(line) for line in (score_run / "cases.jsonl").read_text().splitlines()]
    return [
        {
            "schema_version": scoring.PREDICTION_AUDIT_REVIEW_SCHEMA_VERSION,
            "case_id": case["case_id"],
            "reviewer_id": reviewer,
            "finding": "confirmed",
            "reason_codes": ["case_confirmed"],
            "unresolved": [],
        }
        for case in cases
    ]


def _verify_score(data: dict[str, Any], score_run: Path) -> dict[str, Any]:
    return scoring.verify_enron_gold_audit_score(
        score_run,
        data["sample_run"],
        data["gold_run"],
        data["catalog_run"],
        data["bank"],
        promotion_checks=data["promotion_checks"],
        score_state_dir=data["score_state"],
        gold_state_dir=data["gold_state"],
        expected_gold_commitment=data["expected_gold_commitment"],
    )


def _finalize_prediction_audit(
    data: dict[str, Any], score_receipt: dict[str, Any], score_run: Path, reviews: Path, output: Path
) -> dict[str, Any]:
    return scoring.finalize_enron_prediction_audit_files(
        score_run,
        data["gold_run"],
        reviews,
        output,
        sample_run_dir=data["sample_run"],
        catalog_run_dir=data["catalog_run"],
        bank=data["bank"],
        promotion_checks=data["promotion_checks"],
        score_state_dir=data["score_state"],
        gold_state_dir=data["gold_state"],
        expected_gold_commitment=data["expected_gold_commitment"],
        expected_score_receipt=score_receipt,
        allow_unignored_output=True,
    )


def test_score_scans_once_commits_predictions_and_replays_without_engine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = _build_private_inputs(tmp_path)
    _install_upstream(monkeypatch, data)
    actual_compile = scoring._quality.compile_bank
    actual_scan = scoring._quality._scan_document
    calls = {"compile": 0, "scan": 0}

    def compile_once(*args: Any, **kwargs: Any) -> Any:
        calls["compile"] += 1
        return actual_compile(*args, **kwargs)

    def scan_once(*args: Any, **kwargs: Any) -> Any:
        calls["scan"] += 1
        return actual_scan(*args, **kwargs)

    monkeypatch.setattr(scoring._quality, "compile_bank", compile_once)
    monkeypatch.setattr(scoring._quality, "_scan_document", scan_once)
    score_run = tmp_path / "score-run"
    receipt = scoring.score_enron_gold_audit_files(
        data["sample_run"],
        data["gold_run"],
        data["catalog_run"],
        data["bank"],
        score_run,
        promotion_checks=data["promotion_checks"],
        score_state_dir=data["score_state"],
        gold_state_dir=data["gold_state"],
        expected_gold_commitment=data["expected_gold_commitment"],
        text_view_descriptor=_text_view_descriptor(),
        allow_unignored_output=True,
    )
    assert calls == {"compile": 1, "scan": 100}
    predictions = [json.loads(line) for line in (score_run / "predictions.jsonl").read_text().splitlines()]
    assert scoring._quality.hash_enron_quality_predictions(predictions) == receipt["prediction_commitment"]
    assert receipt["counts"]["case_reasons"] == {
        "boundary_or_class_mismatch": 2,
        "certified_negative_document": 20,
        "false_negative": 1,
        "false_positive": 2,
        "true_positive_sample": 20,
        "wrong_canonical": 1,
    }
    assert _verify_score(data, score_run) == receipt
    assert calls == {"compile": 1, "scan": 100}


def test_support_failure_commits_terminal_run_before_compile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = _build_private_inputs(tmp_path)
    _apply_support_failure(data, "documents_below_minimum")
    _install_upstream(monkeypatch, data)
    compiled = False

    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        nonlocal compiled
        compiled = True
        raise AssertionError("quality preparation must not run")

    monkeypatch.setattr(scoring._quality, "prepare_enron_quality", forbidden)
    output = tmp_path / "score-run"
    receipt = scoring.score_enron_gold_audit_files(
        data["sample_run"],
        data["gold_run"],
        data["catalog_run"],
        data["bank"],
        output,
        promotion_checks=data["promotion_checks"],
        score_state_dir=data["score_state"],
        gold_state_dir=data["gold_state"],
        expected_gold_commitment=data["expected_gold_commitment"],
        text_view_descriptor=_text_view_descriptor(),
        allow_unignored_output=True,
    )
    assert compiled is False
    assert receipt["status"] == "insufficient_support"
    assert receipt["release"] == "do_not_ship"
    assert receipt["support_failure_codes"] == ["documents_below_minimum"]
    assert _verify_score(data, output) == receipt


@pytest.mark.parametrize(
    "failure_code",
    [
        "documents_below_minimum",
        "gold_spans_below_minimum",
        "negative_documents_below_minimum",
        "sensitive_characters_below_minimum",
        "contact_gold_support_missing",
        "person_gold_support_missing",
    ],
)
def test_each_support_floor_is_scan_free_terminal_and_tamper_evident(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure_code: str
) -> None:
    data = _build_private_inputs(tmp_path)
    _apply_support_failure(data, failure_code)
    _install_upstream(monkeypatch, data)
    monkeypatch.setattr(
        scoring._quality,
        "prepare_enron_quality",
        lambda *_args, **_kwargs: pytest.fail("insufficient support must not compile"),
    )
    output = tmp_path / "score-run"
    receipt = scoring.score_enron_gold_audit_files(
        data["sample_run"],
        data["gold_run"],
        data["catalog_run"],
        data["bank"],
        output,
        promotion_checks=data["promotion_checks"],
        score_state_dir=data["score_state"],
        gold_state_dir=data["gold_state"],
        expected_gold_commitment=data["expected_gold_commitment"],
        text_view_descriptor=_text_view_descriptor(),
        allow_unignored_output=True,
    )
    assert receipt["support_failure_codes"] == [failure_code]
    assert _verify_score(data, output) == receipt
    receipt_path = output / "receipt.json"
    tampered = json.loads(receipt_path.read_text())
    tampered["support_failure_codes"] = []
    receipt_path.write_bytes(_canonical(tampered))
    with pytest.raises(scoring.EnronAuditScoringError):
        _verify_score(data, output)


@pytest.mark.parametrize("artifact", ["predictions.jsonl", "cases.jsonl", "quality.json", "manifest.json"])
def test_score_verifier_rejects_tampered_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, artifact: str
) -> None:
    data, _receipt, score_run = _score(tmp_path, monkeypatch)
    path = score_run / artifact
    raw = path.read_bytes()
    path.write_bytes(raw + (b"{}\n" if artifact.endswith(".jsonl") else b" "))
    with pytest.raises(scoring.EnronAuditScoringError):
        _verify_score(data, score_run)


def test_score_verifier_rejects_reordered_predictions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data, _receipt, score_run = _score(tmp_path, monkeypatch)
    path = score_run / "predictions.jsonl"
    lines = path.read_bytes().splitlines(keepends=True)
    lines[0], lines[1] = lines[1], lines[0]
    path.write_bytes(b"".join(lines))
    with pytest.raises(scoring.EnronAuditScoringError):
        _verify_score(data, score_run)


def test_score_rejects_upstream_binding_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = _build_private_inputs(tmp_path)
    data["catalog_receipt"]["audit_output_binding_sha256"] = "sha256:" + "d" * 64
    _install_upstream(monkeypatch, data)
    with pytest.raises(scoring.EnronAuditScoringError, match="upstream binding"):
        scoring.score_enron_gold_audit_files(
            data["sample_run"],
            data["gold_run"],
            data["catalog_run"],
            data["bank"],
            tmp_path / "score-run",
            promotion_checks=data["promotion_checks"],
            score_state_dir=data["score_state"],
            gold_state_dir=data["gold_state"],
            expected_gold_commitment=data["expected_gold_commitment"],
            text_view_descriptor=_text_view_descriptor(),
            allow_unignored_output=True,
        )


def test_score_rejects_frozen_evaluator_drift_before_claim_or_compile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = _build_private_inputs(tmp_path)
    drifted = "sha256:" + "0" * 64
    data["gold_receipt"]["planned_evaluator_source_sha256"] = drifted
    data["catalog_receipt"]["planned_evaluator_source_sha256"] = drifted
    _install_upstream(monkeypatch, data)
    monkeypatch.setattr(
        scoring._quality,
        "prepare_enron_quality",
        lambda *_args, **_kwargs: pytest.fail("compile must not run"),
    )
    with pytest.raises(scoring.EnronAuditScoringError, match="evaluator"):
        scoring.score_enron_gold_audit_files(
            data["sample_run"],
            data["gold_run"],
            data["catalog_run"],
            data["bank"],
            tmp_path / "score-run",
            promotion_checks=data["promotion_checks"],
            score_state_dir=data["score_state"],
            gold_state_dir=data["gold_state"],
            expected_gold_commitment=data["expected_gold_commitment"],
            text_view_descriptor=_text_view_descriptor(),
            allow_unignored_output=True,
        )
    assert not list(data["score_state"].iterdir())


def test_score_requires_externally_trusted_gold_commitment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = _build_private_inputs(tmp_path)
    _install_upstream(monkeypatch, data)
    expected = copy.deepcopy(data["expected_gold_commitment"])
    expected["gold_sha256"] = "sha256:" + "0" * 64
    with pytest.raises(scoring.EnronAuditScoringError, match="trusted expected commitment"):
        scoring.score_enron_gold_audit_files(
            data["sample_run"],
            data["gold_run"],
            data["catalog_run"],
            data["bank"],
            tmp_path / "score-run",
            promotion_checks=data["promotion_checks"],
            score_state_dir=data["score_state"],
            gold_state_dir=data["gold_state"],
            expected_gold_commitment=expected,
            text_view_descriptor=_text_view_descriptor(),
            allow_unignored_output=True,
        )
    assert not list(data["score_state"].iterdir())


@pytest.mark.parametrize("mutation", ["changed", "missing", "duplicate", "weak", "mismatched"])
def test_score_rejects_invalid_frozen_thresholds_before_claim_or_compile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    data = _build_private_inputs(tmp_path)
    checks = copy.deepcopy(data["promotion_checks"])
    if mutation == "changed":
        checks[0]["threshold"] = 1
    elif mutation == "missing":
        checks.pop(0)
    elif mutation == "duplicate":
        duplicate = copy.deepcopy(checks[0])
        duplicate["threshold"] = 1
        checks.append(duplicate)
    elif mutation == "weak":
        target = next(item for item in checks if item["id"] == "open_world_recall")
        target["threshold"] = 0.90
    else:
        target = next(item for item in checks if item["id"] == "open_world_recall")
        target["operator"] = "lte"
    if mutation in {"weak", "mismatched"}:
        threshold_hash = hash_enron_thresholds(checks)
        data["gold_receipt"]["planned_thresholds_sha256"] = threshold_hash
        data["catalog_receipt"]["planned_thresholds_sha256"] = threshold_hash
    _install_upstream(monkeypatch, data)
    monkeypatch.setattr(
        scoring._quality,
        "prepare_enron_quality",
        lambda *_args, **_kwargs: pytest.fail("compile must not run"),
    )
    with pytest.raises(scoring.EnronAuditScoringError):
        scoring.score_enron_gold_audit_files(
            data["sample_run"],
            data["gold_run"],
            data["catalog_run"],
            data["bank"],
            tmp_path / "score-run",
            promotion_checks=checks,
            score_state_dir=data["score_state"],
            gold_state_dir=data["gold_state"],
            expected_gold_commitment=data["expected_gold_commitment"],
            text_view_descriptor=_text_view_descriptor(),
            allow_unignored_output=True,
        )
    assert not list(data["score_state"].iterdir())


def test_score_claim_allows_exactly_one_attempt_across_output_directories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data, _receipt, _score_run = _score(tmp_path, monkeypatch)
    monkeypatch.setattr(
        scoring._quality,
        "prepare_enron_quality",
        lambda *_args, **_kwargs: pytest.fail("second attempt must not compile"),
    )
    with pytest.raises(scoring.EnronAuditScoringError, match="sole score attempt"):
        scoring.score_enron_gold_audit_files(
            data["sample_run"],
            data["gold_run"],
            data["catalog_run"],
            data["bank"],
            tmp_path / "different-score-run",
            promotion_checks=data["promotion_checks"],
            score_state_dir=data["score_state"],
            gold_state_dir=data["gold_state"],
            expected_gold_commitment=data["expected_gold_commitment"],
            text_view_descriptor=_text_view_descriptor(),
            allow_unignored_output=True,
        )


def test_prediction_audit_accepts_complete_distinct_review_and_is_private(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data, score_receipt, score_run = _score(tmp_path, monkeypatch, quality_pass=True)
    reviews = _write_private_jsonl(tmp_path / "reviews.jsonl", _reviews_for(score_run))
    audit_run = tmp_path / "audit-run"
    receipt = _finalize_prediction_audit(data, score_receipt, score_run, reviews, audit_run)
    assert receipt["status"] == "accepted"
    assert receipt["decision_eligible"] is True
    assert receipt["release"] == "quality_eligible"
    assert receipt["counts"]["cases"] == score_receipt["counts"]["cases"]
    assert (
        scoring.verify_enron_prediction_audit(
            audit_run,
            score_run,
            data["gold_run"],
            sample_run_dir=data["sample_run"],
            catalog_run_dir=data["catalog_run"],
            bank=data["bank"],
            promotion_checks=data["promotion_checks"],
            score_state_dir=data["score_state"],
            gold_state_dir=data["gold_state"],
            expected_gold_commitment=data["expected_gold_commitment"],
            expected_score_receipt=score_receipt,
        )
        == receipt
    )
    encoded = json.dumps(receipt, sort_keys=True)
    assert "doc_000" not in encoded
    assert "prediction_reviewer" not in encoded
    assert '"start"' not in encoded


def test_prediction_audit_rejects_catalog_reviewer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data, score_receipt, score_run = _score(tmp_path, monkeypatch)
    reviews = _write_private_jsonl(
        tmp_path / "reviews.jsonl",
        _reviews_for(score_run, reviewer=data["catalog_reviewer_id"]),
    )
    with pytest.raises(scoring.EnronAuditScoringError, match="distinct"):
        _finalize_prediction_audit(data, score_receipt, score_run, reviews, tmp_path / "audit-run")


def test_prediction_audit_rejects_appended_prediction_before_review(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data, score_receipt, score_run = _score(tmp_path, monkeypatch)
    reviews = _write_private_jsonl(tmp_path / "reviews.jsonl", _reviews_for(score_run))
    prediction_path = score_run / "predictions.jsonl"
    prediction_payload = prediction_path.read_bytes()
    prediction_payload += prediction_payload.splitlines(keepends=True)[-1]
    prediction_path.write_bytes(prediction_payload)
    manifest_path = score_run / "manifest.json"
    receipt_path = score_run / "receipt.json"
    quality = json.loads((score_run / "quality.json").read_text())
    manifest = json.loads(manifest_path.read_text())
    manifest["artifacts"]["predictions"] = scoring._artifact_descriptor(
        "predictions.jsonl",
        prediction_payload,
        manifest["artifacts"]["predictions"]["records"] + 1,
    )
    manifest_path.write_bytes(_canonical(manifest))
    receipt_path.write_bytes(_canonical(scoring._score_receipt(manifest, quality)))
    with pytest.raises(scoring.EnronAuditScoringError):
        _finalize_prediction_audit(data, score_receipt, score_run, reviews, tmp_path / "audit-run")


def test_prediction_audit_quality_gate_failure_is_do_not_ship(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data, score_receipt, score_run = _score(tmp_path, monkeypatch)
    assert score_receipt["quality_decision"]["passed"] is False
    source = _write_private_jsonl(tmp_path / "reviews.jsonl", _reviews_for(score_run))
    receipt = _finalize_prediction_audit(data, score_receipt, score_run, source, tmp_path / "audit-run")
    assert receipt["status"] == "quality_gates_failed"
    assert receipt["decision_eligible"] is False
    assert receipt["release"] == "do_not_ship"


def test_prediction_audit_gold_defect_invalidates_without_mutating_score(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data, score_receipt, score_run = _score(tmp_path, monkeypatch)
    score_before = {path.name: path.read_bytes() for path in score_run.iterdir()}
    reviews = _reviews_for(score_run)
    reviews[0]["finding"] = "gold_defect"
    reviews[0]["reason_codes"] = ["incorrect_gold_span"]
    source = _write_private_jsonl(tmp_path / "reviews.jsonl", reviews)
    receipt = _finalize_prediction_audit(data, score_receipt, score_run, source, tmp_path / "audit-run")
    assert receipt["status"] == "invalidated_gold_defect"
    assert receipt["decision_eligible"] is False
    assert receipt["release"] == "do_not_ship"
    assert score_before == {path.name: path.read_bytes() for path in score_run.iterdir()}


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "unknown", "overlap", "unresolved"])
def test_prediction_audit_rejects_incomplete_or_nonindependent_reviews_atomically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    data, score_receipt, score_run = _score(tmp_path, monkeypatch)
    reviews = _reviews_for(score_run)
    if mutation == "missing":
        reviews.pop()
    elif mutation == "duplicate":
        reviews[-1] = copy.deepcopy(reviews[0])
    elif mutation == "unknown":
        reviews[0]["case_id"] = "sha256:" + "f" * 64
    elif mutation == "overlap":
        for row in reviews:
            row["reviewer_id"] = "pass_a"
    else:
        reviews[0]["unresolved"] = ["needs_followup"]
    source = _write_private_jsonl(tmp_path / "reviews.jsonl", reviews)
    output = tmp_path / "audit-run"
    with pytest.raises(scoring.EnronAuditScoringError):
        _finalize_prediction_audit(data, score_receipt, score_run, source, output)
    assert not output.exists()

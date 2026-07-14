from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

from nerb.enron_gold_annotations import (
    ADJUDICATION_SCHEMA_VERSION,
    ANNOTATION_PASS_SCHEMA_VERSION,
    ANNOTATION_REVIEW_SCHEMA_VERSION,
    EnronGoldAnnotationError,
    build_enron_gold,
    enron_gold_annotation_policy_sha256,
    finalize_enron_gold_annotations_files,
    public_enron_gold_receipt,
    verify_enron_gold_annotations,
)
from nerb.enron_private_io import PrivateRun
from nerb.enron_sealed_audit import make_enron_sealed_audit_plan, select_enron_sealed_audit_sample


def _hash_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


def _documents(count: int = 5) -> list[dict[str, object]]:
    text = "Alice emailed bob@example.com."
    return [
        {
            "document_id": f"doc_{index}",
            "text": text,
            "text_sha256": _hash_text(text),
            "unicode_scalars": len(text),
            "stratum": "ignored_private_capture_metadata",
        }
        for index in range(count)
    ]


def _spans() -> list[dict[str, object]]:
    return [
        {"entity_class": "person", "start": 0, "end": 5},
        {"entity_class": "contact", "start": 14, "end": 29},
    ]


def _passes(documents, reviewer: str) -> list[dict[str, object]]:
    return [
        {
            "schema_version": ANNOTATION_PASS_SCHEMA_VERSION,
            "document_id": document["document_id"],
            "text_sha256": document["text_sha256"],
            "reviewer_id": reviewer,
            "coverage": [{"start": 0, "end": document["unicode_scalars"]}],
            "spans": _spans(),
            "unresolved": [],
        }
        for document in documents
    ]


def _adjudications(documents) -> list[dict[str, object]]:
    return [
        {
            "schema_version": ADJUDICATION_SCHEMA_VERSION,
            "document_id": document["document_id"],
            "text_sha256": document["text_sha256"],
            "adjudicator_id": "adjudicator",
            "spans": _spans(),
            "decisions": [],
            "unresolved": [],
        }
        for document in documents
    ]


def _agreement_audit_ids(
    documents: list[dict[str, object]],
    agreement_document_ids: set[str] | None = None,
) -> set[str]:
    binding = {
        "schema_version": "nerb.enron_gold_sample_binding",
        "documents": [
            {
                "document_id": document["document_id"],
                "text_sha256": document["text_sha256"],
                "unicode_scalars": document["unicode_scalars"],
            }
            for document in sorted(documents, key=lambda row: str(row["document_id"]))
        ],
    }
    binding_sha256 = (
        "sha256:" + hashlib.sha256(json.dumps(binding, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    )
    eligible = (
        {str(document["document_id"]) for document in documents}
        if agreement_document_ids is None
        else agreement_document_ids
    )
    ranked = sorted(
        eligible,
        key=lambda document_id: (
            hashlib.sha256(
                ("nerb/enron/gold-agreement-review\0" + binding_sha256 + "\0" + document_id).encode()
            ).digest(),
            document_id,
        ),
    )
    required_count = (len(eligible) + 4) // 5
    return set(ranked[:required_count])


def _reviews(
    documents: list[dict[str, object]],
    *,
    agreement_audit: bool = True,
    agreement_document_ids: set[str] | None = None,
) -> list[dict[str, object]]:
    audited = _agreement_audit_ids(documents, agreement_document_ids) if agreement_audit else set()
    return [
        {
            "schema_version": ANNOTATION_REVIEW_SCHEMA_VERSION,
            "document_id": document["document_id"],
            "text_sha256": document["text_sha256"],
            "reviewer_id": "independent_reviewer",
            "disagreements_reviewed": True,
            "agreement_audit": document["document_id"] in audited,
            "status": "accepted",
            "unresolved": [],
        }
        for document in documents
    ]


def _valid_inputs():
    documents = _documents()
    return (
        documents,
        _passes(documents, "pass_a"),
        _passes(documents, "pass_b"),
        _adjudications(documents),
        _reviews(documents),
    )


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _sample_pair(index: int) -> tuple[dict[str, Any], dict[str, Any]]:
    text = "Alice emailed bob@example.com."
    document_id = f"doc_{index:064x}"
    return (
        {"document_id": document_id, "views": {"subject_current_body": text}},
        {
            "schema_version": "nerb.enron_split_membership.v2",
            "document_id": document_id,
            "group_id": "sha256:" + f"{index:064x}",
            "role": "test",
            "occurrence_count": 1,
            "temporal": {"eligible": True, "status": "valid", "anchor_utc": "2001-01-01T00:00:00Z"},
            "mailbox": "inbox",
            "mailbox_recurrence": "known",
            "size": "1-255",
            "group_size": "1",
            "identities": {"recurrence": "all_known", "count": 1, "contains_frequency": ["head"]},
            "views": {"natural": True, "structured": True},
            "challenges": [],
        },
    )


def _sample_run(tmp_path: Path, count: int = 5) -> tuple[Path, list[dict[str, Any]]]:
    sha = "sha256:" + "a" * 64
    plan = make_enron_sealed_audit_plan(
        sample_size=count,
        frame_documents=count,
        frame_groups=count,
        test_artifact_sha256=sha,
        membership_artifact_sha256=sha,
        split_manifest_sha256=sha,
        split_policy_sha256=sha,
        frozen_git_commit="b" * 40,
        bank_sha256=sha,
        evaluator_source_sha256=sha,
        thresholds_sha256=sha,
        performance_manifest_sha256=sha,
        annotation_policy_sha256=enron_gold_annotation_policy_sha256(),
        catalog_policy_sha256=sha,
        fixture_mode=True,
    )
    selected, receipt = select_enron_sealed_audit_sample([_sample_pair(index) for index in range(count)], plan)
    sample_dir = tmp_path / "sample-run"
    with PrivateRun(sample_dir, allow_unignored_output=True) as run:
        with run.open_binary("plan.json") as file:
            file.write(_canonical(plan))
        with run.open_binary("documents.jsonl") as file:
            for row in selected:
                file.write(_canonical(row))
        with run.open_binary("receipt.json") as file:
            file.write(_canonical(receipt))
        run.commit()
    return sample_dir, [dict(row) for row in selected]


def _write_private_jsonl(path: Path, rows: list[dict[str, Any]]) -> Path:
    path.write_bytes(b"".join(_canonical(row) for row in rows))
    path.chmod(0o600)
    return path


def _file_inputs(tmp_path: Path) -> tuple[Path, Path, Path, Path, Path, list[dict[str, Any]]]:
    sample_dir, documents = _sample_run(tmp_path)
    return (
        sample_dir,
        _write_private_jsonl(tmp_path / "pass-a.jsonl", _passes(documents, "pass_a")),
        _write_private_jsonl(tmp_path / "pass-b.jsonl", _passes(documents, "pass_b")),
        _write_private_jsonl(tmp_path / "adjudications.jsonl", _adjudications(documents)),
        _write_private_jsonl(tmp_path / "reviews.jsonl", _reviews(documents)),
        documents,
    )


def test_build_enron_gold_requires_two_blind_passes_and_emits_no_text_or_surfaces() -> None:
    gold = build_enron_gold(*_valid_inputs())

    assert gold["annotation_policy_sha256"] == enron_gold_annotation_policy_sha256()
    assert gold["counts"] == {
        "documents": 5,
        "documents_with_sensitive_gold": 5,
        "negative_documents": 0,
        "gold_spans": 10,
        "sensitive_gold_characters": 100,
        "by_class": {
            "contact": {
                "documents_with_sensitive_gold": 5,
                "negative_documents": 0,
                "gold_spans": 5,
                "sensitive_gold_characters": 75,
            },
            "person": {
                "documents_with_sensitive_gold": 5,
                "negative_documents": 0,
                "gold_spans": 5,
                "sensitive_gold_characters": 25,
            },
        },
    }
    encoded = json.dumps(gold, sort_keys=True)
    assert "Alice" not in encoded
    assert "bob@example.com" not in encoded
    assert "string" not in encoded


def test_public_gold_receipt_removes_document_ids_and_span_coordinates() -> None:
    gold = build_enron_gold(*_valid_inputs())
    receipt = public_enron_gold_receipt(gold)

    assert receipt["counts"] == gold["counts"]
    assert receipt["privacy"] == {
        "raw_text_included": False,
        "document_ids_included": False,
        "span_surfaces_included": False,
        "private_paths_included": False,
    }
    encoded = json.dumps(receipt, sort_keys=True)
    assert "doc_" not in encoded
    assert '"start"' not in encoded
    assert '"end"' not in encoded


def test_build_enron_gold_rejects_reviewer_identity_reuse() -> None:
    documents, first, _second, adjudications, reviews = _valid_inputs()
    second = _passes(documents, "pass_a")

    with pytest.raises(EnronGoldAnnotationError, match="distinct reviewer"):
        build_enron_gold(documents, first, second, adjudications, reviews)


def test_build_enron_gold_rejects_incomplete_character_coverage() -> None:
    documents, first, second, adjudications, reviews = _valid_inputs()
    first[0]["coverage"] = [{"start": 0, "end": documents[0]["unicode_scalars"] - 1}]

    with pytest.raises(EnronGoldAnnotationError, match="complete character coverage"):
        build_enron_gold(documents, first, second, adjudications, reviews)


def test_build_enron_gold_requires_each_disagreement_to_be_explained_and_reviewed() -> None:
    documents, first, second, adjudications, reviews = _valid_inputs()
    second[0]["spans"] = [second[0]["spans"][1]]

    with pytest.raises(EnronGoldAnnotationError, match="exactly explain"):
        build_enron_gold(documents, first, second, adjudications, reviews)

    adjudications[0]["decisions"] = [
        {
            "entity_class": "person",
            "start": 0,
            "end": 5,
            "resolution": "include",
            "reason_code": "confirmed_person",
        }
    ]
    agreement_ids = {str(document["document_id"]) for document in documents[1:]}
    reviews = _reviews(documents, agreement_document_ids=agreement_ids)
    reviews[0]["disagreements_reviewed"] = False
    with pytest.raises(EnronGoldAnnotationError, match="disagreement"):
        build_enron_gold(documents, first, second, adjudications, reviews)

    reviews[0]["disagreements_reviewed"] = True
    gold = build_enron_gold(documents, first, second, adjudications, reviews)
    assert gold["provenance"]["disagreements"] == 1
    assert gold["provenance"]["adjudication_decisions"] == 1


def test_build_enron_gold_requires_deterministic_twenty_percent_agreement_audit() -> None:
    documents, first, second, adjudications, reviews = _valid_inputs()
    for review in reviews:
        review["agreement_audit"] = False

    with pytest.raises(EnronGoldAnnotationError, match="20% agreement audit"):
        build_enron_gold(documents, first, second, adjudications, reviews)


@pytest.mark.parametrize("forbidden", ["predictions", "matches", "gold_spans", "labels"])
def test_build_enron_gold_rejects_prediction_or_label_fields_in_sample(forbidden: str) -> None:
    documents, first, second, adjudications, reviews = _valid_inputs()
    contaminated = copy.deepcopy(documents)
    contaminated[0][forbidden] = []

    with pytest.raises(EnronGoldAnnotationError, match="predictions or labels"):
        build_enron_gold(contaminated, first, second, adjudications, reviews)


def test_build_enron_gold_rejects_person_nested_inside_contact() -> None:
    documents, first, second, adjudications, reviews = _valid_inputs()
    nested = [
        {"entity_class": "person", "start": 14, "end": 17},
        {"entity_class": "contact", "start": 14, "end": 29},
    ]
    for rows in (first, second):
        rows[0]["spans"] = copy.deepcopy(nested)
    adjudications[0]["spans"] = copy.deepcopy(nested)

    with pytest.raises(EnronGoldAnnotationError, match="nested"):
        build_enron_gold(documents, first, second, adjudications, reviews)


def test_build_enron_gold_rejects_any_cross_class_overlap() -> None:
    documents, first, second, adjudications, reviews = _valid_inputs()
    crossing = [
        {"entity_class": "person", "start": 0, "end": 15},
        {"entity_class": "contact", "start": 14, "end": 29},
    ]
    for rows in (first, second):
        rows[0]["spans"] = copy.deepcopy(crossing)
    adjudications[0]["spans"] = copy.deepcopy(crossing)

    with pytest.raises(EnronGoldAnnotationError, match="different entity classes"):
        build_enron_gold(documents, first, second, adjudications, reviews)


def test_file_finalizer_commits_canonical_private_bundle_and_deep_verifies(tmp_path: Path) -> None:
    sample_dir, first, second, adjudications, reviews, _documents_value = _file_inputs(tmp_path)
    output = tmp_path / "gold-run"

    result = finalize_enron_gold_annotations_files(
        sample_dir,
        first,
        second,
        adjudications,
        reviews,
        output,
        allow_unignored_output=True,
    )
    verified = verify_enron_gold_annotations(output, sample_dir)

    assert result == verified
    assert result["valid"] is True
    assert result["fixture_mode"] is True
    assert result["promotable"] is False
    assert result["counts"]["documents"] == 5
    assert set(path.name for path in output.iterdir()) == {
        "COMMITTED",
        "pass-a.jsonl",
        "pass-b.jsonl",
        "adjudication.jsonl",
        "review.jsonl",
        "gold.jsonl",
        "manifest.json",
        "receipt.json",
    }
    assert os.stat(output).st_mode & 0o777 == 0o700
    assert all(os.stat(path).st_mode & 0o777 == 0o600 for path in output.iterdir())


def test_file_verifier_rejects_tampered_canonical_artifact(tmp_path: Path) -> None:
    sample_dir, first, second, adjudications, reviews, _documents_value = _file_inputs(tmp_path)
    output = tmp_path / "gold-run"
    finalize_enron_gold_annotations_files(
        sample_dir,
        first,
        second,
        adjudications,
        reviews,
        output,
        allow_unignored_output=True,
    )
    pass_a = output / "pass-a.jsonl"
    pass_a.write_bytes(pass_a.read_bytes().replace(b'"reviewer_id":"pass_a"', b'"reviewer_id":"intruder"', 1))

    with pytest.raises(EnronGoldAnnotationError):
        verify_enron_gold_annotations(output, sample_dir)


def test_file_finalizer_is_atomic_when_annotation_input_is_incomplete(tmp_path: Path) -> None:
    sample_dir, first, second, adjudications, reviews, _documents_value = _file_inputs(tmp_path)
    review_rows = [json.loads(line) for line in reviews.read_text().splitlines()]
    _write_private_jsonl(reviews, review_rows[:-1])
    output = tmp_path / "gold-run"

    with pytest.raises(EnronGoldAnnotationError, match="cover every sampled document"):
        finalize_enron_gold_annotations_files(
            sample_dir,
            first,
            second,
            adjudications,
            reviews,
            output,
            allow_unignored_output=True,
        )

    assert not output.exists()
    assert not tuple(tmp_path.glob(".gold-run.stage-*"))


def test_file_workflow_returns_only_aggregate_commitments(tmp_path: Path) -> None:
    sample_dir, first, second, adjudications, reviews, documents = _file_inputs(tmp_path)
    output = tmp_path / "secret-output-name"
    result = finalize_enron_gold_annotations_files(
        sample_dir,
        first,
        second,
        adjudications,
        reviews,
        output,
        allow_unignored_output=True,
    )
    encoded = json.dumps(result, sort_keys=True)

    assert all(document["document_id"] not in encoded and document["text"] not in encoded for document in documents)
    assert '"pass_a"' not in encoded
    assert '"independent_reviewer"' not in encoded
    assert str(output) not in encoded
    assert '"start"' not in encoded
    assert '"end"' not in encoded
    assert result["privacy"] == {
        "aggregate_only": True,
        "raw_text_included": False,
        "document_ids_included": False,
        "reviewer_ids_included": False,
        "span_coordinates_included": False,
        "span_surfaces_included": False,
        "private_paths_included": False,
    }

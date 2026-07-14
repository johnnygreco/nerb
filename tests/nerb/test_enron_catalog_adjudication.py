from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

from nerb.bank import hash_bank
from nerb.engine import Bank
from nerb.enron_catalog_adjudication import (
    CATALOG_REVIEW_SCHEMA_VERSION,
    EnronCatalogAdjudicationError,
    _load_verified_enron_catalog_qualification_files,
    enron_catalog_qualification_policy_sha256,
    finalize_enron_catalog_qualification_files,
    public_enron_catalog_receipt,
    qualify_enron_gold_catalog,
    verify_enron_catalog_qualification,
)
from nerb.enron_gold_annotations import (
    ADJUDICATION_SCHEMA_VERSION,
    ANNOTATION_PASS_SCHEMA_VERSION,
    ANNOTATION_REVIEW_SCHEMA_VERSION,
    build_enron_gold,
    enron_gold_annotation_policy_sha256,
    finalize_enron_gold_annotations_files,
    hash_enron_gold_adjudication,
)
from nerb.enron_private_io import PrivateRun
from nerb.enron_sealed_audit import make_enron_sealed_audit_plan, select_enron_sealed_audit_sample

GENERIC_EMAIL_REGEX = (
    r"(?i)\b[a-z0-9_][a-z0-9.!#$%&'*+/=?^_`{|}~-]*@"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\b"
)


def _literal(value: str, priority: int, *, boundaries: str = "word") -> dict[str, Any]:
    return {
        "kind": "literal",
        "value": value,
        "description": "Catalog qualification fixture literal.",
        "status": "active",
        "priority": priority,
        "case_sensitive": False,
        "normalize_whitespace": True,
        "left_boundary": boundaries,
        "right_boundary": boundaries,
        "metadata": {},
    }


def _regex(value: str, priority: int) -> dict[str, Any]:
    return {
        "kind": "regex",
        "value": value,
        "description": "Catalog qualification fixture regex.",
        "status": "active",
        "priority": priority,
        "regex_flags": [],
        "metadata": {},
    }


def _name(canonical: str, patterns: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "canonical": canonical,
        "description": "Catalog qualification fixture name.",
        "status": "active",
        "patterns": patterns,
        "metadata": {},
    }


def _bank() -> dict[str, Any]:
    return {
        "schema_version": "nerb.bank.v1",
        "id": "catalog_fixture",
        "name": "Catalog fixture",
        "description": "Independent catalog qualification fixture.",
        "version": "fixture",
        "status": "active",
        "created_at": "2026-07-14T00:00:00Z",
        "updated_at": "2026-07-14T00:00:00Z",
        "unicode_normalization": "none",
        "default_regex_flags": [],
        "entities": {
            "person": {
                "description": "People.",
                "status": "active",
                "regex_flags": [],
                "names": {
                    "alice": _name("Alice", {"primary": _literal("Alice", 10)}),
                    "lower_priority_alice": _name("Other Alice", {"alias": _literal("Alice", 20)}),
                },
                "metadata": {},
            },
            "contact": {
                "description": "Contacts.",
                "status": "active",
                "regex_flags": [],
                "names": {
                    "bob": _name("Bob", {"primary": _literal("bob@example.com", 10)}),
                    "generic_email": _name(
                        "Email address",
                        {"fallback": _regex(GENERIC_EMAIL_REGEX, 100)},
                    ),
                },
                "metadata": {},
            },
        },
        "metadata": {},
    }


def _hash_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


def _gold_for(text: str, spans: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    document = {
        "document_id": "doc_1",
        "text": text,
        "text_sha256": _hash_text(text),
        "unicode_scalars": len(text),
    }
    annotation = {
        "schema_version": ANNOTATION_PASS_SCHEMA_VERSION,
        "document_id": "doc_1",
        "text_sha256": document["text_sha256"],
        "reviewer_id": "pass_a",
        "coverage": [{"start": 0, "end": len(text)}],
        "spans": spans,
        "unresolved": [],
    }
    second = {**copy.deepcopy(annotation), "reviewer_id": "pass_b"}
    adjudication = {
        "schema_version": ADJUDICATION_SCHEMA_VERSION,
        "document_id": "doc_1",
        "text_sha256": document["text_sha256"],
        "adjudicator_id": "adjudicator",
        "spans": copy.deepcopy(spans),
        "decisions": [],
        "unresolved": [],
    }
    review = {
        "schema_version": ANNOTATION_REVIEW_SCHEMA_VERSION,
        "document_id": "doc_1",
        "text_sha256": document["text_sha256"],
        "reviewer_id": "reviewer",
        "adjudication_sha256": hash_enron_gold_adjudication(adjudication),
        "disagreements_reviewed": True,
        "agreement_audit": True,
        "status": "accepted",
        "unresolved": [],
    }
    gold = build_enron_gold([document], [annotation], [second], [adjudication], [review])
    return [document], gold


def _rust_exact_match(bank: dict[str, Any], text: str, entity_class: str, start: int, end: int) -> bool:
    compiled = Bank.from_source_bytes(
        json.dumps(bank).encode(),
        format_hint="json",
        use_cache=False,
    )
    return any(
        record["entity"] == entity_class and record["start"] == start and record["end"] == end
        for record in compiled.scan_text(text, offsets="char")
    )


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _write_private_jsonl(path: Path, rows: list[dict[str, Any]]) -> Path:
    path.write_bytes(b"".join(_canonical(row) for row in rows))
    path.chmod(0o600)
    return path


def _catalog_reviews(
    documents: list[dict[str, Any]],
    gold: dict[str, Any],
    bank: dict[str, Any],
    *,
    reviewer_id: str = "catalog_reviewer",
) -> list[dict[str, Any]]:
    qualification = qualify_enron_gold_catalog(bank, documents, gold)
    decisions_by_document = {str(document["document_id"]): [] for document in documents}
    for binding in qualification["bindings"]:
        decisions_by_document[str(binding["document_id"])].append(
            {key: copy.deepcopy(binding[key]) for key in ("entity_class", "start", "end", "catalog_identity")}
        )
    return [
        {
            "schema_version": CATALOG_REVIEW_SCHEMA_VERSION,
            "document_id": document["document_id"],
            "text_sha256": document["text_sha256"],
            "bank_sha256": qualification["bank_sha256"],
            "gold_sha256": qualification["gold_sha256"],
            "reviewer_id": reviewer_id,
            "decisions": decisions_by_document[str(document["document_id"])],
            "unresolved": [],
        }
        for document in documents
    ]


def _qualification_runs(
    tmp_path: Path,
    *,
    catalog_policy_sha256: str | None = None,
    fixture_mode: bool = True,
) -> tuple[Path, Path, dict[str, Any], list[dict[str, Any]], Path, dict[str, str], str]:
    bank = _bank()
    text = "Alice <bob@example.com> Unknown"
    document_id = "doc_" + "1" * 64
    record = {"document_id": document_id, "views": {"subject_current_body": text}}
    membership = {
        "schema_version": "nerb.enron_split_membership.v2",
        "document_id": document_id,
        "group_id": "sha256:" + "2" * 64,
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
    }
    sha = "sha256:" + "3" * 64
    plan = make_enron_sealed_audit_plan(
        sample_size=1,
        frame_documents=1,
        frame_groups=1,
        test_artifact_sha256=sha,
        membership_artifact_sha256=sha,
        split_manifest_sha256=sha,
        split_policy_sha256=sha,
        frozen_git_commit="4" * 40,
        bank_sha256=hash_bank(bank),
        evaluator_source_sha256=sha,
        thresholds_sha256=sha,
        performance_manifest_sha256=sha,
        annotation_policy_sha256=enron_gold_annotation_policy_sha256(),
        catalog_policy_sha256=(catalog_policy_sha256 or enron_catalog_qualification_policy_sha256()),
        fixture_mode=fixture_mode,
    )
    documents, sample_receipt = select_enron_sealed_audit_sample([(record, membership)], plan)
    sample_run = tmp_path / "sample-run"
    with PrivateRun(sample_run, allow_unignored_output=True) as run:
        with run.open_binary("plan.json") as file:
            file.write(_canonical(plan))
        with run.open_binary("documents.jsonl") as file:
            file.write(b"".join(_canonical(row) for row in documents))
        with run.open_binary("receipt.json") as file:
            file.write(_canonical(sample_receipt))
        run.commit()

    spans = [
        {"entity_class": "person", "start": 0, "end": 5},
        {"entity_class": "contact", "start": 7, "end": 22},
        {"entity_class": "person", "start": 24, "end": 31},
    ]
    pass_a = [
        {
            "schema_version": ANNOTATION_PASS_SCHEMA_VERSION,
            "document_id": document_id,
            "text_sha256": documents[0]["text_sha256"],
            "reviewer_id": "pass_a",
            "coverage": [{"start": 0, "end": len(text)}],
            "spans": copy.deepcopy(spans),
            "unresolved": [],
        }
    ]
    pass_b = [{**copy.deepcopy(pass_a[0]), "reviewer_id": "pass_b"}]
    adjudication = [
        {
            "schema_version": ADJUDICATION_SCHEMA_VERSION,
            "document_id": document_id,
            "text_sha256": documents[0]["text_sha256"],
            "adjudicator_id": "adjudicator",
            "spans": copy.deepcopy(spans),
            "decisions": [],
            "unresolved": [],
        }
    ]
    review = [
        {
            "schema_version": ANNOTATION_REVIEW_SCHEMA_VERSION,
            "document_id": document_id,
            "text_sha256": documents[0]["text_sha256"],
            "reviewer_id": "reviewer",
            "adjudication_sha256": hash_enron_gold_adjudication(adjudication[0]),
            "disagreements_reviewed": True,
            "agreement_audit": True,
            "status": "accepted",
            "unresolved": [],
        }
    ]
    gold_run = tmp_path / "gold-run"
    gold_receipt = finalize_enron_gold_annotations_files(
        sample_run,
        _write_private_jsonl(tmp_path / "pass-a.jsonl", pass_a),
        _write_private_jsonl(tmp_path / "pass-b.jsonl", pass_b),
        _write_private_jsonl(tmp_path / "adjudication.jsonl", adjudication),
        _write_private_jsonl(tmp_path / "review.jsonl", review),
        gold_run,
        expected_audit_output_binding_sha256=(
            None if fixture_mode else str(sample_receipt["audit_output_binding_sha256"])
        ),
        allow_unignored_output=True,
    )
    private_documents = [dict(row) for row in documents]
    gold = build_enron_gold(private_documents, pass_a, pass_b, adjudication, review)
    catalog_review_path = _write_private_jsonl(
        tmp_path / "catalog-review.jsonl",
        _catalog_reviews(private_documents, gold, bank),
    )
    gold_commitment = {key: str(gold_receipt[key]) for key in ("gold_sha256", "manifest_sha256", "artifacts_sha256")}
    return (
        sample_run,
        gold_run,
        bank,
        private_documents,
        catalog_review_path,
        gold_commitment,
        str(sample_receipt["audit_output_binding_sha256"]),
    )


def test_catalog_qualification_uses_active_definitions_without_predictions() -> None:
    text = "Alice <bob@example.com> Unknown"
    documents, gold = _gold_for(
        text,
        [
            {"entity_class": "person", "start": 0, "end": 5},
            {"entity_class": "contact", "start": 7, "end": 22},
            {"entity_class": "person", "start": 24, "end": 31},
        ],
    )

    result = qualify_enron_gold_catalog(_bank(), documents, gold)

    identities = [binding["catalog_identity"] for binding in result["bindings"]]
    assert identities == [
        {"entity_id": "person", "name_id": "alice", "pattern_id": "primary"},
        {"entity_id": "contact", "name_id": "bob", "pattern_id": "primary"},
        None,
    ]
    assert result["counts"]["gold_spans"] == 3
    assert result["counts"]["cataloged_gold_spans"] == 2
    assert result["policy_sha256"] == enron_catalog_qualification_policy_sha256()
    assert "prediction" not in json.dumps(result, sort_keys=True).casefold()


def test_catalog_qualification_uses_generic_email_fallback_for_unknown_contact() -> None:
    text = "unknown@example.net"
    documents, gold = _gold_for(text, [{"entity_class": "contact", "start": 0, "end": len(text)}])

    result = qualify_enron_gold_catalog(_bank(), documents, gold)

    assert result["bindings"][0]["catalog_identity"] == {
        "entity_id": "contact",
        "name_id": "generic_email",
        "pattern_id": "fallback",
    }


def test_catalog_literal_qualification_observes_actual_context_boundaries() -> None:
    text = "XAlice"
    documents, gold = _gold_for(text, [{"entity_class": "person", "start": 1, "end": 6}])

    result = qualify_enron_gold_catalog(_bank(), documents, gold)

    assert result["bindings"][0]["catalog_identity"] is None


def test_catalog_public_receipt_is_aggregate_only() -> None:
    text = "Alice"
    documents, gold = _gold_for(text, [{"entity_class": "person", "start": 0, "end": 5}])
    result = qualify_enron_gold_catalog(_bank(), documents, gold)

    receipt = public_enron_catalog_receipt(result)
    encoded = json.dumps(receipt, sort_keys=True)

    assert receipt["catalog_coverage"] == 1.0
    assert "doc_1" not in encoded
    assert "alice" not in encoded.casefold()
    assert '"start"' not in encoded
    assert receipt["privacy"]["catalog_identities_included"] is False


def test_catalog_qualification_rejects_unsupported_independent_regex() -> None:
    bank = _bank()
    bank["entities"]["contact"]["names"]["generic_email"]["patterns"]["fallback"]["value"] = r"(?-u:\b)x"
    documents, gold = _gold_for("x", [{"entity_class": "contact", "start": 0, "end": 1}])

    with pytest.raises(EnronCatalogAdjudicationError, match="unsupported"):
        qualify_enron_gold_catalog(bank, documents, gold)


def test_catalog_qualification_rejects_tampered_gold_commitment() -> None:
    documents, gold = _gold_for("Alice", [{"entity_class": "person", "start": 0, "end": 5}])
    gold["counts"]["gold_spans"] += 1

    with pytest.raises(EnronCatalogAdjudicationError, match="commitment"):
        qualify_enron_gold_catalog(_bank(), documents, gold)


@pytest.mark.parametrize(
    ("pattern", "surface", "boundaries", "expected"),
    [
        ("straße", "straße", "none", True),
        ("straße", "STRASSE", "none", False),
        ("kelvin", "KELVIN", "none", True),
        ("sam", "ſAM", "none", True),
        ("Alice", "\N{COMBINING ACUTE ACCENT}Alice", "word", False),
    ],
)
def test_conservative_literal_qualification_matches_rust_subset(
    pattern: str,
    surface: str,
    boundaries: str,
    expected: bool,
) -> None:
    bank = _bank()
    bank["entities"]["person"]["names"] = {
        "candidate": _name("Candidate", {"primary": _literal(pattern, 1, boundaries=boundaries)})
    }
    start = 1 if surface.startswith("\N{COMBINING ACUTE ACCENT}") else 0
    end = len(surface)
    documents, gold = _gold_for(surface, [{"entity_class": "person", "start": start, "end": end}])

    qualified = qualify_enron_gold_catalog(bank, documents, gold)["bindings"][0]["catalog_identity"] is not None

    assert qualified is expected
    assert qualified is _rust_exact_match(bank, surface, "person", start, end)


@pytest.mark.parametrize(
    ("text", "start", "end", "expected"),
    [
        ("—Alice", 1, 6, True),
        ("-Alice", 1, 6, True),
        ("xAlice", 1, 6, False),
        ("éAlice", 1, 6, False),
        ("\N{COMBINING ACUTE ACCENT}Alice", 1, 6, False),
        ("\N{ARABIC-INDIC DIGIT ONE}Alice", 1, 6, False),
        ("\N{UNDERTIE}Alice", 1, 6, False),
        ("\N{ZERO WIDTH NON-JOINER}Alice", 1, 6, False),
        ("\N{ZERO WIDTH JOINER}Alice", 1, 6, False),
        ("Alice—", 0, 5, True),
    ],
)
def test_unicode_word_boundaries_match_rust_regex_syntax(
    text: str,
    start: int,
    end: int,
    expected: bool,
) -> None:
    bank = _bank()
    bank["entities"]["person"]["names"] = {"candidate": _name("Candidate", {"primary": _literal("Alice", 1)})}
    documents, gold = _gold_for(text, [{"entity_class": "person", "start": start, "end": end}])

    qualified = qualify_enron_gold_catalog(bank, documents, gold)["bindings"][0]["catalog_identity"] is not None

    assert qualified is expected
    assert qualified is _rust_exact_match(bank, text, "person", start, end)


def test_production_email_regex_qualification_matches_rust() -> None:
    text = "<unknown@example.net>"
    start = 1
    end = len(text) - 1
    documents, gold = _gold_for(text, [{"entity_class": "contact", "start": start, "end": end}])
    bank = _bank()

    qualified = qualify_enron_gold_catalog(bank, documents, gold)["bindings"][0]["catalog_identity"] is not None

    assert qualified is True
    assert qualified is _rust_exact_match(bank, text, "contact", start, end)


def test_catalog_qualification_rejects_ambiguous_priority_ties() -> None:
    bank = _bank()
    bank["entities"]["person"]["names"]["lower_priority_alice"]["patterns"]["alias"]["priority"] = 10
    documents, gold = _gold_for("Alice", [{"entity_class": "person", "start": 0, "end": 5}])

    with pytest.raises(EnronCatalogAdjudicationError, match="priorities must be unique"):
        qualify_enron_gold_catalog(bank, documents, gold)


def test_catalog_file_finalizer_commits_and_replays_mapping_or_path(tmp_path: Path) -> None:
    sample_run, gold_run, bank, _documents_value, catalog_review, gold_commitment, _audit_binding = _qualification_runs(
        tmp_path
    )
    output = tmp_path / "catalog-run"
    result = finalize_enron_catalog_qualification_files(
        sample_run,
        gold_run,
        bank,
        catalog_review,
        output,
        expected_gold_commitment=gold_commitment,
        allow_unignored_output=True,
    )
    bank_path = tmp_path / "bank.json"
    bank_path.write_bytes(_canonical(bank))

    verified = verify_enron_catalog_qualification(
        output,
        sample_run,
        gold_run,
        bank_path,
        expected_gold_commitment=gold_commitment,
    )
    bindings, catalog_reviewer_id, loaded_receipt = _load_verified_enron_catalog_qualification_files(
        output,
        sample_run,
        gold_run,
        bank_path,
        expected_gold_commitment=gold_commitment,
    )

    assert result == verified
    assert loaded_receipt == verified
    assert catalog_reviewer_id == "catalog_reviewer"
    assert len(bindings) == 3
    assert result["counts"]["gold_spans"] == 3
    assert result["counts"]["cataloged_gold_spans"] == 2
    assert result["catalog_coverage"] == 2 / 3
    assert result["review_provenance"]["decisions_reviewed"] == 3
    assert result["review_provenance"]["reviewers"] == 1
    assert result["unresolved"] == 0
    assert result["trusted_gold_commitment"] == gold_commitment
    assert result["planned_evaluator_source_sha256"] == "sha256:" + "3" * 64
    assert result["planned_thresholds_sha256"] == "sha256:" + "3" * 64
    assert all(
        isinstance(result[field], str) and result[field].startswith("sha256:")
        for field in (
            "manifest_sha256",
            "artifacts_sha256",
            "binding_artifact_sha256",
            "review_artifact_sha256",
        )
    )
    assert set(path.name for path in output.iterdir()) == {
        "COMMITTED",
        "binding.jsonl",
        "catalog-review.jsonl",
        "manifest.json",
        "receipt.json",
    }
    assert os.stat(output).st_mode & 0o777 == 0o700
    assert all(os.stat(path).st_mode & 0o777 == 0o600 for path in output.iterdir())


def test_catalog_file_verifier_rejects_tampering(tmp_path: Path) -> None:
    sample_run, gold_run, bank, _documents_value, catalog_review, gold_commitment, _audit_binding = _qualification_runs(
        tmp_path
    )
    output = tmp_path / "catalog-run"
    finalize_enron_catalog_qualification_files(
        sample_run,
        gold_run,
        bank,
        catalog_review,
        output,
        expected_gold_commitment=gold_commitment,
        allow_unignored_output=True,
    )
    binding = output / "binding.jsonl"
    binding.write_bytes(binding.read_bytes().replace(b'"pattern_id":"primary"', b'"pattern_id":"forged"', 1))

    with pytest.raises(EnronCatalogAdjudicationError):
        verify_enron_catalog_qualification(
            output,
            sample_run,
            gold_run,
            bank,
            expected_gold_commitment=gold_commitment,
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("missing", "cover every exact gold occurrence"),
        ("duplicate", "duplicate gold occurrence"),
        ("mismatch", "differ from deterministic"),
        ("unresolved", "zero unresolved"),
        ("unbounded_reviewer", "reviewer identity is invalid"),
    ],
)
def test_catalog_file_finalizer_requires_complete_exact_private_review(
    tmp_path: Path,
    mutation: str,
    message: str,
) -> None:
    sample_run, gold_run, bank, _documents, catalog_review, gold_commitment, _audit_binding = _qualification_runs(
        tmp_path
    )
    rows = [json.loads(line) for line in catalog_review.read_text().splitlines()]
    if mutation == "missing":
        rows[0]["decisions"].pop()
    elif mutation == "duplicate":
        rows[0]["decisions"].append(copy.deepcopy(rows[0]["decisions"][0]))
    elif mutation == "mismatch":
        rows[0]["decisions"][-1]["catalog_identity"] = {
            "entity_id": "person",
            "name_id": "alice",
            "pattern_id": "primary",
        }
    elif mutation == "unresolved":
        rows[0]["unresolved"] = ["pending"]
    else:
        rows[0]["reviewer_id"] = "x" * 129
    _write_private_jsonl(catalog_review, rows)
    output = tmp_path / "catalog-run"

    with pytest.raises(EnronCatalogAdjudicationError, match=message):
        finalize_enron_catalog_qualification_files(
            sample_run,
            gold_run,
            bank,
            catalog_review,
            output,
            expected_gold_commitment=gold_commitment,
            allow_unignored_output=True,
        )

    assert not output.exists()


def test_catalog_file_verifier_rejects_tampered_captured_review(tmp_path: Path) -> None:
    sample_run, gold_run, bank, _documents, catalog_review, gold_commitment, _audit_binding = _qualification_runs(
        tmp_path
    )
    output = tmp_path / "catalog-run"
    finalize_enron_catalog_qualification_files(
        sample_run,
        gold_run,
        bank,
        catalog_review,
        output,
        expected_gold_commitment=gold_commitment,
        allow_unignored_output=True,
    )
    captured_review = output / "catalog-review.jsonl"
    captured_review.write_bytes(
        captured_review.read_bytes().replace(b'"reviewer_id":"catalog_reviewer"', b'"reviewer_id":"catalog_intruder"')
    )

    with pytest.raises(EnronCatalogAdjudicationError):
        verify_enron_catalog_qualification(
            output,
            sample_run,
            gold_run,
            bank,
            expected_gold_commitment=gold_commitment,
        )


def test_catalog_file_finalizer_rejects_a_different_trusted_gold_commitment(tmp_path: Path) -> None:
    sample_run, gold_run, bank, _documents, catalog_review, gold_commitment, _audit_binding = _qualification_runs(
        tmp_path
    )
    wrong = dict(gold_commitment)
    wrong["gold_sha256"] = "sha256:" + "f" * 64
    output = tmp_path / "catalog-run"

    with pytest.raises(EnronCatalogAdjudicationError):
        finalize_enron_catalog_qualification_files(
            sample_run,
            gold_run,
            bank,
            catalog_review,
            output,
            expected_gold_commitment=wrong,
            allow_unignored_output=True,
        )

    assert not output.exists()


def test_catalog_file_finalizer_rejects_wrong_plan_policy_atomically(tmp_path: Path) -> None:
    sample_run, gold_run, bank, _documents_value, catalog_review, gold_commitment, _audit_binding = _qualification_runs(
        tmp_path,
        catalog_policy_sha256="sha256:" + "9" * 64,
    )
    output = tmp_path / "catalog-run"

    with pytest.raises(EnronCatalogAdjudicationError, match="current annotation and catalog"):
        finalize_enron_catalog_qualification_files(
            sample_run,
            gold_run,
            bank,
            catalog_review,
            output,
            expected_gold_commitment=gold_commitment,
            allow_unignored_output=True,
        )

    assert not output.exists()
    assert not tuple(tmp_path.glob(".catalog-run.stage-*"))


def test_catalog_file_finalizer_rejects_bank_not_frozen_in_plan(tmp_path: Path) -> None:
    sample_run, gold_run, bank, _documents_value, catalog_review, gold_commitment, _audit_binding = _qualification_runs(
        tmp_path
    )
    changed_bank = copy.deepcopy(bank)
    changed_bank["description"] = "A different canonical bank."
    output = tmp_path / "catalog-run"

    with pytest.raises(EnronCatalogAdjudicationError, match="bank frozen in the audit plan"):
        finalize_enron_catalog_qualification_files(
            sample_run,
            gold_run,
            changed_bank,
            catalog_review,
            output,
            expected_gold_commitment=gold_commitment,
            allow_unignored_output=True,
        )

    assert not output.exists()


def test_catalog_file_receipt_contains_no_private_binding_data(tmp_path: Path) -> None:
    sample_run, gold_run, bank, documents, catalog_review, gold_commitment, _audit_binding = _qualification_runs(
        tmp_path
    )
    output = tmp_path / "private-catalog-name"
    receipt = finalize_enron_catalog_qualification_files(
        sample_run,
        gold_run,
        bank,
        catalog_review,
        output,
        expected_gold_commitment=gold_commitment,
        allow_unignored_output=True,
    )
    encoded = json.dumps(receipt, sort_keys=True)

    assert all(document["document_id"] not in encoded and document["text"] not in encoded for document in documents)
    assert "alice" not in encoded.casefold()
    assert "primary" not in encoded
    assert str(output) not in encoded
    assert '"start"' not in encoded
    assert '"end"' not in encoded
    assert receipt["privacy"] == {
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
    }

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from nerb import ExtractionError, explain_match, extract_report, extract_report_batch, extract_report_file


@pytest.fixture
def minimal_bank(test_data_path) -> dict[str, Any]:
    with open(test_data_path / "minimal_bank.json", encoding="utf-8") as file:
        return json.load(file)


def _regex_pattern(
    value: str,
    *,
    priority: int = 50,
    description: str = "Regex report fixture.",
) -> dict[str, Any]:
    return {
        "kind": "regex",
        "value": value,
        "description": description,
        "status": "active",
        "priority": priority,
        "regex_flags": [],
        "metadata": {},
    }


def _literal_pattern(
    value: str,
    *,
    priority: int = 50,
    description: str = "Literal report fixture.",
) -> dict[str, Any]:
    return {
        "kind": "literal",
        "value": value,
        "description": description,
        "status": "active",
        "priority": priority,
        "case_sensitive": False,
        "normalize_whitespace": True,
        "left_boundary": "word",
        "right_boundary": "word",
        "metadata": {},
    }


def _customer_patterns(bank: dict[str, Any]) -> dict[str, Any]:
    return bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]


def _set_customer_patterns(bank: dict[str, Any], patterns: dict[str, Any]) -> None:
    _customer_patterns(bank).clear()
    _customer_patterns(bank).update(patterns)


def _add_customer_name(bank: dict[str, Any], name_id: str, canonical: str, patterns: dict[str, Any]) -> None:
    bank["entities"]["customer"]["names"][name_id] = {
        "canonical": canonical,
        "description": f"{canonical} fixture.",
        "status": "active",
        "patterns": patterns,
        "metadata": {},
    }


def _add_entity(bank: dict[str, Any], entity_id: str, canonical: str, patterns: dict[str, Any]) -> None:
    bank["entities"][entity_id] = {
        "description": f"{entity_id} fixture.",
        "status": "active",
        "regex_flags": [],
        "names": {
            "primary": {
                "canonical": canonical,
                "description": f"{canonical} fixture.",
                "status": "active",
                "patterns": patterns,
                "metadata": {},
            }
        },
        "metadata": {},
    }


def test_extract_report_shape_defaults_summary_explanation_and_context(minimal_bank):
    report = extract_report(minimal_bank, "Send Acme Corp now.", options={"context_chars": 5})

    assert {"records", "resolved_records", "overlaps", "summary", "diagnostics"}.issubset(report)
    assert len(report["records"]) == 1
    assert len(report["resolved_records"]) == 1
    assert report["overlaps"] == []
    assert report["summary"] == {
        "record_count": 1,
        "resolved_record_count": 1,
        "entity_counts": {"customer": 1},
        "name_counts": {"customer/acme_corp": 1},
    }
    resolved = report["resolved_records"][0]
    assert resolved["record"] == report["records"][0]
    assert resolved["context"] == {"before": "Send ", "match": "Acme Corp", "after": " now."}
    assert resolved["explanation"]["pattern_path"] == "/entities/customer/names/acme_corp/patterns/primary"
    assert resolved["explanation"]["pattern_kind"] == "literal"
    assert resolved["explanation"]["pattern_value"] == "Acme Corp"
    assert "metadata" not in resolved["explanation"]

    hidden_value_report = extract_report(
        minimal_bank,
        "Send Acme Corp now.",
        options={"include_pattern_values": False},
    )
    assert "pattern_value" not in hidden_value_report["resolved_records"][0]["explanation"]


def test_extract_report_file_preserves_file_source_metadata(tmp_path, minimal_bank):
    document_path = tmp_path / "email.txt"
    document_path.write_text("Send Acme Corp now.", encoding="utf-8")

    report = extract_report_file(minimal_bank, document_path, options={"context_chars": 5})

    assert report["source"] == {
        "type": "file",
        "path": str(document_path),
        "length": 19,
        "bytes": 19,
    }
    assert report["resolved_records"][0]["context"] == {"before": "Send ", "match": "Acme Corp", "after": " now."}


def test_report_uses_rust_leftmost_first_records_before_report_resolution(minimal_bank):
    _set_customer_patterns(
        minimal_bank,
        {
            "long": _literal_pattern("Acme Corp", priority=100),
            "short": _literal_pattern("Acme", priority=200),
            "regex_duplicate": _regex_pattern(r"\bAcme Corp\b", priority=100),
        },
    )

    report = extract_report(minimal_bank, "Acme Corp")

    assert [(record["pattern_id"], record["start"], record["end"]) for record in report["records"]] == [("long", 0, 9)]
    assert [item["record"]["pattern_id"] for item in report["resolved_records"]] == ["long"]
    assert report["overlaps"] == []


def test_priority_overlap_tie_breakers_use_longest_then_pattern_identity(minimal_bank):
    _set_customer_patterns(
        minimal_bank,
        {
            "long": _literal_pattern("Acme Corp", priority=100),
            "short": _literal_pattern("Acme", priority=100),
            "regex_duplicate": _regex_pattern(r"\bAcme Corp\b", priority=100),
        },
    )

    report = extract_report(minimal_bank, "Acme Corp")

    assert [item["record"]["pattern_id"] for item in report["resolved_records"]] == ["short"]
    assert report["overlaps"] == []


def test_report_cross_entity_overlap_uses_ascending_rust_priority(minimal_bank):
    _set_customer_patterns(minimal_bank, {"long": _literal_pattern("Acme Corp", priority=200)})
    _add_entity(minimal_bank, "vendor", "Acme Vendor", {"short": _literal_pattern("Acme", priority=20)})

    report = extract_report(minimal_bank, "Acme Corp")

    assert [(record["entity_id"], record["pattern_id"]) for record in report["records"]] == [
        ("vendor", "short"),
        ("customer", "long"),
    ]
    assert [(item["record"]["entity_id"], item["record"]["pattern_id"]) for item in report["resolved_records"]] == [
        ("vendor", "short")
    ]
    assert report["overlaps"][0]["resolved_record"]["entity_id"] == "vendor"


def test_grouped_summary_counts_use_resolved_records(minimal_bank):
    report = extract_report(minimal_bank, "Acme Corp and Acme Corp")

    assert report["summary"]["record_count"] == 2
    assert report["summary"]["resolved_record_count"] == 2
    assert report["summary"]["entity_counts"] == {"customer": 2}
    assert report["summary"]["name_counts"] == {"customer/acme_corp": 2}


def test_context_snippets_respect_context_chars(minimal_bank):
    report = extract_report(minimal_bank, "abcdef Acme Corp ghijkl", options={"context_chars": 3})

    assert report["resolved_records"][0]["context"] == {"before": "ef ", "match": "Acme Corp", "after": " gh"}


def test_context_snippets_convert_rust_byte_offsets_before_slicing(minimal_bank):
    report = extract_report(minimal_bank, "Café Acme Corp now", options={"context_chars": 3})

    assert report["resolved_records"][0]["record"]["offset_unit"] == "byte"
    assert report["resolved_records"][0]["context"] == {"before": "fé ", "match": "Acme Corp", "after": " no"}


def test_metadata_is_excluded_by_default_and_included_when_requested(minimal_bank):
    minimal_bank["metadata"] = {"bank_owner": "ops"}
    customer = minimal_bank["entities"]["customer"]
    customer["metadata"] = {"entity_owner": "sales"}
    name = customer["names"]["acme_corp"]
    name["metadata"] = {"tier": "strategic"}
    name["patterns"]["primary"]["metadata"] = {"source": "crm"}

    default_report = extract_report(minimal_bank, "Acme Corp")
    metadata_report = extract_report(minimal_bank, "Acme Corp", options={"include_metadata": True})

    assert "metadata" not in default_report["resolved_records"][0]["explanation"]
    assert metadata_report["resolved_records"][0]["explanation"]["metadata"] == {
        "bank": {"bank_owner": "ops"},
        "entity": {"entity_owner": "sales"},
        "name": {"tier": "strategic"},
        "pattern": {"source": "crm"},
    }


def test_expected_missing_diagnostic_defaults_to_resolved_scope(minimal_bank):
    _set_customer_patterns(
        minimal_bank,
        {
            "long": _literal_pattern("Acme Corp", priority=200),
            "short": _literal_pattern("Acme", priority=100),
        },
    )
    _add_customer_name(
        minimal_bank,
        "acme_short",
        "Acme",
        {"short": _literal_pattern("Acme", priority=100)},
    )

    report = extract_report(
        minimal_bank,
        "Acme Corp",
        options={"expected": [{"entity_id": "customer", "name_id": "missing_name"}]},
    )
    resolved_scope_report = extract_report(
        minimal_bank,
        "Acme Corp",
        options={"expected": [{"entity_id": "customer", "name_id": "acme_short"}]},
    )
    raw_scope_report = extract_report(
        minimal_bank,
        "Acme Corp",
        options={"expected": [{"entity_id": "customer", "name_id": "acme_short"}], "expected_match_scope": "raw"},
    )

    assert report["diagnostics"] == [
        {
            "severity": "warning",
            "code": "report.expected_missing",
            "path": "/expected/0",
            "message": "Expected entity/name was not matched.",
            "metadata": {
                "entity_id": "customer",
                "name_id": "missing_name",
                "expected_match_scope": "resolved",
            },
        }
    ]
    assert resolved_scope_report["diagnostics"] == []
    assert raw_scope_report["diagnostics"] == []


def test_explain_match_for_literal_pattern_respects_pattern_value_option(minimal_bank):
    explanation = explain_match(minimal_bank, "customer", "acme_corp", "primary")
    hidden_value = explain_match(
        minimal_bank,
        "customer",
        "acme_corp",
        "primary",
        options={"include_pattern_values": False},
    )

    assert explanation == {
        "pattern_path": "/entities/customer/names/acme_corp/patterns/primary",
        "pattern_kind": "literal",
        "priority": 100,
        "description": "Exact Acme Corp alias.",
        "normalization_mode": "none",
        "pattern_value": "Acme Corp",
        "literal_settings": {
            "case_sensitive": False,
            "normalize_whitespace": True,
            "left_boundary": "word",
            "right_boundary": "word",
        },
    }
    assert "pattern_value" not in hidden_value


def test_explain_match_for_regex_pattern_includes_effective_flags_and_eval_refs(minimal_bank):
    minimal_bank["default_regex_flags"] = ["DOTALL", "IGNORECASE"]
    minimal_bank["eval_refs"] = ["bank.jsonl"]
    customer = minimal_bank["entities"]["customer"]
    customer["regex_flags"] = ["MULTILINE"]
    customer["eval_refs"] = ["entity.jsonl"]
    name = customer["names"]["acme_corp"]
    name["eval_refs"] = ["name.jsonl"]
    _set_customer_patterns(
        minimal_bank,
        {
            "regex_alias": {
                **_regex_pattern(r"\bAcme(?:\s+Corp)?\b", priority=70, description="Regex Acme alias."),
                "regex_flags": ["ASCII"],
                "eval_refs": ["pattern.jsonl"],
            }
        },
    )

    explanation = explain_match(
        minimal_bank,
        "customer",
        "acme_corp",
        "regex_alias",
        options={"include_eval_refs": True},
    )

    assert explanation["pattern_kind"] == "regex"
    assert explanation["pattern_value"] == r"\bAcme(?:\s+Corp)?\b"
    assert explanation["effective_regex_flags"] == ["ASCII", "IGNORECASE", "MULTILINE", "DOTALL"]
    assert explanation["eval_refs"] == {
        "bank": ["bank.jsonl"],
        "entity": ["entity.jsonl"],
        "name": ["name.jsonl"],
        "pattern": ["pattern.jsonl"],
    }


def test_explain_match_rejects_missing_pattern(minimal_bank):
    with pytest.raises(ExtractionError, match="Pattern not found"):
        explain_match(minimal_bank, "customer", "acme_corp", "missing")


def test_extract_report_batch_shape(minimal_bank):
    report = extract_report_batch(
        minimal_bank,
        [
            {"document_id": "b_doc", "text": "No match."},
            {"document_id": "a_doc", "text": "Acme Corp"},
        ],
    )

    assert report["source"]["type"] == "batch"
    assert [document["document_id"] for document in report["documents"]] == ["b_doc", "a_doc"]
    assert [record["document_id"] for record in report["records"]] == ["a_doc"]
    assert [item["record"]["document_id"] for item in report["resolved_records"]] == ["a_doc"]
    assert report["summary"]["document_count"] == 2
    assert report["summary"]["record_count"] == 1
    assert report["summary"]["resolved_record_count"] == 1
    assert report["summary"]["documents_with_records"] == 1
    assert report["summary"]["documents_with_resolved_records"] == 1
    assert report["summary"]["entity_counts"] == {"customer": 1}


def test_extract_report_batch_reuses_file_text_snapshot(monkeypatch, tmp_path, minimal_bank):
    source_path = tmp_path / "source.txt"
    source_path.write_text("unused", encoding="utf-8")
    calls: list[Path] = []

    def fake_read_text(path: Path, encoding: str | None = None) -> str:
        del encoding
        calls.append(path)
        return "Acme Corp" if len(calls) == 1 else "ZZZZZZZZZ"

    monkeypatch.setattr(Path, "read_text", fake_read_text)

    report = extract_report_batch(
        minimal_bank,
        [{"document_id": "file_doc", "file_path": source_path}],
        options={"context_chars": 20},
    )

    assert calls == [source_path]
    assert report["records"][0]["string"] == "Acme Corp"
    assert report["resolved_records"][0]["context"]["match"] == "Acme Corp"


def test_extract_report_options_are_validated(minimal_bank):
    with pytest.raises(ExtractionError, match="overlap_policy"):
        extract_report(minimal_bank, "Acme Corp", options={"overlap_policy": "none"})

    with pytest.raises(ExtractionError, match="context_chars"):
        extract_report(minimal_bank, "Acme Corp", options={"context_chars": -1})

    with pytest.raises(ExtractionError, match="expected item 0"):
        extract_report(minimal_bank, "Acme Corp", options={"expected": [copy.deepcopy(["bad"])]})

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from nerb import ExtractionError, eval_bank
from nerb.diagnostics import (
    EVAL_NEGATIVE_FAILED,
    EVAL_POSITIVE_FAILED,
    EVAL_RECORD_INVALID,
    EVAL_REF_TOO_LARGE,
    EVAL_REF_UNRESOLVED,
    EVAL_REF_UNSUPPORTED,
    JSON_PARSE,
    SCHEMA_ADDITIONAL_PROPERTY,
)


@pytest.fixture
def minimal_bank(test_data_path) -> dict[str, Any]:
    with open(test_data_path / "minimal_bank.json", encoding="utf-8") as file:
        return json.load(file)


def _literal_pattern(value: str) -> dict[str, Any]:
    return {
        "kind": "literal",
        "value": value,
        "description": "Literal eval fixture.",
        "status": "active",
        "priority": 50,
        "case_sensitive": False,
        "normalize_whitespace": True,
        "left_boundary": "word",
        "right_boundary": "word",
        "metadata": {},
    }


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> str:
    path.write_text("\n".join(json.dumps(record, separators=(",", ":")) for record in records) + "\n", encoding="utf-8")
    return path.name


def _positive_record(text: str = "Acme Corp", match: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "type": "positive",
        "text": text,
        "matches": [match or {"string": "Acme Corp", "start": 0, "end": 9}],
        "metadata": {},
    }


def _negative_record(text: str = "Acme Corp") -> dict[str, Any]:
    return {"type": "negative", "text": text, "reason": "False-positive guard.", "metadata": {}}


def _add_customer_name(bank: dict[str, Any], name_id: str, canonical: str, pattern_value: str) -> None:
    bank["entities"]["customer"]["names"][name_id] = {
        "canonical": canonical,
        "description": f"{canonical} eval fixture.",
        "status": "active",
        "patterns": {"primary": _literal_pattern(pattern_value)},
        "metadata": {},
    }


def test_eval_bank_pattern_ref_infers_ids_and_summarizes_provenance(minimal_bank, test_data_path):
    pattern = minimal_bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]
    pattern["eval_refs"] = ["evals/acme_pattern.jsonl"]

    result = eval_bank(minimal_bank, base_path=test_data_path)

    assert result["summary"] == {
        "passed": True,
        "positive_total": 1,
        "positive_failed": 0,
        "negative_total": 1,
        "negative_failed": 0,
    }
    assert result["failures"] == []
    assert result["provenance"] == {"total": 1, "by_source_type": {"crm": 1}}
    assert result["by_pattern"]["customer/acme_corp/primary"] == {
        "positive_total": 1,
        "positive_failed": 0,
        "negative_total": 1,
        "negative_failed": 0,
        "provenance_total": 1,
    }


def test_eval_bank_positive_refs_cover_bank_entity_and_name_scopes(tmp_path, minimal_bank):
    bank_ref = _write_jsonl(
        tmp_path / "bank.jsonl",
        [
            _positive_record(
                match={
                    "entity_id": "customer",
                    "name_id": "acme_corp",
                    "pattern_id": "primary",
                    "string": "Acme Corp",
                    "start": 0,
                    "end": 9,
                }
            )
        ],
    )
    entity_ref = _write_jsonl(tmp_path / "entity.jsonl", [_positive_record()])
    name_ref = _write_jsonl(tmp_path / "name.jsonl", [_positive_record()])

    customer = minimal_bank["entities"]["customer"]
    minimal_bank["eval_refs"] = [bank_ref]
    customer["eval_refs"] = [entity_ref]
    customer["names"]["acme_corp"]["eval_refs"] = [name_ref]

    result = eval_bank(minimal_bank, base_path=tmp_path)

    assert result["summary"] == {
        "passed": True,
        "positive_total": 3,
        "positive_failed": 0,
        "negative_total": 0,
        "negative_failed": 0,
    }
    assert result["by_entity"]["customer"]["positive_total"] == 2
    assert result["by_name"]["customer/acme_corp"]["positive_total"] == 1


def test_eval_bank_positive_refs_use_utf8_byte_offsets(tmp_path, minimal_bank):
    text = "Café Acme Corp"
    eval_ref = _write_jsonl(
        tmp_path / "utf8_byte_offsets.jsonl",
        [_positive_record(text=text, match={"string": "Acme Corp", "start": 6, "end": 15})],
    )
    pattern = minimal_bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]
    pattern["eval_refs"] = [eval_ref]

    result = eval_bank(minimal_bank, base_path=tmp_path)

    assert result["summary"] == {
        "passed": True,
        "positive_total": 1,
        "positive_failed": 0,
        "negative_total": 0,
        "negative_failed": 0,
    }
    assert result["failures"] == []


def test_eval_bank_jsonl_lines_do_not_split_on_unicode_line_separators(tmp_path, minimal_bank):
    eval_ref_path = tmp_path / "unicode_line_separator.jsonl"
    eval_ref_path.write_text(
        json.dumps(_positive_record(text="Acme Corp\u2028 signed."), ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    pattern = minimal_bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]
    pattern["eval_refs"] = [eval_ref_path.name]

    result = eval_bank(minimal_bank, base_path=tmp_path)

    assert result["summary"] == {
        "passed": True,
        "positive_total": 1,
        "positive_failed": 0,
        "negative_total": 0,
        "negative_failed": 0,
    }
    assert result["failures"] == []


def test_eval_bank_positive_refs_reject_character_offsets_when_byte_offsets_differ(tmp_path, minimal_bank):
    text = "Café Acme Corp"
    eval_ref = _write_jsonl(
        tmp_path / "character_offsets.jsonl",
        [_positive_record(text=text, match={"string": "Acme Corp", "start": 5, "end": 14})],
    )
    pattern = minimal_bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]
    pattern["eval_refs"] = [eval_ref]

    result = eval_bank(minimal_bank, base_path=tmp_path)

    assert result["summary"]["passed"] is False
    assert result["summary"]["positive_total"] == 0
    failure = result["failures"][0]
    assert failure["diagnostics"][0]["code"] == EVAL_RECORD_INVALID
    assert failure["diagnostics"][0]["path"] == "/matches/0/string"
    assert "byte span" in failure["diagnostics"][0]["message"]


def test_eval_bank_positive_refs_reject_text_that_cannot_encode_as_utf8(tmp_path, minimal_bank):
    eval_ref_path = tmp_path / "invalid_utf8_text.jsonl"
    eval_ref_path.write_text(
        '{"type":"positive","text":"\\ud800 Acme Corp",'
        '"matches":[{"string":"Acme Corp","start":1,"end":10}],"metadata":{}}\n',
        encoding="utf-8",
    )
    pattern = minimal_bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]
    pattern["eval_refs"] = [eval_ref_path.name]

    result = eval_bank(minimal_bank, base_path=tmp_path)
    json.dumps(result, ensure_ascii=False).encode("utf-8")

    assert result["summary"]["passed"] is False
    assert result["summary"]["positive_total"] == 0
    failure = result["failures"][0]
    assert failure["text"] == "\\ud800 Acme Corp"
    assert failure["diagnostics"][0]["code"] == EVAL_RECORD_INVALID
    assert failure["diagnostics"][0]["path"] == "/text"
    assert "UTF-8" in failure["diagnostics"][0]["message"]


def test_eval_bank_sanitizes_invalid_utf8_text_with_non_ascii_prefix(tmp_path, minimal_bank):
    eval_ref_path = tmp_path / "invalid_utf8_text_with_non_ascii.jsonl"
    eval_ref_path.write_text(
        '{"type":"positive","text":"Caf\\u00e9 \\ud800 Acme Corp",'
        '"matches":[{"string":"Acme Corp","start":8,"end":17}],"metadata":{}}\n',
        encoding="utf-8",
    )
    pattern = minimal_bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]
    pattern["eval_refs"] = [eval_ref_path.name]

    result = eval_bank(minimal_bank, base_path=tmp_path)
    json.dumps(result, ensure_ascii=False).encode("utf-8")

    assert result["summary"]["passed"] is False
    failure = result["failures"][0]
    assert failure["text"] == "Café \\ud800 Acme Corp"
    assert failure["diagnostics"][0]["code"] == EVAL_RECORD_INVALID


def test_eval_bank_negative_records_are_scoped_to_attachment_point(tmp_path, minimal_bank):
    _add_customer_name(minimal_bank, "globex", "Globex", "Globex")
    negative_ref = _write_jsonl(tmp_path / "negative.jsonl", [_negative_record("Acme Corp")])
    minimal_bank["entities"]["customer"]["names"]["globex"]["eval_refs"] = [negative_ref]

    result = eval_bank(minimal_bank, base_path=tmp_path)

    assert result["summary"] == {
        "passed": True,
        "positive_total": 0,
        "positive_failed": 0,
        "negative_total": 1,
        "negative_failed": 0,
    }
    assert result["failures"] == []


def test_eval_bank_negative_refs_reject_text_that_cannot_encode_as_utf8(tmp_path, minimal_bank):
    eval_ref_path = tmp_path / "invalid_negative_utf8_text.jsonl"
    eval_ref_path.write_text(
        '{"type":"negative","text":"\\ud800 Acme Corp","reason":"Invalid text guard.","metadata":{}}\n',
        encoding="utf-8",
    )
    pattern = minimal_bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]
    pattern["eval_refs"] = [eval_ref_path.name]

    result = eval_bank(minimal_bank, base_path=tmp_path)
    json.dumps(result, ensure_ascii=False).encode("utf-8")

    assert result["summary"]["passed"] is False
    assert result["summary"]["negative_total"] == 0
    failure = result["failures"][0]
    assert failure["text"] == "\\ud800 Acme Corp"
    assert failure["diagnostics"][0]["code"] == EVAL_RECORD_INVALID
    assert failure["diagnostics"][0]["path"] == "/text"
    assert "UTF-8" in failure["diagnostics"][0]["message"]


def test_eval_bank_sanitizes_eval_ref_that_cannot_encode_as_utf8(tmp_path, minimal_bank):
    eval_ref = "missing\ud800.jsonl"
    pattern = minimal_bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]
    pattern["eval_refs"] = [eval_ref]

    result = eval_bank(minimal_bank, base_path=tmp_path)
    json.dumps(result, ensure_ascii=False).encode("utf-8")

    assert result["summary"]["passed"] is False
    failure = result["failures"][0]
    assert failure["eval_ref"] == "missing\\ud800.jsonl"
    assert failure["diagnostics"][0]["code"] == EVAL_REF_UNRESOLVED


def test_eval_bank_rejects_provenance_source_type_that_cannot_encode_as_utf8(tmp_path, minimal_bank):
    eval_ref_path = tmp_path / "invalid_provenance_utf8.jsonl"
    eval_ref_path.write_text(
        '{"type":"provenance","source_type":"\\ud800","observed_at":"2026-06-05",'
        '"evidence":"CRM export.","metadata":{}}\n',
        encoding="utf-8",
    )
    pattern = minimal_bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]
    pattern["eval_refs"] = [eval_ref_path.name]

    result = eval_bank(minimal_bank, base_path=tmp_path)
    json.dumps(result, ensure_ascii=False).encode("utf-8")

    assert result["summary"]["passed"] is False
    assert result["provenance"] == {"total": 0, "by_source_type": {}}
    failure = result["failures"][0]
    assert failure["diagnostics"][0]["code"] == EVAL_RECORD_INVALID
    assert failure["diagnostics"][0]["path"] == "/source_type"
    assert "UTF-8" in failure["diagnostics"][0]["message"]


def test_eval_bank_positive_failure_includes_repair_diagnostic_and_raw_details(tmp_path, minimal_bank):
    eval_ref = _write_jsonl(
        tmp_path / "positive_fail.jsonl",
        [_positive_record(match={"string": "Acme", "start": 0, "end": 4})],
    )
    pattern = minimal_bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]
    pattern["eval_refs"] = [eval_ref]

    result = eval_bank(minimal_bank, base_path=tmp_path)

    assert result["summary"]["passed"] is False
    assert result["summary"]["positive_failed"] == 1
    assert result["failures"] == [
        {
            "path": "/entities/customer/names/acme_corp/patterns/primary",
            "eval_ref": eval_ref,
            "record": 0,
            "type": "positive",
            "text": "Acme Corp",
            "expected": [
                {
                    "string": "Acme",
                    "start": 0,
                    "end": 4,
                    "entity_id": "customer",
                    "name_id": "acme_corp",
                    "pattern_id": "primary",
                }
            ],
            "actual": [
                {
                    "string": "Acme Corp",
                    "start": 0,
                    "end": 9,
                    "entity_id": "customer",
                    "name_id": "acme_corp",
                    "pattern_id": "primary",
                }
            ],
            "diagnostics": [
                {
                    "severity": "error",
                    "code": EVAL_POSITIVE_FAILED,
                    "path": "/entities/customer/names/acme_corp/patterns/primary",
                    "message": "Positive eval expected records did not match actual scoped extraction records.",
                    "metadata": {
                        "scope": "pattern",
                        "comparison_fields": ["string", "start", "end", "entity_id", "name_id", "pattern_id"],
                    },
                }
            ],
        }
    ]


def test_eval_bank_scoped_positive_preserves_explicit_wrong_ids_as_failure(tmp_path, minimal_bank):
    eval_ref = _write_jsonl(
        tmp_path / "wrong_ids.jsonl",
        [
            _positive_record(
                match={
                    "entity_id": "vendor",
                    "name_id": "wrong",
                    "pattern_id": "wrong",
                    "string": "Acme Corp",
                    "start": 0,
                    "end": 9,
                }
            )
        ],
    )
    pattern = minimal_bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]
    pattern["eval_refs"] = [eval_ref]

    result = eval_bank(minimal_bank, base_path=tmp_path)

    assert result["summary"]["passed"] is False
    assert result["summary"]["positive_failed"] == 1
    assert result["failures"][0]["expected"] == [
        {
            "string": "Acme Corp",
            "start": 0,
            "end": 9,
            "entity_id": "vendor",
            "name_id": "wrong",
            "pattern_id": "wrong",
        }
    ]


def test_eval_bank_negative_failure_uses_scoped_actuals_and_diagnostic(tmp_path, minimal_bank):
    eval_ref = _write_jsonl(tmp_path / "negative_fail.jsonl", [_negative_record("Acme Corp")])
    minimal_bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]["eval_refs"] = [eval_ref]

    result = eval_bank(minimal_bank, base_path=tmp_path)

    assert result["summary"]["passed"] is False
    assert result["summary"]["negative_failed"] == 1
    failure = result["failures"][0]
    assert failure["path"] == "/entities/customer/names/acme_corp/patterns/primary"
    assert failure["eval_ref"] == eval_ref
    assert failure["record"] == 0
    assert failure["type"] == "negative"
    assert failure["expected"] == []
    assert failure["actual"][0]["pattern_id"] == "primary"
    assert failure["diagnostics"][0]["code"] == EVAL_NEGATIVE_FAILED


def test_eval_bank_invalid_jsonl_records_return_diagnostics(tmp_path, minimal_bank):
    eval_ref_path = tmp_path / "invalid.jsonl"
    eval_ref_path.write_text(
        '{"type":"positive","text":"Acme Corp","matches":[{"string":"Acme Corp","start":0,"end":9}],'
        '"metadata":{},"extra":true}\n'
        "{not json}\n",
        encoding="utf-8",
    )
    minimal_bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]["eval_refs"] = [
        eval_ref_path.name
    ]

    result = eval_bank(minimal_bank, base_path=tmp_path)

    assert result["summary"]["passed"] is False
    assert [failure["record"] for failure in result["failures"]] == [0, 1]
    assert result["failures"][0]["diagnostics"][0]["code"] == SCHEMA_ADDITIONAL_PROPERTY
    assert result["failures"][1]["diagnostics"][0]["code"] == JSON_PARSE


def test_eval_bank_invalid_capture_records_return_schema_diagnostics(tmp_path, minimal_bank):
    eval_ref_path = tmp_path / "invalid_captures.jsonl"
    eval_ref_path.write_text(
        json.dumps(
            {
                "type": "positive",
                "text": "Acme Corp",
                "matches": [
                    {
                        "string": "Acme Corp",
                        "start": 0,
                        "end": 9,
                        "captures": {"alias": "Acme Corp", "extra": {"string": "x", "start": 0, "end": 1, "bad": True}},
                    }
                ],
                "metadata": {},
            },
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    minimal_bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]["eval_refs"] = [
        eval_ref_path.name
    ]

    result = eval_bank(minimal_bank, base_path=tmp_path)

    assert result["summary"]["passed"] is False
    diagnostics = result["failures"][0]["diagnostics"]
    assert {diagnostic["code"] for diagnostic in diagnostics} == {"schema.type", "schema.additional_property"}
    assert {diagnostic["path"] for diagnostic in diagnostics} == {
        "/matches/0/captures/alias",
        "/matches/0/captures/extra/bad",
    }


def test_eval_bank_relative_refs_require_base_path(minimal_bank):
    pattern = minimal_bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]
    pattern["eval_refs"] = ["evals/acme_pattern.jsonl"]

    result = eval_bank(minimal_bank)

    assert result["summary"]["passed"] is False
    assert result["failures"][0]["diagnostics"][0]["code"] == EVAL_REF_UNRESOLVED


def test_eval_bank_rejects_absolute_eval_refs(tmp_path, minimal_bank):
    eval_ref_path = tmp_path / "absolute.jsonl"
    _write_jsonl(eval_ref_path, [_positive_record()])
    pattern = minimal_bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]
    pattern["eval_refs"] = [str(eval_ref_path)]

    result = eval_bank(minimal_bank, base_path=tmp_path)

    assert result["summary"]["passed"] is False
    failure = result["failures"][0]
    assert failure["diagnostics"][0]["code"] == EVAL_REF_UNRESOLVED
    assert "relative paths" in failure["diagnostics"][0]["message"]


def test_eval_bank_rejects_parent_traversal_eval_refs(tmp_path, minimal_bank):
    base_path = tmp_path / "base"
    base_path.mkdir()
    _write_jsonl(tmp_path / "outside.jsonl", [_positive_record()])
    pattern = minimal_bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]
    pattern["eval_refs"] = ["../outside.jsonl"]

    result = eval_bank(minimal_bank, base_path=base_path)

    assert result["summary"]["passed"] is False
    failure = result["failures"][0]
    assert failure["diagnostics"][0]["code"] == EVAL_REF_UNRESOLVED
    assert "within the eval base path" in failure["diagnostics"][0]["message"]


def test_eval_bank_reports_invalid_eval_ref_path_resolution(tmp_path, minimal_bank):
    pattern = minimal_bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]
    pattern["eval_refs"] = ["bad\0ref.jsonl"]

    result = eval_bank(minimal_bank, base_path=tmp_path)

    assert result["summary"]["passed"] is False
    failure = result["failures"][0]
    assert failure["diagnostics"][0]["code"] == EVAL_REF_UNRESOLVED
    assert "Could not resolve eval ref" in failure["diagnostics"][0]["message"]


def test_eval_bank_remote_refs_are_deferred_not_fetched(minimal_bank):
    pattern = minimal_bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]
    pattern["eval_refs"] = ["https://example.com/acme.jsonl"]

    result = eval_bank(minimal_bank)

    assert result["summary"]["passed"] is False
    assert result["failures"][0]["diagnostics"][0]["code"] == EVAL_REF_UNSUPPORTED


def test_eval_bank_enforces_eval_ref_size_limit(test_data_path, minimal_bank):
    bank = copy.deepcopy(minimal_bank)
    bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]["eval_refs"] = [
        "evals/acme_pattern.jsonl"
    ]

    result = eval_bank(bank, base_path=test_data_path, options={"max_eval_ref_bytes": 1})

    assert result["summary"]["passed"] is False
    assert result["failures"][0]["diagnostics"][0]["code"] == EVAL_REF_TOO_LARGE


def test_eval_bank_rechecks_eval_ref_size_after_bounded_read(monkeypatch, tmp_path, minimal_bank):
    eval_ref_path = tmp_path / "stale_size.jsonl"
    _write_jsonl(eval_ref_path, [_positive_record()])
    actual_mode = eval_ref_path.stat().st_mode
    original_stat = Path.stat

    class StaleStat:
        st_mode = actual_mode
        st_size = 1

    def stale_stat(self, *args, **kwargs):
        if self == eval_ref_path:
            return StaleStat()
        return original_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", stale_stat)
    pattern = minimal_bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]
    pattern["eval_refs"] = [eval_ref_path.name]

    result = eval_bank(minimal_bank, base_path=tmp_path, options={"max_eval_ref_bytes": 4})

    assert result["summary"]["passed"] is False
    failure = result["failures"][0]
    assert failure["diagnostics"][0]["code"] == EVAL_REF_TOO_LARGE
    assert failure["diagnostics"][0]["metadata"]["bytes"] == 5


def test_eval_bank_rejects_non_regular_eval_refs(tmp_path, minimal_bank):
    pattern = minimal_bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]
    pattern["eval_refs"] = ["."]

    result = eval_bank(minimal_bank, base_path=tmp_path)

    assert result["summary"]["passed"] is False
    failure = result["failures"][0]
    assert failure["diagnostics"][0]["code"] == EVAL_REF_UNRESOLVED
    assert "regular file" in failure["diagnostics"][0]["message"]


def test_eval_bank_rejects_invalid_eval_options(minimal_bank):
    with pytest.raises(ExtractionError, match="max_eval_ref_bytes"):
        eval_bank(minimal_bank, options={"max_eval_ref_bytes": 0})

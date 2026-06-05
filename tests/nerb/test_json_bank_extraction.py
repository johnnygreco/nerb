from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from nerb import (
    ExtractionError,
    bank_cache_info,
    clear_bank_cache,
    extract_batch,
    extract_file,
    extract_text,
)


@pytest.fixture
def minimal_bank(test_data_path) -> dict[str, Any]:
    with open(test_data_path / "minimal_bank.json", encoding="utf-8") as file:
        return json.load(file)


def _regex_pattern(value: str, *, status: str = "active") -> dict[str, Any]:
    return {
        "kind": "regex",
        "value": value,
        "description": "Regex extraction fixture.",
        "status": status,
        "priority": 50,
        "regex_flags": [],
        "metadata": {},
    }


def _literal_pattern(
    value: str,
    *,
    status: str = "active",
    case_sensitive: bool = False,
    normalize_whitespace: bool = True,
) -> dict[str, Any]:
    return {
        "kind": "literal",
        "value": value,
        "description": "Literal extraction fixture.",
        "status": status,
        "priority": 50,
        "case_sensitive": case_sensitive,
        "normalize_whitespace": normalize_whitespace,
        "left_boundary": "word",
        "right_boundary": "word",
        "metadata": {},
    }


def _customer_patterns(bank: dict[str, Any]) -> dict[str, Any]:
    return bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]


def _set_customer_patterns(bank: dict[str, Any], patterns: dict[str, Any]) -> None:
    _customer_patterns(bank).clear()
    _customer_patterns(bank).update(patterns)


def test_extract_text_returns_literal_records_with_response_metadata(minimal_bank):
    result = extract_text(minimal_bank, "Send this to Acme Corp today.")

    assert result["bank"]["id"] == "company_entities"
    assert result["bank"]["version"] == "2026.06.03"
    assert result["bank"]["schema_version"] == "nerb.bank.v1"
    assert result["bank"]["hash"].startswith("sha256:")
    assert result["engine"]["name"] == "nerb_engine"
    assert result["source"] == {"type": "text", "length": 29, "bytes": 29}
    assert result["records"] == [
        {
            "entity": "customer",
            "canonical_name": "Acme Corp",
            "surface_name": "Acme Corp",
            "string": "Acme Corp",
            "start": 13,
            "end": 22,
            "offset_unit": "byte",
            "entity_id": "customer",
            "name_id": "acme_corp",
            "pattern_id": "primary",
            "pattern_kind": "literal",
            "captures": {},
        }
    ]


def test_regex_records_use_pattern_id_as_surface_name_without_capture_projection(minimal_bank):
    _set_customer_patterns(
        minimal_bank,
        {"invoice": _regex_pattern(r"(?P<prefix>INV)-(?P<number>\d+)(?:-(?P<suffix>[A-Z]+))?(?P<empty>)")},
    )

    result = extract_text(minimal_bank, "Please pay INV-123 now.")

    assert result["records"] == [
        {
            "entity": "customer",
            "canonical_name": "Acme Corp",
            "surface_name": "invoice",
            "string": "INV-123",
            "start": 11,
            "end": 18,
            "offset_unit": "byte",
            "entity_id": "customer",
            "name_id": "acme_corp",
            "pattern_id": "invoice",
            "pattern_kind": "regex",
            "captures": {},
        }
    ]


def test_json_bank_extraction_accepts_rust_regex_syntax_that_python_re_cannot_parse(minimal_bank):
    _set_customer_patterns(minimal_bank, {"named_capture": _regex_pattern(r"(?<label>ACME)")})

    result = extract_text(minimal_bank, "abc ACME")

    assert [(record["pattern_id"], record["string"]) for record in result["records"]] == [("named_capture", "ACME")]


def test_unicode_normalization_modes_are_rejected_until_supported_by_rust_engine(minimal_bank):
    minimal_bank["unicode_normalization"] = "NFC"
    _set_customer_patterns(minimal_bank, {"accented": _regex_pattern("Café")})

    with pytest.raises(ExtractionError, match="Rust engine validation") as exc_info:
        extract_text(minimal_bank, "Cafe\u0301 signed.")
    assert any("unicode_normalization" in diagnostic["message"] for diagnostic in exc_info.value.diagnostics)


def test_case_insensitive_literal_uses_original_spans(minimal_bank):
    _set_customer_patterns(minimal_bank, {"acme": _literal_pattern("Acme Corp", case_sensitive=False)})

    result = extract_text(minimal_bank, "ACME CORP replied.")

    assert result["records"][0]["string"] == "ACME CORP"
    assert result["records"][0]["start"] == 0
    assert result["records"][0]["end"] == 9


def test_rust_entity_independent_scan_uses_within_entity_leftmost_first(minimal_bank):
    _set_customer_patterns(
        minimal_bank,
        {
            "long": _literal_pattern("Acme Corp"),
            "short": _literal_pattern("Acme"),
            "regex_duplicate": _regex_pattern(r"\bAcme Corp\b"),
        },
    )

    result = extract_text(minimal_bank, "Acme Corp")
    sort_keys = [
        (
            record["start"],
            record["end"],
            record["entity_id"],
            record["name_id"],
            record["pattern_id"],
            record["string"],
        )
        for record in result["records"]
    ]

    assert [(record["pattern_id"], record["start"], record["end"]) for record in result["records"]] == [("short", 0, 4)]
    assert sort_keys == sorted(sort_keys)


def test_regex_entity_shards_use_deterministic_leftmost_first_for_same_start_matches(minimal_bank):
    _set_customer_patterns(
        minimal_bank,
        {
            "first_regex": _regex_pattern(r"\bAcme\b"),
            "second_regex": _regex_pattern(r"\bAcme\b"),
        },
    )

    result = extract_text(minimal_bank, "Acme")

    assert [(record["pattern_id"], record["string"]) for record in result["records"]] == [("first_regex", "Acme")]


def test_regex_numeric_backreferences_are_rejected_by_rust_regex_profile(minimal_bank):
    _set_customer_patterns(minimal_bank, {"code": _regex_pattern(r"\b([A-Z]+)-\1\b")})

    with pytest.raises(ExtractionError, match="Rust engine validation") as exc_info:
        extract_text(minimal_bank, "Ship ABC-ABC today.")
    assert any("backreferences are not supported" in diagnostic["message"] for diagnostic in exc_info.value.diagnostics)


def test_extract_file_uses_file_source_metadata(tmp_path, minimal_bank):
    source_path = tmp_path / "source.txt"
    source_path.write_text("Acme Corp\n", encoding="utf-8")

    result = extract_file(minimal_bank, source_path)

    assert result["source"] == {"type": "file", "path": str(source_path), "length": 10, "bytes": 10}
    assert result["records"][0]["string"] == "Acme Corp"


def test_extract_batch_groups_documents_and_sorts_flat_records(minimal_bank):
    result = extract_batch(
        minimal_bank,
        [
            {"document_id": "b_doc", "text": "Acme Corp"},
            {"document_id": "a_doc", "text": "Acme Corp"},
        ],
    )

    assert [document["document_id"] for document in result["documents"]] == ["b_doc", "a_doc"]
    assert "document_id" not in result["documents"][0]["records"][0]
    assert [record["document_id"] for record in result["records"]] == ["a_doc", "b_doc"]
    assert result["summary"] == {"document_count": 2, "record_count": 2, "documents_with_records": 2}


def test_extract_batch_rejects_invalid_document_ids_and_generates_valid_default(minimal_bank):
    with pytest.raises(ExtractionError, match="NERB ID syntax"):
        extract_batch(minimal_bank, [{"document_id": "bad id!", "text": "Acme Corp"}])

    result = extract_batch(minimal_bank, [{"text": "Acme Corp"}])

    assert result["documents"][0]["document_id"] == "document_0"
    assert result["records"][0]["document_id"] == "document_0"


def test_extraction_limits_are_enforced(minimal_bank):
    with pytest.raises(ExtractionError, match="configured limit"):
        extract_text(minimal_bank, "Acme Corp", options={"max_text_bytes": 4})

    with pytest.raises(ExtractionError, match="at most 1 documents"):
        extract_batch(
            minimal_bank,
            [{"document_id": "one", "text": "Acme Corp"}, {"document_id": "two", "text": "Acme Corp"}],
            options={"max_batch_documents": 1},
        )

    with pytest.raises(ExtractionError, match="combined limit"):
        extract_batch(
            minimal_bank,
            [{"document_id": "one", "text": "Acme Corp"}, {"document_id": "two", "text": "Acme Corp"}],
            options={"max_batch_text_bytes": 10},
        )


def test_extraction_rejects_runtime_invalid_banks(minimal_bank):
    _set_customer_patterns(minimal_bank, {"empty": _regex_pattern("a*")})

    with pytest.raises(ExtractionError, match="runtime validation") as exc_info:
        extract_text(minimal_bank, "aaa")

    assert any(diagnostic["code"] == "regex.matches_empty" for diagnostic in exc_info.value.diagnostics)


def test_extraction_rejects_zero_width_regexes_that_match_non_empty_text(minimal_bank):
    _set_customer_patterns(minimal_bank, {"word_boundary": _regex_pattern(r"\b")})

    with pytest.raises(ExtractionError, match="runtime validation") as exc_info:
        extract_text(minimal_bank, "abc")

    assert any(diagnostic["code"] == "regex.matches_empty" for diagnostic in exc_info.value.diagnostics)


def test_extraction_rejects_non_json_schema_invalid_banks_with_diagnostics(minimal_bank):
    minimal_bank["metadata"]["bad"] = object()

    with pytest.raises(ExtractionError, match="schema validation") as exc_info:
        extract_text(minimal_bank, "Acme Corp")

    assert any(diagnostic["path"] == "/metadata/bad" for diagnostic in exc_info.value.diagnostics)


def test_extraction_rejects_schema_invalid_banks_before_status_gate():
    with pytest.raises(ExtractionError, match="schema validation") as exc_info:
        extract_text({"schema_version": "nerb.bank.v1"}, "Acme Corp")

    assert any(diagnostic["code"] == "schema.required" for diagnostic in exc_info.value.diagnostics)


def test_extraction_option_validation_rejects_invalid_statuses_and_non_json_options(minimal_bank):
    with pytest.raises(ExtractionError, match="valid status strings"):
        extract_text(minimal_bank, "Acme Corp", options={"include_statuses": ["active", None]})

    with pytest.raises(ExtractionError, match="JSON-compatible"):
        extract_text(minimal_bank, "Acme Corp", options={"engine_options": {"nan": float("nan")}})


def test_status_filtering_defaults_to_active_chains_and_non_active_bank_errors(minimal_bank):
    _customer_patterns(minimal_bank)["inactive_alias"] = _literal_pattern("Acme", status="inactive")

    default_result = extract_text(minimal_bank, "Acme Corp and Acme")

    assert [record["pattern_id"] for record in default_result["records"]] == ["primary"]

    included_result = extract_text(
        minimal_bank,
        "Acme Corp and Acme",
        options={"include_statuses": ["active", "inactive"]},
    )

    assert [record["pattern_id"] for record in included_result["records"]] == [
        "inactive_alias",
        "inactive_alias",
    ]

    draft_bank = copy.deepcopy(minimal_bank)
    draft_bank["status"] = "draft"
    with pytest.raises(ExtractionError):
        extract_text(draft_bank, "Acme Corp")

    result = extract_text(draft_bank, "Acme Corp", options={"include_statuses": ["active", "draft"]})
    assert result["records"][0]["string"] == "Acme Corp"


def test_inactive_rust_incompatible_patterns_do_not_block_active_only_extraction(minimal_bank):
    _customer_patterns(minimal_bank)["inactive_backreference"] = _regex_pattern(r"\b([A-Z]+)-\1\b", status="inactive")

    result = extract_text(minimal_bank, "Acme Corp and ABC-ABC")

    assert [record["pattern_id"] for record in result["records"]] == ["primary"]
    with pytest.raises(ExtractionError, match="Rust engine validation"):
        extract_text(minimal_bank, "ABC-ABC", options={"include_statuses": ["active", "inactive"]})


def test_json_bank_extraction_rejects_ambiguous_source_detector_metadata(minimal_bank):
    customer = minimal_bank["entities"]["customer"]
    customer["names"] = {
        "first": {
            "canonical": "Acme Corp",
            "description": "First ambiguous fixture.",
            "status": "active",
            "patterns": {"alias": _regex_pattern(r"\bAcme\b")},
            "metadata": {},
        },
        "second": {
            "canonical": "Acme Corp",
            "description": "Second ambiguous fixture.",
            "status": "active",
            "patterns": {"alias": _regex_pattern(r"\bCorp\b")},
            "metadata": {},
        },
    }

    with pytest.raises(ExtractionError, match="ambiguous"):
        extract_text(minimal_bank, "Acme Corp")


def test_extraction_runtime_validation_does_not_do_a_separate_rust_compile(monkeypatch, minimal_bank):
    import nerb.validation as validation

    def fail_if_called(_bank):
        raise AssertionError("extraction should not run no-cache Rust validation compile")

    monkeypatch.setattr(validation, "_rust_engine_diagnostics", fail_if_called)

    assert extract_text(minimal_bank, "Acme Corp")["records"][0]["string"] == "Acme Corp"


def test_rust_bank_cache_key_dimensions_are_exposed(minimal_bank):
    clear_bank_cache()
    _customer_patterns(minimal_bank)["inactive_alias"] = _literal_pattern("Acme", status="inactive")

    first = extract_text(minimal_bank, "Acme Corp")
    second = extract_text(minimal_bank, "Acme Corp")
    with_status = extract_text(
        minimal_bank,
        "Acme Corp",
        options={"include_statuses": ["active", "inactive"]},
    )
    with_options = extract_text(
        minimal_bank,
        "Acme Corp",
        options={"engine_options": {"match_mode": "entity_independent"}},
    )

    assert first["engine"]["cache"]["hit"] is False
    assert second["engine"]["cache"]["hit"] is True
    assert with_options["engine"]["cache"]["hit"] is True
    assert bank_cache_info()["size"] == 2
    assert bank_cache_info()["hits"] == 2
    assert bank_cache_info()["misses"] == 2
    assert first["engine"]["cache"]["key"]["bank_hash"] == first["bank"]["hash"]
    assert with_status["engine"]["cache"]["key"]["bank_hash"] != first["engine"]["cache"]["key"]["bank_hash"]
    assert with_options["engine"]["cache"]["key"] == first["engine"]["cache"]["key"]


def test_json_bank_extraction_rejects_internal_match_modes(minimal_bank):
    with pytest.raises(ExtractionError, match="only supports match_mode 'entity_independent'"):
        extract_text(minimal_bank, "Acme Corp", options={"engine_options": {"match_mode": "global_leftmost"}})

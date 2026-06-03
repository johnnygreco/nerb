from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from nerb import (
    ExtractionError,
    clear_compiled_bank_cache,
    compiled_bank_cache_info,
    extract_batch,
    extract_file,
    extract_text,
    hash_bank,
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

    assert result["bank"] == {
        "id": "company_entities",
        "version": "2026.06.03",
        "schema_version": "nerb.bank.v1",
        "hash": hash_bank(minimal_bank),
    }
    assert result["engine"]["name"] == "python_re"
    assert result["engine"]["version"] == "1"
    assert result["source"] == {"type": "text", "length": 29, "bytes": 29}
    assert result["records"] == [
        {
            "entity_id": "customer",
            "entity": "customer",
            "name_id": "acme_corp",
            "name": "Acme Corp",
            "pattern_id": "primary",
            "pattern_kind": "literal",
            "string": "Acme Corp",
            "start": 13,
            "end": 22,
            "captures": {},
        }
    ]


def test_regex_records_named_captures_and_optional_capture_handling(minimal_bank):
    _set_customer_patterns(
        minimal_bank,
        {"invoice": _regex_pattern(r"(?P<prefix>INV)-(?P<number>\d+)(?:-(?P<suffix>[A-Z]+))?(?P<empty>)")},
    )

    result = extract_text(minimal_bank, "Please pay INV-123 now.")

    assert result["records"] == [
        {
            "entity_id": "customer",
            "entity": "customer",
            "name_id": "acme_corp",
            "name": "Acme Corp",
            "pattern_id": "invoice",
            "pattern_kind": "regex",
            "string": "INV-123",
            "start": 11,
            "end": 18,
            "captures": {
                "empty": {"string": "", "start": 18, "end": 18},
                "number": {"string": "123", "start": 15, "end": 18},
                "prefix": {"string": "INV", "start": 11, "end": 14},
            },
        }
    ]
    assert "suffix" not in result["records"][0]["captures"]
    assert all(not name.startswith("nerb__") for name in result["records"][0]["captures"])


def test_unicode_normalized_regex_matches_return_original_spans(minimal_bank):
    minimal_bank["unicode_normalization"] = "NFC"
    _set_customer_patterns(minimal_bank, {"accented": _regex_pattern("Café")})

    result = extract_text(minimal_bank, "Cafe\u0301 signed.")

    assert result["records"][0]["string"] == "Cafe\u0301"
    assert result["records"][0]["start"] == 0
    assert result["records"][0]["end"] == 5


def test_case_insensitive_literal_uses_casefold_with_original_spans(minimal_bank):
    _set_customer_patterns(minimal_bank, {"german": _literal_pattern("Straße", case_sensitive=False)})

    result = extract_text(minimal_bank, "STRASSE replied.")

    assert result["records"][0]["string"] == "STRASSE"
    assert result["records"][0]["start"] == 0
    assert result["records"][0]["end"] == 7


def test_raw_extraction_preserves_overlaps_duplicates_and_ordering(minimal_bank):
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

    assert [(record["pattern_id"], record["start"], record["end"]) for record in result["records"]] == [
        ("short", 0, 4),
        ("long", 0, 9),
        ("regex_duplicate", 0, 9),
    ]
    assert sort_keys == sorted(sort_keys)


def test_regex_entity_shards_preserve_duplicate_same_start_matches(minimal_bank):
    _set_customer_patterns(
        minimal_bank,
        {
            "first_regex": _regex_pattern(r"\bAcme\b"),
            "second_regex": _regex_pattern(r"\bAcme\b"),
        },
    )

    result = extract_text(minimal_bank, "Acme")

    assert [(record["pattern_id"], record["string"]) for record in result["records"]] == [
        ("first_regex", "Acme"),
        ("second_regex", "Acme"),
    ]


def test_regex_numeric_backreferences_are_preserved_under_internal_identity_wrapping(minimal_bank):
    _set_customer_patterns(minimal_bank, {"code": _regex_pattern(r"\b([A-Z]+)-\1\b")})

    result = extract_text(minimal_bank, "Ship ABC-ABC today.")

    assert result["records"][0]["string"] == "ABC-ABC"
    assert result["records"][0]["start"] == 5
    assert result["records"][0]["end"] == 12


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
        "primary",
        "inactive_alias",
    ]

    draft_bank = copy.deepcopy(minimal_bank)
    draft_bank["status"] = "draft"
    with pytest.raises(ExtractionError):
        extract_text(draft_bank, "Acme Corp")

    result = extract_text(draft_bank, "Acme Corp", options={"include_statuses": ["active", "draft"]})
    assert result["records"][0]["string"] == "Acme Corp"


def test_compiled_bank_cache_key_dimensions_are_exposed(minimal_bank):
    clear_compiled_bank_cache()

    first = extract_text(minimal_bank, "Acme Corp", options={"engine_options": {"probe": "a"}})
    second = extract_text(minimal_bank, "Acme Corp", options={"engine_options": {"probe": "a"}})
    with_status = extract_text(
        minimal_bank,
        "Acme Corp",
        options={"engine_options": {"probe": "a"}, "include_statuses": ["active", "inactive"]},
    )
    with_options = extract_text(minimal_bank, "Acme Corp", options={"engine_options": {"probe": "b"}})

    normalized_bank = copy.deepcopy(minimal_bank)
    normalized_bank["unicode_normalization"] = "NFKC"
    with_normalization = extract_text(normalized_bank, "Acme Corp", options={"engine_options": {"probe": "a"}})

    assert first["engine"]["cache"]["hit"] is False
    assert second["engine"]["cache"]["hit"] is True
    assert compiled_bank_cache_info() == {"size": 4, "hits": 1, "misses": 4}
    assert first["engine"]["cache"]["key"]["bank_hash"] == hash_bank(minimal_bank)
    assert first["engine"]["cache"]["key"]["engine_options"] == {"probe": "a"}
    assert with_status["engine"]["cache"]["key"]["include_statuses"] == ["active", "inactive"]
    assert with_options["engine"]["cache"]["key"]["engine_options"] == {"probe": "b"}
    assert with_normalization["engine"]["cache"]["key"]["normalization"] == "NFKC"


def test_compiled_bank_cache_hit_skips_runtime_validation(monkeypatch, minimal_bank):
    import nerb.validation as validation

    clear_compiled_bank_cache()

    first = extract_text(minimal_bank, "Acme Corp")

    def fail_runtime_validation(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise AssertionError("runtime validation should not run for a compiled-bank cache hit")

    monkeypatch.setattr(validation, "validate_bank", fail_runtime_validation)

    second = extract_text(minimal_bank, "Acme Corp")

    assert first["engine"]["cache"]["hit"] is False
    assert second["engine"]["cache"]["hit"] is True

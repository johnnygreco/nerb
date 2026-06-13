from __future__ import annotations

import copy

import pytest

from nerb import deanonymize_file as root_deanonymize_file
from nerb import deanonymize_text as root_deanonymize_text
from nerb.deanonymization import (
    ByteEdit,
    DeanonymizationError,
    _anonymize_config_text_with_db_update,
    allocate_assignment,
    anonymize_config_text,
    anonymize_file,
    anonymize_text,
    apply_byte_replacements,
    assignment_key,
    build_reverse_bank,
    deanonymize_file,
    deanonymize_text,
    finalize_replacement_db_update,
    reverse_bank_fingerprint,
)
from nerb.replacements import (
    create_replacement_db,
    hash_replacement_db,
    load_replacement_db,
    save_replacement_db,
    validate_replacement_db,
)
from nerb.schema import validate_bank_schema


def _span(text: str, value: str) -> tuple[int, int]:
    encoded_text = text.encode("utf-8")
    encoded_value = value.encode("utf-8")
    start = encoded_text.index(encoded_value)
    return start, start + len(encoded_value)


def _record(
    *,
    entity_id: str = "person",
    name_id: str = "john_smith",
    canonical_name: str = "John Smith",
    string: str = "John Smith",
) -> dict:
    return {
        "entity_id": entity_id,
        "name_id": name_id,
        "canonical_name": canonical_name,
        "surface_name": canonical_name,
        "string": string,
        "start": 0,
        "end": len(string.encode("utf-8")),
        "offset_unit": "byte",
    }


def _pseudonym_db(*, reuse: bool = False, store_originals: bool = True) -> dict:
    db = create_replacement_db(reversible=store_originals, now="2026-06-13T00:00:00Z")
    db["defaults"]["replacement_mode"] = "pseudonym"
    db["defaults"]["replacement_set_id"] = "person_names"
    db["defaults"]["store_originals"] = store_originals
    db["replacement_sets"]["person_names"] = {
        "description": "Reserved fake person names.",
        "reuse": reuse,
        "candidates": [
            {"id": "person_name_0001", "value": "Mikey Law", "metadata": {}},
            {"id": "person_name_0002", "value": "Nina Vale", "metadata": {}},
        ],
        "metadata": {},
    }
    return db


def _literal_pattern(value: str, *, priority: int = 50) -> dict:
    return {
        "kind": "literal",
        "value": value,
        "description": "Literal deanonymization fixture.",
        "status": "active",
        "priority": priority,
        "case_sensitive": True,
        "normalize_whitespace": True,
        "left_boundary": "word",
        "right_boundary": "word",
        "metadata": {},
    }


def _regex_pattern(value: str, *, priority: int = 50) -> dict:
    return {
        "kind": "regex",
        "value": value,
        "description": "Regex deanonymization fixture.",
        "status": "active",
        "priority": priority,
        "regex_flags": [],
        "metadata": {},
    }


def _person_bank(*, extra_people: bool = False, include_alias: bool = True) -> dict:
    names = {
        "john_smith": {
            "canonical": "John Smith",
            "description": "John Smith fixture.",
            "status": "active",
            "patterns": {"primary": _literal_pattern("John Smith", priority=100)},
            "metadata": {},
        }
    }
    if include_alias:
        names["john_smith"]["patterns"]["alias"] = _literal_pattern("Johnny", priority=90)
    if extra_people:
        names["jane_smith"] = {
            "canonical": "Jane Smith",
            "description": "Jane Smith fixture.",
            "status": "active",
            "patterns": {"primary": _literal_pattern("Jane Smith", priority=100)},
            "metadata": {},
        }
        names["alex_smith"] = {
            "canonical": "Alex Smith",
            "description": "Alex Smith fixture.",
            "status": "active",
            "patterns": {"primary": _literal_pattern("Alex Smith", priority=100)},
            "metadata": {},
        }

    return {
        "schema_version": "nerb.bank.v1",
        "id": "people",
        "name": "People",
        "description": "People fixture.",
        "version": "2026.06.13",
        "status": "active",
        "created_at": "2026-06-13T00:00:00Z",
        "updated_at": "2026-06-13T00:00:00Z",
        "unicode_normalization": "none",
        "default_regex_flags": [],
        "entities": {
            "person": {
                "description": "Known people.",
                "status": "active",
                "regex_flags": [],
                "names": names,
                "metadata": {},
            }
        },
        "metadata": {},
    }


def test_apply_byte_replacements_handles_multibyte_text_and_reports_final_byte_spans():
    text = "å John 😀 Smith 東京"
    john_start, john_end = _span(text, "John")
    tokyo_start, tokyo_end = _span(text, "東京")

    result = apply_byte_replacements(
        text,
        [
            ByteEdit(john_start, john_end, "Jane", expected="John"),
            ByteEdit(tokyo_start, tokyo_end, "Osaka", expected="東京"),
        ],
    )

    assert result.text == "å Jane 😀 Smith Osaka"
    assert [edit.original_span.as_dict() for edit in result.applied_edits] == [
        {"start": john_start, "end": john_end, "offset_unit": "byte"},
        {"start": tokyo_start, "end": tokyo_end, "offset_unit": "byte"},
    ]
    assert [edit.replacement_span.as_dict() for edit in result.applied_edits] == [
        {"start": john_start, "end": john_start + len(b"Jane"), "offset_unit": "byte"},
        {
            "start": tokyo_start + len(b"Jane") - len(b"John"),
            "end": tokyo_start + len(b"Jane") - len(b"John") + len(b"Osaka"),
            "offset_unit": "byte",
        },
    ]


def test_apply_byte_replacements_rejects_overlap_invalid_spans_and_source_mismatch():
    text = "John Smith"

    with pytest.raises(DeanonymizationError) as overlap_info:
        apply_byte_replacements(text, [ByteEdit(0, 6, "A"), ByteEdit(5, 10, "B")])
    assert overlap_info.value.diagnostics[0]["code"] == "rewrite.overlap"

    with pytest.raises(DeanonymizationError) as invalid_info:
        apply_byte_replacements(text, [ByteEdit(-1, 4, "A")])
    assert invalid_info.value.diagnostics[0]["code"] == "rewrite.invalid_span"

    with pytest.raises(DeanonymizationError) as mismatch_info:
        apply_byte_replacements(text, [ByteEdit(0, 4, "A", expected="Jane")])
    assert mismatch_info.value.diagnostics[0]["code"] == "rewrite.source_mismatch"


def test_apply_byte_replacements_rejects_split_utf8_boundaries_and_zero_length_edits():
    with pytest.raises(DeanonymizationError) as split_info:
        apply_byte_replacements("éé", [ByteEdit(1, 3, "")])
    assert split_info.value.diagnostics[0]["code"] == "rewrite.invalid_span"

    with pytest.raises(DeanonymizationError) as zero_length_info:
        apply_byte_replacements("John", [ByteEdit(0, 0, "X")])
    assert zero_length_info.value.diagnostics[0]["code"] == "rewrite.invalid_span"


def test_assignment_keys_are_stable_by_scope_and_unicode_normalization():
    name_policy = {"assignment_scope": "name", "unicode_normalization": "NFC", "store_originals": False}
    canonical_policy = {"assignment_scope": "canonical", "unicode_normalization": "NFC", "store_originals": False}
    surface_policy = {"assignment_scope": "surface", "unicode_normalization": "NFC", "store_originals": False}
    composed = _record(canonical_name="José", string="José")
    decomposed = _record(canonical_name="Jose\u0301", string="Jose\u0301")

    assert assignment_key(composed, name_policy) == assignment_key(decomposed, name_policy)
    assert assignment_key(composed, canonical_policy) == assignment_key(decomposed, canonical_policy)
    assert assignment_key(composed, surface_policy) == assignment_key(decomposed, surface_policy)
    assert (
        len(
            {
                assignment_key(composed, name_policy),
                assignment_key(composed, canonical_policy),
                assignment_key(composed, surface_policy),
            }
        )
        == 3
    )


def test_assignment_keys_map_config_style_entities_for_canonical_and_surface_scopes():
    canonical_policy = {"assignment_scope": "canonical", "unicode_normalization": "NFC", "store_originals": False}
    surface_policy = {"assignment_scope": "surface", "unicode_normalization": "NFC", "store_originals": False}
    config_record = {"entity": "ARTIST", "canonical_name": "Miles Davis", "string": "Miles Davis"}

    assert assignment_key(config_record, canonical_policy).startswith("artist_")
    assert "|canonical|sha256:" in assignment_key(config_record, canonical_policy)
    assert assignment_key(config_record, surface_policy).startswith("artist_")
    assert "|surface|sha256:" in assignment_key(config_record, surface_policy)


def test_assignment_keys_do_not_merge_distinct_config_style_entity_names():
    canonical_policy = {"assignment_scope": "canonical", "unicode_normalization": "NFC", "store_originals": False}
    upper_record = {"entity": "ARTIST", "canonical_name": "Miles Davis", "string": "Miles Davis"}
    lower_record = {"entity": "artist", "canonical_name": "Miles Davis", "string": "Miles Davis"}
    spaced_record = {"entity": " artist ", "canonical_name": "Miles Davis", "string": "Miles Davis"}

    assert assignment_key(upper_record, canonical_policy) != assignment_key(lower_record, canonical_policy)
    assert assignment_key(spaced_record, canonical_policy) != assignment_key(lower_record, canonical_policy)
    assert assignment_key(lower_record, canonical_policy).startswith("artist|canonical|sha256:")


def test_assignment_keys_reject_missing_required_fields():
    with pytest.raises(DeanonymizationError) as name_info:
        assignment_key({"entity_id": "person", "string": "John"}, {"assignment_scope": "name"})
    assert name_info.value.diagnostics[0]["path"] == "/name_id"

    with pytest.raises(DeanonymizationError) as canonical_info:
        assignment_key({"entity_id": "person", "string": "John"}, {"assignment_scope": "canonical"})
    assert canonical_info.value.diagnostics[0]["path"] == "/canonical_name"

    with pytest.raises(DeanonymizationError) as surface_info:
        assignment_key({"entity_id": "person", "name_id": "john"}, {"assignment_scope": "surface"})
    assert surface_info.value.diagnostics[0]["path"] == "/string"


def test_assignment_keys_reject_malformed_policy_fields_with_diagnostics():
    with pytest.raises(DeanonymizationError) as scope_info:
        assignment_key(_record(), {"assignment_scope": ["name"]})
    assert scope_info.value.diagnostics[0]["path"] == "/assignment_scope"

    with pytest.raises(DeanonymizationError) as normalization_type_info:
        assignment_key(_record(), {"unicode_normalization": ["NFC"]})
    assert normalization_type_info.value.diagnostics[0]["path"] == "/unicode_normalization"

    with pytest.raises(DeanonymizationError) as normalization_value_info:
        assignment_key(_record(), {"unicode_normalization": "NFD"})
    assert normalization_value_info.value.diagnostics[0]["path"] == "/unicode_normalization"


def test_anonymize_config_text_uses_canonical_scope_for_config_records():
    pattern_config = {"ARTIST": {"Miles Davis": r"Miles Davis|M\. Davis"}}
    db = create_replacement_db(reversible=True, assignment_scope="canonical", now="2026-06-13T00:00:00Z")

    response, updated_db = _anonymize_config_text_with_db_update(
        pattern_config,
        "Miles Davis met M. Davis.",
        db,
        options={"mode": "redact"},
    )
    public_response = anonymize_config_text(
        pattern_config,
        "Miles Davis met M. Davis.",
        db,
        options={"mode": "redact"},
    )
    restored = deanonymize_text(response["text"], updated_db)

    first_token, second_token = response["text"].removesuffix(".").split(" met ")
    assert response["schema_version"] == "nerb.anonymize_response.v1"
    assert response["bank"] == {"bank_ref": "b1", "schema_version": "nerb.detector_config.v1", "version": "1"}
    assert first_token == second_token
    assert len(updated_db["assignments"]) == 1
    assert restored["text"] == "Miles Davis met Miles Davis."
    assert public_response["text"] == response["text"]


def test_anonymize_config_text_uses_surface_scope_for_exact_surface_restoration():
    pattern_config = {"TICKET": {"Ticket": r"A-\d+"}}
    db = create_replacement_db(reversible=True, assignment_scope="surface", now="2026-06-13T00:00:00Z")

    response, updated_db = _anonymize_config_text_with_db_update(
        pattern_config,
        "A-123 then A-124",
        db,
        options={"mode": "redact"},
    )
    restored = deanonymize_text(response["text"], updated_db)

    first_token, second_token = response["text"].split(" then ")
    assert first_token != second_token
    assert len(updated_db["assignments"]) == 2
    assert restored["text"] == "A-123 then A-124"


def test_pseudonym_allocation_is_deterministic_reuses_existing_and_reports_exhaustion():
    db = _pseudonym_db()
    first = allocate_assignment(
        _record(name_id="john_smith", canonical_name="John Smith"),
        db,
        now="2026-06-13T00:00:00Z",
    )
    second = allocate_assignment(
        _record(name_id="jane_smith", canonical_name="Jane Smith"),
        first.replacement_db,
        now="2026-06-13T00:00:00Z",
    )
    reused = allocate_assignment(
        _record(name_id="john_smith", canonical_name="John Smith"),
        second.replacement_db,
        now="2026-06-13T00:00:00Z",
    )
    exhausted = allocate_assignment(
        _record(name_id="alex_smith", canonical_name="Alex Smith"),
        second.replacement_db,
        now="2026-06-13T00:00:00Z",
    )

    assert first.created is True
    assert second.created is True
    assert reused.created is False
    assert first.assignment is not None
    assert second.assignment is not None
    assert first.assignment["replacement"]["candidate_id"] == "person_name_0001"
    assert second.assignment["replacement"]["candidate_id"] == "person_name_0002"
    assert reused.assignment == first.assignment
    assert exhausted.assignment is None
    assert exhausted.diagnostics[0]["code"] == "replacement_db.candidates_exhausted"
    assert validate_replacement_db(second.replacement_db)["valid"] is True


def test_allocation_result_assignment_does_not_alias_replacement_db_assignment():
    db = _pseudonym_db()
    result = allocate_assignment(
        _record(name_id="john_smith", canonical_name="John Smith"),
        db,
        now="2026-06-13T00:00:00Z",
    )

    assert result.assignment is not None
    result.assignment["replacement"]["value"] = "Mutated Name"

    stored_assignment = result.replacement_db["assignments"][result.assignment_key]
    assert stored_assignment["replacement"]["value"] == "Mikey Law"
    assert validate_replacement_db(result.replacement_db)["valid"] is True


def test_finalize_replacement_db_update_increments_once_for_save_cycle(tmp_path):
    db = _pseudonym_db()
    path = save_replacement_db(db, tmp_path / "replacements.json")
    loaded = load_replacement_db(path)
    expected_hash = hash_replacement_db(loaded)
    first = allocate_assignment(
        _record(name_id="john_smith", canonical_name="John Smith"),
        loaded,
        now="2026-06-13T00:00:00Z",
    )
    second = allocate_assignment(
        _record(name_id="jane_smith", canonical_name="Jane Smith"),
        first.replacement_db,
        now="2026-06-13T00:00:00Z",
    )

    finalized = finalize_replacement_db_update(
        second.replacement_db,
        base_version=loaded["version"],
        now="2026-06-13T00:00:01Z",
    )
    save_replacement_db(finalized, path, expected_hash=expected_hash, expected_version=loaded["version"])
    saved = load_replacement_db(path)

    assert saved["version"] == 2
    assert saved["updated_at"] == "2026-06-13T00:00:01Z"
    assert len(saved["assignments"]) == 2


def test_pseudonym_allocation_with_reuse_advances_to_avoid_reverse_ambiguity():
    db = _pseudonym_db(reuse=True)
    first = allocate_assignment(
        _record(name_id="john_smith", canonical_name="John Smith"),
        db,
        now="2026-06-13T00:00:00Z",
    )
    second = allocate_assignment(
        _record(name_id="jane_smith", canonical_name="Jane Smith"),
        first.replacement_db,
        now="2026-06-13T00:00:00Z",
    )
    third = allocate_assignment(
        _record(name_id="alex_smith", canonical_name="Alex Smith"),
        second.replacement_db,
        now="2026-06-13T00:00:00Z",
    )

    assert first.assignment is not None
    assert second.assignment is not None
    assert first.assignment["replacement"]["value"] != second.assignment["replacement"]["value"]
    assert third.assignment is None
    assert third.diagnostics[0]["code"] == "replacement_db.candidates_exhausted"
    assert validate_replacement_db(second.replacement_db)["valid"] is True


def test_redaction_allocation_persists_entity_ordinals_across_existing_assignments():
    db = create_replacement_db(reversible=True, now="2026-06-13T00:00:00Z")
    db["entities"]["person"] = {"redaction_template": "[PERSON_{ordinal:04d}]", "store_originals": True}
    first = allocate_assignment(_record(name_id="john_smith"), db, now="2026-06-13T00:00:00Z")
    second = allocate_assignment(_record(name_id="jane_smith", canonical_name="Jane Smith"), first.replacement_db)
    reused = allocate_assignment(_record(name_id="john_smith"), second.replacement_db)

    assert first.assignment is not None
    assert second.assignment is not None
    assert reused.assignment is not None
    assert first.assignment["redaction"] == {"token": "[PERSON_0001]", "ordinal": 1}
    assert second.assignment["redaction"] == {"token": "[PERSON_0002]", "ordinal": 2}
    assert reused.assignment["redaction"] == first.assignment["redaction"]
    assert validate_replacement_db(second.replacement_db)["valid"] is True


def test_store_originals_false_assignments_omit_originals_and_sensitive_identity_fields():
    db = create_replacement_db(now="2026-06-13T00:00:00Z")
    result = allocate_assignment(_record(), db, now="2026-06-13T00:00:00Z")

    assert result.assignment is not None
    assert result.created is True
    assert "original" not in result.assignment
    assert result.assignment["identity"] == {
        "scope": "name",
        "fingerprint": result.assignment["identity"]["fingerprint"],
    }
    assert validate_replacement_db(result.replacement_db)["valid"] is True


def test_store_originals_false_assignment_results_do_not_repr_plaintext_originals():
    db = create_replacement_db(now="2026-06-13T00:00:00Z")
    result = allocate_assignment(_record(), db, now="2026-06-13T00:00:00Z")

    assert "John" not in repr(result)
    assert "john_smith" not in repr(result)


def test_allocation_reports_missing_assignment_when_new_assignments_are_disabled():
    db = create_replacement_db(now="2026-06-13T00:00:00Z")
    db["defaults"]["allow_new_assignments"] = False

    result = allocate_assignment(_record(), db)

    assert result.assignment is None
    assert result.created is False
    assert result.diagnostics[0]["code"] == "replacement_db.missing_assignment"
    assert result.replacement_db["assignments"] == {}


def test_anonymize_text_pseudonymizes_json_bank_matches_with_safe_default_payload():
    db = _pseudonym_db(store_originals=True)
    source = "John Smith met John Smith."

    result = anonymize_text(_person_bank(include_alias=False), source, db, options={"mode": "pseudonym"})

    assert result["schema_version"] == "nerb.anonymize_response.v1"
    assert result["text"] == "Mikey Law met Mikey Law."
    assert result["bank"] == {
        "bank_ref": "b1",
        "version": "2026.06.13",
        "schema_version": "nerb.bank.v1",
    }
    assert result["replacement_db"] == {
        "replacement_db_ref": "rdb1",
        "schema_version": "nerb.replacements.v1",
        "version": 1,
        "modified": True,
        "saved": False,
    }
    assert result["source"] == {"type": "text", "length": len(source), "bytes": len(source.encode("utf-8"))}
    assert result["summary"] == {"record_count": 2, "applied_count": 2, "diagnostic_count": 0}
    assert result["diagnostics"] == []
    assert db["assignments"] == {}

    applied = result["applied_replacements"]
    assert applied == [
        {
            "assignment_ref": "a1",
            "entity": "person",
            "mode": "pseudonym",
            "original_span": {"start": 0, "end": 10, "offset_unit": "byte"},
            "replacement_span": {"start": 0, "end": 9, "offset_unit": "byte"},
            "replacement": "Mikey Law",
        },
        {
            "assignment_ref": "a1",
            "entity": "person",
            "mode": "pseudonym",
            "original_span": {"start": 15, "end": 25, "offset_unit": "byte"},
            "replacement_span": {"start": 14, "end": 23, "offset_unit": "byte"},
            "replacement": "Mikey Law",
        },
    ]
    assert "John Smith" not in repr(result)
    assert "john_smith" not in repr(result)
    assert "assignment_key" not in repr(result)
    assert "fingerprint" not in repr(result)
    assert "hash" not in result["bank"]
    assert "id" not in result["bank"]
    assert "data" not in result["replacement_db"]


def test_anonymize_text_sensitive_options_return_debug_metadata_and_updated_db():
    result = anonymize_text(
        _person_bank(include_alias=False),
        "John Smith joined.",
        _pseudonym_db(store_originals=True),
        options={"mode": "pseudonym", "include_originals": True, "include_sensitive_metadata": True},
    )

    applied = result["applied_replacements"][0]
    assignment_key_value = applied["assignment_key"]

    assert result["text"] == "Mikey Law joined."
    assert result["bank"]["id"] == "people"
    assert result["bank"]["hash"].startswith("sha256:")
    assert result["replacement_db"]["id"] == "replacements"
    assert result["replacement_db"]["hash"].startswith("sha256:")
    assert applied["original"] == "John Smith"
    assert applied["fingerprint"].startswith("sha256:")
    assert applied["source_record"] == {
        "entity_id": "person",
        "name_id": "john_smith",
        "pattern_id": "primary",
        "pattern_kind": "literal",
        "canonical_name": "John Smith",
        "surface_name": "John Smith",
    }
    assert result["replacement_db"]["data"]["assignments"][assignment_key_value]["replacement"] == {
        "mode": "pseudonym",
        "value": "Mikey Law",
        "set_id": "person_names",
        "candidate_id": "person_name_0001",
    }


def test_anonymize_text_redaction_mode_works_without_candidate_sets_and_byte_spans():
    db = create_replacement_db(reversible=True, now="2026-06-13T00:00:00Z")
    source = "Café John Smith now."
    start, end = _span(source, "John Smith")

    result = anonymize_text(_person_bank(include_alias=False), source, db, options={"mode": "redact"})

    assert result["text"] == "Café [PERSON_0001] now."
    assert result["replacement_db"]["modified"] is True
    assert result["replacement_db"]["saved"] is False
    assert result["applied_replacements"] == [
        {
            "assignment_ref": "a1",
            "entity": "person",
            "mode": "redact",
            "original_span": {"start": start, "end": end, "offset_unit": "byte"},
            "replacement_span": {
                "start": start,
                "end": start + len(b"[PERSON_0001]"),
                "offset_unit": "byte",
            },
            "replacement": "[PERSON_0001]",
        }
    ]


def test_anonymize_text_explicit_mode_mismatch_reports_diagnostic_instead_of_wrong_reuse():
    pseudonym_result = anonymize_text(
        _person_bank(include_alias=False),
        "John Smith",
        _pseudonym_db(store_originals=True),
        options={"mode": "pseudonym", "include_sensitive_metadata": True},
    )
    db_with_pseudonym_assignment = pseudonym_result["replacement_db"]["data"]

    result = anonymize_text(
        _person_bank(include_alias=False),
        "John Smith",
        db_with_pseudonym_assignment,
        options={"mode": "redact"},
    )

    assert result["text"] == "John Smith"
    assert result["applied_replacements"] == []
    assert result["summary"] == {"record_count": 1, "applied_count": 0, "diagnostic_count": 1}
    assert result["diagnostics"][0]["code"] == "replacement_db.assignment_mode_mismatch"
    assert result["diagnostics"][0]["path"] == "/assignments"
    assert result["diagnostics"][0]["metadata"] == {"assignment_ref": "a1", "entity": "person"}
    assert "assignment_key" not in repr(result)

    with pytest.raises(DeanonymizationError) as fail_info:
        anonymize_text(
            _person_bank(include_alias=False),
            "John Smith",
            db_with_pseudonym_assignment,
            options={"mode": "redact", "on_missing_assignment": "fail"},
        )
    assert fail_info.value.diagnostics[0]["code"] == "replacement_db.assignment_mode_mismatch"
    assert "assignment_key" not in repr(fail_info.value.diagnostics)

    skip_result = anonymize_text(
        _person_bank(include_alias=False),
        "John Smith",
        db_with_pseudonym_assignment,
        options={"mode": "redact", "on_missing_assignment": "skip"},
    )
    assert skip_result["diagnostics"][0]["code"] == "replacement_db.assignment_mode_mismatch"


def test_anonymize_file_reports_file_source_and_does_not_save(tmp_path):
    source_path = tmp_path / "source.txt"
    source = "John Smith joined."
    source_path.write_text(source, encoding="utf-8")

    result = anonymize_file(
        _person_bank(include_alias=False),
        source_path,
        _pseudonym_db(store_originals=True),
        options={"mode": "pseudonym"},
    )

    assert result["text"] == "Mikey Law joined."
    assert result["source"] == {
        "type": "file",
        "length": len(source),
        "bytes": len(source.encode("utf-8")),
        "source_ref": "s1",
    }
    assert result["replacement_db"]["modified"] is True
    assert result["replacement_db"]["saved"] is False
    assert str(source_path) not in repr(result)

    sensitive_result = anonymize_file(
        _person_bank(include_alias=False),
        source_path,
        _pseudonym_db(store_originals=True),
        options={"mode": "pseudonym", "include_sensitive_metadata": True},
    )
    assert sensitive_result["source"]["path"] == str(source_path)


def test_anonymize_file_preserves_crlf_bytes_and_enforces_extraction_file_limit(tmp_path):
    source_path = tmp_path / "source.txt"
    source_bytes = b"John Smith\r\njoined."
    source_path.write_bytes(source_bytes)

    result = anonymize_file(
        _person_bank(include_alias=False),
        source_path,
        _pseudonym_db(store_originals=True),
        options={"mode": "pseudonym"},
    )

    assert result["text"] == "Mikey Law\r\njoined."
    assert result["source"] == {
        "type": "file",
        "length": len("John Smith\r\njoined."),
        "bytes": len(source_bytes),
        "source_ref": "s1",
    }

    with pytest.raises(DeanonymizationError) as limit_info:
        anonymize_file(
            _person_bank(include_alias=False),
            source_path,
            _pseudonym_db(store_originals=True),
            options={"mode": "pseudonym", "max_text_bytes": 4},
        )
    assert limit_info.value.diagnostics[0]["code"] == "anonymize.extraction_error"


def test_anonymize_text_name_scope_aliases_share_replacement_and_surface_scope_splits_surfaces():
    bank = _person_bank(include_alias=True)
    source = "John Smith and Johnny"

    name_scope_result = anonymize_text(bank, source, _pseudonym_db(), options={"mode": "pseudonym"})

    surface_scope_db = _pseudonym_db()
    surface_scope_db["defaults"]["assignment_scope"] = "surface"
    surface_scope_result = anonymize_text(bank, source, surface_scope_db, options={"mode": "pseudonym"})

    assert name_scope_result["text"] == "Mikey Law and Mikey Law"
    assert [item["assignment_ref"] for item in name_scope_result["applied_replacements"]] == ["a1", "a1"]
    assert surface_scope_result["text"] == "Mikey Law and Nina Vale"
    assert [item["assignment_ref"] for item in surface_scope_result["applied_replacements"]] == ["a1", "a2"]


def test_anonymize_text_missing_assignment_policies_are_deterministic():
    db = create_replacement_db(now="2026-06-13T00:00:00Z")
    db["defaults"]["allow_new_assignments"] = False

    diagnostic_result = anonymize_text(_person_bank(include_alias=False), "John Smith", db)
    skip_result = anonymize_text(
        _person_bank(include_alias=False),
        "John Smith",
        db,
        options={"on_missing_assignment": "skip"},
    )

    assert diagnostic_result["text"] == "John Smith"
    assert diagnostic_result["applied_replacements"] == []
    assert diagnostic_result["summary"] == {"record_count": 1, "applied_count": 0, "diagnostic_count": 1}
    assert diagnostic_result["diagnostics"][0]["code"] == "replacement_db.missing_assignment"
    assert diagnostic_result["diagnostics"][0]["metadata"] == {"assignment_ref": "a1", "entity": "person"}
    assert "assignment_key" not in repr(diagnostic_result)
    assert skip_result["text"] == "John Smith"
    assert skip_result["diagnostics"] == []

    with pytest.raises(DeanonymizationError) as fail_info:
        anonymize_text(
            _person_bank(include_alias=False),
            "John Smith",
            db,
            options={"on_missing_assignment": "fail"},
        )
    assert fail_info.value.diagnostics[0]["code"] == "replacement_db.missing_assignment"


def test_anonymize_text_reports_exhausted_pseudonym_candidates_without_rewriting_that_span():
    result = anonymize_text(
        _person_bank(extra_people=True, include_alias=False),
        "John Smith Jane Smith Alex Smith",
        _pseudonym_db(),
        options={"mode": "pseudonym"},
    )

    assert result["text"] == "Mikey Law Nina Vale Alex Smith"
    assert result["summary"] == {"record_count": 3, "applied_count": 2, "diagnostic_count": 1}
    assert [item["replacement"] for item in result["applied_replacements"]] == ["Mikey Law", "Nina Vale"]
    assert result["diagnostics"][0]["code"] == "replacement_db.candidates_exhausted"
    assert result["diagnostics"][0]["path"] == "/replacement_sets"
    assert "person_names" not in result["diagnostics"][0]["message"]
    assert result["diagnostics"][0]["metadata"] == {"assignment_ref": "a3", "entity": "person"}


def test_anonymize_text_passes_max_text_bytes_to_json_bank_extraction():
    with pytest.raises(DeanonymizationError) as exc_info:
        anonymize_text(
            _person_bank(include_alias=False),
            "John Smith",
            _pseudonym_db(),
            options={"mode": "pseudonym", "max_text_bytes": 4},
        )
    assert exc_info.value.diagnostics[0]["code"] == "anonymize.extraction_error"


def test_anonymize_text_rejects_invalid_options_with_diagnostics():
    with pytest.raises(DeanonymizationError) as mode_info:
        anonymize_text(_person_bank(include_alias=False), "John Smith", _pseudonym_db(), options={"mode": "mask"})
    assert mode_info.value.diagnostics[0]["path"] == "/options/mode"

    with pytest.raises(DeanonymizationError) as originals_info:
        anonymize_text(
            _person_bank(include_alias=False),
            "John Smith",
            _pseudonym_db(),
            options={"include_originals": "yes"},
        )
    assert originals_info.value.diagnostics[0]["path"] == "/options/include_originals"


def test_anonymize_text_does_not_mutate_replacement_db_input():
    db = _pseudonym_db()
    original = copy.deepcopy(db)

    anonymize_text(_person_bank(include_alias=False), "John Smith", db, options={"mode": "pseudonym"})

    assert db == original


def test_anonymize_text_sanitizes_bank_schema_diagnostics_by_default():
    bank = _person_bank(include_alias=False)
    bank["entities"]["person"]["names"]["john_smith"]["patterns"]["primary"]["priority"] = "bad"

    with pytest.raises(DeanonymizationError) as exc_info:
        anonymize_text(bank, "John Smith", _pseudonym_db(), options={"mode": "pseudonym"})

    diagnostics_repr = repr(exc_info.value.diagnostics)
    assert exc_info.value.diagnostics[0]["path"] == "/bank"
    assert "john_smith" not in diagnostics_repr
    assert "primary" not in diagnostics_repr
    assert "person" not in diagnostics_repr
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None

    with pytest.raises(DeanonymizationError) as sensitive_info:
        anonymize_text(
            bank,
            "John Smith",
            _pseudonym_db(),
            options={"mode": "pseudonym", "include_sensitive_metadata": True},
        )
    assert sensitive_info.value.__cause__ is not None


def test_anonymize_text_sanitizes_extraction_runtime_metadata_by_default():
    bank = _person_bank(include_alias=False)
    bank["entities"]["person"]["names"]["john_smith"]["canonical"] = "Secret Person"
    bank["entities"]["person"]["names"]["john_smith"]["patterns"]["primary"] = _regex_pattern("a*")

    with pytest.raises(DeanonymizationError) as exc_info:
        anonymize_text(bank, "Secret Person", _pseudonym_db(), options={"mode": "pseudonym"})

    diagnostics_repr = repr(exc_info.value.diagnostics)
    assert exc_info.value.diagnostics[0]["code"] == "regex.matches_empty"
    assert "Secret Person" not in diagnostics_repr
    assert "canonical_name" not in diagnostics_repr
    assert "surface_name" not in diagnostics_repr
    assert "probe" not in diagnostics_repr


def test_anonymize_text_sanitizes_replacement_validation_diagnostics_by_default():
    db = _pseudonym_db(store_originals=True)
    allocated = allocate_assignment(_record(), db, now="2026-06-13T00:00:00Z").replacement_db
    first_assignment_key = next(iter(allocated["assignments"]))
    second_assignment_key = assignment_key(
        _record(name_id="jane_smith", canonical_name="Jane Smith"),
        allocated["defaults"],
    )
    duplicated_assignment = copy.deepcopy(allocated["assignments"][first_assignment_key])
    duplicated_assignment["assignment_key"] = second_assignment_key
    duplicated_assignment["identity"]["fingerprint"] = second_assignment_key.split("|", 2)[2]
    duplicated_assignment["identity"]["name_id"] = "jane_smith"
    duplicated_assignment["identity"]["canonical_name"] = "Jane Smith"
    duplicated_assignment["original"]["canonical"] = "Jane Smith"
    allocated["assignments"][second_assignment_key] = duplicated_assignment

    with pytest.raises(DeanonymizationError) as exc_info:
        anonymize_text(_person_bank(include_alias=False), "John Smith", allocated, options={"mode": "pseudonym"})

    diagnostics_repr = repr(exc_info.value.diagnostics)
    assert all("|sha256:" not in item["path"] for item in exc_info.value.diagnostics)
    assert "person_names" not in diagnostics_repr
    assert "john_smith" not in diagnostics_repr
    assert first_assignment_key not in diagnostics_repr
    assert second_assignment_key not in diagnostics_repr


def test_anonymize_text_sanitizes_replacement_policy_messages_by_default():
    db = _pseudonym_db(store_originals=True)
    db["defaults"]["redaction_template"] = "[{SECRET_PERSON}_{ordinal:04d}]"

    with pytest.raises(DeanonymizationError) as exc_info:
        anonymize_text(_person_bank(include_alias=False), "John Smith", db, options={"mode": "pseudonym"})

    diagnostics_repr = repr(exc_info.value.diagnostics)
    assert exc_info.value.diagnostics[0]["code"] == "replacement_db.invalid_redaction_template"
    assert "SECRET_PERSON" not in diagnostics_repr
    assert exc_info.value.diagnostics[0]["message"] == "Diagnostic details are redacted by default."
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None

    with pytest.raises(DeanonymizationError) as sensitive_info:
        anonymize_text(
            _person_bank(include_alias=False),
            "John Smith",
            db,
            options={"mode": "pseudonym", "include_sensitive_metadata": True},
        )
    assert sensitive_info.value.__cause__ is not None


def test_build_reverse_bank_is_valid_and_opaque_by_default():
    anonymized = anonymize_text(
        _person_bank(include_alias=False),
        "John Smith joined.",
        create_replacement_db(reversible=True, now="2026-06-13T00:00:00Z"),
        options={"mode": "redact", "include_sensitive_metadata": True},
    )
    db = anonymized["replacement_db"]["data"]

    reverse_bank = build_reverse_bank(db)

    assert validate_bank_schema(reverse_bank)["valid"] is True
    reverse_repr = repr(reverse_bank)
    assignment_key_value = next(iter(db["assignments"]))
    assert "[PERSON_0001]" in reverse_repr
    assert reverse_bank["version"] == "generated"
    assert list(reverse_bank["entities"]) == ["r_000000000001"]
    assert list(next(iter(reverse_bank["entities"].values()))["names"]) == ["a_000000000001"]
    assert "John Smith" not in reverse_repr
    assert "john_smith" not in reverse_repr
    assert assignment_key_value not in reverse_repr
    assert "|sha256:" not in reverse_repr
    assert reverse_bank["entities"]


def test_deanonymize_helpers_are_exported_from_package_root():
    assert root_deanonymize_text is deanonymize_text
    assert root_deanonymize_file is deanonymize_file


def test_reverse_bank_fingerprint_ignores_non_matching_metadata():
    anonymized = anonymize_text(
        _person_bank(include_alias=False),
        "John Smith joined.",
        _pseudonym_db(store_originals=True),
        options={"mode": "pseudonym", "include_sensitive_metadata": True},
    )
    db = anonymized["replacement_db"]["data"]
    changed_metadata = copy.deepcopy(db)
    assignment = next(iter(changed_metadata["assignments"].values()))
    changed_metadata["version"] += 1
    changed_metadata["updated_at"] = "2026-06-13T00:00:01Z"
    changed_metadata["metadata"]["note"] = "not used for matching"
    assignment["use_count"] += 1
    assignment["metadata"]["note"] = "not used for matching"

    changed_match = copy.deepcopy(db)
    changed_match["replacement_sets"]["person_names"]["candidates"][0]["value"] = "Mikey Lawyer"
    next(iter(changed_match["assignments"].values()))["replacement"]["value"] = "Mikey Lawyer"

    options = {"restore_pseudonyms": True}
    assert reverse_bank_fingerprint(db, options=options) == reverse_bank_fingerprint(
        changed_metadata,
        options=options,
    )
    assert reverse_bank_fingerprint(db, options=options) != reverse_bank_fingerprint(changed_match, options=options)


def test_reverse_bank_fingerprint_sanitizes_invalid_db_diagnostics_by_default():
    db = _pseudonym_db(store_originals=True)
    allocated = allocate_assignment(_record(), db, now="2026-06-13T00:00:00Z").replacement_db
    first_assignment_key = next(iter(allocated["assignments"]))
    second_assignment_key = assignment_key(
        _record(name_id="jane_smith", canonical_name="Jane Smith"),
        allocated["defaults"],
    )
    duplicated_assignment = copy.deepcopy(allocated["assignments"][first_assignment_key])
    duplicated_assignment["assignment_key"] = second_assignment_key
    duplicated_assignment["identity"]["fingerprint"] = second_assignment_key.split("|", 2)[2]
    duplicated_assignment["identity"]["name_id"] = "jane_smith"
    duplicated_assignment["identity"]["canonical_name"] = "Jane Smith"
    duplicated_assignment["original"]["canonical"] = "Jane Smith"
    allocated["assignments"][second_assignment_key] = duplicated_assignment

    with pytest.raises(DeanonymizationError) as exc_info:
        reverse_bank_fingerprint(allocated, options={"restore_pseudonyms": True})

    diagnostics_repr = repr(exc_info.value.diagnostics)
    assert all("|sha256:" not in item["path"] for item in exc_info.value.diagnostics)
    assert "first_assignment_key" not in diagnostics_repr
    assert first_assignment_key not in diagnostics_repr
    assert second_assignment_key not in diagnostics_repr
    assert "john_smith" not in diagnostics_repr
    assert "jane_smith" not in diagnostics_repr


def test_build_reverse_bank_fails_before_returning_oversized_generated_bank():
    db = create_replacement_db(reversible=True, now="2026-06-13T00:00:00Z")
    assignments = {}
    for index in range(1001):
        key = f"person|name|sha256:{index:064x}"
        assignments[key] = {
            "assignment_key": key,
            "entity_id": "person",
            "identity": {
                "scope": "name",
                "name_id": f"name_{index}",
                "canonical_name": f"Original {index}",
                "fingerprint": f"sha256:{index:064x}",
            },
            "original": {"canonical": f"Original {index}", "surfaces": [f"Original {index}"]},
            "replacement": {"mode": "redact", "value": f"[PERSON_{index + 1:04d}]"},
            "redaction": {"token": f"[PERSON_{index + 1:04d}]", "ordinal": index + 1},
            "created_at": "2026-06-13T00:00:00Z",
            "updated_at": "2026-06-13T00:00:00Z",
            "use_count": 1,
            "metadata": {},
        }
    db["assignments"] = assignments

    with pytest.raises(DeanonymizationError) as exc_info:
        build_reverse_bank(db)

    assert exc_info.value.diagnostics[0]["code"] == "deanonymize.too_many_reverse_entities"
    assert exc_info.value.diagnostics[0]["metadata"] == {"limit": 1000}


def test_deanonymize_text_restores_redaction_tokens_by_default_with_safe_payload():
    anonymized = anonymize_text(
        _person_bank(include_alias=False),
        "John Smith joined.",
        create_replacement_db(reversible=True, now="2026-06-13T00:00:00Z"),
        options={"mode": "redact", "include_sensitive_metadata": True},
    )

    result = deanonymize_text(anonymized["text"], anonymized["replacement_db"]["data"])

    assert result["schema_version"] == "nerb.deanonymize_response.v1"
    assert result["text"] == "John Smith joined."
    assert result["replacement_db"] == {
        "replacement_db_ref": "rdb1",
        "schema_version": "nerb.replacements.v1",
        "version": 1,
    }
    assert result["source"] == {
        "type": "text",
        "length": len("[PERSON_0001] joined."),
        "bytes": len(b"[PERSON_0001] joined."),
    }
    assert result["summary"] == {"match_count": 1, "applied_count": 1, "diagnostic_count": 0}
    assert result["diagnostics"] == []
    assert result["applied_restorations"] == [
        {
            "assignment_ref": "a1",
            "entity": "person",
            "mode": "redact",
            "replacement_span": {"start": 0, "end": 13, "offset_unit": "byte"},
            "restored_span": {"start": 0, "end": 10, "offset_unit": "byte"},
            "restored_value_source": "canonical",
        }
    ]
    assert "restored" not in result["applied_restorations"][0]
    assert "assignment_key" not in result["applied_restorations"][0]


def test_deanonymize_text_restores_pseudonyms_only_when_explicit_and_warns():
    anonymized = anonymize_text(
        _person_bank(include_alias=False),
        "John Smith joined.",
        _pseudonym_db(store_originals=True),
        options={"mode": "pseudonym", "include_sensitive_metadata": True},
    )
    db = anonymized["replacement_db"]["data"]

    default_result = deanonymize_text("Mikey Law joined.", db)
    opt_in_result = deanonymize_text(
        "Mikey Law joined.",
        db,
        options={"restore_pseudonyms": True, "include_originals": True},
    )

    assert default_result["text"] == "Mikey Law joined."
    assert default_result["applied_restorations"] == []
    assert default_result["diagnostics"] == []
    assert opt_in_result["text"] == "John Smith joined."
    assert opt_in_result["diagnostics"][0]["code"] == "deanonymize.pseudonym_restore_warning"
    assert opt_in_result["diagnostics"][0]["severity"] == "warning"
    assert opt_in_result["applied_restorations"][0]["mode"] == "pseudonym"
    assert opt_in_result["applied_restorations"][0]["restored"] == "John Smith"


def test_deanonymize_text_reports_missing_original_for_non_reversible_assignments():
    anonymized = anonymize_text(
        _person_bank(include_alias=False),
        "John Smith joined.",
        create_replacement_db(now="2026-06-13T00:00:00Z"),
        options={"mode": "redact", "include_sensitive_metadata": True},
    )

    result = deanonymize_text(anonymized["text"], anonymized["replacement_db"]["data"])

    assert result["text"] == "[PERSON_0001] joined."
    assert result["applied_restorations"] == []
    assert result["summary"] == {"match_count": 0, "applied_count": 0, "diagnostic_count": 1}
    assert result["diagnostics"][0]["code"] == "replacement_db.missing_original"
    assert result["diagnostics"][0]["metadata"] == {"assignment_ref": "a1", "entity": "person"}
    assert "John Smith" not in repr(result["diagnostics"])
    assert "assignment_key" not in repr(result["diagnostics"])


def test_deanonymize_text_rejects_ambiguous_reverse_values_before_scanning():
    db = _pseudonym_db(store_originals=True)
    db["replacement_sets"]["person_names"]["candidates"].append(
        {"id": "person_name_0003", "value": "[PERSON_0001]", "metadata": {}}
    )
    first = allocate_assignment(
        _record(name_id="john_smith", canonical_name="John Smith"),
        db,
        now="2026-06-13T00:00:00Z",
    )
    assert first.assignment is not None
    first_key = first.assignment_key
    first.replacement_db["assignments"][first_key]["redaction"] = {"token": "[PERSON_0001]", "ordinal": 1}
    second = allocate_assignment(
        _record(name_id="jane_smith", canonical_name="Jane Smith"),
        first.replacement_db,
        now="2026-06-13T00:00:00Z",
    )
    third = allocate_assignment(
        _record(name_id="alex_smith", canonical_name="Alex Smith"),
        second.replacement_db,
        now="2026-06-13T00:00:00Z",
    )
    assert third.assignment is not None
    assert third.assignment["replacement"]["value"] == "[PERSON_0001]"

    with pytest.raises(DeanonymizationError) as exc_info:
        deanonymize_text("[PERSON_0001]", third.replacement_db, options={"restore_pseudonyms": True})

    assert exc_info.value.diagnostics[0]["code"] == "deanonymize.ambiguous_replacement"
    assert "John Smith" not in repr(exc_info.value.diagnostics)
    assert "Jane Smith" not in repr(exc_info.value.diagnostics)
    assert "Alex Smith" not in repr(exc_info.value.diagnostics)


def test_deanonymize_pseudonyms_use_longest_exact_matches_and_punctuation_boundaries():
    db = create_replacement_db(reversible=True, now="2026-06-13T00:00:00Z")
    db["defaults"]["replacement_mode"] = "pseudonym"
    db["defaults"]["replacement_set_id"] = "names"
    db["replacement_sets"]["names"] = {
        "description": "Synthetic names.",
        "reuse": False,
        "candidates": [
            {"id": "sam", "value": "Sam", "metadata": {}},
            {"id": "samwise", "value": "Samwise", "metadata": {}},
        ],
        "metadata": {},
    }
    first = allocate_assignment(
        _record(name_id="original_sam", canonical_name="Original Sam"),
        db,
        now="2026-06-13T00:00:00Z",
    )
    second = allocate_assignment(
        _record(name_id="original_samwise", canonical_name="Original Samwise"),
        first.replacement_db,
        now="2026-06-13T00:00:00Z",
    )

    result = deanonymize_text(
        "Samwise, Sam, SAM, Sam wise.",
        second.replacement_db,
        options={"restore_pseudonyms": True},
    )

    assert result["text"] == "Original Samwise, Original Sam, SAM, Original Sam wise."
    assert result["summary"]["applied_count"] == 3
    assert [item["mode"] for item in result["applied_restorations"]] == ["pseudonym", "pseudonym", "pseudonym"]


def test_deanonymize_pseudonym_restore_rejects_word_substrings_by_default():
    anonymized = anonymize_text(
        _person_bank(include_alias=False),
        "John Smith joined.",
        _pseudonym_db(store_originals=True),
        options={"mode": "pseudonym", "include_sensitive_metadata": True},
    )

    result = deanonymize_text(
        "Mikey Lawless met Mikey  Law and Mikey Law.",
        anonymized["replacement_db"]["data"],
        options={"restore_pseudonyms": True},
    )

    assert result["text"] == "Mikey Lawless met Mikey  Law and John Smith."
    assert result["summary"]["applied_count"] == 1


def test_deanonymize_file_reports_file_source_preserves_crlf_and_enforces_limit(tmp_path):
    anonymized = anonymize_text(
        _person_bank(include_alias=False),
        "John Smith\r\njoined.",
        create_replacement_db(reversible=True, now="2026-06-13T00:00:00Z"),
        options={"mode": "redact", "include_sensitive_metadata": True},
    )
    source_path = tmp_path / "redacted.txt"
    source_path.write_bytes(anonymized["text"].encode("utf-8"))

    result = deanonymize_file(source_path, anonymized["replacement_db"]["data"])

    assert result["text"] == "John Smith\r\njoined."
    assert result["source"] == {
        "type": "file",
        "length": len("[PERSON_0001]\r\njoined."),
        "bytes": len(b"[PERSON_0001]\r\njoined."),
        "source_ref": "s1",
    }
    assert str(source_path) not in repr(result)

    sensitive_result = deanonymize_file(
        source_path,
        anonymized["replacement_db"]["data"],
        options={"include_sensitive_metadata": True},
    )
    assert sensitive_result["source"]["path"] == str(source_path)

    with pytest.raises(DeanonymizationError) as limit_info:
        deanonymize_file(source_path, anonymized["replacement_db"]["data"], options={"max_text_bytes": 4})
    assert limit_info.value.diagnostics[0]["code"] == "deanonymize.extraction_error"


def test_deanonymize_file_suppresses_raw_extraction_context_by_default(tmp_path):
    missing_path = tmp_path / "John-Smith-secret-missing.txt"

    with pytest.raises(DeanonymizationError) as exc_info:
        deanonymize_file(missing_path, create_replacement_db())

    diagnostics_repr = repr(exc_info.value.diagnostics)
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert "John-Smith-secret" not in diagnostics_repr


def test_deanonymize_helpers_suppress_raw_option_error_context_by_default(tmp_path):
    source_path = tmp_path / "redacted.txt"
    source_path.write_text("[PERSON_0001]", encoding="utf-8")
    sensitive_mode = "/Users/donnie/secret-client/path"
    options = {"engine_options": {"match_mode": sensitive_mode}}

    with pytest.raises(DeanonymizationError) as text_info:
        deanonymize_text("[PERSON_0001]", create_replacement_db(), options=options)
    with pytest.raises(DeanonymizationError) as file_info:
        deanonymize_file(source_path, create_replacement_db(), options=options)

    for error in (text_info.value, file_info.value):
        diagnostics_repr = repr(error.diagnostics)
        assert error.__cause__ is None
        assert error.__context__ is None
        assert sensitive_mode not in diagnostics_repr


def test_deanonymize_text_rejects_invalid_options_with_diagnostics():
    with pytest.raises(DeanonymizationError) as pseudonym_info:
        deanonymize_text("Mikey Law", _pseudonym_db(), options={"restore_pseudonyms": "yes"})
    assert pseudonym_info.value.diagnostics[0]["path"] == "/options/restore_pseudonyms"

    with pytest.raises(DeanonymizationError) as source_limit_info:
        deanonymize_text("Mikey Law", _pseudonym_db(), options={"max_text_bytes": 0})
    assert source_limit_info.value.diagnostics[0]["code"] == "deanonymize.extraction_error"

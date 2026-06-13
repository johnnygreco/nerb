from __future__ import annotations

import pytest

from nerb.deanonymization import (
    ByteEdit,
    DeanonymizationError,
    allocate_assignment,
    apply_byte_replacements,
    assignment_key,
    finalize_replacement_db_update,
)
from nerb.replacements import (
    create_replacement_db,
    hash_replacement_db,
    load_replacement_db,
    save_replacement_db,
    validate_replacement_db,
)


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

    assert assignment_key(config_record, canonical_policy).startswith("artist|canonical|sha256:")
    assert assignment_key(config_record, surface_policy).startswith("artist|surface|sha256:")


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

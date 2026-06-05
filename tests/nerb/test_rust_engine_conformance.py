from __future__ import annotations

import importlib
import json

import pytest
from conformance_helpers import (
    RUST_CONFORMANCE_CASES,
    RUST_REGEX_PROFILE_FIXTURES,
    assert_planned_records_equal,
    utf8_byte_span,
)


@pytest.fixture
def engine():
    return importlib.import_module("nerb._engine")


def _native_source_for_case(case):
    if case.case_id == "entity_flag_ascii":
        pytest.skip("ASCII flag lowering for UTF-8-safe native scanning is deferred beyond #51")
    rows = []
    for entity, patterns in case.pattern_config.items():
        flags = patterns.get("_flags", [])
        for name, pattern in patterns.items():
            if name == "_flags":
                continue
            rows.append(
                {
                    "entity": entity,
                    "canonical_name": name,
                    "surface_name": name,
                    "regex": rf"\b(?:{pattern})\b" if case.add_word_boundaries else pattern,
                    "flags": flags,
                }
            )
    return "\n".join(json.dumps(row) for row in rows).encode()


def _project_native_scan_records(bank, text: str):
    metadata = bank.metadata()
    detectors = {detector["detector_index"]: detector for detector in metadata["detectors"]}
    raw = bank.scan_bytes(text.encode("utf-8"))
    records = []
    text_bytes = text.encode("utf-8")
    for index in range(len(raw)):
        detector_index, start, end = raw[index]
        detector = detectors[detector_index]
        records.append(
            {
                "entity": detector["entity"],
                "canonical_name": detector["canonical_name"],
                "surface_name": detector["surface_name"],
                "string": text_bytes[start:end].decode("utf-8"),
                "start": start,
                "end": end,
                "offset_unit": "byte",
            }
        )
    return records


@pytest.mark.parametrize(
    "case",
    RUST_CONFORMANCE_CASES,
    ids=[case.case_id for case in RUST_CONFORMANCE_CASES],
)
def test_native_entity_independent_scan_matches_supported_planned_conformance_cases(engine, case):
    bank = engine.Bank.from_source_bytes(_native_source_for_case(case), format_hint="jsonl")

    assert_planned_records_equal(_project_native_scan_records(bank, case.text), case.expected_records)


def test_utf8_byte_span_converts_character_offsets_without_leaking_to_runtime_projection():
    text = "Caf\u00e9 Pink Floyd"

    assert utf8_byte_span(text, 5, 15) == (6, 16)


def test_slice_zero_conformance_cases_cover_required_semantic_categories():
    tags = set().union(*(case.tags for case in RUST_CONFORMANCE_CASES))

    assert {
        "non_ascii",
        "offsets",
        "cross_entity",
        "nickname_inside_project",
        "within_entity_leftmost_first",
        "ordered_alternation",
        "underscore_names",
        "word_boundaries",
        "unicode_word_boundaries",
        "flags",
        "flag_IGNORECASE",
        "flag_MULTILINE",
        "flag_DOTALL",
        "flag_VERBOSE",
        "flag_ASCII",
    }.issubset(tags)


def test_underscore_detector_names_are_preserved_by_rust_records(engine):
    source = b'{"CODE":{"Foo Bar":"Foo Bar","Foo_Bar":"Foo_Bar"}}'
    bank = engine.Bank.from_source_bytes(source, format_hint="json")

    records = _project_native_scan_records(bank, "Foo Bar Foo_Bar")

    assert [record["canonical_name"] for record in records] == ["Foo Bar", "Foo_Bar"]


def test_rust_regex_profile_fixtures_cover_unsupported_and_adversarial_categories():
    categories = {fixture.category for fixture in RUST_REGEX_PROFILE_FIXTURES}

    assert {
        "unsupported_backreference",
        "unsupported_lookaround",
        "redos_shape",
        "compile_bomb_shape",
    } == categories
    assert all(fixture.expected_rust_status in {"reject", "reject_or_limit"} for fixture in RUST_REGEX_PROFILE_FIXTURES)


@pytest.mark.parametrize(
    "fixture",
    [
        fixture
        for fixture in RUST_REGEX_PROFILE_FIXTURES
        if fixture.expected_rust_status == "reject" or fixture.case_id == "compile_bomb_huge_repeat"
    ],
    ids=lambda fixture: fixture.case_id,
)
def test_native_bank_rejects_unsupported_or_compile_bomb_regex_profile_fixtures(engine, fixture):
    row = {
        "entity": "CODE",
        "canonical_name": fixture.case_id,
        "surface_name": fixture.case_id,
        "regex": fixture.pattern,
        "flags": [],
    }

    with pytest.raises(ValueError):
        engine.Bank.from_source_bytes(json.dumps(row).encode(), format_hint="jsonl")


def test_native_bank_rejects_ascii_flag_until_utf8_safe_lowering_lands(engine):
    row = {
        "entity": "CODE",
        "canonical_name": "ASCII dot",
        "surface_name": "ASCII dot",
        "regex": ".",
        "flags": ["ASCII"],
    }

    with pytest.raises(ValueError, match="ASCII regex flag is not supported"):
        engine.Bank.from_source_bytes(json.dumps(row).encode(), format_hint="jsonl")


def test_native_verbose_flag_supports_trailing_comments(engine):
    row = {
        "entity": "CODE",
        "canonical_name": "Verbose",
        "surface_name": "Verbose",
        "regex": "A # trailing comment",
        "flags": ["VERBOSE"],
    }

    bank = engine.Bank.from_source_bytes(json.dumps(row).encode(), format_hint="jsonl")
    raw = bank.scan_bytes(b"A")

    assert [raw[index] for index in range(len(raw))] == [(0, 0, 1)]


def test_native_current_json_literal_preserves_whitespace_and_hash_under_verbose_flag(engine, test_data_path):
    source = json.loads((test_data_path / "minimal_bank.json").read_text(encoding="utf-8"))
    source["default_regex_flags"] = ["VERBOSE"]
    pattern = source["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]
    pattern["value"] = "Acme Corp #1"
    pattern["normalize_whitespace"] = False
    pattern["left_boundary"] = "none"
    pattern["right_boundary"] = "none"

    bank = engine.Bank.from_source_bytes(json.dumps(source).encode(), format_hint="json")
    raw = bank.scan_bytes(b"Acme Corp #1 AcmeCorp1")

    assert [raw[index] for index in range(len(raw))] == [(0, 0, 12)]

from __future__ import annotations

import importlib
import json

import pytest
from conformance_helpers import (
    PYTHON_ORACLE_CONFORMANCE_CASES,
    RUST_REGEX_PROFILE_FIXTURES,
    assert_planned_records_equal,
    expected_python_oracle_records,
    project_python_oracle_case_records,
    project_python_oracle_records,
    utf8_byte_span,
)

from nerb import ConfigError


@pytest.fixture
def engine():
    return importlib.import_module("nerb._engine")


@pytest.mark.parametrize(
    "case",
    PYTHON_ORACLE_CONFORMANCE_CASES,
    ids=[case.case_id for case in PYTHON_ORACLE_CONFORMANCE_CASES],
)
def test_python_oracle_projects_to_planned_rust_record_schema(case):
    assert_planned_records_equal(project_python_oracle_case_records(case), expected_python_oracle_records(case))


def _native_source_for_case(case):
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
    PYTHON_ORACLE_CONFORMANCE_CASES,
    ids=[case.case_id for case in PYTHON_ORACLE_CONFORMANCE_CASES],
)
def test_native_entity_independent_scan_matches_supported_planned_conformance_cases(engine, case):
    bank = engine.Bank.from_source_bytes(_native_source_for_case(case), format_hint="jsonl")

    assert_planned_records_equal(_project_native_scan_records(bank, case.text), case.expected_records)


def test_utf8_byte_span_converts_character_offsets_without_leaking_to_runtime_projection():
    text = "Caf\u00e9 Pink Floyd"

    assert utf8_byte_span(text, 5, 15) == (6, 16)
    assert project_python_oracle_records(
        text,
        [
            {
                "entity": "ARTIST",
                "name": "Pink Floyd",
                "string": "Pink Floyd",
                "start": 5,
                "end": 15,
            }
        ],
    ) == [
        {
            "entity": "ARTIST",
            "canonical_name": "Pink Floyd",
            "surface_name": "Pink Floyd",
            "string": "Pink Floyd",
            "start": 6,
            "end": 16,
            "offset_unit": "byte",
        }
    ]


def test_slice_zero_python_oracle_cases_cover_required_semantic_categories():
    tags = set().union(*(case.tags for case in PYTHON_ORACLE_CONFORMANCE_CASES))

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


def test_underscore_detector_name_loss_is_marked_as_a_python_oracle_divergence():
    case = next(
        case for case in PYTHON_ORACLE_CONFORMANCE_CASES if case.case_id == "underscore_name_python_oracle_divergence"
    )

    assert "python_oracle_name_underscore_loss" in case.known_divergences
    assert project_python_oracle_case_records(case)[0]["canonical_name"] == "Foo Bar"
    assert case.expected_records[0]["canonical_name"] == "Foo_Bar"


def test_detector_names_that_only_differ_by_spaces_and_underscores_remain_invalid_current_python_config():
    from nerb import NERB

    with pytest.raises(ConfigError, match="both compile to regex group 'Foo_Bar'"):
        NERB({"CODE": {"Foo Bar": "Foo Bar", "Foo_Bar": "Foo_Bar"}})


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

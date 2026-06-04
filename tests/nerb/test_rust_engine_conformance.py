from __future__ import annotations

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


@pytest.mark.parametrize(
    "case",
    PYTHON_ORACLE_CONFORMANCE_CASES,
    ids=[case.case_id for case in PYTHON_ORACLE_CONFORMANCE_CASES],
)
def test_python_oracle_projects_to_planned_rust_record_schema(case):
    assert_planned_records_equal(project_python_oracle_case_records(case), expected_python_oracle_records(case))


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

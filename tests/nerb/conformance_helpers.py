from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from nerb import NERB, extract_named_entities_records

PlannedRecord = dict[str, int | str]


@dataclass(frozen=True)
class PythonOracleConformanceCase:
    case_id: str
    pattern_config: dict[str, dict[str, Any]]
    text: str
    expected_records: tuple[PlannedRecord, ...]
    tags: frozenset[str]
    add_word_boundaries: bool = False
    python_oracle_expected_records: tuple[PlannedRecord, ...] | None = None
    known_divergences: tuple[str, ...] = ()


@dataclass(frozen=True)
class RustRegexProfileFixture:
    case_id: str
    pattern: str
    category: str
    expected_rust_status: str
    current_python_status: str
    reason: str


def utf8_byte_span(text: str, start: int, end: int) -> tuple[int, int]:
    """Convert a Python string span to UTF-8 byte offsets for conformance tests."""
    if start < 0 or end < start or end > len(text):
        raise ValueError(f"Invalid character span ({start}, {end}) for text length {len(text)}.")
    return len(text[:start].encode("utf-8")), len(text[:end].encode("utf-8"))


def planned_record_sort_key(record: Mapping[str, Any]) -> tuple[int, int, str, str, str, str]:
    return (
        int(record["start"]),
        int(record["end"]),
        str(record["entity"]),
        str(record["canonical_name"]),
        str(record["surface_name"]),
        str(record["string"]),
    )


def project_python_oracle_record(text: str, record: Mapping[str, Any]) -> PlannedRecord:
    start, end = utf8_byte_span(text, int(record["start"]), int(record["end"]))
    name = str(record["name"])
    return {
        "entity": str(record["entity"]),
        "canonical_name": name,
        "surface_name": name,
        "string": str(record["string"]),
        "start": start,
        "end": end,
        "offset_unit": "byte",
    }


def project_python_oracle_records(text: str, records: Sequence[Mapping[str, Any]]) -> list[PlannedRecord]:
    projected = [project_python_oracle_record(text, record) for record in records]
    projected.sort(key=planned_record_sort_key)
    return projected


def project_python_oracle_case_records(case: PythonOracleConformanceCase) -> list[PlannedRecord]:
    extractor = NERB(case.pattern_config, add_word_boundaries=case.add_word_boundaries)
    records = extract_named_entities_records(extractor, case.text)
    return project_python_oracle_records(case.text, records)


def expected_python_oracle_records(case: PythonOracleConformanceCase) -> tuple[PlannedRecord, ...]:
    override = case.python_oracle_expected_records
    return override if override is not None else case.expected_records


def assert_planned_records_equal(actual: Sequence[Mapping[str, Any]], expected: Sequence[Mapping[str, Any]]) -> None:
    actual_records = list(actual)
    expected_records = list(expected)
    assert actual_records == sorted(actual_records, key=planned_record_sort_key)
    assert expected_records == sorted(expected_records, key=planned_record_sort_key)
    assert actual_records == expected_records


PYTHON_ORACLE_CONFORMANCE_CASES: tuple[PythonOracleConformanceCase, ...] = (
    PythonOracleConformanceCase(
        case_id="non_ascii_byte_offsets",
        pattern_config={"ARTIST": {"Pink Floyd": r"Pink\sFloyd"}},
        text="Caf\u00e9 Pink Floyd",
        expected_records=(
            {
                "entity": "ARTIST",
                "canonical_name": "Pink Floyd",
                "surface_name": "Pink Floyd",
                "string": "Pink Floyd",
                "start": 6,
                "end": 16,
                "offset_unit": "byte",
            },
        ),
        tags=frozenset({"offsets", "non_ascii"}),
    ),
    PythonOracleConformanceCase(
        case_id="cross_entity_overlap",
        pattern_config={"PERSON": {"Sam": "Sam"}, "PROJECT": {"Samba": "Samba"}},
        text="Samba ships",
        expected_records=(
            {
                "entity": "PERSON",
                "canonical_name": "Sam",
                "surface_name": "Sam",
                "string": "Sam",
                "start": 0,
                "end": 3,
                "offset_unit": "byte",
            },
            {
                "entity": "PROJECT",
                "canonical_name": "Samba",
                "surface_name": "Samba",
                "string": "Samba",
                "start": 0,
                "end": 5,
                "offset_unit": "byte",
            },
        ),
        tags=frozenset({"overlap", "cross_entity"}),
    ),
    PythonOracleConformanceCase(
        case_id="nickname_inside_project",
        pattern_config={"PERSON": {"JD": "JD"}, "PROJECT": {"JD 42": "JD-42"}},
        text="JD-42 launched",
        expected_records=(
            {
                "entity": "PERSON",
                "canonical_name": "JD",
                "surface_name": "JD",
                "string": "JD",
                "start": 0,
                "end": 2,
                "offset_unit": "byte",
            },
            {
                "entity": "PROJECT",
                "canonical_name": "JD 42",
                "surface_name": "JD 42",
                "string": "JD-42",
                "start": 0,
                "end": 5,
                "offset_unit": "byte",
            },
        ),
        tags=frozenset({"overlap", "nickname_inside_project"}),
    ),
    PythonOracleConformanceCase(
        case_id="within_entity_leftmost_source_order_short_first",
        pattern_config={"PERSON": {"Sam": "Sam", "Samba": "Samba"}},
        text="Samba ships",
        expected_records=(
            {
                "entity": "PERSON",
                "canonical_name": "Sam",
                "surface_name": "Sam",
                "string": "Sam",
                "start": 0,
                "end": 3,
                "offset_unit": "byte",
            },
        ),
        tags=frozenset({"overlap", "within_entity_leftmost_first"}),
    ),
    PythonOracleConformanceCase(
        case_id="within_entity_leftmost_source_order_long_first",
        pattern_config={"PERSON": {"Samba": "Samba", "Sam": "Sam"}},
        text="Samba ships",
        expected_records=(
            {
                "entity": "PERSON",
                "canonical_name": "Samba",
                "surface_name": "Samba",
                "string": "Samba",
                "start": 0,
                "end": 5,
                "offset_unit": "byte",
            },
        ),
        tags=frozenset({"overlap", "within_entity_leftmost_first"}),
    ),
    PythonOracleConformanceCase(
        case_id="ordered_alternation_short_first",
        pattern_config={"PERSON": {"Samwise Short Preferred": "Sam|Samwise"}},
        text="Samwise arrived",
        expected_records=(
            {
                "entity": "PERSON",
                "canonical_name": "Samwise Short Preferred",
                "surface_name": "Samwise Short Preferred",
                "string": "Sam",
                "start": 0,
                "end": 3,
                "offset_unit": "byte",
            },
        ),
        tags=frozenset({"ordered_alternation", "within_pattern_leftmost_first"}),
    ),
    PythonOracleConformanceCase(
        case_id="ordered_alternation_long_first",
        pattern_config={"PERSON": {"Samwise Long Preferred": "Samwise|Sam"}},
        text="Samwise arrived",
        expected_records=(
            {
                "entity": "PERSON",
                "canonical_name": "Samwise Long Preferred",
                "surface_name": "Samwise Long Preferred",
                "string": "Samwise",
                "start": 0,
                "end": 7,
                "offset_unit": "byte",
            },
        ),
        tags=frozenset({"ordered_alternation", "within_pattern_leftmost_first"}),
    ),
    PythonOracleConformanceCase(
        case_id="underscore_name_python_oracle_divergence",
        pattern_config={"CODE": {"Foo_Bar": "Foo_Bar"}},
        text="Foo_Bar",
        expected_records=(
            {
                "entity": "CODE",
                "canonical_name": "Foo_Bar",
                "surface_name": "Foo_Bar",
                "string": "Foo_Bar",
                "start": 0,
                "end": 7,
                "offset_unit": "byte",
            },
        ),
        python_oracle_expected_records=(
            {
                "entity": "CODE",
                "canonical_name": "Foo Bar",
                "surface_name": "Foo Bar",
                "string": "Foo_Bar",
                "start": 0,
                "end": 7,
                "offset_unit": "byte",
            },
        ),
        tags=frozenset({"underscore_names"}),
        known_divergences=("python_oracle_name_underscore_loss",),
    ),
    PythonOracleConformanceCase(
        case_id="word_boundaries",
        pattern_config={"TERM": {"AI": "AI"}},
        text="AIM AI",
        expected_records=(
            {
                "entity": "TERM",
                "canonical_name": "AI",
                "surface_name": "AI",
                "string": "AI",
                "start": 4,
                "end": 6,
                "offset_unit": "byte",
            },
        ),
        tags=frozenset({"word_boundaries"}),
        add_word_boundaries=True,
    ),
    PythonOracleConformanceCase(
        case_id="unicode_word_boundaries",
        pattern_config={"TERM": {"AI": "AI"}},
        text="\u00e9AI AI",
        expected_records=(
            {
                "entity": "TERM",
                "canonical_name": "AI",
                "surface_name": "AI",
                "string": "AI",
                "start": 5,
                "end": 7,
                "offset_unit": "byte",
            },
        ),
        tags=frozenset({"word_boundaries", "unicode_word_boundaries"}),
        add_word_boundaries=True,
    ),
    PythonOracleConformanceCase(
        case_id="entity_flag_ignorecase",
        pattern_config={"GENRE": {"_flags": "IGNORECASE", "Jazz": "jazz"}},
        text="JaZz",
        expected_records=(
            {
                "entity": "GENRE",
                "canonical_name": "Jazz",
                "surface_name": "Jazz",
                "string": "JaZz",
                "start": 0,
                "end": 4,
                "offset_unit": "byte",
            },
        ),
        tags=frozenset({"flags", "flag_IGNORECASE"}),
    ),
    PythonOracleConformanceCase(
        case_id="entity_flag_multiline",
        pattern_config={"CUSTOMER": {"_flags": "MULTILINE", "Acme": "^Acme"}},
        text="skip\nAcme",
        expected_records=(
            {
                "entity": "CUSTOMER",
                "canonical_name": "Acme",
                "surface_name": "Acme",
                "string": "Acme",
                "start": 5,
                "end": 9,
                "offset_unit": "byte",
            },
        ),
        tags=frozenset({"flags", "flag_MULTILINE"}),
    ),
    PythonOracleConformanceCase(
        case_id="entity_flag_dotall",
        pattern_config={"CODE": {"_flags": "DOTALL", "A through Z": "A.*Z"}},
        text="A\nZ",
        expected_records=(
            {
                "entity": "CODE",
                "canonical_name": "A through Z",
                "surface_name": "A through Z",
                "string": "A\nZ",
                "start": 0,
                "end": 3,
                "offset_unit": "byte",
            },
        ),
        tags=frozenset({"flags", "flag_DOTALL"}),
    ),
    PythonOracleConformanceCase(
        case_id="entity_flag_verbose",
        pattern_config={"CUSTOMER": {"_flags": "VERBOSE", "Acme": "A C M E"}},
        text="ACME",
        expected_records=(
            {
                "entity": "CUSTOMER",
                "canonical_name": "Acme",
                "surface_name": "Acme",
                "string": "ACME",
                "start": 0,
                "end": 4,
                "offset_unit": "byte",
            },
        ),
        tags=frozenset({"flags", "flag_VERBOSE"}),
    ),
    PythonOracleConformanceCase(
        case_id="entity_flag_ascii",
        pattern_config={"CODE": {"_flags": "ASCII", "ASCII word": r"\b\w\b"}},
        text="\u00e9 A",
        expected_records=(
            {
                "entity": "CODE",
                "canonical_name": "ASCII word",
                "surface_name": "ASCII word",
                "string": "A",
                "start": 3,
                "end": 4,
                "offset_unit": "byte",
            },
        ),
        tags=frozenset({"flags", "flag_ASCII"}),
    ),
)

RUST_REGEX_PROFILE_FIXTURES: tuple[RustRegexProfileFixture, ...] = (
    RustRegexProfileFixture(
        case_id="backreference",
        pattern=r"\b([A-Z]+)-\1\b",
        category="unsupported_backreference",
        expected_rust_status="reject",
        current_python_status="accepted",
        reason="Backreferences require a backtracking engine and are outside the Rust regex profile.",
    ),
    RustRegexProfileFixture(
        case_id="lookaround",
        pattern=r"(?=A)(?!B)(?=C)Acme",
        category="unsupported_lookaround",
        expected_rust_status="reject",
        current_python_status="accepted_with_static_warning",
        reason="Lookaround is valid Python re syntax but rejected by the default Rust regex profile.",
    ),
    RustRegexProfileFixture(
        case_id="nested_quantifier_redos",
        pattern=r"(a+)+$",
        category="redos_shape",
        expected_rust_status="reject_or_limit",
        current_python_status="accepted_with_static_warning",
        reason="Nested quantifiers are a ReDoS-shaped fixture for validation and conformance gates.",
    ),
    RustRegexProfileFixture(
        case_id="compile_bomb_huge_repeat",
        pattern=r"(?:a{1000000}){1000000}",
        category="compile_bomb_shape",
        expected_rust_status="reject_or_limit",
        current_python_status="not_a_merge_gate",
        reason="Huge bounded repeats must be rejected by structural or automata-size limits before scanning.",
    ),
)

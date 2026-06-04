from __future__ import annotations

import importlib
import json

import pytest


@pytest.fixture
def engine():
    return importlib.import_module("nerb._engine")


def _canonical(bank) -> dict:
    return json.loads(bank.to_canonical_json_bytes())


def test_native_bank_canonicalizes_yaml_detector_maps(engine):
    source = b"""
ARTIST:
  Pink Floyd: 'Pink\\s+Floyd'
GENRE:
  _flags: IGNORECASE
  Jazz: '(?:smooth\\s)?jazz'
"""

    bank = engine.Bank.from_source_bytes(source, format_hint="yaml")
    canonical = _canonical(bank)

    assert canonical["schema"] == 1
    assert canonical["defaults"] == {
        "engine": "rust-regex-meta",
        "unicode": True,
        "case_insensitive": False,
        "word_boundaries": False,
        "normalization": "none",
    }
    assert [entity["name"] for entity in canonical["entities"]] == ["ARTIST", "GENRE"]
    assert canonical["entities"][0]["stable_id"].startswith("entity:sha256:")
    assert canonical["entities"][0]["patterns"][0] == {
        "stable_id": canonical["entities"][0]["patterns"][0]["stable_id"],
        "priority": 0,
        "canonical_name": "Pink Floyd",
        "surface_name": "Pink Floyd",
        "regex": "Pink\\s+Floyd",
        "flags": [],
    }
    assert canonical["entities"][1]["patterns"][0]["flags"] == ["IGNORECASE"]
    assert bank.metadata()["bank_hash"].startswith("sha256:")


def test_native_bank_canonicalizes_current_json_bank_flags_and_literal_boundaries(engine, test_data_path):
    source = (test_data_path / "minimal_bank.json").read_bytes()

    bank = engine.Bank.from_source_bytes(source, format_hint="json")
    pattern = _canonical(bank)["entities"][0]["patterns"][0]

    assert pattern["canonical_name"] == "Acme Corp"
    assert pattern["surface_name"] == "Acme Corp"
    assert pattern["priority"] == 100
    assert pattern["regex"] == r"\b(?:Acme\s+Corp)\b"
    assert pattern["flags"] == ["IGNORECASE"]


def test_native_bank_preserves_current_json_literal_surface_and_whitespace(engine, test_data_path):
    source = json.loads((test_data_path / "minimal_bank.json").read_text(encoding="utf-8"))
    pattern = source["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]
    pattern["value"] = " Acme   Corp "
    pattern["left_boundary"] = "none"
    pattern["right_boundary"] = "none"

    canonical_pattern = _canonical(engine.Bank.from_source_bytes(json.dumps(source).encode(), format_hint="json"))[
        "entities"
    ][0]["patterns"][0]

    assert canonical_pattern["canonical_name"] == "Acme Corp"
    assert canonical_pattern["surface_name"] == " Acme   Corp "
    assert canonical_pattern["regex"] == r"\s+Acme\s+Corp\s+"


def test_native_bank_preserves_literal_surface_newlines(engine, test_data_path):
    source = json.loads((test_data_path / "minimal_bank.json").read_text(encoding="utf-8"))
    pattern = source["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]
    pattern["value"] = "Acme\nCorp"
    pattern["left_boundary"] = "none"
    pattern["right_boundary"] = "none"

    canonical_pattern = _canonical(engine.Bank.from_source_bytes(json.dumps(source).encode(), format_hint="json"))[
        "entities"
    ][0]["patterns"][0]

    assert canonical_pattern["surface_name"] == "Acme\nCorp"
    assert canonical_pattern["regex"] == r"Acme\s+Corp"


def test_native_bank_uses_current_json_regex_pattern_id_as_surface(engine, test_data_path):
    source = json.loads((test_data_path / "minimal_bank.json").read_text(encoding="utf-8"))
    source["entities"]["customer"]["names"]["acme_corp"]["patterns"] = {
        "ticker_alias": {
            "kind": "regex",
            "value": r"ACME-\d+",
            "description": "Regex Acme alias.",
            "status": "active",
            "priority": 7,
            "regex_flags": [],
            "metadata": {},
        }
    }

    pattern = _canonical(engine.Bank.from_source_bytes(json.dumps(source).encode(), format_hint="json"))["entities"][0][
        "patterns"
    ][0]

    assert pattern["canonical_name"] == "Acme Corp"
    assert pattern["surface_name"] == "ticker_alias"
    assert pattern["regex"] == r"ACME-\d+"


def test_native_bank_accepts_multiline_verbose_regex(engine, test_data_path):
    source = json.loads((test_data_path / "minimal_bank.json").read_text(encoding="utf-8"))
    source["entities"]["customer"]["names"]["acme_corp"]["patterns"] = {
        "verbose_alias": {
            "kind": "regex",
            "value": "(?x) Acme \n Corp",
            "description": "Verbose regex Acme alias.",
            "status": "active",
            "priority": 7,
            "regex_flags": ["VERBOSE"],
            "metadata": {},
        }
    }

    pattern = _canonical(engine.Bank.from_source_bytes(json.dumps(source).encode(), format_hint="json"))["entities"][0][
        "patterns"
    ][0]

    assert pattern["surface_name"] == "verbose_alias"
    assert pattern["regex"] == "(?x) Acme \n Corp"


def test_native_bank_accepts_jsonl_and_preserves_distinct_same_regex_detectors(engine):
    source = b"""
{"entity":"CODE","canonical_name":"Alpha","surface_name":"A","regex":"A"}
{"entity":"CODE","canonical_name":"Beta","surface_name":"B","regex":"A"}
"""

    canonical = _canonical(engine.Bank.from_source_bytes(source, format_hint="jsonl"))
    patterns = canonical["entities"][0]["patterns"]

    assert len(patterns) == 2
    assert {pattern["canonical_name"] for pattern in patterns} == {"Alpha", "Beta"}
    assert patterns[0]["stable_id"] != patterns[1]["stable_id"]


def test_native_bank_preserves_jsonl_source_order_as_default_priority(engine):
    source = b"""
{"entity":"CODE","canonical_name":"Zulu","surface_name":"Z","regex":"Z"}
{"entity":"CODE","canonical_name":"Alpha","surface_name":"A","regex":"A"}
"""

    patterns = _canonical(engine.Bank.from_source_bytes(source, format_hint="jsonl"))["entities"][0]["patterns"]

    assert [(pattern["canonical_name"], pattern["priority"]) for pattern in patterns] == [
        ("Zulu", 0),
        ("Alpha", 1),
    ]


def test_native_bank_auto_detects_single_row_jsonl(engine):
    source = b'{"entity":"CODE","canonical_name":"Alpha","surface_name":"A","regex":"A"}'

    canonical = _canonical(engine.Bank.from_source_bytes(source))

    assert canonical["entities"][0]["name"] == "CODE"
    assert canonical["entities"][0]["patterns"][0]["canonical_name"] == "Alpha"


def test_native_bank_auto_detects_json_shaped_yaml_detector_maps(engine):
    canonical = _canonical(engine.Bank.from_source_bytes(b"{CODE: {Alpha: A}}"))

    assert canonical["entities"][0]["name"] == "CODE"
    assert canonical["entities"][0]["patterns"][0]["canonical_name"] == "Alpha"
    assert canonical["entities"][0]["patterns"][0]["regex"] == "A"


def test_native_bank_auto_detects_multiline_json_shaped_yaml_detector_maps(engine):
    canonical = _canonical(engine.Bank.from_source_bytes(b"{CODE: {Alpha: A},\n GENRE: {Jazz: jazz}}\n"))

    assert [entity["name"] for entity in canonical["entities"]] == ["CODE", "GENRE"]


def test_native_bank_does_not_misroute_json_detector_maps_that_resemble_jsonl_rows(engine):
    source = b'{"entity":{"Alpha":"A"},"canonical_name":{"Beta":"B"},"regex":{"Gamma":"G"}}'

    canonical = _canonical(engine.Bank.from_source_bytes(source))

    assert [entity["name"] for entity in canonical["entities"]] == ["canonical_name", "entity", "regex"]


def test_native_bank_rejects_reserved_compact_detector_map_entity_names(engine):
    with pytest.raises(ValueError, match="reserved entity names"):
        engine.Bank.from_source_bytes(b'{"schema":{"Alpha":"A"}}', format_hint="json")

    with pytest.raises(ValueError, match="reserved entity names"):
        engine.Bank.from_source_bytes(b'{"schema_version":{"Alpha":"A"}}', format_hint="json")

    with pytest.raises(ValueError, match="reserved entity names"):
        engine.Bank.from_source_bytes(
            b'{"schema":{"Alpha":"A"},"defaults":{"Beta":"B"},"entities":{"Gamma":"G"}}',
            format_hint="json",
        )


def test_native_bank_routes_marker_values_to_specific_bank_validators(engine):
    with pytest.raises(ValueError, match='/entities: missing required field "entities"'):
        engine.Bank.from_source_bytes(
            b'{"schema_version":"nerb.bank.v1","id":"company_entities",'
            b'"unicode_normalization":"none","default_regex_flags":[]}',
            format_hint="json",
        )

    with pytest.raises(ValueError, match="/entities: canonical bank must define at least one entity"):
        engine.Bank.from_source_bytes(
            b'{"schema":1,"defaults":{"engine":"rust-regex-meta","unicode":true,'
            b'"case_insensitive":false,"word_boundaries":false,"normalization":"none"},"entities":[]}',
            format_hint="json",
        )


def test_native_bank_rejects_exact_duplicate_logical_detectors(engine):
    source = b"""
{"entity":"CODE","canonical_name":"Alpha","surface_name":"A","regex":"A"}
{"entity":"CODE","canonical_name":"Alpha","surface_name":"A","regex":"A"}
"""

    with pytest.raises(ValueError, match="duplicate logical detector"):
        engine.Bank.from_source_bytes(source, format_hint="jsonl")


def test_native_bank_rejects_unknown_fields_and_unsupported_flags(engine):
    with pytest.raises(ValueError, match="/0/unexpected"):
        engine.Bank.from_source_bytes(
            b'{"entity":"CODE","canonical_name":"Alpha","regex":"A","unexpected":true}',
            format_hint="jsonl",
        )

    with pytest.raises(ValueError, match="unsupported regex flag"):
        engine.Bank.from_source_bytes(
            b'{"entity":"CODE","canonical_name":"Alpha","regex":"A","flags":["UNICODE"]}',
            format_hint="jsonl",
        )


def test_native_bank_rejects_duplicate_source_keys(engine):
    with pytest.raises(ValueError, match="duplicate key"):
        engine.Bank.from_source_bytes(b'{"CODE":{"Alpha":"A","Alpha":"B"}}', format_hint="json")

    with pytest.raises(ValueError, match="duplicate key"):
        engine.Bank.from_source_bytes(b'{"CODE":{"Alpha":"A","Alpha":"B"}}')

    with pytest.raises(ValueError, match="duplicate key"):
        engine.Bank.from_source_bytes(
            b'{"entity":"CODE","canonical_name":"Alpha","regex":"A","regex":"B"}',
            format_hint="jsonl",
        )

    with pytest.raises(ValueError, match="line 1: duplicate key"):
        engine.Bank.from_source_bytes(
            b'{"entity":"CODE","canonical_name":"Alpha","regex":"A","regex":"B"}\n'
            b'{"entity":"CODE","canonical_name":"Beta","regex":"B"}'
        )


def test_native_bank_rejects_duplicate_compile_option_keys(engine):
    with pytest.raises(ValueError, match="duplicate key"):
        engine.Bank.from_source_bytes(
            b'{"CODE":{"Alpha":"A"}}',
            format_hint="json",
            compile_options_json='{"match_mode":"entity_independent","match_mode":"all_overlaps"}',
        )


def test_native_bank_validates_and_defaults_compile_options(engine):
    source = b'{"CODE":{"Alpha":"A"}}'
    default_bank = engine.Bank.from_source_bytes(source, format_hint="json")
    empty_options_bank = engine.Bank.from_source_bytes(source, format_hint="json", compile_options_json="{}")
    overlap_bank = engine.Bank.from_source_bytes(
        source,
        format_hint="json",
        compile_options_json='{"match_mode":"all_overlaps"}',
    )

    assert default_bank.metadata()["compile_options"] == {"match_mode": "entity_independent"}
    assert empty_options_bank.metadata()["compile_options"] == {"match_mode": "entity_independent"}
    assert default_bank.metadata()["bank_hash"] == empty_options_bank.metadata()["bank_hash"]
    assert overlap_bank.metadata()["compile_options"] == {"match_mode": "all_overlaps"}
    assert default_bank.metadata()["bank_hash"] != overlap_bank.metadata()["bank_hash"]

    with pytest.raises(ValueError, match="unknown field"):
        engine.Bank.from_source_bytes(source, format_hint="json", compile_options_json='{"unknown":true}')

    with pytest.raises(ValueError, match="unknown variant"):
        engine.Bank.from_source_bytes(source, format_hint="json", compile_options_json='{"match_mode":"bogus"}')


def test_native_bank_rejects_kind_specific_current_json_bank_fields(engine, test_data_path):
    bank = json.loads((test_data_path / "minimal_bank.json").read_text(encoding="utf-8"))
    pattern = bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]
    pattern["regex_flags"] = []

    with pytest.raises(ValueError, match="not allowed for literal patterns"):
        engine.Bank.from_source_bytes(json.dumps(bank).encode(), format_hint="json")

    bank = json.loads((test_data_path / "minimal_bank.json").read_text(encoding="utf-8"))
    bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"] = {
        "kind": "regex",
        "value": "Acme",
        "description": "Regex Acme.",
        "status": "active",
        "priority": 0,
        "metadata": {},
    }
    with pytest.raises(ValueError, match='/regex_flags: missing required field "regex_flags"'):
        engine.Bank.from_source_bytes(json.dumps(bank).encode(), format_hint="json")

    bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]["regex_flags"] = []
    bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]["case_sensitive"] = False
    with pytest.raises(ValueError, match="not allowed for regex patterns"):
        engine.Bank.from_source_bytes(json.dumps(bank).encode(), format_hint="json")


def test_native_bank_rejects_invalid_current_bank_ids_and_resource_limit_violations(engine, test_data_path):
    bank = json.loads((test_data_path / "minimal_bank.json").read_text(encoding="utf-8"))
    bank["id"] = "Bad ID"

    with pytest.raises(ValueError, match="/id"):
        engine.Bank.from_source_bytes(json.dumps(bank).encode(), format_hint="json")

    with pytest.raises(ValueError, match="pattern length"):
        engine.Bank.from_source_bytes(
            json.dumps({"CODE": {"Huge": "A" * 10_001}}).encode(),
            format_hint="json",
        )


def test_native_bank_rejects_backtracking_only_regex_constructs(engine):
    with pytest.raises(ValueError, match="unsupported Rust regex syntax"):
        engine.Bank.from_source_bytes(
            b'{"entity":"CODE","canonical_name":"Alpha","regex":"(?=A)A"}',
            format_hint="jsonl",
        )


def test_native_canonical_json_round_trips_and_validates_stable_ids(engine):
    source_bank = engine.Bank.from_source_bytes(b'{"CODE":{"Alpha":"A"}}', format_hint="json")
    canonical_bytes = source_bank.to_canonical_json_bytes()

    round_tripped = engine.Bank.from_canonical_json_bytes(canonical_bytes)

    assert _canonical(round_tripped) == _canonical(source_bank)
    broken = _canonical(source_bank)
    broken["entities"][0]["stable_id"] = "entity:not-valid"
    with pytest.raises(ValueError, match="invalid entity stable_id"):
        engine.Bank.from_canonical_json_bytes(json.dumps(broken).encode())

    broken = _canonical(source_bank)
    broken["entities"][0]["patterns"][0]["stable_id"] = "pattern:not-valid"
    with pytest.raises(ValueError, match="invalid pattern stable_id"):
        engine.Bank.from_canonical_json_bytes(json.dumps(broken).encode())

    reversed_entities = _canonical(
        engine.Bank.from_source_bytes(b'{"CODE":{"Alpha":"A"},"ARTIST":{"Beta":"B"}}', format_hint="json")
    )
    reversed_entities["entities"] = list(reversed(reversed_entities["entities"]))
    with pytest.raises(ValueError, match="canonical order"):
        engine.Bank.from_canonical_json_bytes(json.dumps(reversed_entities).encode())


def test_native_bank_hash_is_stable_across_input_key_order_and_semantic_options(engine):
    first = engine.Bank.from_source_bytes(
        b'{"CODE":{"Beta":"B","Alpha":"A"},"ARTIST":{"Pink Floyd":"Pink\\\\s+Floyd"}}',
        format_hint="json",
    )
    second = engine.Bank.from_source_bytes(
        b'{"ARTIST":{"Pink Floyd":"Pink\\\\s+Floyd"},"CODE":{"Alpha":"A","Beta":"B"}}',
        format_hint="json",
    )
    different_options = engine.Bank.from_source_bytes(
        b'{"ARTIST":{"Pink Floyd":"Pink\\\\s+Floyd"},"CODE":{"Alpha":"A","Beta":"B"}}',
        format_hint="json",
        compile_options_json='{"match_mode":"all_overlaps"}',
    )

    assert first.metadata()["bank_hash"] == second.metadata()["bank_hash"]
    assert first.metadata()["bank_hash"] != different_options.metadata()["bank_hash"]
    assert different_options.metadata()["compile_options"] == {"match_mode": "all_overlaps"}

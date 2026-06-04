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

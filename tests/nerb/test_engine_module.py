from __future__ import annotations

import importlib
import importlib.metadata
import json

import pytest

import nerb


def test_native_engine_module_imports():
    engine = importlib.import_module("nerb._engine")

    assert engine.ENGINE_NAME == "nerb_engine"
    assert engine.__version__ == importlib.metadata.version("nerb") == nerb.__version__


def test_public_bank_projects_byte_and_char_records_and_scans_paths(tmp_path):
    bank = nerb.Bank.from_source_bytes(b'{"ARTIST":{"Rush":"Rush"}}', format_hint="json")
    document_path = tmp_path / "document.txt"
    document_path.write_text("Café Rush", encoding="utf-8")

    assert bank.metadata()["match_mode"]["name"] == "entity_independent"
    assert bank.scan_text("Café Rush") == [
        {
            "entity": "ARTIST",
            "canonical_name": "Rush",
            "surface_name": "Rush",
            "string": "Rush",
            "start": 6,
            "end": 10,
            "offset_unit": "byte",
        }
    ]
    assert bank.scan_text("Café Rush", offsets="char") == [
        {
            "entity": "ARTIST",
            "canonical_name": "Rush",
            "surface_name": "Rush",
            "string": "Rush",
            "start": 5,
            "end": 9,
            "offset_unit": "char",
        }
    ]
    assert bank.scan_path(document_path) == bank.scan_text("Café Rush")


def test_public_bank_scan_path_rejects_invalid_utf8(tmp_path):
    bank = nerb.Bank.from_source_bytes(b'{"CODE":{"A":"A"}}', format_hint="json")
    document_path = tmp_path / "invalid.bin"
    document_path.write_bytes(b"\xff")

    with pytest.raises(ValueError, match="valid UTF-8"):
        bank.scan_path(document_path)


def test_public_bank_from_config_word_boundaries_are_rust_canonicalized():
    plain = nerb.Bank.from_config({"TERM": {"Art": "art"}})
    bounded = nerb.Bank.from_config({"TERM": {"Art": "art"}}, word_boundaries=True)
    canonical = json.loads(bounded.to_canonical_json_bytes())
    round_tripped = nerb.Bank.from_canonical_json_bytes(bounded.to_canonical_json_bytes())

    assert canonical["defaults"]["word_boundaries"] is True
    assert canonical["entities"][0]["patterns"][0]["regex"] == r"\b(?:art)\b"
    assert bounded.metadata()["compile_options"] == {"match_mode": "entity_independent"}
    assert plain.metadata()["bank_hash"] != bounded.metadata()["bank_hash"]
    assert round_tripped.metadata()["bank_hash"] == bounded.metadata()["bank_hash"]
    assert [record["start"] for record in bounded.scan_text("art article art")] == [0, 12]

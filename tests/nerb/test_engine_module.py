from __future__ import annotations

import importlib
import importlib.metadata

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

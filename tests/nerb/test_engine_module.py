from __future__ import annotations

import importlib
import importlib.metadata
import json

import pytest

import nerb
import nerb.engine as engine_module


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


def test_public_bank_scan_path_projects_native_scanned_bytes(tmp_path):
    class Raw:
        def __len__(self):
            return 1

        def __getitem__(self, index):
            assert index == 0
            return (0, 0, 5)

    class Native:
        def __init__(self):
            self.path = None

        def scan_path_with_bytes(self, path):
            self.path = path
            return Raw(), b"Alpha"

        def metadata(self):
            return {
                "detectors": [
                    {
                        "detector_index": 0,
                        "entity": "CODE",
                        "canonical_name": "Alpha",
                        "surface_name": "Alpha",
                    }
                ]
            }

    native = Native()
    bank = nerb.Bank(native)
    missing_path = tmp_path / "missing.txt"

    assert bank.scan_path(missing_path) == [
        {
            "entity": "CODE",
            "canonical_name": "Alpha",
            "surface_name": "Alpha",
            "string": "Alpha",
            "start": 0,
            "end": 5,
            "offset_unit": "byte",
        }
    ]
    assert native.path == str(missing_path)


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


def test_public_bank_cache_reuses_compiled_banks_and_reports_key_dimensions():
    nerb.clear_bank_cache()

    first = nerb.Bank.from_config({"ARTIST": {"Rush": "Rush"}})
    second = nerb.Bank.from_config({"ARTIST": {"Rush": "Rush"}})
    bounded = nerb.Bank.from_config({"ARTIST": {"Rush": "Rush"}}, word_boundaries=True)

    first_cache = first.cache_metadata()
    second_cache = second.cache_metadata()
    bounded_cache = bounded.cache_metadata()
    key = first_cache["key"]

    assert first_cache["enabled"] is True
    assert first_cache["hit"] is False
    assert second_cache["hit"] is True
    assert second_cache["key"] == key
    assert bounded_cache["hit"] is False
    assert bounded_cache["key"]["bank_hash"] != key["bank_hash"]
    assert key["bank_hash"] == first.metadata()["bank_hash"]
    assert key["schema_version"] == first.metadata()["schema"]
    assert key["semantic_version"] == nerb.__version__
    assert key["engine_name"] == "nerb_engine"
    assert key["engine_version"] == nerb.__version__
    assert key["canonical_engine"] == first.metadata()["defaults"]["engine"]
    assert key["compile_options"] == {"match_mode": "entity_independent"}
    assert isinstance(key["target_triple"], str) and key["target_triple"]
    assert isinstance(key["platform"], str) and key["platform"]
    assert key["pointer_width"] in {32, 64}
    assert key["endian"] in {"little", "big"}
    assert nerb.bank_cache_info()["hits"] == 1
    assert nerb.bank_cache_info()["misses"] == 2
    assert nerb.bank_cache_info()["size"] == 2
    assert nerb.bank_cache_info()["max_entries"] == engine_module.DEFAULT_BANK_CACHE_MAX_ENTRIES


def test_public_bank_cache_evicts_lru_entries_and_reports_caps(monkeypatch):
    nerb.clear_bank_cache()
    monkeypatch.setattr(engine_module, "DEFAULT_BANK_CACHE_MAX_ENTRIES", 3)
    monkeypatch.setattr(engine_module, "DEFAULT_BANK_SOURCE_CACHE_MAX_ENTRIES", 6)

    banks = [nerb.Bank.from_config({"ARTIST": {f"Rush_{index}": f"Rush {index}"}}) for index in range(5)]

    info = nerb.bank_cache_info()
    cached_hashes = {key["bank_hash"] for key in info["keys"]}
    assert info["size"] == 3
    assert info["source_key_count"] <= 6
    assert info["max_entries"] == 3
    assert info["max_source_keys"] == 6
    assert banks[0].metadata()["bank_hash"] not in cached_hashes
    assert banks[1].metadata()["bank_hash"] not in cached_hashes
    assert banks[-1].metadata()["bank_hash"] in cached_hashes


def test_public_bank_cache_can_be_bypassed():
    nerb.clear_bank_cache()

    bank = nerb.Bank.from_config({"ARTIST": {"Rush": "Rush"}}, use_cache=False)

    assert bank.cache_metadata() == {"enabled": False, "hit": False, "key": None}
    assert nerb.bank_cache_info() == {
        "size": 0,
        "source_key_count": 0,
        "max_entries": engine_module.DEFAULT_BANK_CACHE_MAX_ENTRIES,
        "max_source_keys": engine_module.DEFAULT_BANK_SOURCE_CACHE_MAX_ENTRIES,
        "hits": 0,
        "misses": 0,
        "keys": [],
    }


def test_public_bank_compile_options_reject_duplicate_keys_like_native_engine():
    duplicate_match_mode = '{"match_mode":"all_overlaps","match_mode":"entity_independent"}'
    duplicate_word_boundaries = '{"word_boundaries":false,"word_boundaries":true}'
    canonical = nerb.Bank.from_config({"CODE": {"A": "A"}}).to_canonical_json_bytes()

    with pytest.raises(ValueError, match="duplicate key 'match_mode'"):
        nerb.Bank.from_source_bytes(
            b'{"CODE":{"A":"A"}}',
            format_hint="json",
            compile_options_json=duplicate_match_mode,
            use_cache=False,
        )

    with pytest.raises(ValueError, match="duplicate key 'match_mode'"):
        nerb.Bank.from_canonical_json_bytes(canonical, compile_options_json=duplicate_match_mode)

    with pytest.raises(ValueError, match="duplicate key 'word_boundaries'"):
        nerb.Bank.from_config(
            {"CODE": {"A": "A"}},
            compile_options_json=duplicate_word_boundaries,
            word_boundaries=True,
        )


def test_public_bank_compile_options_reject_non_finite_constants():
    with pytest.raises(ValueError, match="non-finite value NaN"):
        nerb.Bank.from_source_bytes(
            b'{"CODE":{"A":"A"}}',
            format_hint="json",
            compile_options_json='{"match_mode":NaN}',
        )


@pytest.mark.parametrize("raw_options", ['{"word_boundaries":"bad"}', '{"word_boundaries":{}}'])
def test_public_bank_config_word_boundary_option_must_be_boolean_before_override(raw_options):
    with pytest.raises(ValueError, match='field "word_boundaries" must be a boolean'):
        nerb.Bank.from_config(
            {"CODE": {"A": "A"}},
            compile_options_json=raw_options,
            word_boundaries=True,
        )


def test_public_bank_config_word_boundary_option_rejects_non_finite_before_override():
    with pytest.raises(ValueError, match="non-finite value"):
        nerb.Bank.from_config(
            {"CODE": {"A": "A"}},
            compile_options_json='{"word_boundaries":1e999}',
            word_boundaries=True,
        )

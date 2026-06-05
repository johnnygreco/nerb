from __future__ import annotations

import importlib
import json
from collections.abc import Sequence

import pytest


@pytest.fixture
def engine():
    return importlib.import_module("nerb._engine")


def _raw_tuples(buffer):
    return [buffer[index] for index in range(len(buffer))]


def test_native_bank_boundary_round_trips_canonical_json_and_metadata(engine):
    bank = engine.Bank.from_source_bytes(
        b'{"CODE":{"Alpha":"A"},"ARTIST":{"Pink Floyd":"Pink\\\\s+Floyd"}}',
        format_hint="json",
        compile_options_json='{"match_mode":"all_overlaps"}',
    )
    canonical = json.loads(bank.to_canonical_json_bytes())
    metadata = bank.metadata()

    assert canonical["schema"] == 1
    assert metadata["engine"] == "nerb_engine"
    assert metadata["schema"] == 1
    assert metadata["entity_count"] == 2
    assert metadata["pattern_count"] == 2
    assert metadata["compile_options"] == {"match_mode": "all_overlaps"}
    assert metadata["match_mode"] == {
        "name": "all_overlaps",
        "status": "internal_prototype",
        "production_default": False,
        "internal_only": True,
        "semantic_notes": (
            "reports raw cross-entity, within-entity, and within-pattern overlaps for prototype measurement"
        ),
    }
    assert metadata["detectors"] == [
        {
            "detector_index": 0,
            "entity": "ARTIST",
            "canonical_name": "Pink Floyd",
            "surface_name": "Pink Floyd",
            "stable_id": canonical["entities"][0]["patterns"][0]["stable_id"],
            "priority": 0,
        },
        {
            "detector_index": 1,
            "entity": "CODE",
            "canonical_name": "Alpha",
            "surface_name": "Alpha",
            "stable_id": canonical["entities"][1]["patterns"][0]["stable_id"],
            "priority": 0,
        },
    ]
    assert metadata["bank_hash"].startswith("sha256:")

    round_tripped = engine.Bank.from_canonical_json_bytes(bank.to_canonical_json_bytes())

    assert json.loads(round_tripped.to_canonical_json_bytes()) == canonical
    assert (
        round_tripped.metadata()["bank_hash"]
        == engine.Bank.from_source_bytes(
            bank.to_canonical_json_bytes(),
            format_hint="canonical_json",
        ).metadata()["bank_hash"]
    )


def test_native_match_buffer_supports_capacity_len_indexing_and_clear(engine):
    buffer = importlib.import_module("nerb._engine").MatchBuffer(capacity=4)

    assert len(buffer) == 0
    assert buffer.is_empty() is True
    assert buffer.capacity() >= 4
    assert buffer.get(0) is None

    buffer.reserve(8)
    assert buffer.capacity() >= 8

    raw = importlib.import_module("nerb._engine").MatchBuffer.from_raw_matches(
        [
            (3, 10, 12),
            (4, 12, 12),
        ]
    )

    assert len(raw) == 2
    assert raw.is_empty() is False
    assert raw[0] == (3, 10, 12)
    assert raw[-1] == (4, 12, 12)
    assert raw.get(99) is None

    with pytest.raises(IndexError, match="index out of range"):
        _ = raw[2]

    raw.clear()

    assert len(raw) == 0
    assert raw.is_empty() is True


def test_native_match_buffer_rejects_invalid_raw_spans(engine):
    with pytest.raises(ValueError, match="before start_byte"):
        engine.MatchBuffer.from_raw_matches([(1, 9, 8)])


def test_native_match_buffer_rejects_oversized_capacity_requests(engine):
    with pytest.raises(MemoryError, match="exceeds pre-scan limit"):
        engine.MatchBuffer(capacity=1_000_001)

    buffer = engine.MatchBuffer()
    with pytest.raises(MemoryError, match="exceeds pre-scan limit"):
        buffer.reserve(1_000_001)


def test_native_match_buffer_rejects_oversized_raw_match_sequences_before_item_access(engine):
    class OversizedRawMatches(Sequence):
        def __len__(self):
            return 1_000_001

        def __getitem__(self, index):
            raise AssertionError("oversized raw match sequence should be rejected before item access")

    with pytest.raises(MemoryError, match="exceeds pre-scan limit"):
        engine.MatchBuffer.from_raw_matches(OversizedRawMatches())


def test_native_scan_bytes_returns_sorted_raw_matches_and_reuses_output_buffer(engine):
    bank = engine.Bank.from_source_bytes(
        b'{"A_LATE":{"late":"late"},"B_EARLY":{"early":"early"}}',
        format_hint="json",
    )
    buffer = engine.MatchBuffer()

    returned = bank.scan_bytes(b"early then late", out=buffer)

    assert returned is buffer
    assert _raw_tuples(buffer) == [(1, 0, 5), (0, 11, 15)]


def test_native_scan_bytes_out_preserves_reserved_capacity(engine):
    bank = engine.Bank.from_source_bytes(b'{"CODE":{"Alpha":"Alpha"}}', format_hint="json")
    buffer = engine.MatchBuffer(capacity=32)
    before = buffer.capacity()

    returned = bank.scan_bytes(b"Alpha", out=buffer)

    assert returned is buffer
    assert buffer.capacity() >= before
    assert _raw_tuples(buffer) == [(0, 0, 5)]


def test_native_all_overlaps_scan_reports_raw_semantic_differences(engine):
    source = b"""
{"entity":"PERSON","canonical_name":"Sam","surface_name":"Sam","regex":"Sam","priority":0}
{"entity":"PERSON","canonical_name":"Samwise","surface_name":"Samwise","regex":"Samwise","priority":1}
{"entity":"PROJECT","canonical_name":"Samba","surface_name":"Samba","regex":"Samba","priority":0}
"""
    default_bank = engine.Bank.from_source_bytes(source, format_hint="jsonl")
    overlap_bank = engine.Bank.from_source_bytes(
        source,
        format_hint="jsonl",
        compile_options_json='{"match_mode":"all_overlaps"}',
    )

    assert _raw_tuples(default_bank.scan_bytes(b"Samba Samwise")) == [(0, 0, 3), (2, 0, 5), (0, 6, 9)]
    assert _raw_tuples(overlap_bank.scan_bytes(b"Samba Samwise")) == [
        (0, 0, 3),
        (2, 0, 5),
        (0, 6, 9),
        (1, 6, 13),
    ]


def test_native_all_overlaps_leftmost_filter_reconstructs_default_entity_semantics(engine):
    source = b"""
{"entity":"PERSON","canonical_name":"Sam","surface_name":"Sam","regex":"Sam","priority":0}
{"entity":"PERSON","canonical_name":"Samwise","surface_name":"Samwise","regex":"Samwise","priority":1}
{"entity":"PROJECT","canonical_name":"Samba","surface_name":"Samba","regex":"Samba","priority":0}
"""
    default_bank = engine.Bank.from_source_bytes(source, format_hint="jsonl")
    overlap_bank = engine.Bank.from_source_bytes(
        source,
        format_hint="jsonl",
        compile_options_json='{"match_mode":"all_overlaps"}',
    )
    buffer = engine.MatchBuffer(capacity=16)
    before = buffer.capacity()

    returned = overlap_bank.scan_bytes_leftmost_from_all_overlaps(b"Samba Samwise", out=buffer)

    assert returned is buffer
    assert buffer.capacity() >= before
    assert _raw_tuples(buffer) == _raw_tuples(default_bank.scan_bytes(b"Samba Samwise"))


def test_native_all_overlaps_leftmost_filter_preserves_ordered_alternation(engine):
    source = b"""
{"entity":"PERSON","canonical_name":"Alias","surface_name":"Alias","regex":"Samwise|Sam","priority":0}
"""
    default_bank = engine.Bank.from_source_bytes(source, format_hint="jsonl")
    overlap_bank = engine.Bank.from_source_bytes(
        source,
        format_hint="jsonl",
        compile_options_json='{"match_mode":"all_overlaps"}',
    )

    assert _raw_tuples(overlap_bank.scan_bytes(b"Samwise")) == [(0, 0, 3), (0, 0, 7)]
    assert _raw_tuples(overlap_bank.scan_bytes_leftmost_from_all_overlaps(b"Samwise")) == _raw_tuples(
        default_bank.scan_bytes(b"Samwise")
    )


def test_native_all_overlaps_scan_reports_quantified_same_detector_spans(engine):
    source = b"""
{"entity":"CODE","canonical_name":"Run","surface_name":"Run","regex":"A+","priority":0}
"""
    overlap_bank = engine.Bank.from_source_bytes(
        source,
        format_hint="jsonl",
        compile_options_json='{"match_mode":"all_overlaps"}',
    )

    assert _raw_tuples(overlap_bank.scan_bytes(b"AAA")) == [
        (0, 0, 1),
        (0, 0, 2),
        (0, 0, 3),
        (0, 1, 2),
        (0, 1, 3),
        (0, 2, 3),
    ]


def test_native_all_overlaps_scan_rejects_unicode_word_boundary_patterns(engine):
    source = b"""
{"entity":"CODE","canonical_name":"foo","surface_name":"foo","regex":"\\\\bfoo\\\\b","priority":0}
"""
    default_bank = engine.Bank.from_source_bytes(source, format_hint="jsonl")

    assert _raw_tuples(default_bank.scan_bytes("élan foo".encode())) == [(0, 6, 9)]
    with pytest.raises(ValueError, match="Unicode word-boundary assertions are not supported"):
        engine.Bank.from_source_bytes(
            source,
            format_hint="jsonl",
            compile_options_json='{"match_mode":"all_overlaps"}',
        )


def test_native_all_overlaps_scan_supports_explicit_ascii_word_boundary_patterns(engine):
    source = b"""
{"entity":"CODE","canonical_name":"foo","surface_name":"foo","regex":"(?-u:\\\\b)foo(?-u:\\\\b)","priority":0}
"""
    overlap_bank = engine.Bank.from_source_bytes(
        source, format_hint="jsonl", compile_options_json='{"match_mode":"all_overlaps"}'
    )

    assert _raw_tuples(overlap_bank.scan_bytes(b"foo bar")) == [(0, 0, 3)]


def test_native_all_overlaps_leftmost_filter_rejects_wrong_mode_and_invalid_utf8(engine):
    default_bank = engine.Bank.from_source_bytes(b'{"CODE":{"Alpha":"Alpha"}}', format_hint="json")
    default_buffer = engine.MatchBuffer.from_raw_matches([(99, 0, 0)])

    with pytest.raises(ValueError, match="requires match_mode"):
        default_bank.scan_bytes_leftmost_from_all_overlaps(b"Alpha", out=default_buffer)

    assert len(default_buffer) == 0

    overlap_bank = engine.Bank.from_source_bytes(
        b'{"CODE":{"Alpha":"Alpha"}}',
        format_hint="json",
        compile_options_json='{"match_mode":"all_overlaps"}',
    )
    invalid_utf8_buffer = engine.MatchBuffer.from_raw_matches([(99, 0, 0)])
    with pytest.raises(ValueError, match="valid UTF-8"):
        overlap_bank.scan_bytes_leftmost_from_all_overlaps(b"\xff", out=invalid_utf8_buffer)

    assert len(invalid_utf8_buffer) == 0


def test_native_scan_bytes_out_clears_partial_matches_after_scan_error(engine):
    bank = engine.Bank.from_source_bytes(b'{"CODE":{"A":"A"}}', format_hint="json")
    buffer = engine.MatchBuffer.from_raw_matches([(99, 0, 0)])

    with pytest.raises(MemoryError, match="exceeds pre-scan limit"):
        bank.scan_bytes(b"A" * 1_000_001, out=buffer)

    assert len(buffer) == 0
    assert buffer.capacity() >= 1


def test_native_scan_bytes_rejects_invalid_utf8(engine):
    bank = engine.Bank.from_source_bytes(b'{"CODE":{"Alpha":"A"}}', format_hint="json")

    with pytest.raises(ValueError, match="valid UTF-8"):
        bank.scan_bytes(b"\xff")

    invalid_utf8_buffer = engine.MatchBuffer.from_raw_matches([(99, 0, 0)])
    with pytest.raises(ValueError, match="valid UTF-8"):
        bank.scan_bytes(b"\xff", out=invalid_utf8_buffer)

    assert len(invalid_utf8_buffer) == 0
    assert invalid_utf8_buffer.capacity() >= 1


def test_native_scan_path_scans_file_into_raw_match_buffer(engine, tmp_path):
    bank = engine.Bank.from_source_bytes(b'{"CODE":{"Alpha":"A"}}', format_hint="json")
    document_path = tmp_path / "document.txt"
    document_path.write_text("Alpha", encoding="utf-8")
    buffer = engine.MatchBuffer()

    raw = bank.scan_path(str(document_path))
    returned = bank.scan_path(str(document_path), out=buffer)

    assert [raw[index] for index in range(len(raw))] == [(0, 0, 1)]
    assert returned is buffer
    assert [buffer[index] for index in range(len(buffer))] == [(0, 0, 1)]


def test_native_scan_path_rejects_invalid_utf8_and_clears_buffer(engine, tmp_path):
    bank = engine.Bank.from_source_bytes(b'{"CODE":{"Alpha":"A"}}', format_hint="json")
    document_path = tmp_path / "invalid.bin"
    document_path.write_bytes(b"\xff")
    buffer = engine.MatchBuffer.from_raw_matches([(99, 0, 0)])

    with pytest.raises(ValueError, match="valid UTF-8"):
        bank.scan_path(str(document_path), out=buffer)

    assert len(buffer) == 0


def test_native_global_leftmost_scan_is_internal_baseline_and_collapses_cross_entity_overlap(engine):
    source = b"""
{"entity":"PERSON","canonical_name":"Sam","surface_name":"Sam","regex":"Sam","priority":0}
{"entity":"PROJECT","canonical_name":"Samba","surface_name":"Samba","regex":"Samba","priority":0}
"""
    default_bank = engine.Bank.from_source_bytes(source, format_hint="jsonl")
    global_bank = engine.Bank.from_source_bytes(
        source,
        format_hint="jsonl",
        compile_options_json='{"match_mode":"global_leftmost"}',
    )
    buffer = engine.MatchBuffer(capacity=8)
    before = buffer.capacity()

    returned = global_bank.scan_bytes(b"Samba ships", out=buffer)

    assert returned is buffer
    assert buffer.capacity() >= before
    assert _raw_tuples(default_bank.scan_bytes(b"Samba ships")) == [(0, 0, 3), (1, 0, 5)]
    assert _raw_tuples(buffer) == [(0, 0, 3)]
    assert global_bank.metadata()["compile_options"] == {"match_mode": "global_leftmost"}
    assert global_bank.metadata()["match_mode"] == {
        "name": "global_leftmost",
        "status": "internal_benchmark_only",
        "production_default": False,
        "internal_only": True,
        "semantic_notes": (
            "collapses cross-entity overlap to one leftmost-first winner per region "
            "and is not semantically equivalent to the production default"
        ),
    }


def test_native_default_scan_mode_stays_entity_independent(engine):
    bank = engine.Bank.from_source_bytes(
        b"""
{"entity":"PERSON","canonical_name":"Sam","surface_name":"Sam","regex":"Sam","priority":0}
{"entity":"PROJECT","canonical_name":"Samba","surface_name":"Samba","regex":"Samba","priority":0}
""",
        format_hint="jsonl",
    )

    assert _raw_tuples(bank.scan_bytes(b"Samba")) == [(0, 0, 3), (1, 0, 5)]
    assert bank.metadata()["compile_options"] == {"match_mode": "entity_independent"}
    assert bank.metadata()["match_mode"]["name"] == "entity_independent"
    assert bank.metadata()["match_mode"]["status"] == "production_default"
    assert bank.metadata()["match_mode"]["production_default"] is True
    assert bank.metadata()["match_mode"]["internal_only"] is False

from __future__ import annotations

import importlib
import json

import pytest


@pytest.fixture
def engine():
    return importlib.import_module("nerb._engine")


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


def test_native_scan_methods_are_boundary_stubs_without_record_projection(engine):
    bank = engine.Bank.from_source_bytes(b'{"CODE":{"Alpha":"A"}}', format_hint="json")
    buffer = engine.MatchBuffer()

    with pytest.raises(NotImplementedError, match="not implemented yet"):
        bank.scan_bytes(b"Alpha", out=buffer)

    with pytest.raises(NotImplementedError, match="not implemented yet"):
        bank.scan_path("document.txt", out=buffer)

    assert len(buffer) == 0

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Iterator
from typing import Any

import pytest

from nerb.engine import Bank
from nerb.enron_contract import (
    PERFORMANCE_SCALE_PATTERNS,
    hash_enron_performance_bank,
    hash_enron_performance_input,
    hash_enron_performance_inventory,
)
from nerb.enron_performance_fixtures import (
    EnronPerformanceBankFixture,
    EnronPerformanceFixtureError,
    EnronPerformanceInputFixture,
    make_enron_performance_bank_fixture,
    make_enron_performance_bank_fixtures,
    make_enron_performance_input_fixtures,
)


def _evaluated_bank() -> dict[str, Any]:
    return {
        "id": "evaluated_enron_bank",
        "bank_hash": "sha256:" + "1" * 64,
        "active_entities": 2,
        "active_names": 628,
        "active_aliases": 127,
        "active_patterns": 628,
        "composition": {
            "taxonomy": [
                {
                    "entity_class": "contact",
                    "entities": 1,
                    "canonical_names": 501,
                    "aliases": 0,
                    "literal_patterns": 500,
                    "regex_patterns": 1,
                },
                {
                    "entity_class": "person",
                    "entities": 1,
                    "canonical_names": 0,
                    "aliases": 127,
                    "literal_patterns": 127,
                    "regex_patterns": 0,
                },
            ]
        },
    }


@pytest.fixture(scope="module")
def scale_family() -> tuple[EnronPerformanceBankFixture, ...]:
    # This is the one focused test setup that compiles the 100k native fixture.
    return make_enron_performance_bank_fixtures(evaluated_bank=_evaluated_bank())


@pytest.fixture(scope="module")
def input_family(
    scale_family: tuple[EnronPerformanceBankFixture, ...],
) -> tuple[EnronPerformanceInputFixture, ...]:
    return make_enron_performance_input_fixtures(scale_family)


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _rows(fixture: EnronPerformanceBankFixture) -> Iterator[dict[str, Any]]:
    for line in fixture.source_bytes.splitlines():
        value = json.loads(line)
        assert type(value) is dict
        yield value


def test_1k_bank_fixture_is_deterministic_and_keeps_aliases_distinct_from_patterns(
    scale_family: tuple[EnronPerformanceBankFixture, ...],
) -> None:
    first = scale_family[0]
    repeated = make_enron_performance_bank_fixture(active_patterns=1_000, evaluated_bank=_evaluated_bank())

    assert first.source_bytes == repeated.source_bytes
    assert first.canonical_bytes == repeated.canonical_bytes
    assert first.descriptor_bytes == repeated.descriptor_bytes
    assert first.source_sha256 == "sha256:a22d215f52c9c715f975be3cc74e78104940d8e7ddac77fb3cebcd875a973912"
    assert first.bank_hash == "sha256:f77abc2c175af27123e073463e2cf7a9039e2598285894f89dc954b28b1e840b"
    assert first.canonical_sha256 == "sha256:5b087680d1f1670edc25f2b3fd48385bc550fd9868836100aa838e3240f30944"
    assert first.preflight_record_count == 3

    descriptor = first.descriptor
    assert descriptor["active_patterns"] == 1_000
    assert descriptor["active_names"] == 1_000
    assert descriptor["active_aliases"] == 202
    assert descriptor["active_aliases"] != descriptor["active_patterns"]
    assert descriptor["active_entities"] == 4
    assert descriptor["composition"]["taxonomy"] == [
        {
            "entity_class": "contact",
            "entities": 2,
            "canonical_names": 798,
            "aliases": 0,
            "literal_patterns": 796,
            "regex_patterns": 2,
        },
        {
            "entity_class": "person",
            "entities": 2,
            "canonical_names": 0,
            "aliases": 202,
            "literal_patterns": 202,
            "regex_patterns": 0,
        },
    ]
    assert descriptor["descriptor_sha256"] == hash_enron_performance_bank(descriptor)
    assert descriptor["artifact"] == first.canonical_artifact
    assert first.source_artifact == {
        "id": "scale_1000_native_source",
        "sha256": first.source_sha256,
        "bytes": len(first.source_bytes),
    }
    assert first.source_filename == "banks/scale_1000.native.jsonl"
    assert first.canonical_filename == "banks/scale_1000.canonical.json"

    rows = list(_rows(first))
    assert len(rows) == descriptor["active_patterns"]
    assert len({row["entity"] for row in rows}) == descriptor["active_entities"]
    assert len({row["surface_name"] for row in rows}) == descriptor["active_names"]
    alias_surfaces = {row["surface_name"] for row in rows if row["surface_name"] != row["canonical_name"]}
    assert len(alias_surfaces) == descriptor["active_aliases"]
    assert sum(str(row["regex"]).startswith("(?:") for row in rows) == 2
    assert sum(len(str(row["regex"]).encode("utf-8")) for row in rows) < 10_000_000
    assert len(first.source_bytes) < 64 * 1024 * 1024
    assert b"NERB_PERF" not in first.descriptor_bytes

    changed = first.descriptor
    changed["active_aliases"] = 1_000
    assert first.descriptor["active_aliases"] == 202

    for fixture in scale_family:
        taxonomy = fixture.descriptor["composition"]["taxonomy"]
        assert taxonomy[0]["entities"] == taxonomy[1]["entities"]


def test_100k_native_compile_scan_preflight_is_aggregate_only(
    scale_family: tuple[EnronPerformanceBankFixture, ...],
) -> None:
    fixture = scale_family[-1]
    descriptor = fixture.descriptor

    assert descriptor["active_patterns"] == 100_000
    assert descriptor["active_names"] == 100_000
    assert descriptor["active_aliases"] == 20_223
    assert descriptor["active_entities"] == 318
    assert len(descriptor["composition"]["taxonomy"]) == 2
    assert [item["entities"] for item in descriptor["composition"]["taxonomy"]] == [159, 159]
    assert fixture.preflight_record_count == 3
    assert len(fixture.source_bytes) == descriptor["native_source_bytes"] == 13_801_751
    assert len(fixture.canonical_bytes) == descriptor["canonical_json_bytes"] == 22_610_807
    assert fixture.source_sha256 == "sha256:e1402abe44d9127f6c6b7c1a2a742c0ebb05267ea160484e98f33c60b9c41673"
    assert fixture.bank_hash == "sha256:d4878822f61ecee7244230068c2e2ce604274ccfe774493a1f575211a9d86633"
    assert fixture.canonical_sha256 == "sha256:8249046bb9e3d30a0d96f00909f10f576edf46bb5bff4e215cb36e3b456ee471"
    assert _sha256(fixture.source_bytes) == fixture.source_sha256
    assert _sha256(fixture.canonical_bytes) == fixture.canonical_sha256
    assert descriptor["descriptor_sha256"] == hash_enron_performance_bank(descriptor)

    rows_per_entity: Counter[str] = Counter()
    pattern_bytes = 0
    row_count = 0
    for row in _rows(fixture):
        row_count += 1
        rows_per_entity[str(row["entity"])] += 1
        pattern_bytes += len(str(row["regex"]).encode("utf-8"))
        assert "@" not in str(row)
    assert row_count == 100_000
    assert len(rows_per_entity) == descriptor["active_entities"]
    # Ratio-preserving sharding is both far below the 50k formal cap and the
    # empirically validated full-lifecycle shape recorded in the module.
    assert max(rows_per_entity.values()) == 502
    assert max(rows_per_entity.values()) <= 50_000
    assert pattern_bytes < 10_000_000
    assert len(fixture.source_bytes) < 64 * 1024 * 1024


def test_controlled_inputs_share_the_negative_medium_anchor_and_reconcile_inventory(
    input_family: tuple[EnronPerformanceInputFixture, ...],
) -> None:
    by_id = {fixture.id: fixture for fixture in input_family}
    assert set(by_id) == {
        "density_dense_input",
        "density_normal_input",
        "density_sparse_input",
        "scale_1000_input",
        "scale_10000_input",
        "scale_25000_input",
        "scale_100000_input",
        "size_huge_input",
        "size_large_input",
        "size_small_input",
    }

    scale_inputs = [by_id[f"scale_{scale}_input"] for scale in PERFORMANCE_SCALE_PATTERNS]
    shared = scale_inputs[0]
    assert all(item.artifact_bytes is shared.artifact_bytes for item in scale_inputs)
    assert all(item.inventory_bytes is shared.inventory_bytes for item in scale_inputs)
    assert all(item.artifact == shared.artifact for item in scale_inputs)
    assert all(item.inventory_ref == shared.inventory_ref for item in scale_inputs)
    assert shared.descriptor["hit_density"] == "negative"
    assert shared.descriptor["size_cohort"] == "medium"
    assert b"NERB_PERF" not in shared.artifact_bytes

    expected_density = {
        "density_sparse_input": ("sparse", 1),
        "density_normal_input": ("normal", 100),
        "density_dense_input": ("dense", 300),
    }
    for identifier, (density, records) in expected_density.items():
        descriptor = by_id[identifier].descriptor
        assert descriptor["hit_density"] == density
        assert descriptor["size_cohort"] == "medium"
        assert descriptor["records"] == records

    expected_sizes = {
        "size_small_input": ("small", 512),
        "size_large_input": ("large", 65_536),
        "size_huge_input": ("huge", 300_000),
    }
    for identifier, (cohort, bytes_per_document) in expected_sizes.items():
        descriptor = by_id[identifier].descriptor
        assert descriptor["hit_density"] == "negative"
        assert descriptor["size_cohort"] == cohort
        assert descriptor["bytes"] == bytes_per_document * 100

    for fixture in input_family:
        descriptor = fixture.descriptor
        inventory = fixture.inventory()
        assert len(fixture.documents) == len(fixture.inventory_rows) == descriptor["documents"] == 100
        assert fixture.artifact_bytes == b"".join(fixture.documents)
        assert sum(row.byte_count for row in fixture.inventory_rows) == len(fixture.artifact_bytes)
        assert sum(row.record_count for row in fixture.inventory_rows) == descriptor["records"]
        assert _sha256(fixture.artifact_bytes) == descriptor["artifact"]["sha256"]
        assert _sha256(fixture.inventory_bytes) == descriptor["inventory_ref"]["sha256"]
        assert hash_enron_performance_inventory(inventory) == descriptor["inventory_ref"]["sha256"]
        assert descriptor["descriptor_sha256"] == hash_enron_performance_input(descriptor)
        assert b"NERB_PERF" not in fixture.descriptor_bytes
        assert "@" not in fixture.artifact_bytes.decode("utf-8")

        offset = 0
        reconstructed = []
        for row in fixture.inventory_rows:
            reconstructed.append(fixture.artifact_bytes[offset : offset + row.byte_count])
            offset += row.byte_count
        assert offset == len(fixture.artifact_bytes)
        assert tuple(reconstructed) == fixture.documents


def test_controlled_input_record_counts_match_native_scans(
    scale_family: tuple[EnronPerformanceBankFixture, ...],
    input_family: tuple[EnronPerformanceInputFixture, ...],
) -> None:
    anchor = scale_family[0]
    bank = Bank.from_source_bytes(anchor.source_bytes, format_hint="jsonl", use_cache=False)
    for fixture in input_family:
        if fixture.descriptor["bank_id"] != anchor.id:
            continue
        actual_records = sum(len(bank.scan_bytes(document)) for document in fixture.documents)
        assert actual_records == fixture.descriptor["records"]


def test_invalid_evaluated_composition_and_incomplete_scale_family_are_rejected(
    scale_family: tuple[EnronPerformanceBankFixture, ...],
) -> None:
    invalid = _evaluated_bank()
    invalid["active_aliases"] = invalid["active_patterns"]
    with pytest.raises(EnronPerformanceFixtureError, match="does not reconcile"):
        make_enron_performance_bank_fixture(active_patterns=1_000, evaluated_bank=invalid)

    with pytest.raises(EnronPerformanceFixtureError, match="complete frozen matcher-scale family"):
        make_enron_performance_input_fixtures(scale_family[:-1])

    with pytest.raises(EnronPerformanceFixtureError, match="frozen active-pattern counts"):
        make_enron_performance_bank_fixture(active_patterns=2_000, evaluated_bank=_evaluated_bank())

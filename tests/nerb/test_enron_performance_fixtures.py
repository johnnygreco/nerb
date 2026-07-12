from __future__ import annotations

import hashlib
import json
import re
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


def _residual_regex_rows(fixture: EnronPerformanceBankFixture) -> list[dict[str, Any]]:
    return [row for row in _rows(fixture) if re.fullmatch(r"NERB\d+\[(\d)X\]", str(row["regex"]))]


def test_1k_bank_fixture_is_deterministic_and_keeps_aliases_distinct_from_patterns(
    scale_family: tuple[EnronPerformanceBankFixture, ...],
) -> None:
    first = scale_family[0]
    repeated = make_enron_performance_bank_fixture(active_patterns=1_000, evaluated_bank=_evaluated_bank())

    assert first.source_bytes == repeated.source_bytes
    assert first.canonical_bytes == repeated.canonical_bytes
    assert first.descriptor_bytes == repeated.descriptor_bytes
    assert first.source_sha256 == "sha256:312eed9b7d8ad77ee7f2d5a4d05b4865560a797b62322e6cfb52508cb2493323"
    assert first.bank_hash == "sha256:d1d4d221e1d2dc007dc512341ebf01fffeedf4b8601ae980545e483c9c9bd871"
    assert first.canonical_sha256 == "sha256:73ee4e4790b10390f827d16539f284dafc3065b18451f9c9cae5d7ab1d9059a0"
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
    residual_rows = _residual_regex_rows(first)
    assert len(residual_rows) == 2
    assert sum(len(str(row["regex"]).encode("utf-8")) for row in rows) < 10_000_000
    assert len(first.source_bytes) < 64 * 1024 * 1024
    assert b"NERB_PERF" not in first.descriptor_bytes

    changed = first.descriptor
    changed["active_aliases"] = 1_000
    assert first.descriptor["active_aliases"] == 202

    for fixture in scale_family:
        taxonomy = fixture.descriptor["composition"]["taxonomy"]
        assert taxonomy[0]["entities"] == taxonomy[1]["entities"]
        expected_regexes = sum(item["regex_patterns"] for item in taxonomy)
        assert len(_residual_regex_rows(fixture)) == expected_regexes


def test_generated_regex_share_is_nonliteral_nonempty_and_uses_native_regex_semantics(
    scale_family: tuple[EnronPerformanceBankFixture, ...],
) -> None:
    fixture = scale_family[0]
    regex_rows = _residual_regex_rows(fixture)
    expected_regexes = sum(item["regex_patterns"] for item in fixture.descriptor["composition"]["taxonomy"])
    assert len(regex_rows) == expected_regexes == 2

    for row in regex_rows:
        pattern = str(row["regex"])
        prefix, character_class = pattern.rsplit("[", 1)
        original = prefix + character_class[0]
        alternate = prefix + "X"
        assert original != alternate
        assert re.fullmatch(pattern, original) is not None
        assert re.fullmatch(pattern, alternate) is not None
        assert re.fullmatch(pattern, "") is None

    # An exact HIR literal without case-insensitive flags can recognize only
    # one byte string.  Compiling one generated row in isolation and matching
    # both distinct alternatives proves that native compilation retained a
    # nonliteral regex matcher instead of projecting this fixture as a literal.
    representative = regex_rows[0]
    pattern = str(representative["regex"])
    prefix, character_class = pattern.rsplit("[", 1)
    original = prefix + character_class[0]
    alternate = prefix + "X"
    source = json.dumps(representative, sort_keys=True, separators=(",", ":")).encode("utf-8")
    probe = Bank.from_source_bytes(source, format_hint="jsonl", use_cache=False)
    records = probe.scan_text(f"{original} {alternate}")
    assert [record["string"] for record in records] == [original, alternate]


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
    residual_rows = _residual_regex_rows(fixture)
    assert len(residual_rows) == 159
    assert len({str(row["entity"]) for row in residual_rows}) == 159
    assert fixture.preflight_record_count == 3
    assert len(fixture.source_bytes) == descriptor["native_source_bytes"] == 13_801_592
    assert len(fixture.canonical_bytes) == descriptor["canonical_json_bytes"] == 22_610_648
    assert fixture.source_sha256 == "sha256:79a5af2e18221866a2077328bd25da0af337f9473ad9ebe1fb7a935733c00067"
    assert fixture.bank_hash == "sha256:f74de4bff5a070f85365c0e4d53a28bd4154e996066d09730dccb0a0966118af"
    assert fixture.canonical_sha256 == "sha256:03bf4d6f1727b0d183c6f049baded6a306a14970314d6f0b6e7956503d9fdced"
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


def test_imbalanced_taxonomy_can_round_one_class_to_zero_without_dividing_by_zero() -> None:
    evaluated = {
        "id": "imbalanced_evaluated_bank",
        "bank_hash": "sha256:" + "2" * 64,
        "active_entities": 2,
        "active_names": 100_000,
        "active_aliases": 0,
        "active_patterns": 100_000,
        "composition": {
            "taxonomy": [
                {
                    "entity_class": "contact",
                    "entities": 1,
                    "canonical_names": 1,
                    "aliases": 0,
                    "literal_patterns": 1,
                    "regex_patterns": 0,
                },
                {
                    "entity_class": "person",
                    "entities": 1,
                    "canonical_names": 99_999,
                    "aliases": 0,
                    "literal_patterns": 99_999,
                    "regex_patterns": 0,
                },
            ]
        },
    }

    fixture = make_enron_performance_bank_fixture(active_patterns=1_000, evaluated_bank=evaluated)

    taxonomy = {item["entity_class"]: item for item in fixture.descriptor["composition"]["taxonomy"]}
    assert taxonomy["contact"] == {
        "entity_class": "contact",
        "entities": 0,
        "canonical_names": 0,
        "aliases": 0,
        "literal_patterns": 0,
        "regex_patterns": 0,
    }
    assert taxonomy["person"]["literal_patterns"] == 1_000
    assert taxonomy["person"]["entities"] == 1


def test_scaled_taxonomy_rejects_names_allocated_to_a_zero_pattern_class() -> None:
    evaluated = {
        "id": "divergent_name_pattern_ratios",
        "bank_hash": "sha256:" + "3" * 64,
        "active_entities": 2,
        "active_names": 150,
        "active_aliases": 0,
        "active_patterns": 100_000,
        "composition": {
            "taxonomy": [
                {
                    "entity_class": "contact",
                    "entities": 1,
                    "canonical_names": 40,
                    "aliases": 0,
                    "literal_patterns": 40,
                    "regex_patterns": 0,
                },
                {
                    "entity_class": "person",
                    "entities": 1,
                    "canonical_names": 110,
                    "aliases": 0,
                    "literal_patterns": 99_960,
                    "regex_patterns": 0,
                },
            ]
        },
    }

    with pytest.raises(EnronPerformanceFixtureError, match="assigned truthfully"):
        make_enron_performance_bank_fixture(active_patterns=1_000, evaluated_bank=evaluated)

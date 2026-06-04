from __future__ import annotations

import copy
import json
import math

import pytest

from nerb import (
    BankSchemaError,
    bank_stats,
    canonicalize_bank,
    hash_bank,
    load_bank,
    validate_bank_schema,
)
from nerb.diagnostics import EVAL_REFS_LARGE, METADATA_LARGE, METADATA_TOO_LARGE


@pytest.fixture
def minimal_bank(test_data_path):
    with open(test_data_path / "minimal_bank.json", encoding="utf-8") as file:
        return json.load(file)


def test_minimal_bank_passes_schema_validation(minimal_bank, test_data_path):
    result = validate_bank_schema(minimal_bank)

    assert result == {"valid": True, "diagnostics": []}
    assert load_bank(test_data_path / "minimal_bank.json") == minimal_bank


def test_missing_required_fields_produce_schema_required_diagnostics(minimal_bank):
    del minimal_bank["description"]
    del minimal_bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]["metadata"]

    result = validate_bank_schema(minimal_bank)

    assert result["valid"] is False
    assert {
        ("schema.required", "/description"),
        ("schema.required", "/entities/customer/names/acme_corp/patterns/primary/metadata"),
    }.issubset({(diagnostic["code"], diagnostic["path"]) for diagnostic in result["diagnostics"]})


def test_unknown_fields_are_rejected_outside_metadata(minimal_bank):
    minimal_bank["unexpected"] = "nope"
    minimal_bank["metadata"]["arbitrary"] = {"nested": ["json", 1, True, None]}

    result = validate_bank_schema(minimal_bank)

    assert result["valid"] is False
    assert ("schema.additional_property", "/unexpected") in {
        (diagnostic["code"], diagnostic["path"]) for diagnostic in result["diagnostics"]
    }
    assert all(diagnostic["path"] != "/metadata/arbitrary" for diagnostic in result["diagnostics"])


def test_multiple_unknown_fields_get_field_level_paths(minimal_bank):
    pattern = minimal_bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]
    pattern["unexpected_one"] = "nope"
    pattern["unexpected_two"] = "also nope"

    result = validate_bank_schema(minimal_bank)

    assert result["valid"] is False
    assert {
        ("schema.additional_property", "/entities/customer/names/acme_corp/patterns/primary/unexpected_one"),
        ("schema.additional_property", "/entities/customer/names/acme_corp/patterns/primary/unexpected_two"),
    }.issubset({(diagnostic["code"], diagnostic["path"]) for diagnostic in result["diagnostics"]})


def test_metadata_must_be_json_compatible(minimal_bank):
    minimal_bank["metadata"]["json_ok"] = {"nested": ["json", 1, 1.5, True, None]}
    minimal_bank["metadata"]["not_json"] = object()
    minimal_bank["metadata"]["not_finite_json"] = math.nan

    result = validate_bank_schema(minimal_bank)

    assert result["valid"] is False
    assert any(diagnostic["path"] == "/metadata/not_json" for diagnostic in result["diagnostics"])
    assert any(diagnostic["path"] == "/metadata/not_finite_json" for diagnostic in result["diagnostics"])


def test_schema_resource_limits_report_hard_errors_and_warnings(minimal_bank):
    pattern = minimal_bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]
    minimal_bank["description"] = "x" * 2_001
    minimal_bank["metadata"]["huge"] = "x" * (1024 * 1024)
    pattern["value"] = "A" * 10_001
    pattern["eval_refs"] = [f"eval_{index}.jsonl" for index in range(1_001)]
    pattern["metadata"]["large"] = "x" * (16 * 1024)

    result = validate_bank_schema(minimal_bank)
    diagnostic_index = {(diagnostic["code"], diagnostic["path"]) for diagnostic in result["diagnostics"]}

    assert result["valid"] is False
    assert ("schema.maxLength", "/description") in diagnostic_index
    assert ("schema.maxLength", "/entities/customer/names/acme_corp/patterns/primary/value") in diagnostic_index
    assert (
        EVAL_REFS_LARGE,
        "/entities/customer/names/acme_corp/patterns/primary/eval_refs",
    ) in diagnostic_index
    assert (METADATA_LARGE, "/entities/customer/names/acme_corp/patterns/primary/metadata") in diagnostic_index
    assert (METADATA_TOO_LARGE, "/metadata") in diagnostic_index


def test_invalid_ids_produce_id_invalid_diagnostics(minimal_bank):
    minimal_bank["id"] = "Company Entities"
    minimal_bank["entities"]["Bad-ID"] = minimal_bank["entities"].pop("customer")
    minimal_bank["entities"]["Bad-ID"]["names"]["Acme Corp"] = minimal_bank["entities"]["Bad-ID"]["names"].pop(
        "acme_corp"
    )
    minimal_bank["entities"]["Bad-ID"]["names"]["Acme Corp"]["patterns"]["Primary"] = minimal_bank["entities"][
        "Bad-ID"
    ]["names"]["Acme Corp"]["patterns"].pop("primary")

    result = validate_bank_schema(minimal_bank)

    assert result["valid"] is False
    assert {
        ("id.invalid", "/id"),
        ("id.invalid", "/entities/Bad-ID"),
        ("id.invalid", "/entities/Bad-ID/names/Acme Corp"),
        ("id.invalid", "/entities/Bad-ID/names/Acme Corp/patterns/Primary"),
    }.issubset({(diagnostic["code"], diagnostic["path"]) for diagnostic in result["diagnostics"]})


@pytest.mark.parametrize(
    ("mutate", "path"),
    [
        (lambda bank: bank["entities"].clear(), "/entities"),
        (lambda bank: bank["entities"]["customer"]["names"].clear(), "/entities/customer/names"),
        (
            lambda bank: bank["entities"]["customer"]["names"]["acme_corp"]["patterns"].clear(),
            "/entities/customer/names/acme_corp/patterns",
        ),
    ],
)
def test_empty_structural_maps_are_rejected(minimal_bank, mutate, path):
    mutate(minimal_bank)

    result = validate_bank_schema(minimal_bank)

    assert result["valid"] is False
    assert ("schema.min_properties", path) in {
        (diagnostic["code"], diagnostic["path"]) for diagnostic in result["diagnostics"]
    }


def test_canonicalization_sorts_maps_eval_refs_and_regex_flags(minimal_bank):
    minimal_bank["eval_refs"] = ["z.jsonl", "a.jsonl"]
    minimal_bank["default_regex_flags"] = ["DOTALL", "IGNORECASE", "DOTALL", "ASCII"]
    customer = minimal_bank["entities"]["customer"]
    customer["regex_flags"] = ["MULTILINE", "ASCII", "MULTILINE"]
    customer["names"]["zeta_name"] = copy.deepcopy(customer["names"]["acme_corp"])
    customer["names"]["zeta_name"]["canonical"] = "Zeta"
    customer["names"]["acme_corp"]["eval_refs"] = ["name/z.jsonl", "name/a.jsonl"]
    customer["names"]["acme_corp"]["patterns"]["regex_alias"] = {
        "kind": "regex",
        "value": "\\bAcme\\b",
        "description": "Regex Acme alias.",
        "status": "active",
        "priority": 50,
        "regex_flags": ["VERBOSE", "IGNORECASE", "VERBOSE"],
        "metadata": {},
        "eval_refs": ["pattern/z.jsonl", "pattern/a.jsonl"],
    }

    result = validate_bank_schema(minimal_bank)
    canonical = canonicalize_bank(minimal_bank)

    assert result["valid"] is True
    assert ("flags.duplicate", "/default_regex_flags") in {
        (diagnostic["code"], diagnostic["path"]) for diagnostic in result["diagnostics"]
    }
    assert list(canonical["entities"]["customer"]["names"]) == ["acme_corp", "zeta_name"]
    assert canonical["eval_refs"] == ["a.jsonl", "z.jsonl"]
    assert canonical["default_regex_flags"] == ["ASCII", "IGNORECASE", "DOTALL"]
    assert canonical["entities"]["customer"]["regex_flags"] == ["ASCII", "MULTILINE"]
    assert canonical["entities"]["customer"]["names"]["acme_corp"]["eval_refs"] == [
        "name/a.jsonl",
        "name/z.jsonl",
    ]
    assert canonical["entities"]["customer"]["names"]["acme_corp"]["patterns"]["regex_alias"]["regex_flags"] == [
        "IGNORECASE",
        "VERBOSE",
    ]
    assert canonical["entities"]["customer"]["names"]["acme_corp"]["patterns"]["regex_alias"]["eval_refs"] == [
        "pattern/a.jsonl",
        "pattern/z.jsonl",
    ]


def test_hash_bank_is_stable_for_different_input_key_order(minimal_bank):
    reordered = {
        "metadata": minimal_bank["metadata"],
        "entities": minimal_bank["entities"],
        "default_regex_flags": minimal_bank["default_regex_flags"],
        "unicode_normalization": minimal_bank["unicode_normalization"],
        "updated_at": minimal_bank["updated_at"],
        "created_at": minimal_bank["created_at"],
        "status": minimal_bank["status"],
        "version": minimal_bank["version"],
        "description": minimal_bank["description"],
        "name": minimal_bank["name"],
        "id": minimal_bank["id"],
        "schema_version": minimal_bank["schema_version"],
    }

    assert hash_bank(minimal_bank) == hash_bank(reordered)
    assert hash_bank(minimal_bank).startswith("sha256:")


def test_load_bank_rejects_non_object_json_with_diagnostics(tmp_path):
    bank_path = tmp_path / "bank.json"
    bank_path.write_text("[]", encoding="utf-8")

    with pytest.raises(BankSchemaError) as exc_info:
        load_bank(bank_path)

    assert exc_info.value.diagnostics == [
        {
            "severity": "error",
            "code": "schema.type",
            "path": "",
            "message": f"JSON bank {str(bank_path)!r} must be an object at the top level.",
        }
    ]


def test_load_bank_rejects_schema_invalid_json_with_diagnostics(tmp_path, minimal_bank):
    del minimal_bank["entities"]
    bank_path = tmp_path / "bank.json"
    bank_path.write_text(json.dumps(minimal_bank), encoding="utf-8")

    with pytest.raises(BankSchemaError) as exc_info:
        load_bank(bank_path)

    assert ("schema.required", "/entities") in {
        (diagnostic["code"], diagnostic["path"]) for diagnostic in exc_info.value.diagnostics
    }


def test_bank_stats_returns_structural_counts(minimal_bank):
    customer = minimal_bank["entities"]["customer"]
    customer["names"]["acme_corp"]["patterns"]["regex_alias"] = {
        "kind": "regex",
        "value": "\\bAcme\\b",
        "description": "Regex Acme alias.",
        "status": "deprecated",
        "priority": 50,
        "regex_flags": [],
        "metadata": {},
    }

    assert bank_stats(minimal_bank) == {
        "totals": {"entities": 1, "names": 1, "patterns": 2},
        "active_totals": {"entities": 1, "names": 1, "patterns": 1},
        "by_status": {
            "draft": {"entities": 0, "names": 0, "patterns": 0},
            "active": {"entities": 1, "names": 1, "patterns": 1},
            "inactive": {"entities": 0, "names": 0, "patterns": 0},
            "deprecated": {"entities": 0, "names": 0, "patterns": 1},
        },
        "by_kind": {"literal": 1, "regex": 1},
    }

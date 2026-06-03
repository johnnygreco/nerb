from __future__ import annotations

import copy
import json
from typing import Any

import jsonpatch
import pytest

from nerb import canonicalize_bank, diff_banks


@pytest.fixture
def minimal_bank(test_data_path) -> dict[str, Any]:
    with open(test_data_path / "minimal_bank.json", encoding="utf-8") as file:
        return json.load(file)


def _literal_pattern(value: str) -> dict[str, Any]:
    return {
        "kind": "literal",
        "value": value,
        "description": "Diff fixture.",
        "status": "active",
        "priority": 50,
        "case_sensitive": False,
        "normalize_whitespace": True,
        "left_boundary": "word",
        "right_boundary": "word",
        "metadata": {},
    }


def _name(canonical: str, value: str) -> dict[str, Any]:
    return {
        "canonical": canonical,
        "description": f"{canonical} diff fixture.",
        "status": "active",
        "patterns": {"primary": _literal_pattern(value)},
        "metadata": {},
    }


def test_diff_banks_returns_applicable_json_patch_and_summary_counts(minimal_bank):
    new_bank = copy.deepcopy(minimal_bank)
    new_bank["updated_at"] = "2026-06-04T00:00:00Z"
    new_bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]["value"] = "Acme Corporation"
    new_bank["entities"]["customer"]["names"]["globex"] = _name("Globex", "Globex")
    new_bank["entities"]["vendor"] = {
        "description": "Vendor organizations.",
        "status": "active",
        "regex_flags": [],
        "names": {"initech": _name("Initech", "Initech")},
        "metadata": {},
    }

    result = diff_banks(minimal_bank, new_bank)

    patched = jsonpatch.apply_patch(canonicalize_bank(minimal_bank), result["patch"], in_place=False)
    assert patched == canonicalize_bank(new_bank)
    assert result["summary"]["entities_added"] == 1
    assert result["summary"]["entities_removed"] == 0
    assert result["summary"]["names_added"] == 2
    assert result["summary"]["patterns_added"] == 2
    assert result["summary"]["patterns_changed"] == 1
    assert result["summary"]["top_level_fields_changed"] == 1
    assert result["diagnostics"] == []


def test_diff_banks_enriches_schema_diagnostics_with_bank_label(minimal_bank):
    old_bank = copy.deepcopy(minimal_bank)
    old_bank["default_regex_flags"] = ["IGNORECASE", "IGNORECASE"]

    result = diff_banks(old_bank, minimal_bank)

    assert result["summary"]["patch_operations"] == 0
    assert result["diagnostics"] == [
        {
            "severity": "warning",
            "code": "flags.duplicate",
            "path": "/default_regex_flags",
            "message": "Duplicate regex flags will be removed during canonicalization: 'IGNORECASE'.",
            "metadata": {"bank": "old_bank"},
        }
    ]

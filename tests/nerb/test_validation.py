from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from nerb import BankPatchError, apply_bank_patches, validate_bank


@pytest.fixture
def minimal_bank(test_data_path) -> dict[str, Any]:
    with open(test_data_path / "minimal_bank.json", encoding="utf-8") as file:
        return json.load(file)


def _regex_pattern(value: str, *, flags: list[str] | None = None) -> dict[str, Any]:
    return {
        "kind": "regex",
        "value": value,
        "description": "Runtime validation fixture.",
        "status": "active",
        "priority": 50,
        "regex_flags": flags or [],
        "metadata": {},
    }


def _add_regex(minimal_bank: dict[str, Any], pattern_id: str, value: str) -> None:
    patterns = minimal_bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]
    patterns[pattern_id] = _regex_pattern(value)


def _add_entity_with_regex(bank: dict[str, Any], entity_id: str, name_id: str, pattern_value: str) -> None:
    bank["entities"][entity_id] = {
        "description": f"{entity_id} fixtures.",
        "status": "active",
        "regex_flags": [],
        "names": {
            name_id: {
                "canonical": name_id.replace("_", " ").title(),
                "description": "Runtime validation fixture.",
                "status": "active",
                "patterns": {"primary": _regex_pattern(pattern_value)},
                "metadata": {},
            }
        },
        "metadata": {},
    }


def _codes(result: dict[str, Any]) -> set[str]:
    return {diagnostic["code"] for diagnostic in result["diagnostics"]}


def _risk_kinds(result: dict[str, Any]) -> set[str]:
    risks = set()
    for item in result["diagnostics"]:
        metadata = item.get("metadata", {})
        if item["code"] == "regex.expensive_static" and "risk" in metadata:
            risks.add(metadata["risk"])
    return risks


@pytest.mark.parametrize("level", ["basic", "standard", "deep"])
def test_validate_bank_accepts_levels_and_returns_json_compatible_response(minimal_bank, level):
    _add_regex(minimal_bank, "regex_alias", r"\bAcme\b")

    result = validate_bank(minimal_bank, level=level)

    assert result["valid"] is True
    assert result["hash"].startswith("sha256:")
    assert result["stats"]["totals"] == {"entities": 1, "names": 1, "patterns": 2}
    assert result["engine_compatibility"]["engine"] == "python_re"
    json.dumps(result)


def test_validate_bank_defaults_to_standard_runtime_probe_bounds(minimal_bank):
    _add_regex(minimal_bank, "regex_alias", r"\bAcme\b")

    result = validate_bank(minimal_bank)

    assert result["engine_compatibility"]["runtime_probes"] == {"enabled": True, "max_per_regex": 5}


def test_deep_validation_uses_larger_runtime_probe_bounds_and_eval_ref_hook(minimal_bank):
    minimal_bank["eval_refs"] = ["evals/customer.jsonl"]
    _add_regex(minimal_bank, "regex_alias", r"\bAcme\b")

    result = validate_bank(minimal_bank, level="deep", base_path="/tmp/evals")

    assert result["engine_compatibility"]["runtime_probes"] == {"enabled": True, "max_per_regex": 25}
    assert result["engine_compatibility"]["eval_refs"] == {
        "count": 1,
        "base_path": "/tmp/evals",
        "runner": "deferred",
    }


def test_basic_validation_reports_standalone_regex_compile_errors(minimal_bank):
    _add_regex(minimal_bank, "broken", "(")

    result = validate_bank(minimal_bank, level="basic")

    assert result["valid"] is False
    assert "regex.compile_error" in _codes(result)


def test_validate_bank_returns_schema_diagnostics_for_non_json_compatible_bank(minimal_bank):
    minimal_bank["metadata"]["bad"] = object()

    result = validate_bank(minimal_bank)

    assert result["valid"] is False
    assert result["hash"] is None
    assert any(diagnostic["path"] == "/metadata/bad" for diagnostic in result["diagnostics"])


def test_validation_reports_regexes_that_match_empty_strings(minimal_bank):
    _add_regex(minimal_bank, "empty", r"a*")

    result = validate_bank(minimal_bank, level="basic")

    assert result["valid"] is False
    assert "regex.matches_empty" in _codes(result)


def test_validation_reports_normalization_changes_and_compile_failures(minimal_bank):
    minimal_bank["unicode_normalization"] = "NFKC"
    _add_regex(minimal_bank, "normalized", "（")

    result = validate_bank(minimal_bank, level="basic")

    assert result["valid"] is False
    assert {"regex.normalized_changed", "regex.normalization_compile_error"}.issubset(_codes(result))


def test_duplicate_flags_warn_and_returned_bank_is_canonicalized(minimal_bank):
    minimal_bank["default_regex_flags"] = ["DOTALL", "IGNORECASE", "DOTALL"]
    _add_regex(minimal_bank, "regex_alias", r"\bAcme\b")

    result = validate_bank(minimal_bank, level="basic")

    assert result["valid"] is True
    assert "flags.duplicate" in _codes(result)
    assert result["bank"]["default_regex_flags"] == ["IGNORECASE", "DOTALL"]


def test_unsupported_flags_are_reported_as_flag_diagnostics(minimal_bank):
    minimal_bank["default_regex_flags"] = ["BOGUS"]

    result = validate_bank(minimal_bank)

    assert result["valid"] is False
    assert "flags.unsupported" in _codes(result)


def test_literal_like_regexes_are_info_diagnostics(minimal_bank):
    _add_regex(minimal_bank, "literal_like", "Acme Corp")

    result = validate_bank(minimal_bank)

    assert result["valid"] is True
    assert "regex.literal_candidate" in _codes(result)


def test_static_regex_risk_checks_cover_required_categories(minimal_bank):
    customer_patterns = minimal_bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]
    customer_patterns.clear()
    customer_patterns.update(
        {
            "nested": _regex_pattern(r"(a+)+$"),
            "dot_star": _regex_pattern(r"Acme.*Corp"),
            "ambiguous": _regex_pattern(r"(foo|foobar)"),
            "huge": _regex_pattern("|".join(f"alias{i}" for i in range(20))),
            "lookaround": _regex_pattern(r"(?=A)(?!B)(?=C)Acme"),
            "groups": _regex_pattern("(a)" * 51),
            "short": _regex_pattern("ab"),
        }
    )

    result = validate_bank(minimal_bank)

    assert {
        "nested_quantifier",
        "unbounded_dot_star",
        "ambiguous_alternation",
        "huge_alternation",
        "repeated_lookaround",
        "excessive_groups",
    }.issubset(_risk_kinds(result))
    assert "regex.short_unbounded" in _codes(result)


def test_python_re_composed_validation_reports_duplicate_user_capture_names(minimal_bank):
    _add_regex(minimal_bank, "first", r"(?P<label>Acme)")
    _add_regex(minimal_bank, "second", r"(?P<label>Corp)")

    result = validate_bank(minimal_bank)

    assert result["valid"] is False
    assert "regex.capture_conflict" in _codes(result)


def test_python_re_capture_names_can_repeat_across_entity_shards(minimal_bank):
    minimal_bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"] = _regex_pattern(
        r"(?P<label>Acme)"
    )
    _add_entity_with_regex(minimal_bank, "vendor", "globex", r"(?P<label>Globex)")

    result = validate_bank(minimal_bank)

    assert result["valid"] is True
    assert "regex.capture_conflict" not in _codes(result)


def test_python_re_composed_validation_reports_internal_identity_capture_conflicts(minimal_bank):
    minimal_bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"] = _regex_pattern(
        r"(?P<nerb__customer__acme_corp__primary>Acme)"
    )

    result = validate_bank(minimal_bank)

    assert result["valid"] is False
    assert "regex.capture_conflict" in _codes(result)


def test_python_re_composed_validation_reports_bare_global_inline_flags(minimal_bank):
    _add_regex(minimal_bank, "inline_flags", r"(?i)Acme")

    result = validate_bank(minimal_bank)

    assert result["valid"] is False
    assert "regex.compose_compile_error" in _codes(result)


def test_apply_bank_patches_returns_validated_candidate(minimal_bank):
    patches = [
        {
            "op": "add",
            "path": "/entities/customer/names/acme_corp/patterns/regex_alias",
            "value": _regex_pattern(r"\bAcme\b"),
        }
    ]

    result = apply_bank_patches(minimal_bank, patches)

    assert result["valid"] is True
    assert "regex_alias" in result["bank"]["entities"]["customer"]["names"]["acme_corp"]["patterns"]


def test_apply_bank_patches_returns_invalid_candidate_with_diagnostics(minimal_bank):
    patches = [{"op": "replace", "path": "/entities/customer/names/acme_corp/patterns/primary/value", "value": ""}]

    result = apply_bank_patches(minimal_bank, patches)

    assert result["valid"] is False
    assert result["bank"]["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]["value"] == ""
    assert "schema.minLength" in _codes(result)


def test_apply_bank_patches_raises_clear_error_for_invalid_patch_operations(minimal_bank):
    original_bank = copy.deepcopy(minimal_bank)

    with pytest.raises(BankPatchError) as exc_info:
        apply_bank_patches(minimal_bank, [{"op": "remove", "path": "/missing"}])

    assert exc_info.value.diagnostics[0]["code"] == "patch.invalid"
    assert minimal_bank == original_bank

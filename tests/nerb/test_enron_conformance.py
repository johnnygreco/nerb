from __future__ import annotations

import copy
import json
import stat
from pathlib import Path
from typing import Any

import pytest

import nerb.enron_conformance as conformance_module
import nerb.enron_contract as contract_module
from nerb.enron_conformance import (
    ADVERSARIAL_TAGS,
    NEGATIVE_CASE_SCHEMA_VERSION,
    POSITIVE_CASE_SCHEMA_VERSION,
    RESULT_SCHEMA_VERSION,
    EnronConformanceError,
    EnronConformanceOptions,
    evaluate_enron_conformance,
    evaluate_enron_conformance_files,
)

_CONFORMANCE_FIELDS = {
    "evaluated",
    "label_artifact_id",
    "active_patterns",
    "patterns_with_positive_cases",
    "approved_positive_cases",
    "correctly_mapped",
    "missed",
    "wrong_canonical",
    "negative_cases",
    "unexpected_negative_matches",
    "positive_cases_artifact",
    "negative_cases_artifact",
    "policy_sha256",
    "recall",
    "passed",
}


def _literal_pattern(
    value: str,
    *,
    priority: int,
    status: str = "active",
    case_sensitive: bool = False,
    normalize_whitespace: bool = True,
    left_boundary: str = "word",
    right_boundary: str = "word",
) -> dict[str, Any]:
    return {
        "kind": "literal",
        "value": value,
        "description": "Synthetic conformance literal.",
        "status": status,
        "priority": priority,
        "case_sensitive": case_sensitive,
        "normalize_whitespace": normalize_whitespace,
        "left_boundary": left_boundary,
        "right_boundary": right_boundary,
        "metadata": {},
    }


def _regex_pattern(value: str, *, priority: int, status: str = "active") -> dict[str, Any]:
    return {
        "kind": "regex",
        "value": value,
        "description": "Synthetic conformance regex.",
        "status": status,
        "priority": priority,
        "regex_flags": [],
        "metadata": {},
    }


def _name(canonical: str, patterns: dict[str, Any], *, status: str = "active") -> dict[str, Any]:
    return {
        "canonical": canonical,
        "description": "Synthetic conformance identity.",
        "status": status,
        "patterns": patterns,
        "metadata": {},
    }


def _entity(canonical: str, names: dict[str, Any], *, status: str = "active") -> dict[str, Any]:
    return {
        "description": f"Synthetic {canonical} class.",
        "status": status,
        "regex_flags": [],
        "names": names,
        "metadata": {},
    }


def _bank() -> dict[str, Any]:
    return {
        "schema_version": "nerb.bank.v1",
        "id": "synthetic_conformance_bank",
        "name": "Synthetic Conformance Bank",
        "description": "Non-sensitive evaluator fixture.",
        "version": "1",
        "status": "active",
        "created_at": "2026-07-11T00:00:00Z",
        "updated_at": "2026-07-11T00:00:00Z",
        "unicode_normalization": "none",
        "default_regex_flags": [],
        "entities": {
            "customer": _entity(
                "Customer",
                {
                    "acme_corp": _name(
                        "Acme Corp",
                        {"primary": _literal_pattern("Acme Corp", priority=10)},
                    ),
                    "cafe": _name(
                        "Café",
                        {
                            "primary": _literal_pattern(
                                "Café",
                                priority=10,
                                case_sensitive=True,
                                normalize_whitespace=False,
                                left_boundary="none",
                                right_boundary="none",
                            )
                        },
                    ),
                },
            ),
            "person": _entity(
                "Person",
                {
                    "sam": _name(
                        "Sam",
                        {
                            "short": _literal_pattern(
                                "Sam",
                                priority=10,
                                case_sensitive=True,
                                normalize_whitespace=False,
                                left_boundary="none",
                                right_boundary="none",
                            )
                        },
                    )
                },
            ),
            "project": _entity(
                "Project",
                {"samba": _name("Samba", {"primary": _literal_pattern("Samba", priority=10)})},
            ),
        },
        "metadata": {},
    }


def _expected(
    bank: dict[str, Any],
    entity_id: str,
    name_id: str,
    pattern_id: str,
    text: str,
    string: str,
    *,
    character_start: int | None = None,
) -> dict[str, Any]:
    name = bank["entities"][entity_id]["names"][name_id]
    pattern = name["patterns"][pattern_id]
    start_character = text.index(string) if character_start is None else character_start
    end_character = start_character + len(string)
    return {
        "entity_id": entity_id,
        "name_id": name_id,
        "pattern_id": pattern_id,
        "pattern_kind": pattern["kind"],
        "canonical_name": name["canonical"],
        "string": string,
        "start": len(text[:start_character].encode("utf-8")),
        "end": len(text[:end_character].encode("utf-8")),
    }


def _positive(case_id: str, text: str, tags: list[str], expected: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": POSITIVE_CASE_SCHEMA_VERSION,
        "case_id": case_id,
        "text": text,
        "tags": tags,
        "expected": expected,
    }


def _negative(case_id: str, text: str, tags: list[str], reason_code: str = "no_match") -> dict[str, Any]:
    return {
        "schema_version": NEGATIVE_CASE_SCHEMA_VERSION,
        "case_id": case_id,
        "text": text,
        "tags": tags,
        "reason_code": reason_code,
    }


def _adversarial_cases(bank: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    casing = "ACME CORP"
    punctuation = "(Acme Corp), approved."
    whitespace = "Acme\tCorp"
    unicode_text = "Unicode Café witness"
    overlap = "Samba"
    html = "<b>Acme Corp</b>"
    signature = "-- \nAcme Corp"
    malformed = "From ???\nAcme Corp"
    positive = [
        _positive(
            "p_casing", casing, ["casing"], [_expected(bank, "customer", "acme_corp", "primary", casing, casing)]
        ),
        _positive(
            "p_punctuation",
            punctuation,
            ["boundary", "punctuation"],
            [_expected(bank, "customer", "acme_corp", "primary", punctuation, "Acme Corp")],
        ),
        _positive(
            "p_whitespace",
            whitespace,
            ["whitespace"],
            [_expected(bank, "customer", "acme_corp", "primary", whitespace, whitespace)],
        ),
        _positive(
            "p_unicode",
            unicode_text,
            ["unicode"],
            [_expected(bank, "customer", "cafe", "primary", unicode_text, "Café")],
        ),
        _positive(
            "p_overlap",
            overlap,
            ["overlap"],
            [
                _expected(bank, "person", "sam", "short", overlap, "Sam"),
                _expected(bank, "project", "samba", "primary", overlap, "Samba"),
            ],
        ),
        _positive(
            "p_html",
            html,
            ["html"],
            [_expected(bank, "customer", "acme_corp", "primary", html, "Acme Corp")],
        ),
        _positive(
            "p_signature",
            signature,
            ["signature"],
            [_expected(bank, "customer", "acme_corp", "primary", signature, "Acme Corp")],
        ),
        _positive(
            "p_malformed",
            malformed,
            ["malformed"],
            [_expected(bank, "customer", "acme_corp", "primary", malformed, "Acme Corp")],
        ),
    ]
    negative = [
        _negative("n_boundary", "XAcme CorpY", ["boundary", "negative"], "substring_boundary"),
        _negative("n_clean", "Nothing sensitive here.", ["negative"]),
    ]
    return positive, negative


def _evaluate_fixture(bank: dict[str, Any] | None = None) -> dict[str, Any]:
    selected = bank or _bank()
    positive, negative = _adversarial_cases(selected)
    return evaluate_enron_conformance(selected, positive, negative)


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.write_text(
        "".join(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n" for record in records),
        encoding="utf-8",
    )


def test_conformance_evaluates_all_adversarial_categories_and_contract_aggregate() -> None:
    result = _evaluate_fixture()
    aggregate = result["catalog_conformance"]

    assert result["schema_version"] == RESULT_SCHEMA_VERSION
    assert set(aggregate) == _CONFORMANCE_FIELDS
    assert aggregate == {
        "evaluated": True,
        "label_artifact_id": "enron_catalog_conformance_labels",
        "active_patterns": 4,
        "patterns_with_positive_cases": 4,
        "approved_positive_cases": 9,
        "correctly_mapped": 9,
        "missed": 0,
        "wrong_canonical": 0,
        "negative_cases": 2,
        "unexpected_negative_matches": 0,
        "positive_cases_artifact": {
            "id": "enron_catalog_conformance_positive_cases",
            "sha256": result["fingerprints"]["positive_cases_sha256"],
            "bytes": aggregate["positive_cases_artifact"]["bytes"],
        },
        "negative_cases_artifact": {
            "id": "enron_catalog_conformance_negative_cases",
            "sha256": result["fingerprints"]["negative_cases_sha256"],
            "bytes": aggregate["negative_cases_artifact"]["bytes"],
        },
        "policy_sha256": result["fingerprints"]["policy_sha256"],
        "recall": 1.0,
        "passed": True,
    }
    assert set(result["fingerprints"]) == {
        "bank_hash",
        "case_plan_sha256",
        "comparison_sha256",
        "contract_schema_sha256",
        "contract_validator_source_sha256",
        "engine_bank_hash",
        "evaluator_source_sha256",
        "execution_adapter_sha256",
        "negative_cases_sha256",
        "policy_sha256",
        "positive_cases_sha256",
    }
    assert all(value.startswith("sha256:") and len(value) == 71 for value in result["fingerprints"].values())


def test_catalog_projection_validates_against_the_frozen_conformance_schema() -> None:
    aggregate = _evaluate_fixture()["catalog_conformance"]
    validator = contract_module.EnronContractValidator(contract_module._CONFORMANCE)

    assert list(validator.iter_errors(aggregate)) == []


def test_public_result_contains_no_case_text_or_catalog_identity() -> None:
    serialized = json.dumps(_evaluate_fixture(), ensure_ascii=False, sort_keys=True)

    for private_value in (
        "ACME CORP",
        "Café",
        "Acme Corp",
        "acme_corp",
        "p_unicode",
        "Samba",
        "samba",
        "Nothing sensitive here",
    ):
        assert private_value not in serialized
    assert "/" not in serialized
    assert "@" not in serialized


def test_full_bank_is_compiled_once_and_cross_entity_overlap_is_preserved(monkeypatch) -> None:
    calls = 0
    real_compile = conformance_module.compile_bank

    def counted_compile(*args, **kwargs):
        nonlocal calls
        calls += 1
        return real_compile(*args, **kwargs)

    monkeypatch.setattr(conformance_module, "compile_bank", counted_compile)

    result = _evaluate_fixture()

    assert calls == 1
    assert result["catalog_conformance"]["approved_positive_cases"] == 9
    assert result["catalog_conformance"]["passed"] is True


def test_case_and_bank_fingerprints_are_order_independent_and_deterministic() -> None:
    bank = _bank()
    positive, negative = _adversarial_cases(bank)
    first = evaluate_enron_conformance(bank, positive, negative)

    reordered_bank = json.loads(json.dumps(bank, sort_keys=True))
    reordered_positive = copy.deepcopy(list(reversed(positive)))
    reordered_negative = copy.deepcopy(list(reversed(negative)))
    for case in reordered_positive:
        case["tags"].reverse()
        case["expected"].reverse()
    for case in reordered_negative:
        case["tags"].reverse()

    second = evaluate_enron_conformance(reordered_bank, reordered_positive, reordered_negative)

    assert second == first


def test_comparison_fingerprint_binds_logical_artifact_plan() -> None:
    bank = _bank()
    positive, negative = _adversarial_cases(bank)
    first = evaluate_enron_conformance(bank, positive, negative)
    changed = evaluate_enron_conformance(
        bank,
        positive,
        negative,
        options=EnronConformanceOptions(
            label_artifact_id="different_labels",
            positive_artifact_id="different_positive",
            negative_artifact_id="different_negative",
        ),
    )

    assert changed["fingerprints"]["case_plan_sha256"] != first["fingerprints"]["case_plan_sha256"]
    assert changed["fingerprints"]["comparison_sha256"] != first["fingerprints"]["comparison_sha256"]


def test_comparison_fingerprint_binds_the_shared_execution_adapter(monkeypatch) -> None:
    bank = _bank()
    positive, negative = _adversarial_cases(bank)
    first = evaluate_enron_conformance(bank, positive, negative)

    monkeypatch.setattr(conformance_module, "extraction_execution_sha256", lambda: "sha256:" + "f" * 64)
    changed = evaluate_enron_conformance(bank, positive, negative)

    assert changed["catalog_conformance"] == first["catalog_conformance"]
    assert changed["fingerprints"]["positive_cases_sha256"] == first["fingerprints"]["positive_cases_sha256"]
    assert changed["fingerprints"]["execution_adapter_sha256"] != first["fingerprints"]["execution_adapter_sha256"]
    assert changed["fingerprints"]["comparison_sha256"] != first["fingerprints"]["comparison_sha256"]


def test_aggregate_only_evaluation_does_not_capture_private_audit_payloads(monkeypatch) -> None:
    bank = _bank()
    positive, negative = _adversarial_cases(bank)
    original = conformance_module._canonical_jsonl_artifact
    capture_values = []

    def recording_artifact(*args: Any, **kwargs: Any) -> Any:
        capture_values.append(kwargs["capture_payload"])
        return original(*args, **kwargs)

    monkeypatch.setattr(conformance_module, "_canonical_jsonl_artifact", recording_artifact)
    result = evaluate_enron_conformance(bank, positive, negative)

    assert result["catalog_conformance"]["passed"] is True
    assert capture_values == [False, False]


def test_missing_active_pattern_support_fails_closed_without_inventing_a_miss() -> None:
    bank = _bank()
    positive, negative = _adversarial_cases(bank)
    overlap = next(case for case in positive if case["case_id"] == "p_overlap")
    overlap["expected"] = [item for item in overlap["expected"] if item["entity_id"] == "project"]

    aggregate = evaluate_enron_conformance(bank, positive, negative)["catalog_conformance"]

    assert aggregate["active_patterns"] == 4
    assert aggregate["patterns_with_positive_cases"] == 3
    assert aggregate["missed"] == 0
    assert aggregate["passed"] is False


def test_wrong_canonical_mapping_is_separate_from_a_miss() -> None:
    bank = _bank()
    bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"] = _regex_pattern(
        r"(?i)Acme\s+Corp|Globex", priority=100
    )
    bank["entities"]["customer"]["names"]["globex"] = _name(
        "Globex", {"primary": _literal_pattern("Globex", priority=0)}
    )
    positive, negative = _adversarial_cases(bank)
    positive.extend(
        [
            _positive(
                "p_globex_correct",
                "Globex",
                ["casing"],
                [_expected(bank, "customer", "globex", "primary", "Globex", "Globex")],
            ),
            _positive(
                "p_globex_wrong_mapping",
                "Globex",
                ["casing"],
                [_expected(bank, "customer", "acme_corp", "primary", "Globex", "Globex")],
            ),
        ]
    )

    aggregate = evaluate_enron_conformance(bank, positive, negative)["catalog_conformance"]

    assert aggregate["patterns_with_positive_cases"] == 5
    assert aggregate["wrong_canonical"] == 1
    assert aggregate["missed"] == 0
    assert aggregate["passed"] is False


def test_same_canonical_wrong_pattern_is_a_miss() -> None:
    bank = _bank()
    bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["shadowed"] = _regex_pattern(
        r"Acme Corp", priority=100
    )
    positive, negative = _adversarial_cases(bank)
    positive.append(
        _positive(
            "p_shadowed",
            "Acme Corp",
            ["overlap"],
            [_expected(bank, "customer", "acme_corp", "shadowed", "Acme Corp", "Acme Corp")],
        )
    )

    aggregate = evaluate_enron_conformance(bank, positive, negative)["catalog_conformance"]

    assert aggregate["patterns_with_positive_cases"] == 5
    assert aggregate["wrong_canonical"] == 0
    assert aggregate["missed"] == 1
    assert aggregate["passed"] is False


def test_negative_false_alarm_counts_the_case_not_emitted_records() -> None:
    bank = _bank()
    positive, negative = _adversarial_cases(bank)
    negative[-1]["text"] = "Acme Corp and Samba"

    aggregate = evaluate_enron_conformance(bank, positive, negative)["catalog_conformance"]

    assert aggregate["negative_cases"] == 2
    assert aggregate["unexpected_negative_matches"] == 1
    assert aggregate["passed"] is False


@pytest.mark.parametrize(("positive", "negative"), [([], []), ([], [_negative("n", "none", ["negative"])])])
def test_empty_behavioral_evidence_is_not_evaluated_and_cannot_pass(positive, negative) -> None:
    result = evaluate_enron_conformance(_bank(), positive, negative)

    assert result["catalog_conformance"] == {
        "evaluated": False,
        "label_artifact_id": None,
        "active_patterns": 0,
        "patterns_with_positive_cases": 0,
        "approved_positive_cases": 0,
        "correctly_mapped": 0,
        "missed": 0,
        "wrong_canonical": 0,
        "negative_cases": 0,
        "unexpected_negative_matches": 0,
        "positive_cases_artifact": None,
        "negative_cases_artifact": None,
        "policy_sha256": None,
        "recall": None,
        "passed": False,
    }


def test_inactive_patterns_are_not_cataloged_or_compiled() -> None:
    bank = _bank()
    bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["unsupported_inactive"] = _regex_pattern(
        r"([A-Z]+)-\1", priority=100, status="inactive"
    )

    aggregate = _evaluate_fixture(bank)["catalog_conformance"]

    assert aggregate["active_patterns"] == 4
    assert aggregate["patterns_with_positive_cases"] == 4
    assert aggregate["passed"] is True


@pytest.mark.parametrize("missing_tag", sorted(ADVERSARIAL_TAGS))
def test_every_adversarial_category_is_required(missing_tag: str) -> None:
    bank = _bank()
    positive, negative = _adversarial_cases(bank)
    for case in [*positive, *negative]:
        case["tags"] = [tag for tag in case["tags"] if tag != missing_tag]

    with pytest.raises(
        EnronConformanceError,
        match="adversarial category|non-empty string array|negative tag declaration",
    ):
        evaluate_enron_conformance(bank, positive, negative)


def test_boundary_category_requires_a_negative_case() -> None:
    bank = _bank()
    positive, negative = _adversarial_cases(bank)
    boundary_negative = next(case for case in negative if "boundary" in case["tags"])
    boundary_negative["tags"] = [tag for tag in boundary_negative["tags"] if tag != "boundary"]

    with pytest.raises(EnronConformanceError, match="boundary-negative"):
        evaluate_enron_conformance(bank, positive, negative)


def test_negative_cases_require_nonempty_text() -> None:
    bank = _bank()
    positive, negative = _adversarial_cases(bank)
    for case in negative:
        case["text"] = ""

    with pytest.raises(EnronConformanceError, match="non-empty string"):
        evaluate_enron_conformance(bank, positive, negative)


def test_closed_case_schema_rejects_additional_fields_without_echoing_values() -> None:
    bank = _bank()
    positive, negative = _adversarial_cases(bank)
    positive[0]["private_secret"] = "must-not-echo"

    with pytest.raises(EnronConformanceError) as exc_info:
        evaluate_enron_conformance(bank, positive, negative)

    assert "closed schema" in str(exc_info.value)
    assert "must-not-echo" not in str(exc_info.value)
    assert "private_secret" not in str(exc_info.value)


def test_expected_span_must_align_to_utf8_scalar_boundaries() -> None:
    bank = _bank()
    positive, negative = _adversarial_cases(bank)
    unicode_case = next(case for case in positive if case["case_id"] == "p_unicode")
    unicode_case["expected"][0]["end"] = 12

    with pytest.raises(EnronConformanceError, match="splits a UTF-8 scalar"):
        evaluate_enron_conformance(bank, positive, negative)


def test_unknown_or_inactive_expected_pattern_is_rejected() -> None:
    bank = _bank()
    positive, negative = _adversarial_cases(bank)
    positive[0]["expected"][0]["pattern_id"] = "unknown_private_pattern"

    with pytest.raises(EnronConformanceError, match="not an active pattern") as exc_info:
        evaluate_enron_conformance(bank, positive, negative)

    assert "unknown_private_pattern" not in str(exc_info.value)


def test_duplicate_case_ids_and_expected_occurrences_are_rejected() -> None:
    bank = _bank()
    positive, negative = _adversarial_cases(bank)
    negative[0]["case_id"] = positive[0]["case_id"]

    with pytest.raises(EnronConformanceError, match="globally unique"):
        evaluate_enron_conformance(bank, positive, negative)

    positive, negative = _adversarial_cases(bank)
    positive[0]["expected"].append(copy.deepcopy(positive[0]["expected"][0]))
    with pytest.raises(EnronConformanceError, match="duplicate expected"):
        evaluate_enron_conformance(bank, positive, negative)


def test_same_identity_wrong_pattern_classification_scales_linearly() -> None:
    expected = [
        {
            "entity_id": "person",
            "name_id": "same_name",
            "pattern_id": f"expected_{index}",
            "pattern_kind": "literal",
            "canonical_name": "Same Name",
            "string": "Same Name",
            "start": 0,
            "end": 9,
        }
        for index in range(5_000)
    ]
    actual = [{**item, "pattern_id": f"actual_{index}"} for index, item in enumerate(expected)]

    statuses = conformance_module._classify_expected(expected, actual)

    assert statuses == ["missed"] * len(expected)


def test_scan_match_budget_fails_closed() -> None:
    bank = _bank()
    bank["entities"]["character"] = _entity(
        "Character",
        {"any": _name("Any character", {"any": _regex_pattern(r".", priority=0)})},
    )
    positive, negative = _adversarial_cases(bank)

    with pytest.raises(EnronConformanceError, match="match limit"):
        evaluate_enron_conformance(
            bank,
            positive,
            negative,
            options=EnronConformanceOptions(max_matches_per_case=1),
        )


def test_compile_failures_do_not_echo_private_bank_values(monkeypatch) -> None:
    def fail_compile(*_args: Any, **_kwargs: Any) -> Any:
        raise ValueError("private canonical value")

    monkeypatch.setattr(conformance_module, "compile_bank", fail_compile)
    with pytest.raises(EnronConformanceError, match="compiled safely") as caught:
        evaluate_enron_conformance(_bank(), [], [])
    assert "private canonical value" not in str(caught.value)


def test_scan_requires_native_byte_offset_records(monkeypatch) -> None:
    bank = _bank()
    positive, negative = _adversarial_cases(bank)
    original_compile = conformance_module.compile_bank

    class Proxy:
        def __init__(self, compiled: Any) -> None:
            self._compiled = compiled

        def __getattr__(self, name: str) -> Any:
            return getattr(self._compiled, name)

        def finditer(self, text: str, *, max_matches: int | None = None) -> list[dict[str, Any]]:
            assert max_matches is not None
            return [{**record, "offset_unit": "char"} for record in self._compiled.finditer(text)]

    def proxy_compile(*args: Any, **kwargs: Any) -> Any:
        compiled, cache_hit = original_compile(*args, **kwargs)
        return Proxy(compiled), cache_hit

    monkeypatch.setattr(conformance_module, "compile_bank", proxy_compile)
    with pytest.raises(EnronConformanceError, match="UTF-8 byte offsets"):
        evaluate_enron_conformance(bank, positive, negative)


def test_file_evaluator_commits_canonical_private_audit_and_returns_only_safe_aggregate(tmp_path: Path) -> None:
    bank = _bank()
    positive, negative = _adversarial_cases(bank)
    positive_path = tmp_path / "positive-input.jsonl"
    negative_path = tmp_path / "negative-input.jsonl"
    output_dir = tmp_path / "private-run"
    _write_jsonl(positive_path, list(reversed(positive)))
    _write_jsonl(negative_path, list(reversed(negative)))

    result = evaluate_enron_conformance_files(bank, positive_path, negative_path, output_dir)

    assert result["committed"] is True
    assert result["catalog_conformance"]["passed"] is True
    assert (output_dir / "COMMITTED").is_file()
    assert (output_dir / "positive-cases.jsonl").is_file()
    assert (output_dir / "negative-cases.jsonl").is_file()
    assert (output_dir / "positive-results.jsonl").is_file()
    assert (output_dir / "negative-results.jsonl").is_file()
    assert json.loads((output_dir / "aggregate.json").read_text(encoding="utf-8")) == {
        key: value for key, value in result.items() if key != "committed"
    }
    assert stat.S_IMODE((output_dir / "positive-cases.jsonl").stat().st_mode) == 0o600
    serialized = json.dumps(result, ensure_ascii=False, sort_keys=True)
    assert str(tmp_path) not in serialized
    assert "Acme Corp" not in serialized
    assert "p_casing" not in serialized


def test_file_evaluator_rejects_non_strict_json_without_leaving_output(tmp_path: Path) -> None:
    bank = _bank()
    _positive, negative = _adversarial_cases(bank)
    positive_path = tmp_path / "positive-input.jsonl"
    negative_path = tmp_path / "negative-input.jsonl"
    output_dir = tmp_path / "private-run"
    positive_path.write_text('{"schema_version":"first","schema_version":"second"}\n', encoding="utf-8")
    _write_jsonl(negative_path, negative)

    with pytest.raises(EnronConformanceError, match="duplicate object key"):
        evaluate_enron_conformance_files(bank, positive_path, negative_path, output_dir)

    assert not output_dir.exists()


def test_file_evaluator_bounds_cumulative_raw_case_bytes(tmp_path: Path) -> None:
    bank = _bank()
    positive, negative = _adversarial_cases(bank)
    positive_path = tmp_path / "positive-input.jsonl"
    negative_path = tmp_path / "negative-input.jsonl"
    output_dir = tmp_path / "private-run"
    _write_jsonl(positive_path, positive)
    _write_jsonl(negative_path, negative)

    with pytest.raises(EnronConformanceError, match="artifact exceeds"):
        evaluate_enron_conformance_files(
            bank,
            positive_path,
            negative_path,
            output_dir,
            options=EnronConformanceOptions(max_artifact_bytes=100),
        )
    assert not output_dir.exists()


def test_private_run_is_atomic_when_case_validation_fails(tmp_path: Path) -> None:
    bank = _bank()
    positive, negative = _adversarial_cases(bank)
    positive[0]["extra"] = "private-value"
    positive_path = tmp_path / "positive-input.jsonl"
    negative_path = tmp_path / "negative-input.jsonl"
    output_dir = tmp_path / "private-run"
    _write_jsonl(positive_path, positive)
    _write_jsonl(negative_path, negative)

    with pytest.raises(EnronConformanceError):
        evaluate_enron_conformance_files(bank, positive_path, negative_path, output_dir)

    assert not output_dir.exists()

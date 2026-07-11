from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

import nerb.enron_bank_builder as bank_builder
import nerb.enron_bank_workflow as bank_workflow
import nerb.enron_contract as enron_contract
from nerb.bank import bank_stats, hash_bank
from nerb.enron_bank_builder import EnronBankBuildError, EnronBankPolicy, _canonical_hash, _canonical_json_bytes
from nerb.enron_bank_workflow import (
    _builder_implementation_sha256,
    _conformance_cases,
    _person_literal_boundaries_match,
    _person_literal_catalog_key,
    _validate_public_card,
)
from nerb.enron_conformance import evaluate_enron_conformance
from nerb.validation import validate_bank

_DATA = Path(__file__).parents[1] / "data"
_EMAIL_SHAPE = re.compile(r"[^\s@]+@[^\s@]+")
_PHONE_SHAPE = re.compile(r"(?<![0-9])[0-9]{3}[ .-][0-9]{3}[ .-][0-9]{4}(?![0-9])")


def _load(name: str) -> dict[str, Any]:
    value = json.loads((_DATA / name).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value:
            yield from _strings(item)


def test_committed_fake_bank_card_and_funnel_are_self_consistent() -> None:
    bank_path = _DATA / "enron_bank_v2_fake.json"
    bank = _load(bank_path.name)
    card = _load("enron_bank_card_v2_fake.json")
    funnel = _load("enron_candidate_funnel_v2_fake.json")

    structural = validate_bank(bank, level="deep", strict=True, check_engine_compile=True)
    assert structural["valid"] is True
    assert structural["engine_compatibility"]["compatible"] is True
    _validate_public_card(card)

    assert card["candidate_funnel"] == funnel
    assert sum(funnel["by_decision"].values()) == funnel["total_candidates"]
    assert sum(item["total"] for item in funnel["by_type"].values()) == funnel["total_candidates"]
    assert sum(funnel["by_primary_reason"].values()) == funnel["total_candidates"]
    assert card["bank"]["canonical_sha256"] == hash_bank(bank)
    assert card["bank"]["canonical_json_bytes"] == len(_canonical_json_bytes(bank))
    assert card["bank"]["stats"] == bank_stats(bank)
    assert card["bank"]["artifact_sha256"] == "sha256:" + hashlib.sha256(bank_path.read_bytes()).hexdigest()
    privacy = card["privacy"]
    assert privacy["report_sha256"] == _canonical_hash(
        {key: value for key, value in privacy.items() if key != "report_sha256"}
    )
    iteration_fields = {
        "schema_version",
        "id",
        "parent_id",
        "policy_sha256",
        "bank_sha256",
        "validation_protocol_sha256",
        "catalog_binding_sha256",
        "quality_run_sha256",
        "contact_labeled_spans",
        "contact_labeled_true_positive",
        "contact_labeled_false_negative",
        "contact_labeled_recall",
        "contact_cataloged_false_negative",
        "contact_cataloged_wrong_canonical",
        "person_labeled_spans",
        "person_cataloged_false_negative",
        "person_cataloged_wrong_canonical",
        "open_world_metrics_supported",
        "utility_metrics_supported",
        "active_patterns",
        "canonical_json_bytes",
        "decision",
        "decision_reason_code",
        "selected",
    }
    assert all(set(item) == iteration_fields for item in card["iterations"])
    positives, negatives = _conformance_cases(bank)
    conformance = evaluate_enron_conformance(bank, positives, negatives)["catalog_conformance"]
    for key in ("active_patterns", "approved_positive_cases", "correctly_mapped", "negative_cases"):
        assert card["catalog_conformance"][key] == conformance[key]


def test_committed_real_50000_aggregate_card_and_funnel_are_public_safe_and_bound() -> None:
    card_path = _DATA / "enron_bank_card_v2_real_50000.json"
    funnel_path = _DATA / "enron_candidate_funnel_v2_real_50000.json"
    card = _load(card_path.name)
    funnel = _load(funnel_path.name)

    _validate_public_card(card)
    assert hashlib.sha256(card_path.read_bytes()).hexdigest() == (
        "28a36f27136826fe33f5ce9c853bd90961fe73aee4ccbd47f68f1216642a233f"
    )
    assert hashlib.sha256(funnel_path.read_bytes()).hexdigest() == (
        "3cbb0a616dc0c0becb274b2cb94633edfd9cb9b3aeb5d1173c477710d14f7f1f"
    )
    assert card["run_sha256"] == "sha256:75c11e49db05c72ea6e14a4b5227f32b5297f93fa364aa6ea4461d2a29a50c9a"
    assert card["bank"]["canonical_sha256"] == (
        "sha256:f8a08d0a1c4cfcd36aabe956f3024d749b9fed2f7b1ce59dd7baa8be53e79232"
    )
    assert card["builder"]["candidate_ledger_sha256"] == (
        "sha256:64a76cab8159031065df28a1df3d0b0967a2772efa799a427c9e5ecded5ca448"
    )
    assert card["builder"]["source_sha256"] == _builder_implementation_sha256()
    assert card["builder"]["policy_sha256"] == EnronBankPolicy().sha256
    assert card["candidate_funnel"] == funnel
    assert sum(funnel["by_decision"].values()) == funnel["total_candidates"] == 15_171
    assert sum(item["total"] for item in funnel["by_type"].values()) == funnel["total_candidates"]
    assert sum(funnel["by_primary_reason"].values()) == funnel["total_candidates"]
    assert card["bank"]["stats"]["active_totals"]["patterns"] == 628
    assert card["validation"]["contact"]["labeled_span_recall"] == 1.0
    assert card["validation"]["contact"]["cataloged_false_negative"] == 0
    assert card["validation"]["contact"]["cataloged_wrong_canonical"] == 0
    assert card["catalog_conformance"]["passed"] is True
    assert card["catalog_conformance"]["missed"] == 0
    assert card["catalog_conformance"]["wrong_canonical"] == 0
    auxiliary = card["independent_auxiliary"]
    assert auxiliary["evaluated"] is True
    assert auxiliary["true_positive"] == 94
    assert auxiliary["false_negative"] == 1_802
    assert auxiliary["metrics"]["cataloged_recall"] == 1.0
    assert card["fixture_mode"] is True
    assert card["promotable"] is False
    assert card["source"]["sealed_test_accessed"] is False
    assert card["privacy"]["status"] == "passed"

    serialized = json.dumps((card, funnel), ensure_ascii=False, sort_keys=True)
    assert "@" not in serialized
    assert not _PHONE_SHAPE.search(serialized)
    assert not re.search(r"doc_[0-9a-f]{64}", serialized)
    assert all(not value.startswith(("/", "~/", "file://")) for value in _strings((card, funnel)))


@pytest.mark.parametrize(
    "metric",
    [
        "precision",
        "open_world_recall",
        "f1",
        "catalog_coverage",
        "cataloged_recall",
        "document_leak_rate",
        "cataloged_document_leak_rate",
        "sensitive_character_recall",
        "sensitive_character_leak_rate",
        "negative_document_false_alarm_rate",
        "over_redaction_rate",
    ],
)
def test_real_aggregate_card_rejects_impossible_auxiliary_metric_arithmetic(metric: str) -> None:
    card = _load("enron_bank_card_v2_real_50000.json")
    metrics = card["independent_auxiliary"]["metrics"]
    metrics[metric] = 1.0 if metrics[metric] != 1.0 else 0.0
    card["run_sha256"] = _canonical_hash({key: value for key, value in card.items() if key != "run_sha256"})

    with pytest.raises(EnronBankBuildError, match="semantic invariants"):
        _validate_public_card(card)


def test_committed_fake_card_rejects_nested_schema_and_privacy_commitment_tampering() -> None:
    card = _load("enron_bank_card_v2_fake.json")
    missing_iteration_field = copy.deepcopy(card)
    del missing_iteration_field["iterations"][0]["policy_sha256"]
    missing_iteration_field["run_sha256"] = _canonical_hash(
        {key: value for key, value in missing_iteration_field.items() if key != "run_sha256"}
    )
    with pytest.raises(EnronBankBuildError, match="nested schema"):
        _validate_public_card(missing_iteration_field)

    stale_privacy_commitment = copy.deepcopy(card)
    stale_privacy_commitment["privacy"]["scanner_source_sha256"] = "sha256:" + "5" * 64
    stale_privacy_commitment["run_sha256"] = _canonical_hash(
        {key: value for key, value in stale_privacy_commitment.items() if key != "run_sha256"}
    )
    with pytest.raises(EnronBankBuildError, match="privacy report commitment"):
        _validate_public_card(stale_privacy_commitment)


def test_committed_fake_artifacts_contain_only_fictitious_identifier_shapes() -> None:
    bank = _load("enron_bank_v2_fake.json")
    card = _load("enron_bank_card_v2_fake.json")
    funnel = _load("enron_candidate_funnel_v2_fake.json")
    serialized = json.dumps((bank, card, funnel), ensure_ascii=False, sort_keys=True)

    assert bank["metadata"]["privacy"] == "fictitious_values_only"
    assert "enron.com" not in serialized.casefold()
    assert not _PHONE_SHAPE.search(serialized)
    for value in _strings((bank, card, funnel)):
        if _EMAIL_SHAPE.fullmatch(value) and not value.startswith("(?i)"):
            assert value.casefold().endswith("@example.invalid")
        assert not value.startswith(("/", "~/", "file://"))
        assert not re.fullmatch(r"doc_[0-9a-f]{64}", value)


def test_builder_implementation_commitment_binds_workflow_and_candidate_logic() -> None:
    digest = hashlib.sha256(b"nerb/enron/bank-builder-implementation/v2\0")
    for label, module in (("candidate_builder", bank_builder), ("workflow", bank_workflow)):
        source_path = Path(str(module.__file__))
        digest.update(label.encode("ascii") + b"\0")
        digest.update(hashlib.sha256(source_path.read_bytes()).digest())

    assert _builder_implementation_sha256() == "sha256:" + digest.hexdigest()


def test_public_card_scanner_commitment_binds_wrapper_and_canonical_scanner() -> None:
    digest = hashlib.sha256(b"nerb/enron/public-card-scanner/v2\0")
    for label, module in (("contract_scanner", enron_contract), ("workflow_wrapper", bank_workflow)):
        source_path = Path(str(module.__file__))
        digest.update(label.encode("ascii") + b"\0")
        digest.update(hashlib.sha256(source_path.read_bytes()).digest())

    assert bank_workflow._public_card_scanner_sha256() == "sha256:" + digest.hexdigest()


def test_generated_conformance_cases_exercise_case_whitespace_and_boundaries() -> None:
    bank = _load("enron_bank_v2_fake.json")
    positives, negatives = _conformance_cases(bank)
    result = evaluate_enron_conformance(bank, positives, negatives)
    assert result["catalog_conformance"]["passed"] is True
    assert len(positives) > result["catalog_conformance"]["active_patterns"]

    person_pattern = bank["entities"]["person"]["names"]["fixture_person"]["patterns"]["full_name"]
    for changes in (
        {"case_sensitive": True},
        {"normalize_whitespace": False},
        {"left_boundary": "none", "right_boundary": "none"},
    ):
        changed = copy.deepcopy(bank)
        changed_pattern = changed["entities"]["person"]["names"]["fixture_person"]["patterns"]["full_name"]
        changed_pattern.update(changes)
        changed_result = evaluate_enron_conformance(changed, positives, negatives)
        assert changed_result["catalog_conformance"]["passed"] is False

    assert person_pattern["case_sensitive"] is False


def test_auxiliary_catalog_binding_uses_declared_literal_semantics() -> None:
    assert _person_literal_catalog_key("Maribel   Quill") == _person_literal_catalog_key("maribel quill")
    assert _person_literal_catalog_key("Quill, Maribel") != _person_literal_catalog_key("Maribel Quill")
    assert _person_literal_catalog_key("Straße") == _person_literal_catalog_key("STRAẞE")
    assert _person_literal_catalog_key("Straße") != _person_literal_catalog_key("STRASSE")
    text = "(Maribel Quill) xMaribel Quill"
    assert _person_literal_boundaries_match(text, 1, 14) is True
    assert _person_literal_boundaries_match(text, 17, 30) is False

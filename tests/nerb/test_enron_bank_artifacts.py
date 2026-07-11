from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

import nerb.enron_bank_builder as bank_builder
import nerb.enron_bank_workflow as bank_workflow
from nerb.bank import bank_stats, hash_bank
from nerb.enron_bank_builder import _canonical_json_bytes
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
    positives, negatives = _conformance_cases(bank)
    conformance = evaluate_enron_conformance(bank, positives, negatives)["catalog_conformance"]
    for key in ("active_patterns", "approved_positive_cases", "correctly_mapped", "negative_cases"):
        assert card["catalog_conformance"][key] == conformance[key]


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
    assert _person_literal_catalog_key("Kenneth   Lay") == _person_literal_catalog_key("kenneth lay")
    assert _person_literal_catalog_key("Lay, Kenneth") != _person_literal_catalog_key("Kenneth Lay")
    text = "(Kenneth Lay) xKenneth Lay"
    assert _person_literal_boundaries_match(text, 1, 12) is True
    assert _person_literal_boundaries_match(text, 15, 26) is False

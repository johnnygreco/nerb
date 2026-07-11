from __future__ import annotations

import copy
import json
from typing import Any

import pytest

import nerb.enron_quality as enron_quality
from nerb.enron_quality import (
    EnronQualityError,
    evaluate_cmu_enron_training_quality,
    evaluate_enron_quality,
    evaluate_enron_quality_files,
)


def _pattern(value: str, *, priority: int = 50) -> dict[str, Any]:
    return {
        "kind": "literal",
        "value": value,
        "description": "Synthetic quality pattern.",
        "status": "active",
        "priority": priority,
        "case_sensitive": True,
        "normalize_whitespace": False,
        "left_boundary": "none",
        "right_boundary": "none",
        "metadata": {},
    }


def _name(canonical: str, value: str) -> dict[str, Any]:
    return {
        "canonical": canonical,
        "description": "Synthetic quality identity.",
        "status": "active",
        "patterns": {"primary": _pattern(value)},
        "metadata": {},
    }


def _bank(names: dict[str, tuple[str, str]] | None = None) -> dict[str, Any]:
    names = names or {
        "alice": ("Alice", "Alice"),
        "alicia": ("Alicia", "Alicia"),
        "noise": ("Noise", "Noise"),
    }
    return {
        "schema_version": "nerb.bank.v1",
        "id": "synthetic_quality_bank",
        "name": "Synthetic Quality Bank",
        "description": "Synthetic bank for aggregate quality tests.",
        "version": "fixture-v1",
        "status": "active",
        "created_at": "2026-07-11T00:00:00Z",
        "updated_at": "2026-07-11T00:00:00Z",
        "unicode_normalization": "none",
        "default_regex_flags": [],
        "entities": {
            "person": {
                "description": "Synthetic people.",
                "status": "active",
                "regex_flags": [],
                "names": {name_id: _name(canonical, value) for name_id, (canonical, value) in names.items()},
                "metadata": {},
            }
        },
        "metadata": {},
    }


_SPAN_POLICY_SHA256 = "sha256:" + "1" * 64


def _document(document_id: str, text: str, *, split_role: str = "validation") -> dict[str, Any]:
    return {
        "document_id": document_id,
        "text": text,
        "text_view": "natural_body",
        "split_role": split_role,
    }


def _gold(
    document_id: str,
    start: int,
    end: int,
    *,
    catalog_name_id: str | None,
    catalog_pattern_id: str = "primary",
) -> dict[str, Any]:
    return {
        "document_id": document_id,
        "entity_class": "person",
        "start": start,
        "end": end,
        "catalog_identity": (
            None
            if catalog_name_id is None
            else {
                "entity_id": "person",
                "name_id": catalog_name_id,
                "pattern_id": catalog_pattern_id,
            }
        ),
    }


def _slice(
    document_ids: list[str],
    *,
    slice_id: str = "person_all_validation",
    label_strength: str = "independent",
    completeness: str = "exhaustive_within_scope",
    cohort: str = "all",
    split_role: str = "validation",
    promotion_gate: bool = False,
) -> dict[str, Any]:
    return {
        "id": slice_id,
        "label_artifact_id": "synthetic_person_labels",
        "label_strength": label_strength,
        "annotation_scope": {
            "entity_classes": ["person"],
            "document_regions": ["natural_body"],
            "span_policy_sha256": _SPAN_POLICY_SHA256,
            "exclusions": [],
        },
        "annotation_completeness": completeness,
        "entity_class": "person",
        "cohort": cohort,
        "split_role": split_role,
        "text_view": "natural_body",
        "text_view_descriptor": {
            "id": "natural_body",
            "artifact_sha256": "sha256:" + "2" * 64,
            "content_policy_sha256": "sha256:" + "3" * 64,
            "document_regions": ["natural_body"],
            "primary_for_quality": True,
            "answer_bearing_fields_included": False,
        },
        "promotion_gate": promotion_gate,
        "document_ids": document_ids,
    }


def _quality_slice(result: dict[str, Any], index: int = 0) -> dict[str, Any]:
    return result["quality"]["slices"][index]


def _write_jsonl(path: Any, rows: list[dict[str, Any]]) -> None:
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def test_quality_reports_catalog_open_world_document_and_utility_metrics_separately() -> None:
    bank = _bank()
    bank["entities"]["person"]["names"]["alice"]["patterns"]["alicia_qualifier"] = {
        "kind": "regex",
        "value": r"Alici[a]",
        "description": "Independently adjudicated overlap qualifier.",
        "status": "active",
        "priority": 100,
        "regex_flags": [],
        "metadata": {},
    }
    bank["entities"]["person"]["names"]["alicia"]["patterns"]["primary"]["priority"] = 10
    documents = [
        _document("doc_1", "Café Alice"),
        _document("doc_2", "Bob"),
        _document("doc_3", "Alicia"),
        _document("doc_4", "Noise"),
    ]
    gold = [
        # Scalar start 5 differs from the native UTF-8 byte start 6.
        _gold("doc_1", 5, 10, catalog_name_id="alice"),
        _gold("doc_2", 0, 3, catalog_name_id=None),
        # The span is detected, but the frozen expected identity is different.
        _gold("doc_3", 0, 6, catalog_name_id="alice", catalog_pattern_id="alicia_qualifier"),
    ]

    result = evaluate_enron_quality(
        bank,
        documents=documents,
        gold_spans=gold,
        slice_specs=[_slice([item["document_id"] for item in documents])],
    )

    assert result["evaluated"] is True
    assert "passed" not in result
    item = _quality_slice(result)
    assert {
        "documents": item["documents"],
        "documents_with_sensitive_gold": item["documents_with_sensitive_gold"],
        "documents_with_any_miss": item["documents_with_any_miss"],
        "documents_with_cataloged_gold": item["documents_with_cataloged_gold"],
        "documents_with_any_cataloged_miss": item["documents_with_any_cataloged_miss"],
        "gold_spans": item["gold_spans"],
        "predicted_spans": item["predicted_spans"],
        "true_positive": item["true_positive"],
        "false_positive": item["false_positive"],
        "false_negative": item["false_negative"],
        "cataloged_gold_spans": item["cataloged_gold_spans"],
        "cataloged_true_positive": item["cataloged_true_positive"],
        "cataloged_false_negative": item["cataloged_false_negative"],
        "cataloged_wrong_canonical": item["cataloged_wrong_canonical"],
    } == {
        "documents": 4,
        "documents_with_sensitive_gold": 3,
        "documents_with_any_miss": 1,
        "documents_with_cataloged_gold": 2,
        "documents_with_any_cataloged_miss": 1,
        "gold_spans": 3,
        "predicted_spans": 3,
        "true_positive": 2,
        "false_positive": 1,
        "false_negative": 1,
        "cataloged_gold_spans": 2,
        "cataloged_true_positive": 1,
        "cataloged_false_negative": 0,
        "cataloged_wrong_canonical": 1,
    }
    assert item["sensitive_gold_characters"] == 14
    assert item["covered_sensitive_characters"] == 11
    assert item["leaked_sensitive_characters"] == 3
    assert item["predicted_characters"] == 16
    assert item["over_redacted_characters"] == 5
    assert item["evaluated_characters"] == 24
    assert item["documents_with_any_leaked_character"] == 1
    assert item["negative_documents"] == item["negative_documents_with_predictions"] == 1
    assert item["metrics"] == {
        "precision": pytest.approx(2 / 3),
        "open_world_recall": pytest.approx(2 / 3),
        "f1": pytest.approx(2 / 3),
        "catalog_coverage": pytest.approx(2 / 3),
        "cataloged_recall": 0.5,
        "document_leak_rate": pytest.approx(1 / 3),
        "cataloged_document_leak_rate": 0.5,
        "sensitive_character_recall": pytest.approx(11 / 14),
        "sensitive_character_leak_rate": pytest.approx(3 / 14),
        "negative_document_false_alarm_rate": 1.0,
        "over_redaction_rate": pytest.approx(5 / 24),
    }


def test_wider_prediction_is_exact_span_miss_but_covers_sensitive_characters() -> None:
    bank = _bank({"alice": ("Alice", "Alice Smith")})
    result = evaluate_enron_quality(
        bank,
        documents=[_document("doc_1", "Alice Smith")],
        gold_spans=[_gold("doc_1", 0, 5, catalog_name_id="alice")],
        slice_specs=[_slice(["doc_1"])],
    )

    item = _quality_slice(result)
    assert (item["true_positive"], item["false_positive"], item["false_negative"]) == (0, 1, 1)
    assert (item["cataloged_false_negative"], item["cataloged_wrong_canonical"]) == (1, 0)
    assert item["documents_with_any_miss"] == 1
    assert item["documents_with_any_leaked_character"] == 0
    assert item["covered_sensitive_characters"] == item["sensitive_gold_characters"] == 5
    assert item["leaked_sensitive_characters"] == 0
    assert item["predicted_characters"] == 11
    assert item["over_redacted_characters"] == 6
    assert item["metrics"]["open_world_recall"] == 0.0
    assert item["metrics"]["sensitive_character_recall"] == 1.0


@pytest.mark.parametrize(
    ("label_strength", "completeness"),
    [("independent", "partial"), ("structured_weak", "exhaustive_within_scope")],
)
def test_partial_and_structured_weak_slices_report_only_labeled_and_catalog_diagnostics(
    label_strength: str, completeness: str
) -> None:
    result = evaluate_enron_quality(
        _bank(),
        documents=[_document("doc_1", "Alice Noise")],
        gold_spans=[_gold("doc_1", 0, 5, catalog_name_id="alice")],
        slice_specs=[
            _slice(
                ["doc_1"],
                label_strength=label_strength,
                completeness=completeness,
            )
        ],
    )

    item = _quality_slice(result)
    assert (item["gold_spans"], item["true_positive"], item["false_negative"]) == (1, 1, 0)
    assert (item["predicted_spans"], item["false_positive"]) == (1, 0)
    assert item["cataloged_gold_spans"] == item["cataloged_true_positive"] == 1
    assert item["metrics"]["catalog_coverage"] == item["metrics"]["cataloged_recall"] == 1.0
    for field in (
        "precision",
        "open_world_recall",
        "f1",
        "document_leak_rate",
        "cataloged_document_leak_rate",
        "sensitive_character_recall",
        "sensitive_character_leak_rate",
        "negative_document_false_alarm_rate",
        "over_redaction_rate",
    ):
        assert item["metrics"][field] is None
    for field in (
        "sensitive_gold_characters",
        "covered_sensitive_characters",
        "leaked_sensitive_characters",
        "predicted_characters",
        "over_redacted_characters",
        "evaluated_characters",
        "negative_documents",
        "negative_documents_with_predictions",
    ):
        assert item[field] == 0


def test_character_positions_are_document_disjoint_and_overlaps_count_once() -> None:
    result = evaluate_enron_quality(
        _bank({"alice": ("Alice", "Alice")}),
        documents=[_document("doc_1", "Alice"), _document("doc_2", "Alice")],
        gold_spans=[
            _gold("doc_1", 0, 5, catalog_name_id="alice"),
            _gold("doc_1", 3, 5, catalog_name_id="alice"),
            _gold("doc_2", 0, 5, catalog_name_id="alice"),
        ],
        slice_specs=[_slice(["doc_1", "doc_2"])],
    )

    item = _quality_slice(result)
    assert item["gold_spans"] == 3
    assert item["sensitive_gold_characters"] == 10
    assert item["covered_sensitive_characters"] == 10
    assert item["predicted_characters"] == 10
    assert item["leaked_sensitive_characters"] == item["over_redacted_characters"] == 0


def test_empty_and_unlabeled_nonexhaustive_slices_fail_closed_with_explicit_reasons() -> None:
    result = evaluate_enron_quality(
        _bank(),
        documents=[_document("doc_1", "Nothing labeled")],
        gold_spans=[],
        slice_specs=[
            _slice([], slice_id="empty"),
            _slice(
                ["doc_1"],
                slice_id="weak_without_labels",
                label_strength="structured_weak",
            ),
        ],
    )

    assert result["evaluated"] is False
    assert "passed" not in result
    assert result["quality"]["evaluated"] is False
    assert result["quality"]["slices"] == []
    assert result["unsupported_slices"] == [
        {"id": "empty", "dimension": "population", "reason_code": "empty_document_population"},
        {"id": "weak_without_labels", "dimension": "population", "reason_code": "zero_labeled_spans"},
    ]


def test_catalog_membership_is_explicit_and_not_inferred_from_predictions() -> None:
    result = evaluate_enron_quality(
        _bank({"alice": ("Alice", "Alice")}),
        documents=[_document("doc_1", "Alice")],
        gold_spans=[_gold("doc_1", 0, 5, catalog_name_id=None)],
        slice_specs=[_slice(["doc_1"])],
    )

    item = _quality_slice(result)
    assert item["true_positive"] == 1
    assert item["cataloged_gold_spans"] == 0
    assert item["metrics"]["catalog_coverage"] == 0.0
    assert item["metrics"]["cataloged_recall"] is None

    with pytest.raises(EnronQualityError, match="active pattern inventory"):
        evaluate_enron_quality(
            _bank({"alice": ("Alice", "Alice")}),
            documents=[_document("doc_1", "Alice")],
            gold_spans=[_gold("doc_1", 0, 5, catalog_name_id="missing_name")],
            slice_specs=[_slice(["doc_1"])],
        )

    with pytest.raises(EnronQualityError, match="active pattern inventory"):
        evaluate_enron_quality(
            _bank({"alice": ("Alice", "Alice")}),
            documents=[_document("doc_1", "Alice")],
            gold_spans=[_gold("doc_1", 0, 5, catalog_name_id="alice", catalog_pattern_id="missing_pattern")],
            slice_specs=[_slice(["doc_1"])],
        )


def test_protocol_is_order_stable_but_invalidates_on_plan_or_input_changes_and_run_binds_bank() -> None:
    documents = [_document("doc_1", "Alice"), _document("doc_2", "No match")]
    gold = [_gold("doc_1", 0, 5, catalog_name_id="alice")]
    slices = [_slice(["doc_2", "doc_1"])]
    bank = _bank({"alice": ("Alice", "Alice")})

    first = evaluate_enron_quality(bank, documents=documents, gold_spans=gold, slice_specs=slices)
    reordered = evaluate_enron_quality(
        bank,
        documents=list(reversed(documents)),
        gold_spans=list(reversed(gold)),
        slice_specs=[{**slices[0], "document_ids": list(reversed(slices[0]["document_ids"]))}],
    )
    assert reordered["protocol_sha256"] == first["protocol_sha256"]
    assert reordered["run_sha256"] == first["run_sha256"]

    changed_plan = evaluate_enron_quality(
        bank,
        documents=documents,
        gold_spans=gold,
        slice_specs=[{**slices[0], "cohort": "known"}],
    )
    assert changed_plan["protocol_sha256"] != first["protocol_sha256"]
    assert changed_plan["run_sha256"] != first["run_sha256"]

    changed_documents = copy.deepcopy(documents)
    changed_documents[1]["text"] = "Different no match"
    changed_input = evaluate_enron_quality(bank, documents=changed_documents, gold_spans=gold, slice_specs=slices)
    assert changed_input["protocol_sha256"] != first["protocol_sha256"]

    changed_bank = _bank({"alice": ("Alice", "Alice"), "unused": ("Unused", "Unused")})
    bank_result = evaluate_enron_quality(changed_bank, documents=documents, gold_spans=gold, slice_specs=slices)
    assert bank_result["protocol_sha256"] == first["protocol_sha256"]
    assert bank_result["run_sha256"] != first["run_sha256"]


def test_run_fingerprint_binds_the_normalized_contract_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    arguments = {
        "documents": [_document("doc_1", "Alice")],
        "gold_spans": [_gold("doc_1", 0, 5, catalog_name_id="alice")],
        "slice_specs": [_slice(["doc_1"])],
    }
    bank = _bank({"alice": ("Alice", "Alice")})
    baseline = evaluate_enron_quality(bank, **arguments)

    monkeypatch.setattr(
        enron_quality,
        "validate_enron_quality_output",
        lambda _quality: {"valid": False, "diagnostics": [{"code": "contract.synthetic_probe"}]},
    )
    changed = evaluate_enron_quality(bank, **arguments)

    assert changed["protocol_sha256"] == baseline["protocol_sha256"]
    assert changed["quality"] == baseline["quality"]
    assert changed["contract_validation"] == {
        "valid": False,
        "diagnostic_codes": ["contract.synthetic_probe"],
    }
    assert changed["run_sha256"] != baseline["run_sha256"]


def test_bank_is_compiled_once_and_output_contains_no_document_text(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0
    compile_bank = enron_quality.compile_bank

    def recording_compile(*args: Any, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        return compile_bank(*args, **kwargs)

    monkeypatch.setattr(enron_quality, "compile_bank", recording_compile)
    result = evaluate_enron_quality(
        _bank({"alice": ("Alice", "Alice")}),
        documents=[_document("private_doc", "Café Alice")],
        gold_spans=[_gold("private_doc", 5, 10, catalog_name_id="alice")],
        slice_specs=[_slice(["private_doc"])],
    )

    assert calls == 1
    serialized = json.dumps(result, sort_keys=True, ensure_ascii=False)
    assert "private_doc" not in serialized
    assert "Café" not in serialized
    assert "Alice" not in serialized
    assert result["evaluator"]["source_sha256"].startswith("sha256:")
    assert result["evaluator_sha256"].startswith("sha256:")
    assert result["protocol_sha256"].startswith("sha256:")
    assert result["catalog_binding_sha256"].startswith("sha256:")
    assert result["run_sha256"].startswith("sha256:")


def test_quality_compile_and_scan_failures_do_not_echo_private_values(monkeypatch: pytest.MonkeyPatch) -> None:
    original_compile = enron_quality.compile_bank
    bank = _bank({"alice": ("Private Canonical", "Private Surface")})
    documents = [_document("private_doc", "Private Surface in a private document")]
    gold = [_gold("private_doc", 0, 15, catalog_name_id="alice")]
    slices = [_slice(["private_doc"])]

    def leaking_compile(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("Private Canonical Private Surface")

    monkeypatch.setattr(enron_quality, "compile_bank", leaking_compile)
    with pytest.raises(EnronQualityError, match="could not be compiled safely") as compile_error:
        evaluate_enron_quality(bank, documents=documents, gold_spans=gold, slice_specs=slices)
    assert "Private" not in str(compile_error.value)

    real_compiled, _cache_hit = original_compile(
        _bank({"alice": ("Alice", "Alice")}), options={"include_statuses": ["active"]}
    )

    class LeakingScanner:
        extractable_bank = real_compiled.extractable_bank
        bank = real_compiled.bank
        bank_hash = real_compiled.bank_hash

        def finditer(self, _text: str, *, max_matches: int | None = None) -> Any:
            assert max_matches == enron_quality.DEFAULT_MAX_QUALITY_PREDICTIONS_PER_DOCUMENT
            raise RuntimeError("private_doc Private Surface")

    monkeypatch.setattr(enron_quality, "compile_bank", lambda *_args, **_kwargs: (LeakingScanner(), False))
    with pytest.raises(EnronQualityError, match="could not be scanned safely") as scan_error:
        evaluate_enron_quality(
            _bank({"alice": ("Alice", "Alice")}),
            documents=[_document("private_doc", "Alice")],
            gold_spans=[_gold("private_doc", 0, 5, catalog_name_id="alice")],
            slice_specs=[_slice(["private_doc"])],
        )
    assert "private_doc" not in str(scan_error.value)
    assert "Private Surface" not in str(scan_error.value)


def test_quality_rejects_non_byte_native_offsets(monkeypatch: pytest.MonkeyPatch) -> None:
    original_compile = enron_quality.compile_bank
    real_compiled, _cache_hit = original_compile(
        _bank({"alice": ("Alice", "Alice")}), options={"include_statuses": ["active"]}
    )

    class CharacterOffsetScanner:
        extractable_bank = real_compiled.extractable_bank
        bank = real_compiled.bank
        bank_hash = real_compiled.bank_hash

        def finditer(self, text: str, *, max_matches: int | None = None) -> list[dict[str, Any]]:
            assert max_matches == enron_quality.DEFAULT_MAX_QUALITY_PREDICTIONS_PER_DOCUMENT
            records = real_compiled.finditer(text)
            return [{**record, "offset_unit": "char"} for record in records]

    monkeypatch.setattr(enron_quality, "compile_bank", lambda *_args, **_kwargs: (CharacterOffsetScanner(), False))
    with pytest.raises(EnronQualityError, match="bounded offsets"):
        evaluate_enron_quality(
            _bank({"alice": ("Alice", "Alice")}),
            documents=[_document("doc_1", "Alice")],
            gold_spans=[_gold("doc_1", 0, 5, catalog_name_id="alice")],
            slice_specs=[_slice(["doc_1"])],
        )


@pytest.mark.parametrize(
    ("target", "extra"),
    [
        ("document", {"extra": True}),
        ("gold", {"surface": "private"}),
        ("slice", {"predicate": "private"}),
    ],
)
def test_quality_inputs_are_closed(target: str, extra: dict[str, Any]) -> None:
    documents = [_document("doc_1", "Alice")]
    gold = [_gold("doc_1", 0, 5, catalog_name_id="alice")]
    slices = [_slice(["doc_1"])]
    if target == "document":
        documents[0].update(extra)
    elif target == "gold":
        gold[0].update(extra)
    else:
        slices[0].update(extra)

    with pytest.raises(EnronQualityError, match="closed quality schema"):
        evaluate_enron_quality(_bank(), documents=documents, gold_spans=gold, slice_specs=slices)


def test_quality_file_helper_uses_strict_private_jsonl_and_returns_the_same_aggregate(tmp_path: Any) -> None:
    documents = [_document("doc_1", "Alice"), _document("doc_2", "No match")]
    gold = [_gold("doc_1", 0, 5, catalog_name_id="alice")]
    slices = [_slice(["doc_1", "doc_2"])]
    documents_path = tmp_path / "documents.jsonl"
    gold_path = tmp_path / "gold.jsonl"
    slices_path = tmp_path / "slices.jsonl"
    _write_jsonl(documents_path, documents)
    _write_jsonl(gold_path, gold)
    _write_jsonl(slices_path, slices)

    expected = evaluate_enron_quality(_bank(), documents=documents, gold_spans=gold, slice_specs=slices)
    actual = evaluate_enron_quality_files(
        _bank(),
        documents_path=documents_path,
        gold_spans_path=gold_path,
        slice_specs_path=slices_path,
    )

    assert actual == expected

    documents_path.write_text('{"document_id":"private","document_id":"duplicate"}\n', encoding="utf-8")
    with pytest.raises(EnronQualityError, match="could not be read safely") as caught:
        evaluate_enron_quality_files(
            _bank(),
            documents_path=documents_path,
            gold_spans_path=gold_path,
            slice_specs_path=slices_path,
        )
    assert "private" not in str(caught.value)


def test_quality_binds_exact_annotation_scope_and_fails_closed_for_invalid_promotion() -> None:
    documents = [_document(f"doc_{index}", "Alice", split_role="test") for index in range(5)]
    gold = [_gold(f"doc_{index}", 0, 5, catalog_name_id="alice") for index in range(5)]
    valid_slice = _slice([document["document_id"] for document in documents], split_role="test", promotion_gate=True)
    result = evaluate_enron_quality(
        _bank({"alice": ("Alice", "Alice")}),
        documents=documents,
        gold_spans=gold,
        slice_specs=[valid_slice],
    )
    assert _quality_slice(result)["annotation_scope"] == valid_slice["annotation_scope"]
    assert result["contract_validation"] == {"valid": True, "diagnostic_codes": []}

    empty = evaluate_enron_quality(
        _bank({"alice": ("Alice", "Alice")}),
        documents=documents,
        gold_spans=[],
        slice_specs=[valid_slice],
    )
    assert empty["evaluated"] is False
    assert empty["unsupported_slices"] == [
        {
            "id": "person_all_validation",
            "dimension": "population",
            "reason_code": "zero_gold_promotion_support",
        }
    ]

    with pytest.raises(EnronQualityError, match="independent exhaustive final-test"):
        evaluate_enron_quality(
            _bank(),
            documents=[_document("doc_1", "Alice")],
            gold_spans=[_gold("doc_1", 0, 5, catalog_name_id="alice")],
            slice_specs=[_slice(["doc_1"], promotion_gate=True)],
        )

    for mutation in ("cohort", "primary"):
        invalid = copy.deepcopy(valid_slice)
        if mutation == "cohort":
            invalid["cohort"] = "tail"
        else:
            invalid["text_view_descriptor"]["primary_for_quality"] = False
        with pytest.raises(EnronQualityError, match="complete unexcluded annotation scope"):
            evaluate_enron_quality(
                _bank({"alice": ("Alice", "Alice")}),
                documents=documents,
                gold_spans=gold,
                slice_specs=[invalid],
            )


def test_text_view_id_is_distinct_from_its_document_regions() -> None:
    document = _document("doc_1", "Alice")
    document["text_view"] = "subject_current_body"
    slice_spec = _slice(["doc_1"])
    slice_spec["text_view"] = "subject_current_body"
    slice_spec["text_view_descriptor"] = {
        "id": "subject_current_body",
        "artifact_sha256": "sha256:" + "4" * 64,
        "content_policy_sha256": "sha256:" + "5" * 64,
        "document_regions": ["natural_body", "natural_subject"],
        "primary_for_quality": False,
        "answer_bearing_fields_included": False,
    }
    slice_spec["annotation_scope"]["document_regions"] = ["natural_body"]

    with pytest.raises(EnronQualityError, match="complete text view"):
        evaluate_enron_quality(
            _bank({"alice": ("Alice", "Alice")}),
            documents=[document],
            gold_spans=[_gold("doc_1", 0, 5, catalog_name_id="alice")],
            slice_specs=[slice_spec],
        )

    slice_spec["annotation_completeness"] = "partial"
    result = evaluate_enron_quality(
        _bank({"alice": ("Alice", "Alice")}),
        documents=[document],
        gold_spans=[_gold("doc_1", 0, 5, catalog_name_id="alice")],
        slice_specs=[slice_spec],
    )

    assert _quality_slice(result)["text_view"] == "subject_current_body"
    assert _quality_slice(result)["annotation_scope"]["document_regions"] == ["natural_body"]
    assert _quality_slice(result)["metrics"]["open_world_recall"] is None
    assert _quality_slice(result)["metrics"]["precision"] is None
    assert _quality_slice(result)["metrics"]["negative_document_false_alarm_rate"] is None


def test_protocol_excludes_candidate_specific_catalog_binding() -> None:
    bank = _bank({"alice": ("Alice", "Alice")})
    documents = [_document("doc_1", "Alice")]
    slices = [_slice(["doc_1"])]
    uncataloged = evaluate_enron_quality(
        bank,
        documents=documents,
        gold_spans=[_gold("doc_1", 0, 5, catalog_name_id=None)],
        slice_specs=slices,
    )
    cataloged = evaluate_enron_quality(
        bank,
        documents=documents,
        gold_spans=[_gold("doc_1", 0, 5, catalog_name_id="alice")],
        slice_specs=slices,
    )

    assert cataloged["protocol_sha256"] == uncataloged["protocol_sha256"]
    assert cataloged["catalog_binding_sha256"] != uncataloged["catalog_binding_sha256"]
    assert cataloged["run_sha256"] != uncataloged["run_sha256"]


def test_unsupported_dimensions_are_explicit_and_fingerprinted() -> None:
    bank = _bank({"alice": ("Alice", "Alice")})
    documents = [_document("doc_1", "Alice")]
    gold = [_gold("doc_1", 0, 5, catalog_name_id="alice")]
    slices = [_slice(["doc_1"])]
    unsupported = [
        {"id": "identity_known", "dimension": "known_novel", "reason_code": "identity_linkage_unavailable"},
        {"id": "frequency_head", "dimension": "head_tail", "reason_code": "train_frequency_unavailable"},
        {"id": "alternate_view", "dimension": "text_view", "reason_code": "text_view_unavailable"},
        {"id": "negative_review", "dimension": "negative", "reason_code": "negative_labels_unavailable"},
    ]
    result = evaluate_enron_quality(
        bank,
        documents=documents,
        gold_spans=gold,
        slice_specs=slices,
        unsupported_slice_specs=list(reversed(unsupported)),
    )

    assert result["unsupported_slices"] == sorted(unsupported, key=lambda item: item["id"])
    changed = evaluate_enron_quality(
        bank,
        documents=documents,
        gold_spans=gold,
        slice_specs=slices,
        unsupported_slice_specs=[{**unsupported[0], "reason_code": "different_reason"}],
    )
    assert changed["protocol_sha256"] != result["protocol_sha256"]


@pytest.mark.parametrize(
    ("target", "value"),
    [
        ("slice_id", "private@example.invalid"),
        ("exclusion", "/private/mailbox/path"),
        ("cohort", "\ud800"),
        ("document_id", "\ud800"),
    ],
)
def test_quality_rejects_private_or_non_utf8_logical_identifiers(target: str, value: str) -> None:
    documents = [_document("doc_1", "Alice")]
    slices = [_slice(["doc_1"])]
    if target == "slice_id":
        slices[0]["id"] = value
    elif target == "exclusion":
        slices[0]["annotation_scope"]["exclusions"] = [value]
    elif target == "cohort":
        slices[0]["cohort"] = value
    else:
        documents[0]["document_id"] = value
        slices[0]["document_ids"] = [value]

    with pytest.raises(EnronQualityError, match="privacy-safe|UTF-8"):
        evaluate_enron_quality(
            _bank({"alice": ("Alice", "Alice")}),
            documents=documents,
            gold_spans=[],
            slice_specs=slices,
        )


def test_quality_rejects_unassigned_documents_and_gold() -> None:
    with pytest.raises(EnronQualityError, match="Every quality document"):
        evaluate_enron_quality(
            _bank(),
            documents=[_document("doc_1", "Alice"), _document("doc_2", "No match")],
            gold_spans=[_gold("doc_1", 0, 5, catalog_name_id="alice")],
            slice_specs=[_slice(["doc_1"])],
        )

    with pytest.raises(EnronQualityError, match="Every gold span"):
        evaluate_enron_quality(
            _bank(),
            documents=[_document("doc_1", "Alice")],
            gold_spans=[
                {
                    "document_id": "doc_1",
                    "entity_class": "organization",
                    "start": 0,
                    "end": 5,
                    "catalog_identity": None,
                }
            ],
            slice_specs=[_slice(["doc_1"])],
        )


def test_negative_documents_do_not_allocate_byte_boundary_maps(monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected_map(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("negative documents must not allocate byte-boundary maps")

    monkeypatch.setattr(enron_quality, "_selected_byte_to_scalar_boundaries", unexpected_map)
    result = evaluate_enron_quality(
        _bank({"alice": ("Alice", "Alice")}),
        documents=[_document("doc_1", "x" * 1_000_000)],
        gold_spans=[],
        slice_specs=[_slice(["doc_1"])],
    )

    assert result["evaluated"] is True
    assert _quality_slice(result)["negative_documents"] == 1


def test_quality_scan_enforces_native_and_cumulative_prediction_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    bank = _bank({"alice": ("Alice", "A")})
    documents = [_document("doc_1", "AAA")]
    slices = [_slice(["doc_1"])]

    monkeypatch.setattr(enron_quality, "DEFAULT_MAX_QUALITY_PREDICTIONS_PER_DOCUMENT", 2)
    monkeypatch.setattr(enron_quality, "DEFAULT_MAX_QUALITY_PREDICTIONS_TOTAL", 10)
    with pytest.raises(EnronQualityError, match="per-document prediction limit"):
        evaluate_enron_quality(bank, documents=documents, gold_spans=[], slice_specs=slices)

    monkeypatch.setattr(enron_quality, "DEFAULT_MAX_QUALITY_PREDICTIONS_PER_DOCUMENT", 10)
    monkeypatch.setattr(enron_quality, "DEFAULT_MAX_QUALITY_PREDICTIONS_TOTAL", 2)
    with pytest.raises(EnronQualityError, match="cumulative prediction limit"):
        evaluate_enron_quality(bank, documents=documents, gold_spans=[], slice_specs=slices)


def test_quality_file_helper_enforces_cumulative_resource_limits(tmp_path: Any) -> None:
    documents_path = tmp_path / "documents.jsonl"
    gold_path = tmp_path / "gold.jsonl"
    slices_path = tmp_path / "slices.jsonl"
    _write_jsonl(documents_path, [_document("doc_1", "Alice")])
    _write_jsonl(gold_path, [_gold("doc_1", 0, 5, catalog_name_id="alice")])
    _write_jsonl(slices_path, [_slice(["doc_1"])])

    with pytest.raises(EnronQualityError, match="cumulative byte limit"):
        evaluate_enron_quality_files(
            _bank(),
            documents_path=documents_path,
            gold_spans_path=gold_path,
            slice_specs_path=slices_path,
            max_input_bytes=10,
        )
    with pytest.raises(EnronQualityError, match="record limit"):
        evaluate_enron_quality_files(
            _bank(),
            documents_path=documents_path,
            gold_spans_path=gold_path,
            slice_specs_path=slices_path,
            max_records=1,
        )


def test_cmu_adapter_binds_verified_source_and_requires_catalog_adjudication(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    import nerb.enron_annotations as annotations

    source = {
        "documents": [
            _document(f"doc_{index}", "Alice" if index == 0 else "No match", split_role="train") for index in range(6)
        ],
        "labels": [{"document_id": "doc_0", "entity_class": "person", "start": 0, "end": 5}],
        "label_artifact_id": "cmu_enron_meetings_person_labels",
        "annotation_scope": {
            "entity_classes": ["person"],
            "document_regions": ["published_source_fragment"],
            "span_policy_sha256": "sha256:" + "6" * 64,
            "exclusions": ["names_inside_email_addresses"],
        },
        "annotation_completeness": "exhaustive_within_scope",
        "label_strength": "independent",
        "text_view_descriptor": {
            "id": "natural_body",
            "artifact_sha256": "sha256:" + "7" * 64,
            "content_policy_sha256": "sha256:" + "8" * 64,
            "document_regions": ["published_source_fragment"],
            "primary_for_quality": True,
            "answer_bearing_fields_included": False,
        },
        "public_binding": {
            "source_sha256": "sha256:" + "9" * 64,
            "documents_sha256": "sha256:" + "a" * 64,
            "labels_sha256": "sha256:" + "b" * 64,
            "span_policy_sha256": "sha256:" + "6" * 64,
            "promotable": False,
            "nonpromotable_reason": "auxiliary_source_without_bound_content_adjudication",
        },
    }
    monkeypatch.setattr(annotations, "load_cmu_enron_training_quality_source", lambda _path: source)
    binding = {
        "document_id": "doc_0",
        "start": 0,
        "end": 5,
        "catalog_identity": {"entity_id": "person", "name_id": "alice", "pattern_id": "primary"},
    }

    result = evaluate_cmu_enron_training_quality(
        _bank({"alice": ("Alice", "Alice")}),
        annotation_run_dir=tmp_path,
        catalog_bindings=[binding],
    )

    assert result["annotation_source"] == source["public_binding"]
    assert result["annotation_binding_sha256"].startswith("sha256:")
    assert result["quality_run_sha256"].startswith("sha256:")
    assert result["run_sha256"] != result["quality_run_sha256"]
    assert [item["id"] for item in result["quality"]["slices"]] == [
        "cmu_person_all_train",
        "cmu_person_negative_train",
    ]
    assert result["quality"]["slices"][0]["cataloged_true_positive"] == 1
    assert result["contract_validation"] == {"valid": True, "diagnostic_codes": []}

    source["public_binding"] = {**source["public_binding"], "labels_sha256": "sha256:" + "c" * 64}
    changed_source = evaluate_cmu_enron_training_quality(
        _bank({"alice": ("Alice", "Alice")}),
        annotation_run_dir=tmp_path,
        catalog_bindings=[binding],
    )
    assert changed_source["quality_run_sha256"] == result["quality_run_sha256"]
    assert changed_source["annotation_binding_sha256"] != result["annotation_binding_sha256"]
    assert changed_source["run_sha256"] != result["run_sha256"]

    with pytest.raises(EnronQualityError, match="exactly cover"):
        evaluate_cmu_enron_training_quality(
            _bank({"alice": ("Alice", "Alice")}),
            annotation_run_dir=tmp_path,
            catalog_bindings=[],
        )

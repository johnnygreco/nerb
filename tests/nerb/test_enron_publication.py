from __future__ import annotations

import copy
import hashlib
import json
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import pytest

import nerb.enron_publication as publication
from nerb.enron_contract import hash_enron_audit_chain, validate_enron_evidence
from nerb.enron_publication import (
    EnronPublicationError,
    export_enron_publication,
    render_enron_publication,
    verify_enron_publication,
)

REPOSITORY_ROOT = Path(__file__).parents[2]
COMMITTED_BUNDLE = REPOSITORY_ROOT / "evidence" / "enron"
FROZEN_INPUT_SHA256 = {
    "bank-card.json": "d3f23569eb060289a67b8eb902c75f9f75e74f01918abd2531c76566f9041aa2",
    "benchmark-evidence.json": "c3634d83a3b57910d4860a852511451755c03e0734e5b391b5bdf7638a434e4f",
    "benchmark-manifest.json": "d0706d2a6d7198645b21d49bfa111dd547f392218e2f6078cefeab4e00b6f1d6",
    "capacity-decision.json": "441d90fc64d45d6febdd2a8ee13d9db25c712d195f4414ca6acb9bf1268ddca2",
    "inventories/controlled_dense_medium_inventory.json": (
        "877e6afd195300f2154250fceb471d90901c84f5d73c2543805a830ee00c9d9f"
    ),
    "inventories/controlled_negative_huge_inventory.json": (
        "aaabd7497f69ca1f4069d321adcf8da54293f629e2f410717a89022210b45d49"
    ),
    "inventories/controlled_negative_large_inventory.json": (
        "d7cdc7ca54d7b56503607ad0a26299e351430d2156821e5b065b918f9bc2a8c8"
    ),
    "inventories/controlled_negative_medium_inventory.json": (
        "471cd812803b9aabf09a7d7b9c665fd6dec939873a80eed3d44d58ab503520c8"
    ),
    "inventories/controlled_negative_small_inventory.json": (
        "6e35842bb2432f7fc0624a0caf0b0e8c82f0f078a123505a94bcdea92a1dea94"
    ),
    "inventories/controlled_normal_medium_inventory.json": (
        "84e0ac3be64ad7854aeacdb5032b29a56af3708fc3e57934ea0ba4a70fd7f61c"
    ),
    "inventories/controlled_sparse_medium_inventory.json": (
        "10a510d0e9199713f0a685374f830ca35983e93b507c5ff29cb05f6bf4134a8d"
    ),
    "inventories/real_validation_inventory.json": ("8c679dfb2f9fb7b51d53473b8f9fb1ffd024280b3ca0d9f553acfd5e651a3456"),
    "performance-report.json": "cf8bc7308772800d0b89dfa29fca9313b044a2527d3f66c11f0c927c201d772c",
}


def _copy_bundle(tmp_path: Path) -> Path:
    target = tmp_path / "bundle"
    shutil.copytree(COMMITTED_BUNDLE, target)
    return target


def _committed_json(relative_path: str) -> dict[str, Any]:
    return json.loads((COMMITTED_BUNDLE / relative_path).read_text(encoding="utf-8"))


def _committed_inventories() -> dict[str, list[dict[str, int]]]:
    return {
        path.stem: json.loads(path.read_text(encoding="utf-8"))
        for path in (COMMITTED_BUNDLE / "inventories").glob("*.json")
    }


def _assert_contract_valid(evidence: dict[str, Any]) -> None:
    assert validate_enron_evidence(
        evidence,
        manifest=_committed_json("benchmark-manifest.json"),
        referenced_input_inventories=_committed_inventories(),
    ) == {"valid": True, "diagnostics": []}


def _rewrite_publication_artifact(
    bundle: Path,
    relative_path: str,
    payload: bytes,
    *,
    binding_updates: dict[str, object] | None = None,
) -> None:
    (bundle / relative_path).write_bytes(payload)
    publication_path = bundle / "publication.json"
    publication_manifest = json.loads(publication_path.read_text(encoding="utf-8"))
    descriptor = next(item for item in publication_manifest["artifacts"] if item["path"] == relative_path)
    descriptor["bytes"] = len(payload)
    descriptor["sha256"] = publication._sha256_bytes(payload)
    if binding_updates is not None:
        publication_manifest["bindings"].update(binding_updates)
    publication_manifest["publication_sha256"] = publication._canonical_hash(
        publication._without(publication_manifest, "publication_sha256")
    )
    publication_path.write_bytes(publication._pretty_json_bytes(publication_manifest))


def _insufficient_support_evidence() -> dict[str, Any]:
    evidence = copy.deepcopy(json.loads((COMMITTED_BUNDLE / "benchmark-evidence.json").read_text(encoding="utf-8")))
    evidence["quality"] = {
        "evaluated": False,
        "matching_semantics": evidence["quality"]["matching_semantics"],
        "character_position_semantics": evidence["quality"]["character_position_semantics"],
        "slices": [],
    }
    evidence["promotion"]["passed"] = False
    evidence["promotion"]["claims"] = []
    evidence["verifier"]["passed"] = False
    for check in evidence["promotion"]["checks"]:
        if check["category"] == "quality":
            check["actual"] = None
            check["passed"] = False
    score = evidence["audit_chain"]["score"]
    score.update(
        {
            "status": "insufficient_support",
            "support_failure_codes": ["gold_spans_below_minimum"],
            "artifacts_sha256": publication._canonical_hash({}),
            "prediction_commitment_sha256": None,
            "quality_decision_sha256": None,
            "quality_decision_passed": False,
        }
    )
    prediction = evidence["audit_chain"]["prediction_audit"]
    prediction.update(
        {
            "status": "not_run_insufficient_support",
            "receipt_sha256": None,
            "manifest_sha256": None,
            "artifacts_sha256": None,
            "prediction_commitment_sha256": None,
            "gold_defects": 0,
            "decision_eligible": False,
            "release": "do_not_ship",
        }
    )
    evidence["audit_chain"]["chain_sha256"] = hash_enron_audit_chain(evidence["audit_chain"])
    return evidence


@pytest.fixture
def fast_capacity(monkeypatch):
    value = json.loads((COMMITTED_BUNDLE / "capacity-decision.json").read_text(encoding="utf-8"))
    monkeypatch.setattr(publication, "_verify_capacity_artifact", lambda _path: value)
    return value


def test_committed_publication_separates_known_bank_contract_from_standalone_redaction() -> None:
    result = verify_enron_publication(COMMITTED_BUNDLE)

    assert result["valid"] is True
    assert result["artifacts_verified"] == 18
    assert result["decision"] == {
        "catalog_conformance_passed": True,
        "capacity_gates_passed": True,
        "performance_gates_passed": True,
        "standalone_privacy_audit_outcome": "do_not_ship",
        "standalone_privacy_audit_status": "quality_gates_failed",
        "standalone_privacy_redaction_allowed": False,
        "standalone_privacy_redaction_quality_passed": False,
    }
    assert "package_release_allowed" not in result["decision"]
    assert "release" not in result["decision"]
    assert result["privacy"]["violation_count"] == 0


def test_standalone_redaction_eligibility_is_separate_from_evidence_validity(fast_capacity) -> None:
    assert verify_enron_publication(COMMITTED_BUNDLE)["valid"] is True

    with pytest.raises(EnronPublicationError, match="not eligible for standalone privacy redaction") as raised:
        verify_enron_publication(COMMITTED_BUNDLE, require_standalone_redaction_eligible=True)

    assert raised.value.code == "enron_standalone_redaction_ineligible"


@pytest.mark.parametrize(
    "relative_path",
    [
        "benchmark-evidence.json",
        "bank-card.json",
        "inventories/real_validation_inventory.json",
        "summary.md",
        "figures/known-bank-contract.svg",
    ],
)
def test_publication_rejects_artifact_tampering(tmp_path: Path, fast_capacity, relative_path: str) -> None:
    bundle = _copy_bundle(tmp_path)
    path = bundle / relative_path
    path.write_bytes(path.read_bytes() + b" ")

    with pytest.raises(EnronPublicationError):
        verify_enron_publication(bundle)


def test_publication_rejects_missing_and_undeclared_artifacts(tmp_path: Path, fast_capacity) -> None:
    missing = _copy_bundle(tmp_path / "missing")
    (missing / "figures" / "bank-coverage.svg").unlink()
    with pytest.raises(EnronPublicationError):
        verify_enron_publication(missing)

    extra = _copy_bundle(tmp_path / "extra")
    (extra / "extra.json").write_text("{}", encoding="utf-8")
    with pytest.raises(EnronPublicationError, match="missing or undeclared"):
        verify_enron_publication(extra)


def test_publication_rejects_symlinked_artifact(tmp_path: Path, fast_capacity) -> None:
    bundle = _copy_bundle(tmp_path)
    summary = bundle / "summary.md"
    replacement = tmp_path / "replacement.md"
    replacement.write_bytes(summary.read_bytes())
    summary.unlink()
    summary.symlink_to(replacement)

    with pytest.raises(EnronPublicationError, match="symbolic links"):
        verify_enron_publication(bundle)


def test_publication_privacy_scan_rejects_direct_identifier() -> None:
    with pytest.raises(EnronPublicationError, match="privacy scan"):
        publication._privacy_scan({"aggregate.json": b'{"value":"contact@example.invalid"}'})


def test_publication_rejects_rehashed_standalone_redaction_overstatement(tmp_path: Path, fast_capacity) -> None:
    bundle = _copy_bundle(tmp_path)
    manifest_path = bundle / "publication.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["decision"]["standalone_privacy_redaction_allowed"] = True
    manifest["publication_sha256"] = publication._canonical_hash(publication._without(manifest, "publication_sha256"))
    manifest_path.write_bytes(publication._pretty_json_bytes(manifest))

    with pytest.raises(EnronPublicationError, match="does not match"):
        verify_enron_publication(bundle)


def test_publication_rejects_rehashed_upstream_quality_decision_overstatement(tmp_path: Path, fast_capacity) -> None:
    evidence = _committed_json("benchmark-evidence.json")
    score = evidence["audit_chain"]["score"]
    score["quality_decision_passed"] = True
    prediction = evidence["audit_chain"]["prediction_audit"]
    prediction.update(
        {
            "status": "accepted",
            "decision_eligible": True,
            "release": "quality_eligible",
        }
    )
    evidence["audit_chain"]["chain_sha256"] = hash_enron_audit_chain(evidence["audit_chain"])
    validation = validate_enron_evidence(
        evidence,
        manifest=_committed_json("benchmark-manifest.json"),
        referenced_input_inventories=_committed_inventories(),
    )

    assert validation["valid"] is False
    assert any(item["path"] == "/audit_chain/score/quality_decision_passed" for item in validation["diagnostics"])
    evidence_path = tmp_path / "overstated-evidence.json"
    evidence_path.write_bytes(publication._pretty_json_bytes(evidence))
    with pytest.raises(EnronPublicationError, match="semantic contract validation"):
        export_enron_publication(
            tmp_path / "output",
            benchmark_manifest_path=COMMITTED_BUNDLE / "benchmark-manifest.json",
            benchmark_evidence_path=evidence_path,
            performance_report_path=COMMITTED_BUNDLE / "performance-report.json",
            capacity_decision_path=COMMITTED_BUNDLE / "capacity-decision.json",
            bank_card_path=COMMITTED_BUNDLE / "bank-card.json",
            inventory_dir=COMMITTED_BUNDLE / "inventories",
        )


def test_publication_rejects_rehashed_performance_decision_corruption(tmp_path: Path, fast_capacity) -> None:
    bundle = _copy_bundle(tmp_path)
    report = json.loads((bundle / "performance-report.json").read_text(encoding="utf-8"))
    report["decision_grade"]["failure_codes"] = ["missing_required_workload"]
    report["run_sha256"] = publication._canonical_hash(publication._without(report, "run_sha256"))
    payload = publication._pretty_json_bytes(report)
    _rewrite_publication_artifact(
        bundle,
        "performance-report.json",
        payload,
        binding_updates={"performance_run_sha256": report["run_sha256"]},
    )

    with pytest.raises(EnronPublicationError, match="differs from the frozen aggregate decision"):
        verify_enron_publication(bundle)


def test_publication_rejects_rehashed_bank_card_document_and_entity_fields(tmp_path: Path, fast_capacity) -> None:
    bundle = _copy_bundle(tmp_path)
    card = json.loads((bundle / "bank-card.json").read_text(encoding="utf-8"))
    card["development_validation"]["unreviewed_document_id"] = "message-000001"
    card["development_validation"]["unreviewed_entity_value"] = "Alice Example"
    card["card_sha256"] = publication._canonical_hash(publication._without(card, "card_sha256"))
    _rewrite_publication_artifact(bundle, "bank-card.json", publication._pretty_json_bytes(card))

    with pytest.raises(EnronPublicationError, match="recursively closed shape"):
        verify_enron_publication(bundle)


def test_render_is_deterministic_and_aggregate_only(tmp_path: Path, fast_capacity) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"

    first_result = render_enron_publication(COMMITTED_BUNDLE, first)
    second_result = render_enron_publication(COMMITTED_BUNDLE, second)

    assert first_result == second_result
    committed_publication = json.loads((COMMITTED_BUNDLE / "publication.json").read_text(encoding="utf-8"))
    assert first_result["source_publication_sha256"] == committed_publication["publication_sha256"]
    assert sorted(path.relative_to(first).as_posix() for path in first.rglob("*") if path.is_file()) == [
        "figures/bank-coverage.svg",
        "figures/known-bank-contract.svg",
        "figures/performance-scale.svg",
        "figures/standalone-redaction.svg",
        "summary.md",
    ]
    for path in first.rglob("*"):
        if path.is_file():
            counterpart = second / path.relative_to(first)
            assert path.read_bytes() == counterpart.read_bytes()
            assert path.read_bytes() == (COMMITTED_BUNDLE / path.relative_to(first)).read_bytes()


def test_renderer_reports_failed_and_unevaluated_conformance_honestly() -> None:
    evidence = _committed_json("benchmark-evidence.json")
    conformance = evidence["catalog_conformance"]
    conformance["correctly_mapped"] -= 1
    conformance["missed"] = 1
    conformance["recall"] = conformance["correctly_mapped"] / conformance["approved_positive_cases"]
    conformance["passed"] = False
    check = next(item for item in evidence["promotion"]["checks"] if item["id"] == "catalog_conformance")
    check["actual"] = False
    check["passed"] = False
    _assert_contract_valid(evidence)

    summary = publication._render_summary(
        _committed_json("benchmark-manifest.json"),
        evidence,
        _committed_json("performance-report.json"),
        _committed_json("bank-card.json"),
        _committed_json("capacity-decision.json"),
    ).decode()
    assert "Known-bank contract evidence: FAIL" in summary
    assert "39,603 of 39,604 approved cases" in summary
    assert "correctly mapped 39,604 approved cases" not in summary
    failed_svg = publication._render_figures(evidence, _committed_json("performance-report.json"))[
        "figures/known-bank-contract.svg"
    ].decode()
    assert "#f05b67" in failed_svg
    assert "39,603 of 39,604 approved cases" in failed_svg

    unevaluated = _committed_json("benchmark-evidence.json")
    conformance = unevaluated["catalog_conformance"]
    for field in (
        "active_patterns",
        "patterns_with_positive_cases",
        "approved_positive_cases",
        "correctly_mapped",
        "missed",
        "wrong_canonical",
        "negative_cases",
        "unexpected_negative_matches",
    ):
        conformance[field] = 0
    for field in (
        "label_artifact_id",
        "positive_cases_artifact",
        "negative_cases_artifact",
        "policy_sha256",
        "recall",
    ):
        conformance[field] = None
    conformance["evaluated"] = False
    conformance["passed"] = False
    check = next(item for item in unevaluated["promotion"]["checks"] if item["id"] == "catalog_conformance")
    check["actual"] = False
    check["passed"] = False
    _assert_contract_valid(unevaluated)

    unavailable_svg = publication._render_figures(unevaluated, _committed_json("performance-report.json"))[
        "figures/known-bank-contract.svg"
    ].decode()
    assert "Known-bank contract evidence unavailable" in unavailable_svg
    assert "0 / 0" not in unavailable_svg


def test_renderer_accounts_for_cataloged_wrong_mappings() -> None:
    evidence = _committed_json("benchmark-evidence.json")
    for slice_id in ("person_contact_all_test", "contact_all_test"):
        quality_slice = next(item for item in evidence["quality"]["slices"] if item["id"] == slice_id)
        quality_slice["cataloged_true_positive"] -= 1
        quality_slice["cataloged_wrong_canonical"] += 1
        quality_slice["metrics"]["cataloged_recall"] = (
            quality_slice["cataloged_true_positive"] / quality_slice["cataloged_gold_spans"]
        )
    for check in evidence["promotion"]["checks"]:
        if check["id"] == "cataloged_recall":
            check["actual"] = evidence["quality"]["slices"][0]["metrics"]["cataloged_recall"]
        elif check["id"] == "cataloged_wrong_canonical":
            check["actual"] = 1
            check["passed"] = False
    _assert_contract_valid(evidence)

    summary = publication._render_summary(
        _committed_json("benchmark-manifest.json"),
        evidence,
        _committed_json("performance-report.json"),
        _committed_json("bank-card.json"),
        _committed_json("capacity-decision.json"),
    ).decode()
    coverage_svg = publication._render_figures(evidence, _committed_json("performance-report.json"))[
        "figures/bank-coverage.svg"
    ].decode()
    assert "1 catalog-qualified wrong canonical mappings" in summary
    assert "1 wrong mapping" in coverage_svg


def test_rendered_plots_expose_values_thresholds_and_high_contrast_labels() -> None:
    summary = publication._render_summary(
        _committed_json("benchmark-manifest.json"),
        _committed_json("benchmark-evidence.json"),
        _committed_json("performance-report.json"),
        _committed_json("bank-card.json"),
        _committed_json("capacity-decision.json"),
    ).decode()
    for value in ("142 / 1,393", "3,183 / 14,916", "7 / 69", "142 / 149"):
        assert value in summary
    for value in ("932,400.9", "53,299.6", "26,714.8", "6,810.8"):
        assert value in summary

    figures = publication._render_figures(
        _committed_json("benchmark-evidence.json"), _committed_json("performance-report.json")
    )
    namespace = {"svg": "http://www.w3.org/2000/svg"}

    def svg_description(payload: bytes) -> str:
        description = ET.fromstring(payload).find("svg:desc", namespace)
        assert description is not None
        return description.text or ""

    descriptions = {path: svg_description(payload) for path, payload in figures.items()}
    assert "13,201 of 13,201 active patterns" in descriptions["figures/known-bank-contract.svg"]
    assert "minimum threshold 100.00%" in descriptions["figures/known-bank-contract.svg"]
    assert "1,247 outside the bank" in descriptions["figures/bank-coverage.svg"]
    assert "142 of 1,393 labeled spans" in descriptions["figures/standalone-redaction.svg"]
    assert "minimum threshold 95.00%" in descriptions["figures/standalone-redaction.svg"]
    for value in ("932,401", "53,300", "26,715", "6,811"):
        assert value in descriptions["figures/performance-scale.svg"]

    def luminance(color: str) -> float:
        channels = [int(color[index : index + 2], 16) / 255 for index in (1, 3, 5)]
        linear = [channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4 for channel in channels]
        return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]

    foreground = luminance(publication._SVG_TEXT)
    background = luminance(publication._SVG_VALUE_BACKGROUND)
    contrast = (max(foreground, background) + 0.05) / (min(foreground, background) + 0.05)
    assert contrast >= 4.5
    for path in (
        "figures/known-bank-contract.svg",
        "figures/standalone-redaction.svg",
        "figures/performance-scale.svg",
    ):
        svg = figures[path].decode()
        assert svg.count('class="value-bg"') == svg.count('class="value"')


def test_insufficient_support_terminal_exports_and_renders_without_quality_rates(tmp_path: Path, fast_capacity) -> None:
    evidence = _insufficient_support_evidence()
    manifest = json.loads((COMMITTED_BUNDLE / "benchmark-manifest.json").read_text(encoding="utf-8"))
    inventories = {
        path.stem: json.loads(path.read_text(encoding="utf-8"))
        for path in (COMMITTED_BUNDLE / "inventories").glob("*.json")
    }
    assert validate_enron_evidence(
        evidence,
        manifest=manifest,
        referenced_input_inventories=inventories,
    ) == {"valid": True, "diagnostics": []}
    evidence_path = tmp_path / "insufficient-support.json"
    evidence_path.write_bytes(publication._pretty_json_bytes(evidence))
    output = tmp_path / "publication"

    result = export_enron_publication(
        output,
        benchmark_manifest_path=COMMITTED_BUNDLE / "benchmark-manifest.json",
        benchmark_evidence_path=evidence_path,
        performance_report_path=COMMITTED_BUNDLE / "performance-report.json",
        capacity_decision_path=COMMITTED_BUNDLE / "capacity-decision.json",
        bank_card_path=COMMITTED_BUNDLE / "bank-card.json",
        inventory_dir=COMMITTED_BUNDLE / "inventories",
    )

    assert result["valid"] is True
    assert result["decision"]["standalone_privacy_audit_outcome"] == "do_not_ship"
    assert result["decision"]["standalone_privacy_redaction_allowed"] is False
    assert result["decision"]["standalone_privacy_redaction_quality_passed"] is False
    publication_manifest = json.loads((output / "publication.json").read_text(encoding="utf-8"))
    assert publication_manifest["scope"]["gold_sample_documents"] is None
    assert publication_manifest["scope"]["gold_spans"] is None
    summary = (output / "summary.md").read_text(encoding="utf-8")
    assert "Known-bank contract evidence: PASS" in summary
    assert "insufficient independent support" in summary
    assert "standalone-redaction rates and miss counts are intentionally unavailable" in summary
    rendered = tmp_path / "rendered"
    render_result = render_enron_publication(output, rendered)
    assert render_result["source_publication_sha256"] == publication_manifest["publication_sha256"]
    assert (rendered / "figures" / "known-bank-contract.svg").read_bytes() == (
        output / "figures" / "known-bank-contract.svg"
    ).read_bytes()


def test_export_round_trip_is_byte_deterministic(tmp_path: Path, fast_capacity) -> None:
    output = tmp_path / "exported"

    result = export_enron_publication(
        output,
        benchmark_manifest_path=COMMITTED_BUNDLE / "benchmark-manifest.json",
        benchmark_evidence_path=COMMITTED_BUNDLE / "benchmark-evidence.json",
        performance_report_path=COMMITTED_BUNDLE / "performance-report.json",
        capacity_decision_path=COMMITTED_BUNDLE / "capacity-decision.json",
        bank_card_path=COMMITTED_BUNDLE / "bank-card.json",
        inventory_dir=COMMITTED_BUNDLE / "inventories",
    )

    assert result["valid"] is True
    expected = sorted(
        path.relative_to(COMMITTED_BUNDLE).as_posix() for path in COMMITTED_BUNDLE.rglob("*") if path.is_file()
    )
    actual = sorted(path.relative_to(output).as_posix() for path in output.rglob("*") if path.is_file())
    assert actual == expected
    for relative_path in expected:
        assert (output / relative_path).read_bytes() == (COMMITTED_BUNDLE / relative_path).read_bytes()


def test_export_requires_every_content_addressed_inventory(tmp_path: Path, fast_capacity) -> None:
    inventories = tmp_path / "inventories"
    shutil.copytree(COMMITTED_BUNDLE / "inventories", inventories)
    (inventories / "real_validation_inventory.json").unlink()

    with pytest.raises(EnronPublicationError):
        export_enron_publication(
            tmp_path / "output",
            benchmark_manifest_path=COMMITTED_BUNDLE / "benchmark-manifest.json",
            benchmark_evidence_path=COMMITTED_BUNDLE / "benchmark-evidence.json",
            performance_report_path=COMMITTED_BUNDLE / "performance-report.json",
            capacity_decision_path=COMMITTED_BUNDLE / "capacity-decision.json",
            bank_card_path=COMMITTED_BUNDLE / "bank-card.json",
            inventory_dir=inventories,
        )


def test_committed_bundle_has_no_direct_identifier_or_private_path_bytes() -> None:
    files = {
        path.relative_to(COMMITTED_BUNDLE).as_posix(): path.read_bytes()
        for path in COMMITTED_BUNDLE.rglob("*")
        if path.is_file()
    }

    publication._privacy_scan(files)


def test_sealed_measurement_inputs_remain_byte_identical() -> None:
    actual = {
        relative_path: hashlib.sha256((COMMITTED_BUNDLE / relative_path).read_bytes()).hexdigest()
        for relative_path in FROZEN_INPUT_SHA256
    }

    assert actual == FROZEN_INPUT_SHA256


def test_public_claims_are_pinned_to_committed_evidence() -> None:
    root = REPOSITORY_ROOT
    expected = {
        "README.md": ("39,604", "13,201", "1,210", "142/146", "146/1,393", "143,057"),
        "docs/index.md": ("39,604", "13,201", "1,210", "142/146", "146/1,393"),
        "docs/enron-evidence.md": (
            "39,604",
            "13,201",
            "1,210",
            "142/146",
            "146/1,393",
            "1,247",
            "10.19%",
            "21.34%",
            "89.86%",
            "143,057",
        ),
        "docs/performance.md": (
            "39,604",
            "0.699 ms",
            "143,057",
            "9.021 µs",
            "55.250 µs",
            "7.792 s",
            "6,811",
        ),
    }

    for relative_path, claims in expected.items():
        text = (root / relative_path).read_text(encoding="utf-8")
        for claim in claims:
            assert claim in text, f"{relative_path} is missing frozen claim {claim}"

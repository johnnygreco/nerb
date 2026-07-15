from __future__ import annotations

import copy
import json
import shutil
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


def _copy_bundle(tmp_path: Path) -> Path:
    target = tmp_path / "bundle"
    shutil.copytree(COMMITTED_BUNDLE, target)
    return target


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


def test_committed_publication_verifies_as_terminal_do_not_ship_evidence() -> None:
    result = verify_enron_publication(COMMITTED_BUNDLE)

    assert result["valid"] is True
    assert result["artifacts_verified"] == 17
    assert result["decision"] == {
        "audit_status": "quality_gates_failed",
        "bank_release_eligible": False,
        "capacity_gates_passed": True,
        "package_release_allowed": False,
        "performance_decision_grade": True,
        "quality_gates_passed": False,
        "release": "do_not_ship",
    }
    assert result["privacy"]["violation_count"] == 0


def test_quality_eligibility_is_separate_from_evidence_validity(fast_capacity) -> None:
    assert verify_enron_publication(COMMITTED_BUNDLE)["valid"] is True

    with pytest.raises(EnronPublicationError, match="not quality-eligible") as raised:
        verify_enron_publication(COMMITTED_BUNDLE, require_quality_eligible=True)

    assert raised.value.code == "enron_quality_ineligible"


@pytest.mark.parametrize(
    "relative_path",
    [
        "benchmark-evidence.json",
        "bank-card.json",
        "inventories/real_validation_inventory.json",
        "summary.md",
        "figures/quality-recall.svg",
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
    (missing / "figures" / "leakage.svg").unlink()
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


def test_publication_rejects_rehashed_release_overstatement(tmp_path: Path, fast_capacity) -> None:
    bundle = _copy_bundle(tmp_path)
    manifest_path = bundle / "publication.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["decision"]["package_release_allowed"] = True
    manifest["publication_sha256"] = publication._canonical_hash(publication._without(manifest, "publication_sha256"))
    manifest_path.write_bytes(publication._pretty_json_bytes(manifest))

    with pytest.raises(EnronPublicationError, match="does not match"):
        verify_enron_publication(bundle)


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
        "figures/leakage.svg",
        "figures/performance-scale.svg",
        "figures/quality-recall.svg",
        "summary.md",
    ]
    for path in first.rglob("*"):
        if path.is_file():
            counterpart = second / path.relative_to(first)
            assert path.read_bytes() == counterpart.read_bytes()
            assert path.read_bytes() == (COMMITTED_BUNDLE / path.relative_to(first)).read_bytes()


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
    assert result["decision"]["release"] == "do_not_ship"
    assert result["decision"]["package_release_allowed"] is False
    publication_manifest = json.loads((output / "publication.json").read_text(encoding="utf-8"))
    assert publication_manifest["scope"]["gold_sample_documents"] is None
    assert publication_manifest["scope"]["gold_spans"] is None
    summary = (output / "summary.md").read_text(encoding="utf-8")
    assert "insufficient independent support" in summary
    assert "rates and miss counts are intentionally shown as unavailable" in summary
    rendered = tmp_path / "rendered"
    render_result = render_enron_publication(output, rendered)
    assert render_result["source_publication_sha256"] == publication_manifest["publication_sha256"]
    assert (rendered / "figures" / "quality-recall.svg").read_bytes() == (
        output / "figures" / "quality-recall.svg"
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


def test_public_claims_are_pinned_to_committed_evidence() -> None:
    root = REPOSITORY_ROOT
    expected = {
        "README.md": ("10.19%", "21.34%", "89.86%", "143,057"),
        "docs/index.md": ("10.19%", "21.34%", "89.86%"),
        "docs/enron-evidence.md": ("10.19%", "21.34%", "89.86%", "1,251", "1,393", "143,057"),
        "docs/performance.md": ("0.699 ms", "143,057", "9.021 µs", "55.250 µs", "7.792 s", "6,811"),
    }

    for relative_path, claims in expected.items():
        text = (root / relative_path).read_text(encoding="utf-8")
        for claim in claims:
            assert claim in text, f"{relative_path} is missing frozen claim {claim}"

from __future__ import annotations

from pathlib import Path
from typing import Any

from nerb.engines import compile_bank
from nerb.enron_bank_builder import (
    ITERATION_POLICIES,
    CandidateEvidence,
    CandidatePool,
    EnronBankPolicy,
    curate_enron_iteration,
    mine_enron_candidates,
)
from nerb.enron_bank_workflow import _qualified_validation_gold
from nerb.validation import validate_bank


def _sender_record(
    index: int,
    *,
    address: str,
    current_body: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    document_id = f"doc_{index:064x}"
    return (
        {
            "document_id": document_id,
            "date": {"utc": f"2001-01-{index:02d}T00:00:00Z"},
            "headers": {
                "from": [{"name": "", "address": address}],
                "to": [],
                "cc": [],
                "bcc": [],
            },
            "views": {"current_body": current_body},
        },
        {
            "document_id": document_id,
            "group_id": f"sha256:{index:064x}",
            "role": "train",
        },
    )


def _display_name_record(index: int, *, name: str, address: str) -> tuple[dict[str, Any], dict[str, Any]]:
    document_id = f"doc_{index:064x}"
    return (
        {
            "document_id": document_id,
            "date": {"utc": f"2001-02-{index:02d}T00:00:00Z"},
            "headers": {
                "from": [{"name": name, "address": address}],
                "to": [],
                "cc": [],
                "bcc": [],
            },
            "views": {"current_body": "Synthetic fixture body."},
        },
        {
            "document_id": document_id,
            "group_id": f"sha256:{index + 100:064x}",
            "role": "train",
        },
    )


def test_sender_body_alias_requires_observed_full_name_and_distinct_group_support(tmp_path: Path) -> None:
    rows = [
        _sender_record(
            1,
            address="alice.alpha@example.invalid",
            current_body="Please review the attached report.\n\nAlice Alpha",
        ),
        _sender_record(
            2,
            address="alice.alpha@example.invalid",
            current_body="Thank you for the update.\n\nAlice   Alpha",
        ),
        _sender_record(
            3,
            address="carol.gamma@example.invalid",
            current_body="The local-part-derived name is not present in this message.",
        ),
        _sender_record(
            4,
            address="carol.gamma@example.invalid",
            current_body="Regards,\nOperations Team",
        ),
    ]
    spool = tmp_path / "sender-body.sqlite3"
    spool.touch()

    pool = mine_enron_candidates(
        rows,
        sqlite_path=spool,
        train_artifact_sha256="sha256:" + "a" * 64,
        policy=EnronBankPolicy(),
    )

    assert [item.normalized_value for item in pool.person_aliases] == ["alice alpha"]
    alias = pool.person_aliases[0]
    assert alias.related_values == ("alice.alpha@example.invalid",)
    assert alias.leakage_group_count == 2
    assert alias.source_types == (("sender_body_local_link", 2),)
    assert alias.surfaces == (("Alice Alpha", 2),)

    curated = curate_enron_iteration(
        pool,
        policy=EnronBankPolicy(),
        iteration=ITERATION_POLICIES[1],
        source_binding={"fixture_mode": True},
    )
    person = next(item for item in curated.candidates if item["candidate_type"] == "person_alias")
    assert person["decision"] == "active"
    assert person["evidence"]["source_types"] == ["sender_body_local_link"]


def test_candidate_mining_is_row_order_independent(tmp_path: Path) -> None:
    rows = [
        _sender_record(
            1,
            address="alice.alpha@example.invalid",
            current_body="First source record.\nAlice Alpha",
        ),
        _sender_record(
            2,
            address="alice.alpha@example.invalid",
            current_body="Second source record.\nAlice Alpha",
        ),
    ]
    policy = EnronBankPolicy()
    source_sha256 = "sha256:" + "b" * 64
    first_spool = tmp_path / "first.sqlite3"
    second_spool = tmp_path / "second.sqlite3"
    first_spool.touch()
    second_spool.touch()

    first = mine_enron_candidates(
        rows,
        sqlite_path=first_spool,
        train_artifact_sha256=source_sha256,
        policy=policy,
    )
    second = mine_enron_candidates(
        reversed(rows),
        sqlite_path=second_spool,
        train_artifact_sha256=source_sha256,
        policy=policy,
    )

    assert first == second


def test_compatible_full_name_aliases_share_one_active_identity(tmp_path: Path) -> None:
    rows = [
        _display_name_record(1, name="Robert Smith", address="rsmith@example.invalid"),
        _display_name_record(2, name="Robert Smith", address="rsmith@example.invalid"),
        _display_name_record(3, name="Rob Smith", address="rsmith@example.invalid"),
        _display_name_record(4, name="Rob Smith", address="rsmith@example.invalid"),
    ]
    spool = tmp_path / "aliases.sqlite3"
    spool.touch()
    policy = EnronBankPolicy()
    pool = mine_enron_candidates(
        rows,
        sqlite_path=spool,
        train_artifact_sha256="sha256:" + "c" * 64,
        policy=policy,
    )
    curated = curate_enron_iteration(
        pool,
        policy=policy,
        iteration=ITERATION_POLICIES[1],
        source_binding={"fixture_mode": True},
    )

    people = [item for item in curated.candidates if item["candidate_type"] == "person_alias"]
    assert len(people) == 2
    assert {item["decision"] for item in people} == {"active"}
    assert len({item["bank_ref"]["name_id"] for item in people}) == 1


def test_person_draft_capacity_is_enforced_per_alias_pattern(tmp_path: Path) -> None:
    rows = [
        _display_name_record(1, name="Robert Smith", address="rsmith@example.invalid"),
        _display_name_record(2, name="Rob Smith", address="rsmith@example.invalid"),
        _display_name_record(3, name="R Smith", address="rsmith@example.invalid"),
    ]
    spool = tmp_path / "draft-cap.sqlite3"
    spool.touch()
    policy = EnronBankPolicy(max_draft_per_class=1)
    pool = mine_enron_candidates(
        rows,
        sqlite_path=spool,
        train_artifact_sha256="sha256:" + "d" * 64,
        policy=policy,
    )
    curated = curate_enron_iteration(
        pool,
        policy=policy,
        iteration=ITERATION_POLICIES[1],
        source_binding={"fixture_mode": True},
    )

    people = [item for item in curated.candidates if item["candidate_type"] == "person_alias"]
    assert len(people) == 3
    assert sum(item["decision"] == "draft" for item in people) == 1
    assert sum(item["decision"] == "rejected" for item in people) == 2
    person_patterns = sum(
        len(item["patterns"])
        for item in curated.bank["entities"]["person"]["names"].values()
        if item["status"] == "draft"
    )
    assert person_patterns == 1


def test_unknown_email_fallback_detects_span_without_claiming_catalog_identity(tmp_path: Path) -> None:
    rows = [
        _display_name_record(1, name="Robert Smith", address="rsmith@example.invalid"),
        _display_name_record(2, name="Robert Smith", address="rsmith@example.invalid"),
    ]
    spool = tmp_path / "catalog-semantics.sqlite3"
    spool.touch()
    policy = EnronBankPolicy()
    pool = mine_enron_candidates(
        rows,
        sqlite_path=spool,
        train_artifact_sha256="sha256:" + "e" * 64,
        policy=policy,
    )
    curated = curate_enron_iteration(
        pool,
        policy=policy,
        iteration=ITERATION_POLICIES[1],
        source_binding={"fixture_mode": True},
    )
    spans = (
        {
            "document_id": "fixture_document",
            "entity_class": "contact",
            "start": 0,
            "end": len("rsmith@example.invalid"),
            "surface": "rsmith@example.invalid",
        },
        {
            "document_id": "fixture_document",
            "entity_class": "contact",
            "start": 24,
            "end": 24 + len("novel.person@example.invalid"),
            "surface": "novel.person@example.invalid",
        },
    )

    gold = _qualified_validation_gold(curated.bank, spans)
    assert gold[0]["catalog_identity"] is not None
    assert gold[1]["catalog_identity"] is None

    compiled, _cache_hit = compile_bank(curated.bank, options={"include_statuses": ["active"]})
    novel = list(compiled.finditer("novel.person@example.invalid"))
    assert len(novel) == 1
    assert novel[0]["name_id"] == "unknown_email_contact"


def test_active_identity_canonical_uses_an_active_alias_not_higher_support_draft(tmp_path: Path) -> None:
    rows = [
        _display_name_record(1, name="Alice Jones", address="rsmith@example.invalid"),
        _display_name_record(2, name="Alice Jones", address="rsmith@example.invalid"),
        _display_name_record(3, name="Alice Jones", address="rsmith@example.invalid"),
        _display_name_record(4, name="Robert Smith", address="rsmith@example.invalid"),
        _display_name_record(5, name="Robert Smith", address="rsmith@example.invalid"),
    ]
    spool = tmp_path / "active-canonical.sqlite3"
    spool.touch()
    policy = EnronBankPolicy()
    pool = mine_enron_candidates(
        rows,
        sqlite_path=spool,
        train_artifact_sha256="sha256:" + "f" * 64,
        policy=policy,
    )
    curated = curate_enron_iteration(
        pool,
        policy=policy,
        iteration=ITERATION_POLICIES[1],
        source_binding={"fixture_mode": True},
    )

    active_name = next(
        item for item in curated.bank["entities"]["person"]["names"].values() if item["status"] == "active"
    )
    assert active_name["canonical"] == "Robert Smith"
    assert active_name["metadata"]["evidence_scope"] == "canonical_alias_only"
    assert active_name["metadata"]["observation_count"] == 2
    assert active_name["metadata"]["identity_aggregate_counts_supported"] is False


def test_recurring_nickname_is_activated_through_a_local_compatible_anchor(tmp_path: Path) -> None:
    rows = [
        _display_name_record(1, name="Maribel Quill", address="maribel.quill@example.invalid"),
        _display_name_record(2, name="Maribel Quill", address="maribel.quill@example.invalid"),
        _display_name_record(3, name="Mari Quill", address="maribel.quill@example.invalid"),
        _display_name_record(4, name="Mari Quill", address="maribel.quill@example.invalid"),
    ]
    spool = tmp_path / "nickname.sqlite3"
    spool.touch()
    policy = EnronBankPolicy()
    pool = mine_enron_candidates(
        rows,
        sqlite_path=spool,
        train_artifact_sha256="sha256:" + "1" * 64,
        policy=policy,
    )
    curated = curate_enron_iteration(
        pool,
        policy=policy,
        iteration=ITERATION_POLICIES[1],
        source_binding={"fixture_mode": True},
    )

    aliases = [item for item in curated.candidates if item["candidate_type"] == "person_alias"]
    assert {item["normalized_value"] for item in aliases} == {"mari quill", "maribel quill"}
    assert {item["decision"] for item in aliases} == {"active"}
    assert len({item["bank_ref"]["name_id"] for item in aliases}) == 1


def test_default_policy_bounds_large_contact_pool_and_keeps_selected_bank_compilable() -> None:
    policy = EnronBankPolicy()
    contacts = tuple(
        CandidateEvidence(
            kind="contact",
            normalized_value=f"fixture{index:05d}@example.invalid",
            surfaces=((f"fixture{index:05d}@example.invalid", 2),),
            related_counts=(),
            source_types=(("structured_header", 2),),
            observation_count=2,
            document_count=2,
            leakage_group_count=2,
            first_seen="2001-01-01T00:00:00Z",
            last_seen="2001-01-02T00:00:00Z",
            unknown_date_documents=0,
            evidence_sha256=f"sha256:{index:064x}",
        )
        for index in range(5_000)
    )
    pool = CandidatePool(
        contacts=contacts,
        person_aliases=(),
        organization_domains=(),
        train_records=10_000,
        observations=10_000,
        source_sha256="sha256:" + "2" * 64,
        ledger_sha256="sha256:" + "3" * 64,
    )

    curated = curate_enron_iteration(
        pool,
        policy=policy,
        iteration=ITERATION_POLICIES[1],
        source_binding={"fixture_mode": True},
    )

    contacts_funnel = curated.funnel["by_type"]["contact"]
    assert contacts_funnel == {"total": 5_000, "active": 500, "draft": 2_000, "rejected": 2_500}
    structural = validate_bank(curated.bank, level="deep", strict=True, check_engine_compile=True)
    assert structural["valid"] is True
    assert structural["engine_compatibility"]["compatible"] is True

    aggregate_only = curate_enron_iteration(
        pool,
        policy=policy,
        iteration=ITERATION_POLICIES[1],
        source_binding={"fixture_mode": True},
        retain_candidate_ledger=False,
    )
    assert aggregate_only.candidates == ()
    assert aggregate_only.funnel == curated.funnel
    assert aggregate_only.bank == curated.bank
    assert aggregate_only.collisions == curated.collisions


def test_match_distinct_person_surfaces_do_not_pool_recurrence_support(tmp_path: Path) -> None:
    rows = [
        _display_name_record(1, name="Fable Rowan", address="fable.rowan@example.invalid"),
        _display_name_record(2, name="Rowan, Fable", address="fable.rowan@example.invalid"),
    ]
    spool = tmp_path / "surface-support.sqlite3"
    spool.touch()
    policy = EnronBankPolicy()
    pool = mine_enron_candidates(
        rows,
        sqlite_path=spool,
        train_artifact_sha256="sha256:" + "2" * 64,
        policy=policy,
    )

    assert {item.normalized_value for item in pool.person_aliases} == {"fable rowan", "rowan, fable"}
    assert {item.leakage_group_count for item in pool.person_aliases} == {1}

    curated = curate_enron_iteration(
        pool,
        policy=policy,
        iteration=ITERATION_POLICIES[1],
        source_binding={"fixture_mode": True},
    )
    aliases = [item for item in curated.candidates if item["candidate_type"] == "person_alias"]
    assert {item["decision"] for item in aliases} == {"draft"}
    assert {item["primary_reason_code"] for item in aliases} == {"insufficient_distinct_group_support"}


def test_reordered_person_surfaces_with_independent_support_share_one_identity(tmp_path: Path) -> None:
    rows = [
        _display_name_record(1, name="Fable Rowan", address="fable.rowan@example.invalid"),
        _display_name_record(2, name="Fable Rowan", address="fable.rowan@example.invalid"),
        _display_name_record(3, name="Rowan, Fable", address="fable.rowan@example.invalid"),
        _display_name_record(4, name="Rowan, Fable", address="fable.rowan@example.invalid"),
    ]
    spool = tmp_path / "reordered-surfaces.sqlite3"
    spool.touch()
    policy = EnronBankPolicy()
    pool = mine_enron_candidates(
        rows,
        sqlite_path=spool,
        train_artifact_sha256="sha256:" + "3" * 64,
        policy=policy,
    )
    curated = curate_enron_iteration(
        pool,
        policy=policy,
        iteration=ITERATION_POLICIES[1],
        source_binding={"fixture_mode": True},
    )

    aliases = [item for item in curated.candidates if item["candidate_type"] == "person_alias"]
    assert {item["normalized_value"] for item in aliases} == {"fable rowan", "rowan, fable"}
    assert {item["decision"] for item in aliases} == {"active"}
    assert len({item["bank_ref"]["name_id"] for item in aliases}) == 1

    compiled, _cache_hit = compile_bank(curated.bank, options={"include_statuses": ["active"]})
    for surface in ("Fable Rowan", "Rowan, Fable"):
        matches = [item for item in compiled.finditer(surface) if item["entity_id"] == "person"]
        assert len(matches) == 1
        assert matches[0]["name_id"] == aliases[0]["bank_ref"]["name_id"]


def test_person_catalog_binding_uses_match_surface_semantics_without_reordering(tmp_path: Path) -> None:
    rows = [
        _display_name_record(1, name="Fable Rowan", address="fable.rowan@example.invalid"),
        _display_name_record(2, name="Fable Rowan", address="fable.rowan@example.invalid"),
    ]
    spool = tmp_path / "catalog-surface.sqlite3"
    spool.touch()
    policy = EnronBankPolicy()
    pool = mine_enron_candidates(
        rows,
        sqlite_path=spool,
        train_artifact_sha256="sha256:" + "4" * 64,
        policy=policy,
    )
    curated = curate_enron_iteration(
        pool,
        policy=policy,
        iteration=ITERATION_POLICIES[1],
        source_binding={"fixture_mode": True},
    )
    spans = (
        {
            "document_id": "fixture_document",
            "entity_class": "person",
            "start": 0,
            "end": len("fable   rowan"),
            "surface": "fable   rowan",
        },
        {
            "document_id": "fixture_document",
            "entity_class": "person",
            "start": 20,
            "end": 20 + len("Rowan, Fable"),
            "surface": "Rowan, Fable",
        },
    )

    gold = _qualified_validation_gold(curated.bank, spans)

    assert gold[0]["catalog_identity"] is not None
    assert gold[1]["catalog_identity"] is None


def test_person_candidates_are_rejected_when_contact_anchor_is_not_retained(tmp_path: Path) -> None:
    rows = [
        *(_display_name_record(index, name="Fixture Sender", address="a@example.invalid") for index in (1, 2, 3)),
        *(_display_name_record(index, name="Sample Writer", address="b@example.invalid") for index in (4, 5, 6)),
    ]
    for index in (7, 8):
        record, membership = _display_name_record(
            index,
            name="Fable Rowan",
            address="fable.rowan@example.invalid",
        )
        record["headers"]["to"] = [{"name": "Fae Rowan", "address": "fable.rowan@example.invalid"}]
        rows.append((record, membership))
    spool = tmp_path / "contact-anchor.sqlite3"
    spool.touch()
    policy = EnronBankPolicy(
        max_active_contacts=1,
        max_draft_per_class=1,
        max_active_people=5,
        max_active_person_aliases=5,
    )
    pool = mine_enron_candidates(
        rows,
        sqlite_path=spool,
        train_artifact_sha256="sha256:" + "5" * 64,
        policy=policy,
    )
    curated = curate_enron_iteration(
        pool,
        policy=policy,
        iteration=ITERATION_POLICIES[1],
        source_binding={"fixture_mode": True},
    )

    anchor_aliases = [
        item
        for item in curated.candidates
        if item["candidate_type"] == "person_alias" and item["normalized_value"] in {"fable rowan", "fae rowan"}
    ]
    assert len(anchor_aliases) == 2
    assert {item["decision"] for item in anchor_aliases} == {"rejected"}
    assert {item["primary_reason_code"] for item in anchor_aliases} == {"contact_anchor_not_retained"}

    contact_names = curated.bank["entities"]["contact"]["names"]
    for person_name in curated.bank["entities"]["person"]["names"].values():
        if person_name["status"] == "active":
            assert person_name["metadata"]["contact_ref"] in contact_names

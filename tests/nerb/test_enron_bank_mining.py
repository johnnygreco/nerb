from __future__ import annotations

from pathlib import Path
from typing import Any

from nerb.engines import compile_bank
from nerb.enron_bank_builder import (
    ITERATION_POLICIES,
    EnronBankPolicy,
    curate_enron_iteration,
    mine_enron_candidates,
)
from nerb.enron_bank_workflow import _qualified_validation_gold


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
        _display_name_record(1, name="Kenneth Lay", address="kenneth.lay@example.invalid"),
        _display_name_record(2, name="Kenneth Lay", address="kenneth.lay@example.invalid"),
        _display_name_record(3, name="Ken Lay", address="kenneth.lay@example.invalid"),
        _display_name_record(4, name="Ken Lay", address="kenneth.lay@example.invalid"),
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
    assert {item["normalized_value"] for item in aliases} == {"ken lay", "kenneth lay"}
    assert {item["decision"] for item in aliases} == {"active"}
    assert len({item["bank_ref"]["name_id"] for item in aliases}) == 1

from __future__ import annotations

import copy
import json
import os
import stat
from multiprocessing import get_context
from queue import Empty
from typing import Any

import pytest

from nerb.diagnostics import ID_INVALID, JSON_PARSE, METADATA_TOO_LARGE, SCHEMA_REQUIRED
from nerb.replacements import (
    MAX_REPLACEMENT_DB_BYTES,
    ReplacementDbLoadError,
    ReplacementDbSaveError,
    ReplacementDbSchemaError,
    canonicalize_replacement_db,
    create_replacement_db,
    hash_replacement_db,
    load_replacement_db,
    save_replacement_db,
    validate_replacement_db,
)
from nerb.replacements_schema import REPLACEMENT_DB_SCHEMA_VERSION, validate_replacement_db_schema


def _assignment_key(entity_id: str = "person", scope: str = "name", fill: str = "a") -> str:
    return f"{entity_id}|{scope}|sha256:{fill * 64}"


def _fingerprint(fill: str = "b") -> str:
    return f"sha256:{fill * 64}"


def _redaction_assignment(*, key: str | None = None, entity_id: str = "person", token: str = "[PERSON_0001]"):
    assignment_key = key or _assignment_key(entity_id=entity_id)
    return {
        "assignment_key": assignment_key,
        "entity_id": entity_id,
        "identity": {"scope": "name", "fingerprint": _fingerprint()},
        "replacement": {"mode": "redact", "value": token},
        "redaction": {"token": token, "ordinal": 1},
        "created_at": "2026-06-12T00:00:00Z",
        "updated_at": "2026-06-12T00:00:00Z",
        "use_count": 1,
        "metadata": {},
    }


def _pseudonym_db() -> dict:
    db = create_replacement_db(reversible=True, now="2026-06-12T00:00:00Z")
    db["replacement_sets"]["person_names"] = {
        "description": "Reserved fake person names.",
        "reuse": False,
        "candidates": [
            {"id": "person_name_0001", "value": "Mikey Law", "metadata": {}},
            {"id": "person_name_0002", "value": "Nina Vale", "metadata": {}},
        ],
    }
    db["entities"]["person"] = {
        "replacement_mode": "pseudonym",
        "replacement_set_id": "person_names",
        "store_originals": True,
    }
    db["assignments"][_assignment_key()] = {
        "assignment_key": _assignment_key(),
        "entity_id": "person",
        "identity": {
            "scope": "name",
            "name_id": "john_smith",
            "canonical_name": "John Smith",
            "fingerprint": _fingerprint(),
        },
        "original": {"canonical": "John Smith", "surfaces": ["John Smith"]},
        "replacement": {
            "mode": "pseudonym",
            "value": "Mikey Law",
            "set_id": "person_names",
            "candidate_id": "person_name_0001",
        },
        "redaction": {"token": "[PERSON_0001]", "ordinal": 1},
        "created_at": "2026-06-12T00:00:00Z",
        "updated_at": "2026-06-12T00:00:00Z",
        "use_count": 1,
        "metadata": {},
    }
    return db


def _save_with_expected(path: str, replacement_db: dict, expected_hash: str, description: str, queue: Any) -> None:
    from nerb.replacements import ReplacementDbSaveError, load_replacement_db, save_replacement_db

    candidate = copy.deepcopy(replacement_db)
    candidate["description"] = description
    candidate["version"] += 1
    try:
        save_replacement_db(candidate, path, expected_hash=expected_hash)
    except ReplacementDbSaveError as exc:
        queue.put(("error", [item["code"] for item in exc.diagnostics]))
    else:
        queue.put(("ok", load_replacement_db(path)["description"]))


def test_create_replacement_db_defaults_to_non_reversible_redaction():
    db = create_replacement_db(now="2026-06-12T00:00:00Z")

    assert db == {
        "schema_version": REPLACEMENT_DB_SCHEMA_VERSION,
        "id": "replacements",
        "description": "",
        "version": 1,
        "created_at": "2026-06-12T00:00:00Z",
        "updated_at": "2026-06-12T00:00:00Z",
        "metadata": {},
        "defaults": {
            "unicode_normalization": "NFC",
            "assignment_scope": "name",
            "replacement_mode": "redact",
            "redaction_template": "[{ENTITY}_{ordinal:04d}]",
            "collision_policy": "error",
            "store_originals": False,
            "allow_new_assignments": True,
        },
        "entities": {},
        "replacement_sets": {},
        "assignments": {},
    }
    assert validate_replacement_db_schema(db) == {"valid": True, "diagnostics": []}
    assert validate_replacement_db(db) == {"valid": True, "diagnostics": []}


def test_create_replacement_db_can_opt_into_reversible_storage():
    db = create_replacement_db(reversible=True, now="2026-06-12T00:00:00Z")

    assert db["defaults"]["store_originals"] is True
    assert validate_replacement_db(db)["valid"] is True


def test_schema_rejects_missing_required_and_unknown_fields():
    db = create_replacement_db(now="2026-06-12T00:00:00Z")
    del db["defaults"]["assignment_scope"]
    db["unexpected"] = "nope"

    result = validate_replacement_db_schema(db)

    assert result["valid"] is False
    assert {
        (SCHEMA_REQUIRED, "/defaults/assignment_scope"),
        ("schema.additional_property", "/unexpected"),
    }.issubset({(item["code"], item["path"]) for item in result["diagnostics"]})


def test_schema_reports_invalid_structural_ids_at_field_paths():
    db = create_replacement_db(now="2026-06-12T00:00:00Z")
    db["id"] = "Replacement DB"
    db["entities"]["Bad-ID"] = {"store_originals": False}
    db["replacement_sets"]["Bad Set"] = {"description": "Names.", "reuse": False, "candidates": []}

    result = validate_replacement_db_schema(db)
    diagnostics = {(item["code"], item["path"]) for item in result["diagnostics"]}

    assert result["valid"] is False
    assert {
        (ID_INVALID, "/id"),
        (ID_INVALID, "/entities/Bad-ID"),
        (ID_INVALID, "/replacement_sets/Bad Set"),
    }.issubset(diagnostics)
    assert ("schema.pattern", "/id") not in diagnostics
    assert ("schema.pattern", "/entities") not in diagnostics
    assert ("schema.pattern", "/replacement_sets") not in diagnostics


def test_schema_rejects_non_json_metadata_and_metadata_over_hard_limit():
    db = create_replacement_db(now="2026-06-12T00:00:00Z")
    db["metadata"]["bad"] = object()
    db["replacement_sets"]["names"] = {
        "description": "Names.",
        "reuse": False,
        "candidates": [{"id": "name_1", "value": "A", "metadata": {"huge": "x" * (1024 * 1024)}}],
    }

    result = validate_replacement_db_schema(db)

    assert result["valid"] is False
    assert any(item["path"] == "/metadata/bad" for item in result["diagnostics"])
    assert (METADATA_TOO_LARGE, "/replacement_sets/names/candidates/0/metadata") in {
        (item["code"], item["path"]) for item in result["diagnostics"]
    }


def test_schema_rejects_non_string_object_keys_before_canonicalization(tmp_path):
    db = create_replacement_db(now="2026-06-12T00:00:00Z")
    db["metadata"][1] = "bad"
    db["entities"][1] = {"store_originals": False}
    db["replacement_sets"][1] = {"description": "Bad key.", "reuse": False, "candidates": []}

    result = validate_replacement_db(db)

    assert result["valid"] is False
    assert {
        ("schema.type", "/metadata"),
        ("schema.type", "/entities"),
        ("schema.type", "/replacement_sets"),
    }.issubset({(item["code"], item["path"]) for item in result["diagnostics"]})
    with pytest.raises(ReplacementDbSchemaError):
        save_replacement_db(db, tmp_path / "invalid.json")


def test_canonicalization_and_hash_are_stable_for_mapping_order_and_sensitive_to_changes():
    db = _pseudonym_db()
    reordered = {
        "assignments": db["assignments"],
        "replacement_sets": db["replacement_sets"],
        "entities": db["entities"],
        "defaults": db["defaults"],
        "metadata": db["metadata"],
        "updated_at": db["updated_at"],
        "created_at": db["created_at"],
        "version": db["version"],
        "description": db["description"],
        "id": db["id"],
        "schema_version": db["schema_version"],
    }

    assert canonicalize_replacement_db(db) == canonicalize_replacement_db(reordered)
    assert hash_replacement_db(db) == hash_replacement_db(reordered)

    changed = copy.deepcopy(db)
    changed["version"] += 1
    assert hash_replacement_db(changed) != hash_replacement_db(db)


def test_validate_replacement_db_enforces_candidate_and_policy_consistency():
    db = _pseudonym_db()
    db["replacement_sets"]["person_names"]["candidates"].append(
        {"id": "person_name_0001", "value": "Mikey Law", "metadata": {}}
    )
    db["entities"]["company"] = {"replacement_mode": "pseudonym"}
    db["assignments"][_assignment_key()]["replacement"]["value"] = "Nina Vale"

    result = validate_replacement_db(db)

    assert result["valid"] is False
    diagnostic_index = {(item["code"], item["path"]) for item in result["diagnostics"]}
    assert (
        "replacement_db.duplicate_candidate_id",
        "/replacement_sets/person_names/candidates/2/id",
    ) in diagnostic_index
    assert (
        "replacement_db.duplicate_candidate_value",
        "/replacement_sets/person_names/candidates/2/value",
    ) in diagnostic_index
    assert ("replacement_db.missing_replacement_set", "/entities/company/replacement_set_id") in diagnostic_index
    assert (
        "replacement_db.invalid_assignment_candidate",
        f"/assignments/{_assignment_key().replace('/', '~1')}/replacement/value",
    ) in diagnostic_index


def test_entity_policy_inherits_default_replacement_set():
    db = create_replacement_db(reversible=True, now="2026-06-12T00:00:00Z")
    db["defaults"]["replacement_mode"] = "pseudonym"
    db["defaults"]["replacement_set_id"] = "person_names"
    db["replacement_sets"]["person_names"] = {
        "description": "Reserved fake person names.",
        "reuse": False,
        "candidates": [{"id": "person_name_0001", "value": "Mikey Law", "metadata": {}}],
    }
    db["entities"]["person"] = {"store_originals": True}

    assert validate_replacement_db(db) == {"valid": True, "diagnostics": []}


def test_invalid_redaction_template_returns_diagnostic_instead_of_raising():
    db = create_replacement_db(now="2026-06-12T00:00:00Z")
    db["defaults"]["redaction_template"] = "{entity.nope}_{ordinal[0]}"

    result = validate_replacement_db(db)

    assert result["valid"] is False
    assert ("replacement_db.invalid_redaction_template", "/defaults/redaction_template") in {
        (item["code"], item["path"]) for item in result["diagnostics"]
    }


def test_store_originals_false_rejects_plaintext_assignment_identity_and_originals():
    db = create_replacement_db(now="2026-06-12T00:00:00Z")
    key = _assignment_key()
    db["assignments"][key] = _redaction_assignment(key=key)
    db["assignments"][key]["identity"]["name_id"] = "john_smith"
    db["assignments"][key]["identity"]["canonical_name"] = "John Smith"
    db["assignments"][key]["original"] = {"canonical": "John Smith", "surfaces": ["John Smith"]}

    result = validate_replacement_db(db)

    assert result["valid"] is False
    assert {
        ("replacement_db.sensitive_field", f"/assignments/{key}/identity/name_id"),
        ("replacement_db.sensitive_field", f"/assignments/{key}/identity/canonical_name"),
        ("replacement_db.sensitive_field", f"/assignments/{key}/original"),
    }.issubset({(item["code"], item["path"]) for item in result["diagnostics"]})


def test_store_originals_true_requires_original_data_for_reversible_assignments():
    db = create_replacement_db(reversible=True, now="2026-06-12T00:00:00Z")
    key = _assignment_key()
    db["assignments"][key] = _redaction_assignment(key=key)

    result = validate_replacement_db(db)

    assert result["valid"] is False
    assert ("replacement_db.missing_original", f"/assignments/{key}/original") in {
        (item["code"], item["path"]) for item in result["diagnostics"]
    }


def test_assignment_key_fingerprint_redaction_and_collision_rules_are_validated():
    db = create_replacement_db(now="2026-06-12T00:00:00Z")
    first_key = _assignment_key(fill="a")
    second_key = _assignment_key(fill="c")
    third_key = _assignment_key(fill="d")
    db["assignments"][first_key] = _redaction_assignment(key=first_key)
    db["assignments"][second_key] = _redaction_assignment(key=second_key)
    db["assignments"][second_key]["identity"]["fingerprint"] = "john-smith"
    db["assignments"][third_key] = _redaction_assignment(key=third_key, token="[PERSON_9999]")

    result = validate_replacement_db(db)

    assert result["valid"] is False
    diagnostic_index = {(item["code"], item["path"]) for item in result["diagnostics"]}
    assert ("replacement_db.assignment_collision", f"/assignments/{second_key}/replacement/value") in diagnostic_index
    assert ("replacement_db.assignment_collision", f"/assignments/{second_key}/redaction/token") in diagnostic_index
    assert ("replacement_db.invalid_fingerprint", f"/assignments/{second_key}/identity/fingerprint") in diagnostic_index
    assert ("replacement_db.invalid_redaction", f"/assignments/{third_key}/redaction/token") in diagnostic_index


def test_pseudonym_assignments_require_self_contained_candidate_reference():
    db = _pseudonym_db()
    key = _assignment_key()
    del db["assignments"][key]["replacement"]["set_id"]

    result = validate_replacement_db(db)

    assert result["valid"] is False
    assert ("replacement_db.invalid_assignment_candidate", f"/assignments/{key}/replacement") in {
        (item["code"], item["path"]) for item in result["diagnostics"]
    }


def test_pseudonym_assignment_redaction_tokens_are_validated_when_present():
    db = _pseudonym_db()
    key = _assignment_key(fill="c")
    second_assignment = copy.deepcopy(next(iter(db["assignments"].values())))
    second_assignment["assignment_key"] = key
    second_assignment["identity"]["name_id"] = "jane_smith"
    second_assignment["identity"]["canonical_name"] = "Jane Smith"
    second_assignment["identity"]["fingerprint"] = _fingerprint(fill="c")
    second_assignment["original"] = {"canonical": "Jane Smith", "surfaces": ["Jane Smith"]}
    second_assignment["replacement"] = {
        "mode": "pseudonym",
        "value": "Nina Vale",
        "set_id": "person_names",
        "candidate_id": "person_name_0002",
    }
    db["assignments"][key] = second_assignment

    result = validate_replacement_db(db)

    assert result["valid"] is False
    assert ("replacement_db.assignment_collision", f"/assignments/{key}/redaction/token") in {
        (item["code"], item["path"]) for item in result["diagnostics"]
    }


def test_load_replacement_db_validates_non_object_and_parse_errors(tmp_path):
    array_path = tmp_path / "array.json"
    array_path.write_text("[]", encoding="utf-8")
    with pytest.raises(ReplacementDbSchemaError) as schema_exc:
        load_replacement_db(array_path)
    assert schema_exc.value.diagnostics[0]["code"] == "schema.type"

    bad_path = tmp_path / "bad.json"
    bad_path.write_text("{", encoding="utf-8")
    with pytest.raises(ReplacementDbLoadError) as load_exc:
        load_replacement_db(bad_path)
    assert load_exc.value.diagnostics[0]["code"] == JSON_PARSE


def test_load_replacement_db_rejects_remote_like_paths_and_large_files(tmp_path):
    with pytest.raises(ReplacementDbLoadError, match="path must be local"):
        load_replacement_db("https://example.com/replacements.json")

    large_path = tmp_path / "large.json"
    large_path.write_text(" " * (10 * 1024 * 1024 + 1), encoding="utf-8")
    with pytest.raises(ReplacementDbLoadError) as exc_info:
        load_replacement_db(large_path)
    assert exc_info.value.diagnostics[0]["code"] == "replacement_db.too_large"


def test_save_replacement_db_atomically_writes_canonical_json_with_owner_only_permissions(tmp_path):
    db = _pseudonym_db()
    path = tmp_path / "replacements.json"

    saved_path = save_replacement_db(db, path)

    assert saved_path == path
    assert load_replacement_db(path) == canonicalize_replacement_db(db)
    assert json.loads(path.read_text(encoding="utf-8")) == canonicalize_replacement_db(db)
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_save_replacement_db_keeps_existing_file_when_candidate_is_invalid(tmp_path):
    path = save_replacement_db(create_replacement_db(now="2026-06-12T00:00:00Z"), tmp_path / "replacements.json")
    original_hash = hash_replacement_db(load_replacement_db(path))
    invalid_db = create_replacement_db(now="2026-06-12T00:00:00Z")
    invalid_db["assignments"][_assignment_key()] = _redaction_assignment()
    invalid_db["assignments"][_assignment_key()]["identity"]["name_id"] = "john_smith"

    with pytest.raises(ReplacementDbSchemaError):
        save_replacement_db(invalid_db, path)

    assert hash_replacement_db(load_replacement_db(path)) == original_hash
    assert list(tmp_path.glob(".replacements.json.*.tmp")) == []


def test_save_replacement_db_refuses_changed_overwrite_without_version_increment(tmp_path):
    path = save_replacement_db(create_replacement_db(now="2026-06-12T00:00:00Z"), tmp_path / "replacements.json")
    loaded = load_replacement_db(path)
    changed = copy.deepcopy(loaded)
    changed["description"] = "changed"

    with pytest.raises(ReplacementDbSaveError) as exc_info:
        save_replacement_db(changed, path)

    assert exc_info.value.diagnostics[0]["code"] == "replacement_db.version_not_incremented"
    assert load_replacement_db(path)["description"] == ""

    changed["version"] += 1
    save_replacement_db(changed, path)
    second_change = load_replacement_db(path)
    second_change["description"] = "changed again"
    with pytest.raises(ReplacementDbSaveError) as second_exc:
        save_replacement_db(second_change, path, expected_version=2)

    assert second_exc.value.diagnostics[0]["code"] == "replacement_db.version_not_incremented"
    assert load_replacement_db(path)["description"] == "changed"


def test_save_replacement_db_refuses_stale_expected_hash_and_version(tmp_path):
    db = create_replacement_db(now="2026-06-12T00:00:00Z")
    path = save_replacement_db(db, tmp_path / "replacements.json")
    loaded = load_replacement_db(path)
    expected_hash = hash_replacement_db(loaded)

    updated = copy.deepcopy(loaded)
    updated["description"] = "new description"
    updated["version"] += 1
    save_replacement_db(updated, path, expected_hash=expected_hash, expected_version=1)

    with pytest.raises(ReplacementDbSaveError) as hash_exc:
        save_replacement_db(loaded, path, expected_hash=expected_hash)
    assert hash_exc.value.diagnostics[0]["code"] == "replacement_db.stale_write"

    with pytest.raises(ReplacementDbSaveError) as version_exc:
        save_replacement_db(loaded, path, expected_version=1)
    assert version_exc.value.diagnostics[0]["path"] == "/version"


def test_save_replacement_db_refuses_candidate_larger_than_load_limit(tmp_path):
    candidate_count = (MAX_REPLACEMENT_DB_BYTES // 10_000) + 20
    db = create_replacement_db(now="2026-06-12T00:00:00Z")
    db["replacement_sets"]["huge_set"] = {
        "description": "Large but schema-valid candidate pool.",
        "reuse": False,
        "candidates": [
            {"id": f"c{index:04d}", "value": f"{index:04d}_" + "x" * 9_995, "metadata": {}}
            for index in range(candidate_count)
        ],
    }
    path = tmp_path / "oversized.json"

    with pytest.raises(ReplacementDbSaveError) as exc_info:
        save_replacement_db(db, path)

    assert exc_info.value.diagnostics[0]["code"] == "replacement_db.too_large"
    assert not path.exists()


def test_save_replacement_db_can_replace_corrupt_file_without_expected_state(tmp_path):
    path = tmp_path / "replacements.json"
    path.write_text("{", encoding="utf-8")

    save_replacement_db(create_replacement_db(now="2026-06-12T00:00:00Z"), path)

    assert load_replacement_db(path)["schema_version"] == REPLACEMENT_DB_SCHEMA_VERSION


def test_save_replacement_db_refuses_existing_directory_destination(tmp_path):
    path = tmp_path / "replacements.json"
    path.mkdir()

    with pytest.raises(ReplacementDbSaveError) as exc_info:
        save_replacement_db(create_replacement_db(now="2026-06-12T00:00:00Z"), path)

    assert exc_info.value.diagnostics[0]["code"] == "replacement_db.not_file"
    assert path.is_dir()


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="os.mkfifo is not available on this platform")
def test_save_replacement_db_refuses_existing_fifo_destination(tmp_path):
    path = tmp_path / "replacements.json"
    os.mkfifo(path)

    with pytest.raises(ReplacementDbSaveError) as exc_info:
        save_replacement_db(create_replacement_db(now="2026-06-12T00:00:00Z"), path)

    assert exc_info.value.diagnostics[0]["code"] == "replacement_db.not_file"
    assert stat.S_ISFIFO(path.lstat().st_mode)


def test_interprocess_locked_save_allows_one_writer_and_refuses_one_stale_writer(tmp_path):
    db = create_replacement_db(now="2026-06-12T00:00:00Z")
    path = save_replacement_db(db, tmp_path / "replacements.json")
    loaded = load_replacement_db(path)
    expected_hash = hash_replacement_db(loaded)

    context = get_context("spawn")
    queue = context.Queue()
    workers = [
        context.Process(target=_save_with_expected, args=(str(path), loaded, expected_hash, "writer one", queue)),
        context.Process(target=_save_with_expected, args=(str(path), loaded, expected_hash, "writer two", queue)),
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=10)

    assert all(worker.exitcode == 0 for worker in workers)
    results = [queue.get(timeout=1), queue.get(timeout=1)]
    with pytest.raises(Empty):
        queue.get(timeout=0.1)
    assert sorted(result[0] for result in results) == ["error", "ok"]
    assert ["replacement_db.stale_write"] in [result[1] for result in results if result[0] == "error"]
    assert load_replacement_db(path)["description"] in {"writer one", "writer two"}


def test_save_replacement_db_refuses_expected_state_for_missing_destination(tmp_path):
    with pytest.raises(ReplacementDbSaveError) as exc_info:
        save_replacement_db(
            create_replacement_db(now="2026-06-12T00:00:00Z"),
            tmp_path / "missing.json",
            expected_hash="sha256:" + "0" * 64,
        )

    assert exc_info.value.diagnostics[0]["code"] == "replacement_db.stale_write"


def test_save_replacement_db_rejects_nonlocal_destination():
    with pytest.raises(ReplacementDbLoadError, match="path must be local"):
        save_replacement_db(create_replacement_db(now="2026-06-12T00:00:00Z"), "file:///tmp/replacements.json")

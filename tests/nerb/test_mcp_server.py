from __future__ import annotations

import asyncio
import json
from importlib.metadata import entry_points
from pathlib import Path

import pytest
from typer.testing import CliRunner

import nerb.mcp_server as mcp_server_module
from nerb import (
    Bank,
    clear_bank_cache,
    load_config,
    save_config,
)
from nerb import (
    apply_bank_patches as apply_bank_patches_helper,
)
from nerb import (
    bank_stats as bank_stats_helper,
)
from nerb import (
    benchmark_bank as benchmark_bank_helper,
)
from nerb import (
    diff_banks as diff_banks_helper,
)
from nerb import (
    eval_bank as eval_bank_helper,
)
from nerb import (
    explain_match as explain_match_helper,
)
from nerb import (
    extract_batch as extract_batch_helper,
)
from nerb import (
    extract_file as extract_file_helper,
)
from nerb import (
    extract_report as extract_report_helper,
)
from nerb import (
    extract_report_batch as extract_report_batch_helper,
)
from nerb import (
    extract_report_file as extract_report_file_helper,
)
from nerb import (
    extract_text as extract_text_helper,
)
from nerb import (
    regress_bank as regress_bank_helper,
)
from nerb import (
    validate_bank as validate_bank_helper,
)
from nerb.cli import app
from nerb.config import DEFAULT_CONFIG_ENV_VAR
from nerb.mcp_server import (
    _ToolError as ToolError,
)
from nerb.mcp_server import (
    add_detector,
    apply_bank_patches,
    bank_stats,
    benchmark_bank,
    clear_engine_cache,
    diff_banks,
    engine_cache_info,
    eval_bank,
    explain_match,
    extract_all_entities,
    extract_batch,
    extract_entity,
    extract_file,
    extract_inline,
    extract_report,
    extract_report_batch,
    extract_text,
    list_detectors,
    load_config_tool,
    mcp,
    regress_bank,
    remove_detector,
    update_detector,
    validate_bank,
    validate_config,
)
from nerb.mcp_server import (
    anonymize_file as anonymize_file_tool,
)
from nerb.mcp_server import (
    anonymize_text as anonymize_text_tool,
)
from nerb.mcp_server import (
    create_replacement_db as create_replacement_db_tool,
)
from nerb.mcp_server import (
    deanonymize_file as deanonymize_file_tool,
)
from nerb.mcp_server import (
    deanonymize_text as deanonymize_text_tool,
)
from nerb.mcp_server import (
    save_replacement_db as save_replacement_db_tool,
)
from nerb.mcp_server import (
    validate_replacement_db as validate_replacement_db_tool,
)
from nerb.replacements import (
    create_replacement_db as create_replacement_db_helper,
)
from nerb.replacements import (
    hash_replacement_db,
    load_replacement_db,
)
from nerb.replacements import (
    save_replacement_db as save_replacement_db_helper,
)

pytest.importorskip("mcp", reason="The MCP SDK supports Python 3.10+.")


def _console_script_entry_points():
    discovered_entry_points = entry_points()
    if hasattr(discovered_entry_points, "select"):
        return discovered_entry_points.select(group="console_scripts")
    return discovered_entry_points.get("console_scripts", [])


def _load_json(path):
    with open(path, encoding="utf-8") as file:
        return json.load(file)


def _expected_config_records(config_path, text: str, entity: str | None = None):
    return Bank.from_config(load_config(config_path), selected_entity=entity).scan_text(text)


def _write_json(path, payload):
    path.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    return path


def _literal_bank_pattern(value: str, *, priority: int = 100) -> dict:
    return {
        "kind": "literal",
        "value": value,
        "description": "MCP de-anonymization fixture.",
        "status": "active",
        "priority": priority,
        "case_sensitive": True,
        "normalize_whitespace": True,
        "left_boundary": "word",
        "right_boundary": "word",
        "metadata": {},
    }


def _person_json_bank() -> dict:
    return {
        "schema_version": "nerb.bank.v1",
        "id": "people",
        "name": "People",
        "description": "People fixture.",
        "version": "2026.06.13",
        "status": "active",
        "created_at": "2026-06-13T00:00:00Z",
        "updated_at": "2026-06-13T00:00:00Z",
        "unicode_normalization": "none",
        "default_regex_flags": [],
        "entities": {
            "person": {
                "description": "Known people.",
                "status": "active",
                "regex_flags": [],
                "names": {
                    "john_smith": {
                        "canonical": "John Smith",
                        "description": "John Smith fixture.",
                        "status": "active",
                        "patterns": {"primary": _literal_bank_pattern("John Smith")},
                        "metadata": {},
                    }
                },
                "metadata": {},
            }
        },
        "metadata": {},
    }


def _replacement_assignment(
    assignment_key: str,
    *,
    canonical: str,
    token: str = "[PERSON_0001]",
) -> dict:
    fingerprint = assignment_key.split("|", 2)[2]
    return {
        "assignment_key": assignment_key,
        "entity_id": "person",
        "identity": {
            "scope": "name",
            "name_id": canonical.lower().replace(" ", "_"),
            "canonical_name": canonical,
            "fingerprint": fingerprint,
        },
        "original": {"canonical": canonical, "surfaces": [canonical]},
        "replacement": {"mode": "redact", "value": token},
        "redaction": {"token": token, "ordinal": 1},
        "created_at": "2026-06-13T00:00:00Z",
        "updated_at": "2026-06-13T00:00:00Z",
        "use_count": 1,
        "metadata": {},
    }


def test_console_script_entry_point_is_registered():
    console_scripts = _console_script_entry_points()

    assert any(
        entry_point.name == "nerb-mcp" and entry_point.value == "nerb.mcp_server:main"
        for entry_point in console_scripts
    )


def test_mcp_server_registers_expected_tools():
    tools = asyncio.run(mcp.list_tools())

    assert {tool.name for tool in tools} >= {
        "validate_config",
        "load_config",
        "engine_cache_info",
        "clear_engine_cache",
        "list_detectors",
        "add_detector",
        "update_detector",
        "remove_detector",
        "extract_entity",
        "extract_all_entities",
        "extract_inline",
        "validate_bank",
        "apply_bank_patches",
        "diff_banks",
        "bank_stats",
        "extract_text",
        "extract_file",
        "extract_batch",
        "extract_report",
        "extract_report_batch",
        "eval_bank",
        "benchmark_bank",
        "explain_match",
        "regress_bank",
        "create_replacement_db",
        "validate_replacement_db",
        "save_replacement_db",
        "anonymize_text",
        "anonymize_file",
        "deanonymize_text",
        "deanonymize_file",
    }


def test_validate_and_load_config_return_json_compatible_data(test_data_path):
    config_path = test_data_path / "music_entities.yaml"

    validation = validate_config(str(config_path))
    loaded = load_config_tool(str(config_path))

    assert validation == {"valid": True, "path": str(config_path), "entity_count": 2, "pattern_count": 15}
    assert loaded["path"] == str(config_path)
    assert loaded["entity_count"] == 2
    assert loaded["pattern_count"] == 15
    assert loaded["config"]["GENRE"]["_flags"] == "IGNORECASE"
    json.dumps(loaded)


def test_json_bank_mcp_validation_patch_diff_and_stats_match_helpers(tmp_path, test_data_path):
    bank_path = test_data_path / "minimal_bank.json"
    bank = _load_json(bank_path)

    validation = validate_bank(bank_path=str(bank_path))
    assert validation == validate_bank_helper(bank, base_path=test_data_path)

    patches = [
        {
            "op": "replace",
            "path": "/entities/customer/names/acme_corp/patterns/primary/value",
            "value": "Acme Corporation",
        }
    ]
    patch_path = _write_json(tmp_path / "patches.json", patches)
    patched = apply_bank_patches(bank_path=str(bank_path), patch_path=str(patch_path))
    assert patched == apply_bank_patches_helper(bank, patches, base_path=test_data_path)

    new_bank = json.loads(json.dumps(bank))
    new_bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]["value"] = "Acme Corporation"
    new_bank_path = _write_json(tmp_path / "new_bank.json", new_bank)
    assert diff_banks(old_bank_path=str(bank_path), new_bank_path=str(new_bank_path)) == diff_banks_helper(
        bank,
        new_bank,
    )
    assert bank_stats(bank=bank) == bank_stats_helper(bank)


def test_json_bank_mcp_extraction_and_reports_match_helpers(tmp_path, test_data_path):
    bank_path = test_data_path / "minimal_bank.json"
    bank = _load_json(bank_path)
    text = "Send this to Acme Corp today."
    document_path = tmp_path / "email.txt"
    document_path.write_bytes("Café\r\nAcme Corp today.".encode())
    documents = [{"document_id": "email_0", "file_path": str(document_path)}]

    clear_bank_cache()
    text_result = extract_text(text, bank_path=str(bank_path))
    clear_bank_cache()
    expected_text = extract_text_helper(bank, text)
    clear_bank_cache()
    file_result = extract_file(str(document_path), bank=bank)
    clear_bank_cache()
    expected_file = extract_file_helper(bank, document_path)
    clear_bank_cache()
    batch_result = extract_batch(documents, bank=bank)
    clear_bank_cache()
    expected_batch = extract_batch_helper(bank, documents)
    clear_bank_cache()
    report_result = extract_report(bank=bank, text=text)
    clear_bank_cache()
    expected_report = extract_report_helper(bank, text)
    clear_bank_cache()
    file_report_result = extract_report(bank_path=str(bank_path), file_path=str(document_path))
    clear_bank_cache()
    expected_file_report = extract_report_file_helper(bank, document_path)
    clear_bank_cache()
    report_batch_result = extract_report_batch(documents, bank=bank)
    clear_bank_cache()
    expected_report_batch = extract_report_batch_helper(bank, documents)

    assert text_result == expected_text
    assert file_result == expected_file
    assert batch_result == expected_batch
    assert report_result == expected_report
    assert file_report_result == expected_file_report
    assert report_batch_result == expected_report_batch
    assert file_result["records"][0]["start"] == 7
    assert file_result["source"]["bytes"] == 23
    assert batch_result["documents"][0]["records"][0]["start"] == 7
    assert explain_match("customer", "acme_corp", "primary", bank=bank) == explain_match_helper(
        bank,
        "customer",
        "acme_corp",
        "primary",
    )


def test_json_bank_mcp_eval_benchmark_and_regress_match_stable_helper_parts(tmp_path, test_data_path):
    bank = _load_json(test_data_path / "minimal_bank.json")
    eval_ref_path = tmp_path / "acme.jsonl"
    eval_ref_path.write_text(
        json.dumps(
            {
                "type": "positive",
                "text": "Acme Corp",
                "matches": [{"string": "Acme Corp", "start": 0, "end": 9}],
                "metadata": {},
            },
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    eval_bank_payload = json.loads(json.dumps(bank))
    eval_bank_payload["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]["eval_refs"] = [
        eval_ref_path.name
    ]
    eval_bank_path = _write_json(tmp_path / "eval_bank.json", eval_bank_payload)

    assert eval_bank(bank_path=str(eval_bank_path)) == eval_bank_helper(eval_bank_payload, base_path=tmp_path)

    benchmark = benchmark_bank(bank=bank, options={"benchmark_iterations": 1, "stress_multiplier": 2})
    expected_benchmark = benchmark_bank_helper(bank, options={"benchmark_iterations": 1, "stress_multiplier": 2})
    assert benchmark["bank"]["id"] == expected_benchmark["bank"]["id"]
    assert benchmark["options"] == expected_benchmark["options"]
    assert benchmark["summary"]["cache_hit_verified"] is True

    new_bank = json.loads(json.dumps(bank))
    new_bank["version"] = "2026.06.04"
    regression = regress_bank(
        old_bank=bank,
        new_bank=new_bank,
        options={"benchmark_iterations": 1, "stress_multiplier": 2},
    )
    expected_regression = regress_bank_helper(
        bank,
        new_bank,
        options={"benchmark_iterations": 1, "stress_multiplier": 2},
    )
    assert regression["diff"] == expected_regression["diff"]
    assert regression["gates"]["passed"] == expected_regression["gates"]["passed"]


def test_json_bank_mcp_tools_enforce_source_rules(tmp_path, test_data_path):
    bank_path = test_data_path / "minimal_bank.json"
    bank = _load_json(bank_path)
    document_path = tmp_path / "email.txt"
    document_path.write_text("Acme Corp", encoding="utf-8")

    with pytest.raises(ToolError, match="exactly one bank source"):
        validate_bank(bank=bank, bank_path=str(bank_path))

    with pytest.raises(ToolError, match="exactly one bank source"):
        validate_bank()

    with pytest.raises(ToolError, match="exactly one text source"):
        extract_report(bank=bank, text="Acme Corp", file_path=str(document_path))


def test_json_bank_mcp_invalid_bank_returns_diagnostics(tmp_path):
    invalid_bank = {"schema_version": "nerb.bank.v1"}
    invalid_bank_path = tmp_path / "invalid_bank.json"
    invalid_bank_path.write_text(json.dumps(invalid_bank), encoding="utf-8")

    validation = validate_bank(bank=invalid_bank)
    direct_extraction = extract_text("Acme Corp", bank=invalid_bank)
    extraction = extract_text("Acme Corp", bank_path=str(invalid_bank_path))

    assert validation["valid"] is False
    assert direct_extraction["valid"] is False
    assert extraction["valid"] is False
    assert validation["diagnostics"][0]["code"].startswith("schema.")
    assert direct_extraction["diagnostics"][0]["code"].startswith("schema.")
    assert extraction["diagnostics"][0]["code"].startswith("schema.")


def test_mcp_replacement_db_create_validate_and_save_are_explicit(tmp_path):
    db_path = tmp_path / "replacements.json"

    created = create_replacement_db_tool(reversible=True)
    replacement_db = created["replacement_db"]
    validation = validate_replacement_db_tool(replacement_db=replacement_db)
    saved = save_replacement_db_tool(replacement_db=replacement_db, save_db_path=str(db_path))

    assert created["saved"] is False
    assert not (tmp_path / "implicit.json").exists()
    assert validation["valid"] is True
    assert saved["saved"] is True
    assert saved["replacement_db"]["path"] == str(db_path)
    assert saved["replacement_db"]["saved"] is True
    assert load_replacement_db(db_path)["assignments"] == {}

    changed = load_replacement_db(db_path)
    changed["description"] = "changed"
    changed["version"] = 2
    unsafe_overwrite = save_replacement_db_tool(replacement_db=changed, save_db_path=str(db_path))

    assert unsafe_overwrite["valid"] is False
    assert unsafe_overwrite["diagnostics"][0]["code"] == "replacement_db.stale_write"
    assert load_replacement_db(db_path)["description"] == ""

    expected_hash = hash_replacement_db(load_replacement_db(db_path))
    safe_overwrite = save_replacement_db_tool(
        replacement_db=changed,
        save_db_path=str(db_path),
        options={"expected_hash": expected_hash, "expected_version": 1},
    )

    assert safe_overwrite["saved"] is True
    assert load_replacement_db(db_path)["description"] == "changed"


def test_mcp_anonymize_and_deanonymize_text_use_explicit_save_path(tmp_path):
    bank = _person_json_bank()
    db_path = save_replacement_db_helper(
        create_replacement_db_helper(reversible=True, now="2026-06-13T00:00:00Z"),
        tmp_path / "replacements.json",
    )

    unsaved = anonymize_text_tool(
        "John Smith joined.",
        bank=bank,
        replacement_db=load_replacement_db(db_path),
        options={"mode": "redact"},
    )
    direct_existing_save = anonymize_text_tool(
        "John Smith joined.",
        bank=bank,
        replacement_db=load_replacement_db(db_path),
        save_db_path=str(db_path),
        options={"mode": "redact", "save": True},
    )

    assert unsaved["text"] == "[PERSON_0001] joined."
    assert unsaved["replacement_db"]["modified"] is True
    assert unsaved["replacement_db"]["saved"] is False
    assert "replacement" not in unsaved["applied_replacements"][0]
    assert load_replacement_db(db_path)["assignments"] == {}
    assert direct_existing_save["valid"] is False
    assert direct_existing_save["diagnostics"][0]["code"] == "replacement_db.stale_write"

    with pytest.raises(ToolError, match="options.save requires save_db_path"):
        anonymize_text_tool(
            "John Smith joined.",
            bank=bank,
            replacement_db_path=str(db_path),
            options={"mode": "redact", "save": True},
        )

    with pytest.raises(ToolError, match="save_db_path writes require options.save"):
        anonymize_text_tool(
            "John Smith joined.",
            bank=bank,
            replacement_db_path=str(db_path),
            save_db_path=str(db_path),
            options={"mode": "redact"},
        )

    saved = anonymize_text_tool(
        "John Smith joined.",
        bank=bank,
        replacement_db_path=str(db_path),
        save_db_path=str(db_path),
        options={"mode": "redact", "save": True},
    )
    restored = deanonymize_text_tool("[PERSON_0001] joined.", replacement_db_path=str(db_path))

    assert saved["text"] == "[PERSON_0001] joined."
    assert saved["replacement_db"]["modified"] is True
    assert saved["replacement_db"]["saved"] is True
    assert saved["replacement_db"]["version"] == 2
    assert len(load_replacement_db(db_path)["assignments"]) == 1
    assert restored["schema_version"] == "nerb.deanonymize_response.v1"
    assert restored["text"] == "John Smith joined."
    assert restored["summary"]["applied_count"] == 1


def test_mcp_anonymize_and_deanonymize_file_match_helper_contracts(tmp_path):
    bank = _person_json_bank()
    db_path = save_replacement_db_helper(
        create_replacement_db_helper(reversible=True, now="2026-06-13T00:00:00Z"),
        tmp_path / "replacements.json",
    )
    document_path = tmp_path / "source.txt"
    anonymized_path = tmp_path / "anonymized.txt"
    document_path.write_bytes("Café\r\nJohn Smith joined.".encode())

    saved = anonymize_file_tool(
        str(document_path),
        bank=bank,
        replacement_db_path=str(db_path),
        save_db_path=str(db_path),
        options={"mode": "redact", "save": True},
    )
    anonymized_path.write_text(saved["text"], encoding="utf-8")
    restored = deanonymize_file_tool(str(anonymized_path), replacement_db_path=str(db_path))

    assert saved["schema_version"] == "nerb.anonymize_response.v1"
    assert saved["source"] == {
        "source_ref": "s1",
        "type": "file",
        "length": 24,
        "bytes": 25,
    }
    assert saved["text"] == "Café\r\n[PERSON_0001] joined."
    assert saved["replacement_db"]["saved"] is True
    assert restored["schema_version"] == "nerb.deanonymize_response.v1"
    assert restored["source"] == {
        "source_ref": "s1",
        "type": "file",
        "length": 27,
        "bytes": 28,
    }
    assert restored["text"] == "Café\r\nJohn Smith joined."


def test_mcp_replacement_db_diagnostics_are_sanitized_by_default(tmp_path):
    db_path = tmp_path / "replacements.json"
    first_key = f"person|name|sha256:{'a' * 64}"
    second_key = f"person|name|sha256:{'b' * 64}"
    replacement_db = create_replacement_db_helper(reversible=True, now="2026-06-13T00:00:00Z")
    replacement_db["assignments"] = {
        first_key: _replacement_assignment(first_key, canonical="John Smith"),
        second_key: _replacement_assignment(second_key, canonical="Jane Smith"),
    }
    _write_json(db_path, replacement_db)

    payload = validate_replacement_db_tool(replacement_db_path=str(db_path))
    sensitive_payload = validate_replacement_db_tool(
        replacement_db_path=str(db_path),
        options={"include_sensitive_metadata": True},
    )

    serialized = json.dumps(payload)
    assert payload["valid"] is False
    assert payload["diagnostics"][0]["path"] == "/assignments"
    assert payload["diagnostics"][0]["message"] == "Assignment diagnostic details are redacted by default."
    assert first_key not in serialized
    assert second_key not in serialized
    assert "sha256:" not in serialized
    assert "first_assignment_key" not in serialized
    assert "John Smith" not in serialized
    assert "Jane Smith" not in serialized
    assert sensitive_payload["diagnostics"][0]["metadata"]["first_assignment_key"] == first_key


def test_config_mutation_tools_write_explicit_config_path(tmp_path):
    config_path = tmp_path / "entities.yaml"

    add_result = add_detector(str(config_path), "ARTIST", "Rush", "Rush")
    assert add_result["action"] == "added"
    assert load_config(config_path) == {"ARTIST": {"Rush": "Rush"}}

    update_result = update_detector(str(config_path), "ARTIST", "Rush", r"Rush(?:\s+band)?")
    assert update_result["action"] == "updated"
    assert load_config(config_path) == {"ARTIST": {"Rush": r"Rush(?:\s+band)?"}}

    list_result = list_detectors(str(config_path))
    assert list_result["detectors"] == [{"entity": "ARTIST", "name": "Rush", "pattern": r"Rush(?:\s+band)?"}]

    remove_result = remove_detector(str(config_path), "ARTIST", "Rush")
    assert remove_result["action"] == "removed"
    assert load_config(config_path) == {}


def test_config_mutation_tools_report_duplicate_add(tmp_path):
    config_path = save_config({"ARTIST": {"Rush": "Rush"}}, tmp_path / "entities.yaml")

    with pytest.raises(ToolError) as duplicate_error:
        add_detector(str(config_path), "ARTIST", "Rush", r"Rush(?:\s+band)?")

    assert f"Could not add detector ARTIST:Rush in {config_path}" in str(duplicate_error.value)
    assert "already exists" in str(duplicate_error.value)
    assert load_config(config_path) == {"ARTIST": {"Rush": "Rush"}}


def test_extract_entity_matches_cli_and_api_for_fixture_config_and_document(test_data_path, prog_rock_wiki):
    config_path = test_data_path / "music_entities.yaml"
    document_path = test_data_path / "prog_rock_wiki.txt"
    expected_records = _expected_config_records(config_path, prog_rock_wiki, "ARTIST")

    mcp_result = extract_entity(str(config_path), "ARTIST", file_path=str(document_path))
    cli_result = CliRunner().invoke(
        app,
        ["extract", "ARTIST", str(document_path), "--config", str(config_path), "--format", "json"],
    )

    assert cli_result.exit_code == 0
    assert mcp_result["records"] == expected_records
    assert mcp_result["records"] == json.loads(cli_result.output)
    assert set(mcp_result["records"][0]) == {
        "entity",
        "canonical_name",
        "surface_name",
        "string",
        "start",
        "end",
        "offset_unit",
    }


def test_extract_all_matches_cli_and_api_for_fixture_config_and_document(test_data_path, prog_rock_wiki):
    config_path = test_data_path / "music_entities.yaml"
    document_path = test_data_path / "prog_rock_wiki.txt"
    expected_records = _expected_config_records(config_path, prog_rock_wiki)

    mcp_result = extract_all_entities(str(config_path), file_path=str(document_path))
    cli_result = CliRunner().invoke(
        app,
        ["extract", "--all", str(document_path), "--config", str(config_path), "--format", "json"],
    )

    assert cli_result.exit_code == 0
    assert mcp_result["records"] == expected_records
    assert mcp_result["records"] == json.loads(cli_result.output)


def test_mcp_config_extraction_reuses_rust_bank_cache(tmp_path):
    config_path = save_config({"ARTIST": {"Rush": "Rush"}}, tmp_path / "entities.yaml")

    clear_engine_cache()
    first = extract_entity(str(config_path), "ARTIST", text="Rush released 2112.")
    after_first = engine_cache_info()
    second = extract_entity(str(config_path), "ARTIST", text="Rush released 2112.")
    after_second = engine_cache_info()
    cleared = clear_engine_cache()

    assert first["records"] == second["records"]
    assert first["cache"]["hit"] is False
    assert second["cache"]["hit"] is True
    assert second["cache"]["key"] == first["cache"]["key"]
    assert first["cache"]["key"]["schema_version"] == 1
    assert first["cache"]["key"]["compile_options"] == {"match_mode": "entity_independent"}
    assert after_first["size"] == 1
    assert after_first["misses"] == 1
    assert after_first["hits"] == 0
    assert after_second["size"] == 1
    assert after_second["misses"] == 1
    assert after_second["hits"] == 1
    assert cleared == {
        "cleared": True,
        "cache": {
            "size": 0,
            "source_key_count": 0,
            "max_entries": 128,
            "max_source_keys": 256,
            "hits": 0,
            "misses": 0,
            "keys": [],
        },
    }


def test_extract_inline_does_not_require_or_write_config(monkeypatch, tmp_path):
    missing_default_config = tmp_path / "missing-default.yaml"
    monkeypatch.setenv(DEFAULT_CONFIG_ENV_VAR, str(missing_default_config))

    result = extract_inline(
        {"ARTIST": {"Pink Floyd": r"Pink\sFloyd"}, "GENRE": {"_flags": "IGNORECASE", "Rock": "rock"}},
        text="Pink Floyd played progressive rock.",
    )

    assert result["records"] == [
        {
            "entity": "ARTIST",
            "canonical_name": "Pink Floyd",
            "surface_name": "Pink Floyd",
            "string": "Pink Floyd",
            "start": 0,
            "end": 10,
            "offset_unit": "byte",
        },
        {
            "entity": "GENRE",
            "canonical_name": "Rock",
            "surface_name": "Rock",
            "string": "rock",
            "start": 30,
            "end": 34,
            "offset_unit": "byte",
        },
    ]
    assert not missing_default_config.exists()


def test_extract_inline_filters_entity_and_reads_document_file(tmp_path):
    document_path = tmp_path / "doc.txt"
    document_path.write_text("Rush played rock.", encoding="utf-8")

    result = extract_inline(
        {"ARTIST": {"Rush": "Rush"}, "GENRE": {"Rock": "rock"}},
        file_path=str(document_path),
        entity="GENRE",
    )

    assert result["entity"] == "GENRE"
    assert result["source"] == {"type": "file", "path": str(document_path)}
    assert result["record_count"] == 1
    assert result["records"] == [
        {
            "entity": "GENRE",
            "canonical_name": "Rock",
            "surface_name": "Rock",
            "string": "rock",
            "start": 12,
            "end": 16,
            "offset_unit": "byte",
        }
    ]


def test_mcp_file_extraction_preserves_original_utf8_byte_offsets_with_crlf(tmp_path):
    config_path = save_config({"ARTIST": {"Rush": "Rush"}}, tmp_path / "entities.yaml")
    document_path = tmp_path / "document.txt"
    document_path.write_bytes("Café\r\nRush".encode())

    result = extract_entity(str(config_path), "ARTIST", file_path=str(document_path))

    assert result["records"] == [
        {
            "entity": "ARTIST",
            "canonical_name": "Rush",
            "surface_name": "Rush",
            "string": "Rush",
            "start": 7,
            "end": 11,
            "offset_unit": "byte",
        }
    ]


def test_mcp_config_extract_rejects_oversized_file_before_read(monkeypatch, tmp_path):
    monkeypatch.setattr(mcp_server_module, "DEFAULT_MAX_TEXT_BYTES", 4)
    config_path = save_config({"ARTIST": {"Rush": "Rush"}}, tmp_path / "entities.yaml")
    document_path = tmp_path / "document.txt"
    document_path.write_text("Rush!", encoding="utf-8")

    with pytest.raises(ToolError, match="configured limit of 4 bytes"):
        extract_entity(str(config_path), "ARTIST", file_path=str(document_path))


def test_mcp_config_extract_rejects_stale_size_oversized_file(monkeypatch, tmp_path):
    monkeypatch.setattr(mcp_server_module, "DEFAULT_MAX_TEXT_BYTES", 4)
    config_path = save_config({"ARTIST": {"Rush": "Rush"}}, tmp_path / "entities.yaml")
    document_path = tmp_path / "document.txt"
    document_path.write_text("Rush!", encoding="utf-8")
    actual_mode = document_path.stat().st_mode
    original_stat = Path.stat

    class StaleStat:
        st_mode = actual_mode
        st_size = 1

    def stale_stat(self, *args, **kwargs):
        if self == document_path:
            return StaleStat()
        return original_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", stale_stat)

    with pytest.raises(ToolError, match="configured limit of 4 bytes"):
        extract_entity(str(config_path), "ARTIST", file_path=str(document_path))


def test_mcp_tools_report_invalid_config_and_regex(tmp_path):
    invalid_config_path = tmp_path / "invalid.yaml"
    invalid_config_path.write_text("ARTIST:\n  Broken: '('\n", encoding="utf-8")

    with pytest.raises(ToolError) as invalid_config_error:
        validate_config(str(invalid_config_path))

    assert f"Config is invalid at {invalid_config_path}" in str(invalid_config_error.value)
    assert "regex parse error" in str(invalid_config_error.value)

    with pytest.raises(ToolError) as invalid_regex_error:
        extract_inline({"ARTIST": {"Broken": "("}}, text="Pink Floyd")

    assert "Could not compile detectors with the Rust engine" in str(invalid_regex_error.value)
    assert "regex parse error" in str(invalid_regex_error.value)


def test_mcp_validate_config_rejects_zero_width_regex(tmp_path):
    config_path = tmp_path / "zero-width.yaml"
    config_path.write_text("ARTIST:\n  Boundary: '" + r"\b" + "'\n", encoding="utf-8")

    with pytest.raises(ToolError) as error:
        validate_config(str(config_path))

    assert f"Config is invalid at {config_path}" in str(error.value)
    assert "zero-length match" in str(error.value)


def test_mcp_config_extraction_rejects_zero_width_regex(tmp_path):
    config_path = tmp_path / "zero-width.yaml"
    config_path.write_text("ARTIST:\n  Boundary: '" + r"\b" + "'\n", encoding="utf-8")

    with pytest.raises(ToolError) as error:
        extract_entity(str(config_path), "ARTIST", text="abc")

    assert "Could not compile detectors with the Rust engine" in str(error.value)
    assert "zero-length match" in str(error.value)


def test_mcp_tools_report_invalid_inline_detector_definitions():
    with pytest.raises(ToolError) as invalid_inline_error:
        extract_inline({"ARTIST": {"_flags": "IGNORECASE"}}, text="Rush")

    assert "Inline detector definitions are invalid" in str(invalid_inline_error.value)
    assert "must define at least one pattern" in str(invalid_inline_error.value)


def test_mcp_tools_report_missing_entity_and_missing_file(tmp_path):
    config_path = save_config({"ARTIST": {"Rush": "Rush"}}, tmp_path / "entities.yaml")
    missing_document_path = tmp_path / "missing.txt"
    invalid_document_path = tmp_path / "invalid.bin"
    invalid_document_path.write_bytes(b"\xff")

    with pytest.raises(ToolError) as missing_entity_error:
        extract_entity(str(config_path), "GENRE", text="jazz")

    assert f"Entity 'GENRE' is not configured in config at {config_path}" in str(missing_entity_error.value)

    with pytest.raises(ToolError) as missing_file_error:
        extract_entity(str(config_path), "ARTIST", file_path=str(missing_document_path))

    assert f"Document file does not exist at {missing_document_path}" in str(missing_file_error.value)

    with pytest.raises(ToolError) as invalid_utf8_error:
        extract_entity(str(config_path), "ARTIST", file_path=str(invalid_document_path))

    assert f"Document file is not valid UTF-8 at {invalid_document_path}" in str(invalid_utf8_error.value)

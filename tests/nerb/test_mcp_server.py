from __future__ import annotations

import asyncio
import json
from importlib.metadata import entry_points

import pytest
from typer.testing import CliRunner

from nerb import (
    NERB,
    clear_compiled_bank_cache,
    extract_named_entities_records,
    extract_named_entity_records,
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
    diff_banks,
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

pytest.importorskip("mcp", reason="The MCP SDK supports Python 3.10+.")


def _console_script_entry_points():
    discovered_entry_points = entry_points()
    if hasattr(discovered_entry_points, "select"):
        return discovered_entry_points.select(group="console_scripts")
    return discovered_entry_points.get("console_scripts", [])


def _load_json(path):
    with open(path, encoding="utf-8") as file:
        return json.load(file)


def _write_json(path, payload):
    path.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    return path


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
    document_path.write_text(text, encoding="utf-8")
    documents = [{"document_id": "email_0", "text": text}]

    clear_compiled_bank_cache()
    text_result = extract_text(text, bank_path=str(bank_path))
    clear_compiled_bank_cache()
    expected_text = extract_text_helper(bank, text)
    clear_compiled_bank_cache()
    file_result = extract_file(str(document_path), bank=bank)
    clear_compiled_bank_cache()
    expected_file = extract_file_helper(bank, document_path)
    clear_compiled_bank_cache()
    batch_result = extract_batch(documents, bank=bank)
    clear_compiled_bank_cache()
    expected_batch = extract_batch_helper(bank, documents)
    clear_compiled_bank_cache()
    report_result = extract_report(bank=bank, text=text)
    clear_compiled_bank_cache()
    expected_report = extract_report_helper(bank, text)
    clear_compiled_bank_cache()
    file_report_result = extract_report(bank_path=str(bank_path), file_path=str(document_path))
    clear_compiled_bank_cache()
    expected_file_report = extract_report_file_helper(bank, document_path)
    clear_compiled_bank_cache()
    report_batch_result = extract_report_batch(documents, bank=bank)
    clear_compiled_bank_cache()
    expected_report_batch = extract_report_batch_helper(bank, documents)

    assert text_result == expected_text
    assert file_result == expected_file
    assert batch_result == expected_batch
    assert report_result == expected_report
    assert file_report_result == expected_file_report
    assert report_batch_result == expected_report_batch
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
    expected_records = extract_named_entity_records(NERB(config_path), "ARTIST", prog_rock_wiki)

    mcp_result = extract_entity(str(config_path), "ARTIST", file_path=str(document_path))
    cli_result = CliRunner().invoke(
        app,
        ["extract", "ARTIST", str(document_path), "--config", str(config_path), "--format", "json"],
    )

    assert cli_result.exit_code == 0
    assert mcp_result["records"] == expected_records
    assert mcp_result["records"] == json.loads(cli_result.output)
    assert set(mcp_result["records"][0]) == {"entity", "name", "string", "start", "end"}


def test_extract_all_matches_cli_and_api_for_fixture_config_and_document(test_data_path, prog_rock_wiki):
    config_path = test_data_path / "music_entities.yaml"
    document_path = test_data_path / "prog_rock_wiki.txt"
    expected_records = extract_named_entities_records(NERB(config_path), prog_rock_wiki)

    mcp_result = extract_all_entities(str(config_path), file_path=str(document_path))
    cli_result = CliRunner().invoke(
        app,
        ["extract", "--all", str(document_path), "--config", str(config_path), "--format", "json"],
    )

    assert cli_result.exit_code == 0
    assert mcp_result["records"] == expected_records
    assert mcp_result["records"] == json.loads(cli_result.output)


def test_extract_inline_does_not_require_or_write_config(monkeypatch, tmp_path):
    missing_default_config = tmp_path / "missing-default.yaml"
    monkeypatch.setenv(DEFAULT_CONFIG_ENV_VAR, str(missing_default_config))

    result = extract_inline(
        {"ARTIST": {"Pink Floyd": r"Pink\sFloyd"}, "GENRE": {"_flags": "IGNORECASE", "Rock": "rock"}},
        text="Pink Floyd played progressive rock.",
    )

    assert result["records"] == [
        {"entity": "ARTIST", "name": "Pink Floyd", "string": "Pink Floyd", "start": 0, "end": 10},
        {"entity": "GENRE", "name": "Rock", "string": "rock", "start": 30, "end": 34},
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
    assert result["records"] == [{"entity": "GENRE", "name": "Rock", "string": "rock", "start": 12, "end": 16}]


def test_mcp_tools_report_invalid_config_and_regex(tmp_path):
    invalid_config_path = tmp_path / "invalid.yaml"
    invalid_config_path.write_text("ARTIST:\n  Broken: '('\n", encoding="utf-8")

    with pytest.raises(ToolError) as invalid_config_error:
        validate_config(str(invalid_config_path))

    assert f"Could not load config at {invalid_config_path}" in str(invalid_config_error.value)
    assert "not a valid regex pattern" in str(invalid_config_error.value)

    with pytest.raises(ToolError) as invalid_regex_error:
        extract_inline({"ARTIST": {"Broken": "("}}, text="Pink Floyd")

    assert "Inline detector definitions are invalid" in str(invalid_regex_error.value)
    assert "not a valid regex pattern" in str(invalid_regex_error.value)


def test_mcp_tools_report_invalid_inline_detector_definitions():
    with pytest.raises(ToolError) as invalid_inline_error:
        extract_inline({"ARTIST": {"_flags": "IGNORECASE"}}, text="Rush")

    assert "Inline detector definitions are invalid" in str(invalid_inline_error.value)
    assert "must define at least one pattern" in str(invalid_inline_error.value)


def test_mcp_tools_report_missing_entity_and_missing_file(tmp_path):
    config_path = save_config({"ARTIST": {"Rush": "Rush"}}, tmp_path / "entities.yaml")
    missing_document_path = tmp_path / "missing.txt"

    with pytest.raises(ToolError) as missing_entity_error:
        extract_entity(str(config_path), "GENRE", text="jazz")

    assert f"Entity 'GENRE' is not configured in config at {config_path}" in str(missing_entity_error.value)

    with pytest.raises(ToolError) as missing_file_error:
        extract_entity(str(config_path), "ARTIST", file_path=str(missing_document_path))

    assert f"Document file does not exist at {missing_document_path}" in str(missing_file_error.value)

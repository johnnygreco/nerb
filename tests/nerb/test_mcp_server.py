from __future__ import annotations

import asyncio
import json
from importlib.metadata import entry_points

import pytest
from typer.testing import CliRunner

from nerb import NERB, extract_named_entities_records, extract_named_entity_records, load_config, save_config
from nerb.cli import app
from nerb.config import DEFAULT_CONFIG_ENV_VAR
from nerb.mcp_server import (
    _ToolError as ToolError,
)
from nerb.mcp_server import (
    add_detector,
    extract_all_entities,
    extract_entity,
    extract_inline,
    list_detectors,
    load_config_tool,
    mcp,
    remove_detector,
    update_detector,
    validate_config,
)

pytest.importorskip("mcp", reason="The MCP SDK supports Python 3.10+.")


def _console_script_entry_points():
    discovered_entry_points = entry_points()
    if hasattr(discovered_entry_points, "select"):
        return discovered_entry_points.select(group="console_scripts")
    return discovered_entry_points.get("console_scripts", [])


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


def test_mcp_tools_report_missing_entity_and_missing_file(tmp_path):
    config_path = save_config({"ARTIST": {"Rush": "Rush"}}, tmp_path / "entities.yaml")
    missing_document_path = tmp_path / "missing.txt"

    with pytest.raises(ToolError) as missing_entity_error:
        extract_entity(str(config_path), "GENRE", text="jazz")

    assert f"Entity 'GENRE' is not configured in config at {config_path}" in str(missing_entity_error.value)

    with pytest.raises(ToolError) as missing_file_error:
        extract_entity(str(config_path), "ARTIST", file_path=str(missing_document_path))

    assert f"Document file does not exist at {missing_document_path}" in str(missing_file_error.value)

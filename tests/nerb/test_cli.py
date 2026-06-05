from __future__ import annotations

import json
import re
from importlib.metadata import entry_points
from importlib.metadata import version as package_version
from io import BytesIO

import pytest
from click.exceptions import Exit
from typer.testing import CliRunner

from nerb import (
    NERB,
    Bank,
    apply_bank_patches,
    benchmark_bank,
    clear_compiled_bank_cache,
    diff_banks,
    eval_bank,
    load_config,
    regress_bank,
    save_config,
    validate_bank,
)
from nerb import (
    extract_file as extract_json_file,
)
from nerb import (
    extract_report as extract_json_report,
)
from nerb import (
    extract_report_file as extract_json_report_file,
)
from nerb import (
    extract_text as extract_json_text,
)
from nerb.cli import _extract_records, _read_extraction_source, app
from nerb.config import DEFAULT_CONFIG_ENV_VAR

runner = CliRunner()


class _BinaryStdin:
    def __init__(self, payload: bytes) -> None:
        self.buffer = BytesIO(payload)

    def read(self) -> str:
        return self.buffer.getvalue().decode()


def _json_records(output: str):
    return json.loads(output)


def _jsonl_records(output: str):
    return [json.loads(line) for line in output.splitlines()]


def _split_table_row(line: str) -> list[str]:
    return re.split(r" {2,}", line.strip())


def _table_records(output: str) -> list[dict[str, str]]:
    lines = [line.rstrip() for line in output.splitlines() if line.strip()]
    header, separator, *rows = lines
    columns = _split_table_row(header)
    separator_cells = _split_table_row(separator)

    assert columns == ["entity", "canonical_name", "surface_name", "string", "start", "end", "offset_unit"]
    assert len(separator_cells) == len(columns)
    assert all(set(cell) == {"-"} for cell in separator_cells)

    records = []
    for row in rows:
        values = _split_table_row(row)
        assert len(values) == len(columns)
        records.append(dict(zip(columns, values)))
    return records


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


def test_help_shows_command_structure():
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Usage:" in result.output
    for command_name in [
        "validate-bank",
        "apply-patches",
        "diff-banks",
        "extract-text",
        "extract-file",
        "extract-report",
        "eval-bank",
        "benchmark-bank",
        "regress-bank",
        "extract",
        "test",
        "compile",
        "doctor",
        "init",
        "add",
        "list",
        "show",
        "remove",
        "validate",
    ]:
        assert command_name in result.output
    assert "--config" in result.output
    assert "--version" in result.output


def test_version_prints_installed_package_version():
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.output.strip() == f"nerb {package_version('nerb')}"


def test_console_script_entry_point_is_registered():
    console_scripts = _console_script_entry_points()

    assert any(entry_point.name == "nerb" and entry_point.value == "nerb.cli:main" for entry_point in console_scripts)


def test_invalid_command_usage_returns_error():
    result = runner.invoke(app, ["add"])

    assert result.exit_code != 0
    assert "Missing argument" in result.output
    assert "ENTITY" in result.output


def test_json_bank_validate_patch_diff_and_eval_commands_match_helpers(tmp_path, test_data_path):
    bank_path = test_data_path / "minimal_bank.json"
    bank = _load_json(bank_path)

    validate_result = runner.invoke(app, ["validate-bank", "--bank", str(bank_path)])
    assert validate_result.exit_code == 0
    assert json.loads(validate_result.output) == validate_bank(bank, base_path=test_data_path)

    patches = [
        {
            "op": "replace",
            "path": "/entities/customer/names/acme_corp/patterns/primary/value",
            "value": "Acme Corporation",
        }
    ]
    patch_path = _write_json(tmp_path / "patches.json", patches)
    apply_result = runner.invoke(app, ["apply-patches", "--bank", str(bank_path), "--patch", str(patch_path)])
    assert apply_result.exit_code == 0
    assert json.loads(apply_result.output) == apply_bank_patches(bank, patches, base_path=test_data_path)

    new_bank = json.loads(json.dumps(bank))
    new_bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]["value"] = "Acme Corporation"
    new_bank_path = _write_json(tmp_path / "new_bank.json", new_bank)
    diff_result = runner.invoke(app, ["diff-banks", str(bank_path), str(new_bank_path)])
    assert diff_result.exit_code == 0
    assert json.loads(diff_result.output) == diff_banks(bank, new_bank)

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
    eval_result = runner.invoke(app, ["eval-bank", "--bank", str(eval_bank_path)])
    assert eval_result.exit_code == 0
    assert json.loads(eval_result.output) == eval_bank(eval_bank_payload, base_path=tmp_path)


def test_json_bank_apply_patches_command_allows_repairing_invalid_bank(tmp_path, test_data_path):
    bank = _load_json(test_data_path / "minimal_bank.json")
    invalid_bank = json.loads(json.dumps(bank))
    del invalid_bank["description"]
    patches = [{"op": "add", "path": "/description", "value": "Restored bank description."}]
    bank_path = _write_json(tmp_path / "invalid_bank.json", invalid_bank)
    patch_path = _write_json(tmp_path / "patches.json", patches)

    result = runner.invoke(app, ["apply-patches", "--bank", str(bank_path), "--patch", str(patch_path)])

    assert result.exit_code == 0
    assert json.loads(result.output) == apply_bank_patches(invalid_bank, patches, base_path=tmp_path)
    assert json.loads(result.output)["valid"] is True


def test_json_bank_extraction_commands_match_helpers(tmp_path, test_data_path):
    bank_path = test_data_path / "minimal_bank.json"
    bank = _load_json(bank_path)
    text = "Send this to Acme Corp today."
    document_path = tmp_path / "email.txt"
    document_path.write_text(text, encoding="utf-8")

    clear_compiled_bank_cache()
    text_result = runner.invoke(app, ["extract-text", "--bank", str(bank_path), "--text", text])
    clear_compiled_bank_cache()
    expected_text = extract_json_text(bank, text)
    clear_compiled_bank_cache()
    file_result = runner.invoke(app, ["extract-file", "--bank", str(bank_path), "--file", str(document_path)])
    clear_compiled_bank_cache()
    expected_file = extract_json_file(bank, document_path)
    clear_compiled_bank_cache()
    report_result = runner.invoke(app, ["extract-report", "--bank", str(bank_path), "--file", str(document_path)])
    clear_compiled_bank_cache()
    expected_report = extract_json_report_file(bank, document_path)

    assert text_result.exit_code == 0
    assert file_result.exit_code == 0
    assert report_result.exit_code == 0
    assert json.loads(text_result.output) == expected_text
    assert json.loads(file_result.output) == expected_file
    assert json.loads(report_result.output) == expected_report


def test_json_bank_cli_enforces_text_source_rules(tmp_path, test_data_path):
    bank_path = test_data_path / "minimal_bank.json"
    document_path = tmp_path / "email.txt"
    document_path.write_text("Acme Corp", encoding="utf-8")

    missing_source = runner.invoke(app, ["extract-text", "--bank", str(bank_path)])
    duplicate_source = runner.invoke(
        app,
        ["extract-report", "--bank", str(bank_path), "--file", str(document_path), "--text", "Acme Corp"],
    )

    assert missing_source.exit_code == 1
    assert duplicate_source.exit_code == 1
    assert "Provide exactly one text source" in missing_source.output
    assert "Provide exactly one text source" in duplicate_source.output


def test_json_bank_cli_stdin_extraction_commands_keep_text_inputs(test_data_path):
    bank_path = test_data_path / "minimal_bank.json"
    bank = _load_json(bank_path)
    text = "Send this to Acme Corp today."

    clear_compiled_bank_cache()
    text_result = runner.invoke(app, ["extract-text", "--bank", str(bank_path), "--stdin"], input=text)
    clear_compiled_bank_cache()
    expected_text = extract_json_text(bank, text)
    clear_compiled_bank_cache()
    report_result = runner.invoke(app, ["extract-report", "--bank", str(bank_path), "--stdin"], input=text)
    clear_compiled_bank_cache()

    assert text_result.exit_code == 0
    assert report_result.exit_code == 0
    assert json.loads(text_result.output) == expected_text
    assert json.loads(report_result.output) == extract_json_report(bank, text)


def test_json_bank_cli_invalid_bank_returns_diagnostics(tmp_path):
    invalid_bank_path = tmp_path / "invalid_bank.json"
    invalid_bank_path.write_text('{"schema_version":"nerb.bank.v1"}', encoding="utf-8")

    validate_result = runner.invoke(app, ["validate-bank", "--bank", str(invalid_bank_path)])
    extract_result = runner.invoke(app, ["extract-text", "--bank", str(invalid_bank_path), "--text", "Acme Corp"])

    assert validate_result.exit_code == 0
    assert extract_result.exit_code == 0
    assert json.loads(validate_result.output)["valid"] is False
    assert json.loads(extract_result.output)["valid"] is False
    assert json.loads(validate_result.output)["diagnostics"][0]["code"].startswith("schema.")


def test_json_bank_benchmark_and_regress_commands_return_json(tmp_path, test_data_path):
    bank = _load_json(test_data_path / "minimal_bank.json")
    old_bank_path = _write_json(tmp_path / "old_bank.json", bank)
    new_bank = json.loads(json.dumps(bank))
    new_bank["version"] = "2026.06.04"
    new_bank_path = _write_json(tmp_path / "new_bank.json", new_bank)

    benchmark_result = runner.invoke(
        app,
        [
            "benchmark-bank",
            "--bank",
            str(old_bank_path),
            "--benchmark-iterations",
            "1",
            "--stress-multiplier",
            "2",
        ],
    )
    regress_result = runner.invoke(
        app,
        [
            "regress-bank",
            "--old-bank",
            str(old_bank_path),
            "--new-bank",
            str(new_bank_path),
            "--benchmark-iterations",
            "1",
            "--stress-multiplier",
            "2",
        ],
    )

    assert benchmark_result.exit_code == 0
    benchmark_payload = json.loads(benchmark_result.output)
    expected_projection = benchmark_bank(bank, options={"benchmark_iterations": 1, "stress_multiplier": 2})
    assert benchmark_payload["bank"]["id"] == expected_projection["bank"]["id"]
    assert benchmark_payload["options"] == expected_projection["options"]
    assert benchmark_payload["summary"]["cache_hit_verified"] is True

    assert regress_result.exit_code == 0
    regress_payload = json.loads(regress_result.output)
    expected_regression = regress_bank(
        bank,
        new_bank,
        options={
            "old_bank_path": str(old_bank_path),
            "new_bank_path": str(new_bank_path),
            "benchmark_iterations": 1,
            "stress_multiplier": 2,
        },
    )
    assert regress_payload["diff"] == expected_regression["diff"]
    assert regress_payload["gates"]["passed"] == expected_regression["gates"]["passed"]


def test_extract_json_matches_api_for_fixture_config_and_document(test_data_path, prog_rock_wiki):
    config_path = test_data_path / "music_entities.yaml"
    document_path = test_data_path / "prog_rock_wiki.txt"
    expected_records = _expected_config_records(config_path, prog_rock_wiki, "ARTIST")

    result = runner.invoke(
        app,
        [
            "extract",
            "ARTIST",
            str(document_path),
            "--config",
            str(config_path),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    records = _json_records(result.output)
    assert records == expected_records
    assert set(records[0]) == {"entity", "canonical_name", "surface_name", "string", "start", "end", "offset_unit"}


def test_extract_stdin_jsonl_matches_api_for_fixture_config(test_data_path, prog_rock_wiki):
    config_path = test_data_path / "music_entities.yaml"
    expected_records = _expected_config_records(config_path, prog_rock_wiki, "ARTIST")

    result = runner.invoke(
        app,
        [
            "extract",
            "ARTIST",
            "--stdin",
            "--config",
            str(config_path),
            "--format",
            "jsonl",
        ],
        input=prog_rock_wiki,
    )

    assert result.exit_code == 0
    records = _jsonl_records(result.output)
    assert records == expected_records


def test_extract_all_json_matches_api_for_fixture_config(test_data_path, prog_rock_wiki):
    config_path = test_data_path / "music_entities.yaml"
    document_path = test_data_path / "prog_rock_wiki.txt"
    expected_records = _expected_config_records(config_path, prog_rock_wiki)

    result = runner.invoke(
        app,
        [
            "extract",
            "--all",
            str(document_path),
            "--config",
            str(config_path),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    assert _json_records(result.output) == expected_records


def test_extract_uses_default_config_path_from_env(monkeypatch, tmp_path):
    config_path = save_config({"ARTIST": {"Rush": "Rush"}}, tmp_path / "default-detectors.yaml")
    monkeypatch.setenv(DEFAULT_CONFIG_ENV_VAR, str(config_path))

    result = runner.invoke(app, ["extract", "ARTIST", "--text", "Rush released 2112.", "--format", "json"])

    assert result.exit_code == 0
    assert _json_records(result.output) == [
        {
            "entity": "ARTIST",
            "canonical_name": "Rush",
            "surface_name": "Rush",
            "string": "Rush",
            "start": 0,
            "end": 4,
            "offset_unit": "byte",
        }
    ]


def test_extract_inline_pattern_from_literal_text_without_config(monkeypatch, tmp_path):
    monkeypatch.setenv(DEFAULT_CONFIG_ENV_VAR, str(tmp_path / "missing-default.yaml"))

    result = runner.invoke(
        app,
        [
            "extract",
            "ARTIST",
            "--text",
            "Pink Floyd played progressive rock.",
            "--pattern",
            r"Pink Floyd=Pink\sFloyd",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    assert _json_records(result.output) == [
        {
            "entity": "ARTIST",
            "canonical_name": "Pink Floyd",
            "surface_name": "Pink Floyd",
            "string": "Pink Floyd",
            "start": 0,
            "end": 10,
            "offset_unit": "byte",
        }
    ]


def test_extract_inline_detectors_from_file_without_config(monkeypatch, tmp_path):
    monkeypatch.setenv(DEFAULT_CONFIG_ENV_VAR, str(tmp_path / "missing-default.yaml"))
    document_path = tmp_path / "doc.txt"
    document_path.write_text("Pink Floyd played progressive rock.", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "extract",
            "--all",
            str(document_path),
            "--detector",
            r"ARTIST:Pink Floyd=Pink\sFloyd",
            "--detector",
            "GENRE:Rock=rock",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    assert _json_records(result.output) == [
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


def test_extract_table_output_records_with_inline_detectors(monkeypatch, tmp_path):
    monkeypatch.setenv(DEFAULT_CONFIG_ENV_VAR, str(tmp_path / "missing-default.yaml"))

    result = runner.invoke(
        app,
        [
            "extract",
            "--all",
            "--text",
            "Rush played progressive rock.",
            "--detector",
            "ARTIST:Rush=Rush",
            "--detector",
            "GENRE:Rock=rock",
        ],
    )

    assert result.exit_code == 0
    assert _table_records(result.output) == [
        {
            "entity": "ARTIST",
            "canonical_name": "Rush",
            "surface_name": "Rush",
            "string": "Rush",
            "start": "0",
            "end": "4",
            "offset_unit": "byte",
        },
        {
            "entity": "GENRE",
            "canonical_name": "Rock",
            "surface_name": "Rock",
            "string": "rock",
            "start": "24",
            "end": "28",
            "offset_unit": "byte",
        },
    ]


def test_extract_word_boundaries_option_limits_inline_matches(monkeypatch, tmp_path):
    monkeypatch.setenv(DEFAULT_CONFIG_ENV_VAR, str(tmp_path / "missing-default.yaml"))

    result = runner.invoke(
        app,
        [
            "extract",
            "TERM",
            "--text",
            "art article art",
            "--pattern",
            "Art=art",
            "--word-boundaries",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    assert [record["start"] for record in _json_records(result.output)] == [0, 12]


def test_extract_file_preserves_original_utf8_byte_offsets_with_crlf(tmp_path):
    config_path = save_config({"ARTIST": {"Rush": "Rush"}}, tmp_path / "entities.yaml")
    document_path = tmp_path / "document.txt"
    document_path.write_bytes("Café\r\nRush".encode())

    result = runner.invoke(
        app,
        ["extract", "ARTIST", str(document_path), "--config", str(config_path), "--format", "json"],
    )

    assert result.exit_code == 0
    assert _json_records(result.output) == [
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


def test_extract_stdin_preserves_original_utf8_byte_offsets(monkeypatch, tmp_path):
    config_path = save_config({"ARTIST": {"Rush": "Rush"}}, tmp_path / "entities.yaml")
    monkeypatch.setattr("sys.stdin", _BinaryStdin("Café\r\nRush".encode()))

    source = _read_extraction_source(None, read_stdin=True, text=None)
    records = _extract_records(load_config(config_path), "ARTIST", source, word_boundaries=False)

    assert records == [
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


def test_extract_reports_invalid_utf8_stdin(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", _BinaryStdin(b"\xffRush"))

    with pytest.raises(Exit) as exc_info:
        _read_extraction_source(None, read_stdin=True, text=None)

    assert exc_info.value.exit_code == 1
    assert "Standard input is not valid UTF-8" in capsys.readouterr().err


def test_extract_no_matches_returns_empty_success(monkeypatch, tmp_path):
    monkeypatch.setenv(DEFAULT_CONFIG_ENV_VAR, str(tmp_path / "missing-default.yaml"))

    result = runner.invoke(
        app,
        ["extract", "ARTIST", "--text", "No configured artists.", "--pattern", "Rush=Rush", "--format", "json"],
    )

    assert result.exit_code == 0
    assert _json_records(result.output) == []


def test_cli_end_to_end_add_validate_extract_from_document(tmp_path):
    config_path = tmp_path / "entities.yaml"
    document_path = tmp_path / "document.txt"
    document_path.write_text("Rush released 2112.", encoding="utf-8")

    add_result = runner.invoke(app, ["add", "ARTIST", "Rush", "Rush", "--config", str(config_path)])
    validate_result = runner.invoke(app, ["validate", "--config", str(config_path)])
    extract_result = runner.invoke(
        app,
        ["extract", "ARTIST", str(document_path), "--config", str(config_path), "--format", "json"],
    )

    assert add_result.exit_code == 0
    assert validate_result.exit_code == 0
    assert extract_result.exit_code == 0
    assert _json_records(extract_result.output) == [
        {
            "entity": "ARTIST",
            "canonical_name": "Rush",
            "surface_name": "Rush",
            "string": "Rush",
            "start": 0,
            "end": 4,
            "offset_unit": "byte",
        }
    ]


def test_extract_reports_missing_document_file(test_data_path, tmp_path):
    config_path = test_data_path / "music_entities.yaml"
    missing_document_path = tmp_path / "missing.txt"

    result = runner.invoke(app, ["extract", "ARTIST", str(missing_document_path), "--config", str(config_path)])

    assert result.exit_code == 1
    assert f"Document file does not exist at {missing_document_path}" in result.output


def test_extract_reports_invalid_utf8_document_file(tmp_path):
    config_path = save_config({"ARTIST": {"Rush": "Rush"}}, tmp_path / "entities.yaml")
    document_path = tmp_path / "invalid.bin"
    document_path.write_bytes(b"\xff")

    result = runner.invoke(app, ["extract", "ARTIST", str(document_path), "--config", str(config_path)])

    assert result.exit_code == 1
    assert f"Document file is not valid UTF-8 at {document_path}" in result.output


def test_extract_reports_unknown_entity(tmp_path):
    config_path = save_config({"ARTIST": {"Rush": "Rush"}}, tmp_path / "entities.yaml")

    result = runner.invoke(app, ["extract", "GENRE", "--text", "jazz", "--config", str(config_path)])

    assert result.exit_code == 1
    assert "GENRE" in result.output
    assert str(config_path) in result.output


def test_extract_reports_invalid_config(tmp_path):
    config_path = tmp_path / "invalid.yaml"
    config_path.write_text("ARTIST:\n  Broken: '('\n", encoding="utf-8")

    result = runner.invoke(app, ["extract", "ARTIST", "--text", "Pink Floyd", "--config", str(config_path)])

    assert result.exit_code == 1
    assert f"Could not load config at {config_path}" in result.output
    assert "not a valid regex pattern" in result.output


def test_extract_reports_invalid_yaml_config(tmp_path):
    config_path = tmp_path / "invalid.yaml"
    config_path.write_text("ARTIST:\n  Rush: [unterminated\n", encoding="utf-8")

    result = runner.invoke(app, ["extract", "ARTIST", "--text", "Rush", "--config", str(config_path)])

    assert result.exit_code == 1
    assert f"Could not load config at {config_path}" in result.output
    assert "Could not parse YAML config" in result.output


def test_extract_reports_invalid_inline_regex(monkeypatch, tmp_path):
    monkeypatch.setenv(DEFAULT_CONFIG_ENV_VAR, str(tmp_path / "missing-default.yaml"))

    result = runner.invoke(
        app,
        ["extract", "ARTIST", "--text", "Pink Floyd", "--pattern", "Broken=(", "--format", "json"],
    )

    assert result.exit_code == 1
    assert "Could not add inline detector ARTIST:Broken" in result.output
    assert "not a valid regex pattern" in result.output


def test_extract_reports_malformed_inline_pattern(monkeypatch, tmp_path):
    monkeypatch.setenv(DEFAULT_CONFIG_ENV_VAR, str(tmp_path / "missing-default.yaml"))

    result = runner.invoke(
        app,
        ["extract", "ARTIST", "--text", "Pink Floyd", "--pattern", "Pink Floyd"],
    )

    assert result.exit_code == 1
    assert "Malformed --pattern value" in result.output
    assert "NAME=REGEX" in result.output


def test_extract_reports_malformed_inline_detector(monkeypatch, tmp_path):
    monkeypatch.setenv(DEFAULT_CONFIG_ENV_VAR, str(tmp_path / "missing-default.yaml"))

    result = runner.invoke(
        app,
        ["extract", "--all", "--text", "Pink Floyd", "--detector", "ARTIST Pink Floyd=Pink Floyd"],
    )

    assert result.exit_code == 1
    assert "Malformed --detector value" in result.output
    assert "ENTITY:NAME=REGEX" in result.output


def test_test_literal_detector_json_success_without_config(monkeypatch, tmp_path):
    config_path = tmp_path / "missing-default.yaml"
    monkeypatch.setenv(DEFAULT_CONFIG_ENV_VAR, str(config_path))

    result = runner.invoke(
        app,
        [
            "test",
            "ARTIST",
            "Pink Floyd",
            r"Pink\sFloyd",
            "--text",
            "Pink Floyd played progressive rock.",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    assert json.loads(result.output) == [
        {
            "entity": "ARTIST",
            "canonical_name": "Pink Floyd",
            "surface_name": "Pink Floyd",
            "string": "Pink Floyd",
            "start": 0,
            "end": 10,
            "offset_unit": "byte",
        }
    ]
    assert not config_path.exists()


def test_test_literal_detector_no_match_returns_empty_json(monkeypatch, tmp_path):
    monkeypatch.setenv(DEFAULT_CONFIG_ENV_VAR, str(tmp_path / "missing-default.yaml"))

    result = runner.invoke(
        app,
        ["test", "ARTIST", "Pink Floyd", r"Pink\sFloyd", "--text", "Rush played.", "--format", "json"],
    )

    assert result.exit_code == 0
    assert json.loads(result.output) == []


def test_test_literal_detector_reports_invalid_regex_without_config_write(monkeypatch, tmp_path):
    config_path = tmp_path / "missing-default.yaml"
    monkeypatch.setenv(DEFAULT_CONFIG_ENV_VAR, str(config_path))

    result = runner.invoke(
        app,
        ["test", "ARTIST", "Broken", "(", "--text", "Pink Floyd", "--format", "json"],
    )

    assert result.exit_code == 1
    assert "Could not compile inline detector ARTIST:Broken" in result.output
    assert "not a valid regex pattern" in result.output
    assert "position 0" in result.output
    assert not config_path.exists()


def test_test_saved_detector_against_text_and_document(tmp_path):
    config_path = save_config(
        {
            "ARTIST": {"Rush": "Rush", "Pink Floyd": r"Pink\sFloyd"},
            "GENRE": {"_flags": "IGNORECASE", "Rock": "rock"},
        },
        tmp_path / "entities.yaml",
    )
    document_path = tmp_path / "doc.txt"
    document_path.write_text("Rush released Moving Pictures.", encoding="utf-8")

    result = runner.invoke(
        app,
        ["test", "GENRE", "Rock", "--text", "ROCK music", "--config", str(config_path), "--format", "json"],
    )

    assert result.exit_code == 0
    assert json.loads(result.output) == [
        {
            "entity": "GENRE",
            "canonical_name": "Rock",
            "surface_name": "Rock",
            "string": "ROCK",
            "start": 0,
            "end": 4,
            "offset_unit": "byte",
        }
    ]

    result = runner.invoke(
        app,
        ["test", "ARTIST", "Rush", "--document", str(document_path), "--config", str(config_path), "--format", "json"],
    )

    assert result.exit_code == 0
    assert json.loads(result.output) == [
        {
            "entity": "ARTIST",
            "canonical_name": "Rush",
            "surface_name": "Rush",
            "string": "Rush",
            "start": 0,
            "end": 4,
            "offset_unit": "byte",
        }
    ]


def test_test_saved_detector_reports_unknown_entity_and_pattern(tmp_path):
    config_path = save_config({"ARTIST": {"Rush": "Rush"}}, tmp_path / "entities.yaml")

    result = runner.invoke(app, ["test", "GENRE", "Rock", "--text", "rock", "--config", str(config_path)])

    assert result.exit_code == 1
    assert "Entity 'GENRE' does not exist" in result.output
    assert str(config_path) in result.output

    result = runner.invoke(app, ["test", "ARTIST", "Pink Floyd", "--text", "Pink Floyd", "--config", str(config_path)])

    assert result.exit_code == 1
    assert "Pattern 'Pink Floyd' does not exist for entity 'ARTIST'" in result.output
    assert str(config_path) in result.output


def test_compile_outputs_compiled_regex_for_entity(tmp_path):
    config_path = save_config({"ARTIST": {"Pink Floyd": r"Pink\sFloyd", "Rush": "Rush"}}, tmp_path / "entities.yaml")

    result = runner.invoke(app, ["compile", "ARTIST", "--config", str(config_path)])

    assert result.exit_code == 0
    assert result.output.strip() == r"(?P<Pink_Floyd>Pink\sFloyd)|(?P<Rush>Rush)"

    result = runner.invoke(app, ["compile", "ARTIST", "--config", str(config_path), "--format", "json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["entity"] == "ARTIST"
    assert payload["pattern"] == r"(?P<Pink_Floyd>Pink\sFloyd)|(?P<Rush>Rush)"
    assert payload["groups"] == [
        {"name": "Pink Floyd", "group": "Pink_Floyd", "index": 1},
        {"name": "Rush", "group": "Rush", "index": 2},
    ]


def test_doctor_reports_valid_and_invalid_config_json(tmp_path):
    config_path = save_config({"ARTIST": {"Pink Floyd": r"Pink\sFloyd"}}, tmp_path / "entities.yaml")

    result = runner.invoke(app, ["doctor", "--config", str(config_path), "--format", "json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["valid"] is True
    assert payload["summary"] == {"entities": 1, "patterns": 1, "errors": 0, "warnings": 0}
    assert payload["diagnostics"] == []

    invalid_config_path = tmp_path / "invalid.yaml"
    invalid_config_path.write_text("ARTIST:\n  Broken: '('\n", encoding="utf-8")

    result = runner.invoke(app, ["doctor", "--config", str(invalid_config_path), "--format", "json"])

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["valid"] is False
    assert payload["summary"]["errors"] == 1
    assert payload["diagnostics"][0]["code"] == "validation_error"
    assert "not a valid regex pattern" in payload["diagnostics"][0]["message"]


def test_doctor_reports_duplicate_compiled_group_names(tmp_path):
    config_path = tmp_path / "entities.yaml"
    config_path.write_text("ARTIST:\n  Pink Floyd: Pink\\sFloyd\n  Pink_Floyd: Pink_Floyd\n", encoding="utf-8")

    result = runner.invoke(app, ["doctor", "--config", str(config_path), "--format", "json"])

    assert result.exit_code == 1
    payload = json.loads(result.output)
    diagnostic_codes = {diagnostic["code"] for diagnostic in payload["diagnostics"]}
    assert "duplicate_group_name" in diagnostic_codes


def test_init_creates_config_and_refuses_existing_file(tmp_path):
    config_path = tmp_path / "entities.yaml"

    result = runner.invoke(app, ["init", "--config", str(config_path)])

    assert result.exit_code == 0
    assert f"Initialized detector config at {config_path}" in result.output
    assert load_config(config_path) == {}

    result = runner.invoke(app, ["init", "--config", str(config_path)])

    assert result.exit_code == 1
    assert f"Config already exists at {config_path}" in result.output


def test_init_force_overwrites_existing_config(tmp_path):
    config_path = save_config({"ARTIST": {"Rush": "Rush"}}, tmp_path / "entities.yaml")

    result = runner.invoke(app, ["init", "--force", "--config", str(config_path)])

    assert result.exit_code == 0
    assert load_config(config_path) == {}


def test_add_creates_config_that_nerb_can_load(tmp_path):
    config_path = tmp_path / "entities.yaml"

    result = runner.invoke(
        app,
        ["add", "ARTIST", "Pink Floyd", r"Pink\sFloyd", "--config", str(config_path)],
    )

    assert result.exit_code == 0
    assert load_config(config_path) == {"ARTIST": {"Pink Floyd": r"Pink\sFloyd"}}
    nerb = NERB(config_path)
    assert nerb.entity_list == ["ARTIST"]
    assert nerb.ARTIST.pattern == r"(?P<Pink_Floyd>Pink\sFloyd)"


def test_add_uses_default_config_path_from_env(monkeypatch, tmp_path):
    config_path = tmp_path / "default-detectors.yaml"
    monkeypatch.setenv(DEFAULT_CONFIG_ENV_VAR, str(config_path))

    result = runner.invoke(app, ["add", "ARTIST", "Rush", "Rush"])

    assert result.exit_code == 0
    assert load_config(config_path) == {"ARTIST": {"Rush": "Rush"}}


def test_add_refuses_duplicate_and_force_replaces(tmp_path):
    config_path = tmp_path / "entities.yaml"
    runner.invoke(app, ["add", "ARTIST", "Pink Floyd", r"Pink\sFloyd", "--config", str(config_path)])

    result = runner.invoke(
        app,
        ["add", "ARTIST", "Pink Floyd", r"Pink(?:\s+)Floyd", "--config", str(config_path)],
    )

    assert result.exit_code == 1
    assert "already exists" in result.output
    assert "ARTIST" in result.output
    assert "Pink Floyd" in result.output
    assert str(config_path) in result.output
    assert load_config(config_path) == {"ARTIST": {"Pink Floyd": r"Pink\sFloyd"}}

    result = runner.invoke(
        app,
        ["add", "ARTIST", "Pink Floyd", r"Pink(?:\s+)Floyd", "--force", "--config", str(config_path)],
    )

    assert result.exit_code == 0
    assert "Replaced pattern 'Pink Floyd'" in result.output
    assert load_config(config_path) == {"ARTIST": {"Pink Floyd": r"Pink(?:\s+)Floyd"}}


def test_add_writes_entity_flags(tmp_path):
    config_path = tmp_path / "entities.yaml"

    result = runner.invoke(
        app,
        [
            "add",
            "GENRE",
            "Jazz",
            r"(?:smooth\s)?jazz",
            "--flag",
            "IGNORECASE",
            "--flag",
            "MULTILINE",
            "--config",
            str(config_path),
        ],
    )

    assert result.exit_code == 0
    assert load_config(config_path) == {
        "GENRE": {
            "_flags": ["IGNORECASE", "MULTILINE"],
            "Jazz": r"(?:smooth\s)?jazz",
        }
    }


def test_add_reports_invalid_entity_flag(tmp_path):
    config_path = tmp_path / "entities.yaml"

    result = runner.invoke(
        app,
        ["add", "GENRE", "Jazz", "jazz", "--flag", "NOT_A_FLAG", "--config", str(config_path)],
    )

    assert result.exit_code == 1
    assert "Invalid _flags" in result.output
    assert "GENRE" in result.output
    assert "NOT_A_FLAG" in result.output
    assert str(config_path) in result.output


def test_add_requires_force_to_change_flags_on_existing_entity(tmp_path):
    config_path = save_config({"GENRE": {"Jazz": "jazz"}}, tmp_path / "entities.yaml")

    result = runner.invoke(
        app,
        ["add", "GENRE", "Rock", "rock", "--flag", "IGNORECASE", "--config", str(config_path)],
    )

    assert result.exit_code == 1
    assert "GENRE" in result.output
    assert "use --force to set _flags" in result.output
    assert load_config(config_path) == {"GENRE": {"Jazz": "jazz"}}


def test_list_shows_all_entities_and_single_entity(tmp_path):
    config_path = save_config(
        {
            "ARTIST": {"Pink Floyd": r"Pink\sFloyd"},
            "GENRE": {"_flags": "IGNORECASE", "Jazz": r"(?:smooth\s)?jazz"},
        },
        tmp_path / "entities.yaml",
    )

    result = runner.invoke(app, ["list", "--config", str(config_path)])

    assert result.exit_code == 0
    assert "ARTIST:\n  Pink Floyd" in result.output
    assert "GENRE:\n  _flags: IGNORECASE\n  Jazz" in result.output

    result = runner.invoke(app, ["list", "GENRE", "--config", str(config_path)])

    assert result.exit_code == 0
    assert "GENRE:" in result.output
    assert "Jazz" in result.output
    assert "ARTIST" not in result.output


def test_list_reports_missing_config_and_unknown_entity(tmp_path):
    missing_config_path = tmp_path / "missing.yaml"

    result = runner.invoke(app, ["list", "--config", str(missing_config_path)])

    assert result.exit_code == 1
    assert f"Config file does not exist at {missing_config_path}" in result.output

    config_path = save_config({"ARTIST": {"Rush": "Rush"}}, tmp_path / "entities.yaml")
    result = runner.invoke(app, ["list", "GENRE", "--config", str(config_path)])

    assert result.exit_code == 1
    assert "GENRE" in result.output
    assert str(config_path) in result.output


def test_show_outputs_entity_or_pattern_yaml(tmp_path):
    config_path = save_config(
        {
            "ARTIST": {"Pink Floyd": r"Pink\sFloyd"},
            "GENRE": {"_flags": "IGNORECASE", "Jazz": r"(?:smooth\s)?jazz"},
        },
        tmp_path / "entities.yaml",
    )

    result = runner.invoke(app, ["show", "ARTIST", "--config", str(config_path)])

    assert result.exit_code == 0
    assert "ARTIST:\n  Pink Floyd: Pink\\sFloyd" in result.output

    result = runner.invoke(app, ["show", "GENRE", "Jazz", "--config", str(config_path)])

    assert result.exit_code == 0
    assert "GENRE:\n  _flags: IGNORECASE\n  Jazz: (?:smooth\\s)?jazz" in result.output


def test_show_reports_missing_entity_and_pattern(tmp_path):
    config_path = save_config({"ARTIST": {"Rush": "Rush"}}, tmp_path / "entities.yaml")

    result = runner.invoke(app, ["show", "GENRE", "--config", str(config_path)])

    assert result.exit_code == 1
    assert "GENRE" in result.output
    assert str(config_path) in result.output

    result = runner.invoke(app, ["show", "ARTIST", "Pink Floyd", "--config", str(config_path)])

    assert result.exit_code == 1
    assert "Pink Floyd" in result.output
    assert "ARTIST" in result.output
    assert str(config_path) in result.output


def test_remove_deletes_pattern_and_saves_config(tmp_path):
    config_path = save_config(
        {"ARTIST": {"Pink Floyd": r"Pink\sFloyd", "Rush": "Rush"}},
        tmp_path / "entities.yaml",
    )

    result = runner.invoke(app, ["remove", "ARTIST", "Rush", "--config", str(config_path)])

    assert result.exit_code == 0
    assert load_config(config_path) == {"ARTIST": {"Pink Floyd": r"Pink\sFloyd"}}


def test_remove_reports_missing_pattern(tmp_path):
    config_path = save_config({"ARTIST": {"Rush": "Rush"}}, tmp_path / "entities.yaml")

    result = runner.invoke(app, ["remove", "ARTIST", "Pink Floyd", "--config", str(config_path)])

    assert result.exit_code == 1
    assert "Pink Floyd" in result.output
    assert "ARTIST" in result.output
    assert str(config_path) in result.output


def test_validate_reports_success_and_invalid_config(tmp_path):
    config_path = save_config({"ARTIST": {"Pink Floyd": r"Pink\sFloyd"}}, tmp_path / "entities.yaml")

    result = runner.invoke(app, ["validate", "--config", str(config_path)])

    assert result.exit_code == 0
    assert f"Config is valid: {config_path} (1 entities, 1 patterns)" in result.output

    invalid_config_path = tmp_path / "invalid.yaml"
    invalid_config_path.write_text("ARTIST:\n  Broken: '('\n", encoding="utf-8")

    result = runner.invoke(app, ["validate", "--config", str(invalid_config_path)])

    assert result.exit_code == 1
    assert f"Config is invalid at {invalid_config_path}" in result.output
    assert "not a valid regex pattern" in result.output


def test_validate_reports_missing_config(tmp_path):
    config_path = tmp_path / "missing.yaml"

    result = runner.invoke(app, ["validate", "--config", str(config_path)])

    assert result.exit_code == 1
    assert f"Config file does not exist at {config_path}" in result.output

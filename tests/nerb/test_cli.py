from __future__ import annotations

import json
import re
from importlib.metadata import entry_points
from importlib.metadata import version as package_version
from io import BytesIO
from pathlib import Path

import pytest
from click.exceptions import Exit
from typer.testing import CliRunner

import nerb.cli as cli_module
from nerb import (
    Bank,
    apply_bank_patches,
    bank_cache_info,
    benchmark_bank,
    clear_bank_cache,
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
from nerb.replacements import create_replacement_db, load_replacement_db

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


def _literal_bank_pattern(value: str, *, priority: int = 100) -> dict:
    return {
        "kind": "literal",
        "value": value,
        "description": "CLI de-anonymization fixture.",
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
        "anonymize-text",
        "anonymize-file",
        "deanonymize-text",
        "deanonymize-file",
        "eval-bank",
        "benchmark-bank",
        "regress-bank",
        "extract",
        "extract-batch",
        "test",
        "doctor",
        "init",
        "add",
        "list",
        "show",
        "remove",
        "validate",
        "replacement-db",
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


@pytest.mark.parametrize(
    "eval_record_json",
    [
        '{"type":"positive","text":"\\ud800 Acme Corp",'
        '"matches":[{"string":"Acme Corp","start":1,"end":10}],"metadata":{}}',
        '{"type":"negative","text":"\\ud800 Acme Corp","reason":"Invalid text guard.","metadata":{}}',
    ],
)
def test_json_bank_eval_command_serializes_invalid_utf8_eval_text(tmp_path, test_data_path, eval_record_json):
    bank = _load_json(test_data_path / "minimal_bank.json")
    eval_ref_path = tmp_path / "invalid_utf8_text.jsonl"
    eval_ref_path.write_text(eval_record_json + "\n", encoding="utf-8")
    bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]["eval_refs"] = [eval_ref_path.name]
    bank_path = _write_json(tmp_path / "bank.json", bank)

    result = runner.invoke(app, ["eval-bank", "--bank", str(bank_path)])

    assert result.exit_code == 0
    result.output.encode("utf-8")
    payload = json.loads(result.output)
    assert payload["summary"]["passed"] is False
    assert payload["failures"][0]["text"] == "\\ud800 Acme Corp"
    assert payload["failures"][0]["diagnostics"][0]["path"] == "/text"


def test_json_bank_eval_command_serializes_invalid_utf8_text_with_non_ascii_prefix(tmp_path, test_data_path):
    bank = _load_json(test_data_path / "minimal_bank.json")
    eval_ref_path = tmp_path / "invalid_utf8_text_with_non_ascii.jsonl"
    eval_ref_path.write_text(
        '{"type":"positive","text":"Caf\\u00e9 \\ud800 Acme Corp",'
        '"matches":[{"string":"Acme Corp","start":8,"end":17}],"metadata":{}}\n',
        encoding="utf-8",
    )
    bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]["eval_refs"] = [eval_ref_path.name]
    bank_path = _write_json(tmp_path / "bank.json", bank)

    result = runner.invoke(app, ["eval-bank", "--bank", str(bank_path)])

    assert result.exit_code == 0
    result.output.encode("utf-8")
    payload = json.loads(result.output)
    assert payload["summary"]["passed"] is False
    assert payload["failures"][0]["text"] == "Café \\ud800 Acme Corp"


def test_json_bank_eval_command_serializes_invalid_utf8_eval_ref(tmp_path, test_data_path):
    bank = _load_json(test_data_path / "minimal_bank.json")
    bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]["eval_refs"] = ["missing\ud800.jsonl"]
    bank_path = _write_json(tmp_path / "bank.json", bank)

    result = runner.invoke(app, ["eval-bank", "--bank", str(bank_path)])

    assert result.exit_code == 0
    result.output.encode("utf-8")
    payload = json.loads(result.output)
    assert payload["summary"]["passed"] is False
    assert payload["failures"][0]["eval_ref"] == "missing\\ud800.jsonl"


def test_json_bank_eval_command_serializes_invalid_utf8_provenance_source_type(tmp_path, test_data_path):
    bank = _load_json(test_data_path / "minimal_bank.json")
    eval_ref_path = tmp_path / "invalid_provenance_utf8.jsonl"
    eval_ref_path.write_text(
        '{"type":"provenance","source_type":"\\ud800","observed_at":"2026-06-05",'
        '"evidence":"CRM export.","metadata":{}}\n',
        encoding="utf-8",
    )
    bank["entities"]["customer"]["names"]["acme_corp"]["patterns"]["primary"]["eval_refs"] = [eval_ref_path.name]
    bank_path = _write_json(tmp_path / "bank.json", bank)

    result = runner.invoke(app, ["eval-bank", "--bank", str(bank_path)])

    assert result.exit_code == 0
    result.output.encode("utf-8")
    payload = json.loads(result.output)
    assert payload["summary"]["passed"] is False
    assert payload["failures"][0]["diagnostics"][0]["path"] == "/source_type"


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
    document_path.write_bytes("Café\r\nAcme Corp today.".encode())

    clear_bank_cache()
    text_result = runner.invoke(app, ["extract-text", "--bank", str(bank_path), "--text", text])
    clear_bank_cache()
    expected_text = extract_json_text(bank, text)
    clear_bank_cache()
    file_result = runner.invoke(app, ["extract-file", "--bank", str(bank_path), "--file", str(document_path)])
    clear_bank_cache()
    expected_file = extract_json_file(bank, document_path)
    clear_bank_cache()
    report_result = runner.invoke(app, ["extract-report", "--bank", str(bank_path), "--file", str(document_path)])
    clear_bank_cache()
    expected_report = extract_json_report_file(bank, document_path)

    assert text_result.exit_code == 0
    assert file_result.exit_code == 0
    assert report_result.exit_code == 0
    assert json.loads(text_result.output) == expected_text
    assert json.loads(file_result.output) == expected_file
    assert json.loads(report_result.output) == expected_report
    assert json.loads(file_result.output)["records"][0]["start"] == 7
    assert json.loads(file_result.output)["source"]["bytes"] == 23


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

    clear_bank_cache()
    text_result = runner.invoke(app, ["extract-text", "--bank", str(bank_path), "--stdin"], input=text)
    clear_bank_cache()
    expected_text = extract_json_text(bank, text)
    clear_bank_cache()
    report_result = runner.invoke(app, ["extract-report", "--bank", str(bank_path), "--stdin"], input=text)
    clear_bank_cache()

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


def test_extract_batch_json_compiles_once_and_preserves_document_order(monkeypatch, tmp_path):
    monkeypatch.setenv(DEFAULT_CONFIG_ENV_VAR, str(tmp_path / "missing-default.yaml"))
    first_document = tmp_path / "first.txt"
    second_document = tmp_path / "second.txt"
    manifest = tmp_path / "manifest.txt"
    first_document.write_text("Rush played rock.", encoding="utf-8")
    second_document.write_text("Pink Floyd played rock.", encoding="utf-8")
    manifest.write_text(f"{second_document.name}\n", encoding="utf-8")
    command = [
        "extract-batch",
        str(first_document),
        "--manifest",
        str(manifest),
        "--all",
        "--detector",
        "ARTIST:Rush=Rush",
        "--detector",
        r"ARTIST:Pink Floyd=Pink\sFloyd",
        "--detector",
        "GENRE:Rock=rock",
        "--format",
        "json",
    ]

    clear_bank_cache()
    first_result = runner.invoke(app, command)
    second_result = runner.invoke(app, command)

    assert first_result.exit_code == 0
    first_payload = json.loads(first_result.output)
    assert first_payload["document_count"] == 2
    assert first_payload["record_count"] == 4
    assert first_payload["cache"]["hit"] is False
    assert first_payload["cache"]["key"]["schema_version"] == 1
    assert first_payload["cache"]["key"]["compile_options"] == {"match_mode": "entity_independent"}
    assert [document["document_id"] for document in first_payload["documents"]] == [
        str(first_document),
        str(second_document),
    ]
    assert first_payload["documents"][0]["records"][0]["string"] == "Rush"
    assert first_payload["documents"][1]["records"][0]["string"] == "Pink Floyd"
    assert first_payload["documents"][1]["records"][1]["string"] == "rock"

    assert second_result.exit_code == 0
    second_payload = json.loads(second_result.output)
    assert second_payload["cache"]["hit"] is True
    assert second_payload["cache"]["key"] == first_payload["cache"]["key"]
    assert bank_cache_info()["size"] == 1
    assert bank_cache_info()["misses"] == 1
    assert bank_cache_info()["hits"] == 1


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


def test_config_extract_rejects_oversized_file_before_read(monkeypatch, tmp_path):
    monkeypatch.setattr(cli_module, "DEFAULT_MAX_TEXT_BYTES", 4)
    config_path = save_config({"ARTIST": {"Rush": "Rush"}}, tmp_path / "entities.yaml")
    document_path = tmp_path / "document.txt"
    document_path.write_text("Rush!", encoding="utf-8")

    result = runner.invoke(
        app,
        ["extract", "ARTIST", str(document_path), "--config", str(config_path), "--format", "json"],
    )

    assert result.exit_code == 1
    assert "configured limit of 4 bytes" in result.output


def test_config_extract_rejects_stale_size_oversized_file(monkeypatch, tmp_path):
    monkeypatch.setattr(cli_module, "DEFAULT_MAX_TEXT_BYTES", 4)
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

    result = runner.invoke(
        app,
        ["extract", "ARTIST", str(document_path), "--config", str(config_path), "--format", "json"],
    )

    assert result.exit_code == 1
    assert "configured limit of 4 bytes" in result.output


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
    assert "Could not compile detectors with the Rust engine" in result.output
    assert "regex parse error" in result.output


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
    assert "Could not compile detectors with the Rust engine" in result.output
    assert "regex parse error" in result.output


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
    assert "Could not compile detectors with the Rust engine" in result.output
    assert "regex parse error" in result.output
    assert "unclosed group" in result.output
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
    assert payload["diagnostics"][0]["code"] == "compile_error"
    assert "regex parse error" in payload["diagnostics"][0]["message"]


def test_doctor_accepts_names_that_only_differ_by_spaces_and_underscores(tmp_path):
    config_path = tmp_path / "entities.yaml"
    config_path.write_text("ARTIST:\n  Pink Floyd: Pink\\sFloyd\n  Pink_Floyd: Pink_Floyd\n", encoding="utf-8")

    result = runner.invoke(app, ["doctor", "--config", str(config_path), "--format", "json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["valid"] is True
    assert payload["diagnostics"] == []


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


def test_add_creates_config_that_bank_can_load(tmp_path):
    config_path = tmp_path / "entities.yaml"

    result = runner.invoke(
        app,
        ["add", "ARTIST", "Pink Floyd", r"Pink\sFloyd", "--config", str(config_path)],
    )

    assert result.exit_code == 0
    assert load_config(config_path) == {"ARTIST": {"Pink Floyd": r"Pink\sFloyd"}}
    bank = Bank.from_config(load_config(config_path))
    assert bank.metadata()["entity_count"] == 1
    assert bank.scan_text("Pink Floyd") == [
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
    assert "regex parse error" in result.output


def test_validate_rejects_zero_width_regex_config(tmp_path):
    config_path = tmp_path / "zero-width.yaml"
    config_path.write_text("ARTIST:\n  Boundary: '" + r"\b" + "'\n", encoding="utf-8")

    result = runner.invoke(app, ["validate", "--config", str(config_path)])

    assert result.exit_code == 1
    assert f"Config is invalid at {config_path}" in result.output
    assert "zero-length match" in result.output


def test_extract_rejects_zero_width_regex_config(tmp_path):
    config_path = tmp_path / "zero-width.yaml"
    config_path.write_text("ARTIST:\n  Boundary: '" + r"\b" + "'\n", encoding="utf-8")

    result = runner.invoke(app, ["extract", "ARTIST", "--text", "abc", "--config", str(config_path)])

    assert result.exit_code == 1
    assert "Could not compile detectors with the Rust engine" in result.output
    assert "zero-length match" in result.output


def test_validate_reports_missing_config(tmp_path):
    config_path = tmp_path / "missing.yaml"

    result = runner.invoke(app, ["validate", "--config", str(config_path)])

    assert result.exit_code == 1
    assert f"Config file does not exist at {config_path}" in result.output


def test_replacement_db_commands_manage_safe_summary(tmp_path):
    db_path = tmp_path / "replacements.json"

    init_result = runner.invoke(app, ["replacement-db", "init", "--db", str(db_path)])
    validate_result = runner.invoke(app, ["replacement-db", "validate", "--db", str(db_path)])
    add_set_result = runner.invoke(
        app,
        [
            "replacement-db",
            "add-set",
            "--db",
            str(db_path),
            "--set",
            "person_names",
            "--candidate",
            "Mikey Law",
            "--candidate",
            "Nina Vale",
        ],
    )
    set_entity_result = runner.invoke(
        app,
        [
            "replacement-db",
            "set-entity",
            "--db",
            str(db_path),
            "--entity",
            "person",
            "--mode",
            "pseudonym",
            "--set",
            "person_names",
            "--store-originals",
        ],
    )
    list_result = runner.invoke(app, ["replacement-db", "list", "--db", str(db_path)])
    values_result = runner.invoke(app, ["replacement-db", "list", "--db", str(db_path), "--include-values"])

    assert init_result.exit_code == 0
    assert validate_result.exit_code == 0
    assert add_set_result.exit_code == 0
    assert set_entity_result.exit_code == 0
    assert list_result.exit_code == 0
    assert values_result.exit_code == 0

    init_payload = json.loads(init_result.output)
    validate_payload = json.loads(validate_result.output)
    list_payload = json.loads(list_result.output)
    values_payload = json.loads(values_result.output)

    assert init_payload["replacement_db"]["saved"] is True
    assert validate_payload == {"valid": True, "path": str(db_path), "diagnostics": []}
    assert list_payload["schema_version"] == "nerb.replacement_db_summary.v1"
    assert list_payload["replacement_db"]["replacement_db_ref"] == "rdb1"
    assert list_payload["replacement_sets"]["person_names"]["candidate_count"] == 2
    assert list_payload["entities"]["person"] == {
        "replacement_mode": "pseudonym",
        "replacement_set_id": "person_names",
        "store_originals": True,
    }
    assert "Mikey Law" not in list_result.output
    assert "Nina Vale" not in list_result.output
    assert "sha256:" not in list_result.output
    assert "assignment_key" not in list_result.output
    assert values_payload["replacement_sets"]["person_names"]["candidates"] == [
        {"id": "person_names_0001", "value": "Mikey Law"},
        {"id": "person_names_0002", "value": "Nina Vale"},
    ]


def test_replacement_db_validate_sanitizes_assignment_diagnostics_by_default(tmp_path):
    db_path = tmp_path / "replacements.json"
    first_key = f"person|name|sha256:{'a' * 64}"
    second_key = f"person|name|sha256:{'b' * 64}"
    replacement_db = create_replacement_db(reversible=True, now="2026-06-13T00:00:00Z")
    replacement_db["assignments"] = {
        first_key: _replacement_assignment(first_key, canonical="John Smith"),
        second_key: _replacement_assignment(second_key, canonical="Jane Smith"),
    }
    _write_json(db_path, replacement_db)

    result = runner.invoke(app, ["replacement-db", "validate", "--db", str(db_path)])
    sensitive_result = runner.invoke(
        app,
        ["replacement-db", "validate", "--db", str(db_path), "--include-sensitive-metadata"],
    )

    assert result.exit_code == 0
    assert sensitive_result.exit_code == 0
    payload = json.loads(result.output)
    sensitive_payload = json.loads(sensitive_result.output)

    assert payload["valid"] is False
    assert payload["diagnostics"][0]["path"] == "/assignments"
    assert payload["diagnostics"][0]["message"] == "Assignment diagnostic details are redacted by default."
    assert first_key not in result.output
    assert second_key not in result.output
    assert "sha256:" not in result.output
    assert "first_assignment_key" not in result.output
    assert "John Smith" not in result.output
    assert "Jane Smith" not in result.output
    assert "[PERSON_0001]" not in result.output
    assert first_key in sensitive_result.output
    assert sensitive_payload["diagnostics"][0]["metadata"]["first_assignment_key"] == first_key


def test_cli_anonymize_text_requires_save_db_to_persist_assignments(tmp_path):
    bank_path = _write_json(tmp_path / "people.json", _person_json_bank())
    db_path = tmp_path / "replacements.json"

    init_result = runner.invoke(app, ["replacement-db", "init", "--db", str(db_path), "--reversible"])
    unsaved_result = runner.invoke(
        app,
        [
            "anonymize-text",
            "--bank",
            str(bank_path),
            "--db",
            str(db_path),
            "--text",
            "John Smith joined.",
            "--mode",
            "redact",
        ],
    )
    assert init_result.exit_code == 0
    assert unsaved_result.exit_code == 0

    unsaved_payload = json.loads(unsaved_result.output)

    assert unsaved_payload["text"] == "[PERSON_0001] joined."
    assert unsaved_payload["replacement_db"]["modified"] is True
    assert unsaved_payload["replacement_db"]["saved"] is False
    assert load_replacement_db(db_path)["assignments"] == {}

    saved_result = runner.invoke(
        app,
        [
            "anonymize-text",
            "--bank",
            str(bank_path),
            "--db",
            str(db_path),
            "--text",
            "John Smith joined.",
            "--mode",
            "redact",
            "--save-db",
        ],
    )
    deanonymized_result = runner.invoke(
        app,
        ["deanonymize-text", "--db", str(db_path), "--text", "[PERSON_0001] joined."],
    )

    assert saved_result.exit_code == 0
    assert deanonymized_result.exit_code == 0

    saved_payload = json.loads(saved_result.output)
    deanonymized_payload = json.loads(deanonymized_result.output)

    assert saved_payload["text"] == "[PERSON_0001] joined."
    assert saved_payload["replacement_db"]["modified"] is True
    assert saved_payload["replacement_db"]["saved"] is True
    assert saved_payload["replacement_db"]["version"] == 2
    assert "replacement" not in saved_payload["applied_replacements"][0]
    assert len(load_replacement_db(db_path)["assignments"]) == 1

    assert deanonymized_payload["schema_version"] == "nerb.deanonymize_response.v1"
    assert deanonymized_payload["text"] == "John Smith joined."
    assert deanonymized_payload["summary"]["applied_count"] == 1
    assert "John Smith" not in saved_result.output
    assert "assignment_key" not in saved_result.output


def test_cli_anonymize_config_text_saves_canonical_assignments(tmp_path):
    config_path = save_config({"ARTIST": {"Miles Davis": r"Miles Davis|M\. Davis"}}, tmp_path / "entities.yaml")
    db_path = tmp_path / "replacements.json"

    init_result = runner.invoke(
        app,
        [
            "replacement-db",
            "init",
            "--db",
            str(db_path),
            "--reversible",
            "--assignment-scope",
            "canonical",
        ],
    )
    anonymized_result = runner.invoke(
        app,
        [
            "anonymize-config-text",
            "--config",
            str(config_path),
            "--db",
            str(db_path),
            "--text",
            "Miles Davis met M. Davis.",
            "--mode",
            "redact",
            "--save-db",
        ],
    )
    deanonymized_result = runner.invoke(
        app,
        ["deanonymize-text", "--db", str(db_path), "--text", json.loads(anonymized_result.output)["text"]],
    )

    assert init_result.exit_code == 0
    assert anonymized_result.exit_code == 0
    assert deanonymized_result.exit_code == 0

    anonymized_payload = json.loads(anonymized_result.output)
    deanonymized_payload = json.loads(deanonymized_result.output)
    first_token, second_token = anonymized_payload["text"].removesuffix(".").split(" met ")

    assert first_token == second_token
    assert anonymized_payload["replacement_db"]["saved"] is True
    assert anonymized_payload["bank"] == {
        "bank_ref": "b1",
        "schema_version": "nerb.detector_config.v1",
        "version": "1",
    }
    assert deanonymized_payload["text"] == "Miles Davis met Miles Davis."
    assert len(load_replacement_db(db_path)["assignments"]) == 1
    assert next(iter(load_replacement_db(db_path)["assignments"])).split("|")[1] == "canonical"
    assert "Miles Davis" not in anonymized_result.output
    assert "sha256:" not in anonymized_result.output


def test_cli_anonymize_save_uses_single_helper_run(monkeypatch, tmp_path):
    bank_path = _write_json(tmp_path / "people.json", _person_json_bank())
    db_path = tmp_path / "replacements.json"
    calls = []

    assert runner.invoke(app, ["replacement-db", "init", "--db", str(db_path), "--reversible"]).exit_code == 0

    def fake_anonymize_text_with_update(bank, text, replacement_db, *, options=None):
        calls.append({"text": text, "options": dict(options or {})})
        updated_db = json.loads(json.dumps(replacement_db))
        return (
            {
                "schema_version": "nerb.anonymize_response.v1",
                "bank": {"bank_ref": "b1"},
                "replacement_db": {
                    "replacement_db_ref": "rdb1",
                    "schema_version": replacement_db["schema_version"],
                    "version": replacement_db["version"],
                    "modified": True,
                    "saved": False,
                },
                "source": {"type": "text", "length": len(text), "bytes": len(text.encode("utf-8"))},
                "text": "[PERSON_0001] joined.",
                "applied_replacements": [],
                "summary": {"record_count": 1, "applied_count": 1, "diagnostic_count": 0},
                "diagnostics": [],
            },
            updated_db,
        )

    monkeypatch.setattr(cli_module, "_anonymize_text_with_db_update", fake_anonymize_text_with_update)

    result = runner.invoke(
        app,
        [
            "anonymize-text",
            "--bank",
            str(bank_path),
            "--db",
            str(db_path),
            "--text",
            "John Smith joined.",
            "--mode",
            "redact",
            "--save-db",
        ],
    )

    assert result.exit_code == 0
    assert len(calls) == 1
    assert calls[0]["options"]["include_sensitive_metadata"] is False
    assert json.loads(result.output)["replacement_db"]["saved"] is True
    assert load_replacement_db(db_path)["version"] == 2


def test_cli_pseudonym_workflow_requires_restore_pseudonyms(tmp_path):
    bank_path = _write_json(tmp_path / "people.json", _person_json_bank())
    db_path = tmp_path / "replacements.json"

    assert runner.invoke(app, ["replacement-db", "init", "--db", str(db_path), "--reversible"]).exit_code == 0
    assert (
        runner.invoke(
            app,
            [
                "replacement-db",
                "add-set",
                "--db",
                str(db_path),
                "--set",
                "person_names",
                "--candidate",
                "Mikey Law",
                "--candidate",
                "Nina Vale",
            ],
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            app,
            [
                "replacement-db",
                "set-entity",
                "--db",
                str(db_path),
                "--entity",
                "person",
                "--mode",
                "pseudonym",
                "--set",
                "person_names",
                "--store-originals",
            ],
        ).exit_code
        == 0
    )
    anonymized_result = runner.invoke(
        app,
        [
            "anonymize-text",
            "--bank",
            str(bank_path),
            "--db",
            str(db_path),
            "--text",
            "John Smith joined.",
            "--mode",
            "pseudonym",
            "--save-db",
        ],
    )
    sensitive_anonymized_result = runner.invoke(
        app,
        [
            "anonymize-text",
            "--bank",
            str(bank_path),
            "--db",
            str(db_path),
            "--text",
            "John Smith joined.",
            "--mode",
            "pseudonym",
            "--include-sensitive-metadata",
        ],
    )
    default_deanonymized_result = runner.invoke(
        app,
        ["deanonymize-text", "--db", str(db_path), "--text", "Mikey Law joined."],
    )
    opt_in_deanonymized_result = runner.invoke(
        app,
        [
            "deanonymize-text",
            "--db",
            str(db_path),
            "--text",
            "Mikey Law joined.",
            "--restore-pseudonyms",
            "--include-originals",
        ],
    )

    assert anonymized_result.exit_code == 0
    assert sensitive_anonymized_result.exit_code == 0
    assert default_deanonymized_result.exit_code == 0
    assert opt_in_deanonymized_result.exit_code == 0

    anonymized_payload = json.loads(anonymized_result.output)
    sensitive_payload = json.loads(sensitive_anonymized_result.output)
    default_payload = json.loads(default_deanonymized_result.output)
    opt_in_payload = json.loads(opt_in_deanonymized_result.output)

    assert anonymized_payload["text"] == "Mikey Law joined."
    assert anonymized_payload["replacement_db"]["saved"] is True
    assert "replacement" not in anonymized_payload["applied_replacements"][0]
    assert sensitive_payload["applied_replacements"][0]["replacement"] == "Mikey Law"
    assert default_payload["text"] == "Mikey Law joined."
    assert default_payload["applied_restorations"] == []
    assert opt_in_payload["text"] == "John Smith joined."
    assert opt_in_payload["applied_restorations"][0]["mode"] == "pseudonym"
    assert opt_in_payload["applied_restorations"][0]["restored"] == "John Smith"
    assert opt_in_payload["diagnostics"][0]["code"] == "deanonymize.pseudonym_restore_warning"
    assert "assignment_key" not in opt_in_deanonymized_result.output


def test_cli_anonymize_file_refuses_unsaved_assignment_output(tmp_path):
    bank_path = _write_json(tmp_path / "people.json", _person_json_bank())
    db_path = tmp_path / "replacements.json"
    input_path = tmp_path / "input.txt"
    output_path = tmp_path / "output.txt"
    input_path.write_text("John Smith joined.", encoding="utf-8")

    assert runner.invoke(app, ["replacement-db", "init", "--db", str(db_path), "--reversible"]).exit_code == 0
    result = runner.invoke(
        app,
        [
            "anonymize-file",
            "--bank",
            str(bank_path),
            "--db",
            str(db_path),
            "--file",
            str(input_path),
            "--output",
            str(output_path),
            "--mode",
            "redact",
        ],
    )

    assert result.exit_code == 1
    assert "Refusing to write output that depends on new unsaved assignments" in result.output
    assert not output_path.exists()
    assert load_replacement_db(db_path)["assignments"] == {}


def test_cli_file_outputs_refuse_overwrite_without_force(tmp_path):
    bank_path = _write_json(tmp_path / "people.json", _person_json_bank())
    db_path = tmp_path / "replacements.json"
    input_path = tmp_path / "input.txt"
    output_path = tmp_path / "output.txt"
    input_path.write_text("John Smith joined.", encoding="utf-8")
    output_path.write_text("existing", encoding="utf-8")

    assert runner.invoke(app, ["replacement-db", "init", "--db", str(db_path), "--reversible"]).exit_code == 0
    result = runner.invoke(
        app,
        [
            "anonymize-file",
            "--bank",
            str(bank_path),
            "--db",
            str(db_path),
            "--file",
            str(input_path),
            "--output",
            str(output_path),
            "--mode",
            "redact",
            "--save-db",
        ],
    )
    assert result.exit_code == 1
    assert f"Output file already exists at {output_path}" in result.output
    assert output_path.read_text(encoding="utf-8") == "existing"
    assert load_replacement_db(db_path)["assignments"] == {}

    forced_result = runner.invoke(
        app,
        [
            "anonymize-file",
            "--bank",
            str(bank_path),
            "--db",
            str(db_path),
            "--file",
            str(input_path),
            "--output",
            str(output_path),
            "--mode",
            "redact",
            "--save-db",
            "--force",
        ],
    )

    assert forced_result.exit_code == 0
    assert output_path.read_text(encoding="utf-8") == "[PERSON_0001] joined."


def test_cli_anonymize_file_rejects_non_directory_output_parent_before_saving(tmp_path):
    bank_path = _write_json(tmp_path / "people.json", _person_json_bank())
    db_path = tmp_path / "replacements.json"
    input_path = tmp_path / "input.txt"
    parent_path = tmp_path / "not-a-directory"
    output_path = parent_path / "output.txt"
    input_path.write_text("John Smith joined.", encoding="utf-8")
    parent_path.write_text("not a directory", encoding="utf-8")

    assert runner.invoke(app, ["replacement-db", "init", "--db", str(db_path), "--reversible"]).exit_code == 0
    result = runner.invoke(
        app,
        [
            "anonymize-file",
            "--bank",
            str(bank_path),
            "--db",
            str(db_path),
            "--file",
            str(input_path),
            "--output",
            str(output_path),
            "--mode",
            "redact",
            "--save-db",
        ],
    )

    assert result.exit_code == 1
    assert f"Output parent path is not a directory: {parent_path}" in result.output
    assert load_replacement_db(db_path)["assignments"] == {}


def test_cli_anonymize_file_rejects_output_over_replacement_db_before_saving(tmp_path):
    bank_path = _write_json(tmp_path / "people.json", _person_json_bank())
    db_path = tmp_path / "replacements.json"
    input_path = tmp_path / "input.txt"
    input_path.write_text("John Smith joined.", encoding="utf-8")

    assert runner.invoke(app, ["replacement-db", "init", "--db", str(db_path), "--reversible"]).exit_code == 0
    before = db_path.read_text(encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "anonymize-file",
            "--bank",
            str(bank_path),
            "--db",
            str(db_path),
            "--file",
            str(input_path),
            "--output",
            str(db_path),
            "--mode",
            "redact",
            "--save-db",
            "--force",
        ],
    )

    assert result.exit_code == 1
    assert f"Output path must not overwrite the replacement database file: {db_path}" in result.output
    assert db_path.read_text(encoding="utf-8") == before
    assert load_replacement_db(db_path)["assignments"] == {}

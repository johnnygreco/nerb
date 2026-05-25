from __future__ import annotations

from importlib.metadata import entry_points
from importlib.metadata import version as package_version

from typer.testing import CliRunner

from nerb import NERB, load_config, save_config
from nerb.cli import app
from nerb.config import DEFAULT_CONFIG_ENV_VAR

runner = CliRunner()


def _console_script_entry_points():
    discovered_entry_points = entry_points()
    if hasattr(discovered_entry_points, "select"):
        return discovered_entry_points.select(group="console_scripts")
    return discovered_entry_points.get("console_scripts", [])


def test_help_shows_command_structure():
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Usage:" in result.output
    for command_name in ["init", "add", "list", "show", "remove", "validate"]:
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

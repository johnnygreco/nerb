from __future__ import annotations

from importlib.metadata import entry_points
from importlib.metadata import version as package_version

from typer.testing import CliRunner

from nerb.cli import COMMAND_NOT_IMPLEMENTED_EXIT_CODE, app

runner = CliRunner()


def test_help_shows_command_structure():
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Usage:" in result.output
    for command_name in ["add", "list", "show", "remove", "validate"]:
        assert command_name in result.output
    assert "--config" in result.output
    assert "--version" in result.output


def test_version_prints_installed_package_version():
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.output.strip() == f"nerb {package_version('nerb')}"


def test_console_script_entry_point_is_registered():
    console_scripts = entry_points(group="console_scripts")

    assert any(entry_point.name == "nerb" and entry_point.value == "nerb.cli:main" for entry_point in console_scripts)


def test_invalid_command_usage_returns_error():
    result = runner.invoke(app, ["add"])

    assert result.exit_code != 0
    assert "Missing argument" in result.output
    assert "ENTITY" in result.output


def test_unimplemented_command_returns_clear_error():
    result = runner.invoke(app, ["add", "ARTIST", "Rush", "Rush"])

    assert result.exit_code == COMMAND_NOT_IMPLEMENTED_EXIT_CODE
    assert "Error: 'add' is not implemented yet." in result.output

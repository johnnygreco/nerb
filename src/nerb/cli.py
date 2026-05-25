from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as package_version
from pathlib import Path
from typing import Optional

import typer

from . import __version__
from .config import DEFAULT_CONFIG_ENV_VAR, resolve_default_config_path

COMMAND_NOT_IMPLEMENTED_EXIT_CODE = 2

app = typer.Typer(
    add_completion=False,
    context_settings={"help_option_names": ["-h", "--help"]},
    help="Build and manage named entity regex detector configs.",
    no_args_is_help=True,
    rich_markup_mode=None,
)


def _installed_version() -> str:
    try:
        return package_version("nerb")
    except PackageNotFoundError:
        return __version__


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"nerb {_installed_version()}")
        raise typer.Exit()


def _not_implemented(command_name: str) -> None:
    typer.echo(f"Error: '{command_name}' is not implemented yet.", err=True)
    raise typer.Exit(COMMAND_NOT_IMPLEMENTED_EXIT_CODE)


@app.callback()
def callback(
    ctx: typer.Context,
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        callback=_version_callback,
        help="Show the installed package version and exit.",
        is_eager=True,
    ),
    config: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help=f"Detector config path. Defaults to ${DEFAULT_CONFIG_ENV_VAR} or the platform config path.",
    ),
) -> None:
    """Build and manage named entity regex detector configs."""
    ctx.obj = {"config_path": resolve_default_config_path(config)}


@app.command("add")
def add_pattern(
    entity: str = typer.Argument(..., help="Detector entity name."),
    name: str = typer.Argument(..., help="Pattern name."),
    pattern: str = typer.Argument(..., help="Regex pattern."),
    replace: bool = typer.Option(False, "--replace", help="Replace an existing entity/name pattern."),
) -> None:
    """Add a detector pattern to the configured detector file."""
    _not_implemented("add")


@app.command("list")
def list_patterns(entity: Optional[str] = typer.Argument(None, help="Optional detector entity name.")) -> None:
    """List detector patterns in the configured detector file."""
    _not_implemented("list")


@app.command("show")
def show_pattern(
    entity: str = typer.Argument(..., help="Detector entity name."),
    name: Optional[str] = typer.Argument(None, help="Optional pattern name."),
) -> None:
    """Show configured detector patterns for an entity."""
    _not_implemented("show")


@app.command("remove")
def remove_pattern(
    entity: str = typer.Argument(..., help="Detector entity name."),
    name: str = typer.Argument(..., help="Pattern name."),
) -> None:
    """Remove a detector pattern from the configured detector file."""
    _not_implemented("remove")


@app.command("validate")
def validate_config() -> None:
    """Validate the configured detector file."""
    _not_implemented("validate")


def main() -> None:
    app()

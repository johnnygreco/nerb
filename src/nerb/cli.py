from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as package_version
from pathlib import Path
from typing import Any, Dict, List, NoReturn, Optional, Set, Union

import typer
import yaml

from . import __version__
from .config import (
    DEFAULT_CONFIG_ENV_VAR,
    FLAGS_KEY,
    ConfigError,
    PatternConfig,
    add_entity_pattern,
    load_config,
    remove_entity_pattern,
    resolve_default_config_path,
    save_config,
    validate_pattern_config,
    validate_regex_flags,
)

COMMAND_ERROR_EXIT_CODE = 1

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


def _config_option() -> Any:
    return typer.Option(
        None,
        "--config",
        "-c",
        help=f"Detector config path. Defaults to ${DEFAULT_CONFIG_ENV_VAR} or the platform config path.",
    )


def _command_config_path(ctx: typer.Context, config: Optional[Path]) -> Path:
    if config is not None:
        return resolve_default_config_path(config)

    if ctx.obj and "config_path" in ctx.obj:
        return ctx.obj["config_path"]

    return resolve_default_config_path()


def _exit_error(message: str) -> NoReturn:
    typer.echo(f"Error: {message}", err=True)
    raise typer.Exit(COMMAND_ERROR_EXIT_CODE)


def _load_command_config(config_path: Path, *, allow_missing: bool = False) -> PatternConfig:
    if not config_path.exists():
        if allow_missing:
            return {}
        _exit_error(f"Config file does not exist at {config_path}.")

    try:
        return load_config(config_path)
    except ConfigError as exc:
        _exit_error(f"Could not load config at {config_path}: {exc}")
    except OSError as exc:
        _exit_error(f"Could not read config at {config_path}: {exc}")


def _save_command_config(config: PatternConfig, config_path: Path) -> None:
    try:
        save_config(config, config_path)
    except ConfigError as exc:
        _exit_error(f"Could not save config at {config_path}: {exc}")
    except OSError as exc:
        _exit_error(f"Could not write config at {config_path}: {exc}")


def _canonical_flag_names(flags: List[str]) -> List[str]:
    flag_names: List[str] = []
    seen: Set[str] = set()
    for raw_value in flags:
        for raw_flag in raw_value.split(","):
            flag_name = raw_flag.strip()
            if flag_name.startswith("re."):
                flag_name = flag_name[3:]
            flag_name = flag_name.upper()
            if flag_name in seen:
                continue
            flag_names.append(flag_name)
            seen.add(flag_name)
    return flag_names


def _flag_config(entity: str, config_path: Path, flags: Optional[List[str]]) -> Optional[Union[str, List[str]]]:
    if not flags:
        return None

    flag_names = _canonical_flag_names(flags)
    if not flag_names:
        _exit_error(f"Invalid _flags for entity {entity!r} in {config_path}: Regex flag names must not be empty.")
    flag_config: Union[str, List[str]] = flag_names[0] if len(flag_names) == 1 else flag_names
    try:
        validate_regex_flags(flag_config)
    except ConfigError as exc:
        _exit_error(f"Invalid _flags for entity {entity!r} in {config_path}: {exc}")
    return flag_config


def _ensure_flag_update_allowed(
    config: PatternConfig,
    entity: str,
    flag_config: Optional[Union[str, List[str]]],
    *,
    force: bool,
    config_path: Path,
) -> None:
    if flag_config is None or entity not in config:
        return

    existing_flags = config[entity].get(FLAGS_KEY)
    if existing_flags == flag_config:
        return

    if existing_flags is None:
        message = f"Entity {entity!r} already exists in {config_path} without _flags; use --force to set _flags."
    else:
        message = f"Entity {entity!r} already has _flags in {config_path}; use --force to replace _flags."

    if not force:
        _exit_error(message)


def _with_entity_flags(
    config: PatternConfig, entity: str, flag_config: Optional[Union[str, List[str]]]
) -> PatternConfig:
    if flag_config is None:
        return config

    updated_config = validate_pattern_config(config)
    entity_config: Dict[str, Any] = {FLAGS_KEY: flag_config}
    for name, pattern in updated_config[entity].items():
        if name != FLAGS_KEY:
            entity_config[name] = pattern
    updated_config[entity] = entity_config
    return validate_pattern_config(updated_config)


def _format_flags(flags: Any) -> str:
    if isinstance(flags, list):
        return f"[{', '.join(str(flag) for flag in flags)}]"
    return str(flags)


def _echo_entity_listing(entity: str, entity_config: Dict[str, Any]) -> None:
    typer.echo(f"{entity}:")
    if FLAGS_KEY in entity_config:
        typer.echo(f"  {FLAGS_KEY}: {_format_flags(entity_config[FLAGS_KEY])}")
    for name in entity_config:
        if name != FLAGS_KEY:
            typer.echo(f"  {name}")


def _yaml_text(config: Dict[str, Any]) -> str:
    return yaml.safe_dump(config, sort_keys=False, default_flow_style=False, allow_unicode=True).rstrip()


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


@app.command("init")
def init_config(
    ctx: typer.Context,
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite an existing detector config."),
    config: Optional[Path] = _config_option(),
) -> None:
    """Create an empty detector config file."""
    config_path = _command_config_path(ctx, config)
    config_exists = config_path.exists()
    if config_exists and not force:
        _exit_error(f"Config already exists at {config_path}; use --force to overwrite it.")

    _save_command_config({}, config_path)
    action = "Reinitialized" if config_exists else "Initialized"
    typer.echo(f"{action} detector config at {config_path}.")


@app.command("add")
def add_pattern(
    ctx: typer.Context,
    entity: str = typer.Argument(..., help="Detector entity name."),
    name: str = typer.Argument(..., help="Pattern name."),
    pattern: str = typer.Argument(..., help="Regex pattern."),
    flags: Optional[List[str]] = typer.Option(
        None,
        "--flag",
        help=f"Regex flag name for this entity's {FLAGS_KEY}. May be repeated or comma-separated.",
    ),
    force: bool = typer.Option(False, "--force", "-f", help="Replace an existing entity/name pattern."),
    config: Optional[Path] = _config_option(),
) -> None:
    """Add a detector pattern to the configured detector file."""
    config_path = _command_config_path(ctx, config)
    pattern_config = _load_command_config(config_path, allow_missing=True)
    flag_config = _flag_config(entity, config_path, flags)
    existing_pattern = entity in pattern_config and name in pattern_config[entity]
    _ensure_flag_update_allowed(pattern_config, entity, flag_config, force=force, config_path=config_path)

    try:
        updated_config = add_entity_pattern(pattern_config, entity, name, pattern, replace=force)
        updated_config = _with_entity_flags(updated_config, entity, flag_config)
    except ConfigError as exc:
        _exit_error(f"Could not add pattern {name!r} for entity {entity!r} in {config_path}: {exc}")

    _save_command_config(updated_config, config_path)
    action = "Replaced" if existing_pattern and force else "Added"
    typer.echo(f"{action} pattern {name!r} for entity {entity!r} in {config_path}.")


@app.command("list")
def list_patterns(
    ctx: typer.Context,
    entity: Optional[str] = typer.Argument(None, help="Optional detector entity name."),
    config: Optional[Path] = _config_option(),
) -> None:
    """List detector patterns in the configured detector file."""
    config_path = _command_config_path(ctx, config)
    pattern_config = _load_command_config(config_path)
    if not pattern_config:
        typer.echo(f"No detector patterns found in {config_path}.")
        return

    if entity is not None:
        if entity not in pattern_config:
            _exit_error(f"Entity {entity!r} does not exist in {config_path}.")
        _echo_entity_listing(entity, pattern_config[entity])
        return

    for entity_name, entity_config in pattern_config.items():
        _echo_entity_listing(entity_name, entity_config)


@app.command("show")
def show_pattern(
    ctx: typer.Context,
    entity: str = typer.Argument(..., help="Detector entity name."),
    name: Optional[str] = typer.Argument(None, help="Optional pattern name."),
    config: Optional[Path] = _config_option(),
) -> None:
    """Show configured detector patterns for an entity."""
    config_path = _command_config_path(ctx, config)
    pattern_config = _load_command_config(config_path)
    if entity not in pattern_config:
        _exit_error(f"Entity {entity!r} does not exist in {config_path}.")

    entity_config = pattern_config[entity]
    if name is None:
        typer.echo(_yaml_text({entity: entity_config}))
        return

    if name not in entity_config:
        _exit_error(f"Pattern {name!r} does not exist for entity {entity!r} in {config_path}.")

    selected_entity_config: Dict[str, Any] = {}
    if FLAGS_KEY in entity_config and name != FLAGS_KEY:
        selected_entity_config[FLAGS_KEY] = entity_config[FLAGS_KEY]
    selected_entity_config[name] = entity_config[name]
    typer.echo(_yaml_text({entity: selected_entity_config}))


@app.command("remove")
def remove_pattern(
    ctx: typer.Context,
    entity: str = typer.Argument(..., help="Detector entity name."),
    name: str = typer.Argument(..., help="Pattern name."),
    config: Optional[Path] = _config_option(),
) -> None:
    """Remove a detector pattern from the configured detector file."""
    config_path = _command_config_path(ctx, config)
    pattern_config = _load_command_config(config_path)
    try:
        updated_config = remove_entity_pattern(pattern_config, entity, name)
    except ConfigError as exc:
        _exit_error(f"Could not remove pattern {name!r} for entity {entity!r} from {config_path}: {exc}")

    _save_command_config(updated_config, config_path)
    typer.echo(f"Removed pattern {name!r} for entity {entity!r} from {config_path}.")


@app.command("validate")
def validate_config(
    ctx: typer.Context,
    config: Optional[Path] = _config_option(),
) -> None:
    """Validate the configured detector file."""
    config_path = _command_config_path(ctx, config)
    if not config_path.exists():
        _exit_error(f"Config file does not exist at {config_path}.")

    try:
        pattern_config = load_config(config_path)
    except ConfigError as exc:
        _exit_error(f"Config is invalid at {config_path}: {exc}")
    except OSError as exc:
        _exit_error(f"Could not read config at {config_path}: {exc}")

    pattern_count = sum(
        len([name for name in entity_config if name != FLAGS_KEY]) for entity_config in pattern_config.values()
    )
    typer.echo(f"Config is valid: {config_path} ({len(pattern_config)} entities, {pattern_count} patterns).")


def main() -> None:
    app()

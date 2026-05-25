from __future__ import annotations

# Standard library
import os
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

# Third-party
import yaml

__all__ = [
    "ConfigError",
    "DEFAULT_CONFIG_ENV_VAR",
    "DEFAULT_CONFIG_FILENAME",
    "FLAGS_KEY",
    "PatternConfig",
    "add_entity_pattern",
    "load_config",
    "load_yaml_config",
    "remove_entity_pattern",
    "resolve_default_config_path",
    "save_config",
    "validate_pattern_config",
    "validate_regex_flags",
]

DEFAULT_CONFIG_ENV_VAR = "NERB_CONFIG_PATH"
DEFAULT_CONFIG_FILENAME = "detectors.yaml"
FLAGS_KEY = "_flags"

PatternConfig = dict[str, dict[str, Any]]


class ConfigError(ValueError):
    """Raised when a detector config cannot be loaded or validated."""


def _yaml_loader():
    """Return the fastest safe YAML loader available for this PyYAML build."""
    return getattr(yaml, "CSafeLoader", yaml.SafeLoader)


def _yaml_dumper():
    """Return the fastest safe YAML dumper available for this PyYAML build."""
    return getattr(yaml, "CSafeDumper", yaml.SafeDumper)


def _default_user_config_path() -> Path:
    """Resolve the stable per-user config path when no env override is set."""
    xdg_config_home = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config_home:
        return Path(xdg_config_home).expanduser() / "nerb" / DEFAULT_CONFIG_FILENAME

    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "nerb" / DEFAULT_CONFIG_FILENAME

    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        base = Path(appdata).expanduser() if appdata else Path.home() / "AppData" / "Roaming"
        return base / "nerb" / DEFAULT_CONFIG_FILENAME

    return Path.home() / ".config" / "nerb" / DEFAULT_CONFIG_FILENAME


def resolve_default_config_path(path: str | Path | None = None, *, create: bool = False) -> Path:
    """
    Resolve the default detector config path.

    Resolution order is:
    1. the explicit ``path`` argument;
    2. the ``NERB_CONFIG_PATH`` environment variable;
    3. the platform's stable user config directory.

    When ``create`` is True, an empty config file is created if it does not already exist.
    Existing files are left untouched.
    """
    if path is not None:
        config_path = Path(path).expanduser()
    else:
        env_path = os.environ.get(DEFAULT_CONFIG_ENV_VAR)
        config_path = Path(env_path).expanduser() if env_path else _default_user_config_path()

    if create and not config_path.exists():
        save_config({}, config_path)

    return config_path


def validate_regex_flags(flags: Any) -> re.RegexFlag:
    """
    Validate regex flags from config and return a combined ``re.RegexFlag``.

    Flags can be stored as an integer bitmask, a single flag name such as ``IGNORECASE``,
    or a list of flag names/integers such as ``[IGNORECASE, MULTILINE]``.
    """
    if isinstance(flags, bool):
        raise ConfigError("Regex flags must be an integer, string, or list; booleans are not valid flags.")

    if isinstance(flags, re.RegexFlag):
        return flags

    if isinstance(flags, int):
        try:
            return re.RegexFlag(flags)
        except ValueError as exc:
            raise ConfigError(f"{flags!r} is not a valid regex flag bitmask.") from exc

    if isinstance(flags, str):
        flag_name = flags.strip()
        if flag_name.startswith("re."):
            flag_name = flag_name[3:]
        flag_name = flag_name.upper()

        if not flag_name:
            raise ConfigError("Regex flag names must not be empty.")

        flag_value = getattr(re, flag_name, None)
        if not isinstance(flag_value, int):
            raise ConfigError(f"{flags!r} is not a valid regex flag name.")

        try:
            return re.RegexFlag(flag_value)
        except ValueError as exc:
            raise ConfigError(f"{flags!r} is not a valid regex flag name.") from exc

    if isinstance(flags, list):
        combined_flags = re.RegexFlag(0)
        for flag in flags:
            combined_flags |= validate_regex_flags(flag)
        return combined_flags

    raise ConfigError("Regex flags must be an integer, string, or list.")


def validate_pattern_config(config: Any) -> PatternConfig:
    """Validate and copy a detector pattern config without mutating the caller's object."""
    if config is None:
        return {}

    if not isinstance(config, Mapping):
        raise ConfigError("Detector config must be a mapping of entity names to pattern mappings.")

    validated_config: PatternConfig = {}
    for entity, entity_config in config.items():
        if not isinstance(entity, str) or not entity:
            raise ConfigError("Entity names must be non-empty strings.")

        if not isinstance(entity_config, Mapping):
            raise ConfigError(f"Entity {entity!r} must map to pattern names and regex strings.")

        validated_entity: dict[str, Any] = {}
        pattern_count = 0
        for name, pattern in entity_config.items():
            if not isinstance(name, str) or not name:
                raise ConfigError(f"Pattern names for entity {entity!r} must be non-empty strings.")

            if name == FLAGS_KEY:
                validate_regex_flags(pattern)
                validated_entity[name] = list(pattern) if isinstance(pattern, list) else pattern
                continue

            if not isinstance(pattern, str):
                raise ConfigError(f"Pattern {name!r} for entity {entity!r} must be a regex string.")

            validated_entity[name] = pattern
            pattern_count += 1

        if pattern_count == 0:
            raise ConfigError(f"Entity {entity!r} must define at least one pattern.")

        validated_config[entity] = validated_entity

    return validated_config


def load_config(file_path: str | Path) -> PatternConfig:
    """Load and validate a detector config from YAML."""
    config_path = Path(file_path).expanduser()

    try:
        with config_path.open(encoding="utf-8") as file:
            config = yaml.load(file, Loader=_yaml_loader())
    except yaml.YAMLError as exc:
        raise ConfigError(f"Could not parse YAML config at {config_path}.") from exc

    return validate_pattern_config(config)


def load_yaml_config(file_path: str | Path) -> PatternConfig:
    """Compatibility alias for loading a detector config from YAML."""
    return load_config(file_path)


def save_config(config: Any, file_path: str | Path) -> Path:
    """Validate and save a detector config to YAML using stable insertion order."""
    config_path = Path(file_path).expanduser()
    validated_config = validate_pattern_config(config)

    config_path.parent.mkdir(parents=True, exist_ok=True)
    with config_path.open("w", encoding="utf-8") as file:
        yaml.dump(
            validated_config,
            file,
            Dumper=_yaml_dumper(),
            sort_keys=False,
            default_flow_style=False,
            allow_unicode=True,
        )

    return config_path


def add_entity_pattern(
    config: Any,
    entity: str,
    name: str,
    pattern: str,
    *,
    replace: bool = False,
) -> PatternConfig:
    """
    Return a copy of ``config`` with ``pattern`` saved under ``entity`` and ``name``.

    Duplicate names raise ``ConfigError`` by default. Pass ``replace=True`` to replace an
    existing pattern with the same entity/name pair.
    """
    if not isinstance(entity, str) or not entity:
        raise ConfigError("Entity names must be non-empty strings.")

    if not isinstance(name, str) or not name:
        raise ConfigError("Pattern names must be non-empty strings.")

    if not isinstance(pattern, str):
        raise ConfigError("Patterns must be regex strings.")

    updated_config = validate_pattern_config(config)
    entity_config = dict(updated_config.get(entity, {}))
    if name in entity_config and not replace:
        raise ConfigError(f"Pattern {name!r} already exists for entity {entity!r}.")

    entity_config[name] = pattern
    updated_config[entity] = entity_config
    return updated_config


def remove_entity_pattern(config: Any, entity: str, name: str, *, missing_ok: bool = False) -> PatternConfig:
    """
    Return a copy of ``config`` with the entity/name pattern removed.

    Missing entities or names raise ``ConfigError`` by default. Pass ``missing_ok=True`` to
    leave the config unchanged when the target pattern is absent. If the last pattern in an
    entity is removed, the entity is removed too.
    """
    updated_config = validate_pattern_config(config)

    if entity not in updated_config or name not in updated_config[entity]:
        if missing_ok:
            return updated_config
        raise ConfigError(f"Pattern {name!r} does not exist for entity {entity!r}.")

    updated_entity = dict(updated_config[entity])
    del updated_entity[name]

    if any(pattern_name != FLAGS_KEY for pattern_name in updated_entity):
        updated_config[entity] = updated_entity
    else:
        del updated_config[entity]

    return updated_config

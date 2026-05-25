from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Any, Literal, NoReturn, cast

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError

from . import __version__
from .config import (
    FLAGS_KEY,
    ConfigError,
    PatternConfig,
    add_entity_pattern,
    remove_entity_pattern,
    resolve_default_config_path,
    save_config,
    validate_pattern_config,
)
from .config import (
    load_config as load_pattern_config,
)
from .extraction import extract_named_entities_records, extract_named_entity_records
from .regex_builder import NERB

Transport = Literal["stdio", "sse", "streamable-http"]

mcp = FastMCP("NERB")


def _raise_tool_error(message: str) -> NoReturn:
    raise ToolError(message)


def _tool_config_path(config_path: str) -> Path:
    if not config_path:
        _raise_tool_error("config_path is required.")
    return resolve_default_config_path(config_path)


def _pattern_count(config: PatternConfig) -> int:
    return sum(1 for entity_config in config.values() for name in entity_config if name != FLAGS_KEY)


def _config_summary(config: PatternConfig) -> dict[str, int]:
    return {"entity_count": len(config), "pattern_count": _pattern_count(config)}


def _load_tool_config(config_path: str, *, allow_missing: bool = False) -> tuple[Path, PatternConfig]:
    path = _tool_config_path(config_path)
    if not path.exists():
        if allow_missing:
            return path, {}
        _raise_tool_error(f"Config file does not exist at {path}.")

    try:
        return path, load_pattern_config(path)
    except ConfigError as exc:
        _raise_tool_error(f"Could not load config at {path}: {exc}")
    except OSError as exc:
        _raise_tool_error(f"Could not read config at {path}: {exc}")


def _save_tool_config(config: PatternConfig, path: Path) -> PatternConfig:
    try:
        save_config(config, path)
        return config
    except ConfigError as exc:
        _raise_tool_error(f"Could not save config at {path}: {exc}")
    except OSError as exc:
        _raise_tool_error(f"Could not write config at {path}: {exc}")


def _read_text_source(text: str | None, file_path: str | None) -> tuple[str, dict[str, str]]:
    source_count = sum([text is not None, file_path is not None])
    if source_count != 1:
        _raise_tool_error("Provide exactly one input source: text or file_path.")

    if text is not None:
        return text, {"type": "text"}

    if not file_path:
        _raise_tool_error("file_path must be a non-empty string.")

    path = Path(file_path).expanduser()
    if not path.exists():
        _raise_tool_error(f"Document file does not exist at {path}.")

    if not path.is_file():
        _raise_tool_error(f"Document path is not a file: {path}.")

    try:
        return path.read_text(encoding="utf-8"), {"type": "file", "path": str(path)}
    except OSError as exc:
        _raise_tool_error(f"Could not read document at {path}: {exc}")


def _ensure_entity(pattern_config: PatternConfig, entity: str, source: str) -> None:
    if entity not in pattern_config:
        _raise_tool_error(f"Entity {entity!r} is not configured in {source}.")


def _ensure_configured_patterns(pattern_config: PatternConfig, source: str) -> None:
    if not pattern_config:
        _raise_tool_error(f"No detector patterns are configured in {source}.")


def _compile_extractor(pattern_config: PatternConfig, *, word_boundaries: bool) -> NERB:
    try:
        return NERB(pattern_config, add_word_boundaries=word_boundaries)
    except (ConfigError, re.error, ValueError) as exc:
        _raise_tool_error(f"Could not compile detectors: {exc}")


def _extract_records(
    pattern_config: PatternConfig,
    selected_entity: str | None,
    text: str,
    *,
    word_boundaries: bool,
) -> list[dict[str, Any]]:
    extractor = _compile_extractor(pattern_config, word_boundaries=word_boundaries)
    if selected_entity is None:
        return extract_named_entities_records(extractor, text)
    return extract_named_entity_records(extractor, selected_entity, text)


def _detector_records(pattern_config: PatternConfig, selected_entity: str | None = None) -> list[dict[str, str]]:
    records = []
    for entity, entity_config in pattern_config.items():
        if selected_entity is not None and entity != selected_entity:
            continue
        for name, pattern in entity_config.items():
            if name == FLAGS_KEY:
                continue
            records.append({"entity": entity, "name": name, "pattern": pattern})
    return records


def _mutation_response(action: str, path: Path, config: PatternConfig, entity: str, name: str) -> dict[str, Any]:
    return {
        "action": action,
        "path": str(path),
        "entity": entity,
        "name": name,
        **_config_summary(config),
    }


@mcp.tool()
def validate_config(config_path: str) -> dict[str, Any]:
    """Validate a detector YAML config file. Reads only the provided config_path."""
    path, pattern_config = _load_tool_config(config_path)
    return {"valid": True, "path": str(path), **_config_summary(pattern_config)}


@mcp.tool(name="load_config")
def load_config_tool(config_path: str) -> dict[str, Any]:
    """Load and validate a detector YAML config file. Reads only the provided config_path."""
    path, pattern_config = _load_tool_config(config_path)
    return {"path": str(path), "config": pattern_config, **_config_summary(pattern_config)}


@mcp.tool()
def list_detectors(config_path: str, entity: str | None = None) -> dict[str, Any]:
    """List detector patterns from a config file. Reads only the provided config_path."""
    path, pattern_config = _load_tool_config(config_path)
    if entity is not None:
        _ensure_entity(pattern_config, entity, f"config at {path}")
    detectors = _detector_records(pattern_config, selected_entity=entity)
    return {"path": str(path), "detectors": detectors, **_config_summary(pattern_config)}


@mcp.tool()
def add_detector(config_path: str, entity: str, name: str, pattern: str) -> dict[str, Any]:
    """Add one detector pattern to config_path, creating that config file if it is missing."""
    path, pattern_config = _load_tool_config(config_path, allow_missing=True)
    try:
        updated_config = add_entity_pattern(pattern_config, entity, name, pattern)
    except ConfigError as exc:
        _raise_tool_error(f"Could not add detector {entity}:{name} in {path}: {exc}")

    saved_config = _save_tool_config(updated_config, path)
    return _mutation_response("added", path, saved_config, entity, name)


@mcp.tool()
def update_detector(config_path: str, entity: str, name: str, pattern: str) -> dict[str, Any]:
    """Update an existing detector pattern in config_path."""
    path, pattern_config = _load_tool_config(config_path)
    if entity not in pattern_config or name not in pattern_config[entity] or name == FLAGS_KEY:
        _raise_tool_error(f"Pattern {name!r} does not exist for entity {entity!r} in {path}.")

    try:
        updated_config = add_entity_pattern(pattern_config, entity, name, pattern, replace=True)
    except ConfigError as exc:
        _raise_tool_error(f"Could not update detector {entity}:{name} in {path}: {exc}")

    saved_config = _save_tool_config(updated_config, path)
    return _mutation_response("updated", path, saved_config, entity, name)


@mcp.tool()
def remove_detector(config_path: str, entity: str, name: str) -> dict[str, Any]:
    """Remove one detector pattern from config_path."""
    path, pattern_config = _load_tool_config(config_path)
    try:
        updated_config = remove_entity_pattern(pattern_config, entity, name)
    except ConfigError as exc:
        _raise_tool_error(f"Could not remove detector {entity}:{name} from {path}: {exc}")

    saved_config = _save_tool_config(updated_config, path)
    return _mutation_response("removed", path, saved_config, entity, name)


@mcp.tool()
def extract_entity(
    config_path: str,
    entity: str,
    text: str | None = None,
    file_path: str | None = None,
    word_boundaries: bool = False,
) -> dict[str, Any]:
    """Extract one configured entity from provided text or an explicit document file path."""
    path, pattern_config = _load_tool_config(config_path)
    _ensure_entity(pattern_config, entity, f"config at {path}")
    document_text, source = _read_text_source(text, file_path)
    records = _extract_records(pattern_config, entity, document_text, word_boundaries=word_boundaries)
    return {
        "config_path": str(path),
        "entity": entity,
        "source": source,
        "records": records,
        "record_count": len(records),
    }


@mcp.tool()
def extract_all_entities(
    config_path: str,
    text: str | None = None,
    file_path: str | None = None,
    word_boundaries: bool = False,
) -> dict[str, Any]:
    """Extract all configured entities from provided text or an explicit document file path."""
    path, pattern_config = _load_tool_config(config_path)
    _ensure_configured_patterns(pattern_config, f"config at {path}")
    document_text, source = _read_text_source(text, file_path)
    records = _extract_records(pattern_config, None, document_text, word_boundaries=word_boundaries)
    return {
        "config_path": str(path),
        "source": source,
        "records": records,
        "record_count": len(records),
    }


@mcp.tool()
def extract_inline(
    detectors: dict[str, dict[str, Any]],
    text: str | None = None,
    file_path: str | None = None,
    entity: str | None = None,
    word_boundaries: bool = False,
) -> dict[str, Any]:
    """
    Extract from one-shot detector definitions without reading or writing a config file.

    The detectors argument uses the same mapping shape as a NERB YAML config.
    """
    try:
        pattern_config = validate_pattern_config(detectors)
    except ConfigError as exc:
        _raise_tool_error(f"Inline detector definitions are invalid: {exc}")

    _ensure_configured_patterns(pattern_config, "inline detector definitions")
    if entity is not None:
        _ensure_entity(pattern_config, entity, "inline detector definitions")

    document_text, source = _read_text_source(text, file_path)
    records = _extract_records(pattern_config, entity, document_text, word_boundaries=word_boundaries)
    return {
        "entity": entity,
        "source": source,
        "records": records,
        "record_count": len(records),
    }


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run the NERB MCP server.")
    parser.add_argument(
        "--transport",
        choices=("stdio", "sse", "streamable-http"),
        default="stdio",
        help="MCP transport to run. Defaults to stdio for local agent clients.",
    )
    parser.add_argument("--version", action="version", version=f"nerb-mcp {__version__}")
    args = parser.parse_args(argv)
    mcp.run(transport=cast(Transport, args.transport))


if __name__ == "__main__":
    main()

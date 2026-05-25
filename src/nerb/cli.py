import json
import re
import sys
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as package_version
from pathlib import Path
from typing import Any, Dict, List, NoReturn, Optional, Set, Tuple, Union

import typer
import yaml
from yaml.constructor import ConstructorError
from yaml.resolver import BaseResolver

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
from .extraction import extract_named_entities_records, extract_named_entity_records
from .regex_builder import NERB

COMMAND_ERROR_EXIT_CODE = 1
OUTPUT_FORMATS = {"json", "jsonl", "table"}
AUTHORING_OUTPUT_FORMATS = {"json", "text"}
RECORD_COLUMNS = ["entity", "name", "string", "start", "end"]
DIAGNOSTIC_ERROR = "error"
DIAGNOSTIC_WARNING = "warning"

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


def _command_config_explicit(ctx: typer.Context, config: Optional[Path]) -> bool:
    return config is not None or bool(ctx.obj and ctx.obj.get("config_explicit"))


def _normalize_format_choice(output_format: str, choices: Set[str]) -> str:
    normalized_format = output_format.lower()
    if normalized_format not in choices:
        formatted_choices = ", ".join(sorted(choices))
        _exit_error(f"Unsupported output format {output_format!r}. Expected one of: {formatted_choices}.")
    return normalized_format


def _normalize_output_format(output_format: str) -> str:
    return _normalize_format_choice(output_format, OUTPUT_FORMATS)


def _normalize_authoring_output_format(output_format: str) -> str:
    return _normalize_format_choice(output_format, AUTHORING_OUTPUT_FORMATS)


def _pattern_count(pattern_config: PatternConfig) -> int:
    return sum(len([name for name in entity_config if name != FLAGS_KEY]) for entity_config in pattern_config.values())


def _resolve_extraction_arguments(
    entity: Optional[str],
    document: Optional[Path],
    *,
    all_entities: bool,
) -> Tuple[Optional[str], Optional[Path]]:
    if all_entities:
        if entity is not None and document is None:
            return None, Path(entity)

        if entity is not None and document is not None:
            _exit_error("Do not provide ENTITY when using --all; pass only DOCUMENT, --stdin, or --text.")

        return None, document

    if entity is None:
        _exit_error("ENTITY is required unless --all is used.")

    return entity, document


def _read_extraction_text(document: Optional[Path], *, read_stdin: bool, text: Optional[str]) -> str:
    source_count = sum([document is not None, read_stdin, text is not None])
    if source_count != 1:
        _exit_error("Provide exactly one input source: DOCUMENT, --stdin, or --text.")

    if text is not None:
        return text

    if read_stdin:
        return sys.stdin.read()

    if document is None:
        _exit_error("Provide exactly one input source: DOCUMENT, --stdin, or --text.")

    if not document.exists():
        _exit_error(f"Document file does not exist at {document}.")

    if not document.is_file():
        _exit_error(f"Document path is not a file: {document}.")

    try:
        return document.read_text(encoding="utf-8")
    except OSError as exc:
        _exit_error(f"Could not read document at {document}: {exc}")


def _parse_pattern_definition(raw_value: str) -> Tuple[str, str]:
    name, separator, pattern = raw_value.partition("=")
    if not separator or not name.strip():
        _exit_error(f"Malformed --pattern value {raw_value!r}. Expected NAME=REGEX.")
    return name.strip(), pattern


def _parse_detector_definition(raw_value: str) -> Tuple[str, str, str]:
    detector_name, separator, pattern = raw_value.partition("=")
    entity, entity_separator, name = detector_name.partition(":")
    if not separator or not entity_separator or not entity.strip() or not name.strip():
        _exit_error(f"Malformed --detector value {raw_value!r}. Expected ENTITY:NAME=REGEX.")
    return entity.strip(), name.strip(), pattern


def _add_inline_pattern(config: PatternConfig, entity: str, name: str, pattern: str) -> PatternConfig:
    try:
        return add_entity_pattern(config, entity, name, pattern)
    except ConfigError as exc:
        _exit_error(f"Could not add inline detector {entity}:{name}: {exc}")


def _load_extraction_config(
    ctx: typer.Context,
    config_path: Path,
    config: Optional[Path],
    *,
    inline_patterns: List[str],
    inline_detectors: List[str],
    selected_entity: Optional[str],
) -> PatternConfig:
    if inline_patterns and selected_entity is None:
        _exit_error("--pattern requires ENTITY and cannot be used with --all.")

    has_inline_detectors = bool(inline_patterns or inline_detectors)
    config_is_required = not has_inline_detectors or config_path.exists() or _command_config_explicit(ctx, config)
    pattern_config = _load_command_config(config_path) if config_is_required else {}

    for raw_pattern in inline_patterns:
        if selected_entity is None:
            _exit_error("--pattern requires ENTITY and cannot be used with --all.")
        name, pattern = _parse_pattern_definition(raw_pattern)
        pattern_config = _add_inline_pattern(pattern_config, selected_entity, name, pattern)

    for raw_detector in inline_detectors:
        entity, name, pattern = _parse_detector_definition(raw_detector)
        pattern_config = _add_inline_pattern(pattern_config, entity, name, pattern)

    if selected_entity is not None and selected_entity not in pattern_config:
        _exit_error(f"Entity {selected_entity!r} is not configured in {config_path} or inline detectors.")

    if selected_entity is None and not pattern_config:
        _exit_error("No detector patterns are configured; pass --config or --detector.")

    return validate_pattern_config(pattern_config)


def _compile_extractor(pattern_config: PatternConfig, *, word_boundaries: bool) -> NERB:
    try:
        return NERB(pattern_config, add_word_boundaries=word_boundaries)
    except (ConfigError, re.error, ValueError) as exc:
        _exit_error(f"Could not compile detectors: {exc}")


def _extract_records(
    pattern_config: PatternConfig,
    selected_entity: Optional[str],
    text: str,
    *,
    word_boundaries: bool,
) -> List[Dict[str, Any]]:
    extractor = _compile_extractor(pattern_config, word_boundaries=word_boundaries)

    if selected_entity is None:
        return extract_named_entities_records(extractor, text)

    return extract_named_entity_records(extractor, selected_entity, text)


def _inline_detector_config(
    entity: str,
    name: str,
    pattern: str,
    *,
    flags: Optional[List[str]],
    config_path: Path,
) -> PatternConfig:
    entity_config: Dict[str, Any] = {}
    flag_config = _flag_config(entity, config_path, flags)
    if flag_config is not None:
        entity_config[FLAGS_KEY] = flag_config
    entity_config[name] = pattern

    try:
        return validate_pattern_config({entity: entity_config})
    except ConfigError as exc:
        _exit_error(f"Could not compile inline detector {entity}:{name}: {exc}")


def _saved_detector_config(pattern_config: PatternConfig, entity: str, name: str, config_path: Path) -> PatternConfig:
    if entity not in pattern_config:
        _exit_error(f"Entity {entity!r} does not exist in {config_path}.")

    entity_config = pattern_config[entity]
    if name == FLAGS_KEY or name not in entity_config:
        _exit_error(f"Pattern {name!r} does not exist for entity {entity!r} in {config_path}.")

    selected_entity_config: Dict[str, Any] = {}
    if FLAGS_KEY in entity_config:
        selected_entity_config[FLAGS_KEY] = entity_config[FLAGS_KEY]
    selected_entity_config[name] = entity_config[name]
    return validate_pattern_config({entity: selected_entity_config})


def _test_detector_config(
    config_path: Path,
    entity: str,
    name: str,
    pattern: Optional[str],
    *,
    flags: Optional[List[str]],
) -> PatternConfig:
    if pattern is not None:
        return _inline_detector_config(entity, name, pattern, flags=flags, config_path=config_path)

    if flags:
        _exit_error("--flag can only be used when testing a literal PATTERN.")

    pattern_config = _load_command_config(config_path)
    return _saved_detector_config(pattern_config, entity, name, config_path)


def _table_cell(value: Any) -> str:
    return str(value).replace("\n", "\\n").replace("\t", "\\t")


def _format_records_table(records: List[Dict[str, Any]]) -> str:
    if not records:
        return "No matches."

    rows = [[_table_cell(record[column]) for column in RECORD_COLUMNS] for record in records]
    widths = [
        max(len(RECORD_COLUMNS[index]), *(len(row[index]) for row in rows)) for index in range(len(RECORD_COLUMNS))
    ]
    header = "  ".join(column.ljust(widths[index]) for index, column in enumerate(RECORD_COLUMNS))
    separator = "  ".join("-" * widths[index] for index in range(len(RECORD_COLUMNS)))
    body = "\n".join("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)) for row in rows)
    return f"{header}\n{separator}\n{body}"


def _echo_records(records: List[Dict[str, Any]], output_format: str) -> None:
    normalized_format = _normalize_output_format(output_format)
    if normalized_format == "json":
        typer.echo(json.dumps(records, ensure_ascii=False))
        return

    if normalized_format == "jsonl":
        for record in records:
            typer.echo(json.dumps(record, ensure_ascii=False))
        return

    typer.echo(_format_records_table(records))


def _compiled_regex_payload(entity: str, entity_config: Dict[str, Any], regex: Any) -> Dict[str, Any]:
    groups = [
        {"name": group_name.replace("_", " "), "group": group_name, "index": index}
        for group_name, index in sorted(regex.groupindex.items(), key=lambda item: item[1])
    ]
    payload: Dict[str, Any] = {
        "entity": entity,
        "pattern": regex.pattern,
        "flags": int(regex.flags),
        "groups": groups,
    }
    if FLAGS_KEY in entity_config:
        payload["configured_flags"] = entity_config[FLAGS_KEY]
    return payload


def _echo_compiled_regex(
    entity: str,
    pattern_config: PatternConfig,
    output_format: str,
    *,
    config_path: Path,
    word_boundaries: bool,
) -> None:
    if entity not in pattern_config:
        _exit_error(f"Entity {entity!r} does not exist in {config_path}.")

    entity_config = pattern_config[entity]
    extractor = _compile_extractor({entity: entity_config}, word_boundaries=word_boundaries)
    regex = getattr(extractor, entity)
    normalized_format = _normalize_authoring_output_format(output_format)
    if normalized_format == "json":
        typer.echo(json.dumps(_compiled_regex_payload(entity, entity_config, regex), ensure_ascii=False))
        return

    typer.echo(regex.pattern)


def _diagnostic(
    level: str,
    code: str,
    message: str,
    *,
    entity: Optional[str] = None,
    name: Optional[str] = None,
    line: Optional[int] = None,
) -> Dict[str, Any]:
    diagnostic: Dict[str, Any] = {"level": level, "code": code, "message": message}
    if entity is not None:
        diagnostic["entity"] = entity
    if name is not None:
        diagnostic["name"] = name
    if line is not None:
        diagnostic["line"] = line
    return diagnostic


def _load_yaml_with_duplicate_diagnostics(config_path: Path) -> Tuple[Any, List[Dict[str, Any]], bool]:
    diagnostics: List[Dict[str, Any]] = []

    class DuplicateKeyLoader(yaml.SafeLoader):
        pass

    def construct_mapping(loader: Any, node: Any, deep: bool = False) -> Dict[Any, Any]:
        mapping: Dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            try:
                key_exists = key in mapping
            except TypeError as exc:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "found unhashable key",
                    key_node.start_mark,
                ) from exc

            if key_exists:
                diagnostics.append(
                    _diagnostic(
                        DIAGNOSTIC_ERROR,
                        "duplicate_yaml_key",
                        f"Duplicate YAML key {key!r}; the later value overrides an earlier value.",
                        line=key_node.start_mark.line + 1,
                    )
                )

            value = loader.construct_object(value_node, deep=deep)
            mapping[key] = value
        return mapping

    DuplicateKeyLoader.add_constructor(BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping)

    try:
        with config_path.open(encoding="utf-8") as file:
            return yaml.load(file, Loader=DuplicateKeyLoader), diagnostics, True
    except yaml.YAMLError as exc:
        diagnostics.append(
            _diagnostic(
                DIAGNOSTIC_ERROR,
                "yaml_parse_error",
                f"Could not parse YAML config at {config_path}: {exc}",
            )
        )
        return None, diagnostics, False
    except OSError as exc:
        diagnostics.append(
            _diagnostic(
                DIAGNOSTIC_ERROR,
                "read_error",
                f"Could not read config at {config_path}: {exc}",
            )
        )
        return None, diagnostics, False


def _diagnose_suspicious_names(raw_config: Any) -> List[Dict[str, Any]]:
    diagnostics: List[Dict[str, Any]] = []
    if not isinstance(raw_config, dict):
        return diagnostics

    for entity, entity_config in raw_config.items():
        if isinstance(entity, str) and entity != entity.strip():
            diagnostics.append(
                _diagnostic(
                    DIAGNOSTIC_WARNING,
                    "suspicious_entity_name",
                    f"Entity name {entity!r} has leading or trailing whitespace.",
                    entity=entity,
                )
            )

        if not isinstance(entity, str) or not isinstance(entity_config, dict):
            continue

        normalized_names: Dict[str, str] = {}
        casefolded_names: Dict[str, str] = {}
        for name in entity_config:
            if not isinstance(name, str) or name == FLAGS_KEY:
                continue

            if name != name.strip():
                diagnostics.append(
                    _diagnostic(
                        DIAGNOSTIC_WARNING,
                        "suspicious_pattern_name",
                        f"Pattern name {name!r} has leading or trailing whitespace.",
                        entity=entity,
                        name=name,
                    )
                )

            normalized_name = name.replace(" ", "_")
            previous_name = normalized_names.get(normalized_name)
            if previous_name is not None and previous_name != name:
                diagnostics.append(
                    _diagnostic(
                        DIAGNOSTIC_ERROR,
                        "duplicate_group_name",
                        f"Pattern names {previous_name!r} and {name!r} both compile to group {normalized_name!r}.",
                        entity=entity,
                        name=name,
                    )
                )
            else:
                normalized_names[normalized_name] = name

            casefolded_name = name.casefold()
            previous_case_name = casefolded_names.get(casefolded_name)
            if previous_case_name is not None and previous_case_name != name:
                diagnostics.append(
                    _diagnostic(
                        DIAGNOSTIC_WARNING,
                        "case_variant_pattern_name",
                        f"Pattern names {previous_case_name!r} and {name!r} differ only by case.",
                        entity=entity,
                        name=name,
                    )
                )
            else:
                casefolded_names[casefolded_name] = name

    return diagnostics


def _diagnose_compiled_entities(pattern_config: PatternConfig) -> List[Dict[str, Any]]:
    diagnostics: List[Dict[str, Any]] = []
    for entity, entity_config in pattern_config.items():
        try:
            NERB({entity: entity_config})
        except (ConfigError, re.error, ValueError) as exc:
            diagnostics.append(
                _diagnostic(
                    DIAGNOSTIC_ERROR,
                    "compile_error",
                    f"Entity {entity!r} could not be compiled: {exc}",
                    entity=entity,
                )
            )
    return diagnostics


def _doctor_payload(
    config_path: Path,
    pattern_config: Optional[PatternConfig],
    diagnostics: List[Dict[str, Any]],
) -> Dict[str, Any]:
    error_count = len([diagnostic for diagnostic in diagnostics if diagnostic["level"] == DIAGNOSTIC_ERROR])
    warning_count = len([diagnostic for diagnostic in diagnostics if diagnostic["level"] == DIAGNOSTIC_WARNING])
    summary_config = pattern_config or {}
    return {
        "config": str(config_path),
        "valid": error_count == 0,
        "summary": {
            "entities": len(summary_config),
            "patterns": _pattern_count(summary_config),
            "errors": error_count,
            "warnings": warning_count,
        },
        "diagnostics": diagnostics,
    }


def _format_doctor_text(payload: Dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [f"Config doctor: {payload['config']}"]
    if payload["valid"]:
        lines.append(f"OK: config is valid ({summary['entities']} entities, {summary['patterns']} patterns).")
    else:
        lines.append(f"Found {summary['errors']} errors and {summary['warnings']} warnings.")

    for diagnostic in payload["diagnostics"]:
        location = []
        if "line" in diagnostic:
            location.append(f"line {diagnostic['line']}")
        if "entity" in diagnostic:
            location.append(f"entity {diagnostic['entity']!r}")
        if "name" in diagnostic:
            location.append(f"name {diagnostic['name']!r}")
        location_text = f" ({', '.join(location)})" if location else ""
        lines.append(f"{diagnostic['level'].upper()} [{diagnostic['code']}]{location_text}: {diagnostic['message']}")

    return "\n".join(lines)


def _run_doctor(config_path: Path) -> Dict[str, Any]:
    if not config_path.exists():
        _exit_error(f"Config file does not exist at {config_path}.")

    raw_config, diagnostics, raw_config_loaded = _load_yaml_with_duplicate_diagnostics(config_path)
    if raw_config_loaded:
        diagnostics.extend(_diagnose_suspicious_names(raw_config))

    pattern_config: Optional[PatternConfig] = None
    if raw_config_loaded:
        try:
            pattern_config = load_config(config_path)
        except ConfigError as exc:
            diagnostics.append(
                _diagnostic(
                    DIAGNOSTIC_ERROR,
                    "validation_error",
                    f"Config is invalid at {config_path}: {exc}",
                )
            )
        except OSError as exc:
            diagnostics.append(
                _diagnostic(
                    DIAGNOSTIC_ERROR,
                    "read_error",
                    f"Could not read config at {config_path}: {exc}",
                )
            )

    if pattern_config is not None:
        diagnostics.extend(_diagnose_compiled_entities(pattern_config))

    return _doctor_payload(config_path, pattern_config, diagnostics)


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
    ctx.obj = {"config_path": resolve_default_config_path(config), "config_explicit": config is not None}


@app.command("extract")
def extract(
    ctx: typer.Context,
    entity: Optional[str] = typer.Argument(None, help="Detector entity name, unless --all is used."),
    document: Optional[Path] = typer.Argument(None, help="Document path to extract from."),
    all_entities: bool = typer.Option(False, "--all", help="Extract all configured detector entities."),
    read_stdin: bool = typer.Option(False, "--stdin", help="Read document text from standard input."),
    text: Optional[str] = typer.Option(None, "--text", help="Literal document text to extract from."),
    inline_patterns: Optional[List[str]] = typer.Option(
        None,
        "--pattern",
        help="Inline detector for ENTITY as NAME=REGEX. May be repeated.",
    ),
    inline_detectors: Optional[List[str]] = typer.Option(
        None,
        "--detector",
        help="Inline detector as ENTITY:NAME=REGEX. May be repeated.",
    ),
    output_format: str = typer.Option(
        "table",
        "--format",
        "-f",
        help="Output format: json, jsonl, or table.",
    ),
    word_boundaries: bool = typer.Option(
        False,
        "--word-boundaries",
        help="Add regex word boundaries around configured detector patterns.",
    ),
    config: Optional[Path] = _config_option(),
) -> None:
    """Extract configured named entities from a document."""
    selected_entity, document_path = _resolve_extraction_arguments(entity, document, all_entities=all_entities)
    document_text = _read_extraction_text(document_path, read_stdin=read_stdin, text=text)
    config_path = _command_config_path(ctx, config)
    pattern_config = _load_extraction_config(
        ctx,
        config_path,
        config,
        inline_patterns=inline_patterns or [],
        inline_detectors=inline_detectors or [],
        selected_entity=selected_entity,
    )
    records = _extract_records(pattern_config, selected_entity, document_text, word_boundaries=word_boundaries)
    _echo_records(records, output_format)


@app.command("test")
def test_detector(
    ctx: typer.Context,
    entity: str = typer.Argument(..., help="Detector entity name."),
    name: str = typer.Argument(..., help="Pattern name."),
    pattern: Optional[str] = typer.Argument(None, help="Literal regex pattern. Omit to use a saved detector."),
    document: Optional[Path] = typer.Option(None, "--document", "-d", help="Document path to test against."),
    read_stdin: bool = typer.Option(False, "--stdin", help="Read document text from standard input."),
    text: Optional[str] = typer.Option(None, "--text", help="Literal document text to test against."),
    flags: Optional[List[str]] = typer.Option(
        None,
        "--flag",
        help=f"Regex flag name for a literal PATTERN's {FLAGS_KEY}. May be repeated or comma-separated.",
    ),
    output_format: str = typer.Option(
        "table",
        "--format",
        "-f",
        help="Output format: json, jsonl, or table.",
    ),
    word_boundaries: bool = typer.Option(
        False,
        "--word-boundaries",
        help="Add regex word boundaries around the detector pattern.",
    ),
    config: Optional[Path] = _config_option(),
) -> None:
    """Test one detector against literal text, standard input, or a document."""
    document_text = _read_extraction_text(document, read_stdin=read_stdin, text=text)
    config_path = _command_config_path(ctx, config)
    pattern_config = _test_detector_config(config_path, entity, name, pattern, flags=flags)
    records = _extract_records(pattern_config, entity, document_text, word_boundaries=word_boundaries)
    _echo_records(records, output_format)


@app.command("compile")
def compile_entity(
    ctx: typer.Context,
    entity: str = typer.Argument(..., help="Detector entity name."),
    output_format: str = typer.Option("text", "--format", "-f", help="Output format: json or text."),
    word_boundaries: bool = typer.Option(
        False,
        "--word-boundaries",
        help="Add regex word boundaries before printing the compiled pattern.",
    ),
    config: Optional[Path] = _config_option(),
) -> None:
    """Print the compiled regex for one configured entity."""
    config_path = _command_config_path(ctx, config)
    pattern_config = _load_command_config(config_path)
    _echo_compiled_regex(
        pattern_config=pattern_config,
        entity=entity,
        output_format=output_format,
        config_path=config_path,
        word_boundaries=word_boundaries,
    )


@app.command("doctor")
def doctor_config(
    ctx: typer.Context,
    output_format: str = typer.Option("text", "--format", "-f", help="Output format: json or text."),
    config: Optional[Path] = _config_option(),
) -> None:
    """Validate and diagnose detector config authoring issues."""
    config_path = _command_config_path(ctx, config)
    payload = _run_doctor(config_path)
    normalized_format = _normalize_authoring_output_format(output_format)
    if normalized_format == "json":
        typer.echo(json.dumps(payload, ensure_ascii=False))
    else:
        typer.echo(_format_doctor_text(payload))

    if not payload["valid"]:
        raise typer.Exit(COMMAND_ERROR_EXIT_CODE)


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

    typer.echo(
        f"Config is valid: {config_path} ({len(pattern_config)} entities, {_pattern_count(pattern_config)} patterns)."
    )


def main() -> None:
    app()

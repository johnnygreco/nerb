import json
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as package_version
from pathlib import Path
from typing import Any, NoReturn

import typer
import yaml
from yaml.constructor import ConstructorError
from yaml.resolver import BaseResolver

from . import __version__
from .bank import (
    BankError,
    BankLoadError,
)
from .bank import (
    load_bank as _load_json_bank,
)
from .bank import (
    read_bank_json as _read_bank_json,
)
from .benchmarks import benchmark_bank as _benchmark_bank
from .benchmarks import regress_bank as _regress_bank
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
from .diagnostics import JSON_PARSE
from .diff import diff_banks as _diff_banks
from .engine import Bank
from .evals import eval_bank as _eval_bank
from .extraction import ExtractionError
from .extraction import (
    extract_file as _json_extract_file,
)
from .extraction import (
    extract_report as _json_extract_report,
)
from .extraction import (
    extract_report_file as _json_extract_report_file,
)
from .extraction import (
    extract_text as _json_extract_text,
)
from .patches import apply_bank_patches as _apply_bank_patches
from .validation import validate_bank as _validate_bank

COMMAND_ERROR_EXIT_CODE = 1
OUTPUT_FORMATS = {"json", "jsonl", "table"}
AUTHORING_OUTPUT_FORMATS = {"json", "text"}
RECORD_COLUMNS = ["entity", "canonical_name", "surface_name", "string", "start", "end", "offset_unit"]
BATCH_RECORD_COLUMNS = ["document_id", *RECORD_COLUMNS]
DIAGNOSTIC_ERROR = "error"
DIAGNOSTIC_WARNING = "warning"

app = typer.Typer(
    add_completion=False,
    context_settings={"help_option_names": ["-h", "--help"]},
    help="Build and manage named entity regex detector configs.",
    no_args_is_help=True,
    rich_markup_mode=None,
)


@dataclass(frozen=True)
class _BatchDocument:
    document_id: str
    source: dict[str, str]
    content: str | bytes


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


def _command_config_path(ctx: typer.Context, config: Path | None) -> Path:
    if config is not None:
        return resolve_default_config_path(config)

    if ctx.obj and "config_path" in ctx.obj:
        return ctx.obj["config_path"]

    return resolve_default_config_path()


def _exit_error(message: str) -> NoReturn:
    typer.echo(f"Error: {message}", err=True)
    raise typer.Exit(COMMAND_ERROR_EXIT_CODE)


def _echo_json(payload: Any) -> None:
    typer.echo(json.dumps(payload, ensure_ascii=False, sort_keys=True))


def _diagnostic_payload(message: str, diagnostics: list[dict[str, Any]], *, path: Path | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {"valid": False, "error": message, "diagnostics": diagnostics}
    if path is not None:
        payload["path"] = str(path)
    return payload


def _bank_load_error_is_json_parse(exc: BankLoadError) -> bool:
    return any(diagnostic.get("code") == JSON_PARSE for diagnostic in exc.diagnostics)


def _ensure_explicit_file(path: Path, label: str) -> Path:
    resolved_path = path.expanduser()
    if not resolved_path.exists():
        _exit_error(f"{label} file does not exist at {resolved_path}.")
    if not resolved_path.is_file():
        _exit_error(f"{label} path is not a file: {resolved_path}.")
    return resolved_path


def _load_raw_bank_json_for_command(bank_path: Path) -> tuple[Any | None, Path, dict[str, Any] | None]:
    path = _ensure_explicit_file(bank_path, "Bank")
    try:
        return _read_bank_json(path), path, None
    except BankLoadError as exc:
        if _bank_load_error_is_json_parse(exc):
            return None, path, _diagnostic_payload(str(exc), exc.diagnostics, path=path)
        _exit_error(f"Could not read bank at {path}: {exc}")


def _load_json_bank_for_command(bank_path: Path) -> tuple[Mapping[str, Any] | None, Path, dict[str, Any] | None]:
    path = _ensure_explicit_file(bank_path, "Bank")
    try:
        return _load_json_bank(path), path, None
    except BankLoadError as exc:
        if _bank_load_error_is_json_parse(exc):
            return None, path, _diagnostic_payload(str(exc), exc.diagnostics, path=path)
        _exit_error(f"Could not read bank at {path}: {exc}")
    except BankError as exc:
        return None, path, _diagnostic_payload(str(exc), exc.diagnostics, path=path)


def _load_patch_json_for_command(patch_path: Path) -> Any:
    path = _ensure_explicit_file(patch_path, "Patch")
    try:
        with path.open(encoding="utf-8") as file:
            return json.load(file)
    except json.JSONDecodeError as exc:
        _exit_error(f"Could not parse JSON patch at {path}: {exc.msg} at line {exc.lineno}, column {exc.colno}.")
    except OSError as exc:
        _exit_error(f"Could not read patch at {path}: {exc}")


def _coerce_patch_object(raw_patch: Mapping[Any, Any], label: str) -> dict[str, Any]:
    patch: dict[str, Any] = {}
    for key, value in raw_patch.items():
        if not isinstance(key, str):
            _exit_error(f"{label} keys must be strings.")
        patch[key] = value
    return patch


def _coerce_patch_sequence(raw_patch: Any) -> list[dict[str, Any]]:
    if isinstance(raw_patch, Mapping):
        return [_coerce_patch_object(raw_patch, "Patch JSON object")]

    if not isinstance(raw_patch, Sequence) or isinstance(raw_patch, (str, bytes)):
        _exit_error("Patch JSON must be an object or an array of objects.")

    patches: list[dict[str, Any]] = []
    for index, patch in enumerate(raw_patch):
        if not isinstance(patch, Mapping):
            _exit_error(f"Patch JSON item {index} must be an object.")
        patches.append(_coerce_patch_object(patch, f"Patch JSON item {index}"))
    return patches


def _read_json_bank_text_source(
    file_path: Path | None,
    *,
    read_stdin: bool,
    text: str | None,
) -> str:
    source_count = sum([file_path is not None, read_stdin, text is not None])
    if source_count != 1:
        _exit_error("Provide exactly one text source: --file, --stdin, or --text.")

    if text is not None:
        return text

    if read_stdin:
        stdin_buffer = getattr(sys.stdin, "buffer", None)
        if stdin_buffer is not None:
            stdin_bytes = stdin_buffer.read()
            try:
                return stdin_bytes.decode("utf-8")
            except UnicodeDecodeError as exc:
                _exit_error(f"Standard input is not valid UTF-8: {exc}")

        stdin_text = sys.stdin.read()
        try:
            stdin_text.encode("utf-8")
        except UnicodeEncodeError as exc:
            _exit_error(f"Standard input is not valid UTF-8: {exc}")
        return stdin_text

    if file_path is None:
        _exit_error("Provide exactly one text source: --file, --stdin, or --text.")

    path = _ensure_explicit_file(file_path, "Document")
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        _exit_error(f"Could not read document at {path}: {exc}")


def _invalid_bank_payloads_payload(payloads: dict[str, dict[str, Any] | None]) -> dict[str, Any] | None:
    invalid_payloads = {label: payload for label, payload in payloads.items() if payload is not None}
    if not invalid_payloads:
        return None

    diagnostics: list[dict[str, Any]] = []
    for label, payload in invalid_payloads.items():
        for item in payload["diagnostics"]:
            diagnostic = dict(item)
            metadata = dict(diagnostic.get("metadata", {}))
            metadata["bank"] = label
            diagnostic["metadata"] = metadata
            diagnostics.append(diagnostic)

    return {"valid": False, "banks": invalid_payloads, "diagnostics": diagnostics}


def _non_mapping_bank_payload(raw_bank: Any, path: Path, label: str) -> dict[str, Any] | None:
    if isinstance(raw_bank, Mapping):
        return None

    validation = _validate_bank(raw_bank)
    return {
        "valid": False,
        "path": str(path),
        "label": label,
        "diagnostics": validation["diagnostics"],
    }


def _run_json_helper(action: Any) -> dict[str, Any]:
    try:
        return action()
    except (ExtractionError, BankError) as exc:
        diagnostics = getattr(exc, "diagnostics", [])
        if diagnostics:
            return _diagnostic_payload(str(exc), diagnostics)
        _exit_error(str(exc))
    except (TypeError, ValueError) as exc:
        _exit_error(str(exc))


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


def _canonical_flag_names(flags: list[str]) -> list[str]:
    flag_names: list[str] = []
    seen: set[str] = set()
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


def _flag_config(entity: str, config_path: Path, flags: list[str] | None) -> str | list[str] | None:
    if not flags:
        return None

    flag_names = _canonical_flag_names(flags)
    if not flag_names:
        _exit_error(f"Invalid _flags for entity {entity!r} in {config_path}: Regex flag names must not be empty.")
    flag_config: str | list[str] = flag_names[0] if len(flag_names) == 1 else flag_names
    try:
        validate_regex_flags(flag_config)
    except ConfigError as exc:
        _exit_error(f"Invalid _flags for entity {entity!r} in {config_path}: {exc}")
    return flag_config


def _ensure_flag_update_allowed(
    config: PatternConfig,
    entity: str,
    flag_config: str | list[str] | None,
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


def _with_entity_flags(config: PatternConfig, entity: str, flag_config: str | list[str] | None) -> PatternConfig:
    if flag_config is None:
        return config

    updated_config = validate_pattern_config(config)
    entity_config: dict[str, Any] = {FLAGS_KEY: flag_config}
    for name, pattern in updated_config[entity].items():
        if name != FLAGS_KEY:
            entity_config[name] = pattern
    updated_config[entity] = entity_config
    return validate_pattern_config(updated_config)


def _format_flags(flags: Any) -> str:
    if isinstance(flags, list):
        return f"[{', '.join(str(flag) for flag in flags)}]"
    return str(flags)


def _echo_entity_listing(entity: str, entity_config: dict[str, Any]) -> None:
    typer.echo(f"{entity}:")
    if FLAGS_KEY in entity_config:
        typer.echo(f"  {FLAGS_KEY}: {_format_flags(entity_config[FLAGS_KEY])}")
    for name in entity_config:
        if name != FLAGS_KEY:
            typer.echo(f"  {name}")


def _yaml_text(config: dict[str, Any]) -> str:
    return yaml.safe_dump(config, sort_keys=False, default_flow_style=False, allow_unicode=True).rstrip()


def _command_config_explicit(ctx: typer.Context, config: Path | None) -> bool:
    return config is not None or bool(ctx.obj and ctx.obj.get("config_explicit"))


def _normalize_format_choice(output_format: str, choices: set[str]) -> str:
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
    entity: str | None,
    document: Path | None,
    *,
    all_entities: bool,
) -> tuple[str | None, Path | None]:
    if all_entities:
        if entity is not None and document is None:
            return None, Path(entity)

        if entity is not None and document is not None:
            _exit_error("Do not provide ENTITY when using --all; pass only DOCUMENT, --stdin, or --text.")

        return None, document

    if entity is None:
        _exit_error("ENTITY is required unless --all is used.")

    return entity, document


def _resolve_batch_entity(entity: str | None, *, all_entities: bool) -> str | None:
    if all_entities:
        if entity is not None:
            _exit_error("Do not provide --entity when using --all.")
        return None

    if entity is None:
        _exit_error("--entity is required unless --all is used.")
    return entity


def _read_extraction_source(document: Path | None, *, read_stdin: bool, text: str | None) -> str | bytes:
    source_count = sum([document is not None, read_stdin, text is not None])
    if source_count != 1:
        _exit_error("Provide exactly one input source: DOCUMENT, --stdin, or --text.")

    if text is not None:
        return text

    if read_stdin:
        return _read_stdin_bytes()

    if document is None:
        _exit_error("Provide exactly one input source: DOCUMENT, --stdin, or --text.")

    return _read_document_bytes(document)


def _read_stdin_bytes() -> bytes:
    stdin_buffer = getattr(sys.stdin, "buffer", None)
    if stdin_buffer is not None:
        stdin_bytes = stdin_buffer.read()
        try:
            stdin_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            _exit_error(f"Standard input is not valid UTF-8: {exc}")
        return stdin_bytes

    try:
        stdin_text = sys.stdin.read()
    except UnicodeDecodeError as exc:
        _exit_error(f"Standard input is not valid UTF-8: {exc}")
    try:
        return stdin_text.encode("utf-8")
    except UnicodeEncodeError as exc:
        _exit_error(f"Standard input is not valid UTF-8: {exc}")


def _read_document_bytes(document: Path) -> bytes:
    if not document.exists():
        _exit_error(f"Document file does not exist at {document}.")

    if not document.is_file():
        _exit_error(f"Document path is not a file: {document}.")

    try:
        document_bytes = document.read_bytes()
    except UnicodeDecodeError as exc:
        _exit_error(f"Document file is not valid UTF-8 at {document}: {exc}")
    except OSError as exc:
        _exit_error(f"Could not read document at {document}: {exc}")

    try:
        document_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        _exit_error(f"Document file is not valid UTF-8 at {document}: {exc}")
    return document_bytes


def _read_manifest_document_paths(manifest: Path) -> list[Path]:
    manifest_path = _ensure_explicit_file(manifest, "Manifest")
    try:
        manifest_text = manifest_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        _exit_error(f"Manifest file is not valid UTF-8 at {manifest_path}: {exc}")
    except OSError as exc:
        _exit_error(f"Could not read manifest at {manifest_path}: {exc}")

    document_paths = []
    for line_number, raw_line in enumerate(manifest_text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        path = Path(line).expanduser()
        if not path.is_absolute():
            path = manifest_path.parent / path
        if not path.exists():
            _exit_error(f"Manifest document path on line {line_number} does not exist at {path}.")
        if not path.is_file():
            _exit_error(f"Manifest document path on line {line_number} is not a file: {path}.")
        document_paths.append(path)
    if not document_paths:
        _exit_error(f"Manifest file at {manifest_path} does not list any document paths.")
    return document_paths


def _parse_pattern_definition(raw_value: str) -> tuple[str, str]:
    name, separator, pattern = raw_value.partition("=")
    if not separator or not name.strip():
        _exit_error(f"Malformed --pattern value {raw_value!r}. Expected NAME=REGEX.")
    return name.strip(), pattern


def _parse_detector_definition(raw_value: str) -> tuple[str, str, str]:
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
    config: Path | None,
    *,
    inline_patterns: list[str],
    inline_detectors: list[str],
    selected_entity: str | None,
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


def _compile_config_bank(
    pattern_config: PatternConfig,
    selected_entity: str | None,
    *,
    word_boundaries: bool,
) -> Bank:
    try:
        return Bank.from_config(
            pattern_config,
            selected_entity=selected_entity,
            word_boundaries=word_boundaries,
        )
    except ValueError as exc:
        _exit_error(f"Could not compile detectors with the Rust engine: {exc}")


def _scan_records(bank: Bank, source: str | bytes) -> list[dict[str, Any]]:
    try:
        if isinstance(source, bytes):
            return bank.scan_bytes(source)
        return bank.scan_text(source)
    except ValueError as exc:
        _exit_error(f"Could not scan document with the Rust engine: {exc}")


def _extract_records(
    pattern_config: PatternConfig,
    selected_entity: str | None,
    source: str | bytes,
    *,
    word_boundaries: bool,
) -> list[dict[str, Any]]:
    bank = _compile_config_bank(pattern_config, selected_entity, word_boundaries=word_boundaries)
    return _scan_records(bank, source)


def _inline_detector_config(
    entity: str,
    name: str,
    pattern: str,
    *,
    flags: list[str] | None,
    config_path: Path,
) -> PatternConfig:
    entity_config: dict[str, Any] = {}
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

    selected_entity_config: dict[str, Any] = {}
    if FLAGS_KEY in entity_config:
        selected_entity_config[FLAGS_KEY] = entity_config[FLAGS_KEY]
    selected_entity_config[name] = entity_config[name]
    return validate_pattern_config({entity: selected_entity_config})


def _test_detector_config(
    config_path: Path,
    entity: str,
    name: str,
    pattern: str | None,
    *,
    flags: list[str] | None,
) -> PatternConfig:
    if pattern is not None:
        return _inline_detector_config(entity, name, pattern, flags=flags, config_path=config_path)

    if flags:
        _exit_error("--flag can only be used when testing a literal PATTERN.")

    pattern_config = _load_command_config(config_path)
    return _saved_detector_config(pattern_config, entity, name, config_path)


def _table_cell(value: Any) -> str:
    return str(value).replace("\n", "\\n").replace("\t", "\\t")


def _format_records_table(records: list[dict[str, Any]]) -> str:
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


def _echo_records(records: list[dict[str, Any]], output_format: str) -> None:
    normalized_format = _normalize_output_format(output_format)
    if normalized_format == "json":
        typer.echo(json.dumps(records, ensure_ascii=False))
        return

    if normalized_format == "jsonl":
        for record in records:
            typer.echo(json.dumps(record, ensure_ascii=False))
        return

    typer.echo(_format_records_table(records))


def _batch_documents(
    document_paths: list[Path],
    *,
    read_stdin: bool,
    manifest: Path | None,
) -> list[_BatchDocument]:
    documents = []
    for document_path in document_paths:
        path = document_path.expanduser()
        documents.append(
            _BatchDocument(
                document_id=str(path),
                source={"type": "file", "path": str(path)},
                content=_read_document_bytes(path),
            )
        )

    if manifest is not None:
        for manifest_document_path in _read_manifest_document_paths(manifest):
            documents.append(
                _BatchDocument(
                    document_id=str(manifest_document_path),
                    source={"type": "file", "path": str(manifest_document_path)},
                    content=_read_document_bytes(manifest_document_path),
                )
            )

    if read_stdin:
        documents.append(
            _BatchDocument(
                document_id="stdin",
                source={"type": "stdin"},
                content=_read_stdin_bytes(),
            )
        )

    if not documents:
        _exit_error("Provide at least one batch input source: DOCUMENT, --manifest, or --stdin.")
    return documents


def _batch_payload(bank: Bank, documents: list[_BatchDocument]) -> dict[str, Any]:
    document_payloads = []
    record_count = 0
    for document in documents:
        records = _scan_records(bank, document.content)
        record_count += len(records)
        document_payloads.append(
            {
                "document_id": document.document_id,
                "source": document.source,
                "records": records,
                "record_count": len(records),
            }
        )

    return {
        "documents": document_payloads,
        "document_count": len(document_payloads),
        "record_count": record_count,
        "cache": bank.cache_metadata(),
    }


def _format_batch_table(payload: dict[str, Any]) -> str:
    rows = []
    for document in payload["documents"]:
        for record in document["records"]:
            rows.append(
                [
                    _table_cell(document["document_id"]),
                    *[_table_cell(record[column]) for column in RECORD_COLUMNS],
                ]
            )
    if not rows:
        return "No matches."

    widths = [
        max(len(BATCH_RECORD_COLUMNS[index]), *(len(row[index]) for row in rows))
        for index in range(len(BATCH_RECORD_COLUMNS))
    ]
    header = "  ".join(column.ljust(widths[index]) for index, column in enumerate(BATCH_RECORD_COLUMNS))
    separator = "  ".join("-" * widths[index] for index in range(len(BATCH_RECORD_COLUMNS)))
    body = "\n".join("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)) for row in rows)
    return f"{header}\n{separator}\n{body}"


def _echo_batch_payload(payload: dict[str, Any], output_format: str) -> None:
    normalized_format = _normalize_output_format(output_format)
    if normalized_format == "json":
        typer.echo(json.dumps(payload, ensure_ascii=False))
        return

    if normalized_format == "jsonl":
        for document in payload["documents"]:
            typer.echo(json.dumps(document, ensure_ascii=False))
        return

    typer.echo(_format_batch_table(payload))


def _diagnostic(
    level: str,
    code: str,
    message: str,
    *,
    entity: str | None = None,
    name: str | None = None,
    line: int | None = None,
) -> dict[str, Any]:
    diagnostic: dict[str, Any] = {"level": level, "code": code, "message": message}
    if entity is not None:
        diagnostic["entity"] = entity
    if name is not None:
        diagnostic["name"] = name
    if line is not None:
        diagnostic["line"] = line
    return diagnostic


def _load_yaml_with_duplicate_diagnostics(config_path: Path) -> tuple[Any, list[dict[str, Any]], bool]:
    diagnostics: list[dict[str, Any]] = []

    class DuplicateKeyLoader(yaml.SafeLoader):
        pass

    def construct_mapping(loader: Any, node: Any, deep: bool = False) -> dict[Any, Any]:
        mapping: dict[Any, Any] = {}
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


def _diagnose_suspicious_names(raw_config: Any) -> list[dict[str, Any]]:
    diagnostics: list[dict[str, Any]] = []
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

        casefolded_names: dict[str, str] = {}
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


def _diagnose_compiled_entities(pattern_config: PatternConfig) -> list[dict[str, Any]]:
    diagnostics: list[dict[str, Any]] = []
    for entity, entity_config in pattern_config.items():
        try:
            Bank.from_config({entity: entity_config})
        except ValueError as exc:
            diagnostics.append(
                _diagnostic(
                    DIAGNOSTIC_ERROR,
                    "compile_error",
                    f"Entity {entity!r} could not be compiled with the Rust engine: {exc}",
                    entity=entity,
                )
            )
    return diagnostics


def _doctor_payload(
    config_path: Path,
    pattern_config: PatternConfig | None,
    diagnostics: list[dict[str, Any]],
) -> dict[str, Any]:
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


def _format_doctor_text(payload: dict[str, Any]) -> str:
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


def _run_doctor(config_path: Path) -> dict[str, Any]:
    if not config_path.exists():
        _exit_error(f"Config file does not exist at {config_path}.")

    raw_config, diagnostics, raw_config_loaded = _load_yaml_with_duplicate_diagnostics(config_path)
    if raw_config_loaded:
        diagnostics.extend(_diagnose_suspicious_names(raw_config))

    pattern_config: PatternConfig | None = None
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
    version: bool | None = typer.Option(
        None,
        "--version",
        callback=_version_callback,
        help="Show the installed package version and exit.",
        is_eager=True,
    ),
    config: Path | None = typer.Option(
        None,
        "--config",
        "-c",
        help=f"Detector config path. Defaults to ${DEFAULT_CONFIG_ENV_VAR} or the platform config path.",
    ),
) -> None:
    """Build and manage named entity regex detector configs."""
    ctx.obj = {"config_path": resolve_default_config_path(config), "config_explicit": config is not None}


@app.command("validate-bank")
def validate_json_bank(
    bank_path: Path = typer.Option(..., "--bank", help="JSON bank path to validate."),
    level: str = typer.Option("standard", "--level", help="Validation level: basic, standard, or deep."),
    engine: str = typer.Option("nerb_engine", "--engine", help="Validation engine."),
    strict: bool = typer.Option(False, "--strict", help="Promote strict validation warnings where supported."),
) -> None:
    """Validate a JSON bank and print the helper response as JSON."""
    raw_bank, path, invalid_payload = _load_raw_bank_json_for_command(bank_path)
    if invalid_payload is not None:
        _echo_json(invalid_payload)
        return

    payload = _run_json_helper(
        lambda: _validate_bank(raw_bank, level=level, engine=engine, base_path=path.parent, strict=strict)
    )
    _echo_json(payload)


@app.command("apply-patches")
def apply_json_bank_patches(
    bank_path: Path = typer.Option(..., "--bank", help="JSON bank path to patch."),
    patch_path: Path = typer.Option(..., "--patch", help="JSON Patch file path."),
    level: str = typer.Option("standard", "--level", help="Validation level after applying patches."),
    engine: str = typer.Option("nerb_engine", "--engine", help="Validation engine after applying patches."),
) -> None:
    """Apply JSON Patch operations to a JSON bank and print the validated candidate."""
    bank, path, invalid_payload = _load_raw_bank_json_for_command(bank_path)
    if invalid_payload is not None:
        _echo_json(invalid_payload)
        return
    if bank is None:
        _exit_error(f"Could not load bank at {path}.")

    patches = _coerce_patch_sequence(_load_patch_json_for_command(patch_path))
    payload = _run_json_helper(
        lambda: _apply_bank_patches(bank, patches, level=level, engine=engine, base_path=path.parent)
    )
    _echo_json(payload)


@app.command("diff-banks")
def diff_json_banks(
    old_bank: Path = typer.Argument(..., help="Old JSON bank path."),
    new_bank: Path = typer.Argument(..., help="New JSON bank path."),
) -> None:
    """Diff two JSON banks and print the helper response as JSON."""
    old_raw, old_path, old_invalid = _load_raw_bank_json_for_command(old_bank)
    new_raw, new_path, new_invalid = _load_raw_bank_json_for_command(new_bank)
    invalid_payload = _invalid_bank_payloads_payload(
        {
            "old_bank": old_invalid or _non_mapping_bank_payload(old_raw, old_path, "old_bank"),
            "new_bank": new_invalid or _non_mapping_bank_payload(new_raw, new_path, "new_bank"),
        }
    )
    if invalid_payload is not None:
        _echo_json(invalid_payload)
        return
    if not isinstance(old_raw, Mapping) or not isinstance(new_raw, Mapping):
        _exit_error("diff-banks requires JSON bank objects.")

    _echo_json(_run_json_helper(lambda: _diff_banks(old_raw, new_raw)))


@app.command("extract-text")
def extract_json_bank_text(
    bank_path: Path = typer.Option(..., "--bank", help="JSON bank path."),
    text: str | None = typer.Option(None, "--text", help="Literal document text to extract from."),
    read_stdin: bool = typer.Option(False, "--stdin", help="Read document text from standard input."),
) -> None:
    """Extract from one in-memory text source using a JSON bank."""
    bank, _path, invalid_payload = _load_json_bank_for_command(bank_path)
    if invalid_payload is not None:
        _echo_json(invalid_payload)
        return
    if bank is None:
        _exit_error(f"Could not load bank at {bank_path}.")

    document_text = _read_json_bank_text_source(None, read_stdin=read_stdin, text=text)
    _echo_json(_run_json_helper(lambda: _json_extract_text(bank, document_text)))


@app.command("extract-file")
def extract_json_bank_file(
    bank_path: Path = typer.Option(..., "--bank", help="JSON bank path."),
    file_path: Path = typer.Option(..., "--file", help="UTF-8 document file path."),
) -> None:
    """Extract from one explicit document file using a JSON bank."""
    bank, _path, invalid_payload = _load_json_bank_for_command(bank_path)
    if invalid_payload is not None:
        _echo_json(invalid_payload)
        return
    if bank is None:
        _exit_error(f"Could not load bank at {bank_path}.")

    document_path = _ensure_explicit_file(file_path, "Document")
    _echo_json(_run_json_helper(lambda: _json_extract_file(bank, document_path)))


@app.command("extract-report")
def extract_json_bank_report(
    bank_path: Path = typer.Option(..., "--bank", help="JSON bank path."),
    file_path: Path | None = typer.Option(None, "--file", help="UTF-8 document file path."),
    text: str | None = typer.Option(None, "--text", help="Literal document text to report on."),
    read_stdin: bool = typer.Option(False, "--stdin", help="Read document text from standard input."),
) -> None:
    """Build a single-document extraction report from a JSON bank."""
    bank, _path, invalid_payload = _load_json_bank_for_command(bank_path)
    if invalid_payload is not None:
        _echo_json(invalid_payload)
        return
    if bank is None:
        _exit_error(f"Could not load bank at {bank_path}.")

    if file_path is not None:
        if read_stdin or text is not None:
            _exit_error("Provide exactly one text source: --file, --stdin, or --text.")
        document_path = _ensure_explicit_file(file_path, "Document")
        _echo_json(_run_json_helper(lambda: _json_extract_report_file(bank, document_path)))
        return

    document_text = _read_json_bank_text_source(None, read_stdin=read_stdin, text=text)
    _echo_json(_run_json_helper(lambda: _json_extract_report(bank, document_text)))


@app.command("eval-bank")
def eval_json_bank(
    bank_path: Path = typer.Option(..., "--bank", help="JSON bank path."),
) -> None:
    """Evaluate a JSON bank against its explicit local eval refs."""
    bank, path, invalid_payload = _load_json_bank_for_command(bank_path)
    if invalid_payload is not None:
        _echo_json(invalid_payload)
        return
    if bank is None:
        _exit_error(f"Could not load bank at {path}.")

    _echo_json(_run_json_helper(lambda: _eval_bank(bank, base_path=path.parent)))


@app.command("benchmark-bank")
def benchmark_json_bank(
    bank_path: Path = typer.Option(..., "--bank", help="JSON bank path."),
    benchmark_iterations: int | None = typer.Option(None, "--benchmark-iterations", help="Benchmark iterations."),
    stress_multiplier: int | None = typer.Option(None, "--stress-multiplier", help="Benchmark stress multiplier."),
) -> None:
    """Benchmark JSON-bank compile and extraction throughput."""
    bank, _path, invalid_payload = _load_json_bank_for_command(bank_path)
    if invalid_payload is not None:
        _echo_json(invalid_payload)
        return
    if bank is None:
        _exit_error(f"Could not load bank at {bank_path}.")

    options: dict[str, Any] = {}
    if benchmark_iterations is not None:
        options["benchmark_iterations"] = benchmark_iterations
    if stress_multiplier is not None:
        options["stress_multiplier"] = stress_multiplier
    _echo_json(_run_json_helper(lambda: _benchmark_bank(bank, options=options or None)))


@app.command("regress-bank")
def regress_json_bank(
    old_bank_path: Path = typer.Option(..., "--old-bank", help="Old JSON bank path."),
    new_bank_path: Path = typer.Option(..., "--new-bank", help="New JSON bank path."),
    benchmark_iterations: int | None = typer.Option(None, "--benchmark-iterations", help="Benchmark iterations."),
    stress_multiplier: int | None = typer.Option(None, "--stress-multiplier", help="Benchmark stress multiplier."),
) -> None:
    """Run diff, eval, and benchmark regression checks for two JSON banks."""
    old_bank, old_path, old_invalid = _load_json_bank_for_command(old_bank_path)
    new_bank, new_path, new_invalid = _load_json_bank_for_command(new_bank_path)
    invalid_payload = _invalid_bank_payloads_payload({"old_bank": old_invalid, "new_bank": new_invalid})
    if invalid_payload is not None:
        _echo_json(invalid_payload)
        return
    if old_bank is None or new_bank is None:
        _exit_error("Could not load both regression banks.")

    options: dict[str, Any] = {"old_bank_path": str(old_path), "new_bank_path": str(new_path)}
    if benchmark_iterations is not None:
        options["benchmark_iterations"] = benchmark_iterations
    if stress_multiplier is not None:
        options["stress_multiplier"] = stress_multiplier
    _echo_json(_run_json_helper(lambda: _regress_bank(old_bank, new_bank, options=options)))


@app.command("extract")
def extract(
    ctx: typer.Context,
    entity: str | None = typer.Argument(None, help="Detector entity name, unless --all is used."),
    document: Path | None = typer.Argument(None, help="Document path to extract from."),
    all_entities: bool = typer.Option(False, "--all", help="Extract all configured detector entities."),
    read_stdin: bool = typer.Option(False, "--stdin", help="Read document text from standard input."),
    text: str | None = typer.Option(None, "--text", help="Literal document text to extract from."),
    inline_patterns: list[str] | None = typer.Option(
        None,
        "--pattern",
        help="Inline detector for ENTITY as NAME=REGEX. May be repeated.",
    ),
    inline_detectors: list[str] | None = typer.Option(
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
    config: Path | None = _config_option(),
) -> None:
    """Extract configured named entities from a document."""
    selected_entity, document_path = _resolve_extraction_arguments(entity, document, all_entities=all_entities)
    document_source = _read_extraction_source(document_path, read_stdin=read_stdin, text=text)
    config_path = _command_config_path(ctx, config)
    pattern_config = _load_extraction_config(
        ctx,
        config_path,
        config,
        inline_patterns=inline_patterns or [],
        inline_detectors=inline_detectors or [],
        selected_entity=selected_entity,
    )
    records = _extract_records(pattern_config, selected_entity, document_source, word_boundaries=word_boundaries)
    _echo_records(records, output_format)


@app.command("extract-batch")
def extract_batch(
    ctx: typer.Context,
    documents: list[Path] | None = typer.Argument(None, help="Explicit document paths to scan in order."),
    entity: str | None = typer.Option(None, "--entity", "-e", help="Detector entity name, unless --all is used."),
    all_entities: bool = typer.Option(False, "--all", help="Extract all configured detector entities."),
    manifest: Path | None = typer.Option(None, "--manifest", help="UTF-8 file listing one document path per line."),
    read_stdin: bool = typer.Option(False, "--stdin", help="Read one batch document from standard input."),
    inline_patterns: list[str] | None = typer.Option(
        None,
        "--pattern",
        help="Inline detector for --entity as NAME=REGEX. May be repeated.",
    ),
    inline_detectors: list[str] | None = typer.Option(
        None,
        "--detector",
        help="Inline detector as ENTITY:NAME=REGEX. May be repeated.",
    ),
    output_format: str = typer.Option(
        "json",
        "--format",
        "-f",
        help="Output format: json, jsonl, or table.",
    ),
    word_boundaries: bool = typer.Option(
        False,
        "--word-boundaries",
        help="Add regex word boundaries around configured detector patterns.",
    ),
    config: Path | None = _config_option(),
) -> None:
    """Extract configured named entities from multiple explicit documents."""
    selected_entity = _resolve_batch_entity(entity, all_entities=all_entities)
    config_path = _command_config_path(ctx, config)
    pattern_config = _load_extraction_config(
        ctx,
        config_path,
        config,
        inline_patterns=inline_patterns or [],
        inline_detectors=inline_detectors or [],
        selected_entity=selected_entity,
    )
    bank = _compile_config_bank(pattern_config, selected_entity, word_boundaries=word_boundaries)
    payload = _batch_payload(
        bank,
        _batch_documents(documents or [], read_stdin=read_stdin, manifest=manifest),
    )
    _echo_batch_payload(payload, output_format)


@app.command("test")
def test_detector(
    ctx: typer.Context,
    entity: str = typer.Argument(..., help="Detector entity name."),
    name: str = typer.Argument(..., help="Pattern name."),
    pattern: str | None = typer.Argument(None, help="Literal regex pattern. Omit to use a saved detector."),
    document: Path | None = typer.Option(None, "--document", "-d", help="Document path to test against."),
    read_stdin: bool = typer.Option(False, "--stdin", help="Read document text from standard input."),
    text: str | None = typer.Option(None, "--text", help="Literal document text to test against."),
    flags: list[str] | None = typer.Option(
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
    config: Path | None = _config_option(),
) -> None:
    """Test one detector against literal text, standard input, or a document."""
    document_source = _read_extraction_source(document, read_stdin=read_stdin, text=text)
    config_path = _command_config_path(ctx, config)
    pattern_config = _test_detector_config(config_path, entity, name, pattern, flags=flags)
    records = _extract_records(pattern_config, entity, document_source, word_boundaries=word_boundaries)
    _echo_records(records, output_format)


@app.command("doctor")
def doctor_config(
    ctx: typer.Context,
    output_format: str = typer.Option("text", "--format", "-f", help="Output format: json or text."),
    config: Path | None = _config_option(),
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
    config: Path | None = _config_option(),
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
    flags: list[str] | None = typer.Option(
        None,
        "--flag",
        help=f"Regex flag name for this entity's {FLAGS_KEY}. May be repeated or comma-separated.",
    ),
    force: bool = typer.Option(False, "--force", "-f", help="Replace an existing entity/name pattern."),
    config: Path | None = _config_option(),
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
    entity: str | None = typer.Argument(None, help="Optional detector entity name."),
    config: Path | None = _config_option(),
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
    name: str | None = typer.Argument(None, help="Optional pattern name."),
    config: Path | None = _config_option(),
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

    selected_entity_config: dict[str, Any] = {}
    if FLAGS_KEY in entity_config and name != FLAGS_KEY:
        selected_entity_config[FLAGS_KEY] = entity_config[FLAGS_KEY]
    selected_entity_config[name] = entity_config[name]
    typer.echo(_yaml_text({entity: selected_entity_config}))


@app.command("remove")
def remove_pattern(
    ctx: typer.Context,
    entity: str = typer.Argument(..., help="Detector entity name."),
    name: str = typer.Argument(..., help="Pattern name."),
    config: Path | None = _config_option(),
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
    config: Path | None = _config_option(),
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

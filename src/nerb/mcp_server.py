from __future__ import annotations

import argparse
import importlib
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Literal, NoReturn, cast

from pydantic import ConfigDict, with_config
from typing_extensions import TypedDict

from . import __version__
from .bank import (
    BankError,
    BankLoadError,
)
from .bank import (
    bank_stats as _json_bank_stats,
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
    FLAGS_KEY,
    ConfigError,
    PatternConfig,
    add_entity_pattern,
    ensure_rust_config_compatible,
    remove_entity_pattern,
    resolve_default_config_path,
    save_config,
    validate_pattern_config,
)
from .config import (
    load_config as load_pattern_config,
)
from .deanonymization import (
    DeanonymizationError,
    _anonymize_config_file_with_db_update,
    _anonymize_config_text_with_db_update,
    _anonymize_file_with_db_update,
    _anonymize_text_with_db_update,
)
from .deanonymization import (
    deanonymize_file as _deanonymize_file,
)
from .deanonymization import (
    deanonymize_text as _deanonymize_text,
)
from .deanonymization import (
    finalize_replacement_db_update as _finalize_replacement_db_update,
)
from .diagnostics import DIAGNOSTIC_ERROR, JSON_PARSE
from .diff import diff_banks as _diff_banks
from .engine import Bank
from .engine import bank_cache_info as _bank_cache_info
from .engine import clear_bank_cache as _clear_bank_cache
from .engines import DEFAULT_MAX_TEXT_BYTES
from .evals import eval_bank as _eval_bank
from .extraction import ExtractionError
from .extraction import (
    explain_match as _json_explain_match,
)
from .extraction import (
    extract_batch as _json_extract_batch,
)
from .extraction import (
    extract_file as _json_extract_file,
)
from .extraction import (
    extract_report as _json_extract_report,
)
from .extraction import (
    extract_report_batch as _json_extract_report_batch,
)
from .extraction import (
    extract_report_file as _json_extract_report_file,
)
from .extraction import (
    extract_text as _json_extract_text,
)
from .patches import apply_bank_patches as _apply_bank_patches
from .replacements import ReplacementDbError
from .replacements import (
    create_replacement_db as _create_replacement_db,
)
from .replacements import (
    hash_replacement_db as _hash_replacement_db,
)
from .replacements import (
    load_replacement_db as _load_replacement_db,
)
from .replacements import (
    sanitize_replacement_db_diagnostics as _sanitize_replacement_db_diagnostics,
)
from .replacements import (
    save_replacement_db as _save_replacement_db,
)
from .replacements import (
    validate_replacement_db as _validate_replacement_db,
)
from .validation import rust_empty_match_diagnostics
from .validation import validate_bank as _validate_bank

Transport = Literal["stdio", "sse", "streamable-http"]
MCP_PYTHON_REQUIRES = (3, 10)
MCP_UNAVAILABLE_MESSAGE = (
    "NERB MCP support requires Python 3.10 or newer and the MCP SDK dependency. "
    "Install NERB with the current package metadata on Python 3.10 or newer."
)


@with_config(ConfigDict(extra="forbid"))
class _ReplacementDbSaveOptions(TypedDict, total=False):
    expected_replacement_db_hash: str
    expected_version: int
    include_sensitive_metadata: bool


class _AnonymizeSaveOptions(_ReplacementDbSaveOptions, total=False):
    save: bool
    word_boundaries: bool
    mode: str
    include_originals: bool
    on_missing_assignment: str
    source_surface_limit: int
    include_statuses: Sequence[str]
    engine: str
    engine_options: Mapping[str, Any]
    max_text_bytes: int
    max_batch_documents: int
    max_batch_text_bytes: int


class NerbMcpUnavailableError(RuntimeError):
    """Raised when MCP tools are used where the MCP SDK is unavailable."""


class _UnavailableMcp:
    """Import-safe stand-in used on Python versions unsupported by the MCP SDK."""

    def tool(self, *args: Any, **kwargs: Any) -> Any:
        def decorator(func: Any) -> Any:
            return func

        return decorator

    def run(self, *args: Any, **kwargs: Any) -> NoReturn:
        raise NerbMcpUnavailableError(MCP_UNAVAILABLE_MESSAGE)


def _load_mcp_sdk() -> tuple[Any, type[Exception]]:
    if sys.version_info < MCP_PYTHON_REQUIRES:
        return _UnavailableMcp(), NerbMcpUnavailableError

    try:
        fastmcp_module = importlib.import_module("mcp.server.fastmcp")
        exceptions_module = importlib.import_module("mcp.server.fastmcp.exceptions")
    except ImportError:
        return _UnavailableMcp(), NerbMcpUnavailableError

    return fastmcp_module.FastMCP("NERB"), exceptions_module.ToolError


mcp, _ToolError = _load_mcp_sdk()


def _raise_tool_error(message: str) -> NoReturn:
    raise _ToolError(message)


def _diagnostic_payload(message: str, diagnostics: list[dict[str, Any]], *, path: Path | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {"valid": False, "error": message, "diagnostics": diagnostics}
    if path is not None:
        payload["path"] = str(path)
    return payload


def _bank_load_error_is_json_parse(exc: BankLoadError) -> bool:
    return any(diagnostic.get("code") == JSON_PARSE for diagnostic in exc.diagnostics)


def _ensure_explicit_file(path_value: str, label: str) -> Path:
    if not path_value:
        _raise_tool_error(f"{label.lower()}_path must be a non-empty string.")
    path = Path(path_value).expanduser()
    if not path.exists():
        _raise_tool_error(f"{label} file does not exist at {path}.")
    if not path.is_file():
        _raise_tool_error(f"{label} path is not a file: {path}.")
    return path


def _load_raw_bank_json_for_tool(bank_path: str) -> tuple[Any | None, Path, dict[str, Any] | None]:
    path = _ensure_explicit_file(bank_path, "Bank")
    try:
        return _read_bank_json(path), path, None
    except BankLoadError as exc:
        if _bank_load_error_is_json_parse(exc):
            return None, path, _diagnostic_payload(str(exc), exc.diagnostics, path=path)
        _raise_tool_error(f"Could not read bank at {path}: {exc}")


def _load_json_bank_for_tool(bank_path: str) -> tuple[Mapping[str, Any] | None, Path, dict[str, Any] | None]:
    path = _ensure_explicit_file(bank_path, "Bank")
    try:
        return _load_json_bank(path), path, None
    except BankLoadError as exc:
        if _bank_load_error_is_json_parse(exc):
            return None, path, _diagnostic_payload(str(exc), exc.diagnostics, path=path)
        _raise_tool_error(f"Could not read bank at {path}: {exc}")
    except BankError as exc:
        return None, path, _diagnostic_payload(str(exc), exc.diagnostics, path=path)


def _resolve_bank_source(
    bank: Any | None,
    bank_path: str | None,
    *,
    base_path: str | None = None,
    raw: bool = False,
) -> tuple[Any | None, Path | None, Path | None, dict[str, Any] | None]:
    has_bank = bank is not None
    has_bank_path = bank_path is not None
    if has_bank == has_bank_path:
        _raise_tool_error("Provide exactly one bank source: bank or bank_path.")

    if bank_path is not None:
        loaded_bank, path, invalid_payload = (
            _load_raw_bank_json_for_tool(bank_path) if raw else _load_json_bank_for_tool(bank_path)
        )
        return loaded_bank, path, path.parent, invalid_payload

    resolved_base_path = Path(base_path).expanduser() if base_path is not None else None
    return bank, None, resolved_base_path, None


def _mapping_bank_or_payload(bank: Any, label: str) -> tuple[Mapping[str, Any] | None, dict[str, Any] | None]:
    if isinstance(bank, Mapping):
        return bank, None
    validation = _validate_bank(bank)
    return None, {"valid": False, "label": label, "diagnostics": validation["diagnostics"]}


def _load_patch_json_for_tool(patch_path: str) -> Any:
    path = _ensure_explicit_file(patch_path, "Patch")
    try:
        with path.open(encoding="utf-8") as file:
            return json.load(file)
    except json.JSONDecodeError as exc:
        _raise_tool_error(f"Could not parse JSON patch at {path}: {exc.msg} at line {exc.lineno}, column {exc.colno}.")
    except OSError as exc:
        _raise_tool_error(f"Could not read patch at {path}: {exc}")


def _coerce_patch_object(raw_patch: Mapping[Any, Any], label: str) -> dict[str, Any]:
    patch: dict[str, Any] = {}
    for key, value in raw_patch.items():
        if not isinstance(key, str):
            _raise_tool_error(f"{label} keys must be strings.")
        patch[key] = value
    return patch


def _resolve_patch_source(patches: Any | None, patch_path: str | None) -> list[dict[str, Any]]:
    has_patches = patches is not None
    has_patch_path = patch_path is not None
    if has_patches == has_patch_path:
        _raise_tool_error("Provide exactly one patch source: patches or patch_path.")

    raw_patch = _load_patch_json_for_tool(patch_path) if patch_path is not None else patches
    if isinstance(raw_patch, Mapping):
        return [_coerce_patch_object(raw_patch, "Patch JSON object")]
    if not isinstance(raw_patch, Sequence) or isinstance(raw_patch, (str, bytes)):
        _raise_tool_error("Patch JSON must be an object or an array of objects.")

    patch_operations: list[dict[str, Any]] = []
    for index, patch in enumerate(raw_patch):
        if not isinstance(patch, Mapping):
            _raise_tool_error(f"Patch JSON item {index} must be an object.")
        patch_operations.append(_coerce_patch_object(patch, f"Patch JSON item {index}"))
    return patch_operations


def _read_json_text_source(text: str | None, file_path: str | None) -> str:
    source_count = sum([text is not None, file_path is not None])
    if source_count != 1:
        _raise_tool_error("Provide exactly one text source: text or file_path.")

    if text is not None:
        return text

    if file_path is None:
        _raise_tool_error("Provide exactly one text source: text or file_path.")

    path = _ensure_explicit_file(file_path, "Document")
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        _raise_tool_error(f"Could not read document at {path}: {exc}")


def _document_sequence(documents: Any) -> Sequence[Mapping[str, Any]]:
    if isinstance(documents, (str, bytes)) or not isinstance(documents, Sequence):
        _raise_tool_error("documents must be an array of explicit document objects.")
    if not all(isinstance(document, Mapping) for document in documents):
        _raise_tool_error("documents must be an array of explicit document objects.")
    return cast(Sequence[Mapping[str, Any]], documents)


def _options_mapping(options: Mapping[str, Any] | None) -> dict[str, Any]:
    if options is None:
        return {}
    if not isinstance(options, Mapping):
        _raise_tool_error("options must be an object.")
    return dict(options)


def _invalid_bank_payloads_payload(payloads: Mapping[str, dict[str, Any] | None]) -> dict[str, Any] | None:
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


def _sanitize_bank_diagnostics_for_anonymize(
    diagnostics: list[dict[str, Any]],
    *,
    include_sensitive_metadata: bool,
) -> list[dict[str, Any]]:
    if include_sensitive_metadata:
        return [dict(item) for item in diagnostics]
    sanitized: list[dict[str, Any]] = []
    for item in diagnostics:
        diagnostic = {
            key: json.loads(json.dumps(value, ensure_ascii=False)) for key, value in item.items() if key != "metadata"
        }
        diagnostic["path"] = "/bank"
        code = diagnostic.get("code")
        if isinstance(code, str) and code.startswith(("schema.", "id.", "metadata.", "engine.", "regex.")):
            diagnostic["message"] = "Bank diagnostic details are redacted by default."
        sanitized.append(diagnostic)
    return sanitized


def _sanitize_invalid_bank_payload_for_anonymize(
    payload: dict[str, Any],
    *,
    include_sensitive_metadata: bool,
) -> dict[str, Any]:
    if include_sensitive_metadata:
        return payload
    sanitized = dict(payload)
    diagnostics = sanitized.get("diagnostics")
    if isinstance(diagnostics, list):
        sanitized["diagnostics"] = _sanitize_bank_diagnostics_for_anonymize(
            diagnostics,
            include_sensitive_metadata=False,
        )
    if "error" in sanitized:
        sanitized["error"] = "Bank diagnostic details are redacted by default."
    return sanitized


def _run_json_tool(action: Any) -> dict[str, Any]:
    try:
        return action()
    except (ExtractionError, BankError, DeanonymizationError, ReplacementDbError) as exc:
        diagnostics = getattr(exc, "diagnostics", [])
        if diagnostics:
            return _diagnostic_payload(str(exc), diagnostics)
        _raise_tool_error(str(exc))
    except (TypeError, ValueError) as exc:
        diagnostics = getattr(exc, "diagnostics", [])
        if diagnostics:
            return _diagnostic_payload(str(exc), diagnostics)
        _raise_tool_error(str(exc))


def _replacement_db_diagnostic_payload(
    message: str,
    diagnostics: list[dict[str, Any]],
    *,
    path: Path | None = None,
    include_sensitive_metadata: bool = False,
) -> dict[str, Any]:
    return _diagnostic_payload(
        message if include_sensitive_metadata else "Replacement database command failed.",
        _sanitize_replacement_db_diagnostics(
            diagnostics,
            include_sensitive_metadata=include_sensitive_metadata,
        ),
        path=path,
    )


def _replacement_db_stale_write_payload(
    path: Path,
    *,
    include_sensitive_metadata: bool = False,
) -> dict[str, Any]:
    diagnostic = {
        "severity": DIAGNOSTIC_ERROR,
        "code": "replacement_db.stale_write",
        "path": "",
        "message": "Existing replacement database destinations require expected_replacement_db_hash.",
    }
    return _replacement_db_diagnostic_payload(
        f"Replacement database {str(path)!r} already exists.",
        [diagnostic],
        path=path,
        include_sensitive_metadata=include_sensitive_metadata,
    )


def _tool_bool_option(options: Mapping[str, Any], key: str, default: bool = False) -> bool:
    value = options.get(key, default)
    if not isinstance(value, bool):
        _raise_tool_error(f"options.{key} must be a boolean.")
    return value


def _tool_string_option(options: Mapping[str, Any], key: str) -> str | None:
    value = options.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        _raise_tool_error(f"options.{key} must be a non-empty string.")
    return value


def _tool_int_option(options: Mapping[str, Any], key: str) -> int | None:
    value = options.get(key)
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool):
        _raise_tool_error(f"options.{key} must be an integer.")
    return value


def _same_path(left: Path, right: Path) -> bool:
    return left.expanduser().resolve(strict=False) == right.expanduser().resolve(strict=False)


def _replacement_db_version(replacement_db: Mapping[str, Any]) -> int:
    version = replacement_db.get("version")
    if not isinstance(version, int) or isinstance(version, bool):
        _raise_tool_error("Replacement database version must be an integer.")
    return version


def _replacement_db_metadata(
    replacement_db: Mapping[str, Any],
    *,
    path: Path | None = None,
    saved: bool | None = None,
    include_sensitive_metadata: bool = False,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "replacement_db_ref": "rdb1",
        "schema_version": replacement_db.get("schema_version"),
        "version": replacement_db.get("version"),
    }
    if path is not None:
        payload["path"] = str(path)
    if saved is not None:
        payload["saved"] = saved
    if include_sensitive_metadata:
        payload["id"] = replacement_db.get("id")
        payload["hash"] = _hash_replacement_db(replacement_db)
    return payload


def _validate_replacement_db_payload(
    replacement_db: Any,
    *,
    path: Path | None = None,
    include_sensitive_metadata: bool = False,
) -> dict[str, Any]:
    result = _validate_replacement_db(replacement_db)
    payload: dict[str, Any] = {
        "valid": result["valid"],
        "diagnostics": _sanitize_replacement_db_diagnostics(
            result["diagnostics"],
            include_sensitive_metadata=include_sensitive_metadata,
        ),
    }
    if path is not None:
        payload["path"] = str(path)
    if isinstance(replacement_db, Mapping):
        payload["replacement_db"] = _replacement_db_metadata(
            replacement_db,
            path=path,
            include_sensitive_metadata=include_sensitive_metadata,
        )
    return payload


def _resolve_replacement_db_source(
    replacement_db: Any | None,
    replacement_db_path: str | None,
    *,
    include_sensitive_metadata: bool = False,
) -> tuple[Mapping[str, Any] | None, Path | None, dict[str, Any] | None]:
    has_db = replacement_db is not None
    has_db_path = replacement_db_path is not None
    if has_db == has_db_path:
        _raise_tool_error("Provide exactly one replacement database source: replacement_db or replacement_db_path.")

    if replacement_db_path is not None:
        path = Path(replacement_db_path).expanduser()
        try:
            return _load_replacement_db(path), path, None
        except ReplacementDbError as exc:
            return (
                None,
                path,
                _replacement_db_diagnostic_payload(
                    str(exc),
                    exc.diagnostics,
                    path=path,
                    include_sensitive_metadata=include_sensitive_metadata,
                ),
            )

    if not isinstance(replacement_db, Mapping):
        return (
            None,
            None,
            _validate_replacement_db_payload(
                replacement_db,
                include_sensitive_metadata=include_sensitive_metadata,
            ),
        )

    validation = _validate_replacement_db_payload(
        replacement_db,
        include_sensitive_metadata=include_sensitive_metadata,
    )
    if validation["valid"] is False:
        return None, None, validation
    return replacement_db, None, None


def _save_options(options: Mapping[str, Any] | None) -> tuple[dict[str, Any], bool, str | None, int | None, bool]:
    resolved = _options_mapping(options)
    save = _tool_bool_option(resolved, "save", False)
    expected_replacement_db_hash = _tool_string_option(resolved, "expected_replacement_db_hash")
    expected_version = _tool_int_option(resolved, "expected_version")
    include_sensitive_metadata = _tool_bool_option(resolved, "include_sensitive_metadata", False)
    return resolved, save, expected_replacement_db_hash, expected_version, include_sensitive_metadata


def _operation_options(options: Mapping[str, Any]) -> dict[str, Any]:
    operation_options = dict(options)
    operation_options.pop("save", None)
    operation_options.pop("expected_replacement_db_hash", None)
    operation_options.pop("expected_version", None)
    return operation_options


def _save_replacement_db_for_tool(
    replacement_db: Mapping[str, Any],
    save_db_path: str,
    *,
    options: Mapping[str, Any] | None = None,
    source_path: Path | None = None,
    source_hash: str | None = None,
    source_version: int | None = None,
) -> dict[str, Any]:
    if not save_db_path:
        _raise_tool_error("save_db_path must be a non-empty string.")

    save_path = Path(save_db_path).expanduser()
    resolved_options, _save, expected_replacement_db_hash, expected_version, include_sensitive_metadata = _save_options(
        options
    )
    if expected_replacement_db_hash is None and source_path is not None and _same_path(source_path, save_path):
        expected_replacement_db_hash = source_hash
        if expected_version is None:
            expected_version = source_version
    require_missing = False
    if save_path.is_file() and expected_replacement_db_hash is None:
        return _replacement_db_stale_write_payload(
            save_path,
            include_sensitive_metadata=include_sensitive_metadata,
        )
    elif source_path is None and expected_replacement_db_hash is None:
        require_missing = True

    try:
        saved_path = _save_replacement_db(
            replacement_db,
            save_path,
            expected_hash=expected_replacement_db_hash,
            expected_version=expected_version,
            require_missing=require_missing,
        )
        saved_db = _load_replacement_db(saved_path)
    except ReplacementDbError as exc:
        return _replacement_db_diagnostic_payload(
            str(exc),
            exc.diagnostics,
            path=save_path,
            include_sensitive_metadata=include_sensitive_metadata,
        )

    response_options: dict[str, Any] = {
        "expected_version": expected_version,
        "save": bool(resolved_options.get("save", False)),
        "stale_guard": "hash" if expected_replacement_db_hash is not None else "missing_destination",
    }
    if include_sensitive_metadata and expected_replacement_db_hash is not None:
        response_options["expected_replacement_db_hash"] = expected_replacement_db_hash
    response = {
        "saved": True,
        "path": str(saved_path),
        "replacement_db": _replacement_db_metadata(
            saved_db,
            path=saved_path,
            saved=True,
            include_sensitive_metadata=include_sensitive_metadata,
        ),
        "diagnostics": [],
        "options": response_options,
    }
    return response


def _saved_anonymize_payload_for_tool(
    action: Any,
    replacement_db: Mapping[str, Any],
    *,
    replacement_db_path: Path | None,
    save_db_path: str | None,
    options: Mapping[str, Any] | None,
) -> dict[str, Any]:
    (
        resolved_options,
        save,
        _expected_replacement_db_hash,
        _expected_version,
        include_sensitive_metadata,
    ) = _save_options(options)
    if save and save_db_path is None:
        _raise_tool_error("options.save requires save_db_path.")
    if save_db_path is not None and not save:
        _raise_tool_error("save_db_path writes require options.save to be true.")

    operation_options = _operation_options(resolved_options)
    base_hash = _hash_replacement_db(replacement_db)
    base_version = _replacement_db_version(replacement_db)
    response, updated_db = action(operation_options)

    replacement_db_metadata = response.get("replacement_db", {})
    modified = bool(replacement_db_metadata.get("modified")) if isinstance(replacement_db_metadata, Mapping) else False
    if not save or not modified:
        return response

    if not isinstance(updated_db, Mapping):
        return _diagnostic_payload(
            "Anonymization did not return an updated replacement database for saving.",
            [
                {
                    "severity": DIAGNOSTIC_ERROR,
                    "code": "replacement_db.save_error",
                    "path": "/replacement_db",
                    "message": "Anonymization did not return an updated replacement database for saving.",
                }
            ],
        )

    try:
        finalized = _finalize_replacement_db_update(updated_db, base_version=base_version)
    except DeanonymizationError as exc:
        return _replacement_db_diagnostic_payload(
            str(exc),
            exc.diagnostics,
            include_sensitive_metadata=include_sensitive_metadata,
        )

    if save_db_path is None:
        _raise_tool_error("options.save requires save_db_path.")
    save_result = _save_replacement_db_for_tool(
        finalized,
        save_db_path,
        options=resolved_options,
        source_path=replacement_db_path,
        source_hash=base_hash,
        source_version=base_version,
    )
    if save_result.get("saved") is not True:
        return save_result

    saved_db = _load_replacement_db(str(save_db_path))
    if isinstance(replacement_db_metadata, dict):
        replacement_db_metadata["version"] = saved_db.get("version")
        replacement_db_metadata["saved"] = True
        if include_sensitive_metadata:
            replacement_db_metadata["data"] = saved_db
            replacement_db_metadata["hash"] = _hash_replacement_db(saved_db)
            replacement_db_metadata["id"] = saved_db.get("id")
        else:
            replacement_db_metadata.pop("data", None)
            replacement_db_metadata.pop("hash", None)
            replacement_db_metadata.pop("id", None)
    return response


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


def _read_text_source(text: str | None, file_path: str | None) -> tuple[str | bytes, dict[str, str]]:
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
        document_size = path.stat().st_size
    except OSError as exc:
        _raise_tool_error(f"Could not inspect document at {path}: {exc}")
    if document_size > DEFAULT_MAX_TEXT_BYTES:
        _raise_tool_error(f"Document file exceeds the configured limit of {DEFAULT_MAX_TEXT_BYTES} bytes at {path}.")

    try:
        with path.open("rb") as file:
            document_bytes = file.read(DEFAULT_MAX_TEXT_BYTES + 1)
    except OSError as exc:
        _raise_tool_error(f"Could not read document at {path}: {exc}")
    if len(document_bytes) > DEFAULT_MAX_TEXT_BYTES:
        _raise_tool_error(f"Document file exceeds the configured limit of {DEFAULT_MAX_TEXT_BYTES} bytes at {path}.")

    try:
        document_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        _raise_tool_error(f"Document file is not valid UTF-8 at {path}: {exc}")
    return document_bytes, {"type": "file", "path": str(path)}


def _ensure_entity(pattern_config: PatternConfig, entity: str, source: str) -> None:
    if entity not in pattern_config:
        _raise_tool_error(f"Entity {entity!r} is not configured in {source}.")


def _ensure_configured_patterns(pattern_config: PatternConfig, source: str) -> None:
    if not pattern_config:
        _raise_tool_error(f"No detector patterns are configured in {source}.")


def _load_anonymize_tool_config(config_path: str, selected_entity: str | None) -> tuple[Path, PatternConfig]:
    path, pattern_config = _load_tool_config(config_path)
    if selected_entity is not None:
        _ensure_entity(pattern_config, selected_entity, f"config at {path}")
    _ensure_configured_patterns(pattern_config, f"config at {path}")
    return path, pattern_config


def _compile_config_bank(
    pattern_config: PatternConfig,
    selected_entity: str | None,
    *,
    word_boundaries: bool,
) -> Bank:
    try:
        bank = Bank.from_config(
            pattern_config,
            selected_entity=selected_entity,
            word_boundaries=word_boundaries,
        )
    except ValueError as exc:
        _raise_tool_error(f"Could not compile detectors with the Rust engine: {exc}")
    diagnostics = rust_empty_match_diagnostics(bank)
    if diagnostics:
        _raise_tool_error(f"Could not compile detectors with the Rust engine: {diagnostics[0]['message']}")
    return bank


def _scan_records(bank: Bank, source: str | bytes) -> list[dict[str, Any]]:
    try:
        if isinstance(source, bytes):
            return bank.scan_bytes(source)
        return bank.scan_text(source)
    except ValueError as exc:
        _raise_tool_error(f"Could not scan document with the Rust engine: {exc}")


def _extract_records_with_cache(
    pattern_config: PatternConfig,
    selected_entity: str | None,
    source: str | bytes,
    *,
    word_boundaries: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    bank = _compile_config_bank(pattern_config, selected_entity, word_boundaries=word_boundaries)
    return _scan_records(bank, source), bank.cache_metadata()


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
def create_replacement_db(
    db_id: str = "replacements",
    description: str = "",
    reversible: bool = False,
    store_originals: bool | None = None,
    assignment_scope: str = "name",
) -> dict[str, Any]:
    """Create an unsaved replacement database object without filesystem writes."""
    if assignment_scope not in {"name", "canonical", "surface"}:
        _raise_tool_error("assignment_scope must be 'name', 'canonical', or 'surface'.")
    return {
        "saved": False,
        "replacement_db": _create_replacement_db(
            db_id=db_id,
            description=description,
            reversible=reversible,
            store_originals=store_originals,
            assignment_scope=assignment_scope,
        ),
    }


@mcp.tool()
def validate_replacement_db(
    replacement_db: Any | None = None,
    replacement_db_path: str | None = None,
    options: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate a replacement database from a direct object or explicit replacement_db_path."""
    resolved_options = _options_mapping(options)
    include_sensitive_metadata = _tool_bool_option(resolved_options, "include_sensitive_metadata", False)

    if replacement_db_path is not None and replacement_db is not None:
        _raise_tool_error("Provide exactly one replacement database source: replacement_db or replacement_db_path.")
    if replacement_db_path is None and replacement_db is None:
        _raise_tool_error("Provide exactly one replacement database source: replacement_db or replacement_db_path.")

    if replacement_db_path is not None:
        path = Path(replacement_db_path).expanduser()
        try:
            loaded = _load_replacement_db(path)
        except ReplacementDbError as exc:
            return _replacement_db_diagnostic_payload(
                str(exc),
                exc.diagnostics,
                path=path,
                include_sensitive_metadata=include_sensitive_metadata,
            )
        return _validate_replacement_db_payload(
            loaded,
            path=path,
            include_sensitive_metadata=include_sensitive_metadata,
        )

    return _validate_replacement_db_payload(
        replacement_db,
        include_sensitive_metadata=include_sensitive_metadata,
    )


@mcp.tool()
def save_replacement_db(
    replacement_db: Any | None = None,
    replacement_db_path: str | None = None,
    save_db_path: str = "",
    options: _ReplacementDbSaveOptions | None = None,
) -> dict[str, Any]:
    """Save a replacement database only to explicit save_db_path with stale-write protection."""
    resolved_options = _options_mapping(options)
    include_sensitive_metadata = _tool_bool_option(resolved_options, "include_sensitive_metadata", False)
    db, source_path, invalid_payload = _resolve_replacement_db_source(
        replacement_db,
        replacement_db_path,
        include_sensitive_metadata=include_sensitive_metadata,
    )
    if invalid_payload is not None:
        return invalid_payload
    if db is None:
        _raise_tool_error("save_replacement_db requires a valid replacement database object.")

    return _save_replacement_db_for_tool(
        db,
        save_db_path,
        options=resolved_options,
        source_path=source_path,
        source_hash=_hash_replacement_db(db) if source_path is not None else None,
        source_version=_replacement_db_version(db) if source_path is not None else None,
    )


@mcp.tool()
def anonymize_text(
    text: str,
    bank: Any | None = None,
    bank_path: str | None = None,
    replacement_db: Any | None = None,
    replacement_db_path: str | None = None,
    save_db_path: str | None = None,
    options: _AnonymizeSaveOptions | None = None,
) -> dict[str, Any]:
    """Anonymize text with a JSON bank and optional explicit replacement DB save."""
    resolved_options = _options_mapping(options)
    include_sensitive_metadata = _tool_bool_option(resolved_options, "include_sensitive_metadata", False)
    bank_value, _bank_path, _base_path, invalid_bank_payload = _resolve_bank_source(bank, bank_path)
    if invalid_bank_payload is not None:
        return _sanitize_invalid_bank_payload_for_anonymize(
            invalid_bank_payload,
            include_sensitive_metadata=include_sensitive_metadata,
        )
    bank_mapping, mapping_invalid = _mapping_bank_or_payload(bank_value, "bank")
    if mapping_invalid is not None:
        return _sanitize_invalid_bank_payload_for_anonymize(
            mapping_invalid,
            include_sensitive_metadata=include_sensitive_metadata,
        )
    if bank_mapping is None:
        _raise_tool_error("anonymize_text requires a JSON bank object.")

    db, db_path, invalid_db_payload = _resolve_replacement_db_source(
        replacement_db,
        replacement_db_path,
        include_sensitive_metadata=include_sensitive_metadata,
    )
    if invalid_db_payload is not None:
        return invalid_db_payload
    if db is None:
        _raise_tool_error("anonymize_text requires a valid replacement database object.")

    return _run_json_tool(
        lambda: _saved_anonymize_payload_for_tool(
            lambda resolved_operation_options: _anonymize_text_with_db_update(
                bank_mapping,
                text,
                db,
                options=resolved_operation_options,
            ),
            db,
            replacement_db_path=db_path,
            save_db_path=save_db_path,
            options=resolved_options,
        )
    )


@mcp.tool()
def anonymize_file(
    file_path: str,
    bank: Any | None = None,
    bank_path: str | None = None,
    replacement_db: Any | None = None,
    replacement_db_path: str | None = None,
    save_db_path: str | None = None,
    options: _AnonymizeSaveOptions | None = None,
) -> dict[str, Any]:
    """Anonymize one explicit UTF-8 file with a JSON bank and optional explicit replacement DB save."""
    resolved_options = _options_mapping(options)
    include_sensitive_metadata = _tool_bool_option(resolved_options, "include_sensitive_metadata", False)
    bank_value, _bank_path, _base_path, invalid_bank_payload = _resolve_bank_source(bank, bank_path)
    if invalid_bank_payload is not None:
        return _sanitize_invalid_bank_payload_for_anonymize(
            invalid_bank_payload,
            include_sensitive_metadata=include_sensitive_metadata,
        )
    bank_mapping, mapping_invalid = _mapping_bank_or_payload(bank_value, "bank")
    if mapping_invalid is not None:
        return _sanitize_invalid_bank_payload_for_anonymize(
            mapping_invalid,
            include_sensitive_metadata=include_sensitive_metadata,
        )
    if bank_mapping is None:
        _raise_tool_error("anonymize_file requires a JSON bank object.")

    document_path = _ensure_explicit_file(file_path, "Document")
    db, db_path, invalid_db_payload = _resolve_replacement_db_source(
        replacement_db,
        replacement_db_path,
        include_sensitive_metadata=include_sensitive_metadata,
    )
    if invalid_db_payload is not None:
        return invalid_db_payload
    if db is None:
        _raise_tool_error("anonymize_file requires a valid replacement database object.")

    return _run_json_tool(
        lambda: _saved_anonymize_payload_for_tool(
            lambda resolved_operation_options: _anonymize_file_with_db_update(
                bank_mapping,
                document_path,
                db,
                options=resolved_operation_options,
            ),
            db,
            replacement_db_path=db_path,
            save_db_path=save_db_path,
            options=resolved_options,
        )
    )


@mcp.tool()
def anonymize_config_text(
    text: str,
    config_path: str,
    entity: str | None = None,
    replacement_db: Any | None = None,
    replacement_db_path: str | None = None,
    save_db_path: str | None = None,
    options: _AnonymizeSaveOptions | None = None,
) -> dict[str, Any]:
    """Anonymize text with a YAML detector config and optional explicit replacement DB save."""
    resolved_options = _options_mapping(options)
    include_sensitive_metadata = _tool_bool_option(resolved_options, "include_sensitive_metadata", False)
    word_boundaries = _tool_bool_option(resolved_options, "word_boundaries", False)
    _config_path, pattern_config = _load_anonymize_tool_config(config_path, entity)
    db, db_path, invalid_db_payload = _resolve_replacement_db_source(
        replacement_db,
        replacement_db_path,
        include_sensitive_metadata=include_sensitive_metadata,
    )
    if invalid_db_payload is not None:
        return invalid_db_payload
    if db is None:
        _raise_tool_error("anonymize_config_text requires a valid replacement database object.")

    return _run_json_tool(
        lambda: _saved_anonymize_payload_for_tool(
            lambda resolved_operation_options: _anonymize_config_text_with_db_update(
                pattern_config,
                text,
                db,
                selected_entity=entity,
                word_boundaries=word_boundaries,
                options=resolved_operation_options,
            ),
            db,
            replacement_db_path=db_path,
            save_db_path=save_db_path,
            options=resolved_options,
        )
    )


@mcp.tool()
def anonymize_config_file(
    file_path: str,
    config_path: str,
    entity: str | None = None,
    replacement_db: Any | None = None,
    replacement_db_path: str | None = None,
    save_db_path: str | None = None,
    options: _AnonymizeSaveOptions | None = None,
) -> dict[str, Any]:
    """Anonymize one explicit UTF-8 file with a YAML detector config and optional explicit replacement DB save."""
    resolved_options = _options_mapping(options)
    include_sensitive_metadata = _tool_bool_option(resolved_options, "include_sensitive_metadata", False)
    word_boundaries = _tool_bool_option(resolved_options, "word_boundaries", False)
    _config_path, pattern_config = _load_anonymize_tool_config(config_path, entity)
    document_path = _ensure_explicit_file(file_path, "Document")
    db, db_path, invalid_db_payload = _resolve_replacement_db_source(
        replacement_db,
        replacement_db_path,
        include_sensitive_metadata=include_sensitive_metadata,
    )
    if invalid_db_payload is not None:
        return invalid_db_payload
    if db is None:
        _raise_tool_error("anonymize_config_file requires a valid replacement database object.")

    return _run_json_tool(
        lambda: _saved_anonymize_payload_for_tool(
            lambda resolved_operation_options: _anonymize_config_file_with_db_update(
                pattern_config,
                document_path,
                db,
                selected_entity=entity,
                word_boundaries=word_boundaries,
                options=resolved_operation_options,
            ),
            db,
            replacement_db_path=db_path,
            save_db_path=save_db_path,
            options=resolved_options,
        )
    )


@mcp.tool()
def deanonymize_text(
    text: str,
    replacement_db: Any | None = None,
    replacement_db_path: str | None = None,
    options: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Restore redaction tokens, and optionally pseudonyms, from text."""
    resolved_options = _options_mapping(options)
    include_sensitive_metadata = _tool_bool_option(resolved_options, "include_sensitive_metadata", False)
    db, _db_path, invalid_db_payload = _resolve_replacement_db_source(
        replacement_db,
        replacement_db_path,
        include_sensitive_metadata=include_sensitive_metadata,
    )
    if invalid_db_payload is not None:
        return invalid_db_payload
    if db is None:
        _raise_tool_error("deanonymize_text requires a valid replacement database object.")

    return _run_json_tool(lambda: _deanonymize_text(text, db, options=resolved_options))


@mcp.tool()
def deanonymize_file(
    file_path: str,
    replacement_db: Any | None = None,
    replacement_db_path: str | None = None,
    options: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Restore redaction tokens, and optionally pseudonyms, from one explicit UTF-8 file."""
    document_path = _ensure_explicit_file(file_path, "Document")
    resolved_options = _options_mapping(options)
    include_sensitive_metadata = _tool_bool_option(resolved_options, "include_sensitive_metadata", False)
    db, _db_path, invalid_db_payload = _resolve_replacement_db_source(
        replacement_db,
        replacement_db_path,
        include_sensitive_metadata=include_sensitive_metadata,
    )
    if invalid_db_payload is not None:
        return invalid_db_payload
    if db is None:
        _raise_tool_error("deanonymize_file requires a valid replacement database object.")

    return _run_json_tool(lambda: _deanonymize_file(document_path, db, options=resolved_options))


@mcp.tool()
def validate_config(config_path: str) -> dict[str, Any]:
    """Validate a detector YAML config file. Reads only the provided config_path."""
    path, pattern_config = _load_tool_config(config_path)
    try:
        ensure_rust_config_compatible(pattern_config)
    except ConfigError as exc:
        _raise_tool_error(f"Config is invalid at {path}: {exc}")
    return {"valid": True, "path": str(path), **_config_summary(pattern_config)}


@mcp.tool(name="load_config")
def load_config_tool(config_path: str) -> dict[str, Any]:
    """Load and validate a detector YAML config file. Reads only the provided config_path."""
    path, pattern_config = _load_tool_config(config_path)
    return {"path": str(path), "config": pattern_config, **_config_summary(pattern_config)}


@mcp.tool()
def engine_cache_info() -> dict[str, Any]:
    """Return process-local Rust Bank cache diagnostics."""
    return _bank_cache_info()


@mcp.tool()
def clear_engine_cache() -> dict[str, Any]:
    """Clear the process-local Rust Bank cache and return the empty diagnostics."""
    _clear_bank_cache()
    return {"cleared": True, "cache": _bank_cache_info()}


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
    document_source, source = _read_text_source(text, file_path)
    records, cache = _extract_records_with_cache(
        pattern_config,
        entity,
        document_source,
        word_boundaries=word_boundaries,
    )
    return {
        "config_path": str(path),
        "entity": entity,
        "source": source,
        "records": records,
        "record_count": len(records),
        "cache": cache,
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
    document_source, source = _read_text_source(text, file_path)
    records, cache = _extract_records_with_cache(
        pattern_config,
        None,
        document_source,
        word_boundaries=word_boundaries,
    )
    return {
        "config_path": str(path),
        "source": source,
        "records": records,
        "record_count": len(records),
        "cache": cache,
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

    document_source, source = _read_text_source(text, file_path)
    records, cache = _extract_records_with_cache(
        pattern_config,
        entity,
        document_source,
        word_boundaries=word_boundaries,
    )
    return {
        "entity": entity,
        "source": source,
        "records": records,
        "record_count": len(records),
        "cache": cache,
    }


@mcp.tool()
def validate_bank(
    bank: Any | None = None,
    bank_path: str | None = None,
    level: str = "standard",
    engine: str = "nerb_engine",
    base_path: str | None = None,
    strict: bool = False,
) -> dict[str, Any]:
    """Validate a JSON bank from a direct object or explicit bank_path."""
    bank_value, _path, resolved_base_path, invalid_payload = _resolve_bank_source(
        bank,
        bank_path,
        base_path=base_path,
        raw=True,
    )
    if invalid_payload is not None:
        return invalid_payload

    return _run_json_tool(
        lambda: _validate_bank(
            bank_value,
            level=level,
            engine=engine,
            base_path=resolved_base_path,
            strict=strict,
        )
    )


@mcp.tool()
def apply_bank_patches(
    bank: Any | None = None,
    bank_path: str | None = None,
    patches: Any | None = None,
    patch_path: str | None = None,
    level: str = "standard",
    engine: str = "nerb_engine",
    base_path: str | None = None,
) -> dict[str, Any]:
    """Apply explicit JSON Patch operations to a JSON bank and validate the candidate."""
    bank_value, _path, resolved_base_path, invalid_payload = _resolve_bank_source(
        bank,
        bank_path,
        base_path=base_path,
        raw=True,
    )
    if invalid_payload is not None:
        return invalid_payload

    patch_operations = _resolve_patch_source(patches, patch_path)
    return _run_json_tool(
        lambda: _apply_bank_patches(
            bank_value,
            patch_operations,
            level=level,
            engine=engine,
            base_path=resolved_base_path,
        )
    )


@mcp.tool()
def diff_banks(
    old_bank: Any | None = None,
    new_bank: Any | None = None,
    old_bank_path: str | None = None,
    new_bank_path: str | None = None,
) -> dict[str, Any]:
    """Diff two JSON banks from direct objects or explicit bank paths."""
    old_value, _old_path, _old_base_path, old_invalid = _resolve_bank_source(old_bank, old_bank_path, raw=True)
    new_value, _new_path, _new_base_path, new_invalid = _resolve_bank_source(new_bank, new_bank_path, raw=True)
    old_mapping, old_mapping_invalid = _mapping_bank_or_payload(old_value, "old_bank")
    new_mapping, new_mapping_invalid = _mapping_bank_or_payload(new_value, "new_bank")
    invalid_payload = _invalid_bank_payloads_payload(
        {"old_bank": old_invalid or old_mapping_invalid, "new_bank": new_invalid or new_mapping_invalid}
    )
    if invalid_payload is not None:
        return invalid_payload
    if old_mapping is None or new_mapping is None:
        _raise_tool_error("diff_banks requires JSON bank objects.")

    return _run_json_tool(lambda: _diff_banks(old_mapping, new_mapping))


@mcp.tool()
def bank_stats(
    bank: Any | None = None,
    bank_path: str | None = None,
    include_engine: bool = False,
    engine: str = "nerb_engine",
) -> dict[str, Any]:
    """Return JSON-bank structural counts without compiling patterns."""
    bank_value, _path, _base_path, invalid_payload = _resolve_bank_source(bank, bank_path, raw=True)
    if invalid_payload is not None:
        return invalid_payload
    bank_mapping, mapping_invalid = _mapping_bank_or_payload(bank_value, "bank")
    if mapping_invalid is not None:
        return mapping_invalid
    if bank_mapping is None:
        _raise_tool_error("bank_stats requires a JSON bank object.")

    return _run_json_tool(lambda: _json_bank_stats(bank_mapping, include_engine=include_engine, engine=engine))


@mcp.tool()
def extract_text(
    text: str | None = None,
    file_path: str | None = None,
    bank: Any | None = None,
    bank_path: str | None = None,
    options: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Extract JSON-bank records from exactly one text document or explicit file_path."""
    bank_value, _path, _base_path, invalid_payload = _resolve_bank_source(bank, bank_path)
    if invalid_payload is not None:
        return invalid_payload
    bank_mapping, mapping_invalid = _mapping_bank_or_payload(bank_value, "bank")
    if mapping_invalid is not None:
        return mapping_invalid
    if bank_mapping is None:
        _raise_tool_error("extract_text requires a JSON bank object.")

    if file_path is not None:
        if text is not None:
            _raise_tool_error("Provide exactly one text source: text or file_path.")
        document_path = _ensure_explicit_file(file_path, "Document")
        return _run_json_tool(
            lambda: _json_extract_file(bank_mapping, document_path, options=_options_mapping(options))
        )

    if text is None:
        _raise_tool_error("Provide exactly one text source: text or file_path.")

    return _run_json_tool(lambda: _json_extract_text(bank_mapping, text, options=_options_mapping(options)))


@mcp.tool()
def extract_file(
    file_path: str,
    bank: Any | None = None,
    bank_path: str | None = None,
    options: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Extract JSON-bank records from one explicit UTF-8 document file."""
    bank_value, _path, _base_path, invalid_payload = _resolve_bank_source(bank, bank_path)
    if invalid_payload is not None:
        return invalid_payload
    bank_mapping, mapping_invalid = _mapping_bank_or_payload(bank_value, "bank")
    if mapping_invalid is not None:
        return mapping_invalid
    if bank_mapping is None:
        _raise_tool_error("extract_file requires a JSON bank object.")

    document_path = _ensure_explicit_file(file_path, "Document")
    return _run_json_tool(lambda: _json_extract_file(bank_mapping, document_path, options=_options_mapping(options)))


@mcp.tool()
def extract_batch(
    documents: Any,
    bank: Any | None = None,
    bank_path: str | None = None,
    options: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Extract JSON-bank records from explicit document objects only."""
    bank_value, _path, _base_path, invalid_payload = _resolve_bank_source(bank, bank_path)
    if invalid_payload is not None:
        return invalid_payload
    bank_mapping, mapping_invalid = _mapping_bank_or_payload(bank_value, "bank")
    if mapping_invalid is not None:
        return mapping_invalid
    if bank_mapping is None:
        _raise_tool_error("extract_batch requires a JSON bank object.")

    return _run_json_tool(
        lambda: _json_extract_batch(bank_mapping, _document_sequence(documents), options=_options_mapping(options))
    )


@mcp.tool()
def extract_report(
    bank: Any | None = None,
    bank_path: str | None = None,
    text: str | None = None,
    file_path: str | None = None,
    options: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a single-document extraction report from text or an explicit file_path."""
    bank_value, _path, _base_path, invalid_payload = _resolve_bank_source(bank, bank_path)
    if invalid_payload is not None:
        return invalid_payload
    bank_mapping, mapping_invalid = _mapping_bank_or_payload(bank_value, "bank")
    if mapping_invalid is not None:
        return mapping_invalid
    if bank_mapping is None:
        _raise_tool_error("extract_report requires a JSON bank object.")

    if file_path is not None:
        if text is not None:
            _raise_tool_error("Provide exactly one text source: text or file_path.")
        document_path = _ensure_explicit_file(file_path, "Document")
        return _run_json_tool(
            lambda: _json_extract_report_file(bank_mapping, document_path, options=_options_mapping(options))
        )

    document_text = _read_json_text_source(text, None)
    return _run_json_tool(lambda: _json_extract_report(bank_mapping, document_text, options=_options_mapping(options)))


@mcp.tool()
def extract_report_batch(
    documents: Any,
    bank: Any | None = None,
    bank_path: str | None = None,
    options: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return extraction reports for explicit document objects only."""
    bank_value, _path, _base_path, invalid_payload = _resolve_bank_source(bank, bank_path)
    if invalid_payload is not None:
        return invalid_payload
    bank_mapping, mapping_invalid = _mapping_bank_or_payload(bank_value, "bank")
    if mapping_invalid is not None:
        return mapping_invalid
    if bank_mapping is None:
        _raise_tool_error("extract_report_batch requires a JSON bank object.")

    return _run_json_tool(
        lambda: _json_extract_report_batch(
            bank_mapping,
            _document_sequence(documents),
            options=_options_mapping(options),
        )
    )


@mcp.tool()
def eval_bank(
    bank: Any | None = None,
    bank_path: str | None = None,
    base_path: str | None = None,
    options: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Evaluate a JSON bank against its explicit local eval_refs."""
    bank_value, _path, resolved_base_path, invalid_payload = _resolve_bank_source(
        bank,
        bank_path,
        base_path=base_path,
    )
    if invalid_payload is not None:
        return invalid_payload
    bank_mapping, mapping_invalid = _mapping_bank_or_payload(bank_value, "bank")
    if mapping_invalid is not None:
        return mapping_invalid
    if bank_mapping is None:
        _raise_tool_error("eval_bank requires a JSON bank object.")

    return _run_json_tool(
        lambda: _eval_bank(bank_mapping, base_path=resolved_base_path, options=_options_mapping(options))
    )


@mcp.tool()
def benchmark_bank(
    bank: Any | None = None,
    bank_path: str | None = None,
    documents: Any | None = None,
    options: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Benchmark JSON-bank compile and extraction throughput."""
    bank_value, _path, _base_path, invalid_payload = _resolve_bank_source(bank, bank_path)
    if invalid_payload is not None:
        return invalid_payload
    bank_mapping, mapping_invalid = _mapping_bank_or_payload(bank_value, "bank")
    if mapping_invalid is not None:
        return mapping_invalid
    if bank_mapping is None:
        _raise_tool_error("benchmark_bank requires a JSON bank object.")

    return _run_json_tool(lambda: _benchmark_bank(bank_mapping, documents=documents, options=_options_mapping(options)))


@mcp.tool()
def explain_match(
    entity_id: str,
    name_id: str,
    pattern_id: str,
    bank: Any | None = None,
    bank_path: str | None = None,
    options: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Explain one configured JSON-bank pattern without scanning text."""
    bank_value, _path, _base_path, invalid_payload = _resolve_bank_source(bank, bank_path)
    if invalid_payload is not None:
        return invalid_payload
    bank_mapping, mapping_invalid = _mapping_bank_or_payload(bank_value, "bank")
    if mapping_invalid is not None:
        return mapping_invalid
    if bank_mapping is None:
        _raise_tool_error("explain_match requires a JSON bank object.")

    return _run_json_tool(
        lambda: _json_explain_match(
            bank_mapping,
            entity_id,
            name_id,
            pattern_id,
            options=_options_mapping(options),
        )
    )


@mcp.tool()
def regress_bank(
    old_bank: Any | None = None,
    new_bank: Any | None = None,
    old_bank_path: str | None = None,
    new_bank_path: str | None = None,
    base_path: str | None = None,
    options: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Run diff, eval, and benchmark regression checks for two JSON banks."""
    old_value, old_path, old_base_path, old_invalid = _resolve_bank_source(
        old_bank,
        old_bank_path,
        base_path=base_path,
    )
    new_value, new_path, new_base_path, new_invalid = _resolve_bank_source(
        new_bank,
        new_bank_path,
        base_path=base_path,
    )
    old_mapping, old_mapping_invalid = _mapping_bank_or_payload(old_value, "old_bank")
    new_mapping, new_mapping_invalid = _mapping_bank_or_payload(new_value, "new_bank")
    invalid_payload = _invalid_bank_payloads_payload(
        {"old_bank": old_invalid or old_mapping_invalid, "new_bank": new_invalid or new_mapping_invalid}
    )
    if invalid_payload is not None:
        return invalid_payload
    if old_mapping is None or new_mapping is None:
        _raise_tool_error("regress_bank requires JSON bank objects.")

    regression_options = _options_mapping(options)
    if old_path is not None:
        regression_options["old_bank_path"] = str(old_path)
    elif old_base_path is not None:
        regression_options["old_base_path"] = str(old_base_path)
    if new_path is not None:
        regression_options["new_bank_path"] = str(new_path)
    elif new_base_path is not None:
        regression_options["new_base_path"] = str(new_base_path)

    return _run_json_tool(lambda: _regress_bank(old_mapping, new_mapping, options=regression_options))


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
    if isinstance(mcp, _UnavailableMcp):
        print(f"Error: {MCP_UNAVAILABLE_MESSAGE}", file=sys.stderr)
        raise SystemExit(1)

    mcp.run(transport=cast(Transport, args.transport))


if __name__ == "__main__":
    main()

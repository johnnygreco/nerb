from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

from .diagnostics import DIAGNOSTIC_ERROR, JSON_PARSE, SCHEMA_TYPE, Diagnostic, diagnostic, has_errors
from .replacements_schema import (
    REPLACEMENT_DB_SCHEMA_VERSION,
    validate_replacement_db_schema,
)

MAX_REPLACEMENT_DB_BYTES = 10 * 1024 * 1024
ASSIGNMENT_KEY_RE = re.compile(
    r"^(?P<entity>[a-z][a-z0-9_]{0,79})\|(?P<scope>name|canonical|surface)\|sha256:[0-9a-f]{64}$"
)
FINGERPRINT_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

__all__ = [
    "MAX_REPLACEMENT_DB_BYTES",
    "ReplacementDbError",
    "ReplacementDbLoadError",
    "ReplacementDbSaveError",
    "ReplacementDbSchemaError",
    "canonicalize_replacement_db",
    "create_replacement_db",
    "hash_replacement_db",
    "load_replacement_db",
    "read_replacement_db_json",
    "save_replacement_db",
    "validate_replacement_db",
]


class ReplacementDbError(ValueError):
    """Base error for replacement database loading and validation failures."""

    def __init__(self, message: str, diagnostics: list[Diagnostic] | None = None) -> None:
        super().__init__(message)
        self.diagnostics = diagnostics or []


class ReplacementDbLoadError(ReplacementDbError):
    """Raised when a replacement database cannot be read or parsed as JSON."""


class ReplacementDbSchemaError(ReplacementDbError):
    """Raised when a replacement database does not satisfy schema or semantic validation."""


class ReplacementDbSaveError(ReplacementDbError):
    """Raised when a replacement database cannot be saved safely."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def create_replacement_db(
    *,
    db_id: str = "replacements",
    description: str = "",
    reversible: bool = False,
    store_originals: bool | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    """Create a minimal replacement database object without writing it to disk."""
    timestamp = now or _utc_now()
    should_store_originals = reversible if store_originals is None else store_originals
    replacement_db: dict[str, Any] = {
        "schema_version": REPLACEMENT_DB_SCHEMA_VERSION,
        "id": db_id,
        "description": description,
        "version": 1,
        "created_at": timestamp,
        "updated_at": timestamp,
        "metadata": {},
        "defaults": {
            "unicode_normalization": "NFC",
            "assignment_scope": "name",
            "replacement_mode": "redact",
            "redaction_template": "[{ENTITY}_{ordinal:04d}]",
            "collision_policy": "error",
            "store_originals": should_store_originals,
            "allow_new_assignments": True,
        },
        "entities": {},
        "replacement_sets": {},
        "assignments": {},
    }
    _raise_if_invalid(replacement_db, label="replacement database")
    return replacement_db


def _resolve_local_path(path: str | Path) -> Path:
    raw_path = os.fspath(path)
    if "://" in raw_path or raw_path.startswith("file:"):
        diagnostic_item = diagnostic(
            DIAGNOSTIC_ERROR,
            "replacement_db.path_not_local",
            "",
            f"Replacement database path {raw_path!r} must be an explicit local filesystem path.",
        )
        raise ReplacementDbLoadError("Replacement database path must be local.", [diagnostic_item])
    return Path(path).expanduser()


def read_replacement_db_json(path: str | Path) -> Any:
    """Read JSON from an explicit replacement database path without applying schema validation."""
    db_path = _resolve_local_path(path)
    try:
        stat_result = db_path.stat()
    except OSError as exc:
        load_diagnostic = diagnostic(
            DIAGNOSTIC_ERROR,
            "replacement_db.load_error",
            "",
            f"Could not read replacement database {str(db_path)!r}: {exc}.",
        )
        raise ReplacementDbLoadError(
            f"Could not read replacement database {str(db_path)!r}.", [load_diagnostic]
        ) from exc

    if not db_path.is_file():
        file_diagnostic = diagnostic(
            DIAGNOSTIC_ERROR,
            "replacement_db.not_file",
            "",
            f"Replacement database path {str(db_path)!r} must be a regular file.",
        )
        raise ReplacementDbLoadError(f"Replacement database path {str(db_path)!r} must be a file.", [file_diagnostic])

    if stat_result.st_size > MAX_REPLACEMENT_DB_BYTES:
        size_diagnostic = diagnostic(
            DIAGNOSTIC_ERROR,
            "replacement_db.too_large",
            "",
            f"Replacement database {str(db_path)!r} exceeds the {MAX_REPLACEMENT_DB_BYTES} byte limit.",
            metadata={"bytes": stat_result.st_size, "limit": MAX_REPLACEMENT_DB_BYTES},
        )
        raise ReplacementDbLoadError(f"Replacement database {str(db_path)!r} is too large.", [size_diagnostic])

    try:
        with db_path.open(encoding="utf-8") as file:
            return json.load(file)
    except json.JSONDecodeError as exc:
        parse_diagnostic = diagnostic(
            DIAGNOSTIC_ERROR,
            JSON_PARSE,
            "",
            (
                f"Could not parse replacement database {str(db_path)!r}: {exc.msg} "
                f"at line {exc.lineno}, column {exc.colno}."
            ),
        )
        raise ReplacementDbLoadError(
            f"Could not parse replacement database {str(db_path)!r}.", [parse_diagnostic]
        ) from exc
    except OSError as exc:
        load_diagnostic = diagnostic(
            DIAGNOSTIC_ERROR,
            "replacement_db.load_error",
            "",
            f"Could not read replacement database {str(db_path)!r}: {exc}.",
        )
        raise ReplacementDbLoadError(
            f"Could not read replacement database {str(db_path)!r}.", [load_diagnostic]
        ) from exc


def load_replacement_db(path: str | Path) -> dict[str, Any]:
    """Load, validate, and canonicalize a replacement database from an explicit JSON file path."""
    db_path = _resolve_local_path(path)
    replacement_db = read_replacement_db_json(db_path)

    if not isinstance(replacement_db, dict):
        type_diagnostic = diagnostic(
            DIAGNOSTIC_ERROR,
            SCHEMA_TYPE,
            "",
            f"Replacement database {str(db_path)!r} must be an object at the top level.",
        )
        raise ReplacementDbSchemaError(f"Replacement database {str(db_path)!r} must be an object.", [type_diagnostic])

    _raise_if_invalid(replacement_db, label=f"replacement database {str(db_path)!r}")
    return canonicalize_replacement_db(replacement_db)


def _canonicalize(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {item_key: _canonicalize(item_value) for item_key, item_value in sorted(value.items())}
    if isinstance(value, list):
        return [_canonicalize(item) for item in value]
    return copy.deepcopy(value)


def canonicalize_replacement_db(replacement_db: Mapping[str, Any]) -> dict[str, Any]:
    """Return a deterministic copy of a replacement database without rewriting semantic fields."""
    canonical = _canonicalize(replacement_db)
    if not isinstance(canonical, dict):
        raise TypeError("Replacement database canonicalization requires a mapping.")
    return canonical


def hash_replacement_db(replacement_db: Mapping[str, Any]) -> str:
    """Return a sha256 hash computed from canonical replacement database JSON."""
    payload = json.dumps(
        canonicalize_replacement_db(replacement_db),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def validate_replacement_db(replacement_db: Any) -> dict[str, Any]:
    """Validate a replacement database object against schema and semantic safety rules."""
    diagnostics = list(validate_replacement_db_schema(replacement_db)["diagnostics"])
    if isinstance(replacement_db, Mapping):
        diagnostics.extend(_iter_policy_diagnostics(replacement_db))
        diagnostics.extend(_iter_replacement_set_diagnostics(replacement_db))
        diagnostics.extend(_iter_assignment_diagnostics(replacement_db))
    diagnostics.sort(key=lambda item: (item["path"], item["severity"], item["code"], item["message"]))
    return {"valid": not has_errors(diagnostics), "diagnostics": diagnostics}


def _raise_if_invalid(replacement_db: Any, *, label: str) -> None:
    result = validate_replacement_db(replacement_db)
    diagnostics = result["diagnostics"]
    if has_errors(diagnostics):
        raise ReplacementDbSchemaError(f"{label} failed validation.", diagnostics)


def _json_pointer(parts: list[Any]) -> str:
    escaped = [str(part).replace("~", "~0").replace("/", "~1") for part in parts]
    return "/" + "/".join(escaped) if escaped else ""


def _error(code: str, path: str, message: str, *, metadata: dict[str, Any] | None = None) -> Diagnostic:
    return diagnostic(DIAGNOSTIC_ERROR, code, path, message, metadata=metadata)


def _render_redaction_template(template: str, entity_id: str, ordinal: int) -> str:
    return template.format(entity=entity_id, ENTITY=entity_id.upper(), ordinal=ordinal)


def _effective_policy(replacement_db: Mapping[str, Any], entity_id: str) -> dict[str, Any]:
    defaults = replacement_db.get("defaults")
    if not isinstance(defaults, Mapping):
        return {}
    policy = dict(defaults)
    entities = replacement_db.get("entities")
    if isinstance(entities, Mapping):
        entity_policy = entities.get(entity_id)
        if isinstance(entity_policy, Mapping):
            policy.update(entity_policy)
    return policy


def _iter_policy_diagnostics(replacement_db: Mapping[str, Any]) -> Iterator[Diagnostic]:
    replacement_sets = replacement_db.get("replacement_sets", {})
    replacement_set_ids = set(replacement_sets) if isinstance(replacement_sets, Mapping) else set()

    policy_items: list[tuple[list[Any], Mapping[str, Any]]] = []
    defaults = replacement_db.get("defaults")
    if isinstance(defaults, Mapping):
        policy_items.append((["defaults"], defaults))
    entities = replacement_db.get("entities")
    if isinstance(entities, Mapping):
        for entity_id, entity_policy in entities.items():
            if isinstance(entity_policy, Mapping):
                effective_policy = dict(defaults) if isinstance(defaults, Mapping) else {}
                effective_policy.update(entity_policy)
                policy_items.append((["entities", entity_id], effective_policy))

    for path_parts, policy in policy_items:
        if policy.get("replacement_mode") == "pseudonym":
            set_id = policy.get("replacement_set_id")
            if not isinstance(set_id, str) or not set_id:
                yield _error(
                    "replacement_db.missing_replacement_set",
                    _json_pointer([*path_parts, "replacement_set_id"]),
                    "Pseudonym replacement mode requires a replacement_set_id.",
                )
            elif set_id not in replacement_set_ids:
                yield _error(
                    "replacement_db.unknown_replacement_set",
                    _json_pointer([*path_parts, "replacement_set_id"]),
                    f"Replacement set {set_id!r} is not defined.",
                )
        else:
            set_id = policy.get("replacement_set_id")
            if isinstance(set_id, str) and set_id not in replacement_set_ids:
                yield _error(
                    "replacement_db.unknown_replacement_set",
                    _json_pointer([*path_parts, "replacement_set_id"]),
                    f"Replacement set {set_id!r} is not defined.",
                )

        template = policy.get("redaction_template")
        if isinstance(template, str):
            try:
                _render_redaction_template(template, "entity", 1)
            except (AttributeError, KeyError, IndexError, TypeError, ValueError) as exc:
                yield _error(
                    "replacement_db.invalid_redaction_template",
                    _json_pointer([*path_parts, "redaction_template"]),
                    f"Redaction template cannot be rendered with entity and ordinal fields: {exc}.",
                )


def _iter_replacement_set_diagnostics(replacement_db: Mapping[str, Any]) -> Iterator[Diagnostic]:
    replacement_sets = replacement_db.get("replacement_sets")
    if not isinstance(replacement_sets, Mapping):
        return

    for set_id, replacement_set in replacement_sets.items():
        if not isinstance(replacement_set, Mapping):
            continue
        candidates = replacement_set.get("candidates")
        if not isinstance(candidates, list):
            continue

        seen_ids: dict[str, int] = {}
        seen_values: dict[str, int] = {}
        for index, candidate in enumerate(candidates):
            if not isinstance(candidate, dict):
                continue
            candidate_mapping = cast(dict[str, Any], candidate)
            candidate_id = candidate_mapping.get("id")
            if isinstance(candidate_id, str):
                if candidate_id in seen_ids:
                    yield _error(
                        "replacement_db.duplicate_candidate_id",
                        _json_pointer(["replacement_sets", set_id, "candidates", index, "id"]),
                        f"Candidate id {candidate_id!r} is duplicated in replacement set {set_id!r}.",
                        metadata={"first_index": seen_ids[candidate_id]},
                    )
                else:
                    seen_ids[candidate_id] = index
            value = candidate_mapping.get("value")
            if isinstance(value, str):
                if value in seen_values:
                    yield _error(
                        "replacement_db.duplicate_candidate_value",
                        _json_pointer(["replacement_sets", set_id, "candidates", index, "value"]),
                        f"Candidate value is duplicated in replacement set {set_id!r}.",
                        metadata={"first_index": seen_values[value]},
                    )
                else:
                    seen_values[value] = index


def _candidate_index(replacement_db: Mapping[str, Any]) -> dict[tuple[str, str], Mapping[str, Any]]:
    index: dict[tuple[str, str], Mapping[str, Any]] = {}
    replacement_sets = replacement_db.get("replacement_sets")
    if not isinstance(replacement_sets, Mapping):
        return index
    for set_id, replacement_set in replacement_sets.items():
        if not isinstance(replacement_set, Mapping):
            continue
        candidates = replacement_set.get("candidates")
        if not isinstance(candidates, list):
            continue
        for candidate in candidates:
            if isinstance(candidate, Mapping) and isinstance(candidate.get("id"), str):
                index[(str(set_id), candidate["id"])] = candidate
    return index


def _iter_assignment_diagnostics(replacement_db: Mapping[str, Any]) -> Iterator[Diagnostic]:
    assignments = replacement_db.get("assignments")
    if not isinstance(assignments, Mapping):
        return

    candidates = _candidate_index(replacement_db)
    replacement_values: dict[str, str] = {}
    redaction_tokens: dict[str, str] = {}

    for assignment_map_key, assignment in assignments.items():
        assignment_path = ["assignments", assignment_map_key]
        if not isinstance(assignment, Mapping):
            continue

        assignment_key = assignment.get("assignment_key")
        if assignment_key != assignment_map_key:
            yield _error(
                "replacement_db.assignment_key_mismatch",
                _json_pointer([*assignment_path, "assignment_key"]),
                "Assignment object assignment_key must match its map key.",
            )

        key_match = ASSIGNMENT_KEY_RE.fullmatch(assignment_map_key) if isinstance(assignment_map_key, str) else None
        if key_match is None:
            yield _error(
                "replacement_db.invalid_assignment_key",
                _json_pointer(assignment_path),
                "Assignment keys must use the opaque '<entity>|<scope>|sha256:<64 hex>' format.",
            )
        key_entity = key_match.group("entity") if key_match else None
        key_scope = key_match.group("scope") if key_match else None

        entity_id = assignment.get("entity_id")
        if key_entity is not None and entity_id != key_entity:
            yield _error(
                "replacement_db.assignment_key_mismatch",
                _json_pointer([*assignment_path, "entity_id"]),
                "Assignment entity_id must match the entity segment of assignment_key.",
            )

        identity = assignment.get("identity")
        identity_scope = identity.get("scope") if isinstance(identity, Mapping) else None
        if key_scope is not None and identity_scope != key_scope:
            yield _error(
                "replacement_db.assignment_key_mismatch",
                _json_pointer([*assignment_path, "identity", "scope"]),
                "Assignment identity scope must match the scope segment of assignment_key.",
            )
        fingerprint = identity.get("fingerprint") if isinstance(identity, Mapping) else None
        if isinstance(fingerprint, str) and FINGERPRINT_RE.fullmatch(fingerprint) is None:
            yield _error(
                "replacement_db.invalid_fingerprint",
                _json_pointer([*assignment_path, "identity", "fingerprint"]),
                "Assignment fingerprints must use 'sha256:<64 hex>' format.",
            )

        policy = _effective_policy(replacement_db, str(entity_id)) if isinstance(entity_id, str) else {}
        store_originals = bool(policy.get("store_originals"))
        if not store_originals:
            if "original" in assignment:
                yield _error(
                    "replacement_db.sensitive_field",
                    _json_pointer([*assignment_path, "original"]),
                    "Assignments for store_originals=false policies must not contain plaintext originals.",
                )
            if isinstance(identity, Mapping):
                for field in ("name_id", "canonical_name", "surface"):
                    if field in identity:
                        yield _error(
                            "replacement_db.sensitive_field",
                            _json_pointer([*assignment_path, "identity", field]),
                            f"Assignments for store_originals=false policies must not contain identity.{field}.",
                        )
        else:
            original = assignment.get("original")
            if not isinstance(original, Mapping):
                yield _error(
                    "replacement_db.missing_original",
                    _json_pointer([*assignment_path, "original"]),
                    "Assignments for store_originals=true policies must include original data.",
                )
            elif identity_scope in {"name", "canonical"}:
                if not isinstance(original.get("canonical"), str) or not original.get("canonical"):
                    yield _error(
                        "replacement_db.missing_original",
                        _json_pointer([*assignment_path, "original", "canonical"]),
                        "Name and canonical assignments must include original.canonical.",
                    )
            elif identity_scope == "surface":
                surfaces = original.get("surfaces")
                if not isinstance(surfaces, list) or not surfaces:
                    yield _error(
                        "replacement_db.missing_original",
                        _json_pointer([*assignment_path, "original", "surfaces"]),
                        "Surface assignments must include at least one original surface.",
                    )

        replacement = assignment.get("replacement")
        if not isinstance(replacement, Mapping):
            continue
        replacement_mode = replacement.get("mode")
        replacement_value = replacement.get("value")
        if isinstance(replacement_value, str):
            previous_key = replacement_values.get(replacement_value)
            if previous_key is not None and previous_key != assignment_map_key:
                yield _error(
                    "replacement_db.assignment_collision",
                    _json_pointer([*assignment_path, "replacement", "value"]),
                    "Replacement value maps to multiple assignments.",
                    metadata={"first_assignment_key": previous_key},
                )
            else:
                replacement_values[replacement_value] = str(assignment_map_key)

        if replacement_mode == "pseudonym":
            set_id = replacement.get("set_id")
            candidate_id = replacement.get("candidate_id")
            if not isinstance(set_id, str) or not isinstance(candidate_id, str):
                yield _error(
                    "replacement_db.invalid_assignment_candidate",
                    _json_pointer([*assignment_path, "replacement"]),
                    "Pseudonym assignments must include replacement.set_id and replacement.candidate_id.",
                )
            else:
                candidate = candidates.get((set_id, candidate_id))
                if candidate is None:
                    yield _error(
                        "replacement_db.invalid_assignment_candidate",
                        _json_pointer([*assignment_path, "replacement", "candidate_id"]),
                        f"Candidate {candidate_id!r} is not defined in replacement set {set_id!r}.",
                    )
                elif replacement_value != candidate.get("value"):
                    yield _error(
                        "replacement_db.invalid_assignment_candidate",
                        _json_pointer([*assignment_path, "replacement", "value"]),
                        "Pseudonym assignment value must match the referenced candidate value.",
                    )

        redaction = assignment.get("redaction")
        if replacement_mode == "redact" and not isinstance(redaction, Mapping):
            yield _error(
                "replacement_db.invalid_redaction",
                _json_pointer([*assignment_path, "redaction"]),
                "Redaction assignments must include redaction token and ordinal metadata.",
            )
            continue

        if "redaction" in assignment:
            if not isinstance(redaction, Mapping):
                yield _error(
                    "replacement_db.invalid_redaction",
                    _json_pointer([*assignment_path, "redaction"]),
                    "Redaction assignments must include redaction token and ordinal metadata.",
                )
                continue
            ordinal = redaction.get("ordinal")
            token = redaction.get("token")
            if isinstance(token, str):
                previous_key = redaction_tokens.get(token)
                if previous_key is not None and previous_key != assignment_map_key:
                    yield _error(
                        "replacement_db.assignment_collision",
                        _json_pointer([*assignment_path, "redaction", "token"]),
                        "Redaction token maps to multiple assignments.",
                        metadata={"first_assignment_key": previous_key},
                    )
                else:
                    redaction_tokens[token] = str(assignment_map_key)
            if isinstance(ordinal, int) and not isinstance(ordinal, bool) and isinstance(token, str):
                template = policy.get("redaction_template")
                if isinstance(template, str) and isinstance(entity_id, str):
                    try:
                        expected_token = _render_redaction_template(template, entity_id, ordinal)
                    except (AttributeError, KeyError, IndexError, TypeError, ValueError):
                        continue
                    if token != expected_token:
                        yield _error(
                            "replacement_db.invalid_redaction",
                            _json_pointer([*assignment_path, "redaction", "token"]),
                            f"Redaction token must match the active template for ordinal {ordinal}.",
                        )
                if replacement_mode == "redact" and replacement_value != token:
                    yield _error(
                        "replacement_db.invalid_redaction",
                        _json_pointer([*assignment_path, "replacement", "value"]),
                        "Redaction replacement value must match redaction.token.",
                    )


def _current_file_state(path: Path) -> tuple[str, int]:
    current = load_replacement_db(path)
    version = current.get("version")
    if not isinstance(version, int):
        raise ReplacementDbSaveError(f"Replacement database {str(path)!r} has an invalid version.")
    return hash_replacement_db(current), version


@contextmanager
def _locked_path(path: Path) -> Iterator[None]:
    lock_path = path.with_name(f".{path.name}.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    with os.fdopen(fd, "r+") as lock_file:
        if os.name == "nt":
            import msvcrt

            lock_file.seek(0)
            lock_file.write("0")
            lock_file.flush()
            lock_file.seek(0)
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                lock_file.seek(0)
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _chmod_owner_only(path: Path) -> None:
    if os.name != "nt":
        path.chmod(0o600)


def save_replacement_db(
    replacement_db: Mapping[str, Any],
    path: str | Path,
    *,
    expected_hash: str | None = None,
    expected_version: int | None = None,
) -> Path:
    """Validate and atomically save a replacement database to an explicit JSON path."""
    db_path = _resolve_local_path(path)
    _raise_if_invalid(replacement_db, label="replacement database candidate")
    canonical = canonicalize_replacement_db(replacement_db)
    serialized = json.dumps(canonical, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    payload = serialized.encode("utf-8")
    if len(payload) > MAX_REPLACEMENT_DB_BYTES:
        raise ReplacementDbSaveError(
            f"Replacement database candidate exceeds the {MAX_REPLACEMENT_DB_BYTES} byte limit.",
            [
                _error(
                    "replacement_db.too_large",
                    "",
                    f"Replacement database candidate exceeds the {MAX_REPLACEMENT_DB_BYTES} byte limit.",
                    metadata={"bytes": len(payload), "limit": MAX_REPLACEMENT_DB_BYTES},
                )
            ],
        )

    db_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    with _locked_path(db_path):
        if db_path.exists():
            try:
                current_hash, current_version = _current_file_state(db_path)
            except ReplacementDbError as exc:
                if expected_hash is not None or expected_version is not None:
                    raise ReplacementDbSaveError(
                        f"Could not verify current replacement database state for {str(db_path)!r}.",
                        [
                            _error(
                                "replacement_db.stale_write",
                                "",
                                "Cannot satisfy expected_hash or expected_version because the current file is invalid.",
                            )
                        ],
                    ) from exc
                current_hash = None
                current_version = None

            if expected_hash is not None and current_hash != expected_hash:
                raise ReplacementDbSaveError(
                    f"Replacement database {str(db_path)!r} changed since it was read.",
                    [
                        _error(
                            "replacement_db.stale_write",
                            "",
                            "Current replacement database hash does not match expected_hash.",
                        )
                    ],
                )
            if expected_version is not None and current_version != expected_version:
                raise ReplacementDbSaveError(
                    f"Replacement database {str(db_path)!r} changed since it was read.",
                    [
                        _error(
                            "replacement_db.stale_write",
                            "/version",
                            "Current replacement database version does not match expected_version.",
                        )
                    ],
                )
            candidate_version = canonical["version"]
            candidate_hash = hash_replacement_db(canonical)
            if (
                current_hash is not None
                and current_version is not None
                and candidate_hash != current_hash
                and candidate_version != current_version + 1
            ):
                raise ReplacementDbSaveError(
                    f"Replacement database {str(db_path)!r} version must increment on changed saves.",
                    [
                        _error(
                            "replacement_db.version_not_incremented",
                            "/version",
                            "Changed replacement database saves must increment version by exactly 1.",
                            metadata={"current_version": current_version, "candidate_version": candidate_version},
                        )
                    ],
                )
        elif expected_hash is not None or expected_version is not None:
            raise ReplacementDbSaveError(
                f"Replacement database {str(db_path)!r} does not exist.",
                [
                    _error(
                        "replacement_db.stale_write",
                        "",
                        "Cannot satisfy expected_hash or expected_version because the destination does not exist.",
                    )
                ],
            )

        try:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=db_path.parent,
                prefix=f".{db_path.name}.",
                suffix=".tmp",
                delete=False,
            ) as file:
                temp_path = Path(file.name)
                _chmod_owner_only(temp_path)
                file.write(serialized)
                file.flush()
                os.fsync(file.fileno())

            temp_path.replace(db_path)
            _chmod_owner_only(db_path)
        except Exception:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
            raise

    return db_path

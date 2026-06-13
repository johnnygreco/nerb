from __future__ import annotations

import copy
import hashlib
import json
import re
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, cast

from .diagnostics import DIAGNOSTIC_ERROR, Diagnostic, diagnostic, has_errors
from .replacements import (
    _effective_policy,
    _render_redaction_template,
    canonicalize_replacement_db,
    validate_replacement_db,
)
from .replacements_schema import MAX_STORED_ORIGINAL_SURFACES
from .schema import ID_RE, UNICODE_NORMALIZATION_VALUES

__all__ = [
    "AssignmentAllocation",
    "ByteEdit",
    "ByteSpan",
    "DeanonymizationError",
    "RewriteResult",
    "AppliedByteEdit",
    "allocate_assignment",
    "apply_byte_replacements",
    "assignment_key",
    "finalize_replacement_db_update",
]

ASSIGNMENT_SCOPES = {"name", "canonical", "surface"}
REPLACEMENT_MISSING_ASSIGNMENT = "replacement_db.missing_assignment"
REPLACEMENT_CANDIDATES_EXHAUSTED = "replacement_db.candidates_exhausted"
ENTITY_ID_HASH_LENGTH = 12


class DeanonymizationError(ValueError):
    """Raised when a de-anonymization helper cannot safely continue."""

    def __init__(self, message: str, diagnostics: Sequence[Diagnostic] | None = None) -> None:
        super().__init__(message)
        self.diagnostics = list(diagnostics or [])


@dataclass(frozen=True)
class ByteSpan:
    """A byte-offset span in UTF-8 encoded text."""

    start: int
    end: int
    offset_unit: str = "byte"

    def as_dict(self) -> dict[str, Any]:
        return {"start": self.start, "end": self.end, "offset_unit": self.offset_unit}


@dataclass(frozen=True)
class ByteEdit:
    """A validated replacement to apply to a UTF-8 byte span."""

    start: int
    end: int
    replacement: str
    expected: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class AppliedByteEdit:
    """Metadata for one byte edit after rewriting."""

    original_span: ByteSpan
    replacement_span: ByteSpan
    replacement: str
    expected: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class RewriteResult:
    """Text plus byte-span metadata returned by apply_byte_replacements."""

    text: str
    applied_edits: tuple[AppliedByteEdit, ...]


@dataclass(frozen=True)
class _AssignmentIdentity:
    """Stable opaque identity material for one source record under one policy."""

    assignment_key: str = field(repr=False)
    entity_id: str
    scope: str
    fingerprint: str = field(repr=False)
    identity: dict[str, Any] = field(repr=False)
    canonical: str | None = field(repr=False)
    surface: str | None = field(repr=False)


@dataclass(frozen=True)
class AssignmentAllocation:
    """Result of looking up or allocating an assignment in a replacement DB copy."""

    replacement_db: dict[str, Any] = field(repr=False)
    assignment_key: str
    assignment: dict[str, Any] | None = field(repr=False)
    created: bool
    diagnostics: tuple[Diagnostic, ...] = ()


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _json_pointer(parts: Sequence[Any]) -> str:
    escaped = [str(part).replace("~", "~0").replace("/", "~1") for part in parts]
    return "/" + "/".join(escaped) if escaped else ""


def _error(code: str, path: str, message: str, *, metadata: dict[str, Any] | None = None) -> Diagnostic:
    return diagnostic(DIAGNOSTIC_ERROR, code, path, message, metadata=metadata)


def _raise_for_diagnostics(message: str, diagnostics: Sequence[Diagnostic]) -> None:
    if diagnostics:
        raise DeanonymizationError(message, diagnostics)


def _hash_parts(*parts: Any) -> str:
    payload = json.dumps(parts, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _normalize(value: str, unicode_normalization: str) -> str:
    if unicode_normalization == "none":
        return value
    if unicode_normalization not in UNICODE_NORMALIZATION_VALUES:
        raise DeanonymizationError(
            "Unsupported unicode normalization.",
            [
                _error(
                    "replacement_db.invalid_policy",
                    "/unicode_normalization",
                    f"Unsupported unicode normalization {unicode_normalization!r}.",
                )
            ],
        )
    if unicode_normalization == "NFC":
        return unicodedata.normalize("NFC", value)
    return unicodedata.normalize("NFKC", value)


def _record_string(record: Mapping[str, Any], field: str) -> str | None:
    value = record.get(field)
    return value if isinstance(value, str) and value else None


def _record_entity_id(record: Mapping[str, Any]) -> str:
    entity_id = _record_string(record, "entity_id")
    if entity_id is not None:
        if not ID_RE.fullmatch(entity_id):
            raise DeanonymizationError(
                "Record entity id is invalid.",
                [
                    _error(
                        "replacement.assignment_key_invalid_entity",
                        "/entity_id",
                        f"Assignment key entity id {entity_id!r} must match the NERB ID pattern.",
                    )
                ],
            )
        return entity_id

    raw_entity = _record_string(record, "entity")
    if raw_entity is None:
        raise DeanonymizationError(
            "Record is missing an entity id.",
            [_error("replacement.assignment_key_missing_field", "/entity_id", "Assignment key requires entity_id.")],
        )
    return _config_entity_id(raw_entity)


def _config_entity_id(raw_entity: str) -> str:
    if ID_RE.fullmatch(raw_entity):
        return raw_entity

    stripped = raw_entity.strip()
    lowered = stripped.lower()
    slug = re.sub(r"[^a-z0-9_]+", "_", lowered)
    slug = re.sub(r"_+", "_", slug).strip("_") or "entity"
    if not slug[0].isalpha():
        slug = f"entity_{slug}"

    suffix = hashlib.sha256(raw_entity.encode("utf-8")).hexdigest()[:ENTITY_ID_HASH_LENGTH]
    prefix_length = 80 - len(suffix) - 1
    prefix = slug[:prefix_length].rstrip("_") or "entity"
    slug = f"{prefix}_{suffix}"

    if ID_RE.fullmatch(slug):
        return slug
    return "entity_" + hashlib.sha256(raw_entity.encode("utf-8")).hexdigest()[:ENTITY_ID_HASH_LENGTH]


def _policy_scope(policy: Mapping[str, Any]) -> str:
    scope = policy.get("assignment_scope", "name")
    if not isinstance(scope, str) or scope not in ASSIGNMENT_SCOPES:
        raise DeanonymizationError(
            "Unsupported assignment scope.",
            [
                _error(
                    "replacement.assignment_scope_invalid",
                    "/assignment_scope",
                    f"Assignment scope must be one of {sorted(ASSIGNMENT_SCOPES)}.",
                )
            ],
        )
    return str(scope)


def _policy_normalization(policy: Mapping[str, Any]) -> str:
    normalization = policy.get("unicode_normalization", "NFC")
    if not isinstance(normalization, str):
        raise DeanonymizationError(
            "Unsupported unicode normalization.",
            [
                _error(
                    "replacement_db.invalid_policy",
                    "/unicode_normalization",
                    "Unicode normalization policy must be a string.",
                )
            ],
        )
    return normalization


def _assignment_identity(record: Mapping[str, Any], policy: Mapping[str, Any]) -> _AssignmentIdentity:
    """Return stable assignment identity material for a source record and policy."""
    entity_id = _record_entity_id(record)
    scope = _policy_scope(policy)
    normalization = _policy_normalization(policy)
    store_originals = bool(policy.get("store_originals"))
    identity: dict[str, Any] = {"scope": scope}
    canonical: str | None = None
    surface: str | None = None

    if scope == "name":
        name_id = _record_string(record, "name_id")
        if name_id is None:
            raise DeanonymizationError(
                "Name-scoped assignment requires name_id.",
                [
                    _error(
                        "replacement.assignment_key_missing_field",
                        "/name_id",
                        "Name-scoped assignment keys require name_id.",
                    )
                ],
            )
        digest = _hash_parts("name", entity_id, name_id)
        canonical = _record_string(record, "canonical_name") or _record_string(record, "surface_name")
        if canonical is not None:
            canonical = _normalize(canonical, normalization)
        if store_originals:
            identity["name_id"] = name_id
            if canonical is not None:
                identity["canonical_name"] = canonical
    elif scope == "canonical":
        canonical = _record_string(record, "canonical_name") or _record_string(record, "surface_name")
        if canonical is None:
            raise DeanonymizationError(
                "Canonical-scoped assignment requires canonical_name.",
                [
                    _error(
                        "replacement.assignment_key_missing_field",
                        "/canonical_name",
                        "Canonical-scoped assignment keys require canonical_name.",
                    )
                ],
            )
        canonical = _normalize(canonical, normalization)
        digest = _hash_parts("canonical", entity_id, canonical)
        if store_originals:
            identity["canonical_name"] = canonical
    else:
        surface = _record_string(record, "string")
        if surface is None:
            raise DeanonymizationError(
                "Surface-scoped assignment requires string.",
                [
                    _error(
                        "replacement.assignment_key_missing_field",
                        "/string",
                        "Surface-scoped assignment keys require the matched string.",
                    )
                ],
            )
        surface = _normalize(surface, normalization)
        digest = _hash_parts("surface", entity_id, surface)
        if store_originals:
            identity["surface"] = surface

    matched_surface = _record_string(record, "string")
    if matched_surface is not None:
        surface = _normalize(matched_surface, normalization)

    identity["fingerprint"] = digest
    return _AssignmentIdentity(
        assignment_key=f"{entity_id}|{scope}|{digest}",
        entity_id=entity_id,
        scope=scope,
        fingerprint=digest,
        identity=identity,
        canonical=canonical,
        surface=surface,
    )


def assignment_key(record: Mapping[str, Any], policy: Mapping[str, Any]) -> str:
    """Return the stable opaque assignment key for a source record and policy.

    Assignment keys and fingerprints are deterministic and linkable. They are lookup identifiers, not a privacy
    boundary. Treat replacement databases as sensitive even when store_originals is false.
    """
    return _assignment_identity(record, policy).assignment_key


def _validate_byte_edits(source_bytes: bytes, edits: Sequence[ByteEdit]) -> list[tuple[ByteEdit, bytes]]:
    normalized_edits: list[tuple[ByteEdit, bytes]] = []
    diagnostics: list[Diagnostic] = []

    for index, edit in enumerate(edits):
        path = f"/edits/{index}"
        if not _is_int(edit.start) or not _is_int(edit.end):
            diagnostics.append(_error("rewrite.invalid_span", path, "Byte edit start and end must be integers."))
            continue
        if edit.start < 0 or edit.end <= edit.start or edit.end > len(source_bytes):
            diagnostics.append(
                _error(
                    "rewrite.invalid_span",
                    path,
                    "Byte edit span must satisfy 0 <= start < end <= len(text.encode('utf-8')).",
                )
            )
            continue
        actual_bytes = source_bytes[edit.start : edit.end]
        try:
            actual_bytes.decode("utf-8")
        except UnicodeDecodeError:
            diagnostics.append(
                _error(
                    "rewrite.invalid_span",
                    path,
                    "Byte edit span must align with UTF-8 character boundaries.",
                )
            )
            continue
        replacement_bytes = edit.replacement.encode("utf-8")
        if edit.expected is not None:
            expected_bytes = edit.expected.encode("utf-8")
            if actual_bytes != expected_bytes:
                diagnostics.append(
                    _error(
                        "rewrite.source_mismatch",
                        path,
                        "Byte edit expected text does not match the source bytes.",
                    )
                )
        normalized_edits.append((edit, replacement_bytes))

    sorted_edits = sorted(normalized_edits, key=lambda item: (item[0].start, item[0].end))
    previous_end = 0
    for edit, _replacement_bytes in sorted_edits:
        if edit.start < previous_end:
            diagnostics.append(
                _error("rewrite.overlap", "/edits", "Byte edits must not overlap after sorting by start offset.")
            )
            break
        previous_end = edit.end

    _raise_for_diagnostics("Byte replacements cannot be applied safely.", diagnostics)
    return sorted_edits


def apply_byte_replacements(text: str, edits: Sequence[ByteEdit]) -> RewriteResult:
    """Apply non-overlapping UTF-8 byte-span replacements and return rewritten text plus span metadata."""
    source_bytes = text.encode("utf-8")
    sorted_edits = _validate_byte_edits(source_bytes, edits)
    rewritten = bytearray(source_bytes)
    for edit, replacement_bytes in sorted(sorted_edits, key=lambda item: item[0].start, reverse=True):
        rewritten[edit.start : edit.end] = replacement_bytes

    applied_edits: list[AppliedByteEdit] = []
    delta = 0
    for edit, replacement_bytes in sorted_edits:
        replacement_start = edit.start + delta
        replacement_end = replacement_start + len(replacement_bytes)
        applied_edits.append(
            AppliedByteEdit(
                original_span=ByteSpan(edit.start, edit.end),
                replacement_span=ByteSpan(replacement_start, replacement_end),
                replacement=edit.replacement,
                expected=edit.expected,
            )
        )
        delta += len(replacement_bytes) - (edit.end - edit.start)

    try:
        rewritten_text = bytes(rewritten).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DeanonymizationError(
            "Byte replacements produced invalid UTF-8.",
            [_error("rewrite.invalid_utf8", "", f"Byte replacements produced invalid UTF-8: {exc}.")],
        ) from exc

    return RewriteResult(text=rewritten_text, applied_edits=tuple(applied_edits))


def _validate_replacement_db_for_allocation(replacement_db: Mapping[str, Any]) -> dict[str, Any]:
    result = validate_replacement_db(replacement_db)
    diagnostics = result["diagnostics"]
    if has_errors(diagnostics):
        raise DeanonymizationError("Replacement database is invalid.", diagnostics)
    return canonicalize_replacement_db(replacement_db)


def _existing_assignment_values(replacement_db: Mapping[str, Any]) -> tuple[set[tuple[str, str]], dict[str, str]]:
    used_candidates: set[tuple[str, str]] = set()
    replacement_values: dict[str, str] = {}
    assignments = replacement_db.get("assignments")
    if not isinstance(assignments, Mapping):
        return used_candidates, replacement_values

    for assignment_key_value, assignment in assignments.items():
        if not isinstance(assignment, Mapping):
            continue
        replacement = assignment.get("replacement")
        if not isinstance(replacement, Mapping):
            continue
        set_id = replacement.get("set_id")
        candidate_id = replacement.get("candidate_id")
        if isinstance(set_id, str) and isinstance(candidate_id, str):
            used_candidates.add((set_id, candidate_id))
        replacement_value = replacement.get("value")
        if isinstance(replacement_value, str):
            replacement_values[replacement_value] = str(assignment_key_value)

    return used_candidates, replacement_values


def _replacement_set_candidates(
    replacement_db: Mapping[str, Any], policy: Mapping[str, Any]
) -> tuple[str | None, list[Mapping[str, Any]]]:
    set_id = policy.get("replacement_set_id")
    replacement_sets = replacement_db.get("replacement_sets")
    if not isinstance(set_id, str) or not isinstance(replacement_sets, Mapping):
        return None, []
    replacement_set = replacement_sets.get(set_id)
    if not isinstance(replacement_set, Mapping):
        return set_id, []
    candidates = replacement_set.get("candidates")
    if not isinstance(candidates, list):
        return set_id, []
    return set_id, [candidate for candidate in candidates if isinstance(candidate, Mapping)]


def _candidate_start_index(assignment_key_value: str, candidates: Sequence[Mapping[str, Any]]) -> int:
    if not candidates:
        return 0
    digest = hashlib.sha256(assignment_key_value.encode("utf-8")).hexdigest()
    return int(digest, 16) % len(candidates)


def _select_candidate(
    replacement_db: Mapping[str, Any],
    policy: Mapping[str, Any],
    assignment_key_value: str,
) -> tuple[Mapping[str, Any] | None, Diagnostic | None]:
    set_id, candidates = _replacement_set_candidates(replacement_db, policy)
    if not isinstance(set_id, str):
        return None, _error(
            "replacement_db.missing_replacement_set",
            "/replacement_set_id",
            "Pseudonym replacement mode requires a replacement_set_id.",
        )
    used_candidates, replacement_values = _existing_assignment_values(replacement_db)
    reusable = bool(
        replacement_db.get("replacement_sets", {}).get(set_id, {}).get("reuse")
        if isinstance(replacement_db.get("replacement_sets"), Mapping)
        else False
    )
    ordered_candidates = candidates
    if reusable and candidates:
        start = _candidate_start_index(assignment_key_value, candidates)
        ordered_candidates = [*candidates[start:], *candidates[:start]]

    for candidate in ordered_candidates:
        candidate_id = candidate.get("id")
        candidate_value = candidate.get("value")
        if not isinstance(candidate_id, str) or not isinstance(candidate_value, str):
            continue
        if not reusable and (set_id, candidate_id) in used_candidates:
            continue
        assigned_key = replacement_values.get(candidate_value)
        if assigned_key is not None and assigned_key != assignment_key_value:
            continue
        return candidate, None

    return None, _error(
        REPLACEMENT_CANDIDATES_EXHAUSTED,
        _json_pointer(["replacement_sets", set_id, "candidates"]),
        f"Replacement set {set_id!r} has no available unambiguous candidates.",
    )


def _next_redaction_ordinal(replacement_db: Mapping[str, Any], entity_id: str) -> int:
    assignments = replacement_db.get("assignments")
    if not isinstance(assignments, Mapping):
        return 1
    max_ordinal = 0
    for assignment in assignments.values():
        if not isinstance(assignment, Mapping) or assignment.get("entity_id") != entity_id:
            continue
        redaction = assignment.get("redaction")
        if not isinstance(redaction, Mapping):
            continue
        ordinal = redaction.get("ordinal")
        if isinstance(ordinal, int) and not isinstance(ordinal, bool):
            max_ordinal = max(max_ordinal, ordinal)
    return max_ordinal + 1


def _stored_surfaces(identity: _AssignmentIdentity, limit: int) -> list[str]:
    if identity.surface is None or limit <= 0:
        return []
    return [identity.surface][:limit]


def _original_payload(identity: _AssignmentIdentity, source_surface_limit: int) -> dict[str, Any] | None:
    surfaces = _stored_surfaces(identity, source_surface_limit)
    if identity.scope in {"name", "canonical"}:
        if identity.canonical is None:
            return None
        original: dict[str, Any] = {"canonical": identity.canonical}
        if surfaces:
            original["surfaces"] = surfaces
        return original
    if surfaces:
        return {"surfaces": surfaces}
    return None


def _new_assignment(
    replacement_db: Mapping[str, Any],
    identity: _AssignmentIdentity,
    policy: Mapping[str, Any],
    *,
    now: str,
    source_surface_limit: int,
) -> tuple[dict[str, Any] | None, Diagnostic | None]:
    mode = policy.get("replacement_mode", "redact")
    store_originals = bool(policy.get("store_originals"))
    assignment: dict[str, Any] = {
        "assignment_key": identity.assignment_key,
        "entity_id": identity.entity_id,
        "identity": dict(identity.identity),
        "created_at": now,
        "updated_at": now,
        "use_count": 1,
        "metadata": {},
    }
    if store_originals:
        original = _original_payload(identity, source_surface_limit)
        if original is not None:
            assignment["original"] = original

    if mode == "redact":
        ordinal = _next_redaction_ordinal(replacement_db, identity.entity_id)
        template = policy.get("redaction_template", "[{ENTITY}_{ordinal:04d}]")
        token = _render_redaction_template(str(template), identity.entity_id, ordinal)
        assignment["replacement"] = {"mode": "redact", "value": token}
        assignment["redaction"] = {"token": token, "ordinal": ordinal}
        return assignment, None

    if mode == "pseudonym":
        candidate, candidate_diagnostic = _select_candidate(replacement_db, policy, identity.assignment_key)
        if candidate_diagnostic is not None:
            return None, candidate_diagnostic
        if candidate is None:
            return None, _error(
                REPLACEMENT_CANDIDATES_EXHAUSTED,
                "/replacement_sets",
                "No replacement candidate is available.",
            )
        set_id = policy.get("replacement_set_id")
        assignment["replacement"] = {
            "mode": "pseudonym",
            "value": candidate["value"],
            "set_id": set_id,
            "candidate_id": candidate["id"],
        }
        return assignment, None

    return None, _error(
        "replacement_db.invalid_policy",
        "/replacement_mode",
        f"Unsupported replacement mode {mode!r}.",
    )


def allocate_assignment(
    record: Mapping[str, Any],
    replacement_db: Mapping[str, Any],
    *,
    now: str | None = None,
    source_surface_limit: int = MAX_STORED_ORIGINAL_SURFACES,
) -> AssignmentAllocation:
    """Reuse or allocate one assignment in a validated replacement database copy."""
    db = _validate_replacement_db_for_allocation(replacement_db)
    entity_id = _record_entity_id(record)
    policy = _effective_policy(db, entity_id)
    identity = _assignment_identity(record, policy)
    assignments = db.setdefault("assignments", {})
    existing = assignments.get(identity.assignment_key)
    if isinstance(existing, Mapping):
        return AssignmentAllocation(
            replacement_db=db,
            assignment_key=identity.assignment_key,
            assignment=cast(dict[str, Any], copy.deepcopy(dict(existing))),
            created=False,
        )

    if not bool(policy.get("allow_new_assignments", True)):
        return AssignmentAllocation(
            replacement_db=db,
            assignment_key=identity.assignment_key,
            assignment=None,
            created=False,
            diagnostics=(
                _error(
                    REPLACEMENT_MISSING_ASSIGNMENT,
                    "/assignments",
                    "No assignment exists and allow_new_assignments is false.",
                ),
            ),
        )

    assignment, assignment_diagnostic = _new_assignment(
        db,
        identity,
        policy,
        now=now or _utc_now(),
        source_surface_limit=source_surface_limit,
    )
    if assignment_diagnostic is not None or assignment is None:
        return AssignmentAllocation(
            replacement_db=db,
            assignment_key=identity.assignment_key,
            assignment=None,
            created=False,
            diagnostics=(assignment_diagnostic,) if assignment_diagnostic is not None else (),
        )

    assignments[identity.assignment_key] = assignment
    result = validate_replacement_db(db)
    diagnostics = result["diagnostics"]
    if has_errors(diagnostics):
        raise DeanonymizationError("Allocated assignment produced an invalid replacement database.", diagnostics)

    return AssignmentAllocation(
        replacement_db=db,
        assignment_key=identity.assignment_key,
        assignment=copy.deepcopy(assignment),
        created=True,
    )


def finalize_replacement_db_update(
    replacement_db: Mapping[str, Any],
    *,
    base_version: int | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    """Return a validated DB copy with version incremented once for an operation-level save."""
    db = _validate_replacement_db_for_allocation(replacement_db)
    current_version = base_version if base_version is not None else db.get("version")
    if not isinstance(current_version, int) or isinstance(current_version, bool) or current_version < 1:
        raise DeanonymizationError(
            "Replacement database version cannot be finalized.",
            [
                _error(
                    "replacement_db.invalid_version",
                    "/version",
                    "Replacement database version must be a positive integer before finalization.",
                )
            ],
        )

    db["version"] = current_version + 1
    db["updated_at"] = now or _utc_now()
    result = validate_replacement_db(db)
    diagnostics = result["diagnostics"]
    if has_errors(diagnostics):
        raise DeanonymizationError("Finalized replacement database is invalid.", diagnostics)
    return db

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from .bank import canonicalize_bank
from .diagnostics import (
    DIAGNOSTIC_ERROR,
    EVAL_NEGATIVE_FAILED,
    EVAL_POSITIVE_FAILED,
    EVAL_RECORD_INVALID,
    EVAL_REF_TOO_LARGE,
    EVAL_REF_UNRESOLVED,
    EVAL_REF_UNSUPPORTED,
    JSON_PARSE,
    SCHEMA_ADDITIONAL_PROPERTY,
    SCHEMA_REQUIRED,
    SCHEMA_TYPE,
    Diagnostic,
    diagnostic,
)
from .engines import ExtractionError
from .extraction import extract_text
from .records import MatchRecord, record_sort_key

__all__ = ["DEFAULT_MAX_EVAL_REF_BYTES", "eval_bank"]

DEFAULT_MAX_EVAL_REF_BYTES = 100 * 1024 * 1024

_URI_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_POSITIVE_FIELDS = {"type", "text", "matches", "metadata"}
_NEGATIVE_FIELDS = {"type", "text", "reason", "metadata"}
_PROVENANCE_FIELDS = {"type", "source_type", "observed_at", "evidence", "metadata"}
_MATCH_FIELDS = {
    "entity",
    "entity_id",
    "name",
    "name_id",
    "pattern_id",
    "pattern_kind",
    "string",
    "start",
    "end",
    "captures",
}
_CORE_COMPARISON_FIELDS = ("string", "start", "end")
_OPTIONAL_COMPARISON_FIELDS = (
    "entity_id",
    "name_id",
    "pattern_id",
    "pattern_kind",
    "captures",
)


@dataclass(frozen=True)
class EvalOptions:
    max_eval_ref_bytes: int


@dataclass(frozen=True)
class EvalScope:
    kind: str
    path: str
    eval_refs: tuple[str, ...]
    entity_id: str | None = None
    name_id: str | None = None
    pattern_id: str | None = None

    @property
    def entity_key(self) -> str | None:
        return self.entity_id

    @property
    def name_key(self) -> str | None:
        if self.entity_id is None or self.name_id is None:
            return None
        return f"{self.entity_id}/{self.name_id}"

    @property
    def pattern_key(self) -> str | None:
        if self.entity_id is None or self.name_id is None or self.pattern_id is None:
            return None
        return f"{self.entity_id}/{self.name_id}/{self.pattern_id}"


def eval_bank(
    bank: Mapping[str, Any],
    *,
    base_path: str | Path | None = None,
    options: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Evaluate a JSON bank against attached local JSONL eval references."""
    eval_options = _resolve_eval_options(options)
    canonical_bank = canonicalize_bank(bank)
    resolved_base_path = _resolve_base_path(base_path, options)
    result = _empty_result()

    for scope in _iter_eval_scopes(canonical_bank):
        for eval_ref in scope.eval_refs:
            for record_index, record in _load_eval_ref(scope, eval_ref, resolved_base_path, eval_options, result):
                _evaluate_record(canonical_bank, scope, eval_ref, record_index, record, options, result)

    summary = result["summary"]
    summary["passed"] = summary["positive_failed"] == 0 and summary["negative_failed"] == 0 and not result["failures"]
    _strip_empty_buckets(result["by_entity"])
    _strip_empty_buckets(result["by_name"])
    _strip_empty_buckets(result["by_pattern"])
    return result


def _resolve_eval_options(options: Mapping[str, Any] | None) -> EvalOptions:
    raw_options = options or {}
    max_eval_ref_bytes = raw_options.get("max_eval_ref_bytes", DEFAULT_MAX_EVAL_REF_BYTES)
    if not isinstance(max_eval_ref_bytes, int) or isinstance(max_eval_ref_bytes, bool) or max_eval_ref_bytes <= 0:
        raise ExtractionError("Eval option max_eval_ref_bytes must be a positive integer.")
    return EvalOptions(max_eval_ref_bytes=max_eval_ref_bytes)


def _resolve_base_path(base_path: str | Path | None, options: Mapping[str, Any] | None) -> Path | None:
    if base_path is not None:
        return Path(base_path).expanduser()

    raw_options = options or {}
    option_base_path = raw_options.get("base_path")
    if option_base_path is not None:
        return Path(cast(str | Path, option_base_path)).expanduser()

    bank_path = raw_options.get("bank_path")
    if bank_path is not None:
        return Path(cast(str | Path, bank_path)).expanduser().parent

    return None


def _empty_result() -> dict[str, Any]:
    return {
        "summary": {
            "passed": True,
            "positive_total": 0,
            "positive_failed": 0,
            "negative_total": 0,
            "negative_failed": 0,
        },
        "by_entity": {},
        "by_name": {},
        "by_pattern": {},
        "provenance": {"total": 0, "by_source_type": {}},
        "failures": [],
    }


def _empty_counts() -> dict[str, int]:
    return {
        "positive_total": 0,
        "positive_failed": 0,
        "negative_total": 0,
        "negative_failed": 0,
        "provenance_total": 0,
    }


def _strip_empty_buckets(buckets: dict[str, dict[str, int]]) -> None:
    empty_keys = [key for key, counts in buckets.items() if not any(counts.values())]
    for key in empty_keys:
        del buckets[key]


def _increment(
    result: Mapping[str, Any],
    scope: EvalScope,
    key: str,
    *,
    amount: int = 1,
) -> None:
    result["summary"][key] += amount
    for bucket_name, scope_key in (
        ("by_entity", scope.entity_key),
        ("by_name", scope.name_key),
        ("by_pattern", scope.pattern_key),
    ):
        if scope_key is None:
            continue
        bucket = result[bucket_name].setdefault(scope_key, _empty_counts())
        bucket[key] += amount


def _increment_provenance(result: Mapping[str, Any], scope: EvalScope, source_type: str) -> None:
    result["provenance"]["total"] += 1
    by_source_type = result["provenance"]["by_source_type"]
    by_source_type[source_type] = by_source_type.get(source_type, 0) + 1
    for bucket_name, scope_key in (
        ("by_entity", scope.entity_key),
        ("by_name", scope.name_key),
        ("by_pattern", scope.pattern_key),
    ):
        if scope_key is None:
            continue
        bucket = result[bucket_name].setdefault(scope_key, _empty_counts())
        bucket["provenance_total"] += 1


def _iter_eval_scopes(bank: Mapping[str, Any]) -> Iterable[EvalScope]:
    bank_refs = _eval_refs(bank)
    if bank_refs:
        yield EvalScope(kind="bank", path="", eval_refs=bank_refs)

    entities = bank.get("entities", {})
    if not isinstance(entities, Mapping):
        return

    for entity_id, entity in sorted(entities.items()):
        if not isinstance(entity_id, str) or not isinstance(entity, Mapping):
            continue
        entity_map = cast(Mapping[str, Any], entity)
        entity_path = _json_pointer(["entities", entity_id])
        entity_refs = _eval_refs(entity_map)
        if entity_refs:
            yield EvalScope(kind="entity", path=entity_path, eval_refs=entity_refs, entity_id=entity_id)

        names = entity_map.get("names", {})
        if not isinstance(names, Mapping):
            continue
        for name_id, name in sorted(names.items()):
            if not isinstance(name_id, str) or not isinstance(name, Mapping):
                continue
            name_map = cast(Mapping[str, Any], name)
            name_path = _json_pointer(["entities", entity_id, "names", name_id])
            name_refs = _eval_refs(name_map)
            if name_refs:
                yield EvalScope(
                    kind="name",
                    path=name_path,
                    eval_refs=name_refs,
                    entity_id=entity_id,
                    name_id=name_id,
                )

            patterns = name_map.get("patterns", {})
            if not isinstance(patterns, Mapping):
                continue
            for pattern_id, pattern in sorted(patterns.items()):
                if not isinstance(pattern_id, str) or not isinstance(pattern, Mapping):
                    continue
                pattern_map = cast(Mapping[str, Any], pattern)
                pattern_refs = _eval_refs(pattern_map)
                if not pattern_refs:
                    continue
                yield EvalScope(
                    kind="pattern",
                    path=_json_pointer(["entities", entity_id, "names", name_id, "patterns", pattern_id]),
                    eval_refs=pattern_refs,
                    entity_id=entity_id,
                    name_id=name_id,
                    pattern_id=pattern_id,
                )


def _eval_refs(value: Mapping[str, Any]) -> tuple[str, ...]:
    refs = value.get("eval_refs", [])
    if not isinstance(refs, Sequence) or isinstance(refs, (str, bytes)):
        return ()
    return tuple(str(ref) for ref in refs if isinstance(ref, str))


def _load_eval_ref(
    scope: EvalScope,
    eval_ref: str,
    base_path: Path | None,
    options: EvalOptions,
    result: dict[str, Any],
) -> Iterable[tuple[int, Mapping[str, Any]]]:
    path = _resolve_eval_ref_path(eval_ref, base_path)
    if path is None:
        code = EVAL_REF_UNSUPPORTED if _is_uri(eval_ref) else EVAL_REF_UNRESOLVED
        message = (
            "Remote eval refs are not supported by the local eval runner."
            if code == EVAL_REF_UNSUPPORTED
            else "Relative eval refs require an explicit base_path when evaluating an in-memory bank object."
        )
        _append_failure(
            result,
            scope=scope,
            eval_ref=eval_ref,
            record_index=None,
            record_type="eval_ref",
            text=None,
            expected=None,
            actual=None,
            diagnostics=[diagnostic(DIAGNOSTIC_ERROR, code, scope.path, message)],
        )
        return

    if not path.exists():
        _append_failure(
            result,
            scope=scope,
            eval_ref=eval_ref,
            record_index=None,
            record_type="eval_ref",
            text=None,
            expected=None,
            actual=None,
            diagnostics=[
                diagnostic(
                    DIAGNOSTIC_ERROR,
                    EVAL_REF_UNRESOLVED,
                    scope.path,
                    f"Could not read eval ref {eval_ref!r}: file does not exist.",
                    metadata={"file_path": str(path)},
                )
            ],
        )
        return

    try:
        size = path.stat().st_size
    except OSError as exc:
        _append_failure(
            result,
            scope=scope,
            eval_ref=eval_ref,
            record_index=None,
            record_type="eval_ref",
            text=None,
            expected=None,
            actual=None,
            diagnostics=[
                diagnostic(
                    DIAGNOSTIC_ERROR,
                    EVAL_REF_UNRESOLVED,
                    scope.path,
                    f"Could not inspect eval ref {eval_ref!r}: {exc}.",
                    metadata={"file_path": str(path)},
                )
            ],
        )
        return

    if size > options.max_eval_ref_bytes:
        _append_failure(
            result,
            scope=scope,
            eval_ref=eval_ref,
            record_index=None,
            record_type="eval_ref",
            text=None,
            expected=None,
            actual=None,
            diagnostics=[
                diagnostic(
                    DIAGNOSTIC_ERROR,
                    EVAL_REF_TOO_LARGE,
                    scope.path,
                    f"Eval ref {eval_ref!r} exceeds the configured limit of {options.max_eval_ref_bytes} bytes.",
                    metadata={"file_path": str(path), "bytes": size},
                )
            ],
        )
        return

    try:
        with path.open(encoding="utf-8") as file:
            for record_index, line in enumerate(file):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    record = json.loads(stripped, parse_constant=_reject_json_constant)
                except (json.JSONDecodeError, ValueError) as exc:
                    _append_failure(
                        result,
                        scope=scope,
                        eval_ref=eval_ref,
                        record_index=record_index,
                        record_type="invalid",
                        text=None,
                        expected=None,
                        actual=None,
                        diagnostics=[
                            diagnostic(
                                DIAGNOSTIC_ERROR,
                                JSON_PARSE,
                                scope.path,
                                f"Could not parse eval JSONL record {record_index}: {exc}.",
                            )
                        ],
                    )
                    continue

                diagnostics = _record_validation_diagnostics(record)
                if diagnostics:
                    _append_failure(
                        result,
                        scope=scope,
                        eval_ref=eval_ref,
                        record_index=record_index,
                        record_type=str(record.get("type", "invalid")) if isinstance(record, Mapping) else "invalid",
                        text=record.get("text") if isinstance(record, Mapping) else None,
                        expected=record.get("matches") if isinstance(record, Mapping) else None,
                        actual=None,
                        diagnostics=diagnostics,
                    )
                    continue

                yield record_index, cast(Mapping[str, Any], record)
    except OSError as exc:
        _append_failure(
            result,
            scope=scope,
            eval_ref=eval_ref,
            record_index=None,
            record_type="eval_ref",
            text=None,
            expected=None,
            actual=None,
            diagnostics=[
                diagnostic(
                    DIAGNOSTIC_ERROR,
                    EVAL_REF_UNRESOLVED,
                    scope.path,
                    f"Could not read eval ref {eval_ref!r}: {exc}.",
                    metadata={"file_path": str(path)},
                )
            ],
        )


def _resolve_eval_ref_path(eval_ref: str, base_path: Path | None) -> Path | None:
    if _is_uri(eval_ref):
        return None
    path = Path(eval_ref).expanduser()
    if path.is_absolute():
        return path
    if base_path is None:
        return None
    return base_path / path


def _is_uri(eval_ref: str) -> bool:
    return bool(_URI_SCHEME_RE.match(eval_ref))


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-JSON numeric value {value!r}")


def _record_validation_diagnostics(record: Any) -> list[Diagnostic]:
    if not isinstance(record, Mapping):
        return [
            diagnostic(
                DIAGNOSTIC_ERROR,
                SCHEMA_TYPE,
                "",
                "Eval JSONL record must be an object.",
            )
        ]

    record_type = record.get("type")
    if record_type == "positive":
        return _positive_diagnostics(record)
    if record_type == "negative":
        return _negative_diagnostics(record)
    if record_type == "provenance":
        return _provenance_diagnostics(record)

    diagnostics = []
    if "type" not in record:
        diagnostics.append(_missing_diagnostic("/type"))
    else:
        diagnostics.append(
            diagnostic(
                DIAGNOSTIC_ERROR,
                EVAL_RECORD_INVALID,
                "/type",
                "Eval JSONL record type must be 'positive', 'negative', or 'provenance'.",
                metadata={"type": record_type},
            )
        )
    return diagnostics


def _positive_diagnostics(record: Mapping[str, Any]) -> list[Diagnostic]:
    diagnostics = _strict_fields(record, required=_POSITIVE_FIELDS, allowed=_POSITIVE_FIELDS)
    if not isinstance(record.get("text"), str):
        diagnostics.append(_type_diagnostic("/text", "Positive eval text must be a string."))
    diagnostics.extend(_metadata_diagnostics(record.get("metadata")))

    matches = record.get("matches")
    if not isinstance(matches, Sequence) or isinstance(matches, (str, bytes)):
        diagnostics.append(_type_diagnostic("/matches", "Positive eval matches must be an array."))
        return diagnostics
    if not matches:
        diagnostics.append(
            diagnostic(DIAGNOSTIC_ERROR, EVAL_RECORD_INVALID, "/matches", "Positive eval matches must not be empty.")
        )
        return diagnostics

    text = record.get("text")
    for index, match in enumerate(matches):
        diagnostics.extend(_match_diagnostics(match, index, text if isinstance(text, str) else None))
    return diagnostics


def _negative_diagnostics(record: Mapping[str, Any]) -> list[Diagnostic]:
    diagnostics = _strict_fields(record, required=_NEGATIVE_FIELDS, allowed=_NEGATIVE_FIELDS)
    if not isinstance(record.get("text"), str):
        diagnostics.append(_type_diagnostic("/text", "Negative eval text must be a string."))
    if not isinstance(record.get("reason"), str):
        diagnostics.append(_type_diagnostic("/reason", "Negative eval reason must be a string."))
    diagnostics.extend(_metadata_diagnostics(record.get("metadata")))
    return diagnostics


def _provenance_diagnostics(record: Mapping[str, Any]) -> list[Diagnostic]:
    diagnostics = _strict_fields(record, required=_PROVENANCE_FIELDS, allowed=_PROVENANCE_FIELDS)
    if not isinstance(record.get("source_type"), str):
        diagnostics.append(_type_diagnostic("/source_type", "Provenance source_type must be a string."))
    if not isinstance(record.get("observed_at"), str):
        diagnostics.append(_type_diagnostic("/observed_at", "Provenance observed_at must be a string."))
    if not isinstance(record.get("evidence"), str):
        diagnostics.append(_type_diagnostic("/evidence", "Provenance evidence must be a string."))
    diagnostics.extend(_metadata_diagnostics(record.get("metadata")))
    return diagnostics


def _strict_fields(record: Mapping[str, Any], *, required: set[str], allowed: set[str]) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    for field in sorted(required - set(record)):
        diagnostics.append(_missing_diagnostic(f"/{field}"))
    for field in sorted(set(record) - allowed):
        diagnostics.append(
            diagnostic(
                DIAGNOSTIC_ERROR,
                SCHEMA_ADDITIONAL_PROPERTY,
                f"/{field}",
                f"Additional eval record property {field!r} is not allowed.",
            )
        )
    return diagnostics


def _metadata_diagnostics(metadata: Any) -> list[Diagnostic]:
    if not isinstance(metadata, Mapping):
        return [_type_diagnostic("/metadata", "Eval metadata must be an object.")]
    try:
        json.dumps(metadata, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        return [
            diagnostic(
                DIAGNOSTIC_ERROR,
                EVAL_RECORD_INVALID,
                "/metadata",
                f"Eval metadata must be JSON-compatible: {exc}.",
            )
        ]
    return []


def _match_diagnostics(match: Any, index: int, text: str | None) -> list[Diagnostic]:
    path = f"/matches/{index}"
    if not isinstance(match, Mapping):
        return [_type_diagnostic(path, "Positive eval match must be an object.")]

    diagnostics: list[Diagnostic] = []
    for field in sorted({"string", "start", "end"} - set(match)):
        diagnostics.append(_missing_diagnostic(f"{path}/{field}"))
    for field in sorted(set(match) - _MATCH_FIELDS):
        diagnostics.append(
            diagnostic(
                DIAGNOSTIC_ERROR,
                SCHEMA_ADDITIONAL_PROPERTY,
                f"{path}/{field}",
                f"Additional eval match property {field!r} is not allowed.",
            )
        )

    expected_string = match.get("string")
    if not isinstance(expected_string, str):
        diagnostics.append(_type_diagnostic(f"{path}/string", "Positive eval match string must be a string."))

    start = match.get("start")
    end = match.get("end")
    if not _is_non_negative_int(start):
        diagnostics.append(
            _type_diagnostic(f"{path}/start", "Positive eval match start must be a non-negative integer.")
        )
    if not _is_non_negative_int(end):
        diagnostics.append(_type_diagnostic(f"{path}/end", "Positive eval match end must be a non-negative integer."))
    if _is_non_negative_int(start) and _is_non_negative_int(end):
        start_int = cast(int, start)
        end_int = cast(int, end)
        if end_int < start_int:
            diagnostics.append(
                diagnostic(
                    DIAGNOSTIC_ERROR,
                    EVAL_RECORD_INVALID,
                    f"{path}/end",
                    "Positive eval match end must be greater than or equal to start.",
                )
            )
        elif text is not None:
            if end_int > len(text):
                diagnostics.append(
                    diagnostic(
                        DIAGNOSTIC_ERROR,
                        EVAL_RECORD_INVALID,
                        f"{path}/end",
                        "Positive eval match span must be within the eval text.",
                    )
                )
            elif isinstance(expected_string, str) and text[start_int:end_int] != expected_string:
                diagnostics.append(
                    diagnostic(
                        DIAGNOSTIC_ERROR,
                        EVAL_RECORD_INVALID,
                        f"{path}/string",
                        "Positive eval match string must equal text[start:end].",
                    )
                )

    for id_field in ("entity", "entity_id", "name", "name_id", "pattern_id", "pattern_kind"):
        if id_field in match and not isinstance(match[id_field], str):
            diagnostics.append(
                _type_diagnostic(f"{path}/{id_field}", f"Positive eval match {id_field} must be a string.")
            )
    if "entity" in match and "entity_id" in match and match["entity"] != match["entity_id"]:
        diagnostics.append(
            diagnostic(
                DIAGNOSTIC_ERROR,
                EVAL_RECORD_INVALID,
                f"{path}/entity",
                "Positive eval match entity and entity_id must agree when both are provided.",
            )
        )
    if "captures" in match:
        diagnostics.extend(_captures_diagnostics(match["captures"], path))
    return diagnostics


def _captures_diagnostics(captures: Any, match_path: str) -> list[Diagnostic]:
    if not isinstance(captures, Mapping):
        return [_type_diagnostic(f"{match_path}/captures", "Positive eval match captures must be an object.")]

    diagnostics: list[Diagnostic] = []
    for capture_name, capture in captures.items():
        capture_path = f"{match_path}/captures/{_json_pointer_part(str(capture_name))}"
        if not isinstance(capture_name, str):
            diagnostics.append(
                _type_diagnostic(f"{match_path}/captures", "Positive eval capture names must be strings.")
            )
            continue
        if not isinstance(capture, Mapping):
            diagnostics.append(_type_diagnostic(capture_path, "Positive eval capture must be an object."))
            continue

        for field in sorted({"string", "start", "end"} - set(capture)):
            diagnostics.append(_missing_diagnostic(f"{capture_path}/{field}"))
        for field in sorted(set(capture) - {"string", "start", "end"}):
            diagnostics.append(
                diagnostic(
                    DIAGNOSTIC_ERROR,
                    SCHEMA_ADDITIONAL_PROPERTY,
                    f"{capture_path}/{field}",
                    f"Additional eval capture property {field!r} is not allowed.",
                )
            )

        if not isinstance(capture.get("string"), str):
            diagnostics.append(
                _type_diagnostic(f"{capture_path}/string", "Positive eval capture string must be a string.")
            )
        if not _is_non_negative_int(capture.get("start")):
            diagnostics.append(
                _type_diagnostic(f"{capture_path}/start", "Positive eval capture start must be a non-negative integer.")
            )
        if not _is_non_negative_int(capture.get("end")):
            diagnostics.append(
                _type_diagnostic(f"{capture_path}/end", "Positive eval capture end must be a non-negative integer.")
            )
        if _is_non_negative_int(capture.get("start")) and _is_non_negative_int(capture.get("end")):
            start = cast(int, capture["start"])
            end = cast(int, capture["end"])
            if end < start:
                diagnostics.append(
                    diagnostic(
                        DIAGNOSTIC_ERROR,
                        EVAL_RECORD_INVALID,
                        f"{capture_path}/end",
                        "Positive eval capture end must be greater than or equal to start.",
                    )
                )
    return diagnostics


def _json_pointer_part(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _is_non_negative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _missing_diagnostic(path: str) -> Diagnostic:
    return diagnostic(DIAGNOSTIC_ERROR, SCHEMA_REQUIRED, path, "Required eval record property is missing.")


def _type_diagnostic(path: str, message: str) -> Diagnostic:
    return diagnostic(DIAGNOSTIC_ERROR, SCHEMA_TYPE, path, message)


def _evaluate_record(
    bank: Mapping[str, Any],
    scope: EvalScope,
    eval_ref: str,
    record_index: int,
    record: Mapping[str, Any],
    extraction_options: Mapping[str, Any] | None,
    result: dict[str, Any],
) -> None:
    record_type = record["type"]
    if record_type == "positive":
        _evaluate_positive(bank, scope, eval_ref, record_index, record, extraction_options, result)
    elif record_type == "negative":
        _evaluate_negative(bank, scope, eval_ref, record_index, record, extraction_options, result)
    else:
        _increment_provenance(result, scope, str(record["source_type"]))


def _evaluate_positive(
    bank: Mapping[str, Any],
    scope: EvalScope,
    eval_ref: str,
    record_index: int,
    record: Mapping[str, Any],
    extraction_options: Mapping[str, Any] | None,
    result: dict[str, Any],
) -> None:
    _increment(result, scope, "positive_total")
    expected = [
        _normalize_expected_match(match, scope) for match in cast(Sequence[Mapping[str, Any]], record["matches"])
    ]
    actual = _actual_for_text(bank, scope, str(record["text"]), extraction_options)
    fields = _comparison_fields(expected)
    expected_records = _project_records(expected, fields)
    actual_records = _project_records(actual, fields)

    if expected_records == actual_records:
        return

    _increment(result, scope, "positive_failed")
    _append_failure(
        result,
        scope=scope,
        eval_ref=eval_ref,
        record_index=record_index,
        record_type="positive",
        text=str(record["text"]),
        expected=expected_records,
        actual=actual_records,
        diagnostics=[
            diagnostic(
                DIAGNOSTIC_ERROR,
                EVAL_POSITIVE_FAILED,
                scope.path,
                "Positive eval expected records did not match actual scoped extraction records.",
                metadata={"scope": scope.kind, "comparison_fields": list(fields)},
            )
        ],
    )


def _evaluate_negative(
    bank: Mapping[str, Any],
    scope: EvalScope,
    eval_ref: str,
    record_index: int,
    record: Mapping[str, Any],
    extraction_options: Mapping[str, Any] | None,
    result: dict[str, Any],
) -> None:
    _increment(result, scope, "negative_total")
    actual = _actual_for_text(bank, scope, str(record["text"]), extraction_options)
    if not actual:
        return

    _increment(result, scope, "negative_failed")
    actual_records = _project_records(actual, _CORE_COMPARISON_FIELDS + _OPTIONAL_COMPARISON_FIELDS)
    _append_failure(
        result,
        scope=scope,
        eval_ref=eval_ref,
        record_index=record_index,
        record_type="negative",
        text=str(record["text"]),
        expected=[],
        actual=actual_records,
        diagnostics=[
            diagnostic(
                DIAGNOSTIC_ERROR,
                EVAL_NEGATIVE_FAILED,
                scope.path,
                "Negative eval produced scoped extraction records.",
                metadata={"scope": scope.kind, "reason": record["reason"]},
            )
        ],
    )


def _actual_for_text(
    bank: Mapping[str, Any],
    scope: EvalScope,
    text: str,
    options: Mapping[str, Any] | None,
) -> list[MatchRecord]:
    extraction = extract_text(bank, text, options=options)
    records = [_record for _record in extraction["records"] if _record_in_scope(_record, scope)]
    records.sort(key=record_sort_key)
    return records


def _record_in_scope(record: Mapping[str, Any], scope: EvalScope) -> bool:
    if scope.entity_id is not None and record.get("entity_id") != scope.entity_id:
        return False
    if scope.name_id is not None and record.get("name_id") != scope.name_id:
        return False
    if scope.pattern_id is not None and record.get("pattern_id") != scope.pattern_id:
        return False
    return True


def _normalize_expected_match(match: Mapping[str, Any], scope: EvalScope) -> dict[str, Any]:
    expected = dict(match)
    if "entity_id" not in expected and "entity" in expected:
        expected["entity_id"] = expected["entity"]
    expected.pop("entity", None)
    expected.pop("name", None)

    if scope.entity_id is not None and "entity_id" not in expected:
        expected["entity_id"] = scope.entity_id
    if scope.name_id is not None and "name_id" not in expected:
        expected["name_id"] = scope.name_id
    if scope.pattern_id is not None and "pattern_id" not in expected:
        expected["pattern_id"] = scope.pattern_id
    return expected


def _comparison_fields(records: Sequence[Mapping[str, Any]]) -> tuple[str, ...]:
    fields: list[str] = list(_CORE_COMPARISON_FIELDS)
    for field in _OPTIONAL_COMPARISON_FIELDS:
        if any(field in record for record in records):
            fields.append(field)
    return tuple(fields)


def _project_records(records: Sequence[Mapping[str, Any]], fields: Sequence[str]) -> list[dict[str, Any]]:
    projected: list[dict[str, Any]] = []
    for record in records:
        item = {field: record[field] for field in fields if field in record}
        projected.append(item)
    projected.sort(key=_projected_record_sort_key)
    return projected


def _projected_record_sort_key(record: Mapping[str, Any]) -> tuple[Any, ...]:
    return tuple(
        json.dumps(record.get(field), sort_keys=True, ensure_ascii=False) for field in _CORE_COMPARISON_FIELDS
    ) + (json.dumps(record, sort_keys=True, ensure_ascii=False),)


def _append_failure(
    result: dict[str, Any],
    *,
    scope: EvalScope,
    eval_ref: str,
    record_index: int | None,
    record_type: str,
    text: str | None,
    expected: Any,
    actual: Any,
    diagnostics: list[Diagnostic],
) -> None:
    result["failures"].append(
        {
            "path": scope.path,
            "eval_ref": eval_ref,
            "record": record_index,
            "type": record_type,
            "text": text,
            "expected": expected,
            "actual": actual,
            "diagnostics": diagnostics,
        }
    )


def _json_pointer(parts: Iterable[Any]) -> str:
    escaped = [str(part).replace("~", "~0").replace("/", "~1") for part in parts]
    return "/" + "/".join(escaped) if escaped else ""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, cast

from .bank import canonicalize_bank
from .diagnostics import DIAGNOSTIC_WARNING, REPORT_EXPECTED_MISSING, diagnostic, has_errors
from .engines import ExtractionError
from .extraction import _extract_prepared_batch, _prepare_batch_documents, extract_text
from .records import MatchRecord, record_sort_key
from .schema import REGEX_FLAG_ORDER, validate_bank_schema

__all__ = ["extract_report", "extract_report_batch", "explain_match"]

DEFAULT_OVERLAP_POLICY = "priority"
DEFAULT_CONTEXT_CHARS = 80
DEFAULT_INCLUDE_METADATA = False
DEFAULT_INCLUDE_PATTERN_VALUES = True
DEFAULT_EXPECTED_MATCH_SCOPE = "resolved"


@dataclass(frozen=True)
class ExpectedMatch:
    entity_id: str
    name_id: str


@dataclass(frozen=True)
class ReportOptions:
    overlap_policy: str
    context_chars: int
    include_metadata: bool
    include_pattern_values: bool
    include_eval_refs: bool
    expected: tuple[ExpectedMatch, ...]
    expected_match_scope: str


def extract_report(
    bank: Mapping[str, Any],
    text: str,
    *,
    options: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a report with raw records, report-level resolved records, summaries, and diagnostics."""
    report_options = _resolve_report_options(options)
    extraction = extract_text(bank, text, options=options)
    canonical_bank = canonicalize_bank(bank)
    return _build_report(canonical_bank, text, extraction, report_options)


def extract_report_batch(
    bank: Mapping[str, Any],
    documents: Sequence[Mapping[str, Any]],
    *,
    options: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return reports for a bounded batch of text or file documents."""
    report_options = _resolve_report_options(options)
    prepared_documents, combined_bytes = _prepare_batch_documents(documents, options=options)
    batch = _extract_prepared_batch(bank, prepared_documents, combined_bytes=combined_bytes, options=options)
    canonical_bank = canonicalize_bank(bank)

    document_reports: list[dict[str, Any]] = []
    flat_resolved_records: list[dict[str, Any]] = []
    flat_overlaps: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []

    for index, (document_id, _source, text) in enumerate(prepared_documents):
        document_result = batch["documents"][index]
        report = _build_report(
            canonical_bank,
            text,
            {
                "bank": batch["bank"],
                "engine": batch["engine"],
                "source": document_result["source"],
                "records": document_result["records"],
            },
            report_options,
        )
        document_report = {
            "document_id": document_id,
            "source": document_result["source"],
            "records": report["records"],
            "resolved_records": report["resolved_records"],
            "overlaps": report["overlaps"],
            "summary": report["summary"],
            "diagnostics": report["diagnostics"],
        }
        document_reports.append(document_report)

        for resolved in report["resolved_records"]:
            flat_resolved = {
                **resolved,
                "record": {"document_id": document_id, **resolved["record"]},
            }
            flat_resolved_records.append(flat_resolved)

        for overlap in report["overlaps"]:
            flat_overlaps.append({"document_id": document_id, **overlap})

        for item in report["diagnostics"]:
            metadata = dict(item.get("metadata", {}))
            metadata["document_id"] = document_id
            diagnostics.append({**item, "metadata": metadata})

    flat_resolved_records.sort(key=lambda item: _batch_decorated_record_sort_key(item["record"]))
    flat_overlaps.sort(key=lambda item: (item["document_id"], item["span"]["start"], item["span"]["end"], item["id"]))
    diagnostics.sort(key=lambda item: (item.get("path", ""), item.get("metadata", {}).get("document_id", "")))

    return {
        "bank": batch["bank"],
        "engine": batch["engine"],
        "source": batch["source"],
        "documents": document_reports,
        "records": batch["records"],
        "resolved_records": flat_resolved_records,
        "overlaps": flat_overlaps,
        "summary": {
            "document_count": batch["summary"]["document_count"],
            "record_count": len(batch["records"]),
            "resolved_record_count": len(flat_resolved_records),
            "documents_with_records": batch["summary"]["documents_with_records"],
            "documents_with_resolved_records": sum(1 for report in document_reports if report["resolved_records"]),
            **_grouped_counts([item["record"] for item in flat_resolved_records]),
        },
        "diagnostics": diagnostics,
    }


def explain_match(
    bank: Mapping[str, Any],
    entity_id: str,
    name_id: str,
    pattern_id: str,
    *,
    options: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Explain one configured pattern without scanning text."""
    report_options = _resolve_report_options(options)
    schema_result = validate_bank_schema(bank)
    diagnostics = schema_result["diagnostics"]
    if has_errors(diagnostics):
        raise ExtractionError("Bank failed schema validation and cannot be explained.", diagnostics)
    canonical_bank = canonicalize_bank(bank)
    return _explain_pattern(canonical_bank, entity_id, name_id, pattern_id, report_options)


def _build_report(
    bank: Mapping[str, Any],
    text: str,
    extraction: Mapping[str, Any],
    options: ReportOptions,
) -> dict[str, Any]:
    records = list(extraction["records"])
    overlap_groups = _overlap_groups(bank, records, options)
    resolved_records = _resolve_records(records, overlap_groups)
    decorated_resolved_records = [
        {
            "record": record,
            "explanation": _compact_explanation(bank, record, options),
            "context": _context_snippet(text, record, options.context_chars),
        }
        for record in resolved_records
    ]
    diagnostics = _expected_diagnostics(options, records, resolved_records)

    return {
        "bank": extraction["bank"],
        "engine": extraction["engine"],
        "source": extraction["source"],
        "records": records,
        "resolved_records": decorated_resolved_records,
        "overlaps": overlap_groups,
        "summary": {
            "record_count": len(records),
            "resolved_record_count": len(resolved_records),
            **_grouped_counts(resolved_records),
        },
        "diagnostics": diagnostics,
    }


def _resolve_report_options(options: Mapping[str, Any] | None) -> ReportOptions:
    raw_options = options or {}
    overlap_policy = raw_options.get("overlap_policy", DEFAULT_OVERLAP_POLICY)
    if overlap_policy != DEFAULT_OVERLAP_POLICY:
        raise ExtractionError("Report option overlap_policy must be 'priority'.")

    context_chars = raw_options.get("context_chars", DEFAULT_CONTEXT_CHARS)
    if not isinstance(context_chars, int) or isinstance(context_chars, bool) or context_chars < 0:
        raise ExtractionError("Report option context_chars must be a non-negative integer.")

    include_metadata = _bool_option(raw_options, "include_metadata", DEFAULT_INCLUDE_METADATA)
    include_pattern_values = _bool_option(raw_options, "include_pattern_values", DEFAULT_INCLUDE_PATTERN_VALUES)
    include_eval_refs = _bool_option(raw_options, "include_eval_refs", False)

    expected_match_scope = raw_options.get("expected_match_scope", DEFAULT_EXPECTED_MATCH_SCOPE)
    if expected_match_scope not in {"resolved", "raw"}:
        raise ExtractionError("Report option expected_match_scope must be 'resolved' or 'raw'.")

    return ReportOptions(
        overlap_policy=overlap_policy,
        context_chars=context_chars,
        include_metadata=include_metadata,
        include_pattern_values=include_pattern_values,
        include_eval_refs=include_eval_refs,
        expected=_expected_matches(raw_options.get("expected", [])),
        expected_match_scope=expected_match_scope,
    )


def _bool_option(options: Mapping[str, Any], key: str, default: bool) -> bool:
    value = options.get(key, default)
    if not isinstance(value, bool):
        raise ExtractionError(f"Report option {key} must be a boolean.")
    return value


def _expected_matches(value: Any) -> tuple[ExpectedMatch, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ExtractionError("Report option expected must be a sequence of objects.")

    expected: list[ExpectedMatch] = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            raise ExtractionError(f"Report option expected item {index} must be an object.")
        expected_item = cast(Mapping[str, Any], item)
        entity_id = expected_item.get("entity_id")
        name_id = expected_item.get("name_id")
        if not isinstance(entity_id, str) or not isinstance(name_id, str):
            raise ExtractionError(f"Report option expected item {index} must include string entity_id and name_id.")
        expected.append(ExpectedMatch(entity_id=entity_id, name_id=name_id))
    return tuple(expected)


def _overlap_groups(
    bank: Mapping[str, Any],
    records: list[MatchRecord],
    options: ReportOptions,
) -> list[dict[str, Any]]:
    del options
    groups: list[list[tuple[int, MatchRecord]]] = []
    current_group: list[tuple[int, MatchRecord]] = []
    current_end = -1

    for index, record in enumerate(records):
        start = int(record["start"])
        end = int(record["end"])
        if not current_group or start >= current_end:
            if len(current_group) > 1:
                groups.append(current_group)
            current_group = [(index, record)]
            current_end = end
            continue
        current_group.append((index, record))
        current_end = max(current_end, end)

    if len(current_group) > 1:
        groups.append(current_group)

    overlap_items: list[dict[str, Any]] = []
    for group_index, group in enumerate(groups):
        winner_index, winner = _select_priority_winner(bank, group)
        losers = [record for index, record in group if index != winner_index]
        overlap_items.append(
            {
                "id": f"overlap_{group_index}",
                "policy": DEFAULT_OVERLAP_POLICY,
                "span": {
                    "start": min(int(record["start"]) for _, record in group),
                    "end": max(int(record["end"]) for _, record in group),
                },
                "records": [record for _, record in group],
                "resolved_record": winner,
                "dropped_records": losers,
            }
        )
    return overlap_items


def _resolve_records(records: list[MatchRecord], overlap_groups: list[dict[str, Any]]) -> list[MatchRecord]:
    dropped_keys = {_record_identity_key(record) for group in overlap_groups for record in group["dropped_records"]}
    resolved = [record for record in records if _record_identity_key(record) not in dropped_keys]
    resolved.sort(key=record_sort_key)
    return resolved


def _select_priority_winner(
    bank: Mapping[str, Any],
    group: list[tuple[int, MatchRecord]],
) -> tuple[int, MatchRecord]:
    return min(group, key=lambda item: (_priority_resolution_key(bank, item[1]), item[0]))


def _priority_resolution_key(bank: Mapping[str, Any], record: MatchRecord) -> tuple[int, int, int, str, str, str, str]:
    pattern = _pattern_for_record(bank, record)
    priority = pattern.get("priority", 0)
    if not isinstance(priority, int) or isinstance(priority, bool):
        priority = 0
    length = int(record["end"]) - int(record["start"])
    return (
        -priority,
        -length,
        int(record["start"]),
        str(record["entity_id"]),
        str(record["name_id"]),
        str(record["pattern_id"]),
        str(record["string"]),
    )


def _record_identity_key(record: MatchRecord) -> tuple[str, str, str, int, int, str]:
    return (
        str(record["entity_id"]),
        str(record["name_id"]),
        str(record["pattern_id"]),
        int(record["start"]),
        int(record["end"]),
        str(record["string"]),
    )


def _grouped_counts(records: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, int]]:
    entity_counts: Counter[str] = Counter()
    name_counts: Counter[str] = Counter()
    for record in records:
        entity_id = str(record["entity_id"])
        name_id = str(record["name_id"])
        entity_counts[entity_id] += 1
        name_counts[f"{entity_id}/{name_id}"] += 1
    return {"entity_counts": dict(sorted(entity_counts.items())), "name_counts": dict(sorted(name_counts.items()))}


def _context_snippet(text: str, record: Mapping[str, Any], context_chars: int) -> dict[str, str]:
    start = int(record["start"])
    end = int(record["end"])
    return {
        "before": text[max(0, start - context_chars) : start],
        "match": text[start:end],
        "after": text[end : end + context_chars],
    }


def _compact_explanation(bank: Mapping[str, Any], record: Mapping[str, Any], options: ReportOptions) -> dict[str, Any]:
    return _explain_pattern(
        bank,
        str(record["entity_id"]),
        str(record["name_id"]),
        str(record["pattern_id"]),
        options,
    )


def _explain_pattern(
    bank: Mapping[str, Any],
    entity_id: str,
    name_id: str,
    pattern_id: str,
    options: ReportOptions,
) -> dict[str, Any]:
    entity, name, pattern = _pattern_context(bank, entity_id, name_id, pattern_id)
    pattern_kind = pattern["kind"]
    explanation: dict[str, Any] = {
        "pattern_path": _pattern_path(entity_id, name_id, pattern_id),
        "pattern_kind": pattern_kind,
        "priority": pattern["priority"],
        "description": pattern["description"],
        "normalization_mode": bank["unicode_normalization"],
    }
    if options.include_pattern_values:
        explanation["pattern_value"] = pattern["value"]
    if pattern_kind == "regex":
        explanation["effective_regex_flags"] = _effective_regex_flags(bank, entity, pattern)
    else:
        explanation["literal_settings"] = {
            "case_sensitive": pattern["case_sensitive"],
            "normalize_whitespace": pattern["normalize_whitespace"],
            "left_boundary": pattern["left_boundary"],
            "right_boundary": pattern["right_boundary"],
        }
    if options.include_metadata:
        explanation["metadata"] = {
            "bank": bank.get("metadata", {}),
            "entity": entity.get("metadata", {}),
            "name": name.get("metadata", {}),
            "pattern": pattern.get("metadata", {}),
        }
    if options.include_eval_refs:
        explanation["eval_refs"] = _eval_refs(bank, entity, name, pattern)
    return explanation


def _expected_diagnostics(
    options: ReportOptions,
    raw_records: Sequence[Mapping[str, Any]],
    resolved_records: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    if not options.expected:
        return []
    scoped_records = raw_records if options.expected_match_scope == "raw" else resolved_records
    matched_pairs = {(str(record["entity_id"]), str(record["name_id"])) for record in scoped_records}

    diagnostics: list[dict[str, Any]] = []
    for index, expected in enumerate(options.expected):
        if (expected.entity_id, expected.name_id) in matched_pairs:
            continue
        diagnostics.append(
            diagnostic(
                DIAGNOSTIC_WARNING,
                REPORT_EXPECTED_MISSING,
                f"/expected/{index}",
                "Expected entity/name was not matched.",
                metadata={
                    "entity_id": expected.entity_id,
                    "name_id": expected.name_id,
                    "expected_match_scope": options.expected_match_scope,
                },
            )
        )
    return diagnostics


def _pattern_for_record(bank: Mapping[str, Any], record: Mapping[str, Any]) -> Mapping[str, Any]:
    _, _, pattern = _pattern_context(
        bank,
        str(record["entity_id"]),
        str(record["name_id"]),
        str(record["pattern_id"]),
    )
    return pattern


def _pattern_context(
    bank: Mapping[str, Any],
    entity_id: str,
    name_id: str,
    pattern_id: str,
) -> tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]]:
    try:
        entity = bank["entities"][entity_id]
        name = entity["names"][name_id]
        pattern = name["patterns"][pattern_id]
    except KeyError as exc:
        raise ExtractionError(f"Pattern not found: {entity_id}/{name_id}/{pattern_id}.") from exc
    if not isinstance(entity, Mapping) or not isinstance(name, Mapping) or not isinstance(pattern, Mapping):
        raise ExtractionError(f"Pattern not found: {entity_id}/{name_id}/{pattern_id}.")
    return entity, name, pattern


def _effective_regex_flags(
    bank: Mapping[str, Any],
    entity: Mapping[str, Any],
    pattern: Mapping[str, Any],
) -> list[str]:
    seen: set[str] = set()
    flags: list[str] = []
    for flag_set in (
        bank.get("default_regex_flags", []),
        entity.get("regex_flags", []),
        pattern.get("regex_flags", []),
    ):
        if not isinstance(flag_set, Sequence) or isinstance(flag_set, (str, bytes)):
            continue
        for flag in flag_set:
            if isinstance(flag, str) and flag in REGEX_FLAG_ORDER and flag not in seen:
                seen.add(flag)
                flags.append(flag)
    return sorted(flags, key=REGEX_FLAG_ORDER.index)


def _eval_refs(
    bank: Mapping[str, Any],
    entity: Mapping[str, Any],
    name: Mapping[str, Any],
    pattern: Mapping[str, Any],
) -> dict[str, list[str]]:
    refs: dict[str, list[str]] = {}
    for key, value in (
        ("bank", bank.get("eval_refs")),
        ("entity", entity.get("eval_refs")),
        ("name", name.get("eval_refs")),
        ("pattern", pattern.get("eval_refs")),
    ):
        if isinstance(value, list):
            refs[key] = [item for item in value if isinstance(item, str)]
    return refs


def _pattern_path(entity_id: str, name_id: str, pattern_id: str) -> str:
    entity_part = _json_pointer_part(entity_id)
    name_part = _json_pointer_part(name_id)
    pattern_part = _json_pointer_part(pattern_id)
    return f"/entities/{entity_part}/names/{name_part}/patterns/{pattern_part}"


def _json_pointer_part(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _batch_decorated_record_sort_key(record: Mapping[str, Any]) -> tuple[str, int, int, str, str, str, str]:
    return (
        str(record["document_id"]),
        int(record["start"]),
        int(record["end"]),
        str(record["entity_id"]),
        str(record["name_id"]),
        str(record["pattern_id"]),
        str(record["string"]),
    )

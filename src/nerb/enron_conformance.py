"""Privacy-safe catalog conformance evaluation for the Enron benchmark.

The evaluator scans synthetic, privately held case text with the complete active
bank.  Public results contain only aggregate counts and content fingerprints;
case text, identities, and per-case outcomes stay inside an optional private
transactional run.
"""

from __future__ import annotations

import hashlib
import heapq
import json
import re
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, TextIO, cast

from . import enron_contract
from .bank import bank_stats, hash_bank
from .engines import CompiledBank, compile_bank, extraction_execution_sha256
from .enron_activity import ACTIVITY_RECORD_INTERVAL
from .enron_contract import validate_enron_conformance_output
from .enron_private_io import EnronPrivateIOError, PrivateRun, iter_strict_jsonl

RESULT_SCHEMA_VERSION = "nerb.enron_conformance_result.v2"
POSITIVE_CASE_SCHEMA_VERSION = "nerb.enron_conformance_positive_case.v2"
NEGATIVE_CASE_SCHEMA_VERSION = "nerb.enron_conformance_negative_case.v2"
CASE_RESULT_SCHEMA_VERSION = "nerb.enron_conformance_case_result.v2"
EVALUATOR_ID = "nerb-enron-catalog-conformance"
EVALUATOR_VERSION = "2.0.0"

DEFAULT_LABEL_ARTIFACT_ID = "enron_catalog_conformance_labels"
DEFAULT_POSITIVE_ARTIFACT_ID = "enron_catalog_conformance_positive_cases"
DEFAULT_NEGATIVE_ARTIFACT_ID = "enron_catalog_conformance_negative_cases"
DEFAULT_MAX_CASES = 250_000
DEFAULT_MAX_LINE_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_CASE_TEXT_BYTES = 10 * 1024 * 1024
DEFAULT_MAX_EXPECTED_PER_CASE = 10_000
DEFAULT_MAX_MATCHES_PER_CASE = 100_000

ADVERSARIAL_TAGS = frozenset(
    {
        "boundary",
        "casing",
        "html",
        "malformed",
        "negative",
        "overlap",
        "punctuation",
        "signature",
        "unicode",
        "whitespace",
    }
)
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256_PREFIX = "sha256:"
_POSITIVE_FIELDS = frozenset({"schema_version", "case_id", "text", "tags", "expected"})
_NEGATIVE_FIELDS = frozenset({"schema_version", "case_id", "text", "tags", "reason_code"})
_EXPECTED_FIELDS = frozenset(
    {
        "entity_id",
        "name_id",
        "pattern_id",
        "pattern_kind",
        "canonical_name",
        "string",
        "start",
        "end",
    }
)

_POLICY = {
    "schema_version": "nerb.enron_conformance_policy.v2",
    "active_chain": ["bank", "entity", "name", "pattern"],
    "included_statuses": ["active"],
    "case_schemas": [POSITIVE_CASE_SCHEMA_VERSION, NEGATIVE_CASE_SCHEMA_VERSION],
    "offset_unit": "utf8_byte",
    "positive_matching": "one_to_one_exact_span_string_entity_name_pattern_kind_canonical",
    "wrong_canonical": "unmatched_exact_span_string_entity_with_different_name_or_canonical",
    "same_canonical_wrong_pattern": "missed",
    "negative_matching": "case_fails_when_any_full_active_bank_record_is_emitted",
    "required_adversarial_tags": sorted(ADVERSARIAL_TAGS),
    "case_order": "case_id_lexicographic",
    "expected_order": "exact_record_identity_lexicographic",
    "empty_evidence": "not_evaluated_and_fail_closed",
    "resource_limits": "bounded_cases_lines_artifacts_text_expected_and_emitted_matches",
}


class EnronConformanceError(ValueError):
    """Raised when conformance evidence cannot be evaluated safely."""


@dataclass(frozen=True)
class EnronConformanceOptions:
    """Resource limits and logical artifact identities for one evaluation."""

    label_artifact_id: str = DEFAULT_LABEL_ARTIFACT_ID
    positive_artifact_id: str = DEFAULT_POSITIVE_ARTIFACT_ID
    negative_artifact_id: str = DEFAULT_NEGATIVE_ARTIFACT_ID
    max_cases: int = DEFAULT_MAX_CASES
    max_line_bytes: int = DEFAULT_MAX_LINE_BYTES
    max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES
    max_case_text_bytes: int = DEFAULT_MAX_CASE_TEXT_BYTES
    max_expected_per_case: int = DEFAULT_MAX_EXPECTED_PER_CASE
    max_matches_per_case: int = DEFAULT_MAX_MATCHES_PER_CASE


@dataclass(frozen=True)
class _ActivePattern:
    entity_id: str
    name_id: str
    pattern_id: str
    pattern_kind: str
    canonical_name: str

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.entity_id, self.name_id, self.pattern_id)


@dataclass(frozen=True)
class _Evaluation:
    public: dict[str, Any]
    positive_bytes: bytes | None
    negative_bytes: bytes | None
    positive_details: tuple[dict[str, Any], ...]
    negative_details: tuple[dict[str, Any], ...]


@dataclass(slots=True)
class _ActivityReporter:
    callback: Callable[[], None] | None
    pending: int = 0

    def worked(self) -> None:
        self.pending += 1
        if self.pending == ACTIVITY_RECORD_INTERVAL:
            self.boundary()

    def boundary(self) -> None:
        if self.callback is not None:
            try:
                self.callback()
            except Exception:
                raise EnronConformanceError("Conformance activity callback failed.") from None
        self.pending = 0


def evaluate_enron_conformance(
    bank: Mapping[str, Any],
    positive_cases: Sequence[Mapping[str, Any]],
    negative_cases: Sequence[Mapping[str, Any]],
    *,
    options: EnronConformanceOptions | None = None,
    activity_callback: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Evaluate strict synthetic cases and return only aggregates and digests.

    Case text and expected identities are accepted as private inputs but are
    deliberately absent from the returned mapping.
    """

    return _evaluate(
        bank,
        positive_cases,
        negative_cases,
        options or EnronConformanceOptions(),
        capture_private_audit=False,
        activity_callback=activity_callback,
    ).public


def evaluate_enron_conformance_files(
    bank: Mapping[str, Any],
    positive_cases_path: str | Path,
    negative_cases_path: str | Path,
    output_dir: str | Path,
    *,
    options: EnronConformanceOptions | None = None,
    allow_unignored_output: bool = False,
    activity_callback: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Evaluate strict JSONL cases and atomically commit a private audit run."""

    resolved = options or EnronConformanceOptions()
    _validate_options(resolved)
    try:
        positive_cases = _load_jsonl_cases(Path(positive_cases_path), resolved)
        negative_cases = _load_jsonl_cases(Path(negative_cases_path), resolved)
        evaluation = _evaluate(
            bank,
            positive_cases,
            negative_cases,
            resolved,
            capture_private_audit=True,
            activity_callback=activity_callback,
        )
        if evaluation.positive_bytes is None or evaluation.negative_bytes is None:
            raise EnronConformanceError("Conformance private audit capture failed safely.")
        with PrivateRun(Path(output_dir), allow_unignored_output=allow_unignored_output) as run:
            with run.open_binary("positive-cases.jsonl") as file:
                file.write(evaluation.positive_bytes)
            with run.open_binary("negative-cases.jsonl") as file:
                file.write(evaluation.negative_bytes)
            with run.open_text("positive-results.jsonl") as file:
                _write_detail_jsonl(file, evaluation.positive_details)
            with run.open_text("negative-results.jsonl") as file:
                _write_detail_jsonl(file, evaluation.negative_details)
            with run.open_text("aggregate.json") as file:
                file.write(json.dumps(evaluation.public, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False))
                file.write("\n")
            run.commit()
    except EnronPrivateIOError as exc:
        raise EnronConformanceError(str(exc)) from None

    return {**evaluation.public, "committed": True}


def enron_conformance_policy_sha256() -> str:
    """Return the digest of the frozen conformance semantics."""

    return _hash_bytes(_canonical_json_bytes(_POLICY))


def enron_conformance_evaluator_source_sha256() -> str:
    """Return a digest of the evaluator-owned implementation source."""

    try:
        source = Path(__file__).read_bytes()
    except OSError:  # pragma: no cover - installed package corruption
        raise EnronConformanceError("Conformance evaluator source could not be fingerprinted.") from None
    return _hash_bytes(source)


def _evaluate(
    bank: Mapping[str, Any],
    positive_cases: Sequence[Mapping[str, Any]],
    negative_cases: Sequence[Mapping[str, Any]],
    options: EnronConformanceOptions,
    *,
    capture_private_audit: bool,
    activity_callback: Callable[[], None] | None = None,
) -> _Evaluation:
    if activity_callback is not None and not callable(activity_callback):
        raise EnronConformanceError("Conformance activity callback must be callable when provided.")
    activity = _ActivityReporter(activity_callback)
    activity.boundary()
    _validate_options(options)
    if not isinstance(bank, Mapping):
        raise EnronConformanceError("Conformance bank must be a mapping.")
    if isinstance(positive_cases, (str, bytes)) or not isinstance(positive_cases, Sequence):
        raise EnronConformanceError("Positive conformance cases must be a sequence of objects.")
    if isinstance(negative_cases, (str, bytes)) or not isinstance(negative_cases, Sequence):
        raise EnronConformanceError("Negative conformance cases must be a sequence of objects.")
    if len(positive_cases) > options.max_cases or len(negative_cases) > options.max_cases:
        raise EnronConformanceError("Conformance case count exceeds the configured limit.")

    try:
        compiled, _cache_hit = compile_bank(bank, options={"include_statuses": ["active"]})
    except Exception:
        raise EnronConformanceError("Conformance bank could not be compiled safely.") from None
    active_patterns = _active_pattern_catalog(compiled)
    activity.boundary()
    normalized_positive = _normalize_positive_cases(
        positive_cases,
        active_patterns,
        options,
        activity_reporter=activity,
    )
    normalized_negative = _normalize_negative_cases(
        negative_cases,
        options,
        activity_reporter=activity,
    )
    _validate_case_set(normalized_positive, normalized_negative)

    positive_bytes, positive_size, positive_sha256 = _canonical_jsonl_artifact(
        normalized_positive,
        max_bytes=options.max_artifact_bytes,
        capture_payload=capture_private_audit,
        activity_reporter=activity,
    )
    negative_bytes, negative_size, negative_sha256 = _canonical_jsonl_artifact(
        normalized_negative,
        max_bytes=options.max_artifact_bytes,
        capture_payload=capture_private_audit,
        activity_reporter=activity,
    )
    if positive_size and negative_size and positive_sha256 == negative_sha256:
        raise EnronConformanceError("Positive and negative case artifacts must be distinct.")

    evaluator_source_sha256 = enron_conformance_evaluator_source_sha256()
    try:
        contract_validator_source_sha256 = _hash_bytes(Path(enron_contract.__file__).read_bytes())
        execution_adapter_sha256 = extraction_execution_sha256()
    except (OSError, RuntimeError, ValueError):
        raise EnronConformanceError("Conformance contract validator could not be fingerprinted.") from None
    contract_schema_sha256 = _hash_bytes(_canonical_json_bytes(enron_contract.ENRON_CONFORMANCE_OUTPUT_SCHEMA))
    policy_sha256 = enron_conformance_policy_sha256()
    bank_hash = hash_bank(compiled.bank)
    case_plan_sha256 = _hash_bytes(
        _canonical_json_bytes(
            {
                "schema_version": "nerb.enron_conformance_case_plan.v2",
                "label_artifact_id": options.label_artifact_id,
                "positive_cases_artifact": {
                    "id": options.positive_artifact_id,
                    "sha256": positive_sha256,
                    "bytes": positive_size,
                },
                "negative_cases_artifact": {
                    "id": options.negative_artifact_id,
                    "sha256": negative_sha256,
                    "bytes": negative_size,
                },
            }
        )
    )
    fingerprints = {
        "bank_hash": bank_hash,
        "engine_bank_hash": compiled.bank_hash,
        "case_plan_sha256": case_plan_sha256,
        "contract_schema_sha256": contract_schema_sha256,
        "contract_validator_source_sha256": contract_validator_source_sha256,
        "evaluator_source_sha256": evaluator_source_sha256,
        "execution_adapter_sha256": execution_adapter_sha256,
        "negative_cases_sha256": negative_sha256,
        "policy_sha256": policy_sha256,
        "positive_cases_sha256": positive_sha256,
    }
    fingerprints["comparison_sha256"] = _hash_bytes(
        _canonical_json_bytes(
            {
                "schema_version": "nerb.enron_conformance_fingerprint.v2",
                **fingerprints,
                "engine": {
                    "name": compiled.engine_name,
                    "version": compiled.engine_version,
                    "options": compiled.engine_options,
                },
            }
        )
    )

    if not active_patterns or not normalized_positive or not normalized_negative:
        aggregate = _unevaluated_aggregate()
        activity.boundary()
        return _Evaluation(
            public=_public_result(compiled, aggregate, fingerprints),
            positive_bytes=positive_bytes,
            negative_bytes=negative_bytes,
            positive_details=(),
            negative_details=(),
        )

    correctly_mapped = 0
    missed = 0
    wrong_canonical = 0
    supported_patterns: set[tuple[str, str, str]] = set()
    positive_details: list[dict[str, Any]] = []
    for case in normalized_positive:
        activity.worked()
        records = _scan_case(compiled, str(case["text"]), options)
        expected = cast(list[dict[str, Any]], case["expected"])
        statuses = _classify_expected(expected, records)
        correctly_mapped += statuses.count("correct")
        missed += statuses.count("missed")
        wrong_canonical += statuses.count("wrong_canonical")
        for item in expected:
            supported_patterns.add((str(item["entity_id"]), str(item["name_id"]), str(item["pattern_id"])))
        if capture_private_audit:
            positive_details.append(
                {
                    "schema_version": CASE_RESULT_SCHEMA_VERSION,
                    "case_id": case["case_id"],
                    "kind": "positive",
                    "expected": len(expected),
                    "correctly_mapped": statuses.count("correct"),
                    "missed": statuses.count("missed"),
                    "wrong_canonical": statuses.count("wrong_canonical"),
                    "outcomes": [
                        {
                            "entity_id": item["entity_id"],
                            "name_id": item["name_id"],
                            "pattern_id": item["pattern_id"],
                            "status": status,
                        }
                        for item, status in zip(expected, statuses, strict=True)
                    ],
                }
            )

    unexpected_negative_matches = 0
    negative_details: list[dict[str, Any]] = []
    for case in normalized_negative:
        activity.worked()
        records = _scan_case(compiled, str(case["text"]), options)
        unexpected = bool(records)
        unexpected_negative_matches += int(unexpected)
        if capture_private_audit:
            negative_details.append(
                {
                    "schema_version": CASE_RESULT_SCHEMA_VERSION,
                    "case_id": case["case_id"],
                    "kind": "negative",
                    "unexpected_match": unexpected,
                    "record_count": len(records),
                }
            )

    approved_positive_cases = correctly_mapped + missed + wrong_canonical
    recall = correctly_mapped / approved_positive_cases if approved_positive_cases else None
    positive_artifact = _artifact(options.positive_artifact_id, positive_size, positive_sha256)
    negative_artifact = _artifact(options.negative_artifact_id, negative_size, negative_sha256)
    active_count = len(active_patterns)
    supported_count = len(supported_patterns)
    passed = (
        approved_positive_cases > 0
        and len(normalized_negative) > 0
        and active_count > 0
        and supported_count == active_count
        and approved_positive_cases >= supported_count
        and missed == 0
        and wrong_canonical == 0
        and unexpected_negative_matches == 0
        and recall == 1.0
    )
    aggregate = {
        "evaluated": True,
        "label_artifact_id": options.label_artifact_id,
        "active_patterns": active_count,
        "patterns_with_positive_cases": supported_count,
        "approved_positive_cases": approved_positive_cases,
        "correctly_mapped": correctly_mapped,
        "missed": missed,
        "wrong_canonical": wrong_canonical,
        "negative_cases": len(normalized_negative),
        "unexpected_negative_matches": unexpected_negative_matches,
        "positive_cases_artifact": positive_artifact,
        "negative_cases_artifact": negative_artifact,
        "policy_sha256": policy_sha256,
        "recall": recall,
        "passed": passed,
    }
    contract_validation = validate_enron_conformance_output(aggregate, active_patterns=active_count)
    diagnostic_codes = {str(item["code"]) for item in contract_validation["diagnostics"]}
    if diagnostic_codes - {"contract.incomplete_pattern_support"}:
        raise EnronConformanceError("Conformance output failed standalone contract validation.")
    activity.boundary()
    return _Evaluation(
        public=_public_result(compiled, aggregate, fingerprints),
        positive_bytes=positive_bytes,
        negative_bytes=negative_bytes,
        positive_details=tuple(positive_details),
        negative_details=tuple(negative_details),
    )


def _validate_options(options: EnronConformanceOptions) -> None:
    for artifact_id in (options.label_artifact_id, options.positive_artifact_id, options.negative_artifact_id):
        if not isinstance(artifact_id, str) or not _ID_RE.fullmatch(artifact_id):
            raise EnronConformanceError("Conformance artifact identities must be bounded opaque identifiers.")
    if options.positive_artifact_id == options.negative_artifact_id:
        raise EnronConformanceError("Positive and negative artifact identities must be distinct.")
    for limit in (
        options.max_cases,
        options.max_line_bytes,
        options.max_artifact_bytes,
        options.max_case_text_bytes,
        options.max_expected_per_case,
        options.max_matches_per_case,
    ):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise EnronConformanceError("Conformance resource limits must be positive integers.")


def _active_pattern_catalog(compiled: CompiledBank) -> dict[tuple[str, str, str], _ActivePattern]:
    catalog: dict[tuple[str, str, str], _ActivePattern] = {}
    bank = compiled.bank
    if bank.get("status") != "active":
        return catalog
    entities = bank.get("entities", {})
    if not isinstance(entities, Mapping):
        return catalog
    for entity_id, entity in sorted(entities.items()):
        if not isinstance(entity_id, str) or not isinstance(entity, Mapping):
            continue
        entity_map = cast(Mapping[str, Any], entity)
        if entity_map.get("status") != "active":
            continue
        names = entity_map.get("names", {})
        if not isinstance(names, Mapping):
            continue
        for name_id, name in sorted(names.items()):
            if not isinstance(name_id, str) or not isinstance(name, Mapping):
                continue
            name_map = cast(Mapping[str, Any], name)
            if name_map.get("status") != "active":
                continue
            canonical_name = name_map.get("canonical")
            patterns = name_map.get("patterns", {})
            if not isinstance(canonical_name, str) or not isinstance(patterns, Mapping):
                continue
            for pattern_id, pattern in sorted(patterns.items()):
                if not isinstance(pattern_id, str) or not isinstance(pattern, Mapping):
                    continue
                pattern_map = cast(Mapping[str, Any], pattern)
                if pattern_map.get("status") != "active":
                    continue
                active = _ActivePattern(
                    entity_id=entity_id,
                    name_id=name_id,
                    pattern_id=pattern_id,
                    pattern_kind=str(pattern_map.get("kind", "")),
                    canonical_name=canonical_name,
                )
                catalog[active.key] = active

    expected_count = bank_stats(bank)["active_totals"]["patterns"]
    if len(catalog) != expected_count:
        raise EnronConformanceError("Active-pattern catalog does not agree with bank statistics.")
    return catalog


def _normalize_positive_cases(
    cases: Sequence[Mapping[str, Any]],
    catalog: Mapping[tuple[str, str, str], _ActivePattern],
    options: EnronConformanceOptions,
    *,
    activity_reporter: _ActivityReporter | None = None,
) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for index, raw in enumerate(cases):
        if activity_reporter is not None:
            activity_reporter.worked()
        case = _require_case_mapping(raw, _POSITIVE_FIELDS, "Positive", index)
        if case["schema_version"] != POSITIVE_CASE_SCHEMA_VERSION:
            raise EnronConformanceError(f"Positive conformance case {index} has an unsupported schema version.")
        case_id = _case_id(case.get("case_id"), "Positive", index)
        text = _case_text(case.get("text"), "Positive", index, options)
        tags = _case_tags(case.get("tags"), "Positive", index, negative=False)
        expected_raw = case.get("expected")
        if not isinstance(expected_raw, list) or not expected_raw:
            raise EnronConformanceError(f"Positive conformance case {index} requires expected occurrences.")
        if len(expected_raw) > options.max_expected_per_case:
            raise EnronConformanceError(f"Positive conformance case {index} exceeds the expected-occurrence limit.")
        text_bytes = text.encode("utf-8")
        expected = [
            _normalize_expected(item, catalog, text_bytes, case_index=index, expected_index=expected_index)
            for expected_index, item in enumerate(expected_raw)
        ]
        expected.sort(key=_expected_sort_key)
        if len({_expected_sort_key(item) for item in expected}) != len(expected):
            raise EnronConformanceError(f"Positive conformance case {index} contains duplicate expected occurrences.")
        normalized_case = {
            "schema_version": POSITIVE_CASE_SCHEMA_VERSION,
            "case_id": case_id,
            "text": text,
            "tags": tags,
            "expected": expected,
        }
        _ensure_canonical_line_limit(normalized_case, "Positive", index, options)
        normalized.append(normalized_case)
    normalized.sort(key=lambda item: str(item["case_id"]))
    return normalized


def _normalize_negative_cases(
    cases: Sequence[Mapping[str, Any]],
    options: EnronConformanceOptions,
    *,
    activity_reporter: _ActivityReporter | None = None,
) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for index, raw in enumerate(cases):
        if activity_reporter is not None:
            activity_reporter.worked()
        case = _require_case_mapping(raw, _NEGATIVE_FIELDS, "Negative", index)
        if case["schema_version"] != NEGATIVE_CASE_SCHEMA_VERSION:
            raise EnronConformanceError(f"Negative conformance case {index} has an unsupported schema version.")
        reason_code = case.get("reason_code")
        if not isinstance(reason_code, str) or not _ID_RE.fullmatch(reason_code):
            raise EnronConformanceError(f"Negative conformance case {index} has an invalid reason code.")
        normalized_case = {
            "schema_version": NEGATIVE_CASE_SCHEMA_VERSION,
            "case_id": _case_id(case.get("case_id"), "Negative", index),
            "text": _case_text(case.get("text"), "Negative", index, options),
            "tags": _case_tags(case.get("tags"), "Negative", index, negative=True),
            "reason_code": reason_code,
        }
        _ensure_canonical_line_limit(normalized_case, "Negative", index, options)
        normalized.append(normalized_case)
    normalized.sort(key=lambda item: str(item["case_id"]))
    return normalized


def _require_case_mapping(raw: Any, fields: frozenset[str], label: str, index: int) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise EnronConformanceError(f"{label} conformance case {index} must be an object.")
    if set(raw) != fields:
        raise EnronConformanceError(f"{label} conformance case {index} must use the exact closed schema.")
    return dict(raw)


def _case_id(value: Any, label: str, index: int) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise EnronConformanceError(f"{label} conformance case {index} has an invalid opaque identifier.")
    return value


def _case_text(value: Any, label: str, index: int, options: EnronConformanceOptions) -> str:
    if not isinstance(value, str) or not value:
        raise EnronConformanceError(f"{label} conformance case {index} text must be a non-empty string.")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError:
        raise EnronConformanceError(f"{label} conformance case {index} text must be valid UTF-8.") from None
    if size > options.max_case_text_bytes:
        raise EnronConformanceError(f"{label} conformance case {index} text exceeds the byte limit.")
    return value


def _ensure_canonical_line_limit(
    value: Mapping[str, Any], label: str, index: int, options: EnronConformanceOptions
) -> None:
    if len(_canonical_json_bytes(value)) + 1 > options.max_line_bytes:
        raise EnronConformanceError(f"{label} conformance case {index} exceeds the canonical line byte limit.")


def _case_tags(value: Any, label: str, index: int, *, negative: bool) -> list[str]:
    if not isinstance(value, list) or not value or any(not isinstance(tag, str) for tag in value):
        raise EnronConformanceError(f"{label} conformance case {index} tags must be a non-empty string array.")
    tags = cast(list[str], value)
    if len(set(tags)) != len(tags) or not set(tags) <= ADVERSARIAL_TAGS:
        raise EnronConformanceError(f"{label} conformance case {index} has duplicate or unsupported tags.")
    if negative != ("negative" in tags):
        raise EnronConformanceError(f"{label} conformance case {index} has an invalid negative tag declaration.")
    return sorted(tags)


def _normalize_expected(
    raw: Any,
    catalog: Mapping[tuple[str, str, str], _ActivePattern],
    text_bytes: bytes,
    *,
    case_index: int,
    expected_index: int,
) -> dict[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != _EXPECTED_FIELDS:
        raise EnronConformanceError(
            f"Positive conformance case {case_index} expected occurrence {expected_index} must use the closed schema."
        )
    item = dict(raw)
    string_fields = ("entity_id", "name_id", "pattern_id", "pattern_kind", "canonical_name", "string")
    if any(not isinstance(item.get(field), str) for field in string_fields):
        raise EnronConformanceError(
            f"Positive conformance case {case_index} expected occurrence {expected_index} has invalid identity fields."
        )
    key = (str(item["entity_id"]), str(item["name_id"]), str(item["pattern_id"]))
    active = catalog.get(key)
    if active is None:
        raise EnronConformanceError(
            f"Positive conformance case {case_index} expected occurrence {expected_index} is not an active pattern."
        )
    if item["pattern_kind"] != active.pattern_kind or item["canonical_name"] != active.canonical_name:
        raise EnronConformanceError(
            f"Positive conformance case {case_index} expected occurrence {expected_index} disagrees with the bank."
        )
    start = item.get("start")
    end = item.get("end")
    if (
        isinstance(start, bool)
        or not isinstance(start, int)
        or isinstance(end, bool)
        or not isinstance(end, int)
        or start < 0
        or end <= start
        or end > len(text_bytes)
    ):
        raise EnronConformanceError(
            f"Positive conformance case {case_index} expected occurrence {expected_index} has an invalid byte span."
        )
    try:
        actual = text_bytes[start:end].decode("utf-8")
    except UnicodeDecodeError:
        raise EnronConformanceError(
            f"Positive conformance case {case_index} expected occurrence {expected_index} splits a UTF-8 scalar."
        ) from None
    if actual != item["string"]:
        raise EnronConformanceError(
            f"Positive conformance case {case_index} expected occurrence {expected_index} "
            "string disagrees with its span."
        )
    return {field: item[field] for field in sorted(_EXPECTED_FIELDS)}


def _validate_case_set(positive: Sequence[Mapping[str, Any]], negative: Sequence[Mapping[str, Any]]) -> None:
    ids = [str(item["case_id"]) for item in (*positive, *negative)]
    if len(ids) != len(set(ids)):
        raise EnronConformanceError("Positive and negative conformance case identifiers must be globally unique.")
    if not positive or not negative:
        return
    covered_tags = {str(tag) for item in (*positive, *negative) for tag in cast(Sequence[str], item["tags"])}
    if covered_tags != ADVERSARIAL_TAGS:
        raise EnronConformanceError("Conformance cases do not cover every required adversarial category.")
    if not any({"boundary", "negative"} <= set(cast(Sequence[str], item["tags"])) for item in negative):
        raise EnronConformanceError("Conformance cases require a boundary-negative adversarial case.")


def _scan_case(compiled: CompiledBank, text: str, options: EnronConformanceOptions) -> list[dict[str, Any]]:
    try:
        records = compiled.finditer(text, max_matches=options.max_matches_per_case)
    except MemoryError:
        raise EnronConformanceError("Conformance scan exceeded the per-case match limit.") from None
    except Exception:
        raise EnronConformanceError("Conformance case could not be scanned safely.") from None
    if len(records) > options.max_matches_per_case:
        raise EnronConformanceError("Conformance scan exceeded the per-case match limit.")
    if any(record.get("offset_unit") != "byte" for record in records):
        raise EnronConformanceError("Conformance scan did not return UTF-8 byte offsets.")
    return records


def _classify_expected(
    expected: Sequence[Mapping[str, Any]], actual: Sequence[Mapping[str, Any]]
) -> list[Literal["correct", "missed", "wrong_canonical"]]:
    statuses: list[Literal["correct", "missed", "wrong_canonical"] | None] = [None] * len(expected)
    unused = set(range(len(actual)))
    exact_index: dict[tuple[Any, ...], deque[int]] = {}
    for actual_index, record in enumerate(actual):
        exact_index.setdefault(_exact_record_key(record), deque()).append(actual_index)

    # Reserve all exact matches first so a wrong-canonical candidate cannot
    # consume a prediction that exactly satisfies another overlapping target.
    for expected_index, item in enumerate(expected):
        candidates = exact_index.get(_exact_record_key(item))
        while candidates and candidates[0] not in unused:
            candidates.popleft()
        if candidates:
            exact_match_index = candidates.popleft()
            unused.remove(exact_match_index)
            statuses[expected_index] = "correct"

    wrong_indices: dict[tuple[Any, ...], dict[tuple[Any, Any], deque[int]]] = {}
    for actual_index in sorted(unused):
        record = actual[actual_index]
        occurrence_key = _occurrence_record_key(record)
        identity = (record.get("name_id"), record.get("canonical_name"))
        wrong_indices.setdefault(occurrence_key, {}).setdefault(identity, deque()).append(actual_index)
    wrong_heaps: dict[tuple[Any, ...], list[tuple[int, tuple[Any, Any]]]] = {
        occurrence_key: [(indices[0], identity) for identity, indices in by_identity.items()]
        for occurrence_key, by_identity in wrong_indices.items()
    }
    for heap in wrong_heaps.values():
        heapq.heapify(heap)

    for expected_index, item in enumerate(expected):
        if statuses[expected_index] is not None:
            continue
        occurrence_key = _occurrence_record_key(item)
        by_identity = wrong_indices.get(occurrence_key, {})
        heap = wrong_heaps.get(occurrence_key, [])
        expected_identity = (item.get("name_id"), item.get("canonical_name"))
        held_expected: tuple[int, tuple[Any, Any]] | None = None
        wrong_match_index: int | None = None
        while heap:
            candidate_index, identity = heapq.heappop(heap)
            identity_indices = by_identity[identity]
            if not identity_indices or identity_indices[0] != candidate_index:
                continue
            if identity == expected_identity:
                held_expected = (candidate_index, identity)
                continue
            wrong_match_index = identity_indices.popleft()
            if identity_indices:
                heapq.heappush(heap, (identity_indices[0], identity))
            break
        if held_expected is not None:
            heapq.heappush(heap, held_expected)
        if wrong_match_index is not None:
            unused.remove(wrong_match_index)
            statuses[expected_index] = "wrong_canonical"
        else:
            statuses[expected_index] = "missed"
    return cast(list[Literal["correct", "missed", "wrong_canonical"]], statuses)


def _exact_record_key(value: Mapping[str, Any]) -> tuple[Any, ...]:
    return tuple(
        value.get(field)
        for field in (
            "entity_id",
            "name_id",
            "pattern_id",
            "pattern_kind",
            "canonical_name",
            "string",
            "start",
            "end",
        )
    )


def _occurrence_record_key(value: Mapping[str, Any]) -> tuple[Any, ...]:
    return tuple(value.get(field) for field in ("entity_id", "string", "start", "end"))


def _expected_sort_key(item: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        int(item["start"]),
        int(item["end"]),
        str(item["entity_id"]),
        str(item["name_id"]),
        str(item["pattern_id"]),
        str(item["pattern_kind"]),
        str(item["canonical_name"]),
        str(item["string"]),
    )


def _unevaluated_aggregate() -> dict[str, Any]:
    return {
        "evaluated": False,
        "label_artifact_id": None,
        "active_patterns": 0,
        "patterns_with_positive_cases": 0,
        "approved_positive_cases": 0,
        "correctly_mapped": 0,
        "missed": 0,
        "wrong_canonical": 0,
        "negative_cases": 0,
        "unexpected_negative_matches": 0,
        "positive_cases_artifact": None,
        "negative_cases_artifact": None,
        "policy_sha256": None,
        "recall": None,
        "passed": False,
    }


def _public_result(
    compiled: CompiledBank, aggregate: Mapping[str, Any], fingerprints: Mapping[str, str]
) -> dict[str, Any]:
    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "evaluator": {
            "id": EVALUATOR_ID,
            "version": EVALUATOR_VERSION,
            "source_sha256": fingerprints["evaluator_source_sha256"],
        },
        "engine": {"name": compiled.engine_name, "version": compiled.engine_version},
        "fingerprints": dict(fingerprints),
        "catalog_conformance": dict(aggregate),
    }


def _artifact(artifact_id: str, size: int, digest: str) -> dict[str, Any]:
    if size <= 0:
        raise EnronConformanceError("Evaluated conformance artifacts must be non-empty.")
    return {"id": artifact_id, "sha256": digest, "bytes": size}


def _load_jsonl_cases(path: Path, options: EnronConformanceOptions) -> list[Mapping[str, Any]]:
    cases: list[Mapping[str, Any]] = []
    total_bytes = 0
    for _line_number, raw, case in iter_strict_jsonl(path, options.max_line_bytes):
        total_bytes += len(raw)
        if total_bytes > options.max_artifact_bytes:
            raise EnronConformanceError("Conformance case artifact exceeds the configured byte limit.")
        cases.append(case)
        if len(cases) > options.max_cases:
            raise EnronConformanceError("Conformance case count exceeds the configured limit.")
    return cases


def _write_detail_jsonl(file: TextIO, records: Sequence[Mapping[str, Any]]) -> None:
    for record in records:
        file.write(_canonical_json_bytes(record).decode("utf-8"))
        file.write("\n")


def _canonical_jsonl_artifact(
    records: Sequence[Mapping[str, Any]],
    *,
    max_bytes: int,
    capture_payload: bool,
    activity_reporter: _ActivityReporter | None = None,
) -> tuple[bytes | None, int, str]:
    digest = hashlib.sha256()
    payload = bytearray() if capture_payload else None
    size = 0
    for record in records:
        if activity_reporter is not None:
            activity_reporter.worked()
        line = _canonical_json_bytes(record) + b"\n"
        size += len(line)
        if size > max_bytes:
            raise EnronConformanceError("Conformance case artifact exceeds the configured byte limit.")
        digest.update(line)
        if payload is not None:
            payload.extend(line)
    return (None if payload is None else bytes(payload), size, _SHA256_PREFIX + digest.hexdigest())


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise EnronConformanceError("Conformance value is not canonical finite UTF-8 JSON.") from None


def _hash_bytes(value: bytes) -> str:
    return _SHA256_PREFIX + hashlib.sha256(value).hexdigest()


__all__ = [
    "ADVERSARIAL_TAGS",
    "DEFAULT_LABEL_ARTIFACT_ID",
    "DEFAULT_NEGATIVE_ARTIFACT_ID",
    "DEFAULT_POSITIVE_ARTIFACT_ID",
    "EVALUATOR_ID",
    "EVALUATOR_VERSION",
    "EnronConformanceError",
    "EnronConformanceOptions",
    "NEGATIVE_CASE_SCHEMA_VERSION",
    "POSITIVE_CASE_SCHEMA_VERSION",
    "RESULT_SCHEMA_VERSION",
    "enron_conformance_evaluator_source_sha256",
    "enron_conformance_policy_sha256",
    "evaluate_enron_conformance",
    "evaluate_enron_conformance_files",
]

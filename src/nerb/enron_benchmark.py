from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import math
import os
import platform
import re
import sys
import time
from collections import Counter
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from stat import S_ISREG
from typing import Any, TextIO, cast

from .bank import bank_stats, hash_bank
from .benchmarks import benchmark_bank
from .enron_bank_builder import build_enron_entity_bank
from .extraction import extract_batch
from .schema import validate_bank_schema

ARTIFACT_SCHEMA_VERSION = "nerb.enron_benchmark.v1"
GATE_SCHEMA_VERSION = "nerb.enron_benchmark_gate.v1"
DEFAULT_DATASET_ID = "corbt/enron-emails"
DEFAULT_SPLIT = "train"
DEFAULT_OUTPUT_DIR = ".nerb/enron-benchmark/baseline"
DEFAULT_SAMPLE_FRACTION = 0.5
DEFAULT_TEST_FRACTION = 0.2
DEFAULT_SEED = "nerb-enron-v1"
DEFAULT_MAX_BODY_CHARS = 20_000
DEFAULT_MAX_ADDRESSES = 5_000
DEFAULT_MAX_DOMAINS = 500
DEFAULT_BENCHMARK_DOCUMENTS = 50
DEFAULT_QUALITY_DOCUMENTS = 1_000
DEFAULT_BENCHMARK_ITERATIONS = 3
DEFAULT_MAX_BASELINE_BENCHMARK_BYTES = 64 * 1024 * 1024
BANK_TIMESTAMP = "2026-06-09T00:00:00Z"

EMAIL_RE = re.compile(r"(?i)^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+\.[a-z]{2,}$")
EMAIL_SPAN_RE = re.compile(r"(?i)[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+\.[a-z]{2,}")
DOMAIN_SPAN_RE = re.compile(
    r"(?i)(?:(?<=@)|(?<![a-z0-9.-]))"
    r"([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*"
    r"\.[a-z]{2,63})"
    r"(?![a-z0-9-])"
)
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
HEADER_LINE_RE = re.compile(r"(?i)^(message-id|date|from|to|cc|bcc|subject|x-[a-z0-9-]+):\s+")
ORIGINAL_MESSAGE_RE = re.compile(r"(?i)^[-_\s]*(original message|forwarded by|forwarded message)[-_\s]*$")
ON_WROTE_RE = re.compile(r"(?i)^on .{0,160}\bwrote:\s*$")
WHITESPACE_RE = re.compile(r"[ \t]+")


@dataclass(frozen=True)
class PreparedRecord:
    document_id: str
    message_id: str | None
    source_index: int
    text: str
    body_hash: str
    addresses: tuple[str, ...]
    domains: tuple[str, ...]


@dataclass(frozen=True)
class PrepOptions:
    output_dir: Path
    dataset_id: str
    dataset_split: str
    dataset_revision: str | None
    input_jsonl: Path | None
    row_limit: int | None
    sample_fraction: float
    test_fraction: float
    seed: str
    max_body_chars: int
    max_addresses: int
    max_domains: int
    min_address_count: int
    min_domain_count: int
    benchmark_documents: int
    quality_documents: int
    benchmark_iterations: int
    created_at: str
    baseline_benchmark_json: Path | None
    max_cold_compile_seconds_ratio: float | None
    max_warm_cached_compile_seconds_ratio: float | None
    min_target_bytes_per_second_ratio: float | None


def main(argv: Sequence[str] | None = None) -> None:
    options = _parse_args(argv)
    result = prepare_enron_benchmark(options)
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False))
    gate = result.get("gate")
    if isinstance(gate, Mapping) and gate.get("configured") is True and gate.get("passed") is not True:
        raise SystemExit(1)


def prepare_enron_benchmark(options: PrepOptions) -> dict[str, Any]:
    start = time.perf_counter()
    run_started_at = _timestamp()
    _validate_source_options(options)
    output_dir = _prepare_output_dir(options.output_dir)

    paths = {
        "train": output_dir / "train.jsonl",
        "test": output_dir / "test.jsonl",
        "bank": output_dir / "bank.json",
        "manifest": output_dir / "manifest.json",
        "benchmark": output_dir / "benchmark.json",
    }

    address_counts: Counter[str] = Counter()
    domain_counts: Counter[str] = Counter()
    prep_summary = _write_split_artifacts(options, paths["train"], paths["test"], address_counts, domain_counts)

    bank = build_enron_entity_bank(
        address_counts,
        domain_counts,
        max_addresses=options.max_addresses,
        max_domains=options.max_domains,
        min_address_count=options.min_address_count,
        min_domain_count=options.min_domain_count,
        created_at=options.created_at,
    )
    _write_json(paths["bank"], bank)

    train_documents = _load_benchmark_documents(paths["train"], options.benchmark_documents)
    test_documents = _load_benchmark_documents(paths["test"], options.benchmark_documents)
    train_quality_documents = _load_benchmark_documents(paths["train"], options.quality_documents)
    test_quality_documents = _load_benchmark_documents(paths["test"], options.quality_documents)
    if not train_documents:
        raise ValueError("Enron benchmark prep produced no training documents.")
    if not test_documents:
        raise ValueError(
            "Enron benchmark prep produced no held-out test documents; increase --row-limit, --sample-fraction, "
            "or --test-fraction."
        )

    extraction_options = {
        "max_batch_documents": max(100, len(train_documents), len(test_documents), options.quality_documents),
        "max_batch_text_bytes": 64 * 1024 * 1024,
    }
    benchmark_options = {
        **extraction_options,
        "benchmark_iterations": options.benchmark_iterations,
        "stress_multiplier": 2,
    }
    documents = {
        "baseline": train_documents[: min(10, len(train_documents))],
        "target": test_documents,
        "stress": test_documents,
    }
    benchmark = benchmark_bank(bank, documents=documents, options=benchmark_options)
    quality = {
        "train": _quality_summary(bank, train_quality_documents, extraction_options),
        "test": _quality_summary(bank, test_quality_documents, extraction_options),
    }

    manifest = _manifest(options, paths, prep_summary, bank, run_started_at=run_started_at)
    _write_json(paths["manifest"], manifest)

    result = {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "created_at": options.created_at,
        "run_started_at": run_started_at,
        "elapsed_seconds": _seconds(time.perf_counter() - start),
        "paths": {key: str(path) for key, path in paths.items()},
        "manifest": manifest,
        "bank": {
            "hash": hash_bank(bank),
            "stats": bank_stats(bank),
            "schema_valid": validate_bank_schema(bank)["valid"],
        },
        "quality": quality,
        "benchmark": benchmark,
        "gate": _unconfigured_gate(),
        "summary": {
            "selected_records": prep_summary["selected_records"],
            "train_records": prep_summary["train_records"],
            "test_records": prep_summary["test_records"],
            "bank_entities": bank_stats(bank)["active_totals"]["entities"],
            "bank_names": bank_stats(bank)["active_totals"]["names"],
            "bank_patterns": bank_stats(bank)["active_totals"]["patterns"],
            "cold_compile_seconds": benchmark["summary"]["cold_compile_seconds"],
            "target_bytes_per_second": benchmark["summary"]["target_bytes_per_second"],
            "warm_cached_compile_seconds": benchmark["summary"]["warm_cached_compile_seconds"],
            "test_record_count": quality["test"]["record_count"],
            "test_documents_with_records": quality["test"]["documents_with_records"],
            "test_precision": quality["test"]["precision"],
            "test_recall": quality["test"]["recall"],
            "test_f1": quality["test"]["f1"],
        },
    }
    result["gate"] = _benchmark_gate(result, options)
    _write_json(paths["benchmark"], result)
    return result


def clean_email_text(value: Any, *, max_chars: int = DEFAULT_MAX_BODY_CHARS) -> str:
    text = "" if value is None else str(value)
    text = CONTROL_RE.sub(" ", text.replace("\r\n", "\n").replace("\r", "\n"))
    kept_lines: list[str] = []
    for raw_line in text.split("\n"):
        line = WHITESPACE_RE.sub(" ", raw_line).strip()
        if not line:
            if kept_lines and kept_lines[-1] != "":
                kept_lines.append("")
            continue
        if ORIGINAL_MESSAGE_RE.match(line) or ON_WROTE_RE.match(line):
            break
        if line.startswith(">"):
            continue
        if HEADER_LINE_RE.match(line):
            continue
        kept_lines.append(line)

    cleaned = "\n".join(kept_lines).strip()
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    if len(cleaned) > max_chars:
        return cleaned[:max_chars].rstrip()
    return cleaned


def iter_jsonl_rows(path: Path) -> Iterator[Mapping[str, Any]]:
    with path.expanduser().open(encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            value = json.loads(stripped)
            if not isinstance(value, Mapping):
                raise ValueError(f"JSONL row {line_number} must be an object.")
            yield value


def iter_huggingface_rows(dataset_id: str, split: str, revision: str | None) -> Iterator[Mapping[str, Any]]:
    try:
        datasets_module = importlib.import_module("datasets")
    except ImportError as exc:  # pragma: no cover - exercised by command usage, not unit tests.
        raise RuntimeError(
            "Hugging Face dataset loading requires the optional 'datasets' package. "
            "Use the pinned command in docs/enron-benchmark.md, including "
            "`uv run --with datasets==5.0.0` and a concrete `--dataset-revision`."
        ) from exc

    load_dataset = datasets_module.load_dataset
    kwargs: dict[str, Any] = {"split": split, "streaming": True}
    if revision is not None:
        kwargs["revision"] = revision
    dataset = load_dataset(dataset_id, **kwargs)
    for row in dataset:
        if not isinstance(row, Mapping):
            raise ValueError("Hugging Face dataset rows must be objects.")
        yield row


def _write_split_artifacts(
    options: PrepOptions,
    train_path: Path,
    test_path: Path,
    address_counts: Counter[str],
    domain_counts: Counter[str],
) -> dict[str, Any]:
    seen_message_ids: set[str] = set()
    seen_body_hashes: set[str] = set()
    summary: dict[str, Any] = {
        "input_records": 0,
        "selected_records": 0,
        "train_records": 0,
        "test_records": 0,
        "dropped_empty_text": 0,
        "dropped_duplicate_message_id": 0,
        "dropped_duplicate_body": 0,
        "dropped_sample_fraction": 0,
    }
    rows = (
        iter_jsonl_rows(options.input_jsonl)
        if options.input_jsonl
        else iter_huggingface_rows(
            options.dataset_id,
            options.dataset_split,
            options.dataset_revision,
        )
    )
    with _open_private_text(train_path) as train_file, _open_private_text(test_path) as test_file:
        for index, row in enumerate(rows):
            if options.row_limit is not None and index >= options.row_limit:
                break
            summary["input_records"] += 1
            prepared = _prepare_row(row, index, options.max_body_chars)
            if prepared is None:
                summary["dropped_empty_text"] += 1
                continue
            if prepared.message_id and prepared.message_id in seen_message_ids:
                summary["dropped_duplicate_message_id"] += 1
                continue
            if prepared.body_hash in seen_body_hashes:
                summary["dropped_duplicate_body"] += 1
                continue
            if not _include_sample(prepared.document_id, options.seed, options.sample_fraction):
                summary["dropped_sample_fraction"] += 1
                continue

            if prepared.message_id:
                seen_message_ids.add(prepared.message_id)
            seen_body_hashes.add(prepared.body_hash)
            split = _split_name(prepared.document_id, options.seed, options.test_fraction)
            _write_jsonl_record(train_file if split == "train" else test_file, _prepared_record_payload(prepared))
            summary["selected_records"] += 1
            summary[f"{split}_records"] += 1
            if split == "train":
                address_counts.update(prepared.addresses)
                domain_counts.update(prepared.domains)
    return summary


def _prepare_row(row: Mapping[str, Any], index: int, max_body_chars: int) -> PreparedRecord | None:
    message_id = _optional_string(row.get("message_id"))
    subject = clean_email_text(row.get("subject"), max_chars=512)
    body = clean_email_text(row.get("body", row.get("text")), max_chars=max_body_chars)
    addresses = tuple(sorted(_row_addresses(row) | _text_addresses(subject) | _text_addresses(body)))
    domains = tuple(sorted({address.rsplit("@", 1)[1] for address in addresses}))
    text_parts = _document_text_parts(row, subject, body, addresses)
    text = "\n".join(part for part in text_parts if part).strip()
    if not text:
        return None
    body_hash = _hash_text(body or text)
    document_id = "doc_" + _hash_text(f"{message_id or ''}\n{index}\n{text}")[:16]
    return PreparedRecord(
        document_id=document_id,
        message_id=message_id,
        source_index=index,
        text=text,
        body_hash=body_hash,
        addresses=addresses,
        domains=domains,
    )


def _document_text_parts(row: Mapping[str, Any], subject: str, body: str, addresses: tuple[str, ...]) -> list[str]:
    parts: list[str] = []
    sender = _normalize_address(row.get("from"))
    if sender:
        parts.append(f"From: {sender}")
    recipients = [address for field in ("to", "cc", "bcc") for address in _normalize_address_list(row.get(field))]
    if recipients:
        parts.append("To: " + ", ".join(sorted(set(recipients))))
    if addresses:
        parts.append("Addresses: " + ", ".join(addresses))
    if subject:
        parts.append(f"Subject: {subject}")
    if body:
        parts.append(body)
    return parts


def _row_addresses(row: Mapping[str, Any]) -> set[str]:
    addresses: set[str] = set()
    for field in ("from", "to", "cc", "bcc"):
        addresses.update(_normalize_address_list(row.get(field)))
    return addresses


def _text_addresses(text: str) -> set[str]:
    values = set()
    for raw in re.findall(r"(?i)[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+\.[a-z]{2,}", text):
        normalized = _normalize_address(raw)
        if normalized:
            values.add(normalized)
    return values


def _normalize_address_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        candidates = re.split(r"[,;\s]+", value)
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        candidates = [str(item) for item in value]
    else:
        candidates = [str(value)]
    addresses = []
    for candidate in candidates:
        normalized = _normalize_address(candidate)
        if normalized is not None:
            addresses.append(normalized)
    return addresses


def _normalize_address(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip().strip("<>()[]{}'\".,;:")
    text = text.replace("mailto:", "").lower()
    if not text or text in {"none", "null"}:
        return None
    if EMAIL_RE.fullmatch(text):
        return text
    return None


def _prepared_record_payload(record: PreparedRecord) -> dict[str, Any]:
    return {
        "document_id": record.document_id,
        "message_id": record.message_id,
        "source_index": record.source_index,
        "body_hash": "sha256:" + record.body_hash,
        "addresses": list(record.addresses),
        "domains": list(record.domains),
        "text": record.text,
    }


def _load_benchmark_documents(path: Path, limit: int) -> list[dict[str, str]]:
    documents: list[dict[str, str]] = []
    for row in iter_jsonl_rows(path):
        document_id = row.get("document_id")
        text = row.get("text")
        if isinstance(document_id, str) and isinstance(text, str):
            documents.append({"document_id": document_id, "text": text})
        if len(documents) >= limit:
            break
    return documents


def _quality_summary(
    bank: Mapping[str, Any],
    documents: Sequence[Mapping[str, str]],
    options: Mapping[str, Any],
) -> dict[str, Any]:
    if not documents:
        return {
            "document_count": 0,
            "record_count": 0,
            "documents_with_records": 0,
            "entity_counts": {},
            **_span_metric_summary(set(), set()),
        }
    response = extract_batch(bank, cast(Sequence[Mapping[str, Any]], documents), options=options)
    entity_counts: Counter[str] = Counter(str(record["entity_id"]) for record in response["records"])
    gold_spans = set().union(*(_gold_span_keys(document) for document in documents))
    predicted_spans = _predicted_span_keys(response["records"])
    return {
        "document_count": response["summary"]["document_count"],
        "record_count": response["summary"]["record_count"],
        "documents_with_records": response["summary"]["documents_with_records"],
        "entity_counts": dict(sorted(entity_counts.items())),
        **_span_metric_summary(gold_spans, predicted_spans),
    }


SpanKey = tuple[str, str, int, int, str]


def _gold_span_keys(document: Mapping[str, str]) -> set[SpanKey]:
    document_id = document.get("document_id")
    text = document.get("text")
    if not isinstance(document_id, str) or not isinstance(text, str):
        return set()
    offsets = _byte_offsets(text)
    spans: set[SpanKey] = set()
    for match in EMAIL_SPAN_RE.finditer(text):
        normalized = _normalize_address(match.group(0))
        if normalized is None:
            continue
        spans.add(
            (
                document_id,
                "email_address",
                offsets[match.start()],
                offsets[match.end()],
                normalized,
            )
        )
    for match in DOMAIN_SPAN_RE.finditer(text):
        raw_domain = match.group(1)
        spans.add(
            (
                document_id,
                "email_domain",
                offsets[match.start(1)],
                offsets[match.end(1)],
                raw_domain.lower(),
            )
        )
    return spans


def _predicted_span_keys(records: Sequence[Mapping[str, Any]]) -> set[SpanKey]:
    spans: set[SpanKey] = set()
    for record in records:
        document_id = record.get("document_id")
        entity_id = record.get("entity_id")
        start = record.get("start")
        end = record.get("end")
        string = record.get("string")
        if (
            isinstance(document_id, str)
            and isinstance(entity_id, str)
            and isinstance(start, int)
            and isinstance(end, int)
            and isinstance(string, str)
        ):
            spans.add((document_id, entity_id, start, end, string.lower()))
    return spans


def _span_metric_summary(gold_spans: set[SpanKey], predicted_spans: set[SpanKey]) -> dict[str, Any]:
    true_positive_spans = gold_spans & predicted_spans
    false_positive_spans = predicted_spans - gold_spans
    false_negative_spans = gold_spans - predicted_spans
    summary = _classification_metrics(
        true_positive=len(true_positive_spans),
        false_positive=len(false_positive_spans),
        false_negative=len(false_negative_spans),
    )
    entity_ids = sorted({span[1] for span in gold_spans | predicted_spans})
    by_entity = {
        entity_id: {
            **_classification_metrics(
                true_positive=sum(1 for span in true_positive_spans if span[1] == entity_id),
                false_positive=sum(1 for span in false_positive_spans if span[1] == entity_id),
                false_negative=sum(1 for span in false_negative_spans if span[1] == entity_id),
            ),
            "gold_count": sum(1 for span in gold_spans if span[1] == entity_id),
            "predicted_count": sum(1 for span in predicted_spans if span[1] == entity_id),
        }
        for entity_id in entity_ids
    }
    return {
        **summary,
        "gold_count": len(gold_spans),
        "predicted_count": len(predicted_spans),
        "by_entity": by_entity,
        "metric_scope": "exact span/entity/surface micro-average over prepared documents",
    }


def _classification_metrics(*, true_positive: int, false_positive: int, false_negative: int) -> dict[str, Any]:
    precision_denominator = true_positive + false_positive
    recall_denominator = true_positive + false_negative
    precision = true_positive / precision_denominator if precision_denominator else 0.0
    recall = true_positive / recall_denominator if recall_denominator else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "precision": _metric(precision),
        "recall": _metric(recall),
        "f1": _metric(f1),
    }


def _byte_offsets(text: str) -> list[int]:
    offsets = [0]
    total = 0
    for character in text:
        total += len(character.encode("utf-8"))
        offsets.append(total)
    return offsets


def _manifest(
    options: PrepOptions,
    paths: Mapping[str, Path],
    prep_summary: Mapping[str, Any],
    bank: Mapping[str, Any],
    *,
    run_started_at: str,
) -> dict[str, Any]:
    artifact_hashes = {
        key: "sha256:" + _file_sha256(path)
        for key, path in paths.items()
        if key in {"train", "test", "bank"} and path.exists()
    }
    return {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "created_at": options.created_at,
        "run_started_at": run_started_at,
        "dataset": {
            "id": options.dataset_id,
            "split": options.dataset_split,
            "revision": options.dataset_revision,
            "input_jsonl": str(options.input_jsonl) if options.input_jsonl is not None else None,
            "row_limit": options.row_limit,
        },
        "sampling": {
            "seed": options.seed,
            "sample_fraction": options.sample_fraction,
            "test_fraction": options.test_fraction,
            "max_body_chars": options.max_body_chars,
            "benchmark_documents": options.benchmark_documents,
            "quality_documents": options.quality_documents,
        },
        "candidate_limits": {
            "max_addresses": options.max_addresses,
            "max_domains": options.max_domains,
            "min_address_count": options.min_address_count,
            "min_domain_count": options.min_domain_count,
        },
        "prep_summary": dict(prep_summary),
        "artifact_hashes": artifact_hashes,
        "artifact_sizes": {
            key: path.stat().st_size
            for key, path in paths.items()
            if key in {"train", "test", "bank"} and path.exists()
        },
        "bank_hash": hash_bank(bank),
        "bank_stats": bank_stats(bank),
        "environment": {
            "python": platform.python_version(),
            "python_implementation": platform.python_implementation(),
            "platform": platform.platform(),
            "executable_name": Path(sys.executable).name,
        },
    }


def _benchmark_gate(result: Mapping[str, Any], options: PrepOptions) -> dict[str, Any]:
    if options.baseline_benchmark_json is None:
        return _unconfigured_gate()
    baseline = _load_json_mapping(options.baseline_benchmark_json)
    _validate_baseline_benchmark_payload(baseline, options.baseline_benchmark_json)
    return _compare_enron_benchmark_gate(baseline, result, options)


def _unconfigured_gate() -> dict[str, Any]:
    return {
        "schema_version": GATE_SCHEMA_VERSION,
        "configured": False,
        "passed": None,
        "baseline_path": None,
        "evaluator": {"passed": None, "checks": []},
        "quality": {"passed": None, "checks": []},
        "performance": {"configured": False, "passed": None, "checks": []},
    }


def _compare_enron_benchmark_gate(
    baseline: Mapping[str, Any],
    candidate: Mapping[str, Any],
    options: PrepOptions,
) -> dict[str, Any]:
    baseline_fingerprint = _evaluator_fingerprint(baseline)
    candidate_fingerprint = _evaluator_fingerprint(candidate)
    evaluator_checks = [
        _boolean_gate_check(
            "evaluator_fingerprint",
            candidate_fingerprint == baseline_fingerprint,
            "candidate run must use the same dataset split, sampling artifacts, and benchmark options as baseline",
        )
    ]
    evaluator_passed = all(check["passed"] for check in evaluator_checks)
    if not evaluator_passed:
        return {
            "schema_version": GATE_SCHEMA_VERSION,
            "configured": True,
            "passed": False,
            "baseline_path": str(options.baseline_benchmark_json),
            "evaluator": {
                "passed": False,
                "baseline": baseline_fingerprint,
                "candidate": candidate_fingerprint,
                "checks": evaluator_checks,
            },
            "quality": {
                "passed": None,
                "skipped": True,
                "reason": "evaluator fingerprint mismatch",
                "checks": [],
            },
            "performance": {
                "configured": _performance_gate_configured(options),
                "passed": None,
                "skipped": True,
                "reason": "evaluator fingerprint mismatch",
                "checks": [],
            },
        }

    quality_checks = [
        _quality_metric_delta_check(
            "test_f1_delta",
            baseline["quality"]["test"]["f1"],
            candidate["quality"]["test"]["f1"],
        ),
        _quality_metric_delta_check(
            "test_precision_delta",
            baseline["quality"]["test"]["precision"],
            candidate["quality"]["test"]["precision"],
        ),
        _quality_metric_delta_check(
            "test_recall_delta",
            baseline["quality"]["test"]["recall"],
            candidate["quality"]["test"]["recall"],
        ),
    ]
    quality_passed = all(check["passed"] for check in quality_checks)

    performance_checks: list[dict[str, Any]] = []
    if options.max_cold_compile_seconds_ratio is not None:
        performance_checks.append(
            _numeric_gate_check(
                "cold_compile_seconds_ratio",
                _ratio(
                    candidate["benchmark"]["summary"]["cold_compile_seconds"],
                    baseline["benchmark"]["summary"]["cold_compile_seconds"],
                ),
                "<=",
                options.max_cold_compile_seconds_ratio,
            )
        )
    if options.max_warm_cached_compile_seconds_ratio is not None:
        performance_checks.append(
            _numeric_gate_check(
                "warm_cached_compile_seconds_ratio",
                _ratio(
                    candidate["benchmark"]["summary"]["warm_cached_compile_seconds"],
                    baseline["benchmark"]["summary"]["warm_cached_compile_seconds"],
                ),
                "<=",
                options.max_warm_cached_compile_seconds_ratio,
            )
        )
    if options.min_target_bytes_per_second_ratio is not None:
        performance_checks.append(
            _numeric_gate_check(
                "target_bytes_per_second_ratio",
                _ratio(
                    candidate["benchmark"]["summary"]["target_bytes_per_second"],
                    baseline["benchmark"]["summary"]["target_bytes_per_second"],
                ),
                ">=",
                options.min_target_bytes_per_second_ratio,
            )
        )
    performance_configured = bool(performance_checks)
    performance_passed = all(check["passed"] for check in performance_checks)

    return {
        "schema_version": GATE_SCHEMA_VERSION,
        "configured": True,
        "passed": evaluator_passed and quality_passed and performance_passed,
        "baseline_path": str(options.baseline_benchmark_json),
        "evaluator": {
            "passed": evaluator_passed,
            "baseline": baseline_fingerprint,
            "candidate": candidate_fingerprint,
            "checks": evaluator_checks,
        },
        "quality": {"passed": quality_passed, "checks": quality_checks},
        "performance": {
            "configured": performance_configured,
            "passed": performance_passed,
            "checks": performance_checks,
        },
    }


def _evaluator_fingerprint(payload: Mapping[str, Any]) -> dict[str, Any]:
    manifest = cast(Mapping[str, Any], payload["manifest"])
    dataset = cast(Mapping[str, Any], manifest["dataset"])
    artifact_hashes = cast(Mapping[str, Any], manifest["artifact_hashes"])
    benchmark = cast(Mapping[str, Any], payload["benchmark"])
    tiers = cast(Mapping[str, Any], benchmark["tiers"])
    return {
        "schema_version": payload.get("schema_version"),
        "dataset": {
            "id": dataset.get("id"),
            "split": dataset.get("split"),
            "revision": dataset.get("revision"),
            "row_limit": dataset.get("row_limit"),
        },
        "sampling": manifest.get("sampling"),
        "train_artifact_hash": artifact_hashes.get("train"),
        "test_artifact_hash": artifact_hashes.get("test"),
        "benchmark_options": benchmark.get("options"),
        "quality_documents": manifest.get("sampling", {}).get("quality_documents"),
        "benchmark_tiers": {
            tier: {
                "document_count": tiers[tier]["document_count"],
                "bytes": tiers[tier]["bytes"],
                "iterations": tiers[tier]["iterations"],
            }
            for tier in ("baseline", "target", "stress")
        },
    }


def _validate_baseline_benchmark_payload(payload: Mapping[str, Any], path: Path) -> None:
    _baseline_mapping(payload, ("manifest", "dataset"), path)
    _baseline_mapping(payload, ("manifest", "artifact_hashes"), path)
    _baseline_mapping(payload, ("benchmark", "summary"), path)
    _baseline_mapping(payload, ("benchmark", "tiers", "baseline"), path)
    _baseline_mapping(payload, ("benchmark", "tiers", "target"), path)
    _baseline_mapping(payload, ("benchmark", "tiers", "stress"), path)
    _baseline_mapping(payload, ("quality", "test"), path)

    required_paths = (
        ("schema_version",),
        ("manifest", "sampling"),
        ("manifest", "candidate_limits"),
        ("benchmark", "options"),
        ("benchmark", "summary", "cold_compile_seconds"),
        ("benchmark", "summary", "warm_cached_compile_seconds"),
        ("benchmark", "summary", "target_bytes_per_second"),
        ("benchmark", "tiers", "baseline", "document_count"),
        ("benchmark", "tiers", "baseline", "bytes"),
        ("benchmark", "tiers", "baseline", "iterations"),
        ("benchmark", "tiers", "target", "document_count"),
        ("benchmark", "tiers", "target", "bytes"),
        ("benchmark", "tiers", "target", "iterations"),
        ("benchmark", "tiers", "stress", "document_count"),
        ("benchmark", "tiers", "stress", "bytes"),
        ("benchmark", "tiers", "stress", "iterations"),
    )
    for field_path in required_paths:
        _baseline_field(payload, field_path, path)
    _baseline_nonnegative_int(payload, ("quality", "test", "record_count"), path)
    _baseline_entity_counts(payload, ("quality", "test", "entity_counts"), path)
    for metric_name in ("precision", "recall", "f1"):
        _baseline_unit_metric(payload, ("quality", "test", metric_name), path)


def _baseline_field(payload: Mapping[str, Any], field_path: tuple[str, ...], path: Path) -> Any:
    current: Any = payload
    for field in field_path:
        if not isinstance(current, Mapping) or field not in current:
            dotted = ".".join(field_path)
            raise ValueError(f"Benchmark baseline JSON {str(path)!r} is missing required field {dotted}.")
        current = current[field]
    return current


def _baseline_mapping(payload: Mapping[str, Any], field_path: tuple[str, ...], path: Path) -> Mapping[str, Any]:
    value = _baseline_field(payload, field_path, path)
    if not isinstance(value, Mapping):
        dotted = ".".join(field_path)
        raise ValueError(f"Benchmark baseline JSON {str(path)!r} field {dotted} must be an object.")
    return value


def _baseline_nonnegative_int(payload: Mapping[str, Any], field_path: tuple[str, ...], path: Path) -> int:
    value = _baseline_field(payload, field_path, path)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        dotted = ".".join(field_path)
        raise ValueError(f"Benchmark baseline JSON {str(path)!r} field {dotted} must be a nonnegative integer.")
    return value


def _baseline_entity_counts(
    payload: Mapping[str, Any],
    field_path: tuple[str, ...],
    path: Path,
) -> dict[str, int]:
    value = _baseline_mapping(payload, field_path, path)
    counts: dict[str, int] = {}
    for entity, count in value.items():
        if not isinstance(entity, str) or not isinstance(count, int) or isinstance(count, bool) or count < 0:
            dotted = ".".join(field_path)
            raise ValueError(
                f"Benchmark baseline JSON {str(path)!r} field {dotted} must map entity names to nonnegative integers."
            )
        counts[entity] = count
    return counts


def _baseline_unit_metric(payload: Mapping[str, Any], field_path: tuple[str, ...], path: Path) -> float:
    value = _baseline_field(payload, field_path, path)
    number = _finite_json_number(value)
    if number is None or number < 0 or number > 1:
        dotted = ".".join(field_path)
        raise ValueError(f"Benchmark baseline JSON {str(path)!r} field {dotted} must be a finite number from 0 to 1.")
    return number


def _boolean_gate_check(name: str, actual: bool, description: str) -> dict[str, Any]:
    return {
        "name": name,
        "actual": actual,
        "operator": "==",
        "threshold": True,
        "passed": actual is True,
        "description": description,
    }


def _performance_gate_configured(options: PrepOptions) -> bool:
    return (
        options.max_cold_compile_seconds_ratio is not None
        or options.max_warm_cached_compile_seconds_ratio is not None
        or options.min_target_bytes_per_second_ratio is not None
    )


def _numeric_gate_check(
    name: str,
    actual: float | int | None,
    operator: str,
    threshold: float | int,
    *,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if actual is None:
        passed = False
    elif operator == "<=":
        passed = actual <= threshold
    elif operator == ">=":
        passed = actual >= threshold
    else:
        raise ValueError(f"Unsupported benchmark gate operator: {operator}.")
    check: dict[str, Any] = {
        "name": name,
        "actual": actual,
        "operator": operator,
        "threshold": threshold,
        "passed": passed,
    }
    if metadata is not None:
        check["metadata"] = dict(metadata)
    return check


def _quality_metric_delta_check(name: str, baseline_value: Any, candidate_value: Any) -> dict[str, Any]:
    baseline_number = _finite_json_number(baseline_value)
    candidate_number = _finite_json_number(candidate_value)
    delta = None
    if baseline_number is not None and candidate_number is not None:
        delta = _metric(candidate_number - baseline_number)
    return _numeric_gate_check(
        name,
        delta,
        ">=",
        0,
        metadata={
            "baseline": baseline_number,
            "candidate": candidate_number,
            "description": "candidate held-out exact-span metric must not regress against the stored baseline",
        },
    )


def _ratio(candidate_value: Any, baseline_value: Any) -> float | None:
    candidate_number = _finite_json_number(candidate_value)
    baseline_number = _finite_json_number(baseline_value)
    if candidate_number is None or baseline_number is None or candidate_number <= 0 or baseline_number <= 0:
        return None
    return round(candidate_number / baseline_number, 6)


def _finite_json_number(value: Any) -> float | None:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None
    try:
        parsed = float(value)
    except OverflowError:
        return None
    if not math.isfinite(parsed):
        return None
    return parsed


def _include_sample(document_id: str, seed: str, sample_fraction: float) -> bool:
    return _stable_unit_interval(f"sample:{seed}:{document_id}") < sample_fraction


def _split_name(document_id: str, seed: str, test_fraction: float) -> str:
    return "test" if _stable_unit_interval(f"split:{seed}:{document_id}") < test_fraction else "train"


def _stable_unit_interval(value: str) -> float:
    digest = hashlib.sha256(value.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") / float(2**64)


def _write_jsonl_record(file: TextIO, payload: Mapping[str, Any]) -> None:
    file.write(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n")


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    with _open_private_text(path) as file:
        file.write(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n")


def _prepare_output_dir(path: Path) -> Path:
    output_dir = path.expanduser()
    if output_dir.is_symlink():
        raise ValueError(f"Output directory must not be a symlink: {output_dir}.")
    if output_dir.exists() and not output_dir.is_dir():
        raise ValueError(f"Output path must be a directory: {output_dir}.")
    output_dir.mkdir(parents=True, exist_ok=True)
    output_dir.chmod(0o700)
    return output_dir


def _open_private_text(path: Path) -> TextIO:
    if path.is_symlink():
        raise ValueError(f"Benchmark artifact path must not be a symlink: {path}.")
    if path.exists():
        metadata = path.stat()
        if not S_ISREG(metadata.st_mode):
            raise ValueError(f"Benchmark artifact path must be a regular file: {path}.")
        path.chmod(0o600)

    def opener(raw_path: str, flags: int) -> int:
        return os.open(raw_path, flags, 0o600)

    file = open(path, "w", encoding="utf-8", opener=opener)
    path.chmod(0o600)
    return file


def _validate_source_options(options: PrepOptions) -> None:
    if options.input_jsonl is None and not options.dataset_revision:
        raise ValueError("Hugging Face Enron benchmark runs require --dataset-revision for reproducibility.")
    for field in (
        "max_cold_compile_seconds_ratio",
        "max_warm_cached_compile_seconds_ratio",
        "min_target_bytes_per_second_ratio",
    ):
        value = getattr(options, field)
        if value is not None:
            parsed = _finite_json_number(value)
            if parsed is None or parsed <= 0:
                raise ValueError(f"Benchmark gate threshold {field} must be a finite positive number.")
    if options.baseline_benchmark_json is None and _performance_gate_configured(options):
        raise ValueError("Benchmark gate thresholds require --baseline-benchmark-json.")


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json_mapping(path: Path) -> Mapping[str, Any]:
    benchmark_path = path.expanduser()
    if benchmark_path.is_symlink():
        raise ValueError(f"Benchmark baseline JSON path must not be a symlink: {benchmark_path}.")
    try:
        metadata = benchmark_path.stat()
    except OSError as exc:
        raise OSError(f"Could not inspect benchmark baseline JSON {str(benchmark_path)!r}: {exc}") from exc
    if not S_ISREG(metadata.st_mode):
        raise ValueError(f"Benchmark baseline JSON path must be a regular file: {benchmark_path}.")
    if metadata.st_size > DEFAULT_MAX_BASELINE_BENCHMARK_BYTES:
        raise ValueError(
            f"Benchmark baseline JSON {str(benchmark_path)!r} exceeds the configured limit of "
            f"{DEFAULT_MAX_BASELINE_BENCHMARK_BYTES} bytes."
        )
    try:
        with benchmark_path.open("rb") as file:
            payload = file.read(DEFAULT_MAX_BASELINE_BENCHMARK_BYTES + 1)
    except OSError as exc:
        raise OSError(f"Could not read benchmark baseline JSON {str(benchmark_path)!r}: {exc}") from exc
    if len(payload) > DEFAULT_MAX_BASELINE_BENCHMARK_BYTES:
        raise ValueError(
            f"Benchmark baseline JSON {str(benchmark_path)!r} exceeds the configured limit of "
            f"{DEFAULT_MAX_BASELINE_BENCHMARK_BYTES} bytes."
        )
    try:
        value = json.loads(
            payload.decode("utf-8"),
            parse_constant=_reject_non_finite_json_constant,
            parse_float=_finite_json_float,
            object_pairs_hook=_reject_duplicate_json_object_keys,
        )
    except UnicodeDecodeError as exc:
        raise ValueError(f"Benchmark baseline JSON must be UTF-8 encoded: {benchmark_path}.") from exc
    if not isinstance(value, Mapping):
        raise ValueError(f"Benchmark baseline JSON must be an object: {path}.")
    return value


def _reject_non_finite_json_constant(constant: str) -> None:
    raise ValueError(f"Benchmark baseline JSON must not contain non-finite value {constant}.")


def _finite_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError(f"Benchmark baseline JSON must not contain non-finite value {value}.")
    return parsed


def _reject_duplicate_json_object_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"Benchmark baseline JSON must not contain duplicate key {key!r}.")
        value[key] = item
    return value


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _positive_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("value must be a finite positive number")
    return parsed


def _fraction(value: str) -> float:
    parsed = float(value)
    if not 0 < parsed <= 1:
        raise argparse.ArgumentTypeError("value must be greater than 0 and at most 1")
    return parsed


def _timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _seconds(value: float) -> float:
    return round(value, 9)


def _metric(value: float) -> float:
    return round(value, 9)


def _parse_args(argv: Sequence[str] | None) -> PrepOptions:
    parser = argparse.ArgumentParser(
        description="Prepare a local Enron-derived NERB entity-bank benchmark and run its baseline measurements.",
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--dataset", default=None, help=f"Hugging Face dataset id. Defaults to {DEFAULT_DATASET_ID}.")
    source.add_argument("--input-jsonl", type=Path, help="Local JSONL fixture/source with Enron-like rows.")
    parser.add_argument("--dataset-split", default=DEFAULT_SPLIT, help="Hugging Face dataset split.")
    parser.add_argument("--dataset-revision", default=None, help="Optional Hugging Face dataset revision.")
    parser.add_argument("--output-dir", type=Path, default=Path(DEFAULT_OUTPUT_DIR), help="Local output directory.")
    parser.add_argument("--row-limit", type=_positive_int, default=None, help="Maximum raw rows to inspect.")
    parser.add_argument("--sample-fraction", type=_fraction, default=DEFAULT_SAMPLE_FRACTION)
    parser.add_argument("--test-fraction", type=_fraction, default=DEFAULT_TEST_FRACTION)
    parser.add_argument("--seed", default=DEFAULT_SEED)
    parser.add_argument("--max-body-chars", type=_positive_int, default=DEFAULT_MAX_BODY_CHARS)
    parser.add_argument("--max-addresses", type=_positive_int, default=DEFAULT_MAX_ADDRESSES)
    parser.add_argument("--max-domains", type=_positive_int, default=DEFAULT_MAX_DOMAINS)
    parser.add_argument("--min-address-count", type=_positive_int, default=2)
    parser.add_argument("--min-domain-count", type=_positive_int, default=2)
    parser.add_argument("--benchmark-documents", type=_positive_int, default=DEFAULT_BENCHMARK_DOCUMENTS)
    parser.add_argument("--quality-documents", type=_positive_int, default=DEFAULT_QUALITY_DOCUMENTS)
    parser.add_argument("--benchmark-iterations", type=_positive_int, default=DEFAULT_BENCHMARK_ITERATIONS)
    parser.add_argument(
        "--baseline-benchmark-json",
        type=Path,
        default=None,
        help="Stored Enron benchmark.json to compare this candidate run against.",
    )
    parser.add_argument(
        "--max-cold-compile-seconds-ratio",
        type=_positive_float,
        default=None,
        help="Fail the gate if candidate cold compile seconds exceed this baseline ratio.",
    )
    parser.add_argument(
        "--max-warm-cached-compile-seconds-ratio",
        type=_positive_float,
        default=None,
        help="Fail the gate if candidate warm cached compile seconds exceed this baseline ratio.",
    )
    parser.add_argument(
        "--min-target-bytes-per-second-ratio",
        type=_positive_float,
        default=None,
        help="Fail the gate if candidate target throughput falls below this baseline ratio.",
    )
    parser.add_argument(
        "--created-at",
        default=BANK_TIMESTAMP,
        help="Deterministic timestamp written into generated bank metadata.",
    )
    parsed = parser.parse_args(argv)
    if parsed.baseline_benchmark_json is None and (
        parsed.max_cold_compile_seconds_ratio is not None
        or parsed.max_warm_cached_compile_seconds_ratio is not None
        or parsed.min_target_bytes_per_second_ratio is not None
    ):
        parser.error("benchmark gate thresholds require --baseline-benchmark-json")
    dataset_id = parsed.dataset or ("local-jsonl" if parsed.input_jsonl is not None else DEFAULT_DATASET_ID)
    return PrepOptions(
        output_dir=parsed.output_dir,
        dataset_id=dataset_id,
        dataset_split=parsed.dataset_split,
        dataset_revision=parsed.dataset_revision,
        input_jsonl=parsed.input_jsonl,
        row_limit=parsed.row_limit,
        sample_fraction=parsed.sample_fraction,
        test_fraction=parsed.test_fraction,
        seed=parsed.seed,
        max_body_chars=parsed.max_body_chars,
        max_addresses=parsed.max_addresses,
        max_domains=parsed.max_domains,
        min_address_count=parsed.min_address_count,
        min_domain_count=parsed.min_domain_count,
        benchmark_documents=parsed.benchmark_documents,
        quality_documents=parsed.quality_documents,
        benchmark_iterations=parsed.benchmark_iterations,
        created_at=parsed.created_at,
        baseline_benchmark_json=parsed.baseline_benchmark_json,
        max_cold_compile_seconds_ratio=parsed.max_cold_compile_seconds_ratio,
        max_warm_cached_compile_seconds_ratio=parsed.max_warm_cached_compile_seconds_ratio,
        min_target_bytes_per_second_ratio=parsed.min_target_bytes_per_second_ratio,
    )

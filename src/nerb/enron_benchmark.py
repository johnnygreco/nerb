from __future__ import annotations

import argparse
import hashlib
import importlib
import json
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
from .extraction import extract_batch
from .schema import validate_bank_schema

ARTIFACT_SCHEMA_VERSION = "nerb.enron_benchmark.v1"
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
DEFAULT_BENCHMARK_ITERATIONS = 3
BANK_TIMESTAMP = "2026-06-09T00:00:00Z"

EMAIL_RE = re.compile(r"(?i)^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+\.[a-z]{2,}$")
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
    benchmark_iterations: int
    created_at: str


def main(argv: Sequence[str] | None = None) -> None:
    options = _parse_args(argv)
    result = prepare_enron_benchmark(options)
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))


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
    if not train_documents:
        raise ValueError("Enron benchmark prep produced no training documents.")
    if not test_documents:
        raise ValueError(
            "Enron benchmark prep produced no held-out test documents; increase --row-limit, --sample-fraction, "
            "or --test-fraction."
        )

    extraction_options = {
        "max_batch_documents": max(100, len(train_documents), len(test_documents)),
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
        "train": _quality_summary(bank, train_documents, extraction_options),
        "test": _quality_summary(bank, test_documents, extraction_options),
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
        "summary": {
            "selected_records": prep_summary["selected_records"],
            "train_records": prep_summary["train_records"],
            "test_records": prep_summary["test_records"],
            "bank_entities": bank_stats(bank)["active_totals"]["entities"],
            "bank_names": bank_stats(bank)["active_totals"]["names"],
            "bank_patterns": bank_stats(bank)["active_totals"]["patterns"],
            "cold_compile_seconds": benchmark["summary"]["cold_compile_seconds"],
            "target_bytes_per_second": benchmark["summary"]["target_bytes_per_second"],
            "test_record_count": quality["test"]["record_count"],
            "test_documents_with_records": quality["test"]["documents_with_records"],
        },
    }
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


def build_enron_entity_bank(
    address_counts: Counter[str],
    domain_counts: Counter[str],
    *,
    max_addresses: int = DEFAULT_MAX_ADDRESSES,
    max_domains: int = DEFAULT_MAX_DOMAINS,
    min_address_count: int = 2,
    min_domain_count: int = 2,
    created_at: str = BANK_TIMESTAMP,
) -> dict[str, Any]:
    addresses = _top_items(address_counts, max_items=max_addresses, min_count=min_address_count)
    domains = _top_items(domain_counts, max_items=max_domains, min_count=min_domain_count)
    entities: dict[str, Any] = {}
    if addresses:
        entities["email_address"] = _literal_entity(
            "Email addresses mined from training-set message headers and bodies.",
            addresses,
            pattern_description="Exact email address literal.",
        )
    if domains:
        entities["email_domain"] = _literal_entity(
            "Email domains mined from training-set message headers and bodies.",
            domains,
            pattern_description="Exact email domain literal.",
        )
    if not entities:
        raise ValueError("Cannot build Enron entity bank because no eligible addresses or domains were mined.")

    return {
        "schema_version": "nerb.bank.v1",
        "id": "enron_corpus_entities",
        "name": "Enron Corpus Entities",
        "description": "Deterministic entity bank mined from the Enron email training split for NERB benchmarking.",
        "version": "2026.06.09",
        "status": "active",
        "created_at": created_at,
        "updated_at": created_at,
        "unicode_normalization": "none",
        "default_regex_flags": ["IGNORECASE"],
        "entities": entities,
        "metadata": {
            "source": "nerb.enron_benchmark.build_enron_entity_bank",
            "address_candidates": len(addresses),
            "domain_candidates": len(domains),
            "min_address_count": min_address_count,
            "min_domain_count": min_domain_count,
        },
    }


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


def _literal_entity(description: str, values: Sequence[str], *, pattern_description: str) -> dict[str, Any]:
    names: dict[str, Any] = {}
    for priority, value in enumerate(values):
        name_id = _id_from_value(value)
        names[name_id] = {
            "canonical": value,
            "description": "Corpus-mined literal.",
            "status": "active",
            "patterns": {
                "primary": {
                    "kind": "literal",
                    "value": value,
                    "description": pattern_description,
                    "status": "active",
                    "priority": priority,
                    "case_sensitive": False,
                    "normalize_whitespace": False,
                    "left_boundary": "none",
                    "right_boundary": "none",
                    "metadata": {},
                }
            },
            "metadata": {},
        }
    return {"description": description, "status": "active", "regex_flags": [], "names": names, "metadata": {}}


def _top_items(counts: Counter[str], *, max_items: int, min_count: int) -> list[str]:
    candidates = [item for item, count in counts.items() if count >= min_count]
    candidates.sort(key=lambda item: (-counts[item], item))
    return candidates[:max_items]


def _id_from_value(value: str) -> str:
    return "v_" + _hash_text(value)[:16]


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
        }
    response = extract_batch(bank, cast(Sequence[Mapping[str, Any]], documents), options=options)
    entity_counts: Counter[str] = Counter(str(record["entity_id"]) for record in response["records"])
    return {
        "document_count": response["summary"]["document_count"],
        "record_count": response["summary"]["record_count"],
        "documents_with_records": response["summary"]["documents_with_records"],
        "entity_counts": dict(sorted(entity_counts.items())),
    }


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
        },
        "candidate_limits": {
            "max_addresses": options.max_addresses,
            "max_domains": options.max_domains,
            "min_address_count": options.min_address_count,
            "min_domain_count": options.min_domain_count,
        },
        "prep_summary": dict(prep_summary),
        "artifact_hashes": artifact_hashes,
        "bank_hash": hash_bank(bank),
        "bank_stats": bank_stats(bank),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "executable": sys.executable,
        },
    }


def _include_sample(document_id: str, seed: str, sample_fraction: float) -> bool:
    return _stable_unit_interval(f"sample:{seed}:{document_id}") < sample_fraction


def _split_name(document_id: str, seed: str, test_fraction: float) -> str:
    return "test" if _stable_unit_interval(f"split:{seed}:{document_id}") < test_fraction else "train"


def _stable_unit_interval(value: str) -> float:
    digest = hashlib.sha256(value.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") / float(2**64)


def _write_jsonl_record(file: TextIO, payload: Mapping[str, Any]) -> None:
    file.write(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    with _open_private_text(path) as file:
        file.write(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


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


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def _fraction(value: str) -> float:
    parsed = float(value)
    if not 0 < parsed <= 1:
        raise argparse.ArgumentTypeError("value must be greater than 0 and at most 1")
    return parsed


def _timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _seconds(value: float) -> float:
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
    parser.add_argument("--benchmark-iterations", type=_positive_int, default=DEFAULT_BENCHMARK_ITERATIONS)
    parser.add_argument(
        "--created-at",
        default=BANK_TIMESTAMP,
        help="Deterministic timestamp written into generated bank metadata.",
    )
    parsed = parser.parse_args(argv)
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
        benchmark_iterations=parsed.benchmark_iterations,
        created_at=parsed.created_at,
    )

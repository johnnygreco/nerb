from __future__ import annotations

# Standard library
from collections.abc import Mapping, Sequence
from pathlib import Path
from stat import S_ISREG
from typing import Any

# Project
from .engines import CompiledBank, ExtractionError, compile_bank, resolve_extraction_options
from .records import MatchRecord, record_sort_key
from .schema import ID_RE

__all__ = [
    "ExtractionError",
    "extract_batch",
    "extract_file",
    "extract_report",
    "extract_report_batch",
    "extract_report_file",
    "extract_text",
    "explain_match",
]


def extract_text(bank: Mapping[str, Any], text: str, *, options: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Extract JSON-bank records with the Rust-backed Bank scanner."""
    if not isinstance(text, str):
        raise TypeError("extract_text text must be a string.")

    resolved = resolve_extraction_options(options)
    _ensure_text_limit(text, resolved.max_text_bytes)
    compiled, cache_hit = compile_bank(bank, options=options)
    _ensure_bank_status_extractable(compiled.bank, resolved.include_statuses)
    records = _extract_records(compiled, text)
    return {
        "bank": _bank_metadata(compiled),
        "engine": _engine_metadata(compiled, cache_hit),
        "source": _text_source_metadata(text),
        "records": records,
    }


def extract_file(
    bank: Mapping[str, Any],
    file_path: str | Path,
    *,
    options: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Extract rich JSON-bank records from a UTF-8 text file."""
    path = Path(file_path).expanduser()
    resolved = resolve_extraction_options(options)
    text, byte_count = _read_utf8_file(path, max_bytes=resolved.max_text_bytes)
    compiled, cache_hit = compile_bank(bank, options=options)
    _ensure_bank_status_extractable(compiled.bank, resolved.include_statuses)
    records = _extract_records(compiled, text)
    return {
        "bank": _bank_metadata(compiled),
        "engine": _engine_metadata(compiled, cache_hit),
        "source": _file_source_metadata(path, text, byte_count),
        "records": records,
    }


def extract_batch(
    bank: Mapping[str, Any],
    documents: Sequence[Mapping[str, Any]],
    *,
    options: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Extract rich JSON-bank records from a bounded batch of text or file documents."""
    prepared_documents, combined_bytes = _prepare_batch_documents(documents, options=options)
    return _extract_prepared_batch(bank, prepared_documents, combined_bytes=combined_bytes, options=options)


def _prepare_batch_documents(
    documents: Sequence[Mapping[str, Any]],
    *,
    options: Mapping[str, Any] | None = None,
) -> tuple[list[tuple[str, dict[str, Any], str]], int]:
    if isinstance(documents, (str, bytes)) or not isinstance(documents, Sequence):
        raise TypeError("extract_batch documents must be a sequence of document objects.")

    resolved = resolve_extraction_options(options)
    if len(documents) > resolved.max_batch_documents:
        raise ExtractionError(
            f"Batch extraction accepts at most {resolved.max_batch_documents} documents; got {len(documents)}."
        )

    prepared_documents: list[tuple[str, dict[str, Any], str]] = []
    combined_bytes = 0
    for index, document in enumerate(documents):
        prepared_document, byte_count = _prepare_batch_document(
            index,
            document,
            max_text_bytes=resolved.max_text_bytes,
            max_batch_text_bytes=resolved.max_batch_text_bytes,
            current_batch_text_bytes=combined_bytes,
        )
        combined_bytes += byte_count
        prepared_documents.append(prepared_document)

    return prepared_documents, combined_bytes


def _extract_prepared_batch(
    bank: Mapping[str, Any],
    prepared_documents: Sequence[tuple[str, dict[str, Any], str]],
    *,
    combined_bytes: int,
    options: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    resolved = resolve_extraction_options(options)
    compiled, cache_hit = compile_bank(bank, options=options)
    _ensure_bank_status_extractable(compiled.bank, resolved.include_statuses)

    document_results: list[dict[str, Any]] = []
    flat_records: list[MatchRecord] = []
    for document_id, source, text in prepared_documents:
        records = _extract_records(compiled, text)
        document_results.append({"document_id": document_id, "source": source, "records": records})
        for record in records:
            flat_record = {"document_id": document_id, **record}
            flat_records.append(flat_record)

    flat_records.sort(key=_batch_record_sort_key)
    return {
        "bank": _bank_metadata(compiled),
        "engine": _engine_metadata(compiled, cache_hit),
        "source": {
            "type": "batch",
            "document_count": len(prepared_documents),
            "bytes": combined_bytes,
        },
        "documents": document_results,
        "records": flat_records,
        "summary": {
            "document_count": len(prepared_documents),
            "record_count": len(flat_records),
            "documents_with_records": sum(1 for document in document_results if document["records"]),
        },
    }


def extract_report(
    bank: Mapping[str, Any],
    text: str,
    *,
    options: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a single-document extraction report."""
    from .reports import extract_report as _extract_report

    return _extract_report(bank, text, options=options)


def extract_report_batch(
    bank: Mapping[str, Any],
    documents: Sequence[Mapping[str, Any]],
    *,
    options: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return extraction reports for a bounded batch."""
    from .reports import extract_report_batch as _extract_report_batch

    return _extract_report_batch(bank, documents, options=options)


def extract_report_file(
    bank: Mapping[str, Any],
    file_path: str | Path,
    *,
    options: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a single-file extraction report."""
    from .reports import extract_report_file as _extract_report_file

    return _extract_report_file(bank, file_path, options=options)


def explain_match(
    bank: Mapping[str, Any],
    entity_id: str,
    name_id: str,
    pattern_id: str,
    *,
    options: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Explain one configured JSON-bank pattern."""
    from .reports import explain_match as _explain_match

    return _explain_match(bank, entity_id, name_id, pattern_id, options=options)


def _extract_records(compiled: CompiledBank, text: str) -> list[MatchRecord]:
    records = compiled.finditer(text)
    records.sort(key=record_sort_key)
    return records


def _ensure_text_limit(text: str, max_text_bytes: int) -> None:
    size = _text_size_bytes(text)
    if size > max_text_bytes:
        raise ExtractionError(f"Extraction text exceeds the configured limit of {max_text_bytes} bytes.")


def _ensure_bank_status_extractable(bank: Mapping[str, Any], include_statuses: tuple[str, ...]) -> None:
    status = bank.get("status")
    if status not in include_statuses:
        raise ExtractionError(
            f"Bank status {status!r} is not included in extraction statuses {list(include_statuses)!r}."
        )


def _text_size_bytes(text: str) -> int:
    return len(text.encode("utf-8"))


def _bank_metadata(compiled: CompiledBank) -> dict[str, Any]:
    return {
        "id": compiled.bank["id"],
        "version": compiled.bank["version"],
        "schema_version": compiled.bank["schema_version"],
        "hash": compiled.bank_hash,
    }


def _engine_metadata(compiled: CompiledBank, cache_hit: bool) -> dict[str, Any]:
    return {
        "name": compiled.engine_name,
        "version": compiled.engine_version,
        "cache": {**compiled.cache_metadata, "hit": cache_hit},
    }


def _text_source_metadata(text: str) -> dict[str, Any]:
    return {"type": "text", "length": len(text), "bytes": _text_size_bytes(text)}


def _file_source_metadata(path: Path, text: str, byte_count: int) -> dict[str, Any]:
    return {"type": "file", "path": str(path), "length": len(text), "bytes": byte_count}


def _prepare_batch_document(
    index: int,
    document: Mapping[str, Any],
    *,
    max_text_bytes: int,
    max_batch_text_bytes: int,
    current_batch_text_bytes: int,
) -> tuple[tuple[str, dict[str, Any], str], int]:
    if not isinstance(document, Mapping):
        raise TypeError("Batch documents must be objects.")

    document_id = document.get("document_id", document.get("id", f"document_{index}"))
    if not isinstance(document_id, str) or not ID_RE.fullmatch(document_id):
        raise ExtractionError("Batch document IDs must use the NERB ID syntax.")

    has_text = "text" in document
    has_file_path = "file_path" in document
    if has_text == has_file_path:
        raise ExtractionError("Each batch document must provide exactly one of text or file_path.")

    if has_text:
        text = document["text"]
        if not isinstance(text, str):
            raise TypeError("Batch document text must be a string.")
        byte_count = _text_size_bytes(text)
        _ensure_byte_limit(byte_count, max_text_bytes)
        _ensure_batch_byte_limit(current_batch_text_bytes, byte_count, max_batch_text_bytes)
        return (document_id, {"type": "text", "length": len(text), "bytes": byte_count}, text), byte_count

    file_path = document["file_path"]
    if not isinstance(file_path, (str, Path)):
        raise TypeError("Batch document file_path must be a string or Path.")
    path = Path(file_path).expanduser()
    file_size = _file_size(path)
    _ensure_batch_byte_limit(current_batch_text_bytes, file_size, max_batch_text_bytes)
    text, byte_count = _read_utf8_file(path, max_bytes=max_text_bytes, known_size=file_size)
    _ensure_batch_byte_limit(current_batch_text_bytes, byte_count, max_batch_text_bytes)
    return (document_id, _file_source_metadata(path, text, byte_count), text), byte_count


def _read_utf8_file(path: Path, *, max_bytes: int, known_size: int | None = None) -> tuple[str, int]:
    byte_count = _file_size(path) if known_size is None else known_size
    _ensure_byte_limit(byte_count, max_bytes)
    try:
        with path.open("rb") as file:
            data = file.read(max_bytes + 1)
    except OSError as exc:
        raise ExtractionError(f"Could not read extraction source file {str(path)!r}: {exc}.") from exc
    if len(data) > max_bytes:
        _ensure_byte_limit(len(data), max_bytes)
    try:
        return data.decode("utf-8"), len(data)
    except UnicodeDecodeError as exc:
        raise ExtractionError(f"Extraction source file {str(path)!r} is not valid UTF-8: {exc}.") from exc


def _file_size(path: Path) -> int:
    try:
        metadata = path.stat()
    except OSError as exc:
        raise ExtractionError(f"Could not inspect extraction source file {str(path)!r}: {exc}.") from exc
    if not S_ISREG(metadata.st_mode):
        raise ExtractionError(f"Extraction source file {str(path)!r} must be a regular file.")
    return metadata.st_size


def _ensure_byte_limit(byte_count: int, max_bytes: int) -> None:
    if byte_count > max_bytes:
        raise ExtractionError(f"Extraction text exceeds the configured limit of {max_bytes} bytes.")


def _ensure_batch_byte_limit(current_bytes: int, document_bytes: int, max_bytes: int) -> None:
    if current_bytes + document_bytes > max_bytes:
        raise ExtractionError(f"Batch extraction text exceeds the configured combined limit of {max_bytes} bytes.")


def _batch_record_sort_key(record: MatchRecord) -> tuple[str, int, int, str, str, str, str]:
    return (
        str(record["document_id"]),
        int(record["start"]),
        int(record["end"]),
        str(record["entity_id"]),
        str(record["name_id"]),
        str(record["pattern_id"]),
        str(record["string"]),
    )

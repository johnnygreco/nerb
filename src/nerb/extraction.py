from __future__ import annotations

# Standard library
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

# Project
from .engines import (
    CompiledBank,
    ExtractionError,
    compile_bank,
    resolve_extraction_options,
)
from .named_entities import NamedEntity, NamedEntityList
from .records import MatchRecord, record_sort_key
from .schema import ID_RE

__all__ = [
    "ExtractionError",
    "extract_batch",
    "extract_file",
    "extract_named_entities",
    "extract_named_entities_records",
    "extract_named_entity",
    "extract_named_entity_records",
    "extract_text",
]


def _sort_key(entity: NamedEntity) -> tuple[int, int, str, str, str]:
    return (entity.span[0], entity.span[1], entity.entity, entity.name, entity.string)


def extract_named_entity(extractor: Any, entity: str, text: str) -> NamedEntityList:
    """
    Extract one configured entity from text.

    Results preserve the regex engine's deterministic left-to-right match order.
    """
    if not hasattr(extractor, entity):
        raise AttributeError(f"This NERB instance does not have a compiled regex called {entity}.")

    regex = getattr(extractor, entity)
    named_entity_list = NamedEntityList()

    for match in regex.finditer(text):
        if match.lastgroup is None:
            continue

        name = match.lastgroup.replace("_", " ")
        named_entity_list.append(NamedEntity(entity=entity, name=name, string=match.group(), span=match.span()))

    return named_entity_list


def extract_named_entities(extractor: Any, text: str) -> NamedEntityList:
    """
    Extract all configured entities from text.

    Results are sorted by start offset, end offset, entity, name, and matched string so
    callers receive deterministic document-order output across entity groups.
    """
    named_entity_list = NamedEntityList()

    for entity in extractor.entity_list:
        named_entity_list.extend(extract_named_entity(extractor, entity, text))

    named_entity_list.sort(key=_sort_key)
    return named_entity_list


def extract_named_entity_records(extractor: Any, entity: str, text: str) -> list[dict[str, Any]]:
    """Extract one configured entity and serialize the matches as records."""
    return extract_named_entity(extractor, entity, text).to_records()


def extract_named_entities_records(extractor: Any, text: str) -> list[dict[str, Any]]:
    """Extract all configured entities and serialize the matches as records."""
    return extract_named_entities(extractor, text).to_records()


def extract_text(bank: Mapping[str, Any], text: str, *, options: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Extract rich JSON-bank records from a single in-memory text document."""
    if not isinstance(text, str):
        raise TypeError("extract_text text must be a string.")

    resolved = resolve_extraction_options(options)
    _ensure_text_limit(text, resolved.max_text_bytes)
    _ensure_bank_status_extractable(bank, resolved.include_statuses)
    compiled, cache_hit = compile_bank(bank, options=options)
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
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ExtractionError(f"Could not read extraction source file {str(path)!r}: {exc}.") from exc

    resolved = resolve_extraction_options(options)
    _ensure_text_limit(text, resolved.max_text_bytes)
    _ensure_bank_status_extractable(bank, resolved.include_statuses)
    compiled, cache_hit = compile_bank(bank, options=options)
    records = _extract_records(compiled, text)
    return {
        "bank": _bank_metadata(compiled),
        "engine": _engine_metadata(compiled, cache_hit),
        "source": _file_source_metadata(path, text),
        "records": records,
    }


def extract_batch(
    bank: Mapping[str, Any],
    documents: Sequence[Mapping[str, Any]],
    *,
    options: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Extract rich JSON-bank records from a bounded batch of text or file documents."""
    if isinstance(documents, (str, bytes)) or not isinstance(documents, Sequence):
        raise TypeError("extract_batch documents must be a sequence of document objects.")

    resolved = resolve_extraction_options(options)
    if len(documents) > resolved.max_batch_documents:
        raise ExtractionError(
            f"Batch extraction accepts at most {resolved.max_batch_documents} documents; got {len(documents)}."
        )

    prepared_documents = [_prepare_batch_document(index, document) for index, document in enumerate(documents)]
    combined_bytes = sum(_text_size_bytes(text) for _, _, text in prepared_documents)
    if combined_bytes > resolved.max_batch_text_bytes:
        raise ExtractionError(
            f"Batch extraction text exceeds the configured combined limit of {resolved.max_batch_text_bytes} bytes."
        )
    for _, _, text in prepared_documents:
        _ensure_text_limit(text, resolved.max_text_bytes)

    _ensure_bank_status_extractable(bank, resolved.include_statuses)
    compiled, cache_hit = compile_bank(bank, options=options)

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
        "cache": {"hit": cache_hit, "key": compiled.cache_key.to_dict()},
    }


def _text_source_metadata(text: str) -> dict[str, Any]:
    return {"type": "text", "length": len(text), "bytes": _text_size_bytes(text)}


def _file_source_metadata(path: Path, text: str) -> dict[str, Any]:
    return {"type": "file", "path": str(path), "length": len(text), "bytes": _text_size_bytes(text)}


def _prepare_batch_document(index: int, document: Mapping[str, Any]) -> tuple[str, dict[str, Any], str]:
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
        return document_id, {"type": "text", "length": len(text), "bytes": _text_size_bytes(text)}, text

    file_path = document["file_path"]
    if not isinstance(file_path, (str, Path)):
        raise TypeError("Batch document file_path must be a string or Path.")
    path = Path(file_path).expanduser()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ExtractionError(f"Could not read extraction source file {str(path)!r}: {exc}.") from exc
    return document_id, _file_source_metadata(path, text), text


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

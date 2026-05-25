---
name: nerb-extraction-surfaces
description: Use when changing NERB extraction behavior, serialized output records, public extraction helpers, or future CLI/MCP extraction surfaces.
---

# NERB Extraction Surfaces

Use this skill for extraction behavior and output formats. Preserve the Python API while making CLI and MCP outputs first-class wrappers around shared helpers.

## Files

- `src/nerb/regex_builder.py`: `NERB`, compiled regex attributes, and instance extraction methods.
- `src/nerb/extraction.py`: shared extraction functions.
- `src/nerb/named_entities.py`: serialized record shape.
- `src/nerb/__init__.py`: public exports.
- `tests/nerb/test_extraction.py`: extraction ordering and records.

## Stable Behavior

- `NERB(pattern_config, add_word_boundaries=False)` accepts a path/string YAML config or an in-memory config dict.
- Entity regexes remain accessible as attributes such as `nerb.ARTIST`.
- `extract_named_entity` returns `NamedEntityList` for one entity.
- `extract_named_entities` returns all entities in deterministic document order.
- `NamedEntity.to_dict()` and `NamedEntityList.to_records()` use JSON-compatible records with `entity`, `name`, `string`, `start`, and `end`.
- Spaces in detector names become underscores in regex group names, then become spaces again in extracted `name` values.

## Implementation Guidance

- Add new serialization formats by adapting `NamedEntityList.to_records()` output rather than changing the record fields.
- Keep CLI and MCP extraction commands thin: load/build a `NERB`, call `extract_named_entity` or `extract_named_entities`, then serialize records.
- Export new public helpers from `src/nerb/__init__.py` only when they are intended as Python API.
- Keep fixture parity between Python API, future CLI extraction, and future MCP tools.
- Do not change `NamedEntity` field names or `NamedEntityList` behavior without explicit compatibility work.

## Acceptance Checks

```shell
uv run pytest tests/nerb/test_extraction.py tests/nerb/test_regex_builder.py
uv run ruff check .
uv run ty check
```

Use `make check` for shared extraction changes before a PR.

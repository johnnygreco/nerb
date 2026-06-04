---
name: nerb-extraction-surfaces
description: Use when changing NERB extraction behavior, serialized output records, public extraction helpers, or future CLI/MCP extraction surfaces.
---

# NERB Extraction Surfaces

Use this skill for extraction behavior and output formats. During the Rust engine migration, treat the Rust-backed `Bank`
surface and explicit record contracts as the target; current Python output can be a test oracle, not the target surface.

## Rust Engine Plan Precedence

When working on tracker #45 or `agent-scratchpads/rust-engine-plan.md`, that plan and the active implementation issue
override current-surface guidance in this skill. Use the current Python behavior as an oracle only where the active issue
asks for differential checks.

## Files

- `src/nerb/regex_builder.py`: `NERB`, compiled regex attributes, and instance extraction methods.
- `src/nerb/extraction.py`: shared extraction functions.
- `src/nerb/named_entities.py`: serialized record shape.
- `src/nerb/__init__.py`: public exports.
- `tests/nerb/test_extraction.py`: extraction ordering and records.

## Current Python Behavior

- `NERB(pattern_config, add_word_boundaries=False)` accepts a path/string YAML config or an in-memory config dict.
- Entity regexes remain accessible as attributes such as `nerb.ARTIST`.
- `extract_named_entity` returns `NamedEntityList` for one entity.
- `extract_named_entities` returns all entities in deterministic document order.
- `NamedEntity.to_dict()` and `NamedEntityList.to_records()` use JSON-compatible records with `entity`, `name`, `string`, `start`, and `end`.
- Spaces in detector names become underscores in regex group names, then become spaces again in extracted `name` values.

## Implementation Guidance

- Use the current Python behavior as an oracle only when an active issue calls for differential checks.
- Keep CLI and MCP extraction commands thin: load/build the active engine surface, call the shared extraction helper, then serialize records.
- Export new public helpers from `src/nerb/__init__.py` only when they are intended as Python API.
- Keep fixture parity between Python API, future CLI extraction, and future MCP tools.
- Do not add shims for current Python regex-builder callers unless an active issue explicitly requires one.

## Acceptance Checks

```shell
uv run pytest tests/nerb/test_extraction.py tests/nerb/test_regex_builder.py
uv run ruff check .
uv run ty check
```

Use `make check` for shared extraction changes before a PR.

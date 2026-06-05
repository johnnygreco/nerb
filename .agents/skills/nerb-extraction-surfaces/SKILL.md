---
name: nerb-extraction-surfaces
description: Use when changing NERB extraction behavior, serialized output records, public extraction helpers, or future CLI/MCP extraction surfaces.
---

# NERB Extraction Surfaces

Use this skill for extraction behavior and output formats. Treat the Rust-backed `Bank` surface and explicit record
contracts as the target.

## Rust Engine Plan Precedence

When working on tracker #45 or `agent-scratchpads/rust-engine-plan.md`, that plan and the active implementation issue
override current-surface guidance in this skill.

## Files

- `src/nerb/engine.py`: Rust-backed `Bank` wrapper and native cache integration.
- `src/nerb/engines.py`: JSON-bank extraction adapter and source-ID enrichment.
- `src/nerb/extraction.py`: shared JSON-bank extraction functions.
- `src/nerb/records.py`: shared record typing and deterministic sort keys.
- `src/nerb/__init__.py`: public exports.
- `tests/nerb/test_json_bank_extraction.py`: JSON-bank extraction records and cache behavior.
- `tests/nerb/test_rust_engine_conformance.py`: Rust record-contract conformance.

## Current Rust-Backed Behavior

- `Bank.from_source_bytes`, `Bank.from_path`, and `Bank.from_config` compile through the native Rust engine.
- Public `Bank.scan_text` records include `entity`, `canonical_name`, `surface_name`, `string`, `start`, `end`, and
  `offset_unit`.
- JSON-bank extraction helpers enrich Rust records with `entity_id`, `name_id`, `pattern_id`, `pattern_kind`, and
  `captures`.
- Offsets are byte offsets by default unless a caller explicitly asks `Bank.scan_text(..., offsets="char")`.
- Detector names are preserved as canonical names and are not constrained by Python regex group-name rules.

## Implementation Guidance

- Keep CLI and MCP extraction commands thin: load/build the active engine surface, call the shared extraction helper, then serialize records.
- Export new public helpers from `src/nerb/__init__.py` only when they are intended as Python API.
- Keep fixture parity between Python API, CLI extraction, and MCP tools.
- Do not add shims for removed Python regex-builder callers unless an active issue explicitly requires one.

## Acceptance Checks

```shell
uv run pytest tests/nerb/test_json_bank_extraction.py tests/nerb/test_rust_engine_conformance.py
uv run ruff check .
uv run ty check
```

Use `make check` for shared extraction changes before a PR.

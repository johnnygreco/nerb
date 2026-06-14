# De-Anonymization Feature Status

This document is a historical implementation note for NERB's anonymization and de-anonymization feature. The detailed
step-by-step plan that originally lived here has been replaced by the current status and the maintained references
below.

The implemented behavior is now documented in:

- [`README.md`](../README.md): copyable CLI workflows and security notes.
- [`docs/schemas.md`](schemas.md): replacement database, anonymization response, and de-anonymization response
  contracts.
- `src/nerb/replacements_schema.py`: replacement database schema.
- `src/nerb/replacements.py`: creation, validation, hashing, loading, saving, and persistence helpers.
- `src/nerb/deanonymization.py`: anonymization, redaction, pseudonymization, de-anonymization, byte rewriting, and
  response construction.
- `src/nerb/cli.py`: `replacement-db`, `anonymize-*`, and `deanonymize-*` commands.
- `src/nerb/mcp_server.py`: MCP replacement database, anonymization, and de-anonymization tools.

## Current Status

NERB supports deterministic replacement of extracted entities with redaction tokens or pseudonyms. Reversible workflows
use an explicit local replacement database. That database is sensitive when it stores originals.

Implemented surfaces include:

- Python helpers: `anonymize_text`, `anonymize_file`, `anonymize_config_text`, `anonymize_config_file`,
  `deanonymize_text`, and `deanonymize_file`.
- CLI commands: `replacement-db init`, `replacement-db validate`, `replacement-db list`, `replacement-db add-set`,
  `replacement-db set-entity`, `anonymize-text`, `anonymize-file`, `anonymize-config-text`,
  `anonymize-config-file`, `deanonymize-text`, and `deanonymize-file`.
- MCP tools: `create_replacement_db`, `validate_replacement_db`, `save_replacement_db`, text/file anonymization tools,
  config-backed anonymization tools, and text/file de-anonymization tools.

The default replacement database mode is non-reversible redaction. Reversible de-anonymization requires an explicit
database that stores originals. Pseudonym restoration is opt-in because it is exact string replacement and can also
restore natural occurrences of the pseudonym in transformed text.

## Decisions Preserved

The implemented feature kept the core decisions from the original plan:

- Replacement databases are versioned JSON objects with schema version `nerb.replacements.v1`.
- JSON is the persistence format because it matches JSON banks, is local and inspectable, can be validated as one
  object, and supports whole-file atomic writes. SQLite, JSONL, YAML, and embedding assignments in banks were deferred
  to avoid extra persistence models or unsafe sharing of per-user sensitive state.
- Assignment scope is explicit: `name` for JSON-bank records, `canonical` when stable `name_id` values are unavailable,
  and `surface` when each matched surface should receive its own assignment.
- Text rewriting uses byte spans from the Rust-backed extraction contract and validates edits before applying them.
- De-anonymization builds an opaque reverse bank from reversible assignments and scans with the same Rust-backed `Bank`
  path used by extraction. Generated reverse banks must not expose originals through schema IDs, canonical values, or
  default diagnostics.
- CLI and MCP writes are explicit. Reading a replacement database never implies an in-place save.
- Default CLI and MCP response metadata redacts originals, raw assignment keys, fingerprints, hashes, and source IDs.
- Diagnostics use machine-readable codes such as `schema.*`, `replacement_db.candidates_exhausted`,
  `replacement_db.missing_original`, `rewrite.invalid_span`, `rewrite.overlap`, and
  `deanonymize.ambiguous_replacement`.
- Scale limits stay bounded: text inputs use existing extraction limits, stored surfaces per assignment are capped, and
  reverse de-anonymization with more than 1,000 generated reverse entities should receive dedicated performance and
  memory evidence before being treated as routine.
- Pseudonymization is deterministic replacement, not cryptographic anonymization. Reversible databases and sensitive
  response flags can expose original identities and should be handled as local sensitive files/data.

## Validation

Focused checks for this feature:

```shell
uv run pytest tests/nerb/test_replacement_db.py tests/nerb/test_deanonymization.py
uv run pytest tests/nerb/test_cli.py tests/nerb/test_mcp_server.py
uv run ruff check .
uv run ty check
```

Run `make check` before a broad release or maintenance PR when practical.

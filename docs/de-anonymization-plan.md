# De-Anonymization Implementation Plan

## Purpose

Add a shared NERB feature for replacing extracted entities with stable substitute text and, when the user keeps a
reversible local replacement database, restoring those substitutes back to the original entities. The feature should
support two related workflows:

1. Stable pseudonymization for long-horizon agent work, such as always replacing `John Smith` with `Mikey Law` across
   documents and sessions.
2. De-anonymization of transformed text, such as restoring `[PERSON_0001]` or, when explicitly enabled, `Mikey Law` back
   to `John Smith` when the local replacement database contains the reversible assignment.

This plan is intentionally implementation-ready. It defines the database format, ownership boundaries, algorithms,
response contracts, CLI/MCP surfaces, validation, tests, performance gates, security model, and the recommended issue
sequence for a future implementation agent.

## Current Repo Constraints

- JSON banks are the main agent and service format. They already provide stable entity/name/pattern IDs and enriched
  extraction records through `src/nerb/extraction.py` and `src/nerb/engines.py`.
- The Rust-backed `Bank` API is the matching data plane. New replacement features should use existing extraction and
  generated reverse banks instead of adding a second matcher.
- Byte offsets are the public extraction contract. Text rewriting must either operate on UTF-8 bytes or convert byte
  spans to character spans through one shared helper before slicing Python strings.
- CLI and MCP extraction surfaces should stay thin. Shared behavior belongs in core modules such as a new
  `src/nerb/deanonymization.py`, a schema module, and small record helpers.
- Writes must be explicit and atomic. The detector config path rules are the model: no broad filesystem discovery, no
  implicit project-wide state, and no direct YAML/JSON writes from CLI or MCP wrappers.
- Backward compatibility is not required for this new feature because no existing de-anonymization surface exists.

## Terms

- **Original**: the sensitive text matched in the source document, for example `John Smith`.
- **Replacement**: the substitute text written into the transformed document, for example `Mikey Law`.
- **Redaction token**: a synthetic substitute intended to be unambiguous, for example `[PERSON_0001]`.
- **Assignment**: a stable database row that maps one entity identity to one replacement and optional redaction token.
- **Replacement database**: a versioned local JSON file containing replacement pools, assignment policy, and assignments.
- **Pseudonymization**: replacing originals with plausible or user-provided alternatives.
- **Redaction**: replacing originals with structured tokens.
- **De-anonymization**: restoring replacements or redaction tokens using the reversible replacement database. By default
  this restores canonical identity for `name` and `canonical` scopes, not necessarily the exact source surface.

## Goals

- Provide deterministic, repeatable replacements for extracted entities across many agent sessions.
- Make reversible de-anonymization possible when the user explicitly keeps a database containing originals.
- Keep all matching local and explainable through NERB's existing Rust-backed extraction path.
- Support JSON-bank workflows first, with a constrained YAML detector config path that uses the same shared helpers.
- Preserve deterministic output ordering, bounded inputs, explicit paths, and machine-readable JSON responses.
- Make privacy risks visible: the database is sensitive when it stores originals, and NERB should not imply otherwise.

## Non-Goals

- No cryptographic anonymization guarantee. This is deterministic replacement and optional restoration, not a formal
  privacy-preserving transformation.
- No remote database, server, key-management service, or cloud sync in the first implementation.
- No automatic replacement generation from external services.
- No full-document provenance store. The database stores entity assignments, not source documents.
- No changes to Rust scan semantics unless a later implementation issue proves a native helper is necessary.
- No guessing during de-anonymization. If a reversible assignment is missing or ambiguous, return diagnostics. Exact
  source-surface round trips require `surface` scope, per-surface redaction tokens, or a sidecar occurrence manifest;
  `name` and `canonical` scopes restore the canonical original.

## Recommended Database Format

Use a versioned UTF-8 JSON object stored as a single local file.

Recommended filename examples:

- `nerb-replacements.json`
- `.nerb/replacements.json` when the user explicitly passes that path

Recommended schema version:

```json
"nerb.replacements.v1"
```

### Why JSON

- It matches the JSON-bank ecosystem and can reuse the existing `jsonschema` validation approach.
- It is local, inspectable, diffable, portable across CLI, Python, and MCP clients, and friendly to agent workflows.
- Whole-file atomic writes are straightforward and consistent with current config behavior.
- The first implementation does not need transactional multi-writer semantics beyond an optimistic revision check.

### Rejected Alternatives

- **SQLite**: good for very large stores and concurrent writers, but adds a second persistence model, migration surface,
  and harder manual review. It can be revisited after JSON reaches clear scale limits.
- **JSONL**: append-friendly, but harder to validate as a complete consistent database, harder to rewrite atomically, and
  awkward for assignment updates.
- **YAML**: user-friendly, but the project already treats JSON banks as the machine-oriented agent/service format.
  Strict schemas and deterministic serialization matter more here.
- **Embedding assignments in JSON banks**: conflates entity recognition with per-user sensitive replacement state and
  makes sharing banks unsafe.

## Replacement Database Schema

Create `src/nerb/replacements_schema.py` with a `REPLACEMENT_DB_SCHEMA` and `validate_replacement_db_schema()` following
the style of `src/nerb/schema.py`. Keep the schema JSON-compatible and reject additional properties unless explicitly
reserved.

Generated databases must default to non-reversible redaction mode: `replacement-db init` without an explicit
`--store-originals` or `--reversible` option creates `store_originals: false`, `replacement_mode: "redact"`, empty
replacement sets, and no assignments. The example below shows an opt-in reversible database so the sensitive fields are
visible in the schema discussion.

Top-level shape:

```json
{
  "schema_version": "nerb.replacements.v1",
  "id": "project_alpha_replacements",
  "description": "Local replacements for project alpha agent workflows.",
  "version": 1,
  "created_at": "2026-06-12T00:00:00Z",
  "updated_at": "2026-06-12T00:00:00Z",
  "metadata": {},
  "defaults": {
    "unicode_normalization": "NFC",
    "assignment_scope": "name",
    "replacement_mode": "pseudonym",
    "redaction_template": "[{ENTITY}_{ordinal:04d}]",
    "collision_policy": "error",
    "store_originals": true,
    "allow_new_assignments": true
  },
  "entities": {
    "person": {
      "assignment_scope": "name",
      "replacement_set_id": "person_names",
      "replacement_mode": "pseudonym",
      "redaction_template": "[PERSON_{ordinal:04d}]",
      "store_originals": true
    }
  },
  "replacement_sets": {
    "person_names": {
      "description": "Reserved fake person names.",
      "reuse": false,
      "candidates": [
        {"id": "person_name_0001", "value": "Mikey Law", "metadata": {}},
        {"id": "person_name_0002", "value": "Nina Vale", "metadata": {}}
      ]
    }
  },
  "assignments": {
    "person|name|sha256:6f1b4c4d2a9e": {
      "assignment_key": "person|name|sha256:6f1b4c4d2a9e",
      "entity_id": "person",
      "identity": {
        "scope": "name",
        "name_id": "john_smith",
        "canonical_name": "John Smith",
        "fingerprint": "sha256:..."
      },
      "original": {
        "canonical": "John Smith",
        "surfaces": ["John Smith"]
      },
      "replacement": {
        "mode": "pseudonym",
        "value": "Mikey Law",
        "set_id": "person_names",
        "candidate_id": "person_name_0001"
      },
      "redaction": {
        "token": "[PERSON_0001]",
        "ordinal": 1
      },
      "created_at": "2026-06-12T00:00:00Z",
      "updated_at": "2026-06-12T00:00:00Z",
      "use_count": 1,
      "metadata": {}
    }
  }
}
```

### Required Top-Level Fields

- `schema_version`: must be `nerb.replacements.v1`.
- `id`: NERB ID string using the same ID pattern as JSON banks.
- `description`: human-readable string capped at 2,000 characters.
- `version`: positive integer incremented on every save.
- `created_at` and `updated_at`: timestamp strings. The schema does not need to enforce a timestamp format initially.
- `metadata`: JSON-compatible object with the same size limits as JSON-bank metadata.
- `defaults`: object containing default assignment policy.
- `entities`: object keyed by entity ID. Values override defaults per entity.
- `replacement_sets`: object keyed by replacement set ID.
- `assignments`: object keyed by assignment key.

### Defaults And Entity Policy

Supported fields:

- `unicode_normalization`: `none`, `NFC`, or `NFKC`. Default `NFC`.
- `assignment_scope`: one of `name`, `canonical`, or `surface`.
- `replacement_mode`: `pseudonym` or `redact`.
- `redaction_template`: format string supporting `{entity}`, `{ENTITY}`, and `{ordinal:04d}`.
- `collision_policy`: `error` by default. Future values may include `skip` and `suffix`, but only implement them when
  tests prove the semantics.
- `store_originals`: boolean. When false, new assignments may support stable future pseudonymization but cannot support
  de-anonymization to originals.
- `allow_new_assignments`: boolean. When false, unknown entities produce diagnostics instead of allocating replacements.
- `replacement_set_id`: required for `pseudonym` mode unless every requested identity already has an assignment.

Assignment scope rules:

- `name`: default for JSON banks. The identity uses `entity_id` and `name_id`; aliases for the same canonical name share
  one replacement. This supports `John Smith` always becoming `Mikey Law`, but de-anonymization restores the canonical
  value for that name. It cannot know whether a specific occurrence was `John Smith`, `J. Smith`, or another alias unless
  the operation used `surface` scope or a sidecar occurrence manifest.
- `canonical`: use when `name_id` is unavailable, such as YAML detector configs. The key uses `entity` plus normalized
  `canonical_name`.
- `surface`: use for dynamic classes such as account numbers, ticket IDs, emails, or dates where each distinct matched
  surface should get its own assignment.

### Assignment Keys

Implement one shared helper:

```python
assignment_key(record: Mapping[str, Any], policy: ReplacementPolicy) -> str
```

Rules:

- Normalize strings with the policy's `unicode_normalization`.
- JSON-bank `name` scope: compute lookup material from `entity_id` and `name_id`, but persist an opaque key
  `"{entity_id}|name|sha256:{entity_id_and_name_id_hash}"` unless sensitive output/storage is explicitly enabled.
- `canonical` scope: `"{entity}|canonical|sha256:{normalized_canonical_hash}"`.
- `surface` scope: `"{entity}|surface|sha256:{normalized_surface_hash}"`.
- Reject records that lack required fields for the selected scope.
- Store a `fingerprint` for audit and collision detection, but do not use a hash as the only human-readable assignment
  key when stable IDs are available.
- Treat all fingerprints and hashed assignment keys as sensitive/linkable. Plain SHA-256 is for deterministic lookup and
  collision checks, not a privacy guarantee; default responses and diagnostics must omit fingerprints unless the caller
  requests sensitive details.
- Treat user-authored source IDs such as `name_id`, `pattern_id`, and raw assignment keys as sensitive by default because
  users commonly derive them from original identities. Default responses use opaque per-response `assignment_ref` values,
  while raw IDs require an explicit `include_sensitive_metadata` option.

### Sensitive Data Modes

`store_originals` controls reversibility:

- `true`: assignments store `original.canonical` and bounded `original.surfaces`. De-anonymization can restore originals.
- `false`: assignments store only fingerprints and replacements. Stable replacement still works for future extracted
  originals, but de-anonymization returns an explicit diagnostic because the original is not present.

The database should never store document context by default. `original.surfaces` should be capped, deduplicated, and
only record the matched entity strings needed for reversible restoration and audit.

Conditional validation rules:

- When `store_originals` is false for an assignment, reject `original`, plaintext `identity.canonical_name`, plaintext
  `identity.name_id`, plaintext `pattern_id`, plaintext surface lists, or any assignment key segment that contains raw
  source identity material. This is stricter than normalized-original matching because source IDs can encode originals in
  snake_case, transliteration, or project-specific abbreviations.
- When `store_originals` is true, require `original.canonical` for `name` and `canonical` scopes and require enough
  original data to perform the documented restoration mode.
- For redaction assignments, require `redaction.ordinal` and `redaction.token`; validate that the token matches the
  active entity template for that ordinal.

## New Core Modules

Add these modules:

- `src/nerb/replacements_schema.py`: schema constants and schema-only validation.
- `src/nerb/replacements.py`: load, validate, canonicalize, hash, save, create, patch, and diff replacement databases.
- `src/nerb/deanonymization.py`: anonymize, pseudonymize, redact, de-anonymize, span patching, assignment allocation,
  and response builders.

Export public helpers from `src/nerb/__init__.py` only after the API is stable enough to be documented.

Suggested public helpers:

```python
from nerb import (
    anonymize_text,
    anonymize_file,
    deanonymize_text,
    deanonymize_file,
    create_replacement_db,
    load_replacement_db,
    save_replacement_db,
    validate_replacement_db,
)
```

Keep implementation names precise. Avoid a generic `replace()` helper that could be confused with string replacement.

## Core Algorithms

### Anonymization And Pseudonymization

Input:

- JSON bank or YAML detector config-derived `Bank`
- source text or file path
- replacement database object and optional path
- operation options

Steps:

1. Validate and canonicalize the replacement database.
2. Extract records with the existing NERB scanner.
   - JSON-bank path should use `extract_report()` and apply only `resolved_records`.
   - YAML config support should come after JSON-bank support. The first config-backed implementation should use the
     Rust-resolved scan records exactly as returned by `Bank.scan_text()` instead of duplicating the JSON-bank report
     resolver. If config-backed overlap policies beyond Rust leftmost behavior are required later, define a shared lean
     record resolver with tests before exposing it in CLI or MCP.
3. Convert byte spans to a safe rewrite representation.
   - Preferred implementation: encode the original text as UTF-8 bytes, validate each record span against the bytes, and
     apply replacements on bytes in descending `start` order.
   - If returning string offsets for replacements, compute them from the rewritten UTF-8 text after patching.
4. For each resolved record, compute the assignment key from the entity policy.
5. If an assignment exists, reuse it.
6. If no assignment exists:
   - if `allow_new_assignments` is false, add a diagnostic and leave the span unchanged unless an explicit `on_missing`
     option says to fail the whole operation;
   - if replacement mode is `redact`, allocate the next redaction ordinal and token;
   - if replacement mode is `pseudonym`, allocate the first unused candidate from the configured replacement set;
   - if the set is exhausted, return an error diagnostic unless the caller explicitly enabled a fallback token mode.
7. Validate replacement collisions before writing text.
   - Replacement values and redaction tokens must be unique across reversible assignments unless an explicit alias maps to
     the same original.
   - A replacement value must not map to multiple originals.
   - Empty replacement strings are invalid.
8. Apply replacements in descending source byte order.
9. Return the transformed text, applied replacement records, diagnostics, replacement database metadata, and a flag that
   says whether the database was modified.
10. Persist the updated database only when the caller explicitly requested a write.

### Replacement Allocation

Allocation must be deterministic:

- Preserve replacement set candidate order from the canonical database.
- Track used candidate IDs per replacement set.
- Allocate the first unused candidate when `reuse` is false.
- When `reuse` is true, allocate by stable hash modulo candidate count, then verify that the selected value does not
  create a reverse ambiguity. If it does, advance deterministically through the candidate list.
- Redaction ordinals are per entity by default and stored in assignments. Do not derive ordinal solely from current file
  scan order because that breaks consistency across sessions.

### De-Anonymization

Input:

- transformed text or file path
- replacement database
- options controlling whether to restore pseudonyms, redaction tokens, or both

Steps:

1. Validate and canonicalize the replacement database.
2. Build an in-memory reverse JSON bank from assignments that are reversible:
   - patterns are literal replacement values and/or redaction tokens;
   - generated bank names and canonical values are opaque assignment IDs, never original sensitive strings;
   - the private Python lookup maps `assignment_key` to the original value used at rewrite time;
   - generated metadata must not include originals.
3. Compile the reverse bank through the Rust-backed `Bank` API. Cache by the reverse-bank fingerprint and compile options.
4. Scan transformed text for known replacements. By default, scan redaction tokens only; pseudonym restoration requires an
   explicit `restore_pseudonyms` option because a natural occurrence of the pseudonym cannot be distinguished from a
   replacement without a sidecar occurrence manifest.
5. Resolve overlaps with deterministic priority:
   - longer match wins;
   - redaction token beats pseudonym when both resolve to the same span;
   - lower assignment key wins only as a final deterministic tie-breaker;
   - ambiguous matches that map the same string to different originals are validation errors before scanning.
6. Apply reverse replacements on UTF-8 bytes in descending source byte order.
7. Return restored text, applied restoration records, diagnostics, and database metadata.

Important limitation: pseudonym de-anonymization without a sidecar manifest is exact string replacement. If `Mikey Law`
appears naturally in transformed text, NERB cannot prove provenance from text alone. The plan should document redaction
tokens as the safer reversible workflow and pseudonyms as a usability tradeoff for agent-facing documents.

### Reverse Bank Shape

The reverse bank must be a valid `nerb.bank.v1` object and must pass `validate_bank_schema()` before compiling. Construct
it in a helper so CLI and MCP never assemble this schema themselves.

Shape requirements:

- Top-level fields use all required `nerb.bank.v1` values: `schema_version: "nerb.bank.v1"`, an ID such as
  `reverse_replacements`, `name: "Reverse Replacement Bank"`, a non-sensitive description, a string `version` derived
  from the reverse-bank fingerprint, `status: "active"`, deterministic `created_at` and `updated_at` values for the
  generated object, `unicode_normalization` from the replacement DB policy, `default_regex_flags: []`, `metadata: {}`,
  `eval_refs: []` only when needed, and generated active entities.
- Each generated entity includes required entity fields: `description`, `status: "active"`, `regex_flags: []`,
  `names`, and `metadata: {}`.
- Each generated name includes required name fields: opaque `canonical`, `description`, `status: "active"`, `patterns`,
  and `metadata: {}`.
- Each generated literal pattern includes all literal fields: `kind: "literal"`, non-empty `value`, `description`,
  `status: "active"`, `priority`, `case_sensitive`, `normalize_whitespace`, `left_boundary`, `right_boundary`, and
  `metadata: {}`. Regex-only fields must be absent.
- To preserve prefix overlaps with the production `entity_independent` scanner, generate one synthetic entity per
  reversible assignment and enabled restore mode, for example `r_ab12cd34`. This makes overlaps cross-entity so Python
  can still apply the documented longest-match resolver.
- Derive valid schema IDs from assignment keys by hashing: entity ID `r_<12 hex>`, name ID `a_<12 hex>`, and pattern IDs
  `token` and `pseudonym` when present. Never put raw assignment keys or originals in schema IDs.
- Generated names use opaque canonical strings such as `assignment:<hash>`. The actual original value lives only in the
  private lookup outside the generated bank.
- Literal reverse patterns use exact matching: `case_sensitive: true` and `normalize_whitespace: false`.
- Redaction-token patterns use `left_boundary: "none"` and `right_boundary: "none"` because tokens are structured and
  should be matched exactly wherever the token appears.
- Pseudonym patterns use a default post-scan adjacency guard. When the first or last character of the pseudonym is a word
  character, reject a candidate match whose adjacent source character is also a word character. This prevents restoring
  `Mikey Law` inside `Mikey Lawless`. A future `unsafe_substring_pseudonym_restore` option may bypass this only with a
  warning diagnostic and explicit tests.
- Pattern priority should prefer longer literal values when two generated patterns share an entity in a future
  optimization. The initial one-entity-per-assignment design still stores explicit priorities for auditability.
- Add tests for the full generated skeleton passing `validate_bank_schema()`, `Sam` and `Samwise`, case changes,
  whitespace changes, punctuation, redaction tokens, and substrings such as `Mikey Lawless`.

### Span Rewriting Helper

Add a single helper used by anonymization and de-anonymization:

```python
def apply_byte_replacements(text: str, edits: Sequence[ByteEdit]) -> RewriteResult:
    ...
```

Requirements:

- Validate non-overlapping edits.
- Validate that `text.encode("utf-8")[start:end]` decodes to the record string when an expected original is supplied.
- Sort edits descending by `start`.
- Return rewritten text plus mapping metadata from original spans to replacement spans.
- Include tests for multibyte Unicode before any CLI or MCP surface lands.

## Response Contracts

Add schema names to response payloads so agents can branch safely.

Default CLI/MCP responses must be safe for agent transcripts. They should not include raw assignment keys, JSON-bank
`id`, `name_id`, or `pattern_id`, replacement DB IDs, fingerprints, replacement DB hashes, bank hashes, or original
strings. Use opaque per-response references such as `assignment_ref: "a1"`, `bank_ref: "b1"`, and `replacement_db_ref:
"rdb1"`, and expose sensitive identifiers only when the caller passes an explicit `include_sensitive_metadata` option.
Python helpers may make richer metadata available to direct callers, but the default serialized payload should match the
redacted contract below.

### Anonymize Response

```json
{
  "schema_version": "nerb.anonymize_response.v1",
  "bank": {"bank_ref": "b1", "version": "2026.06.12", "schema_version": "nerb.bank.v1"},
  "replacement_db": {
    "replacement_db_ref": "rdb1",
    "schema_version": "nerb.replacements.v1",
    "version": 2,
    "path": "nerb-replacements.json",
    "modified": true,
    "saved": false
  },
  "source": {"type": "text", "length": 22, "bytes": 22},
  "text": "Mikey Law joined Acme.",
  "applied_replacements": [
    {
      "assignment_ref": "a1",
      "entity": "person",
      "mode": "pseudonym",
      "original_span": {"start": 0, "end": 10, "offset_unit": "byte"},
      "replacement_span": {"start": 0, "end": 9, "offset_unit": "byte"},
      "replacement": "Mikey Law"
    }
  ],
  "summary": {"record_count": 1, "applied_count": 1, "diagnostic_count": 0},
  "diagnostics": []
}
```

Default responses should omit original matched strings and source record IDs from `applied_replacements` because the
transformed output is usually intended to be less sensitive than extraction output. Provide `include_originals` and
`include_sensitive_metadata` options for debugging and tests, and document that enabling either can leak sensitive
values into the response.

### De-Anonymize Response

```json
{
  "schema_version": "nerb.deanonymize_response.v1",
  "replacement_db": {
    "replacement_db_ref": "rdb1",
    "schema_version": "nerb.replacements.v1",
    "version": 2,
    "path": "nerb-replacements.json"
  },
  "source": {"type": "text", "length": 22, "bytes": 22},
  "text": "John Smith joined Acme.",
  "applied_restorations": [
    {
      "assignment_ref": "a1",
      "entity": "person",
      "mode": "pseudonym",
      "replacement_span": {"start": 0, "end": 9, "offset_unit": "byte"},
      "restored_span": {"start": 0, "end": 10, "offset_unit": "byte"},
      "restored_value_source": "canonical"
    }
  ],
  "summary": {"match_count": 1, "applied_count": 1, "diagnostic_count": 0},
  "diagnostics": []
}
```

## Python API Plan

Suggested signatures:

```python
def anonymize_text(
    bank: Mapping[str, Any],
    text: str,
    replacement_db: Mapping[str, Any],
    *,
    options: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    ...


def anonymize_file(
    bank: Mapping[str, Any],
    file_path: str | Path,
    replacement_db: Mapping[str, Any],
    *,
    options: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    ...


def deanonymize_text(
    text: str,
    replacement_db: Mapping[str, Any],
    *,
    options: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    ...


def deanonymize_file(
    file_path: str | Path,
    replacement_db: Mapping[str, Any],
    *,
    options: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    ...
```

Options:

- `mode`: `pseudonym`, `redact`, or `entity_policy`. Default `entity_policy`.
- `include_originals`: boolean, default false.
- `include_sensitive_metadata`: boolean, default false. When false, default responses omit raw assignment keys, source
  record IDs, fingerprints, and hashes.
- `restore_pseudonyms`: boolean for de-anonymization, default false. When false, de-anonymization only restores redaction
  tokens.
- `on_missing_assignment`: `diagnostic`, `fail`, or `skip`. Default `diagnostic`.
- `save`: boolean handled by CLI/MCP wrappers, not by pure text helper unless a path-specific helper is added.
- `include_statuses`, `max_text_bytes`, and batch limits should pass through existing extraction options.
- `source_surface_limit`: maximum number of surfaces to store per assignment, default small and documented.

Add path-based convenience helpers only if they can preserve explicit writes:

```python
def anonymize_text_with_db_path(..., replacement_db_path: str | Path, save: bool = False) -> dict[str, Any]:
    ...
```

Do not hide writes inside the pure object helpers.

## CLI Plan

Add JSON-bank commands first.

Safe default non-reversible redaction workflow:

```shell
nerb replacement-db init --db replacements.json
nerb replacement-db validate --db replacements.json
nerb replacement-db list --db replacements.json
nerb anonymize-text --bank people.json --db replacements.json --text "John Smith joined." --mode redact --save-db
nerb deanonymize-text --db replacements.json --text "[PERSON_0001] joined."
```

The final command should return a `replacement_db.missing_original` diagnostic because the default database does not
store originals.

Opt-in reversible redaction workflow:

```shell
nerb replacement-db init --db replacements.json --reversible
nerb anonymize-text --bank people.json --db replacements.json --text "John Smith joined." --mode redact --save-db
nerb deanonymize-text --db replacements.json --text "[PERSON_0001] joined."
```

Opt-in reversible pseudonym workflow:

```shell
nerb replacement-db init --db replacements.json --reversible
nerb replacement-db add-set --db replacements.json --set person_names --candidate "Mikey Law" --candidate "Nina Vale"
nerb replacement-db set-entity --db replacements.json --entity person --mode pseudonym --set person_names --store-originals
nerb anonymize-text --bank people.json --db replacements.json --text "John Smith joined." --mode pseudonym --save-db
nerb anonymize-file --bank people.json --db replacements.json --file input.txt --output redacted.txt --save-db
nerb deanonymize-text --db replacements.json --text "Mikey Law joined." --restore-pseudonyms
nerb deanonymize-file --db replacements.json --file redacted.txt --output restored.txt --restore-pseudonyms
```

CLI rules:

- Output JSON by default for the new commands. These are agent-facing workflows.
- `replacement-db init` creates a redaction-only, non-reversible database by default. Reversible databases require an
  explicit `--store-originals` or `--reversible` option. Pseudonym mode requires an existing replacement set, created by
  `replacement-db add-set`, `replacement-db import-candidates`, or an explicit `init --candidate-file`.
- `replacement-db set-entity` binds entity policy to a replacement set and mode. It must validate that pseudonym mode has
  a set, that reversible mode has `store_originals: true`, and that redaction mode can operate without a candidate set.
- `replacement-db list` returns a redacted summary by default: an opaque database ref, version, entity policy,
  replacement set counts, assignment counts, and modes. It must not print raw database IDs, originals, surfaces,
  fingerprints, or replacement values unless the caller passes explicit sensitive-output flags such as
  `--include-originals`, `--include-values`, or `--include-sensitive-metadata`.
- Require `--save-db` for mutations to persist. Without it, in-memory text commands return `modified: true, saved:
  false`.
- When `--output` would write transformed text that depends on new unsaved assignments, require `--save-db`; otherwise
  fail before writing the output file. A future `--allow-unsaved-db` escape hatch may be added only with a warning
  diagnostic and tests.
- Require `--output` for writing transformed documents. Without it, print the JSON response containing `text`.
- Never overwrite an output file unless `--force` is passed.
- Error clearly when a replacement set is missing or exhausted.
- Validate the database before and after mutation.
- New database files should be created with owner-only permissions where the platform supports it.
- Do not add hidden defaults based on current working directory. Every database read or write uses the explicit `--db`.
- De-anonymization restores redaction tokens by default. Pseudonym restoration requires `--restore-pseudonyms` and should
  include a warning diagnostic explaining that natural occurrences of the pseudonym may be restored too.

Config-backed commands can be added after JSON-bank commands:

```shell
nerb anonymize-config-text --config detectors.yaml --db replacements.json --text "..."
nerb anonymize-config-file --config detectors.yaml --db replacements.json --file input.txt --output output.txt
```

Keep config-backed naming separate unless the implementation can avoid confusing `--bank` and `--config` options on the
same command.

## MCP Plan

MCP tools should mirror the Python helpers and read only explicit paths or direct objects.

Suggested tools:

- `create_replacement_db(options: Mapping[str, Any] | None = None)`: pure object creation, no filesystem write.
- `save_replacement_db(replacement_db, save_db_path: str, options: Mapping[str, Any] | None = None)`.
- `validate_replacement_db(db: object | None = None, db_path: str | None = None)`.
- `anonymize_text(text, bank=None, bank_path=None, replacement_db=None, replacement_db_path=None, save_db_path=None,
  options=None)`.
- `anonymize_file(file_path, bank=None, bank_path=None, replacement_db=None, replacement_db_path=None, save_db_path=None,
  options=None)`.
- `deanonymize_text(text, replacement_db=None, replacement_db_path=None, options=None)`.
- `deanonymize_file(file_path, replacement_db=None, replacement_db_path=None, options=None)`.

MCP write rules:

- `create_replacement_db` returns an object only. File creation uses `save_replacement_db` with explicit
  `save_db_path`.
- Read source must be exactly one of `replacement_db` or `replacement_db_path`.
- Writes require `options.save` and an explicit `save_db_path`. If the caller read from a path and wants in-place update,
  it must pass the same path as `save_db_path`; the read path is not implicitly a write destination.
- Path writes must save atomically through the shared helper and the per-path lock.
- When saving an object that did not come from `replacement_db_path`, require `options.expected_replacement_db_hash` or a
  missing destination file. This prevents overwriting an existing DB with a stale direct object.
- Tool errors must not echo original sensitive strings unless the caller requested `include_originals`.
- File input follows current MCP limits and explicit path checks.

## Validation And Diagnostics

Use existing diagnostic object style where possible.

Important diagnostics:

- `replacement_db.schema_error`: replacement database failed schema validation.
- `replacement_db.assignment_collision`: one replacement maps to multiple originals.
- `replacement_db.exhausted_set`: no candidate remains for a required pseudonym.
- `replacement_db.missing_original`: assignment cannot be de-anonymized because `store_originals` was false.
- `replacement_db.missing_assignment`: operation encountered an entity while new assignments were disabled.
- `rewrite.invalid_span`: extraction record span does not match the source bytes.
- `rewrite.overlap`: resolved records still overlap and cannot be patched safely.
- `deanonymize.ambiguous_replacement`: reverse bank would map one replacement value to multiple originals.

Default diagnostics should include machine-readable metadata such as opaque `assignment_ref`, entity class, and path when
available. Raw assignment keys, source record IDs, fingerprints, hashes, and original strings require
`include_sensitive_metadata` or `include_originals` as appropriate.

## Performance Plan

Targets:

- Anonymization should add only O(number of resolved records + source bytes) post-processing after extraction.
- Assignment lookup should be dictionary-based by assignment key.
- Reverse de-anonymization should compile a generated JSON bank from replacements and use the Rust-backed scanner.
- Cache generated reverse banks by a `reverse_bank_fingerprint`, engine version, platform dimensions, and compile
  options. The fingerprint should include only reversible assignment keys, replacement values/tokens, restoration values,
  restore-mode options, and literal settings. It should exclude `version`, `updated_at`, `use_count`, metadata, and stored
  surface samples that do not affect reverse matching.
- Do not scan once per assignment.

Default limits:

- Maximum replacement DB file size: 10 MiB.
- Warning threshold: 1,000 assignments or 5 MiB DB file.
- Default supported reverse matcher channel limit: 1,000 generated reverse entities, matching the current Rust engine
  evidence for the production medium-bank target and the one-synthetic-entity-per-assignment-and-mode reverse-bank shape.
  The implementation must compute this as `active reversible assignments * enabled restore modes`.
- Larger databases may still store more assignments, but reverse de-anonymization beyond 1,000 generated reverse entities
  should fail with a diagnostic until a dedicated implementation issue adds and passes 10,000-channel reverse-bank compile,
  scan, and memory gates.
- Maximum replacement candidate value length: 10,000 characters, matching pattern value limits.
- Maximum stored original surfaces per assignment: default 5.

Benchmarks:

- Add tests with a small bank and a synthetic medium replacement database.
- Add a benchmark command or extend existing benchmark helpers only after the core tests land.
- Proposed gates for 1 MB text and 1,000 assignments:
  - anonymization post-processing after extraction is no more than 25 percent of compiled extraction time;
  - cold reverse-bank generation plus compile is under 5 seconds;
  - warm reverse-bank cache lookup is under 0.01 seconds before scanning;
  - warm de-anonymization scan/project is under 0.2 seconds and scans with one generated reverse bank;
  - peak parsed replacement DB memory is recorded and should stay below 4x DB byte size for the synthetic gate.

Memory:

- Bound text inputs with existing extraction limits.
- Bound stored surfaces per assignment.
- Validate maximum replacement value length using the same 10,000-character cap as patterns.
- Emit warning diagnostics at the assignment and DB-size warning thresholds before compiling a large reverse bank.

## Security And Privacy Plan

- The replacement database is sensitive when `store_originals` is true. Documentation and CLI help must say this plainly.
- New database files should use restrictive permissions when possible.
- No telemetry, network calls, or remote URI reads.
- No implicit database path from environment in the first implementation. Explicit paths reduce accidental leakage.
- No original strings in default errors, logs, or agent-facing response metadata.
- `include_originals` must be opt-in and documented as sensitive.
- Fingerprints and hashed assignment keys are sensitive/linkable. They should be excluded from default CLI/MCP responses
  and diagnostics.
- Atomic saves should take an interprocess per-database path lock, such as an advisory lock or lock file next to the DB,
  reload the current hash/version under that lock, apply the mutation, validate the candidate, write a temp file in the
  destination directory, and replace the destination only after validation. A process-local lock is not sufficient because
  separate CLI invocations and MCP servers can write the same path.
- Preserve the prior file if validation of the candidate database fails.
- Use optimistic revision checks inside the lock: if the file hash/version changed since the caller's read, refuse the
  save or retry from the latest file only when the caller explicitly chose that behavior.
- Do not claim that pseudonyms are safe against re-identification. Candidate pools may make text more readable, not more
  private in a formal sense.

## Documentation Plan

Update docs after implementation, not before, except for this plan:

- `README.md`: short example for `replacement-db init`, `anonymize-text`, and `deanonymize-text`.
- `docs/schemas.md`: replacement database schema and response contracts.
- MCP section: tool names and explicit path/write rules.
- Security note: local reversible databases contain sensitive originals.
- Examples: one small people bank and replacement database fixture.

## Test Plan

Unit tests:

- Replacement database schema accepts the minimal valid object and rejects missing required fields.
- Assignment key generation for `name`, `canonical`, and `surface` scopes.
- `store_originals=false` never serializes originals in assignment keys, identity fields, diagnostics, or default
  responses.
- Candidate allocation is deterministic and stable across reloads.
- Replacement set exhaustion produces a diagnostic/error.
- Redaction ordinals are persisted and stable.
- `store_originals=false` supports stable pseudonymization but blocks de-anonymization.
- Byte rewriting handles multibyte UTF-8 before, inside, and after replacements.
- Overlapping records are rejected by the rewrite helper unless resolved first.
- Reverse de-anonymization restores redaction token assignments by default and restores pseudonyms only when
  `restore_pseudonyms` is explicit.
- Name-scope alias tests prove `John Smith`, `J. Smith`, and `Johnny` share one replacement and restore the canonical
  value only; surface-scope tests prove exact surface restoration when configured.
- Generated reverse banks are valid `nerb.bank.v1`, contain no original strings in canonical names, metadata, IDs, default
  records, or diagnostics, and handle `Sam`/`Samwise`, case, whitespace, punctuation, and `Mikey Lawless` substring cases.
- The full reverse-bank skeleton, including required top-level, entity, name, and literal pattern fields, passes
  `validate_bank_schema()`.
- Default applied records and diagnostics expose only opaque `assignment_ref` values; raw assignment keys, source IDs,
  fingerprints, and hashes appear only when `include_sensitive_metadata` is explicit.
- Pseudonym restore does not modify `Mikey Lawless` by default and only permits substring restoration through an explicit
  unsafe option.
- Ambiguous reverse mappings fail validation.
- Default responses do not include original strings in applied replacement records.
- Interprocess per-path locked saves reject or retry stale writers deterministically, including a test with separate
  processes or separate CLI invocations.

Integration tests:

- Python `anonymize_text` round trip with a JSON bank: `John Smith` -> `Mikey Law` -> `John Smith` only when
  `restore_pseudonyms=True`; default de-anonymization does not restore pseudonyms.
- JSON-bank CLI anonymize without `--save-db` returns `modified: true, saved: false` and leaves the DB unchanged.
- JSON-bank CLI file anonymize with `--output` and new assignments fails before writing unless `--save-db` is passed.
- JSON-bank CLI anonymize with `--save-db` persists the assignment atomically.
- `replacement-db list` redacts sensitive fields by default and prints originals/values only behind explicit sensitive
  flags.
- The copyable CLI redaction workflow works without candidate sets, and the reversible pseudonym workflow works only
  after `replacement-db set-entity` binds the replacement set to the entity.
- CLI `deanonymize-text` restores from a saved database.
- Output file commands refuse overwrite without `--force`.
- MCP `anonymize_text` and `deanonymize_text` match Python helper responses for the same bank and DB.
- MCP `create_replacement_db` returns an unsaved object, and `save_replacement_db` writes only to an explicit
  `save_db_path` with stale-hash protection.
- MCP write-safety tests cover direct object read-only behavior, explicit `save_db_path`, atomic path writes, stale hash
  refusal, and sanitized errors without original strings.
- YAML/config-backed path uses canonical or surface assignment keys as documented.

Focused commands:

```shell
uv run pytest tests/nerb/test_replacement_db.py tests/nerb/test_deanonymization.py
uv run pytest tests/nerb/test_cli.py tests/nerb/test_mcp*.py
uv run ruff check .
uv run ty check
```

Before PR merge:

```shell
make check
```

## Implementation Sequence

### 1. Replacement Database Schema And Persistence

Files:

- `src/nerb/replacements_schema.py`
- `src/nerb/replacements.py`
- `tests/nerb/test_replacement_db.py`
- `docs/schemas.md` after implementation

Acceptance:

- Create, validate, canonicalize, hash, load, and atomically save `nerb.replacements.v1`.
- Enforce schema, metadata size, replacement uniqueness, candidate validity, and assignment consistency.
- Enforce privacy-safe keys and conditional `store_originals` rules.
- Tests cover valid minimal DB, invalid DBs, interprocess per-path locked atomic save behavior, stale writer refusal, and
  hash/version changes.

### 2. Shared Rewrite And Assignment Helpers

Files:

- `src/nerb/deanonymization.py`
- `tests/nerb/test_deanonymization.py`

Acceptance:

- Compute assignment keys for JSON-bank and config-backed records.
- Allocate pseudonyms and redaction tokens deterministically.
- Apply byte-span edits safely and return span mapping metadata.
- Tests cover Unicode spans, overlap rejection, allocation reuse, redaction ordinals, and exhaustion.

### 3. JSON-Bank Anonymize API

Files:

- `src/nerb/deanonymization.py`
- `src/nerb/__init__.py`
- `tests/nerb/test_deanonymization.py`

Acceptance:

- `anonymize_text` and `anonymize_file` call existing JSON-bank extraction/report helpers.
- Responses match `nerb.anonymize_response.v1`.
- Default response omits originals.
- Fixture creates stable `John Smith` -> `Mikey Law` assignment while documenting whether restoration is canonical or
  exact surface.

### 4. De-Anonymize API

Files:

- `src/nerb/deanonymization.py`
- `tests/nerb/test_deanonymization.py`

Acceptance:

- Build valid opaque reverse JSON banks from replacement assignments, prove the complete generated skeleton with schema
  validation, and cache them by reverse-bank fingerprint.
- Restore redaction tokens by default and pseudonyms only when explicitly requested, using existing Rust-backed matching.
- Detect ambiguous reverse values before scanning.
- Return `nerb.deanonymize_response.v1`.

### 5. CLI Surface

Files:

- `src/nerb/cli.py`
- `tests/nerb/test_cli.py`
- `README.md` after behavior is final

Acceptance:

- Add `replacement-db` commands and JSON-bank anonymize/deanonymize commands.
- Explicit `--db`, `--save-db`, `--allow-unsaved-db`, `--output`, `--force`, and sensitive list flags are covered.
- `replacement-db set-entity` and candidate import/add-set flows are covered for pseudonym mode.
- CLI JSON output matches Python helper contracts.
- No unexpected writes happen without explicit save/output options.

### 6. MCP Surface

Files:

- `src/nerb/mcp_server.py`
- `tests/nerb/test_mcp*.py`
- README MCP section after behavior is final

Acceptance:

- Add validation and anonymize/deanonymize MCP tools.
- Add `create_replacement_db` and `save_replacement_db` MCP tools with pure-create and explicit-save semantics.
- Tools accept direct objects or explicit paths and follow the write rules.
- MCP results match Python helper results for fixture banks and replacement databases.
- Tests cover `save_db_path`, direct-object read-only behavior, stale-save refusal, and sanitized errors.

### 7. Config-Backed Support And Documentation

Files:

- `src/nerb/deanonymization.py`
- `src/nerb/cli.py`
- `src/nerb/mcp_server.py`
- docs and README

Acceptance:

- Config-backed extraction can anonymize using `canonical` or `surface` assignment scope without duplicating the
  JSON-bank report resolver.
- Documentation explains that JSON banks provide stronger stable identity through `entity_id` and `name_id`.
- Full `make check` passes.

## Open Design Decisions For Implementers

- Whether path-based Python helpers should persist directly or whether persistence remains only in CLI/MCP wrappers.
  The safer default is pure object helpers plus explicit path wrappers.
- Whether the first CLI names should be `anonymize-*` or `replace-*`. This plan recommends `anonymize-*` because the
  user-facing goal is anonymization/de-anonymization, not arbitrary replacement.
- Whether config-backed commands should ship in the first PR or follow JSON-bank support. This plan recommends JSON-bank
  support first because it has stable source IDs and richer records.

## Completion Criteria For The Feature

The feature is complete only when:

- JSON replacement database schema, validation, load/save, and atomic persistence are implemented.
- Python API can pseudonymize, redact, and de-anonymize text and files with deterministic assignments.
- CLI and MCP surfaces expose the same behavior without duplicating core logic.
- Round-trip tests prove `John Smith` can become `Mikey Law` consistently, redaction tokens restore by default, and
  pseudonym restoration is opt-in with canonical-versus-surface semantics documented.
- Unicode span rewriting, overlap behavior, assignment collisions, missing assignments, exhausted candidate pools, and
  `store_originals=false` are covered by tests.
- Generated reverse banks are opaque, valid JSON banks and do not expose originals through default records or diagnostics.
- Docs warn that reversible databases contain sensitive originals.
- `make check` passes.

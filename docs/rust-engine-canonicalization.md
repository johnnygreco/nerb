# Rust Engine Canonicalization

Issue #49 introduced Rust-owned source-bank canonicalization for the engine migration. The current Rust-backed `Bank`
layer parses source bytes, validates the supported source schema, assigns deterministic stable IDs, emits canonical JSON,
computes the bank hash, compiles detector indexes, scans UTF-8 text, and projects public records.

The current Rust entry point is the native module:

```python
from nerb import _engine

bank = _engine.Bank.from_source_bytes(source_bytes, format_hint="yaml")
canonical = bank.to_canonical_json_bytes()
metadata = bank.metadata()
```

Supported `format_hint` values are `yaml`, `json`, `jsonl`, and `canonical_json`. If the hint is omitted, Rust tries JSON,
JSONL, and YAML in that order. The source bytes are parsed by Rust; Python should not pre-canonicalize them.

## Authored Inputs

YAML or JSON detector maps are the compact authored form:

```yaml
ARTIST:
  Pink Floyd: 'Pink\s+Floyd'
GENRE:
  _flags: IGNORECASE
  Jazz: '(?:smooth\s)?jazz'
```

Compact detector-map entity names cannot be `schema` or `schema_version`; those names are reserved for canonical JSON and
current JSON-bank source disambiguation.

JSONL is the structured bulk-review form. Each non-empty line is one detector row:

```jsonl
{"entity":"ARTIST","canonical_name":"Pink Floyd","surface_name":"Pink Floyd","regex":"Pink\\s+Floyd","flags":["IGNORECASE"]}
{"entity":"GENRE","canonical_name":"Jazz","surface_name":"Jazz","regex":"(?:smooth\\s)?jazz"}
```

The existing JSON-bank object shape is accepted as a source input so current authoring helpers can feed the Rust
canonicalizer. Rust maps bank-level, entity-level, and pattern-level flags into canonical per-pattern flags. Literal
patterns are escaped into regex syntax, and `word` boundaries become explicit boundary wrappers. For current JSON-bank
inputs, literal pattern `value` becomes the canonical `surface_name`; regex patterns use the source `pattern_id` as the
surface label until a later projection surface introduces richer regex alias metadata.

## Canonical JSON

Canonical JSON is an engine artifact, not the hand-authored format:

```json
{
  "schema": 1,
  "defaults": {
    "engine": "rust-regex-meta",
    "unicode": true,
    "case_insensitive": false,
    "word_boundaries": false,
    "normalization": "none"
  },
  "entities": [
    {
      "stable_id": "entity:sha256:...",
      "name": "ARTIST",
      "patterns": [
        {
          "stable_id": "pattern:sha256:...",
          "priority": 0,
          "canonical_name": "Pink Floyd",
          "surface_name": "Pink Floyd",
          "regex": "Pink\\s+Floyd",
          "flags": ["IGNORECASE"]
        }
      ]
    }
  ]
}
```

Entity arrays are ordered by entity name. Patterns are ordered by priority, canonical name, surface name, regex, and flags.
Map-style detector sources assign default priorities from source order within each entity, so reordering map entries can
change leftmost-first priority and the bank hash. JSONL rows follow the same source-order default unless a row provides an
explicit `priority`.

Stable IDs are assigned by Rust. `from_canonical_json_bytes` rejects canonical JSON whose stable IDs do not match the
deterministic IDs for the logical detector fields.

## Bank Hash

`metadata()["bank_hash"]` is a `sha256:` hash over the canonical bank plus effective semantic compile options. Compile
options are parsed with the same duplicate-key rejection as source JSON, unknown keys are rejected, and omitted keys are
filled with defaults. The default compile options are:

```json
{"match_mode":"entity_independent"}
```

Supported `match_mode` values are:

- `entity_independent`: production default.
- `all_overlaps`: internal prototype for raw overlap measurement.
- `global_leftmost`: internal benchmark-only throughput baseline that collapses cross-entity overlap.

Changing semantic options changes the hash:

```python
default_bank = _engine.Bank.from_source_bytes(b'{"CODE":{"Alpha":"A"}}', format_hint="json")
overlap_bank = _engine.Bank.from_source_bytes(
    b'{"CODE":{"Alpha":"A"}}',
    format_hint="json",
    compile_options_json='{"match_mode":"all_overlaps"}',
)
assert default_bank.metadata()["bank_hash"] != overlap_bank.metadata()["bank_hash"]
```

## Diagnostics

Rust canonicalization fails clearly on invalid inputs. Example messages include:

```text
bank validation error at /0/unexpected: unknown field "unexpected"
could not parse json source: duplicate key "Alpha" at /CODE
bank validation error at /flags: unsupported regex flag "UNICODE"; supported flags are ASCII, IGNORECASE, MULTILINE, DOTALL, VERBOSE
bank validation error at /regex: unsupported Rust regex syntax for detector "CODE"/"Alpha": ...
bank validation error at /entities/CODE/patterns: duplicate logical detector for entity "CODE", canonical_name "Alpha", surface_name "A"
```

Exact duplicate logical detectors are rejected. Detectors with the same regex remain distinct when their entity,
canonical name, or surface name differs, because attribution is part of the detector identity.

Source parsing rejects duplicate object keys before canonicalization, caps source bytes and JSONL line/row counts before
full canonicalization, and rejects excessive nesting depth.

YAML support currently uses the `serde_yaml` parser, which is deprecated upstream and pulls `unsafe-libyaml`. The parser
is isolated to source-bank canonicalization and remains in scope because YAML authoring is part of the Rust engine plan;
it should be revisited before release hardening or any dependency-deny policy.

## Deferred Fields

The Rust-backed `Bank` API now implements scanner APIs, process-local compiled-bank caching, and public record
projection. It does not preserve the removed Python regex-builder object model.

The canonical JSON contains the engine-ready detector identity and regex fields. JSON-bank status, descriptions, eval
references, metadata, and richer literal authoring settings remain Python control-plane fields unless Rust scanning needs
them for matching or projection.

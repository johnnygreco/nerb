# Rust Engine Canonicalization

Issue #49 introduces Rust-owned source-bank canonicalization for the engine migration. This layer parses source bytes,
validates the supported source schema, assigns deterministic stable IDs, emits canonical JSON, and computes the bank hash.
It does not implement matching yet.

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

JSONL is the structured bulk-review form. Each non-empty line is one detector row:

```jsonl
{"entity":"ARTIST","canonical_name":"Pink Floyd","surface_name":"Pink Floyd","regex":"Pink\\s+Floyd","flags":["IGNORECASE"]}
{"entity":"GENRE","canonical_name":"Jazz","surface_name":"Jazz","regex":"(?:smooth\\s)?jazz"}
```

The existing JSON-bank object shape is accepted as a source input so current authoring helpers can feed the Rust
canonicalizer. Rust maps bank-level, entity-level, and pattern-level flags into canonical per-pattern flags. Literal
patterns are escaped into regex syntax, and `word` boundaries become explicit boundary wrappers.

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
Map-style detector sources assign default priorities after deterministic key ordering; JSONL rows may provide explicit
priorities.

Stable IDs are assigned by Rust. `from_canonical_json_bytes` rejects canonical JSON whose stable IDs do not match the
deterministic IDs for the logical detector fields.

## Bank Hash

`metadata()["bank_hash"]` is a `sha256:` hash over the canonical bank plus semantic compile options. The default compile
options are:

```json
{"match_mode":"entity_independent"}
```

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
bank validation error at /flags: unsupported regex flag "UNICODE"; supported flags are ASCII, IGNORECASE, MULTILINE, DOTALL, VERBOSE
bank validation error at /regex: unsupported Rust regex syntax for detector "CODE"/"Alpha": ...
bank validation error at /entities/CODE/patterns: duplicate logical detector for entity "CODE", canonical_name "Alpha", surface_name "A"
```

Exact duplicate logical detectors are rejected. Detectors with the same regex remain distinct when their entity,
canonical name, or surface name differs, because attribution is part of the detector identity.

## Deferred Fields

This slice intentionally does not implement scanner APIs, compiled engine caches, serialized engine artifacts, or public
record projection. It also does not preserve the current Python regex-builder object model.

The canonical JSON emitted in this slice contains the engine-ready detector identity and regex fields. Existing JSON-bank
status, descriptions, eval references, metadata, and richer literal authoring settings remain Python control-plane fields
until later engine wiring decides which of them must cross the native boundary for scanning or projection.

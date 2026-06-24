# Rust Engine PyO3 Boundary

This document records the native boundary that backs the current Python `Bank` wrapper and the CLI/MCP extraction
surfaces. Historical issues #50, #51, #52, #53, and #54 introduced the boundary, the first Rust scanning path, the
measured `all_overlaps` prototype, the internal `global_leftmost` throughput baseline, and the first public wrapper.

## Native Bank Constructors

```python
from nerb import _engine

bank = _engine.Bank.from_source_bytes(b'{"CODE":{"Alpha":"A"}}', format_hint="json")
canonical = bank.to_canonical_json_bytes()
round_tripped = _engine.Bank.from_canonical_json_bytes(canonical)

assert round_tripped.metadata()["bank_hash"] == bank.metadata()["bank_hash"]
```

`metadata()` exposes only engine and canonical-bank facts needed by Python wrappers:

```json
{
  "engine": "nerb_engine",
  "schema": 1,
  "bank_hash": "sha256:...",
  "entity_count": 1,
  "pattern_count": 1,
  "defaults": {
    "engine": "rust-regex-meta",
    "unicode": true,
    "case_insensitive": false,
    "word_boundaries": false,
    "normalization": "none"
  },
  "compile_options": {
    "match_mode": "entity_independent"
  },
  "match_mode": {
    "name": "entity_independent",
    "status": "production_default",
    "production_default": true,
    "internal_only": false,
    "semantic_notes": "reports cross-entity overlap with leftmost-first matching within each entity"
  },
  "detectors": [
    {
      "detector_index": 0,
      "entity": "CODE",
      "canonical_name": "Alpha",
      "surface_name": "Alpha",
      "stable_id": "pattern:sha256:...",
      "priority": 0
    }
  ]
}
```

## MatchBuffer

`MatchBuffer` is a Rust-owned container for raw scan results:

```rust
pub struct RawMatch {
    pub detector_index: u32,
    pub start_byte: u64,
    pub end_byte: u64,
}
```

Python can create, reserve, clear, and inspect a buffer without constructing public record dictionaries:

```python
buffer = _engine.MatchBuffer(capacity=1024)
assert len(buffer) == 0

raw = _engine.MatchBuffer.from_raw_matches([(7, 10, 15)])
assert raw[0] == (7, 10, 15)
raw.clear()
```

`from_raw_matches` accepts a sized Python sequence and exists to test the boundary. `Bank.scan_bytes` fills
`MatchBuffer` from Rust. Public record projection remains outside the scan loop.

Python-created buffers and Rust scanner appends are capped at 1,000,000 requested raw matches and use fallible Rust
allocation paths. Later dense-hit measurement may revisit this logical limit.

## Scanning

`Bank.scan_bytes` implements the production-default `entity_independent` mode: one `regex-automata` meta matcher per
entity with leftmost-first semantics inside each entity and cross-entity overlap preserved. It validates UTF-8 input,
releases the GIL during the Rust scan, returns raw `(detector_index, start_byte, end_byte)` matches sorted by byte offsets
and detector index, and optionally fills a caller-provided `MatchBuffer`.

Matcher construction applies bounded `regex-automata` NFA, one-pass, hybrid-cache, and DFA limits. Unsupported syntax and
compile-bomb shapes fail during bank construction with `ValueError`.

`IGNORECASE`, `MULTILINE`, `DOTALL`, and `VERBOSE` are applied through per-pattern syntax configuration. The `ASCII` flag
lowers ASCII-sensitive escapes and boundaries such as `\w`, `\d`, `\s`, and `\b` while leaving the rest of the detector
pattern in UTF-8-safe Unicode regex mode.

```python
bank = _engine.Bank.from_source_bytes(b'{"PERSON":{"Sam":"Sam"},"PROJECT":{"Samba":"Samba"}}')
raw = bank.scan_bytes(b"Samba ships")
assert [raw[i] for i in range(len(raw))] == [(0, 0, 3), (1, 0, 5)]
```

## All Overlaps Prototype

`compile_options_json='{"match_mode":"all_overlaps"}'` builds an internal prototype around lower-level
`regex-automata` hybrid DFAs:

- a forward DFA runs overlapping search with `MatchKind::All`;
- a reverse DFA with per-pattern start states recovers the start byte for each reported end;
- local pattern IDs are translated back to global detector indexes before appending to `MatchBuffer`.

The prototype rejects Unicode word-boundary assertions such as `\b` because the lower-level DFA only provides heuristic
Unicode-boundary support that can quit on valid non-ASCII UTF-8. Use explicit ASCII word-boundary syntax such as
`(?-u:\b)` for raw `all_overlaps`, or use the production-default `entity_independent` mode for Unicode boundary
semantics.

Raw `all_overlaps` output is intentionally not the default contract. It preserves cross-entity overlap, but it also
reports within-entity overlapping detectors and every matching span for each detector pattern. It does not preserve a
separate branch identity inside one regex; attribution still stops at the NERB detector index. For example, the
production `entity_independent` mode chooses `Samwise` for `Samwise|Sam` over `Samwise`, while raw `all_overlaps` exposes
both `(0, 0, 3)` and `(0, 0, 7)` for that one detector. That means a span-only candidate post-filter cannot prove exact
leftmost-first reconstruction.

The prototype therefore exposes `Bank.scan_bytes_leftmost_from_all_overlaps` only as a measurement path. It first runs
the raw overlapping scan, then uses the existing entity-independent shards to reconstruct the exact leftmost-first output.
This keeps raw overlap cost and exact reconstruction cost visible without pretending that raw candidates alone preserve
enough ordering information. Reconstruction is exact only when the raw overlapping scan itself fits the `MatchBuffer`
pre-scan capacity cap; extremely dense raw overlap workloads can fail before the reconstruction pass runs.

```python
source = b"""
{"entity":"PERSON","canonical_name":"Sam","surface_name":"Sam","regex":"Sam","priority":0}
{"entity":"PERSON","canonical_name":"Samwise","surface_name":"Samwise","regex":"Samwise","priority":1}
{"entity":"PROJECT","canonical_name":"Samba","surface_name":"Samba","regex":"Samba","priority":0}
"""
default_bank = _engine.Bank.from_source_bytes(source, format_hint="jsonl")
overlap_bank = _engine.Bank.from_source_bytes(
    source,
    format_hint="jsonl",
    compile_options_json='{"match_mode":"all_overlaps"}',
)

raw = overlap_bank.scan_bytes(b"Samba Samwise")
default_raw = default_bank.scan_bytes(b"Samba Samwise")
reconstructed = overlap_bank.scan_bytes_leftmost_from_all_overlaps(b"Samba Samwise")

assert [raw[i] for i in range(len(raw))] == [
    (0, 0, 3),
    (2, 0, 5),
    (0, 6, 9),
    (1, 6, 13),
]
assert [reconstructed[i] for i in range(len(reconstructed))] == [default_raw[i] for i in range(len(default_raw))]
```

## Global Leftmost Internal Baseline

`compile_options_json='{"match_mode":"global_leftmost"}'` builds one combined `regex-automata` meta matcher in
`LeftmostFirst` mode. It is exposed only as an internal throughput baseline. `metadata()["match_mode"]` labels it with:

```json
{
  "name": "global_leftmost",
  "status": "internal_benchmark_only",
  "production_default": false,
  "internal_only": true,
  "semantic_notes": "collapses cross-entity overlap to one leftmost-first winner per region and is not semantically equivalent to the production default"
}
```

The mode intentionally violates NERB's production overlap contract:

```python
source = b"""
{"entity":"PERSON","canonical_name":"Sam","surface_name":"Sam","regex":"Sam","priority":0}
{"entity":"PROJECT","canonical_name":"Samba","surface_name":"Samba","regex":"Samba","priority":0}
"""
default_bank = _engine.Bank.from_source_bytes(source, format_hint="jsonl")
global_bank = _engine.Bank.from_source_bytes(
    source,
    format_hint="jsonl",
    compile_options_json='{"match_mode":"global_leftmost"}',
)

default_raw = default_bank.scan_bytes(b"Samba ships")
global_raw = global_bank.scan_bytes(b"Samba ships")

assert [default_raw[i] for i in range(len(default_raw))] == [(0, 0, 3), (1, 0, 5)]
assert [global_raw[i] for i in range(len(global_raw))] == [(0, 0, 3)]
```

Native `_engine.Bank.scan_path` reads one explicit file path in Rust, validates the bytes through the same UTF-8 scanner,
and returns raw matches in a `MatchBuffer`. It does not allocate Python match records. The public Python
`nerb.Bank.scan_path` wrapper uses the native path scan variant that returns the scanned byte snapshot with the raw
matches, then projects that same snapshot into public records.

## Error Boundary

Native validation and parse failures are translated to `ValueError`. File-read failures are `OSError`. Buffer indexing
failures are `IndexError`, native allocation failures are `MemoryError`, and panic-safe wrappers
translate an unexpected Rust panic into `RuntimeError` instead of unwinding through Python.

## Public Python Bank

`from nerb import Bank` exposes the high-level Rust-backed wrapper. It projects raw native matches into the public record
schema:

```python
from nerb import Bank

bank = Bank.from_source_bytes(b'{"ARTIST":{"Rush":"Rush"}}', format_hint="json")
records = bank.scan_text("Café Rush")
assert records == [
    {
        "entity": "ARTIST",
        "canonical_name": "Rush",
        "surface_name": "Rush",
        "string": "Rush",
        "start": 6,
        "end": 10,
        "offset_unit": "byte",
    }
]
```

Byte offsets are the default for `scan_text`, `scan_bytes`, `scan_path`, CLI extraction, and MCP extraction. Text callers
may explicitly ask for character offsets:

```python
assert bank.scan_text("Café Rush", offsets="char")[0]["offset_unit"] == "char"
```

`Bank.scan_path(path)` reads the exact file bytes and then uses the native UTF-8 scan path. Invalid UTF-8 raises
`ValueError`; callers that need lossy or custom decoding must decode text explicitly and pass it to `scan_text`.

`Bank.from_config(..., word_boundaries=True)` passes the boundary policy to Rust canonicalization. Rust emits canonical
JSON with `defaults.word_boundaries: true`, wraps whole detector regexes once during canonicalization, and includes that
policy in pattern stable IDs and the bank hash.

CLI `nerb extract` and the config-backed MCP extraction tools now use this wrapper. Their records no longer include the
old Python `name` field; use `canonical_name` and `surface_name` instead.

```shell
uv run nerb extract --all --text "Rush played rock." \
  --detector "ARTIST:Rush=Rush" \
  --detector "GENRE:Rock=rock" \
  --format json
```

```json
[
  {"entity": "ARTIST", "canonical_name": "Rush", "surface_name": "Rush", "string": "Rush", "start": 0, "end": 4, "offset_unit": "byte"},
  {"entity": "GENRE", "canonical_name": "Rock", "surface_name": "Rock", "string": "rock", "start": 12, "end": 16, "offset_unit": "byte"}
]
```

## Compiled Bank Cache And Batch Extraction

The public Python wrapper caches compiled native `Bank` objects in process. The cache key is semantic rather than
path-based:

```python
from nerb import Bank, bank_cache_info, clear_bank_cache

clear_bank_cache()
first = Bank.from_config({"ARTIST": {"Rush": "Rush"}})
second = Bank.from_config({"ARTIST": {"Rush": "Rush"}})

assert first.cache_metadata()["hit"] is False
assert second.cache_metadata()["hit"] is True
print(second.cache_metadata()["key"])
print(bank_cache_info())
```

Example key shape:

```json
{
  "bank_hash": "sha256:...",
  "schema_version": 1,
  "semantic_version": "0.0.9",
  "engine_name": "nerb_engine",
  "engine_version": "0.0.9",
  "canonical_engine": "rust-regex-meta",
  "compile_options": {"match_mode": "entity_independent"},
  "target_triple": "x86_64-linux-gnu",
  "platform": "linux-x86_64",
  "pointer_width": 64,
  "endian": "little"
}
```

`use_cache=False` bypasses lookup and insertion for callers that need isolated compilation. `clear_bank_cache()` clears
only this process. The process-local cache uses bounded LRU eviction and reports `max_entries` plus `max_source_keys` in
`bank_cache_info()`. The cache does not serialize matcher state, write engine artifacts, or add a disk cache.

The config-backed MCP extraction tools return the same per-extraction cache metadata and expose `engine_cache_info` plus
`clear_engine_cache` for process-local diagnostics.

Batch CLI extraction compiles once and scans many explicit documents:

```shell
uv run nerb extract-batch doc-a.txt doc-b.txt --entity ARTIST --config detectors.yaml --format json
uv run nerb extract-batch --manifest docs.txt --all --config detectors.yaml --format jsonl
uv run nerb extract-batch --stdin --entity ARTIST --config detectors.yaml --format table
```

The JSON output includes top-level `cache` metadata and document payloads in input order. Manifest files are UTF-8 text
files with one explicit path per nonblank line; relative paths resolve against the manifest file's parent directory.
Recursive walking, gitignore discovery, Rayon batch parallelism, and serialized DFA or engine-payload caches are not part
of the current process-local cache.

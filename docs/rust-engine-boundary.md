# Rust Engine PyO3 Boundary

Issues #50, #51, and #52 expose the native boundary, the first Rust scanning path, and the measured `all_overlaps`
prototype. The native module is still `nerb._engine`; the public Python wrapper in `nerb.engine.Bank` is deferred.

## Bank Constructors

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
is rejected in this slice because lowering it correctly for a UTF-8 text scanner requires a narrower rewrite than
byte-mode `(?-u:...)`; that migration remains explicit future work.

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

`Bank.scan_path` remains a boundary stub in this slice. It raises `NotImplementedError` and does not allocate Python
match records. `global_leftmost` remains a future mode and raises a validation error if scanned.

## Error Boundary

Native validation and parse failures are translated to `ValueError`. Buffer indexing failures are `IndexError`, scan
future scan stubs are `NotImplementedError`, native allocation failures are `MemoryError`, and panic-safe wrappers
translate an unexpected Rust panic into `RuntimeError` instead of unwinding through Python.

# Rust Engine PyO3 Boundary

Issues #50 and #51 expose the native boundary and first Rust scanning path. The native module is still `nerb._engine`;
the public Python wrapper in `nerb.engine.Bank` is deferred.

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

`Bank.scan_bytes` implements the initial `entity_independent` mode: one `regex-automata` meta matcher per entity with
leftmost-first semantics inside each entity and cross-entity overlap preserved. It validates UTF-8 input, releases the
GIL during the Rust scan, returns raw `(detector_index, start_byte, end_byte)` matches sorted by byte offsets and detector
index, and optionally fills a caller-provided `MatchBuffer`.

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

`Bank.scan_path` remains a boundary stub in this slice. It raises `NotImplementedError` and does not allocate Python
match records. All-overlaps and global-leftmost modes remain future work.

## Error Boundary

Native validation and parse failures are translated to `ValueError`. Buffer indexing failures are `IndexError`, scan
future scan stubs are `NotImplementedError`, native allocation failures are `MemoryError`, and panic-safe wrappers
translate an unexpected Rust panic into `RuntimeError` instead of unwinding through Python.

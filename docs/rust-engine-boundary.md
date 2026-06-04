# Rust Engine PyO3 Boundary

Issue #50 exposes the non-scanning native boundary that later matching slices will use. The native module is still
`nerb._engine`; the public Python wrapper in `nerb.engine.Bank` is deferred.

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
  }
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

`from_raw_matches` exists to test the boundary before scans land. The scanner slice will fill `MatchBuffer` from Rust.
Public record projection remains outside the scan loop.

## Scan Stubs

`Bank.scan_bytes` and `Bank.scan_path` are exported only as boundary stubs in this slice. They raise
`NotImplementedError` and do not allocate Python match records. Issue #51 will attach `regex-automata` matching to these
methods and use PyO3's GIL-detach path around the Rust scan.

## Error Boundary

Native validation and parse failures are translated to `ValueError`. Buffer indexing failures are `IndexError`, scan
stubs are `NotImplementedError`, and panic-safe wrappers translate an unexpected Rust panic into `RuntimeError` instead
of unwinding through Python.

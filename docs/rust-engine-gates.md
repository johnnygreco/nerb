# Rust Engine Gate Evidence

Recorded on 2026-06-05 from branch `goal/rust-engine-slice-10-conformance-benchmark-gates`, then updated by
slice 11 after the Rust-backed `Bank` surface became the extraction path.

## Gate Command

The reproducible local report command is:

```shell
uv run python scripts/rust_engine_gate_report.py --iterations 5 --target-bytes 100000 --dense-bytes 512
```

The report emits JSON with conformance, performance, dense-memory, mode-strategy, and distribution sections. The report
only includes sections it measures directly in `overall.passed`: performance, dense memory, and mode strategy.
Conformance and distribution are marked `external_required` and must be proven by the PR validation commands.

Routine local target documents are 100 KB and exercise small-bank, literal-heavy, regex-heavy, dense-overlap, memory,
cache, projection, and output behavior.

Larger 1 MB evidence was recorded with:

```shell
timeout 180s uv run python scripts/rust_engine_gate_report.py --iterations 1 --target-bytes 1000000 --dense-bytes 512
```

The single-iteration 1 MB report passed under the cap. A five-iteration 1 MB report is not a routine local gate.

## Conformance

Required command:

```shell
uv run pytest tests/nerb/test_rust_engine_conformance.py tests/nerb/test_rust_engine_boundary.py
```

The report records this command as `external_required`; the PR validation log is the authority for pass/fail status.

The accepted conformance decisions remain in `docs/decisions/0001-rust-engine-semantics.md`:

- `entity_independent` is the production default.
- `global_leftmost` is an internal throughput baseline because it drops cross-entity overlap.
- raw `all_overlaps` is a measured prototype because dense outputs amplify heavily and raw candidates alone do not prove
  leftmost-first reconstruction.
- ASCII flag lowering rewrites ASCII-sensitive escapes and boundaries while keeping the rest of each pattern in
  UTF-8-safe Unicode regex mode.
- Detector names with underscores are preserved by the Rust record contract.

## Performance

Pass criteria for each workload:

- Native raw-match projection and public `Bank` records match exactly.
- Repeated scan/project counts are stable.
- Public `Bank` cache misses cold and hits warm for the same source/options.
- Rust `entity_independent` raw-scan and scan/project timings stay under checked-in ceilings, and Rust scan/project
  throughput stays above checked-in floors:
  - small-bank floor: `entity_independent` scan/project <= 0.01s, raw scan <= 0.005s, scan/project >= 1 MB/s;
  - literal-heavy and regex-heavy: `entity_independent` scan/project <= 0.05s, raw scan <= 0.02s,
    scan/project >= 5 MB/s.

Stage coverage:

- `source_parse_jsonl`: Python-side source parse timing for the JSONL source used by the workload.
- `rust_entity_independent_compile`: native compile, inclusive of source parsing, canonicalization, schema validation,
  runtime validation, and matcher construction.
- `rust_native_scan_project`: native raw scan plus explicit record projection.
- `rust_public_bank_cache_lookup`: one cold compile/cache miss followed by warm cache lookups.
- `rust_entity_independent_scan_raw`, `rust_all_overlaps_scan_raw`, and `rust_global_leftmost_scan_raw`: raw native
  scan timings for the three mode strategies.
- `rust_entity_independent_scan_project`: Rust raw scan plus public wrapper record projection.
- `json_output`: JSON serialization of already projected Rust records.

Routine report, 5 iterations. `--target-bytes` applies to the literal-heavy and regex-heavy workloads; the small-bank
floor is intentionally fixed at 10 KB.

The report emits one object per workload with `native_public_records_equal`, `measurements`, `criteria`, and
`rust_scan_project_bytes_per_second`. The JSON report is the authority for exact timings.

Larger 1 MB report, 1 iteration:

The 1 MB report uses the same fields as the routine report.

The literal-heavy and regex-heavy gates pass independently. Both preserve the planned records, have stable counts, and
stay inside the Rust timing and throughput thresholds. The small-bank floor also remains inside the checked-in floor.

## Dense Memory And Mode Strategy

Dense probe: two entities, 32 prefix detectors each, 512 bytes of `A`.

| Measurement | Count |
| --- | ---: |
| `entity_independent` | 32 |
| `all_overlaps` raw | 31,776 |
| `all_overlaps` reconstructed | 32 |
| `global_leftmost` | 16 |

`all_overlaps` raw output amplified the production count by 993x. The exact reconstruction path returned the same raw
tuples as production `entity_independent`. `global_leftmost` returned half the production count because it collapses
valid cross-entity overlap.

The dense memory probe runs in an isolated child process before the parent performs mode scans. It gates on stable raw
match count, raw count below the `MatchBuffer` pre-scan capacity cap of 1,000,000, `MatchBuffer` capacity below that same
cap, max-RSS growth under a 64 MiB budget, and absolute child max-RSS under a 256 MiB budget. The routine report measured
31,776 raw matches, `MatchBuffer` capacity 32,768, absolute child max-RSS 58,508 KiB, and max-RSS growth 0 KiB. The
capacity value is the direct materialized-output allocation evidence; the RSS fields bound the isolated child process.

Synthetic entity-cardinality sweep: 8 dense prefix detectors per entity over 256 bytes.

| Entities | Patterns | `entity_independent` | `all_overlaps` raw | `global_leftmost` | Raw/Entity Ratio |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 2 | 16 | 64 | 4,040 | 32 | 63.125x |
| 8 | 64 | 256 | 16,160 | 32 | 63.125x |
| 32 | 256 | 1,024 | 64,640 | 32 | 63.125x |

The sweep also gates order-tens performance in two ways:

- Dense 256-byte semantic probe: the 32-entity `entity_independent` raw scan must remain under 0.01s and the 32-to-2
  entity scan-time ratio must remain under 40x. The routine report measured 0.000248s for the 32-entity scan and a
  16.533x 32-to-2 ratio.
- Routine-size sparse no-match probe: 2-entity and 32-entity banks scan the configured target bytes, avoiding
  `all_overlaps` output amplification while bounding `entity_independent` entity/document scaling. The 32-entity
  `entity_independent` scan must remain under 0.05s and the 32-to-2 `entity_independent` ratio under 40x. The routine
  100 KB report measured 0.000115s for the 32-entity scan and a 10.455x ratio. The 1 MB evidence measured 0.001338s and
  a 12.164x ratio.

Mode decision: keep `entity_independent` as the production default for the current Rust engine path and the synthetic
order-tens entity-cardinality evidence above. `all_overlaps` remains a measured prototype and `global_leftmost` remains
an internal benchmark baseline.

The real bank-owner entity-cardinality target is still not recorded in this repository. It must be captured before final
engine cleanup; if expected entity classes exceed the order-tens range validated here, open a new issue before changing
the default mode strategy.

## Distribution

Required command:

```shell
make build
```

The report records package validation as `external_required`; the PR validation log is the authority for pass/fail
status.

Supported releases publish a source distribution plus CPython 3.10 through 3.14 wheels for Linux x86_64
`manylinux_2_28`, macOS universal2 (x86_64 and arm64), and Windows x86_64. Other platforms use the source
distribution and require a Rust toolchain. Local `make build` still builds and verifies the source distribution plus
the local platform wheel; GitHub Actions is the authority for the full supported wheel matrix and no-Rust wheel install
smoke tests, including both macOS slices for the universal2 artifact.

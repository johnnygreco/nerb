# Rust Engine Gate Evidence

Recorded on 2026-06-05 from the Rust engine migration branches, then updated by the final gate follow-up after the
Rust-backed `Bank` surface, wheel matrix, and record contract follow-ups merged.

## Gate Command

The reproducible local report command is:

```shell
uv run python scripts/rust_engine_gate_report.py --iterations 5 --target-bytes 100000 --dense-bytes 512
```

The report emits JSON with conformance, performance, dense-memory, mode-strategy, distribution, and bank-owner
cardinality sections. The report only includes sections it measures directly in `overall.passed`: performance, dense
memory, and mode strategy. Conformance and distribution are marked `external_required` and must be proven by the PR
validation commands. Bank-owner cardinality is marked `external_required` unless the bank-owner entity-count flags are
provided.

Routine local target documents are 100 KB and exercise small-bank, literal-heavy, regex-heavy, mixed-bank,
corpus-size, dense-overlap, memory, cache, projection, and output behavior.

Larger 1 MB evidence was recorded with:

```shell
timeout 180s uv run python scripts/rust_engine_gate_report.py --iterations 1 --target-bytes 1000000 --dense-bytes 512
```

The single-iteration 1 MB report passed under the cap. A five-iteration 1 MB report is not a routine local gate.

For #73, the bank-owner target is a representative synthetic medium bank with 1,000 top-level entities. Record that
target with:

```shell
uv run python scripts/rust_engine_gate_report.py --iterations 5 --target-bytes 100000 --dense-bytes 512 \
  --bank-owner-entity-count 1000 \
  --bank-owner-growth-entity-count 1000 \
  --bank-owner-note "user-directed representative synthetic medium bank target on 2026-06-05"
```

The bank-owner section passes only when both counts are recorded and both are within the validated 1,000-entity
synthetic medium-bank range. Counts above that range require a new mode-strategy issue before changing the production
default.

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
  - literal-heavy, regex-heavy, and mixed: `entity_independent` scan/project <= 0.05s, raw scan <= 0.02s,
    scan/project >= 5 MB/s.
  - corpus-size mixed-bank scaling: scan/project >= 5 MB/s for the 10 KB floor and configured target bytes.

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

Routine report, 5 iterations. `--target-bytes` applies to the literal-heavy, regex-heavy, mixed, and configured-size
mixed corpus-size workloads; the small-bank floor and the corpus-size floor are intentionally fixed at 10 KB.

The report emits one object per workload with `native_public_records_equal`, `measurements`, `criteria`, and
`rust_scan_project_bytes_per_second`. The JSON report is the authority for exact timings.

Larger 1 MB report, 1 iteration:

The 1 MB report uses the same fields as the routine report.

The literal-heavy, regex-heavy, and mixed gates pass independently. All preserve the planned records, have stable counts,
and stay inside the Rust timing and throughput thresholds. The small-bank floor also remains inside the checked-in floor.

Routine 100 KB report, 5 iterations, final gate update:

| Workload | Text bytes | Records | Scan/project median | Scan/project throughput |
| --- | ---: | ---: | ---: | ---: |
| small-bank floor | 10,000 | 870 | 0.000643s | 15.6 MB/s |
| literal-heavy | 100,000 | 96 | 0.000648s | 154.3 MB/s |
| regex-heavy | 100,000 | 75 | 0.000211s | 473.9 MB/s |
| mixed | 100,000 | 181 | 0.000660s | 151.5 MB/s |

The mixed-bank corpus-size section measured the same mixed workload at 10 KB and 100 KB. Both cases passed the stable
count and 5 MB/s throughput floor. The 1 MB evidence command measured the mixed corpus case at 1,000,000 bytes,
0.002440s scan/project median, 1,805 records, and 409.8 MB/s scan/project throughput.

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
31,776 raw matches, `MatchBuffer` capacity 32,768, absolute child max-RSS 57,432 KiB, and max-RSS growth 0 KiB. The
capacity value is the direct materialized-output allocation evidence; the RSS fields bound the isolated child process.

Synthetic entity-cardinality sweep: 8 dense prefix detectors per entity over 256 bytes. The dense all-overlaps stress
ceiling is 64 entities; the separate production-default medium-bank case validates the target 1,000-entity bank without
materializing amplified raw `all_overlaps` output.

| Entities | Patterns | `entity_independent` | `all_overlaps` raw | `global_leftmost` | Raw/Entity Ratio |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 2 | 16 | 64 | 4,040 | 32 | 63.125x |
| 8 | 64 | 256 | 16,160 | 32 | 63.125x |
| 32 | 256 | 1,024 | 64,640 | 32 | 63.125x |
| 64 | 512 | 2,048 | 129,280 | 32 | 63.125x |

The sweep also gates production-default cardinality performance in three ways:

- Dense 256-byte semantic probe: the max-entity `entity_independent` raw scan must remain under 0.01s and the
  max-to-2 entity scan-time ratio must remain under 80x. The routine report measured 0.000316s for the 64-entity scan
  and a 35.111x max-to-2 ratio.
- Routine-size sparse no-match probe: 2-entity and 64-entity banks scan the configured target bytes, avoiding
  `all_overlaps` output amplification while bounding `entity_independent` entity/document scaling. The 64-entity
  `entity_independent` scan must remain under 0.05s and the max-to-2 `entity_independent` ratio under 80x. The routine
  100 KB report measured 0.000218s for the 64-entity scan and a 21.8x ratio. The 1 MB evidence measured a
  13.981x routine max-to-2 ratio.
- Medium-bank sparse no-match probe: 1,000 entities with 8 generated patterns per entity scan the configured target
  bytes using the production default and public projection path. The routine 100 KB report measured 1,000 entities,
  8,000 patterns, 1,000,000 source bytes, 0.638117s native compile median, 0.003395s raw scan median, 0.008648s
  scan/project median, and 11.6 MB/s scan/project throughput. The 1,000-to-64 raw scan ratio was 15.573x, below the
  40x ceiling. The 1 MB evidence measured 0.794416s native compile median, 0.033708s raw scan median, 0.043460s
  scan/project median, 23.0 MB/s scan/project throughput, and a 15.357x 1,000-to-64 raw scan ratio.

Mode decision: keep `entity_independent` as the production default for the current Rust engine path and the synthetic
medium-bank entity-cardinality evidence above. `all_overlaps` remains a measured prototype and `global_leftmost` remains
an internal benchmark baseline.

Issue #73 records the bank-owner target as a representative synthetic medium bank with 1,000 top-level entities. If
expected entity classes exceed the 1,000-entity range validated here, open a new mode-strategy issue before changing the
default mode strategy.

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

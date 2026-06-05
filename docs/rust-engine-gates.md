# Rust Engine Gate Evidence

Recorded on 2026-06-05 from branch `goal/rust-engine-slice-10-conformance-benchmark-gates`.

## Gate Command

The reproducible local report command is:

```shell
uv run python scripts/rust_engine_gate_report.py --iterations 5 --target-bytes 100000 --dense-bytes 512
```

The report emits JSON with conformance, performance, dense-memory, mode-strategy, and distribution sections. The report
only includes sections it measures directly in `overall.passed`: performance, dense memory, and mode strategy.
Conformance and distribution are marked `external_required` and must be proven by the PR validation commands.

Routine local target documents are 100 KB so Python-oracle comparison remains practical while still exercising
small-bank, literal-heavy, regex-heavy, dense-overlap, memory, cache, projection, and output behavior.

Larger 1 MB evidence was recorded with:

```shell
timeout 180s uv run python scripts/rust_engine_gate_report.py --iterations 1 --target-bytes 1000000 --dense-bytes 512
```

The single-iteration 1 MB comparison passed under the cap. A five-iteration 1 MB comparison is not a routine gate because
the Python oracle takes about 65 seconds for the literal-heavy scan/project stage alone.

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
- ASCII flag lowering remains explicitly rejected until UTF-8-safe lowering lands.
- Python oracle underscore-name loss is a named oracle divergence, not Rust target behavior.

## Performance

Pass criteria for each workload:

- Python oracle projection and Rust projection match exactly.
- Repeated scan/project counts are stable.
- Public `Bank` cache misses cold and hits warm for the same source/options.
- Rust `entity_independent` scan/project median is less than or equal to the Python oracle scan/project median,
  including the small-bank floor.

Stage coverage:

- `source_parse_jsonl`: Python-side source parse timing for the JSONL source used by the workload.
- `python_re_compile` and `python_re_scan_project`: current Python oracle compile and extraction projection.
- `rust_entity_independent_compile`: native compile, inclusive of source parsing, canonicalization, schema validation,
  runtime validation, and matcher construction.
- `rust_public_bank_cache_lookup`: one cold compile/cache miss followed by warm cache lookups.
- `rust_entity_independent_scan_raw`, `rust_all_overlaps_scan_raw`, and `rust_global_leftmost_scan_raw`: raw native
  scan timings for the three mode strategies.
- `rust_entity_independent_scan_project`: Rust raw scan plus Python record projection and sorting.
- `json_output`: JSON serialization of already projected Rust records.

Routine 100 KB report, 5 iterations:

| Workload | Patterns | Records Equal | Python Scan/Project | Rust Scan/Project | Rust Raw Scan | Warm Cache | JSON Output |
| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: |
| Small-bank floor | 4 | true | 0.001909s | 0.001232s | 0.000153s | 0.000016s | 0.001072s |
| Literal-heavy | 1,000 | true | 6.538850s | 0.000611s | 0.000043s | 0.000103s | 0.000069s |
| Regex-heavy | 200 | true | 0.578122s | 0.000247s | 0.000070s | 0.000032s | 0.000074s |

Larger 1 MB report, 1 iteration:

| Workload | Records Equal | Python Scan/Project | Rust Scan/Project | Rust Raw Scan |
| --- | --- | ---: | ---: | ---: |
| Small-bank floor | true | 0.002039s | 0.000789s | 0.000115s |
| Literal-heavy | true | 65.470126s | 0.003218s | 0.001152s |
| Regex-heavy | true | 5.760181s | 0.002827s | 0.001804s |

The literal-heavy and regex-heavy gates pass independently. Both preserve the planned records, have stable counts, and
keep Rust `entity_independent` scan/project below the Python oracle on the measured workloads. The small-bank floor also
remains below Python oracle time.

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
match count, raw count below the `MatchBuffer` pre-scan capacity cap of 1,000,000, and max-RSS delta under a 64 MiB
budget. The routine report measured 31,776 raw matches and a 0 KiB max-RSS delta.

Synthetic entity-cardinality sweep: 8 dense prefix detectors per entity over 256 bytes.

| Entities | Patterns | `entity_independent` | `all_overlaps` raw | `global_leftmost` | Raw/Entity Ratio |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 2 | 16 | 64 | 4,040 | 32 | 63.125x |
| 8 | 64 | 256 | 16,160 | 32 | 63.125x |
| 32 | 256 | 1,024 | 64,640 | 32 | 63.125x |

Mode decision: keep `entity_independent` as the production default for the current Rust engine path and the synthetic
order-tens entity-cardinality evidence above. `all_overlaps` remains a measured prototype and `global_leftmost` remains
an internal benchmark baseline.

The real bank-owner entity-cardinality target is still not recorded in this repository. It must be captured before final
Python removal; if expected entity classes exceed the order-tens range validated here, open a new issue before changing
the default mode strategy.

## Distribution

Required command:

```shell
make build
```

The report records package validation as `external_required`; the PR validation log is the authority for pass/fail
status.

Current supported distribution is the source distribution/source-build path with a Rust toolchain. Local `make build`
also produces a platform wheel as a smoke artifact and runs `twine check --strict dist/*`, but this repository does not
yet claim a supported PyPI wheel matrix. `docs/releasing.md` tracks the manylinux/macOS/Windows wheel matrix as future
distribution work.

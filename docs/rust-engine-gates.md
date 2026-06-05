# Rust Engine Gate Evidence

Recorded on 2026-06-05 from branch `goal/rust-engine-slice-10-conformance-benchmark-gates`.

## Gate Command

The reproducible local report command is:

```shell
uv run python scripts/rust_engine_gate_report.py --iterations 5 --target-bytes 100000 --dense-bytes 512
```

The report emits JSON with conformance, performance, mode-strategy, dense-memory, and distribution sections. The routine
local target uses 100 KB documents so that Python-oracle comparison remains practical while still exercising small-bank,
literal-heavy, regex-heavy, and dense-overlap behavior.

Larger 1 MB evidence was recorded with:

```shell
timeout 180s uv run python scripts/rust_engine_gate_report.py --iterations 1 --target-bytes 1000000 --dense-bytes 512
```

The single-iteration 1 MB comparison passed under the cap. A five-iteration 1 MB comparison is not a routine gate because
the Python oracle took about 65 seconds for the literal-heavy scan/project stage alone.

## Conformance

Command:

```shell
uv run pytest tests/nerb/test_rust_engine_conformance.py tests/nerb/test_rust_engine_boundary.py
```

Status: passed as part of the full `uv run pytest` run.

The accepted conformance decisions remain in `docs/decisions/0001-rust-engine-semantics.md`:

- `entity_independent` is the production default.
- `global_leftmost` is an internal throughput baseline because it drops cross-entity overlap.
- raw `all_overlaps` is a measured prototype because dense outputs amplify heavily and raw candidates alone do not prove
  leftmost-first reconstruction.
- ASCII flag lowering remains explicitly rejected until UTF-8-safe lowering lands.
- Python oracle underscore-name loss is a named oracle divergence, not Rust target behavior.

## Performance

Routine 100 KB report, 5 iterations:

| Workload | Patterns | Records Equal | Python Scan/Project Median | Rust Scan/Project Median | Rust Raw Scan Median |
| --- | ---: | --- | ---: | ---: | ---: |
| Small-bank floor | 4 | true | 0.001925s | 0.000599s | 0.000105s |
| Literal-heavy | 1,000 | true | 6.518116s | 0.000612s | 0.000043s |
| Regex-heavy | 200 | true | 0.580329s | 0.000227s | 0.000063s |

Larger 1 MB report, 1 iteration:

| Workload | Records Equal | Python Scan/Project | Rust Scan/Project |
| --- | --- | ---: | ---: |
| Small-bank floor | true | 0.002090s | 0.000689s |
| Literal-heavy | true | 65.435123s | 0.003334s |
| Regex-heavy | true | 5.823658s | 0.002504s |

The literal-heavy and regex-heavy gates pass independently: both preserve the planned records and both show Rust
`entity_independent` scan/project substantially below the Python oracle on the measured workloads. The small-bank floor
also remains below Python oracle time.

## Dense Memory And Mode Strategy

Dense probe: two entities, 32 prefix detectors each, 512 bytes of `A`.

| Measurement | Count |
| --- | ---: |
| `entity_independent` | 32 |
| `all_overlaps` raw | 31,776 |
| `global_leftmost` | 16 |

`all_overlaps` raw output amplified the production count by 993x. `global_leftmost` returned half the production count
because it collapses valid cross-entity overlap. The dense raw count remained under the `MatchBuffer` pre-scan capacity
cap of 1,000,000, and the local report observed no max-RSS increase during the probe.

Mode decision: keep `entity_independent` as the production default. `all_overlaps` remains a measured prototype and
`global_leftmost` remains an internal benchmark baseline.

## Distribution

Command:

```shell
make build
```

Status: passed locally. The build produced the source distribution and the local CPython 3.14 Linux wheel, then
`twine check --strict dist/*` passed. GitHub CI also validates package build on PRs.

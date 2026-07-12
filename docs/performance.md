# Performance And Scale Evidence

This page summarizes the current Rust-backed performance posture, the decision-grade Enron development result, and the
reproducible gate commands.

Rust engine conformance, benchmark, dense-memory, mode-strategy, and distribution gate evidence is recorded in
[`rust-engine-gates.md`](rust-engine-gates.md). The semantic contract is recorded in
[`decisions/0001-rust-engine-semantics.md`](decisions/0001-rust-engine-semantics.md).

## Current Posture

- Public extraction compiles JSON banks through the Rust-backed `Bank` API and scans with the production
  `entity_independent` mode.
- Literal and regex patterns are canonicalized into Rust detector metadata, scanned natively, then projected into stable
  byte-offset records.
- Compiled native banks are cached in process by canonical bank hash, engine name/version, compile options, platform
  dimensions, and target triple.
- Extraction still performs schema/canonicalization and extraction-scope authoring diagnostics before native cache
  lookup. NERB does not maintain a disk cache or caller-supplied cache key.
- `all_overlaps` and `global_leftmost` are internal measurement modes only; they are not public JSON-bank extraction
  semantics.

## Enron Intelligence-Cache Workflow

The Enron workflow freezes a private workload before it measures anything. It accepts verified train/validation
development and bank-build runs; there is deliberately no preparation-source or sealed-test input. Source profiling is
restricted to the verified development-train artifact used by the builder. Use ignored directories
for both outputs because the prepared run contains the evaluated bank, selected validation documents, generated scale
fixtures, inventories, and private source locations.

```shell
uv run nerb prepare-enron-performance \
  --bank-build-run .nerb/enron/bank-build \
  --development-run .nerb/enron/development \
  --output-dir .nerb/enron/performance-plan

# Five samples per cell: useful for correctness and workflow smoke only.
uv run nerb run-enron-performance \
  --prepared-run .nerb/enron/performance-plan \
  --output-dir .nerb/enron/performance-smoke \
  --profile smoke

# Long-running evidence: ten paired blocks with phase-specific frozen sample counts.
uv run nerb run-enron-performance \
  --prepared-run .nerb/enron/performance-plan \
  --output-dir .nerb/enron/performance-decision \
  --profile decision

uv run nerb verify-enron-performance \
  --run-dir .nerb/enron/performance-decision
```

The decision plan keeps these paths separate:

| Measurement | What it answers |
| --- | --- |
| Direct compiled-`Bank` reuse | Cost after constructing one native bank and scanning repeatedly through that same object. This is the primary cache-value path. |
| Helper cache hit/miss | Cost of the higher-level compile/extract helper with its process-local canonical-bank cache either warm or cold. |
| Uncached/end to end | Cost when validation, compilation, input handling, or application work is included as declared by the frozen harness. |
| Exact same-path stability control | An exact twin with the same operation, bank, input, process model, warmups, work, and sample policy. Candidate/twin pairs use ten frozen blocks with a hash-derived balanced mix of ABBA and BAAB order. Reused paths receive fresh candidate and control worker sessions in every block. Runner source and tests enforce balanced construction order; verifier-observable evidence binds chronology, per-block PID reuse or freshness, and disjoint twin PIDs rather than unrecorded creation events. One symmetric metric per true decision cell—and a median metric for the support proxy—checks measured stability, not prior-code regression or statistical equivalence. |
| Cross-path cache-value comparison | A separate 100-sample `real_direct_cache_value` support cell, helper-cache hit/miss, and end-to-end paths scan the same whole-input population in ten four-path Williams-balanced blocks. The support cell has `decision_grade: false` and cannot be a headline, absolute gate, or break-even input. Canonical aggregate digests prove identical mapped outputs before the separate directional comparisons. |
| Generic regex and Python literal scans | Exploratory, explicitly non-equivalent baselines. They cannot support a semantic regression claim or the promoted break-even comparison. |

Scale banks contain 1k, 10k, 25k, and 100k **active matcher patterns**. Alias and canonical-name counts remain separate
composition metrics; a matcher-pattern count must never be reported as an alias count. The 100k controlled fixture has
two semantic taxonomy classes backed by 318 native matcher shards (159 per class, at most 502 patterns per shard). A
non-promotable five-native-shard feasibility probe exceeded 5 GiB and did not complete, so the 100k result must not be
presented as small-shard-topology evidence. One-time source profiling, source building, and cold compilation use 20
fresh-process samples in ten two-sample blocks; their one same-path stability metric is median time. Helper-cache
hit/miss and end-to-end cells use 100 samples in ten ten-sample blocks and also compare median time. The matrix has 19
true decision cells; every true direct whole-input and document-latency cell uses 1,000 pooled samples in ten 100-sample
blocks and compares p99. The additional direct-cache-value support proxy uses 100 samples and median stability. Every
document block is one complete balanced pass over the exact 100-document population, so document composition cannot be
confounded with worker-session effects. The five-sample smoke profile is
non-promotable and intentionally limited to evaluated-bank compile/cache/direct/end-to-end paths plus 1k serial and
bounded-concurrency cells and the two exploratory baselines. It does not rebuild/profile the source or load the 100k
bank.

For a same-path metric with candidate value `C` and exact-twin value `B`, the symmetric gap is
`max(C, B) / min(C, B) - 1`, equivalently bounded by `abs(log(C / B)) <= log(1.05)`. A gap at or below 5% is
`within_tolerance`. For a larger gap, the diagnostic enumerates all `2^10` whole-block label swaps and recomputes the
pooled metric for each assignment. A diagnostic p-value at or below 0.05 yields `unstable`; a larger value yields
`inconclusive`. Both outcomes fail promotion. `within_tolerance` means only that this measurement met the frozen
engineering tolerance; it is not a confidence interval or an equivalence claim. Cross-path comparisons remain
directional and do not reuse these symmetric outcome semantics. Absolute latency, throughput, and RSS gates are always
evaluated independently of the exact twin. Only directional cross-path comparisons use paired-block timing-ratio MAD;
their noise floor has an unconditional 25% ceiling, and exceeding it fails promotion regardless of whether the measured
direction would otherwise be improved or within its directional boundary.

Preparation and execution commit private transactional runs. The path-free plan and aggregate report contain hashes,
counts, timing/resource samples, environment metadata, and privacy-safe inventories—not message text, detected surfaces,
scan records, or local paths. Verification rechecks those bindings without returning or publishing protected text, and
every stage records `sealed_test_accessed: false`. Whole-input `records_per_second` uses the worker's stable observed aggregate
count; this prevents non-equivalent regex/literal baselines from borrowing NERB's record denominator.

The break-even model records source curation, train-source profiling, and bank building as the same shared acquisition
cost on both paths, so those terms cancel. Direct reuse then adds one cold compile and its cost per frozen whole-input
request; the helper-cache-miss alternative pays its measured cost for that same request. The unit is one complete scan
of the exact 100-document, 35,837-byte input, not an individual document or an arbitrary batch size. A median of
heterogeneous per-document timings is never compared with a whole-input average. `--source-curation-seconds` is a
shared declared scenario—not a measured model invocation, token, hosted-service, or dollar cost—and cannot manufacture
the crossing.

## Decision-Grade Development Result

Here, *decision-grade* means the workload and thresholds were frozen before measurement; exact paths prove the same
mapped outputs; repeated isolated blocks quantify tails, session variation, and memory; software, hardware, and artifact
lineage are recorded; and the aggregate result passes privacy and integrity verification. That is sufficient to choose
the compile-once/scan-many runtime path. It is not a recall claim or final publication approval: quality, full-source
capacity, and the one-shot sealed evaluation retain their own gates.

The recorded decision profile passed the frozen exact-block plan on Apple M4 arm64 hardware with 10 logical CPUs,
16 GiB RAM, macOS, and Python 3.13.12. The run used package and native engine 0.0.11 at clean commit
`7dd1128d3b2f7ade7caf86b7fc5d9cb633e05f0b`, passed its aggregate privacy scan with zero violations, and recorded
`sealed_test_accessed: false`. Its frozen plan is
`sha256:5ac7496f85867ef71ed91305db2c87ca38a9092abef5c58a331fefa07f165650`, its performance manifest is
`sha256:b5dfb33fb2ab351a9fb95d4f14a6bf1224b3aee1715e9a344880d4b7c2c290f0`, and the deep-verified run is
`sha256:99ed7abddd34c9edf4c3dc2f43868885c5af768fae7eb9e3b57e973fb075f53c`.

This is development evidence over the frozen 50,000-row train/validation build, not the final public full-source claim.
The mandatory full 517,401-row streaming/resource proof and one-shot sealed evaluation remain separate gates. The real
performance input contains 100 validation documents, 35,837 UTF-8 bytes, and 1,314 expected mapped records. The evaluated
bank has two semantic classes, 628 active patterns, 127 aliases, 8,783,376 canonical JSON bytes, 1,266,398 native-source
bytes, and a 13,293,272-byte private bank artifact.

### Frozen promotion gates

| Gate | Frozen threshold | Measured result | Status |
| --- | ---: | ---: | --- |
| Real document p99 | at most 50 ms | 0.259 ms | passed |
| Real whole-input documents/s | at least 100 | 128,994 | passed |
| Real whole-input MiB/s | at least 1 | 44.09 | passed |
| 100k-pattern MiB/s | at least 1 | 99.69 | passed |
| Peak RSS | at most 8 GiB | 555.6 MiB maximum measured cell | passed |
| Exact-twin symmetric gap | at most 5% | 2.14% maximum across 20 comparisons | passed |
| Cross-path paired-ratio MAD noise floor | at most 25% | 5.32% maximum across 12 comparisons | passed |

### Lifecycle and cache value

Setup stability uses the median of 20 fresh-process samples, slow cache-path stability uses the median of 100 samples,
and direct/document p99 stability uses 1,000 pooled samples. The separate direct comparison-support proxy uses 100
samples and median stability. All candidate/exact-twin pairs are acquired in ten frozen paired blocks.

| Path | Median | Tail | Throughput | Peak RSS |
| --- | ---: | ---: | ---: | ---: |
| Train-source profile | 2.680 s | p95 2.692 s | one-time setup | 38.5 MiB |
| Intelligence-bank build, including private snapshot setup | 45.382 s | p95 45.798 s | one-time setup | 555.6 MiB |
| Cold compile | 3.188 s | p95 3.246 s | one-time setup | 130.8 MiB |
| Direct compiled `Bank`, one document | 0.0062 ms | p99 0.259 ms | document sample | 122.3 MiB |
| Direct compiled `Bank`, 100 documents | 0.775 ms | p99 0.831 ms | 128,994 docs/s; 44.09 MiB/s; 1.69M records/s | 122.3 MiB |
| Helper cache hit | 3.117 s | p99 3.198 s | 32.1 docs/s; 0.0110 MiB/s | 155.7 MiB |
| Helper cache miss | 3.241 s | p99 3.313 s | 30.9 docs/s; 0.0105 MiB/s | 123.5 MiB |
| End to end | 3.293 s | p99 3.346 s | 30.4 docs/s; 0.0104 MiB/s | 143.4 MiB |

The promoted break-even model's measured per-request inputs differ by about 4,181×: 0.000775 seconds for direct reuse
versus 3.241025 seconds for the exact helper-cache-miss path. This ratio is a model-input summary, not the paired
directional estimator or a generic speed promise. Helper paths include JSON-bank validation, canonicalization, hashing,
and adapter work that a caller avoids by retaining the compiled `Bank`. After shared profiling, curation, and bank-build
costs cancel, the direct path pays 3.188219 seconds to compile plus its 0.000775-second first frozen whole-input request.
It is already ahead by about 52.0 ms at the model's minimum of one complete 100-document request; the result must not be
translated into a per-document crossing.

The exploratory generic email regex reached 78.05 MiB/s and happened to emit the same aggregate record count, but it
cannot map a mention to a known canonical identity or implement the full bank semantics. The Python literal baseline
reached 2.72 MiB/s and emitted only 631 records, so neither is a semantically exact correctness baseline. All 20
same-path comparisons—including every true decision cell and the support proxy—were `within_tolerance`. Of the 12
cross-path outcomes, nine were `improved` and three were `equivalent_within_noise`; none regressed or exceeded the
unconditional noise ceiling.

### Matcher scale

Each scale row scans the same deterministic 100-document, 1,024,000-byte negative workload. Composition preserves the
evaluated bank's contact/person and alias proportions while reporting active patterns separately from aliases. Every
contact shard includes a nonempty residual regex, so these are mixed literal/regex banks rather than literal-only
exact-match fixtures.

| Active patterns | Native shards | Aliases | Canonical JSON | Native source | Median / 100 docs | p99 | MiB/s | Peak RSS |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1,000 | 4 | 202 | 226,280 B | 138,016 B | 0.172 ms | 0.187 ms | 5,669.45 | 40.9 MiB |
| 10,000 | 32 | 2,022 | 2,261,206 B | 1,380,158 B | 1.021 ms | 1.059 ms | 956.63 | 80.2 MiB |
| 25,000 | 80 | 5,056 | 5,652,792 B | 3,450,400 B | 2.492 ms | 2.567 ms | 391.95 | 143.8 MiB |
| 100,000 | 318 | 20,223 | 22,610,648 B | 13,801,592 B | 9.796 ms | 10.148 ms | 99.69 | 485.9 MiB |

Four-thread scanning of the tiny 1k negative cell was slower than single-thread scanning because coordination and Python
projection overhead dominate sub-millisecond work. Concurrency is deterministic and bounded, but this cell does not
support a parallel-speedup claim. NERB does not expose an exact compiled-object-size API, so the report uses physical
artifact bytes, canonical/native source bytes, and process peak RSS as distinct size proxies.

## Reproducible Gate

Routine local gate:

```shell
uv run python scripts/rust_engine_gate_report.py --iterations 5 --target-bytes 100000 --dense-bytes 512 \
  --bank-owner-entity-count 1000 \
  --bank-owner-growth-entity-count 1000 \
  --bank-owner-note "representative synthetic medium bank target"
```

Larger 1 MB evidence, used as recorded release-gate evidence rather than a routine local check:

```shell
timeout 180s uv run python scripts/rust_engine_gate_report.py --iterations 1 --target-bytes 1000000 --dense-bytes 512 \
  --bank-owner-entity-count 1000 \
  --bank-owner-growth-entity-count 1000 \
  --bank-owner-note "representative synthetic medium bank target"
```

The report emits JSON with conformance, performance, dense-memory, mode-strategy, distribution, and bank-owner
cardinality sections. The measured sections in `overall.passed` are performance, dense memory, and mode strategy.
Conformance and distribution are external-required sections proven by PR validation commands and wheel smoke tests.

## Smoke Profiles

`benchmark_fixture_profiles()` and `make_benchmark_fixture_profile(profile_id)` provide deterministic structural smoke
profiles for benchmark output shape:

| Profile | Workload | Purpose |
| --- | --- | --- |
| `small` | tiny mixed bank | Cheapest structural signal for benchmark output shape. |
| `literal_heavy` | alias-heavy literal bank | Models curated exact-name banks and entity shard fan-out. |
| `regex_heavy` | regex-dominant bank | Keeps regex validation and shard scan costs visible. |
| `mixed` | balanced literal/regex bank | Exercises both matcher families in one fixture. |
| `adversarial_smoke` | dense-hit and near-miss text | Exercises overlap, alternation, dense records, and near misses safely. |

Run one smoke profile:

```shell
uv run python - <<'PY'
import json
from nerb import benchmark_bank, make_benchmark_fixture_profile

fixture = make_benchmark_fixture_profile("adversarial_smoke")
result = benchmark_bank(fixture["bank"], documents=fixture["documents"], options=fixture["options"])
summary = {
    "profile": fixture["id"],
    "gate": fixture["gate"],
    "sections": sorted(result),
    "compile_cache": result["stages"]["compile_cache"],
    "record_count_stable": {name: tier["record_count_stable"] for name, tier in result["tiers"].items()},
}
print(json.dumps(summary, indent=2, sort_keys=True))
PY
```

## Resource Limits

| Limit | Current Status |
| --- | --- |
| ID length 80 | Enforced by `ID_PATTERN` in schema validation. |
| Description 2,000 characters | Enforced by JSON Schema `maxLength`. |
| Pattern value 10,000 characters | Enforced by JSON Schema `maxLength`. |
| `eval_refs` warning above 1,000 refs | Enforced as `eval_refs.large` warning in schema validation. |
| Metadata warning above 16 KiB | Enforced as `metadata.large` warning in schema validation. |
| Metadata error above 1 MiB | Enforced as `metadata.too_large` error in schema validation. |
| Single extraction text 10 MiB | Enforced by default extraction options. |
| Batch 100 documents / 25 MiB combined text | Enforced by default extraction options. |
| Eval JSONL 100 MiB | Enforced by default eval options. |
| Runtime regex probes standard 5 / deep 25 | Enforced by runtime validation probe limits. |

Extraction and eval byte limits remain explicit options for callers. There is no disk cache in the current engine path.

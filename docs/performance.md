# Performance And Scale Evidence

This page summarizes the current Rust-backed performance posture, the decision-grade Enron benchmark standard, and the
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
The required owner-only scratch root keeps the preparation-time bank replay inside caller-accounted storage.

```shell
install -d -m 700 .nerb/enron-scratch
uv run nerb prepare-enron-performance \
  --bank-build-run .nerb/enron/bank-build \
  --development-run .nerb/enron/development \
  --output-dir .nerb/enron/performance-plan \
  --scratch-root .nerb/enron-scratch

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

### Frozen production result

The frozen decision-profile run passed all 19 decision cells and its aggregate privacy scan on an Apple M4 with 10 CPU
cores and 16 GiB memory. The evaluated bank had 13,201 active patterns. Its 100-document direct throughput cell measured
0.699 ms median (143,057 documents/s); direct per-document latency measured 9.021 µs median and 55.250 µs p95. Cold
compilation measured 7.792 s median, full train-source bank construction measured 334.988 s median, and the controlled
100,000-pattern cell measured 6,811 documents/s. The separate full-source capacity evidence also passed.

These are runtime results, not a release endorsement. The independently annotated quality audit failed recall and
leakage gates, so the evaluated bank is do-not-ship for privacy redaction. See the
[aggregate evidence and decision](enron-evidence.md).

## Decision-Grade Performance Benchmark Standard

A *decision-grade performance benchmark* is evidence strong enough to support a specific runtime-architecture decision,
not merely a timing that looks favorable. Here, the decision is whether compile-once/scan-many can meet the frozen
latency, throughput, memory, and stability requirements on the frozen benchmark bank and workload. It is not a claim
that the sampled workload is a production request trace.

The result is decision-grade only when the decision question, workload identities, sample counts, comparison design,
and pass/fail thresholds are frozen before measurement. Every exact path must prove identical mapped output, so speed is
not purchased by silently doing less work. Repeated isolated blocks must measure tails, process/session variation,
ordering effects, and peak RSS. The run must bind the selected bank, evaluator, validation aggregate, source split,
implementation, software, hardware, and environment with verified hashes.

The full production-capacity workflow must also pass its separate progress, scratch-space, free-space, and resource
gates. Public evidence must be aggregate-only, pass privacy scanning, record `sealed_test_accessed: false`, and report
every required cell—including failures and inconclusive stability outcomes—without post-hoc workload or threshold
changes.

That standard can justify a runtime architecture choice. It cannot establish PII recall, low leakage, or release
readiness: quality evaluation, full-source capacity, and the one-shot sealed evaluation remain independent gates. The
final evidence contract uses `decision_grade` for the broader *release decision*, which passes only when those independent
quality, privacy, capacity, lineage, and performance requirements all pass. Smoke runs are useful for correctness and
harness checks, but their small sample counts are not decision-grade performance evidence.

The repository publishes the frozen aggregate performance and capacity result with a clean-clone verifier. Any bank,
evaluator, workload, implementation, or threshold change creates a different candidate and requires new preregistered
evidence; the sealed panel reported here must not be reused for tuning or rescoring.

### Frozen promotion gates

| Gate | Frozen threshold | Evidence required |
| --- | ---: | --- |
| Real document p99 | at most 50 ms | Fresh decision-profile run |
| Real whole-input documents/s | at least 100 | Fresh decision-profile run |
| Real whole-input MiB/s | at least 1 | Fresh decision-profile run |
| 100k-pattern MiB/s | at least 1 | Fresh decision-profile run |
| Peak RSS | at most 8 GiB | Maximum over every required cell |
| Exact-twin symmetric gap | at most 5% | Every required same-path comparison |
| Cross-path paired-ratio MAD noise floor | at most 25% | Every required directional comparison |

### Frozen measurement design

Setup stability uses the median of 20 fresh-process samples, slow cache-path stability uses the median of 100 samples,
and direct/document p99 stability uses 1,000 pooled samples. The separate direct comparison-support proxy uses 100
samples and median stability. All candidate/exact-twin pairs are acquired in ten frozen paired blocks.

The measured lifecycle must include source profiling, bank construction, cold compilation, direct compiled-bank reuse,
helper-cache hit and miss paths, and end-to-end extraction. The break-even model may compare only the same complete
whole-input request. Generic regex and Python literal baselines remain exploratory because they do not implement exact
bank semantics or canonical identity mapping.

### Matcher scale

Each scale row scans the same deterministic 100-document, 1,024,000-byte negative workload. Composition preserves the
evaluated bank's contact/person and alias proportions while reporting active patterns separately from aliases. Every
contact shard includes a nonempty residual regex, so these are mixed literal/regex banks rather than literal-only
exact-match fixtures.

Fresh evidence must report the active-pattern count, native shard count, alias count, canonical and native-source bytes,
latency, throughput, and peak RSS for every scale row. NERB does not expose an exact compiled-object-size API, so the
report keeps physical artifact bytes, canonical/native source bytes, and process peak RSS as distinct size proxies.

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
| Single inline or path scan 10 MiB | Enforced by the native boundary before mapped-haystack allocation; extraction options may set a lower limit. |
| Concurrent scans per compiled bank 8 | Enforced by the native per-bank scan limiter and used for regex-cache accounting. |
| Batch 100 documents / 25 MiB combined text | Enforced by default extraction options. |
| Eval JSONL 100 MiB | Enforced by default eval options. |
| Runtime regex probes standard 5 / deep 25 | Enforced by runtime validation probe limits. |

Extraction and eval byte limits remain explicit options for callers. There is no disk cache in the current engine path.

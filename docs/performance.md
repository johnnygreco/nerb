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

# Long-running evidence: 20 setup samples, 100 whole-input scans, and 500 paired document timings.
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
| Exact same-path stability control | An ABBA-interleaved duplicate with the same operation, bank, input, process model, warmups, work, and sample policy. It estimates run noise and order effects; because both sides use the current implementation, it is not a prior-code regression baseline. |
| Cross-path cache-value comparison | Direct reuse, helper-cache hit/miss, and end-to-end paths scan the same whole-input population in a four-path Williams-balanced schedule nested inside ABBA. Canonical aggregate digests prove identical mapped outputs before paired-block latency and throughput comparisons. |
| Generic regex and Python literal scans | Exploratory, explicitly non-equivalent baselines. They cannot support a semantic regression claim or the promoted break-even comparison. |

Scale banks contain 1k, 10k, 25k, and 100k **active matcher patterns**. Alias and canonical-name counts remain separate
composition metrics; a matcher-pattern count must never be reported as an alias count. The 100k controlled fixture has
two semantic taxonomy classes backed by 318 native matcher shards (159 per class, at most 502 patterns per shard). A
non-promotable five-native-shard feasibility probe exceeded 5 GiB and did not complete, so the 100k result must not be
presented as small-shard-topology evidence. One-time source profiling, source
building, and cold compilation use 20 fresh-process samples and nearest-rank p95. Whole-input decision cells use 100
samples and p99. Document latency uses 500 paired timings—five balanced passes over exactly 100 documents—so paired
relative MAD measures timing variation instead of document-size heterogeneity. The five-sample smoke profile is
non-promotable and intentionally limited to evaluated-bank compile/cache/direct/end-to-end paths plus 1k serial and
bounded-concurrency cells and the two exploratory baselines. It does not rebuild/profile the source or load the 100k
bank.

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

Here, *decision-grade* means the workload and thresholds were frozen before measurement; equivalent paths prove the same
mapped outputs; repeated isolated samples quantify tails, dispersion, noise, and memory; software, hardware, and artifact
lineage are recorded; and the aggregate result passes privacy and integrity verification. That is sufficient to choose
the compile-once/scan-many runtime path. It is not a recall claim or final publication approval: quality, full-source
capacity, and the one-shot sealed evaluation retain their own gates.

The complete decision profile passed on Apple M4 arm64 hardware with 10 logical CPUs, 16 GiB RAM, macOS, and Python
3.13.12. The run used package and native engine 0.0.11 at clean commit
`270c5e1fddcd9afecf1c15df118e172325c540a6`, passed its aggregate privacy scan with zero violations, and recorded
`sealed_test_accessed: false`. Its frozen plan is
`sha256:f28c6a1d24515ad942f8601f59de01f94fe06b1ce17638e9a7f2b7ceb3ee0693`, its performance manifest is
`sha256:f19018f5a897d1b7ef285e9874bc35964f0ad190ad1ca39708183585f685b778`, and the deep-verified run is
`sha256:9819206cba50b81850f99a08e2237b3b9458af44a7b440f18209f52a01703593`.

This is development evidence over the frozen 50,000-row train/validation build, not the final public full-source claim.
The mandatory full 517,401-row streaming/resource proof and one-shot sealed evaluation remain separate gates. The real
performance input contains 100 validation documents, 35,837 UTF-8 bytes, and 1,314 expected mapped records. The evaluated
bank has two semantic classes, 628 active patterns, 127 aliases, 8,783,376 canonical JSON bytes, 1,266,398 native-source
bytes, and a 13,293,272-byte private bank artifact.

### Frozen promotion gates

| Gate | Frozen threshold | Measured result | Status |
| --- | ---: | ---: | --- |
| Real document p99 | at most 50 ms | 0.140 ms | passed |
| Real whole-input documents/s | at least 100 | 116,130 | passed |
| Real whole-input MiB/s | at least 1 | 39.69 | passed |
| 100k-pattern MiB/s | at least 1 | 99.54 | passed |
| Peak RSS | at most 8 GiB | 485.9 MiB maximum measured cell | passed |
| Exact-control noise floor | at most 25% | 12.61% maximum | passed |

### Lifecycle and cache value

Setup phases use 20 fresh-process samples and report p95; scan-bearing phases use 100 whole-input samples and p99. The
document-latency cell uses 500 balanced samples.

| Path | Median | Tail | Throughput | Peak RSS |
| --- | ---: | ---: | ---: | ---: |
| Train-source profile | 2.676 s | p95 2.684 s | one-time setup | 38.6 MiB |
| Intelligence-bank build, including private snapshot setup | 45.211 s | p95 45.526 s | one-time setup | 438.2 MiB |
| Cold compile | 3.177 s | p95 3.207 s | one-time setup | 130.6 MiB |
| Direct compiled `Bank`, one document | 0.0043 ms | p99 0.140 ms | document sample | 121.0 MiB |
| Direct compiled `Bank`, 100 documents | 0.861 ms | p99 0.929 ms | 116,130 docs/s; 39.69 MiB/s; 1.53M records/s | 121.8 MiB |
| Helper cache hit | 3.103 s | p99 3.164 s | 32.2 docs/s; 0.0110 MiB/s | 155.0 MiB |
| Helper cache miss | 3.235 s | p99 3.297 s | 30.9 docs/s; 0.0106 MiB/s | 123.5 MiB |
| End to end | 3.282 s | p99 3.361 s | 30.5 docs/s; 0.0104 MiB/s | 143.4 MiB |

Direct reuse is about 3,757× faster than the exact helper-cache-miss path on median whole-input time. That comparison is
not a generic promise: helper paths include JSON-bank validation, canonicalization, hashing, and adapter work that a
caller avoids by retaining the compiled `Bank`. After shared profiling, curation, and bank-build costs cancel, the
direct path pays 3.177056 seconds to compile plus 0.000861 seconds for its first frozen whole-input request, versus
3.234750 seconds for one helper-cache-miss request. It is therefore already ahead by about 56.8 ms at the model's
minimum of one complete 100-document request; the result must not be translated into a per-document crossing.

The exploratory generic email regex reached 77.74 MiB/s and happened to emit the same aggregate record count, but it
cannot map a mention to a known canonical identity or implement the full bank semantics. The Python literal baseline
reached 2.73 MiB/s and emitted only 631 records, so neither is an equivalent correctness baseline. All 34 same-path
comparisons were equivalent within measured noise. Of 12 cross-path cache-value comparisons, nine improved and three
were equivalent within noise.

### Matcher scale

Each scale row scans the same deterministic 100-document, 1,024,000-byte negative workload. Composition preserves the
evaluated bank's contact/person and alias proportions while reporting active patterns separately from aliases. Every
contact shard includes a nonempty residual regex, so these are mixed literal/regex banks rather than literal-only
exact-match fixtures.

| Active patterns | Native shards | Aliases | Canonical JSON | Native source | Median / 100 docs | p99 | MiB/s | Peak RSS |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1,000 | 4 | 202 | 226,280 B | 138,016 B | 0.172 ms | 0.178 ms | 5,688.70 | 40.8 MiB |
| 10,000 | 32 | 2,022 | 2,261,206 B | 1,380,158 B | 1.015 ms | 1.048 ms | 962.11 | 80.0 MiB |
| 25,000 | 80 | 5,056 | 5,652,792 B | 3,450,400 B | 2.486 ms | 2.518 ms | 392.80 | 143.7 MiB |
| 100,000 | 318 | 20,223 | 22,610,648 B | 13,801,592 B | 9.811 ms | 9.956 ms | 99.54 | 485.9 MiB |

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

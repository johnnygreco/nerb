# Performance And Scale Evidence

This page summarizes the current Rust-backed performance posture and the reproducible gate commands. Detailed historical
engine notes were condensed after the Rust-backed `Bank` path became the production extraction engine.

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

## Enron v2 Cache-Value Workflow

The Enron v2 workflow freezes a private workload before it measures anything. It accepts verified train/validation
development and bank-build runs; there is deliberately no preparation-source or sealed-test input. Source profiling is
restricted to the verified development-train artifact used by the builder. Use ignored directories
for both outputs because the prepared run contains the evaluated bank, selected validation documents, generated scale
fixtures, inventories, and private source locations.

```shell
uv run nerb prepare-enron-performance \
  --bank-build-run .nerb/enron-v2/bank-build \
  --development-run .nerb/enron-v2/development \
  --output-dir .nerb/enron-v2/performance-plan

# Five samples per cell: useful for correctness and workflow smoke only.
uv run nerb run-enron-performance \
  --prepared-run .nerb/enron-v2/performance-plan \
  --output-dir .nerb/enron-v2/performance-smoke \
  --profile smoke

# Long-running evidence: 20 setup samples, 100 whole-input scans, and 500 paired document timings.
uv run nerb run-enron-performance \
  --prepared-run .nerb/enron-v2/performance-plan \
  --output-dir .nerb/enron-v2/performance-decision \
  --profile decision

uv run nerb verify-enron-performance \
  --run-dir .nerb/enron-v2/performance-decision
```

The decision plan keeps these paths separate:

| Measurement | What it answers |
| --- | --- |
| Direct compiled-`Bank` reuse | Cost after constructing one native bank and scanning repeatedly through that same object. This is the primary cache-value path. |
| Helper cache hit/miss | Cost of the higher-level compile/extract helper with its process-local canonical-bank cache either warm or cold. |
| Uncached/end to end | Cost when validation, compilation, input handling, or application work is included as declared by the frozen harness. |
| Exact same-path stability control | An ABBA-interleaved duplicate with the same operation, bank, input, process model, warmups, work, and sample policy. It estimates run noise and order effects; because both sides use the current implementation, it is not a historical regression baseline. |
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
scan records, or local paths. Verification rechecks those bindings without reading protected corpus text, and every
stage records `sealed_test_accessed: false`. Whole-input `records_per_second` uses the worker's stable observed aggregate
count; this prevents non-equivalent regex/literal baselines from borrowing NERB's record denominator.

The break-even model records source curation, train-source profiling, and bank building as the same shared acquisition
cost on both paths, so those terms cancel. Direct reuse then adds one cold compile and its per-document scan cost; the
helper-cache-miss alternative pays its measured per-document cost. Both marginal costs use the same whole-input
population and document count; a median of heterogeneous per-document timings is never compared with a whole-input
average. `--source-curation-seconds` is a shared declared scenario—not a measured model invocation, token,
hosted-service, or dollar cost—and cannot manufacture the crossing.

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

## Recorded Gate Highlights

Final routine 100 KB report highlights:

| Workload | Records | Scan/project median | Scan/project throughput |
| --- | ---: | ---: | ---: |
| small-bank floor | 870 | 0.000643s | 15.6 MB/s |
| literal-heavy | 96 | 0.000648s | 154.3 MB/s |
| regex-heavy | 75 | 0.000211s | 473.9 MB/s |
| mixed | 181 | 0.000660s | 151.5 MB/s |

The mixed corpus-size gate passed at 10 KB and 100 KB in the routine report. The 1 MB report passed with 1,805 records,
0.002356s scan/project median, and 424.4 MB/s scan/project throughput.

The production medium-bank case validates 1,000 top-level entities with 8 generated patterns per entity over the
configured 100 KB sparse no-match document. The routine report measured:

| Metric | Value |
| --- | ---: |
| Patterns | 8,000 |
| JSONL bank-source bytes | 1,000,000 |
| Native compile median | 0.635903s |
| Raw scan median | 0.003640s |
| Scan/project median | 0.008654s |
| Scan/project throughput | 11.6 MB/s |

The corresponding 1 MB evidence measured 0.704808s native compile median, 0.034258s raw scan median, 0.043692s
scan/project median, and 22.9 MB/s scan/project throughput.

Dense prefix stress validates semantic reconstruction through 64 synthetic entity classes, with 8 dense prefix detectors
per entity over 256 bytes. At 64 entities, `entity_independent` emitted 2,048 production matches, raw `all_overlaps`
emitted 129,280 matches, and `global_leftmost` emitted 32 matches. The 64-to-2 dense scan ratio was 18.875x under the
80x ceiling.

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

## Large Synthetic Bank Review

The pre-release large-bank review showed exact-literal warm extraction was not the target-tier bottleneck; cold setup
and bank hashing dominated large synthetic banks.

| Workload | Names | Patterns | Engine Profile | Cold Compile | Warm Cache Lookup | Target Warm Extraction | Notes |
| --- | ---: | ---: | --- | ---: | ---: | ---: | --- |
| Target exact literals | 10,000 | 100,000 literal | literal: 64 | 24.657s | 0.750s | 0.032s | Cache hit verified; target records stable. |
| Target mixed | 10,000 | 95,000 literal / 5,000 regex | literal: 64, regex: 32 | 26.461s | 0.777s | 1.266s | Regex shard scanning dominates warm extraction. |
| Stress probe exact literals | 25,000 | 250,000 literal | literal: 128 | 61.522s | 1.899s | 0.015s | Cold setup scales linearly enough to dominate. |
| Full stress cap exact literals | 100,000 | 1,000,000 literal | intended literal: 128 | >180s | not reached | not reached | Timed out before payload. |

The full stress tier is not practical as a routine local or CI check.

## Dependency Decision

NERB does not add a separate literal-matcher runtime dependency for the current production path. The portable Rust
literal automaton meets the target tier without adding binary build, wheel availability, or supply-chain risk. Revisit an
external matcher only if real workloads show long-document warm extraction is the bottleneck after the current engine
path.

PCRE2 remains optional and is not a current blocker. The engine boundary leaves room for a future PCRE2 backend, but the
recorded review does not justify making it part of the production path.

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

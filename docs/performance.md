# V1 Performance Scale Review

Recorded on 2026-06-03 in the local agent workspace:

- Python: `Python 3.14.4`
- Platform: `Linux 6.8.0-1053-gcp x86_64 GNU/Linux`
- CPU count: 4
- Memory: 31 GiB total, 28 GiB available before benchmark review

## V1 Implementation Posture

- Compiled banks are cached in process by canonical bank hash, engine name/version, include statuses, engine options, and
  normalization mode.
- Cache hits skip bounded runtime validation and reuse the compiled bank. They still compute the canonical hash because
  v1 intentionally does not maintain a disk cache or caller-supplied cache key.
- Literal patterns are separate from regex shards. Exact literals compile into per-entity Aho-Corasick-style shards in
  the portable fallback. Literal patterns with whitespace normalization over actual whitespace stay on the regex
  fallback path to preserve `\s+` semantics.
- Regex patterns still compile into one Python `re` shard per entity.
- Literal and regex records are sorted by the stable record key before returning from compiled extraction.
- Shards are immutable after construction and can be parallelized later without changing output shape.

## Rust Engine Smoke Profiles

Slice 2 adds deterministic smoke profiles through `benchmark_fixture_profiles()` and
`make_benchmark_fixture_profile(profile_id)`. These profiles are fixture scaffolding for the Rust engine migration, not
final performance thresholds. Each profile emits JSON-compatible benchmark results with separate stage metadata for
input parsing availability, canonicalization, validation, compile/cache lookup, document preparation, and combined
scan/project/sort work.

Current smoke profiles:

| Profile | Workload | Purpose |
| --- | --- | --- |
| `small` | tiny mixed bank | Cheapest structural signal for benchmark output shape. |
| `literal_heavy` | alias-heavy literal bank | Models curated exact-name banks and entity shard fan-out. |
| `regex_heavy` | regex-dominant bank | Keeps regex validation and shard scan costs visible. |
| `mixed` | balanced literal/regex bank | Exercises both matcher families in one fixture. |
| `adversarial_smoke` | dense-hit and near-miss text | Exercises overlap, alternation, dense records, and near misses safely. |

The smoke gate currently requires all five profiles, the `baseline`/`target`/`stress` tiers, stable record counts across
iterations, cache-hit verification, and the expected JSON sections. It intentionally does not enforce wall-clock
thresholds yet. Full gates are deferred until native Rust modes exist and can report mode-specific compile, scan,
projection, memory, and match-amplification numbers. Later full gates should use larger real or synthetic banks and may
add thresholds such as cold compile ceilings, target bytes/records per second, memory caps, and all-overlaps
amplification limits.

## Benchmark Commands

Target exact-literal bank:

```shell
uv run python -c 'import json; from nerb.benchmarks import benchmark_bank, make_synthetic_bank; bank=make_synthetic_bank(name_count=10000, patterns_per_name=10, entity_count=64, literal_ratio=1.0); result=benchmark_bank(bank, options={"benchmark_iterations":2,"stress_multiplier":4,"max_pattern_examples":24}); summary={"bank_stats": result["bank"]["stats"]["active_totals"], "by_kind": result["bank"]["stats"]["by_kind"], "compile": result["compile"], "engine_matchers": result["engine"]["matchers"], "summary": result["summary"], "tiers": {name: {"documents": tier["document_count"], "bytes": tier["bytes"], "record_count": tier["record_count"], "warm_extraction_seconds": tier["warm_extraction_seconds"], "bytes_per_second": tier["throughput"]["bytes_per_second"], "records_per_second": tier["throughput"]["records_per_second"], "stable": tier["record_count_stable"]} for name, tier in result["tiers"].items()}}; print(json.dumps(summary, indent=2, sort_keys=True))'
```

Target mixed bank with 95% literals and 5% regex:

```shell
timeout 180s uv run python -c 'import json; from nerb.benchmarks import benchmark_bank, make_synthetic_bank; bank=make_synthetic_bank(name_count=10000, patterns_per_name=10, entity_count=64, literal_ratio=0.95); result=benchmark_bank(bank, options={"benchmark_iterations":1,"stress_multiplier":2,"max_pattern_examples":24}); summary={"bank_stats": result["bank"]["stats"]["active_totals"], "by_kind": result["bank"]["stats"]["by_kind"], "compile": result["compile"], "engine_matchers": result["engine"]["matchers"], "summary": result["summary"], "tiers": {name: {"bytes": tier["bytes"], "record_count": tier["record_count"], "warm_extraction_seconds": tier["warm_extraction_seconds"], "bytes_per_second": tier["throughput"]["bytes_per_second"], "stable": tier["record_count_stable"]} for name, tier in result["tiers"].items()}}; print(json.dumps(summary, indent=2, sort_keys=True))'
```

Intermediate stress probe:

```shell
timeout 180s uv run python -c 'import json; from nerb.benchmarks import benchmark_bank, make_synthetic_bank; bank=make_synthetic_bank(name_count=25000, patterns_per_name=10, entity_count=128, literal_ratio=1.0); result=benchmark_bank(bank, options={"benchmark_iterations":1,"stress_multiplier":1,"max_pattern_examples":12}); summary={"bank_stats": result["bank"]["stats"]["active_totals"], "by_kind": result["bank"]["stats"]["by_kind"], "compile": result["compile"], "engine_matchers": result["engine"]["matchers"], "summary": result["summary"], "tiers": {name: {"bytes": tier["bytes"], "record_count": tier["record_count"], "warm_extraction_seconds": tier["warm_extraction_seconds"], "bytes_per_second": tier["throughput"]["bytes_per_second"], "stable": tier["record_count_stable"]} for name, tier in result["tiers"].items()}}; print(json.dumps(summary, indent=2, sort_keys=True))'
```

Full stress cap:

```shell
timeout 180s uv run python -c 'import json; from nerb.benchmarks import benchmark_bank, make_synthetic_bank; bank=make_synthetic_bank(name_count=100000, patterns_per_name=10, entity_count=128, literal_ratio=1.0); result=benchmark_bank(bank, options={"benchmark_iterations":1,"stress_multiplier":1,"max_pattern_examples":12}); print(json.dumps(result["summary"], indent=2, sort_keys=True))'
```

The full stress command exited with status `124` after the 180-second cap and did not emit a benchmark payload.

## Recorded Results

| Workload | Names | Patterns | Matcher Shards | Cold Compile | Warm Cache Lookup | Target Warm Extraction | Notes |
| --- | ---: | ---: | --- | ---: | ---: | ---: | --- |
| Target exact literals | 10,000 | 100,000 literal | literal: 64 | 24.657s | 0.750s | 0.032s | Cache hit verified; 48 target records stable over 2 iterations. |
| Target mixed | 10,000 | 95,000 literal / 5,000 regex | literal: 64, regex: 32 | 26.461s | 0.777s | 1.266s | Regex shard scanning dominates warm extraction. |
| Stress probe exact literals | 25,000 | 250,000 literal | literal: 128 | 61.522s | 1.899s | 0.015s | Cold setup scales linearly enough to dominate. |
| Full stress cap exact literals | 100,000 | 1,000,000 literal | intended literal: 128 | >180s | not reached | not reached | Timed out before payload. |

The target exact-literal run is inside the V1 target tier. The full stress tier is not practical as a routine local or
CI check with the current Python implementation.

## Bottlenecks

- Exact-literal warm extraction is no longer the target-tier bottleneck for small and medium synthetic documents. The
  portable automaton shard scans target documents in milliseconds at 100,000 exact literals.
- Cold setup is the target and stress bottleneck. It includes canonicalization, hash computation, schema/resource
  validation, runtime validation, and automaton construction.
- Warm cache lookup is materially cheaper than cold compile but still scales with bank size because v1 hashes the bank
  object for every lookup. A local pre-cleanup target run measured 1.421s warm lookup before avoiding a duplicate
  canonical hash pass; the final target run measured 0.750s.
- Regex-containing workloads remain sensitive to Python `re` shard scanning. The 5,000-regex mixed target run spent
  1.266s in target warm extraction, despite similar cold compile time to the exact-literal target.

## Dependency Decision

Reviewed automaton-style literal matcher options:

- `pyahocorasick`: maintained, latest PyPI release 2.3.1 on 2026-04-27, BSD-3-Clause, Python `>=3.10`, C extension.
  Source: <https://pypi.org/project/pyahocorasick/>
- `ahocorasick-rs`: latest PyPI release 1.0.3 on 2025-10-08, Apache-2.0, Python `>=3.10`, Rust extension with wheels
  for CPython 3.10 through 3.14 on common platforms. Source: <https://pypi.org/project/ahocorasick-rs/>
- `flashtext`: MIT, but latest PyPI release is 2.7 from 2018-02-16, so it is not a strong V1 dependency candidate.
  Source: <https://pypi.org/project/flashtext/>

Decision: do not add a literal matcher runtime dependency for V1. The portable exact-literal automaton meets the target
tier without adding binary build, wheel availability, or supply-chain risk. Revisit `ahocorasick-rs` or `pyahocorasick`
only if real workloads show long-document warm extraction is the bottleneck after V1.

PCRE2 remains optional and is not a V1 blocker. The engine boundary still leaves room for a future PCRE2 backend, but the
current review does not justify making it part of the production path.

## Resource Limit Review

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

Extraction and eval byte limits remain explicit options for callers. There is no disk cache in V1.

# V1 Performance Scale Review

Rust engine conformance, benchmark, dense-memory, mode-strategy, and distribution gate evidence for the migration is
recorded in [`rust-engine-gates.md`](rust-engine-gates.md).

Recorded on 2026-06-03 in the local agent workspace:

- Python: `Python 3.14.4`
- Platform: `Linux 6.8.0-1053-gcp x86_64 GNU/Linux`
- CPU count: 4
- Memory: 31 GiB total, 28 GiB available before benchmark review

## V1 Implementation Posture

- Public extraction compiles JSON banks through the Rust-backed `Bank` API and scans with the production
  `entity_independent` mode.
- Compiled native banks are cached in process by canonical bank hash, engine name/version, compile options, platform
  dimensions, and target triple.
- Extraction still performs schema/canonicalization and extraction-scope authoring diagnostics before native cache lookup;
  v1 intentionally does not maintain a disk cache or caller-supplied cache key.
- Literal and regex patterns are canonicalized into Rust engine detector metadata, scanned natively, then projected into
  stable byte-offset records before returning from extraction helpers.
- `all_overlaps` and `global_leftmost` remain internal measurement modes for gate reports and are not public
  JSON-bank extraction semantics.

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

Run one smoke profile with:

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

Trimmed output shape:

```json
{
  "compile_cache": {
    "cache_hit_verified": true,
    "exclusive": false,
    "includes": ["canonicalize", "schema_validation", "runtime_validation", "cache_lookup", "matcher_compile"]
  },
  "gate": {
    "requires_cache_hit_verified": true,
    "requires_stable_record_counts": true,
    "thresholds_configured": false
  },
  "profile": "adversarial_smoke",
  "record_count_stable": {
    "baseline": true,
    "stress": true,
    "target": true
  },
  "sections": ["bank", "compile", "diagnostics", "engine", "options", "stages", "summary", "tiers"]
}
```

## Slice 6/7 Native Mode Probe

Slice 6 added a native `all_overlaps` prototype with `regex-automata` lower-level hybrid DFAs. Slice 7 adds
`global_leftmost` as an internal throughput baseline only. The probe below uses a dense two-entity prefix bank with 32
detectors per entity (`A{32}` down to `A`) over a 512-byte `A...A` document. Source order prefers the longest detector.
The production `entity_independent` contract emits 32 non-overlapping leftmost matches: 16 per entity. The internal
`global_leftmost` baseline emits 16 matches because it collapses cross-entity overlap to one winner per region. Raw
`all_overlaps` emits every overlapping detector span and amplifies the same scan to 31,776 raw matches.

Recorded on 2026-06-05 with the editable native extension rebuilt by:

```shell
uv run --with 'maturin>=1.9.4,<2' maturin develop
```

Probe command:

```shell
python - <<'PY'
from __future__ import annotations

import json
import statistics
import time
from nerb import _engine

pattern_count_per_entity = 32
entities = ["ALPHA", "BETA"]
doc_bytes = 512
iterations = 25
source_lines = []
for entity in entities:
    for index in range(pattern_count_per_entity, 0, -1):
        token = "A" * index
        source_lines.append(
            json.dumps(
                {
                    "entity": entity,
                    "canonical_name": f"{entity}_A{index}",
                    "surface_name": f"{entity}_A{index}",
                    "regex": token,
                    "priority": pattern_count_per_entity - index,
                },
                separators=(",", ":"),
            )
        )
source = ("\n".join(source_lines) + "\n").encode()
haystack = b"A" * doc_bytes


def measure(label, func):
    counts = []
    seconds = []
    for _ in range(iterations):
        start = time.perf_counter()
        buffer = func()
        seconds.append(time.perf_counter() - start)
        counts.append(len(buffer))
    return {
        "label": label,
        "count": counts[0],
        "count_stable": len(set(counts)) == 1,
        "median_seconds": round(statistics.median(seconds), 6),
        "min_seconds": round(min(seconds), 6),
    }


def mode(options=None):
    return _engine.Bank.from_source_bytes(source, format_hint="jsonl", compile_options_json=options)


def metadata_profile(bank):
    metadata = bank.metadata()["match_mode"]
    return {key: metadata[key] for key in ("name", "status", "production_default", "internal_only")}


def raw_tuples(buffer):
    return [buffer[index] for index in range(len(buffer))]


default_bank = mode()
overlap_bank = mode('{"match_mode":"all_overlaps"}')
global_bank = mode('{"match_mode":"global_leftmost"}')
entity = measure("entity_independent", lambda: default_bank.scan_bytes(haystack))
global_leftmost = measure("global_leftmost_internal_baseline", lambda: global_bank.scan_bytes(haystack))
raw = measure("all_overlaps_raw", lambda: overlap_bank.scan_bytes(haystack))
reconstructed = measure(
    "all_overlaps_raw_plus_exact_leftmost_reconstruction",
    lambda: overlap_bank.scan_bytes_leftmost_from_all_overlaps(haystack),
)
semantics_source = b"""
{"entity":"PERSON","canonical_name":"Sam","surface_name":"Sam","regex":"Sam","priority":0}
{"entity":"PROJECT","canonical_name":"Samba","surface_name":"Samba","regex":"Samba","priority":0}
"""
semantics_default = _engine.Bank.from_source_bytes(semantics_source, format_hint="jsonl")
semantics_global = _engine.Bank.from_source_bytes(
    semantics_source,
    format_hint="jsonl",
    compile_options_json='{"match_mode":"global_leftmost"}',
)
summary = {
    "bank": {
        "entities": len(entities),
        "patterns": len(entities) * pattern_count_per_entity,
        "pattern_lengths": [1, pattern_count_per_entity],
    },
    "document_bytes": doc_bytes,
    "iterations": iterations,
    "match_mode_metadata": {
        "entity_independent": metadata_profile(default_bank),
        "all_overlaps": metadata_profile(overlap_bank),
        "global_leftmost": metadata_profile(global_bank),
    },
    "measurements": [entity, global_leftmost, raw, reconstructed],
    "global_to_entity_count_ratio": round(global_leftmost["count"] / entity["count"], 3),
    "raw_to_entity_count_ratio": round(raw["count"] / entity["count"], 3),
    "raw_to_reconstructed_count_ratio": round(raw["count"] / reconstructed["count"], 3),
    "semantic_probe": {
        "text": "Samba ships",
        "entity_independent": raw_tuples(semantics_default.scan_bytes(b"Samba ships")),
        "global_leftmost": raw_tuples(semantics_global.scan_bytes(b"Samba ships")),
    },
}
print(json.dumps(summary, indent=2, sort_keys=True))
PY
```

Output:

```json
{
  "bank": {
    "entities": 2,
    "pattern_lengths": [1, 32],
    "patterns": 64
  },
  "document_bytes": 512,
  "global_to_entity_count_ratio": 0.5,
  "iterations": 25,
  "match_mode_metadata": {
    "all_overlaps": {
      "internal_only": true,
      "name": "all_overlaps",
      "production_default": false,
      "status": "internal_prototype"
    },
    "entity_independent": {
      "internal_only": false,
      "name": "entity_independent",
      "production_default": true,
      "status": "production_default"
    },
    "global_leftmost": {
      "internal_only": true,
      "name": "global_leftmost",
      "production_default": false,
      "status": "internal_benchmark_only"
    }
  },
  "measurements": [
    {
      "count": 32,
      "count_stable": true,
      "label": "entity_independent",
      "median_seconds": 0.000016,
      "min_seconds": 0.00001
    },
    {
      "count": 16,
      "count_stable": true,
      "label": "global_leftmost_internal_baseline",
      "median_seconds": 0.000009,
      "min_seconds": 0.000005
    },
    {
      "count": 31776,
      "count_stable": true,
      "label": "all_overlaps_raw",
      "median_seconds": 0.004303,
      "min_seconds": 0.003907
    },
    {
      "count": 32,
      "count_stable": true,
      "label": "all_overlaps_raw_plus_exact_leftmost_reconstruction",
      "median_seconds": 0.004465,
      "min_seconds": 0.004384
    }
  ],
  "raw_to_entity_count_ratio": 993.0,
  "raw_to_reconstructed_count_ratio": 993.0,
  "semantic_probe": {
    "entity_independent": [
      [0, 0, 3],
      [1, 0, 5]
    ],
    "global_leftmost": [
      [0, 0, 3]
    ],
    "text": "Samba ships"
  }
}
```

Interpretation: `global_leftmost` is the fastest internal scan baseline in this smoke probe, but it is faster partly
because it drops valid cross-entity matches. Its output count is half of the production `entity_independent` count on the
two-entity fixture, and the semantic probe shows `PROJECT/Samba` disappearing when `PERSON/Sam` wins the overlapping
region. Raw `all_overlaps` is feasible on the smoke fixture, but dense overlap can multiply materialized matches by three
orders of magnitude. Exact leftmost reconstruction currently measures raw overlap cost and then reruns the
entity-independent shards; the important finding remains semantic: raw candidates alone do not preserve enough
ordered-alternation information to prove leftmost-first conformance. The reconstruction measurement is exact only when
the raw overlapping scan fits the current `MatchBuffer` pre-scan capacity cap. The Slice 6 raw prototype also rejects
Unicode word-boundary assertions; explicit ASCII word boundaries are available, and Unicode boundary behavior remains
covered by `entity_independent` unless a later issue adds a measured fallback.

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

| Workload | Names | Patterns | Engine Profile | Cold Compile | Warm Cache Lookup | Target Warm Extraction | Notes |
| --- | ---: | ---: | --- | ---: | ---: | ---: | --- |
| Target exact literals | 10,000 | 100,000 literal | literal: 64 | 24.657s | 0.750s | 0.032s | Cache hit verified; 48 target records stable over 2 iterations. |
| Target mixed | 10,000 | 95,000 literal / 5,000 regex | literal: 64, regex: 32 | 26.461s | 0.777s | 1.266s | Regex shard scanning dominates warm extraction. |
| Stress probe exact literals | 25,000 | 250,000 literal | literal: 128 | 61.522s | 1.899s | 0.015s | Cold setup scales linearly enough to dominate. |
| Full stress cap exact literals | 100,000 | 1,000,000 literal | intended literal: 128 | >180s | not reached | not reached | Timed out before payload. |

The target exact-literal run is inside the V1 target tier. The full stress tier is not practical as a routine local or
CI check.

## Bottlenecks

- Exact-literal warm extraction is no longer the target-tier bottleneck for small and medium synthetic documents. The
  portable automaton shard scans target documents in milliseconds at 100,000 exact literals.
- Cold setup is the target and stress bottleneck. It includes canonicalization, hash computation, schema/resource
  validation, runtime validation, and automaton construction.
- Warm cache lookup is materially cheaper than cold compile but still scales with bank size because v1 hashes the bank
  object for every lookup. A local pre-cleanup target run measured 1.421s warm lookup before avoiding a duplicate
  canonical hash pass; the final target run measured 0.750s.
- Regex-containing workloads should now be interpreted through the Rust gate report rather than the pre-removal Python
  shard timings. The current report separates native scan, projection, cache lookup, and output shaping for the measured
  workloads.

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

# Enron Entity-Bank Build Benchmark

This benchmark prepares a local, ignored Enron email corpus split, mines a baseline JSON bank from the training split,
and runs NERB's public benchmark and extraction summaries against held-out documents. It is the baseline evaluator for
the entity-bank construction optimization goal tracked in GitHub issue #86.

Raw and cleaned Enron text can include personal information. Keep generated artifacts under `.nerb/`, which is ignored
by git, and do not paste raw records into issues, pull requests, docs, or screenshots.

## Real-Corpus Run

Use the Hugging Face `datasets` package only for the data-prep command. Pin both the package and dataset revision for
baseline runs:

```shell
uv run --with datasets==5.0.0 scripts/enron_bank_build_benchmark.py \
  --dataset corbt/enron-emails \
  --dataset-split train \
  --dataset-revision cfc06c758093d90993abce1a43668fb7357258a6 \
  --output-dir .nerb/enron-benchmark/baseline \
  --sample-fraction 0.5 \
  --test-fraction 0.2 \
  --seed nerb-enron-v1 \
  --created-at 2026-06-09T00:00:00Z \
  --benchmark-documents 50 \
  --quality-documents 1000 \
  --benchmark-iterations 3
```

The default `--sample-fraction 0.5` uses a deterministic hash sample, so it can stream a large fraction of the dataset
without loading all raw text into memory. Record `manifest.json`, `benchmark.json`, the dataset id, revision, row counts,
artifact hashes, and machine metadata in benchmark notes.

## Local Fixture Smoke

For development and CI-style validation, pass a small local JSONL file:

```shell
uv run python scripts/enron_bank_build_benchmark.py \
  --input-jsonl tests/data/enron_sample.jsonl \
  --output-dir .nerb/enron-benchmark/fixture \
  --sample-fraction 1.0 \
  --test-fraction 0.35 \
  --seed fixture-seed \
  --created-at 2026-06-09T00:00:00Z \
  --min-address-count 1 \
  --min-domain-count 1 \
  --benchmark-documents 5 \
  --quality-documents 5 \
  --benchmark-iterations 1
```

The committed tests build temporary fixture files instead of requiring the real Hugging Face dataset.

## Outputs

The output directory contains:

- `train.jsonl` and `test.jsonl`: cleaned local documents with mined address/domain metadata.
- `bank.json`: baseline JSON bank mined from the training split.
- `manifest.json`: provenance, sampling settings, prep counts, artifact hashes, bank stats, and environment metadata.
- `benchmark.json`: manifest plus `benchmark_bank` output and aggregate train/test exact-span NER metrics.

The benchmark JSON intentionally stores aggregate counts and NERB benchmark document summaries, not raw extracted record
strings. Quality metrics include precision, recall, F1, true positives, false positives, false negatives, gold span
count, predicted span count, and per-entity metric summaries. `--benchmark-documents` controls the small document sample
used for timing tiers; `--quality-documents` controls the train/test document sample used for exact-span NER metrics.

## Stage Semantics

`benchmark.json` includes `benchmark.stages` and `benchmark.compile` sections. The top-level `canonicalize` and
`validation` stages are benchmark preflight work. The nested `compile_construction` report comes from the extraction
compile path and intentionally shows the second schema/canonicalization pass that currently happens before native
construction. Do not sum those fields together.

Python-side stages such as schema validation, canonicalization, extractable-bank filtering, JSON serialization, cache key
work, runtime validation, and detector-index projection are exclusive timings. Native Rust construction is currently one
inclusive call that contains Rust source parsing, Rust canonicalization, stable hashing, and matcher compilation; the
report labels those sub-stages as unavailable until the Rust API exposes finer counters. Warm source-cache hits mark
native construction as skipped and report only the Python/cache work needed to reuse the compiled bank.

The report also records canonical/extractable bank byte sizes, entity/name/pattern counts, cache hit/miss metadata,
benchmark iteration counts, and machine metadata. Later optimization runs should compare against the same prepared
train/test manifest and benchmark options.

## Baseline Gates

To compare a candidate run against a stored baseline, pass the baseline `benchmark.json` and any desired thresholds:

```shell
uv run python scripts/enron_bank_build_benchmark.py \
  --input-jsonl tests/data/enron_sample.jsonl \
  --output-dir .nerb/enron-benchmark/candidate \
  --sample-fraction 1.0 \
  --test-fraction 0.35 \
  --seed fixture-seed \
  --created-at 2026-06-09T00:00:00Z \
  --min-address-count 1 \
  --min-domain-count 1 \
  --benchmark-documents 5 \
  --quality-documents 5 \
  --benchmark-iterations 1 \
  --baseline-benchmark-json .nerb/enron-benchmark/baseline/benchmark.json \
  --max-cold-compile-seconds-ratio 1.05 \
  --max-warm-cached-compile-seconds-ratio 1.10 \
  --min-target-bytes-per-second-ratio 0.95
```

The gate first checks an evaluator fingerprint: dataset id/revision, sampling settings, train/test artifact hashes,
benchmark options, quality-document count, and benchmark tier sizes. If the fingerprint differs, the gate fails before
interpreting quality or performance ratios. This keeps benchmark/evaluator changes separate from optimizer changes while
still allowing the candidate bank to change. The quality gate requires held-out F1, precision, and recall to stay at or
above the stored baseline. When a stored-baseline gate is configured and fails, the command exits nonzero after writing
and printing `benchmark.json`. Threshold flags require `--baseline-benchmark-json`; threshold-only commands are rejected.

## Autoresearch Loop

Use `docs/autoresearch.md` and `scripts/nerb_autoresearch.py` when running repeated construction optimization
experiments. The harness treats this benchmark command as the frozen evaluator, appends aggregate-only JSONL result rows,
and can keep or discard a candidate based on score, gate status, timeout/crash behavior, and an explicit editable-file
surface.

## Hero Image Direction

Use `docs/hero-images.md` for benchmark-grounded plot assets. The committed visuals are generated from aggregate
measurement JSON and intentionally avoid raw email text, personal data, screenshots, and unsupported claims.

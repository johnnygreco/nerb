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
  --benchmark-iterations 1
```

The committed tests build temporary fixture files instead of requiring the real Hugging Face dataset.

## Outputs

The output directory contains:

- `train.jsonl` and `test.jsonl`: cleaned local documents with mined address/domain metadata.
- `bank.json`: baseline JSON bank mined from the training split.
- `manifest.json`: provenance, sampling settings, prep counts, artifact hashes, bank stats, and environment metadata.
- `benchmark.json`: manifest plus `benchmark_bank` output and aggregate train/test extraction summaries.

The benchmark JSON intentionally stores aggregate counts and NERB benchmark document summaries, not raw extracted record
strings.

# NERB Autoresearch Harness

The autoresearch harness turns the Enron construction benchmark into a bounded optimization loop. It follows the
Karpathy-style pattern: keep data prep and evaluation fixed, let an agent edit a small experiment surface, extract one
scalar score, append a result row, and keep or discard the candidate based on measured evidence.

This is an experiment runner, not a merge gate bypass. A kept experiment still needs a focused PR, independent review,
green CI, and a Review Record before it can merge.

## Fixed Evaluator

Use the Enron benchmark from `docs/enron-benchmark.md` as the evaluator. The candidate command should run
`scripts/enron_bank_build_benchmark.py` with the same data source, split, seed, sample settings, benchmark settings, and
stored baseline `benchmark.json`.

The candidate benchmark command should include baseline gates:

```shell
uv run python scripts/enron_bank_build_benchmark.py \
  --input-jsonl tests/data/enron_sample.jsonl \
  --output-dir .nerb/enron-benchmark/autoresearch-candidate \
  --sample-fraction 1.0 \
  --test-fraction 0.35 \
  --seed fixture-seed \
  --created-at 2026-06-09T00:00:00Z \
  --min-address-count 1 \
  --min-domain-count 1 \
  --benchmark-documents 5 \
  --benchmark-iterations 1 \
  --baseline-benchmark-json .nerb/enron-benchmark/autoresearch-baseline/benchmark.json \
  --max-cold-compile-seconds-ratio 1.05 \
  --max-warm-cached-compile-seconds-ratio 1.10 \
  --min-target-bytes-per-second-ratio 0.95
```

For real-corpus runs, use the pinned Hugging Face command in `docs/enron-benchmark.md`; keep raw and cleaned artifacts
under ignored `.nerb/` paths.

## Editable Surface

By default, the harness allows construction-related source edits in:

- `src/nerb/bank.py`
- `src/nerb/engine.py`
- `src/nerb/engines.py`
- `src/nerb/records.py`
- `rust/Cargo.lock`
- `rust/Cargo.toml`
- `rust/src/*.rs` files used by bank construction and matching

It freezes evaluator and large-source guidance files:

- `scripts/enron_bank_build_benchmark.py`
- `src/nerb/benchmarks.py`
- `src/nerb/enron_benchmark.py`
- `tests/nerb/test_enron_benchmark.py`
- `tests/data/enron_sample.jsonl`
- `docs/enron-benchmark.md`
- `.agents/skills/nerb-large-source-bank-building`

Pass repeated `--editable-path` or `--frozen-path` values when an issue deliberately changes the boundary. If an
experiment touches a frozen file or a file outside the editable surface, the result is logged and discarded.

## Scoring And Decisions

The primary scalar score is `benchmark.summary.cold_compile_seconds`; lower is better. A candidate is kept only when all
of these are true:

- the candidate command exits successfully within the timeout
- no frozen or out-of-surface files changed relative to `--checkpoint-ref`
- the candidate benchmark JSON has configured gates and `gate.passed == true`
- evaluator and held-out quality gates pass
- canonical and extractable JSON byte sizes stay within configured ratios
- the primary score improves over the baseline by at least `--min-improvement-ratio`

Crashes, timeouts, evaluator fingerprint mismatches, held-out quality changes, size ceiling failures, and insufficient
score improvements are logged as `discard`.

## Running One Experiment

First create a baseline benchmark JSON under `.nerb/`. Then let an agent make one bounded change on an experiment
branch. Score it with:

```shell
uv run python scripts/nerb_autoresearch.py \
  --baseline-benchmark-json .nerb/enron-benchmark/autoresearch-baseline/benchmark.json \
  --candidate-benchmark-json .nerb/enron-benchmark/autoresearch-candidate/benchmark.json \
  --results-jsonl .nerb/autoresearch/results.jsonl \
  --description "try construction optimization idea" \
  --checkpoint-ref HEAD \
  --timeout-seconds 1800 \
  --min-improvement-ratio 0.01 \
  --candidate-command uv run python scripts/enron_bank_build_benchmark.py \
    --input-jsonl tests/data/enron_sample.jsonl \
    --output-dir .nerb/enron-benchmark/autoresearch-candidate \
    --sample-fraction 1.0 \
    --test-fraction 0.35 \
    --seed fixture-seed \
    --created-at 2026-06-09T00:00:00Z \
    --min-address-count 1 \
    --min-domain-count 1 \
    --benchmark-documents 5 \
    --benchmark-iterations 1 \
    --baseline-benchmark-json .nerb/enron-benchmark/autoresearch-baseline/benchmark.json \
    --max-cold-compile-seconds-ratio 1.05 \
    --max-warm-cached-compile-seconds-ratio 1.10 \
    --min-target-bytes-per-second-ratio 0.95
```

Put `--candidate-command` last; all remaining arguments belong to the evaluator command.

By default the harness is dry-run safe: it logs the keep/discard decision but does not mutate git state. To make
non-improving or failed experiments reset to the previous best commit, pass `--apply-git-decision`. This can run
`git reset --hard <checkpoint-ref>` plus `git clean -fd` for the changed experiment paths on discard, so use it only on
an experiment branch with result logs and benchmark artifacts under ignored `.nerb/` paths.

## Result Log

Each result is one compact JSON object per line. The schema version is `nerb.autoresearch_result.v1`. Rows include:

- commit, checkpoint ref, changed paths, editable paths, frozen paths, and path-gate result
- evaluator baseline/candidate paths, bank hashes, and artifact hashes
- process command, exit code, timeout flag, elapsed seconds, and stdout/stderr tails
- primary score, timing metrics, gate status, and memory/size metadata
- decision value and reason
- optional git action applied by the harness

See `examples/artifacts/autoresearch/results.jsonl` for a redacted fixture-shaped row.

## Using The Bank-Building Skill

The large-source skill at `.agents/skills/nerb-large-source-bank-building/SKILL.md` remains the guide for corpus
profiling, taxonomy design, candidate mining, curation, privacy, and eval integrity. The autoresearch harness should be
used after the evaluator is frozen: it measures construction changes and keeps the loop honest, but it should not decide
which entity classes matter or silently change train/test data.

When a kept experiment is ready, open a normal PR with the result row, exact commands, candidate/baseline benchmark
hashes, and a short explanation of why the result is not an evaluator artifact.

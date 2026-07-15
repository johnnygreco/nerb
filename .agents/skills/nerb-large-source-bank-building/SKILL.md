---
name: nerb-large-source-bank-building
description: Use when building, improving, or reviewing a NERB JSON entity bank from a large corpus or dataset, including corpus profiling, entity taxonomy design, candidate alias mining, eval/train/test split design, privacy-safe artifacts, validation, benchmarking, regression checks, and handoff guidance for agent-built entity banks.
---

# NERB Large-Source Bank Building

Use this skill to turn a large data source into a useful NERB entity bank. Be strict about provenance, privacy, split
integrity, validation, and regression evidence. Stay flexible about taxonomy shape, candidate discovery, regex style, and
corpus-specific heuristics.

For detailed checklists, read `references/build-checklist.md` only when planning or reviewing a substantial bank build.

## Operating Stance

- Start from the charter's actual contract. NERB guarantees qualifying matches against a supplied known bank, so catalog
  conformance and correct canonical mapping are primary engine evidence. Catalog coverage is a separate bank-construction
  question.
- When a bank is proposed for open-ended privacy discovery or comprehensive redaction, missed sensitive spans,
  documents, and characters become primary application harms. Measure that open-world use explicitly without relabeling
  uncataloged entities as matcher failures.
- Treat the corpus as evidence, not as the taxonomy owner. User goals decide which entity classes matter.
- Keep raw or sensitive corpora out of git. Commit scripts, schemas, tiny fixtures, aggregate metrics, and redacted examples.
- Freeze data prep and held-out evals before claiming benchmark or quality improvements. Always report exact catalog
  conformance first. Add natural-text catalog diagnostics and population coverage; add open-world span, document, and
  character leakage only when the charter claims comprehensive discovery or redaction. Precision, false alarms,
  over-redaction, and F1 remain secondary constraints only when labels support them.
- Separate evaluator changes from bank or engine changes. If both must change, say so explicitly in the PR/tracker.

## Workflow

1. Profile the source before designing the bank.
   - Identify record shape, volume, languages, encodings, duplicate patterns, noisy boilerplate, and sensitive fields.
   - Sample enough records to see real variation, but do not paste raw private text into issues or docs.
   - Record dataset id, revision, source path, sample limits, split seed, row counts, and artifact hashes when available.

2. Define a bank charter.
   - State the intended user value: what decisions, workflows, or agent memory this bank should support.
   - Choose entity classes from that value plus corpus evidence. Do not force a universal taxonomy.
   - For each entity class, define what should match, what should not match, and metric floors or ceilings tied to the
     harm model. Privacy charters must put explicit missed-span, leaked-document, and leaked-character limits first.

3. Create reproducible private artifacts.
   - Clean obvious transport noise, quoted/replied boilerplate, control characters, empty fields, and pathological records.
   - Create deterministic train/test or train/validation/test splits before candidate tuning.
   - Preserve or derive independent, exhaustive-within-scope gold labels when the charter needs population coverage,
     open-world recall, or leakage metrics. Add precision, false-alarm, over-redaction, and F1 evidence only where the
     annotation scope supports them.
   - Store large or sensitive generated corpora under ignored paths such as `.nerb/`.

4. Seed the bank conservatively.
   - Start with high-confidence literals and simple regexes that reflect recurring corpus evidence.
   - Keep names, pattern IDs, descriptions, statuses, and metadata meaningful enough for later agents to inspect.
   - Prefer explicit eval refs for important patterns before expanding the candidate set.

5. Mine candidates, then curate.
   - Use corpus frequency, contexts, schemas, known dictionaries, clustering, or LLM-assisted suggestions as candidate sources.
   - Review candidates for ambiguity, false-positive risk, stale identifiers, and privacy leakage before adding them.
   - Promote candidates in small batches so `diff-banks`, evals, and benchmarks remain interpretable.

6. Validate and measure.
   - Run structural validation:
     ```shell
     uv run nerb validate-bank --bank path/to/bank.json
     ```
   - Inspect behavior on representative documents:
     ```shell
     uv run nerb extract-report --bank path/to/bank.json --file path/to/document.txt
     ```
   - Run evals when the bank has eval refs or train/test labels:
     ```shell
     uv run nerb eval-bank --bank path/to/bank.json
     ```
   - Run construction/extraction benchmarks before and after meaningful changes:
     ```shell
     uv run nerb benchmark-bank --bank path/to/bank.json --benchmark-iterations 3
     uv run nerb regress-bank --old-bank baseline.json --new-bank candidate.json --benchmark-iterations 3
     ```

7. Iterate with gates.
   - Add or change eval refs when they reveal a real quality gap, then refreeze before optimization claims.
   - Keep a result log with bank hash, artifact hashes, metrics, command lines, and the decision to keep or discard.
   - For Enron-backed work, follow `docs/enron-bank-building.md`: build from a committed development bundle, then deep
     verify the output. Keep the complete run private.

     ```shell
     uv run nerb build-enron-bank \
       --development-run .nerb/enron-splits/development \
       --output-dir .nerb/enron-bank-builds/run
     install -d -m 700 .nerb/enron-scratch
     uv run nerb verify-enron-bank-build \
       --run-dir .nerb/enron-bank-builds/run \
       --development-run .nerb/enron-splits/development \
       --scratch-root .nerb/enron-scratch
     ```
   - Treat the builder's structured-header validation as `structured_weak` labeled-span evidence. It is not open-world
     recall; unsupported precision, false-alarm, and over-redaction metrics stay `null`. Perfect synthetic conformance
     proves active-catalog behavior, not catalog completeness.
   - Do not use `benchmark-bank`, `regress-bank`, a partial-corpus run, or the builder's deep verification to support a
     decision-grade full-source capacity claim. For that claim, freeze the corpus, gates, measured commit, reader lock,
     and run policy first; then follow the isolated full-corpus run, verification, and aggregate-only export workflow in
     `docs/enron-bank-building.md`. Keep its run directory and attempt ledger private.

     ```shell
     uv sync --locked --no-default-groups --group enron-capacity --python 3.13 --reinstall-package nerb
     uv run --locked --no-default-groups --group enron-capacity --no-sync --python 3.13 \
       python -I -S -B scripts/run_enron_capacity.py run-enron-capacity \
       --output-dir .nerb/enron/capacity \
       --attempt-ledger-dir .nerb/enron/capacity-attempts
     uv run --locked --no-default-groups --group enron-capacity --no-sync --python 3.13 \
       python -I -S -B scripts/run_enron_capacity.py verify-enron-capacity \
       --run-dir .nerb/enron/capacity \
       --attempt-ledger-dir .nerb/enron/capacity-attempts
     uv run --locked --no-default-groups --group enron-capacity --no-sync --python 3.13 \
       python -I -S -B scripts/run_enron_capacity.py export-enron-capacity \
       --run-dir .nerb/enron/capacity \
       --attempt-ledger-dir .nerb/enron/capacity-attempts \
       --output capacity-decision.json
     ```
   - Do not optimize against an Enron final-test score. Stop after train mining, validation-only policy selection,
     optional auxiliary-train diagnostics, and catalog conformance. Only a release steward may use the one-shot sealed
     final-test path after the bank, evaluator, thresholds, claims, and workloads are frozen.
   - Treat the first sealed outcome as terminal for that bank and panel. A valid aggregate bundle may honestly encode a
     quality failure; do not resample, relabel, tune, or rescore merely to obtain a passing result. Verify the evidence
     normally, then use the explicit eligibility flag in any release gate:

     ```shell
     uv run nerb verify-enron-evidence --bundle evidence/enron
     uv run nerb verify-enron-evidence \
       --bundle evidence/enron \
       --require-standalone-redaction-eligible
     uv run nerb render-enron-evidence \
       --bundle evidence/enron \
       --output-dir /tmp/nerb-enron-render
     ```

     The first command proves authenticity and arithmetic. The second applies only when a workflow requires this bank to
     stand alone as a comprehensive privacy redactor; it must fail for an ineligible bank. That application result never
     controls release of NERB for its known-bank contract.

8. Leave a handoff another agent can use.
   - Summarize entity classes, split policy, artifact locations, eval coverage, known false positives, and next candidate
     pools.
   - Include exact commands and results. Avoid screenshots or pasted raw corpus rows when aggregate JSON is enough.

## Freedom And Guardrails

Strict:

- provenance, source revisions, split seeds, artifact hashes
- privacy boundaries and ignored output locations
- validation before extraction or benchmarking
- evidence-strength-appropriate quality checks before quality claims; never infer precision from incomplete labels
- regression evidence before merging bank or construction changes

Flexible:

- entity taxonomy and granularity
- candidate generation method
- regex vs literal balance
- batching strategy for candidate promotion
- corpus-specific cleaning heuristics

Stop and update the tracker or ask the user when the desired entity classes are unclear, the corpus cannot be used safely,
the held-out split is empty or contaminated, or a benchmark win requires changing the evaluator.

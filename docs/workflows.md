---
icon: lucide/git-branch
description: "Practical NERB workflows for authoring, validation, patching, evaluation, benchmarking, and promotion."
---

# Workflows

NERB is built around a small loop: author a bank, validate it, scan documents, inspect diagnostics, and promote changes
with diff/eval/benchmark evidence.

## Bank Lifecycle

| Stage | Command | Output |
| --- | --- | --- |
| Validate structure | `nerb validate-bank --bank company.json` | Schema and runtime diagnostics |
| Extract evidence | `nerb extract-text --bank company.json --text "..."` | Deterministic extraction records |
| Report matches | `nerb extract-report --bank company.json --file email.txt` | Report-oriented records and metadata |
| Patch safely | `nerb apply-patches --bank company.json --patch patches.json` | Validated candidate response |
| Compare versions | `nerb diff-banks old.json new.json` | Added, removed, and changed bank elements |
| Evaluate | `nerb eval-bank --bank company.json` | Eval records and metric summaries |
| Benchmark | `nerb benchmark-bank --bank company.json` | Compile/cache/scan timing evidence |
| Promote | `nerb regress-bank --old-bank old.json --new-bank new.json` | Combined promotion gate |

## Authoring Guidance

- Keep entity IDs stable and machine-readable.
- Put human-readable labels in `name`, `canonical`, and `description` fields.
- Prefer literal patterns for exact aliases; reserve regex patterns for real variability.
- Set statuses deliberately. Extraction includes active banks, entities, names, and patterns by default.
- Store review metadata on the nearest relevant object: bank, entity, name, or pattern.

## Validation Strategy

Use validation before extraction in automation:

```shell
nerb validate-bank --bank company.json
```

Validation catches schema errors, runtime regex problems, unsafe eval references, overly large metadata, and extraction
scope issues before they become ambiguous scan results.

## Patching And Promotion

Agents and services can propose RFC 6902 JSON Patch operations instead of rewriting entire banks:

```shell
nerb apply-patches --bank company.json --patch proposed-patch.json
```

NERB validates the patched candidate and returns diagnostics alongside the candidate response. Use that result as the
review surface, then run `regress-bank` before promotion.

## Evaluation And Regression

Evaluation references live in `eval_refs` on bank objects. Local eval execution requires relative paths under the eval
base path; absolute paths, parent traversal outside the base, remote URIs, non-regular files, and invalid UTF-8 are
rejected.

```shell
nerb eval-bank --bank company.json
nerb regress-bank --old-bank old-company.json --new-bank company.json
```

Regression combines diff, eval, and benchmark checks so the promotion decision is based on behavior, not just schema
validity.

## Large Source Banks

For large corpora, treat bank construction as an evidence pipeline:

- profile the corpus and privacy constraints;
- mine aliases into candidate banks;
- split eval/train/test references intentionally;
- benchmark compile and scan behavior at the expected scale;
- keep handoff artifacts reproducible and privacy-safe.

The [Enron Benchmark](enron-benchmark.md), [private preparation workflow](enron-preparation.md),
[train-only bank construction guide](enron-bank-building.md), [Autoresearch](autoresearch.md), and
[large-source bank skill](https://github.com/johnnygreco/nerb/tree/main/.agents/skills/nerb-large-source-bank-building)
document that deeper workflow.

### Measure Enron cache value

After a verified train/validation bank build, freeze and smoke-test the private workload before starting the long
decision profile:

```shell
nerb prepare-enron-performance \
  --bank-build-run .nerb/enron-v2/bank-build \
  --development-run .nerb/enron-v2/development \
  --output-dir .nerb/enron-v2/performance-plan
nerb run-enron-performance \
  --prepared-run .nerb/enron-v2/performance-plan \
  --output-dir .nerb/enron-v2/performance-smoke \
  --profile smoke
nerb verify-enron-performance --run-dir .nerb/enron-v2/performance-smoke
```

The commands expose neither a preparation-source nor sealed-test path; profiling is confined to the verified train
artifact. Outputs remain private and ignored; only privacy-scanned aggregate evidence is
suitable for a later reviewed handoff. The smoke profile is non-promotable. See [Performance](performance.md#enron-v2-cache-value-workflow)
for the decision command, measurement boundaries, scale semantics, and sample policy.

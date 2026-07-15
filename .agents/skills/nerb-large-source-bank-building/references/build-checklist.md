# Large-Corpus Bank Build Checklist

Use this reference when planning or reviewing a substantial NERB bank build. Do not treat it as a rigid sequence; use the
sections that match the current corpus and goal.

## Corpus Profile

- What is the source id, revision, owner, license/access constraint, and expected update cadence?
- What record fields exist, and which fields should never be committed or pasted?
- How many records, bytes, duplicate groups, empty records, and extreme-size records are present?
- What boilerplate appears often: signatures, quoted replies, forwarded headers, machine templates, logs, or markup?
- Which identifiers are stable enough to become entity names or metadata?
- Which fields are useful for provenance but unsafe for eval text?

## Bank Charter

- Who will use this bank, and what should it help them cache or retrieve?
- Which entity classes are high-value enough to justify eval work?
- For each class, what counts as a true positive, acceptable alias, near miss, and false positive?
- Is the contract known-bank matching, open-ended discovery, comprehensive redaction, or a combination? Which metric
  belongs to each claim?
- What harm does a cataloged miss cause? If population coverage is in scope, what harm does an uncataloged entity cause,
  and what recall/leakage floors and over-redaction/runtime ceilings follow?
- Which classes should remain out of scope until evidence supports them?

## Candidate Sources

- Corpus frequency tables for tokens, phrases, addresses, domains, IDs, codes, or titles.
- Structured fields such as sender/recipient lists, account columns, labels, tags, or filenames.
- Known reference lists, controlled vocabularies, schemas, or user-provided seed examples.
- Context windows around seed matches to discover aliases or false positives.
- LLM-suggested candidates, but only after corpus evidence and human-readable rationale are recorded.

## Curation Rules

- Prefer literals for stable names and aliases.
- Use regexes when the surface form is genuinely patterned, not to hide a long unreviewed list.
- Keep regexes bounded and readable; avoid zero-width, catastrophic, or overbroad patterns.
- Assign pattern IDs that explain the surface, not the temporary discovery method.
- Mark uncertain candidates as draft/inactive until evals justify activation.
- Keep candidate promotions small enough that diffs and regressions remain explainable.

## Eval Integrity

- Freeze train/test or train/validation/test splits before tuning.
- Keep held-out documents separate from candidate discovery prompts and ad hoc debugging.
- Include negative or no-match cases for ambiguous classes.
- Ensure eval refs are local, deterministic, and safe to commit; otherwise store private eval artifacts under ignored paths.
- Lead with exhaustive catalog conformance and correct canonical mapping for NERB's known-bank contract. Report
  natural-text catalog diagnostics separately. If the bank is proposed for open-ended privacy discovery or comprehensive
  redaction, add held-out catalog coverage, open-world span recall, leaked-document rate, and sensitive-character recall
  plus per-entity breakdowns. Treat uncataloged spans as coverage gaps, not matcher misses. Report precision, false
  alarms, over-redaction, and F1 only where exhaustive labels make them valid.
- Do not report an optimization win if the evaluator, split, or bank-generation rules changed in the same comparison.

## NERB Checks

Run the checks that match the artifact maturity:

```shell
uv run nerb validate-bank --bank path/to/bank.json
uv run nerb extract-report --bank path/to/bank.json --file path/to/document.txt
uv run nerb eval-bank --bank path/to/bank.json
uv run nerb benchmark-bank --bank path/to/bank.json --benchmark-iterations 3
uv run nerb regress-bank --old-bank baseline.json --new-bank candidate.json --benchmark-iterations 3
```

For the supported Enron train-only workflow, build from a committed private development bundle and deep-verify the
transactional output:

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

The builder has no sealed-test option. It mines train only, uses validation for three frozen policy iterations, and emits
private artifacts plus an aggregate development card. Structured-weak labeled-span recall is not open-world recall;
precision, false-alarm, and over-redaction metrics remain unsupported without independent exhaustive annotations. Never
tune bank construction or policy selection on final-test quality.

Generic `benchmark-bank`/`regress-bank` runs and builder verification are development evidence, not decision-grade
full-source capacity evidence. For a full-source Enron capacity claim, freeze the corpus, gates, measured commit, reader
lock, and run policy before execution. Then use the isolated `python -I -S -B scripts/run_enron_capacity.py` run,
verification, and aggregate-only export commands documented in `docs/enron-bank-building.md`; keep both the capacity run
and append-only attempt ledger under ignored private paths.

## Handoff Summary

Record:

- source id/revision/path, sample size, split seed, and artifact hashes
- bank file path, bank hash, entity/name/pattern counts, and active/draft split
- eval refs added or changed, including known gaps
- benchmark/regression commands and key metrics
- candidate pools intentionally deferred
- privacy-sensitive artifacts that must remain ignored

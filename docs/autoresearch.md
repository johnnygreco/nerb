# Enron V2 Autoresearch Policy

> **Status: policy frozen; v2 runner staged.** The current `scripts/nerb_autoresearch.py` and
> `nerb.autoresearch_result.v1` rows belong to the historical Enron v1 workflow. Its held-out F1 objective and v1
> benchmark command do not satisfy the [v2 charter](enron-benchmark.md). Do not run them to produce a v2 result or use
> their committed examples, plots, keep/discard decisions, or scores as public evidence.

Autoresearch is useful after a benchmark contract is frozen: an agent makes one bounded construction change, evaluates
it against unchanged train/validation artifacts, records the result, and keeps or discards it. It is not allowed to turn
the final test into feedback or optimize a convenient scalar that hides privacy misses.

No runnable v2 command is documented yet. Later implementation work must supply a runner that emits and verifies
`nerb.enron_manifest.v2` and `nerb.enron_evidence.v2` artifacts before this page can describe an executable workflow.

## Experiment Boundary

A v2 experiment starts from a committed checkpoint and one frozen manifest family. It may read:

- train text and train-derived candidate/provenance artifacts;
- validation text, labels, and aggregate/per-slice validation failures;
- synthetic catalog-conformance cases;
- the current-best train/validation bank and evidence; and
- public source code, synthetic fixtures, and aggregate historical experiment logs.

It must not read or derive feedback from:

- sealed final-test text, labels, identities, per-document output, metrics, or failure examples;
- a scalar or pass/fail bit computed from final-test quality;
- another split's answer-bearing structured fields appended to scan text; or
- raw private artifacts from a different authorized source or benchmark run.

Only construction surfaces are editable during an optimization series. The evaluator, preparation/grouping logic, split
manifest, label artifacts, metric definitions, evidence verifier, conformance generator, and benchmark workloads stay
frozen. A deliberate evaluator or split change starts a new baseline/version and cannot be compared as an optimizer win.
The future runner must fail any candidate that changes a frozen or out-of-surface file.

## Privacy-First Selection

V1 used held-out micro F1 as a primary scalar. V2 uses a lexicographic decision, because one additional sensitive miss
cannot be traded invisibly for many easy true positives.

A candidate is considered only after these validity checks pass:

1. the command completed within its limit and wrote a fresh evidence artifact;
2. the evaluator, source, cleaning, split, label, workload, package/engine, and checkpoint fingerprints are complete and
   match the frozen experiment series;
3. path/frozen-file checks pass;
4. quality slices are non-empty where required, arithmetic is valid, and label strengths remain separate;
5. privacy-safe serialization passes; and
6. synthetic catalog conformance is 100% with zero wrong canonical mappings.

Valid candidates are compared in this order:

1. reject any nonzero cataloged misses, documents with a cataloged miss, or wrong canonical mappings;
2. prefer fewer validation open-world false negatives and leaked sensitive characters, then higher open-world span and
   sensitive-character recall, at the frozen class/cohort floors;
3. require negative-document false-alarm and over-redaction ceilings, then prefer lower over-redacted characters;
4. use precision and F1 as secondary diagnostics/tie-breakers, never as permission to accept more privacy misses;
5. require bank-size, compile, direct-reuse throughput, tail-latency, and peak-memory gates; then use performance or size
   improvements as tie-breakers among privacy-equivalent candidates.

Every threshold and tie-break rule is frozen before an experiment series. A reported win shows all raw counts and gate
results, including regressions outside the primary target. If two candidates trade open-world misses across important
classes or cohorts, keep neither automatically; require review rather than hiding the trade in a micro average.

## One Bounded Experiment

The future v2 loop follows this sequence:

1. resolve and record the checkpoint commit and current-best bank/evidence hashes;
2. state one construction hypothesis and the complete editable/frozen path boundary;
3. let the agent make one bounded change without evaluator or split access;
4. validate the bank, run conformance, quality, utility, and required performance workloads on train/validation only;
5. independently verify the emitted manifest/evidence and changed paths;
6. append a privacy-safe result row with the decision and rationale; and
7. promote the current-best ignored artifact only after a keep decision. Git mutation remains an explicit opt-in on a
   disposable experiment branch.

At least three bounded construction iterations should be recorded before the final candidate is frozen. A discarded or
crashed attempt remains part of the aggregate experiment history; silent cherry-picking exaggerates confidence.

## Required Result Record

The v2 runner's privacy-safe result record must reference, rather than duplicate, the authoritative v2 evidence. It
includes:

- hypothesis, created time, checkpoint commit, changed/editable/frozen paths, and path-gate result;
- exact sanitized process argv, timeout, exit status, elapsed time, and bounded **privacy-scanned** output metadata;
- baseline and candidate manifest/evidence/bank hashes;
- label-strength and evaluator/split/workload fingerprints;
- cataloged and open-world miss counts, document miss counts, leaked/over-redacted characters, character recall, coverage,
  conformance, wrong mappings, false alarms, and precision/F1 by required validation slice;
- size, compile, direct-reuse latency/throughput, memory metrics, and raw-sample references;
- every configured threshold, comparison result, final decision, and human-review requirement; and
- whether ignored current-best artifacts or git state were changed.

Raw email, aliases, match strings, local paths, document IDs, failure context, and unfiltered stdout/stderr do not belong
in a committed result. Private detailed logs remain under ignored `.nerb/` storage with the retention policy from the v2
charter.

## Promotion And Final Test

A kept experiment is only a candidate. It still needs a focused change, independent review, green checks, and a verified
train/validation evidence bundle. Before final-test access, freeze:

- bank, evaluator, source/split/label, and workload hashes;
- all privacy, utility, class/cohort, performance, and size gates;
- the exact supportable claim templates; and
- package, engine, commit, command, and environment identities.

The sealed final test is then evaluated once by the release workflow. Its score cannot be copied back into autoresearch,
used to select another candidate, or converted into a keep/discard reward. A failed final gate is reported or requires a
newly versioned benchmark with a new sealed test.

## Historical V1 Quarantine

The v1 harness remains in the repository only as historical implementation until later work replaces or removes it. Its
default editable/frozen path lists, fixture command, F1 scoring rule, stored `benchmark.json` baseline, result schema,
and optional git/promotion behavior are not the v2 contract. In particular:

- `quality.test.f1` is not a permitted v2 autoresearch objective;
- the v1 two-way test is not a v2 validation split;
- a v1 fingerprint does not prove v2 split or evaluator integrity;
- the committed `examples/artifacts/autoresearch/results.jsonl` is synthetic historical documentation, not evidence of a
  v2 experiment; and
- a v1 `gate.passed == true` does not authorize any current public Enron claim.

Use the large-source bank-building skill at `.agents/skills/nerb-large-source-bank-building/SKILL.md` for corpus
profiling, taxonomy, candidate curation, private-artifact handling, and handoff. That workflow remains broader than the
optimizer: user value defines the taxonomy, and measured evidence decides promotion.

---
icon: lucide/database-zap
description: "Train-only Enron entity-bank construction, validation iterations, private artifacts, and verification."
---

# Enron Bank Construction

The bank builder turns one committed [development split](enron-splits.md) into a deterministic private entity bank.
It mines candidates from **train only**, evaluates three frozen construction policies on validation, selects the bounded
email-recall policy, and generates catalog-conformance evidence for every active pattern. It never accepts a sealed-test
path or role.

The resulting bank build is development evidence, not a promoted benchmark result. The public bank card is marked
`promotable: false` because the sealed final test remains unopened and the main validation corpus does not have
independent exhaustive labels for open-world PII or utility metrics.

## Build and verify

Start with a committed private development bundle produced by `split-enron`. Keep the output under an ignored private
path, and choose a new output directory: the transactional writer does not replace an existing run.

```shell
uv run nerb build-enron-bank \
  --development-run .nerb/enron-splits/development \
  --output-dir .nerb/enron-bank-builds/run \
  --benchmark-version enron-v2
```

An optional verified [CMU annotation bundle](enron-evaluation.md#private-ingestion) adds an independent,
training-only person-name diagnostic. It must be paired with a separately reviewed private catalog-binding JSONL that
exactly covers the bundle's training labels. It remains auxiliary and non-promotable.

```shell
uv run nerb build-enron-bank \
  --development-run .nerb/enron-splits/development \
  --annotation-run .nerb/enron-annotations/cmu-meetings \
  --cmu-catalog-bindings .nerb/enron-annotations/cmu-reviewed-catalog-bindings.jsonl \
  --output-dir .nerb/enron-bank-builds/run \
  --benchmark-version enron-v2
```

Deep verification rehashes the complete private inventory, validates and compiles the selected bank, replays all three
validation runs, replays catalog conformance, checks candidate-funnel conservation, and rescans the public card for
direct identifiers and private paths. Supply the same annotation run to re-evaluate optional CMU evidence rather than
only checking its stored commitment.

```shell
uv run nerb verify-enron-bank-build \
  --run-dir .nerb/enron-bank-builds/run \
  --annotation-run .nerb/enron-annotations/cmu-meetings
```

Omit both `--annotation-run` and `--cmu-catalog-bindings` from the build when no auxiliary bundle is available; supplying
only one fails closed. Verification needs the annotation run because it replays the exact reviewed bindings already
copied into the private build. The build command also supports a fixed `--created-at` value for reproducible metadata.
`--allow-unignored-output` is an explicit escape hatch for a private destination outside an ignored Git path; it does
not make that destination or its contents public-safe.

## Train-only candidate policy

The builder streams verified train records and their aligned leakage-group memberships into a private SQLite spool.
Distinct leakage groups, not duplicate messages, are the support unit. Candidate evidence records observation and
document counts, first and last observed dates, source type, collision decisions, private provenance commitments, and
the curation reason.

The initial taxonomy is deliberately narrow:

| Class | Train evidence and selected-bank treatment |
| --- | --- |
| Contact | Valid structured-header addresses recur in at least two distinct train leakage groups before activation. The selected policy also activates one bounded, low-precedence unknown-email fallback. |
| Person | Full names come from structured display names or a sender-local-part name that is also observed near the end of that sender's current body. Support is counted separately for each matcher-equivalent case/whitespace surface, so reordered or punctuated forms do not pool recurrence. Independently recurring matcher-distinct surfaces may share one address identity only when they normalize to the exact same full name; for example, `First Last` and `Last, First` can qualify separately. Nickname-like and same-initial/same-last-name variants remain separate identities rather than being merged. A first-initial identity remains draft, as do all otherwise eligible full identities when an initial-plus-surname address is compatible with more than one of them. An active alias also needs one unambiguous recurring contact-address anchor retained as active or draft and local-part compatibility. The contact literal may remain draft only because of the compile-safe active cap. First-name-only aliases are prohibited. |
| Organization domain | Observed domains are retained as draft because the current literal boundary model cannot express the intended exact domain span without unsafe expansion. |
| Phone number | The bounded US phone fallback is an experiment only. It remains draft in the selected bank because independent negative and over-redaction evidence is unavailable. |

Validation records never enter the candidate spool. Their labels or literal surfaces are not copied into the bank.
Changing the development bundle, construction policy, source code, or benchmark version changes the corresponding
commitments.

## Deferred candidate pools

The builder does not mine the following pools, including as draft patterns. Structured headers do not provide enough
independent semantic evidence for them, and opportunistic body-text mining would increase both false positives and the
amount of private source material retained. Each pool needs a bounded train-only source plus independently reviewed
validation before it can enter the lifecycle:

| Deferred pool | Why it is not mined | Evidence required before inclusion |
| --- | --- | --- |
| Teams and projects | Names overlap ordinary phrases, person aliases, and organization names; project names can also be short-lived. | Exhaustive span and canonical-identity labels, time-aware aliases, and negative overlap cases from representative message bodies. |
| Facilities | Office, site, room, plant, and geographic names are easily conflated, and headers contain no reliable facility relation. | A reviewed facility registry linked to labeled spans, location/facility disambiguation, and boundary/over-redaction negatives. |
| Products and systems | Acronyms, code names, versions, and generic technical words are ambiguous and change over time. | Versioned authoritative catalogs, reviewed aliases, temporal bindings, and acronym/common-word negative evidence. |
| Roles | Titles and desk functions are context-dependent, often generic, and do not identify a stable canonical entity. | A declared role taxonomy, exhaustive in-scope role spans, canonical labels, and person/organization collision tests. |
| Counterparties | A counterparty may be a person, contact, organization, or legal entity, so name recurrence alone cannot establish the relationship. | An approved legal-entity or relationship source, canonical cross-class links, independently labeled spans, and ambiguity adjudication. |

## Candidate lifecycle

Every selected-iteration candidate has one explicit decision:

- **Active:** supported under the frozen policy and eligible for ordinary extraction in the selected bank.
- **Draft:** preserved for review and future evidence, but inactive during ordinary scans.
- **Rejected:** retained only in the private candidate ledger with a bounded reason code; it is not serialized as a bank
  pattern.

The aggregate candidate funnel conserves the ledger across active, draft, and rejected totals and breaks decisions down
by candidate type and primary reason. A capacity limit is a rejection reason, not permission to silently truncate the
evidence trail.

## Three validation-only iterations

The workflow always constructs and records the same three parent-linked policies. Only train-derived candidates differ
between banks; validation is used to compare the frozen policies, never to create aliases.

| Iteration | Change | Decision |
| --- | --- | --- |
| `iteration_01_catalog` | Activates recurring exact contacts and eligible person aliases; generic email and phone fallbacks remain draft. | Discarded after establishing the catalog-only baseline. |
| `iteration_02_email_recall` | Activates the bounded unknown-email fallback at lower precedence than exact contacts. | Selected only when the structured-weak contact slice has no labeled miss, cataloged miss, or wrong canonical mapping. |
| `iteration_03_phone_experiment` | Also activates the bounded phone fallback. | Discarded because validation lacks independent exhaustive phone-negative and over-redaction evidence. |

The iteration ledger binds each policy, bank, validation protocol, catalog binding, quality run, decision, and reason by
hash. The workflow fails closed instead of selecting a different iteration when the frozen selection conditions are not
met.

## What the validation metrics mean

The main validation projection serializes parsed `from`, `to`, `cc`, and `bcc` fields into an answer-bearing structured
header view. Address spans and plausible display-name spans are deterministic `structured_weak` labels. This view is not
the primary natural message body, and its labels are not independent annotations.

The bank card may therefore report raw labeled-span hits and misses, labeled-span recall, catalog coverage, cataloged
recall, and wrong-canonical counts for the declared structured scope. These measures answer a limited question: how the
bank behaves on the parsed header values the source already exposed. They do **not** establish open-world PII recall.

The following main-validation metrics remain `null` and unsupported until an independent,
`exhaustive_within_scope` annotation covers the complete scanned view:

- open-world recall;
- precision and F1;
- negative-document false-alarm rate; and
- over-redaction and leaked-sensitive-character rates.

An unlabeled prediction cannot be counted as a false positive, and an absent structured label cannot prove that a
document contains no PII. The optional CMU Meetings train diagnostic is independently labeled for its declared
person-name scope, but it is auxiliary training evidence: it does not measure contacts, domains, phones, the main email
corpus, or sealed-test performance.

The builder never manufactures CMU catalog qualification from scan output, label text, or active-bank aliases. A human
or independent review process must explicitly adjudicate every label as either `null` or one active person identity in
the caller-supplied JSONL. The strict evaluator requires that file to cover the verified annotation spans exactly and
rejects invalid catalog identities. The builder evaluates a canonical private copy of those exact reviewed records and
retains it for deep replay. Reviewers must not use name-normalization conveniences such as reversing `Last, First` to
manufacture catalog coverage for a differently ordered pattern.

## Catalog conformance

After iteration 2 is selected, the builder compiles the whole active bank and generates:

- exact/case/context witnesses for every active pattern and canonical identity, plus whitespace witnesses where the
  pattern declares whitespace normalization; and
- negative/adversarial cases covering boundaries, casing, HTML residue, malformed input, overlap, punctuation,
  signatures, Unicode, and whitespace.

The gate requires complete active-pattern support, conformance recall exactly `1.0`, zero wrong canonical mappings, and
zero unexpected negative matches. It proves deterministic behavior for approved active catalog patterns. It does not
prove that the catalog contains every real PII surface, so perfect conformance must never be presented as perfect privacy
recall.

## Private and public artifacts

The output directory is a private, transactional run. It has private permissions, a manifest-bound file inventory, and
a `COMMITTED` marker. It contains real names and contact information and must remain ignored and access controlled.

Private artifacts include:

- all three iteration banks and the selected `bank.json`;
- the candidate ledger, collision report, aggregate funnel, and SQLite mining spool;
- validation documents, weak labels, unsupported-dimension declarations, per-iteration gold bindings, quality results,
  and structural reports;
- generated conformance cases and results;
- the exact caller-supplied, separately reviewed CMU catalog bindings and optional quality results; and
- the private manifest and aggregate bank card.

Do not publish an artifact merely because its filename sounds aggregate. The candidate ledger, bank, validation files,
conformance witnesses, SQLite spool, manifest, and auxiliary bindings are private. Raw text, surfaces, document IDs,
private paths, and direct identifiers must never be copied into Git, an issue, a PR description, or public evidence.

`bank-card.json` is the only artifact designed as a possible public handoff after successful deep verification and an
independent publication review. It contains aggregate source commitments, bank statistics, the aggregate candidate
funnel, iteration decisions, supported validation summaries, explicit `null` metrics, conformance totals, optional
auxiliary totals, and privacy declarations. Before committing the private run, the builder rejects a card containing an
email shape or `@`, a phone shape, a document ID, or a private path. The card remains non-promotable until the separate
freeze, one-shot sealed-test, privacy-verification, performance, and lineage requirements in the
[charter](enron-benchmark.md) are satisfied.

## Scale and fail-closed caps

The SQLite spool keeps raw candidate mining disk-backed and deterministic, while explicit ceilings prevent a malformed
or unexpectedly large source from causing unbounded work. The default policy uses these limits:

| Resource | Limit |
| --- | ---: |
| Train records | 600,000 |
| Train role artifact | 512 MiB |
| Validation records | 10,000 |
| Validation role artifact | 96 MiB |
| Validation structured header entries | 250,000 |
| Validation structured labeled spans | 150,000 |
| Validation structured-view UTF-8 bytes | 64 MiB |
| Quality predictions per validation iteration | 500,000 |
| Development memberships artifact | 48 MiB |
| Development samples artifact | 24 MiB |
| Structured header entries per document | 8,192 |
| Candidate observations | 2,000,000 |
| Unique candidates | 50,000 |
| UTF-8 bytes per candidate value | 4,096 |
| Active contacts | 500 |
| Active person identities | 500 |
| Active person aliases | 500 |
| Reserved active-domain capacity | 500 |
| Observed draft candidates per class | 2,000 |
| Active patterns in the selected bank | 25,000 |
| Total active-pattern UTF-8 bytes | 5 MiB |
| Canonical bank JSON | 32 MiB |
| Private JSON artifact bytes | 64 MiB |
| Private JSONL records per artifact | 750,000 |
| Private JSONL bytes per artifact | 256 MiB |
| Private JSONL bytes per line | 16 MiB |
| Private SQLite spool bytes | 2 GiB |
| Private artifact-tree entries / nesting depth | 256 / 8 |

Ingestion, candidate-value, and bank-size limit violations abort the build. Curation overflow moves into draft or
rejected decisions with aggregate funnel accounting; it is never silently dropped. These limits establish bounded
construction behavior, not a latency or memory claim. Realistic compile-once/scan-many performance still needs the
frozen workload and release evidence required by the charter.

The per-class active ceilings include headroom beneath the current Rust entity-independent matcher construction limit;
the builder proved larger single-class banks fail closed during deep compilation. The 25,000-pattern global ceiling is
still a bank-wide safety limit, not permission for one entity class to consume that entire budget. Issue #152 measures
and, if justified, improves larger realistic shapes without weakening this builder's compile-before-commit guarantee.

These are the reviewed #151 development-build limits, not a claim that the current in-memory evaluator can process the
full pinned source. The measured 50,000-row evidence run used 721,302 candidate observations and 15,171 unique
candidates. Its train, validation, membership, and sample artifacts used 419,355,677, 64,931,388, 29,093,619, and
13,477,581 bytes respectively. The defaults retain explicit measured headroom while bounding I/O and Python object
amplification. Manifest-declared record and artifact-byte capacities are checked before hashing large role artifacts or
starting candidate mining. The two non-selected iterations retain only aggregate funnel counters; only the selected
iteration materializes the private candidate ledger needed for audit and replay.

The 150,000-span ceiling bounds retained weak-label and per-iteration gold objects; it is not a prediction-count
preflight. A bank can produce matches outside labeled spans, so the evaluator independently enforces its frozen
500,000-prediction runtime ceiling and still fails closed if scanning reaches it.

Raising these limits for the full pinned source requires #163 to demonstrate a streaming/capacity design with peak-RSS
and runtime evidence and to review any evaluator-capacity change separately. The #153 run must fail before any sealed-test
access if that development-stage proof has not landed; a higher numeric limit alone is not evidence of acceptable scale.

## Reviewed 50k development evidence

The committed aggregate-only evidence files `tests/data/enron_bank_card_real_50000.json` and
`tests/data/enron_candidate_funnel_real_50000.json` come from a frozen 50,000-row real-source development fixture.
The fixture is deliberately marked `fixture_mode: true` and non-promotable; it contains 40,007 train and 4,995
validation records, and the sealed test remained unopened.

The final train-only run mined 721,302 observations into 15,171 candidates: 628 active, 3,667 draft, and 10,876
rejected. The selected bank has 500 recurring exact contacts, one bounded unknown-email fallback, and 127 recurring
person aliases. Structured-weak contact validation detected 59,854 of 59,854 labeled spans; known-catalog coverage was
0.447121, with cataloged recall 1.0 and zero cataloged misses or wrong canonical mappings. Conformance covered all 628
active patterns, 1,885 transformed positives, and 137 adversarial negatives with zero misses, wrong mappings, or
unexpected negative matches.

The separately adjudicated CMU-train binding contains 94 cataloged and 1,802 explicitly uncataloged person labels.
Independent review found zero decision, identity, ambiguity, or exact-offset mismatches. Its auxiliary diagnostic reports
cataloged recall 1.0, open-world recall/catalog coverage 0.049578, precision 0.789916, document leak rate 0.968519, and
over-redaction 0.000411. These low open-world values are the unknown-name limitation in measured form; they are not
hidden by the catalog guarantee.

On an Apple M4 with 16 GiB RAM, the fresh transactional rebuild took 44.21 seconds and 458,276,864 bytes peak RSS. Deep
verification passed. The repeated setup and steady-state measurements are reported separately in the
[decision-grade performance result](performance.md#decision-grade-development-result); a single construction timing is
not a latency claim.

Key commitments are:

- selected bank: `sha256:670f180d3ca8173d4a4269e0deb963566aeca68f3cb8ad893d69baa4e99f2f6d`;
- bank artifact: `sha256:7c2a408f5c5167d35b953eae32f72a1f6aaa8bdaf1daeb4fc412f66db4df313e`;
- candidate ledger: `sha256:64a76cab8159031065df28a1df3d0b0967a2772efa799a427c9e5ecded5ca448`;
- builder implementation: `sha256:ccf3619150ee309a96004002c376b583b2b5233287f76e209be0636d7ee968e2`;
- privacy scanner implementation: `sha256:6c1d428a567dc9d14a064fb6fde6cfaf7645122517cefd8ab134340b1340ddf2`;
- reviewed CMU binding file: `sha256:361baa7fe257b7104bb6c1d854bb24276ac633d4895f34e451304173671ebd6d`;
- canonical CMU catalog binding: `sha256:2be99b7d6ae81eaee466214d75e9a767583a7b3fd6e90595242b7d366b39e232`;
- bank-card run: `sha256:d3ad40dd72768b5840e031dd758e3c6ad83d3ab7e6871240efefd3bb9756b4bf`;
- committed bank-card file: `sha256:6353d3ba91f52eb24309b02817870539ad63f7ffca1ba0a3535c9c3faf673f1f`; and
- committed candidate-funnel file: `sha256:3cbb0a616dc0c0becb274b2cb94633edfd9cb9b3aeb5d1173c477710d14f7f1f`.

The exact invocations remain bound inside the private run. Their privacy-safe CLI shape is:

```shell
/usr/bin/time -l uv run nerb build-enron-bank \
  --development-run .nerb/enron/development \
  --output-dir .nerb/enron/bank-build \
  --annotation-run .nerb/enron/annotations \
  --cmu-catalog-bindings .nerb/enron/cmu-catalog-bindings.jsonl

/usr/bin/time -l uv run nerb verify-enron-bank-build \
  --run-dir .nerb/enron/bank-build \
  --annotation-run .nerb/enron/annotations
```

## Sealed-test boundary

The CLI deliberately accepts `--development-run`, not a role selector or sealed-test path. The source binding recorded
in the private manifest and public card states `sealed_test_accessed: false`, and the verifier returns the same fact.
Builders stop after train mining, validation policy selection, optional auxiliary-train diagnostics, and synthetic
conformance.

Do not inspect, copy, summarize, or derive a scalar from the final-test bundle while building or reviewing this bank.
After the bank, evaluator, thresholds, claims, and workloads are frozen, a release steward—not the builder—may use the
one-shot access path described in the [split guide](enron-splits.md#sealed-test-access).

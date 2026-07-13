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
  --output-dir .nerb/enron-bank-builds/run
```

An optional verified [CMU annotation bundle](enron-evaluation.md#private-ingestion) adds an independent,
training-only person-name diagnostic. It must be paired with a separately reviewed private catalog-binding JSONL that
exactly covers the bundle's training labels. It remains auxiliary and non-promotable.

```shell
uv run nerb build-enron-bank \
  --development-run .nerb/enron-splits/development \
  --annotation-run .nerb/enron-annotations/cmu-meetings \
  --cmu-catalog-bindings .nerb/enron-annotations/cmu-reviewed-catalog-bindings.jsonl \
  --output-dir .nerb/enron-bank-builds/run
```

Deep verification rehashes the complete private inventory, validates and compiles the selected bank, independently
rebuilds the train candidate pool in bounded private scratch, streams all three validation replays, replays catalog
conformance, checks candidate-funnel conservation, and rescans the public card for direct identifiers and private
paths. Supply the same annotation run to re-evaluate optional CMU evidence rather than only checking its stored
commitment.

The verifier requires an existing owner-only scratch root. It creates a private child there and wipes every authenticated
sensitive payload when verification ends; an owner-only, zero-byte cleanup tombstone can remain if safe removal cannot be
proven. Mining snapshots, rebuilds, validation spools, and optional CMU spools never fall back to system temporary
storage.

The capacity workflow uses the shared internal `_run_enron_streaming_validation` adapter for its validation-only phase.
That adapter snapshots the committed build and exact development bundle, compiles the selected bank once, streams the
selected validation population once through the sole quality session, compares the result exactly with the stored
selected aggregate, and returns only record/byte counts and hashes. It never remines train, retains documents or
predictions, or reads the sealed bundle. Build, deep verification, and this adapter accept a separate observational
activity callback for liveness; activity signals do not increment cumulative record progress or alter artifacts.

```shell
install -d -m 700 .nerb/enron-scratch
uv run nerb verify-enron-bank-build \
  --run-dir .nerb/enron-bank-builds/run \
  --development-run .nerb/enron-splits/development \
  --annotation-run .nerb/enron-annotations/cmu-meetings \
  --scratch-root .nerb/enron-scratch
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
Changing the development bundle, construction policy, or executable source changes the corresponding commitments.

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
| Train role artifact | 6 GiB |
| Validation records | 75,000 |
| Validation role artifact | 1 GiB |
| Validation structured header entries | 1,000,000 |
| Validation structured labeled spans | 1,000,000 |
| Validation structured-view UTF-8 bytes | 1 GiB |
| Quality predictions per validation iteration | 5,000,000 |
| Development memberships artifact | 512 MiB |
| Development samples artifact | 64 MiB |
| Structured header entries per document | 8,192 |
| Candidate observations | 10,000,000 |
| Unique candidates | 200,000 |
| UTF-8 bytes per candidate value | 4,096 |
| Active contacts | 12,000 |
| Active person identities | 12,000 |
| Active person aliases | 12,999 |
| Active domains | 0 |
| Observed draft candidates per class | 2,000 |
| Active patterns in the selected bank | 25,000 |
| Total active-pattern UTF-8 bytes | 5 MiB |
| Canonical bank JSON | 32 MiB |
| Private JSON artifact bytes | 64 MiB |
| Candidate ledger | 200,002 records / 1 GiB |
| Auxiliary CMU bindings | 500,000 records / 256 MiB |
| Conformance suite | 100,000 total records; 256 MiB per positive/negative artifact |
| Iteration ledger | 16 MiB |
| Validation plan | 256 records / 4 MiB |
| Private JSONL bytes per line | 16 MiB |
| Quality metadata spool | 2 GiB |
| Deep-verification scratch | 12 GiB |
| Private artifact-tree entries / nesting depth | 256 / 8 |

Ingestion, candidate-value, and bank-size limit violations abort the build. Curation overflow moves into draft or
rejected decisions with aggregate funnel accounting; it is never silently dropped. These limits establish bounded
construction behavior, not a latency or memory claim. Realistic compile-once/scan-many performance still needs the
frozen workload and release evidence required by the charter.

The selected-bank allocation conserves the complete 25,000-pattern envelope: at most 12,000 recurring exact contacts,
at most 12,999 recurring collision-free person aliases across at most 12,000 person identities, and one generic email
fallback. Organization domains remain draft because exact domain-boundary semantics are unavailable. The fallback is
reserved before curation, the global ceiling remains independently enforced, and compilation remains a mandatory
pre-commit check.

The 200,000-candidate cap is the frozen bounded envelope for full-source execution. It stays independently below the
10,000,000-observation, 12 GiB SQLite, and 1 GiB candidate-ledger ceilings. Only a complete capacity run can establish
that this envelope is sufficient; a partial-source extrapolation is not benchmark evidence.

Conformance sizing is preflighted before evaluation or commit. The 32 MiB canonical-bank ceiling, 100,000-case total
gate, and 256 MiB per positive/negative artifact are separate structural limits. They do not override the native
compiler's regex and aggregate resource ceilings, and passing them is not a compile-latency or RSS claim.

The repository includes one locked, aggregate-only native witness for the exact selected-bank topology: one contact
entity with 12,000 exact literals plus one structured fallback, and one person entity with 12,999 normalized-whitespace
literals. It scans an exact 10 MiB document through one serial and eight concurrent calls, forcing Unicode whitespace
collapse and the mapped simple-fold path:

```shell
uv run --locked --python 3.13 python scripts/enron_native_capacity_probe.py --require-clean-commit
```

The JSON output binds generator implementation hash, generated source/document hashes and bytes, exact detector output
digest, current/embedded/committed native build-source hashes, binary and runtime identity, regex resource profile,
compile/scan times, output equivalence, and absolute plus growth max-RSS gates. The clean-commit flag fails unless the
extension was built from the checked-out commit and the complete working tree is clean. This is a reproducible native
capacity smoke witness, not decision-grade timing, full-source quality, privacy, or promotion evidence.

The defaults bound the full 517,401-row pinned source while keeping all high-volume work streaming or disk-backed.
Manifest-declared record and artifact-byte capacities are checked before hashing large role artifacts or starting
candidate mining. Validation is scanned in one prepare/consume/finish session, and the two non-selected iterations retain
only aggregate funnel counters. Only the selected iteration materializes the private candidate ledger needed for audit
and replay. Deep verification rebuilds train-derived candidates independently inside caller-owned scratch space, compares
that rebuild with the committed ledger, destroys the first pool, and then replays the committed pool; it never retains two
full candidate pools at once.

The 1,000,000-span ceiling bounds validation gold input; it is not a prediction-count preflight. A bank can produce
matches outside labeled spans, so the evaluator independently enforces its 5,000,000-prediction runtime ceiling and fails
closed if scanning reaches it. Numeric capacity alone is not performance evidence: the capacity run must separately prove
the frozen runtime, RSS, free-space, owned-high-water, progress, and sealed-access gates on the complete pinned source.

### Full-source capacity run

The production reader is an exact non-runtime dependency group, not a base NERB dependency. Consume the checked-in
lock with Python 3.13; do not use an independently resolved `--with` environment:

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

The tracked launcher is the only production-capacity entry. It starts with isolated mode, site processing disabled,
and bytecode disabled; installs a fresh private pycache prefix before importing NERB; and adds the validated worktree
source and virtual-environment dependency roots directly. It never calls `site.addsitedir`, so `.pth`, `sitecustomize`,
and user-site hooks are not processed. Direct `nerb run-enron-capacity`, `nerb verify-enron-capacity`, and
`nerb export-enron-capacity` invocations fail closed outside that bootstrap.

The capacity decision uses these frozen resource gates:

| Resource gate | Passing requirement |
| --- | --- |
| Preflight free space | At least 25 GiB on each distinct output and attempt-ledger filesystem |
| Owned and temporary high-water | At most 20 GiB |
| Runtime free-space floor | At least 5 GiB on every monitored filesystem |
| Total attempt runtime | At most 4 hours |
| Phase throughput | At least 100 source rows per second in every phase |
| Effective RSS cap | `min(8 GiB, 75% of physical memory)` |
| Passing observed RSS | At most 75% of the effective RSS cap |
| Resource-observation wall gap | At most 500 ms through report write, promotion, and the promoted final-tree scan |

Reported RSS is the maximum, under the enforced cadence, of sampled current live-process-tree RSS and a conservative
kernel high-water bound formed from the root process maximum plus the reaped-child maximum. Those two kernel maxima may
come from different instants, so their sum can overestimate an instantaneous tree peak; the cadence still does not claim
to capture every transient live-tree peak. The report freezes its resource totals before report serialization. The
terminal attempt receipt strictly extends that envelope through report fsync, final staging inspection, atomic promotion,
and the promoted final-tree observation.

The run requires the exact locked reader set (`datasets==5.0.0`, `huggingface-hub==1.23.0`, `fsspec==2026.4.0`, and
`pyarrow==25.0.0`). It records a path-free hash of the complete installed name/version inventory and hashes every regular
in-root package or `.dist-info` file listed by those four distributions, excluding bytecode caches and external `..`
entries such as installed console scripts. It proves each required top-level reader module originates below its hashed
distribution root; the distribution inventory covers submodule source files but does not separately attest every loaded
submodule origin. It also binds the checked-in `pyproject.toml` plus `uv.lock`.

Those hashes identify the bytes that were observed; they do not compare them with a precommitted wheel attestation. A
production run therefore requires a trusted, access-controlled host and a fresh uv-managed install from the checked-in
lock. A locally modified package that retains its version metadata produces a different observed hash but is not rejected
against a known-good package digest. Lower HTTP dependencies remain lock-and-version bound rather than individually
byte-attested. Both limitations are explicit in portable evidence.

Reader provenance is metadata-only before the preparation phase: neither `datasets` nor its Hub, filesystem, or Arrow
dependencies may load before the phase owns its runtime tree. The first import occurs after HOME, temporary, XDG,
dataset/module/download/extraction, Hub/assets/Xet, transformer, and credential paths are redirected to phase-owned
private roots. The run fixes the official Hub endpoint, disables offline mode, ambient credentials, implicit tokens,
Xet, telemetry, and cache symlinks, passes `token=False` plus the phase cache explicitly, and uses umask `077`. It
validates the effective library constants before and after source consumption without publishing an absolute path or
credential value.

The full run has one cleanup owner for its complete lifetime. Preparation, split, and bank-build transactions transfer
their retained payload descriptors to that outer transaction before their own commit handles close. After every phase
stops its writers, the outer transaction also performs a bounded no-follow adoption pass over every regular file created
directly by the reader or another third-party component. Cleanup authority remains live through post-promotion gates and
durable attempt terminalization, so an in-process later failure wipes authenticated payload inodes even if a same-user
race moved a child outside the staging tree. Before promotion, the attempt ledger durably binds the complete inode
inventory. Crash recovery retains every reachable expected inode while wiping it. A failed authenticated wipe is moved
to the bounded process retry registry and blocks terminalization until verified zero; a later in-process recovery retries
that authority before writing a receipt. Recovery reports `sensitive_content_wiped: false` when inventory or path evidence
is incomplete, and it does not claim that an inode moved before a new recovery process opened it can be recovered without
a live descriptor. The process-wide limit is 128 retained files. Under `RLIMIT_NOFILE`, NERB also
reserves the maximum 64-level cleanup walk plus 8 descriptors for the file and transaction overhead (72 total);
exceeding either bound fails closed before promotion.

`verify-portable-enron-capacity --artifact capacity-decision.json` is a clean-clone verifier. It checks closed report
arithmetic, the full attempt hash chain, terminal cross-bindings, the measured Git commit and root tree, tracked source
blobs, reader lock, and native build-source commitment. It does not independently re-read the original private payload,
re-attest the promoted inode, prove recorded timing/RSS/disk observations, or reproduce/authenticate the native binary
bytes. It also does not independently byte-attest HTTP dependencies below the four critical reader distributions.
Those limits are included and hash-bound in the exported artifact itself.

Export pins the report, commit marker, and complete attempt-chain snapshot while holding the ledger's shared lock through
the no-replace publication and directory fsync. That successful publication is the snapshot's linearization point; a
cooperating later attempt appends only after the export releases the lock and is therefore outside that artifact.

## Regenerating bank evidence

Policy, allocation, evaluator, or workload changes require a fresh private run and fresh aggregate commitments. A
decision-grade result must bind the complete
pinned source, selected bank, evaluator, validation result, implementation, resource observations, and
`sealed_test_accessed: false`; planning projections and smoke fixtures cannot substitute for that evidence.

The privacy-safe CLI shape for regenerating the private run is:

```shell
/usr/bin/time -l uv run nerb build-enron-bank \
  --development-run .nerb/enron/development \
  --output-dir .nerb/enron/bank-build \
  --annotation-run .nerb/enron/annotations \
  --cmu-catalog-bindings .nerb/enron/cmu-catalog-bindings.jsonl

/usr/bin/time -l uv run nerb verify-enron-bank-build \
  --run-dir .nerb/enron/bank-build \
  --development-run .nerb/enron/development \
  --annotation-run .nerb/enron/annotations \
  --scratch-root .nerb/enron-scratch
```

## Sealed-test boundary

The CLI deliberately accepts `--development-run`, not a role selector or sealed-test path. The source binding recorded
in the private manifest and public card states `sealed_test_accessed: false`, and the verifier returns the same fact.
Builders stop after train mining, validation policy selection, optional auxiliary-train diagnostics, and synthetic
conformance.

Do not inspect, copy, summarize, or derive a scalar from the final-test bundle while building or reviewing this bank.
After the bank, evaluator, thresholds, claims, and workloads are frozen, a release steward—not the builder—may use the
one-shot access path described in the [split guide](enron-splits.md#sealed-test-access).
